#include <config.h>

#ifdef WITH_TLS
# ifndef IN_TLS_C
#  define IN_TLS_C 1
# endif

# include "ftpd.h"
# include "tls.h"
# include "ftpwho-update.h"
# include "globals.h"
# include "messages.h"
# include "alt_arc4random.h"
# include "tls_extcert.h"

static void tls_error(const int line, int err)
{
    if (err == 0) {
        err = ERR_get_error();
    }
    if (err != 0) {
        logfile(LOG_ERR, "TLS [%s](%d): %s",
                cert_file, line, ERR_error_string(err, NULL));
    }
    _EXIT(EXIT_FAILURE);
}

static int validate_sni_name(const char * const sni_name)
{
    static const char *valid_chars =
        "abcdefghijklmnopqrstuvwxyz.-0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char        *pnt = sni_name;

    if (strlen(sni_name) > 255) {
        return -1;
    }
    while (*pnt != 0) {
        if (strchr(valid_chars, *pnt) == NULL) {
            return -1;
        }
        pnt++;
    }
    return 0;
}

static int tls_create_new_context(const char *cert_file,
                                  const char *key_file);

static int ssl_servername_cb(SSL *cnx, int *al, void *arg)
{
    CertResult  result;
    const char *sni_name;

    (void) al;
    (void) arg;
    if ((sni_name = SSL_get_servername(cnx, TLSEXT_NAMETYPE_host_name))
        == NULL || *sni_name == 0 || validate_sni_name(sni_name) != 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    logfile(LOG_INFO, "SNI: [%s]", sni_name);
    if (chrooted != 0 || loggedin != 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    if (use_extcert == 0) {
        return SSL_TLSEXT_ERR_OK;
    }
    memset(&result, 0, sizeof result);
    tls_extcert_get(&result, sni_name);
    if (result.cert_ok != 1) {
        die(400, LOG_ERR, "Cert handler not ready");
    }
    if (result.action == CERT_ACTION_DENY) {
        die(400, LOG_INFO, MSG_LOGOUT);
    }
    if (result.action == CERT_ACTION_DEFAULT) {
        return SSL_TLSEXT_ERR_OK;
    }
    if (result.cert_file == NULL) {
        if (result.action == CERT_ACTION_STRICT) {
            die(400, LOG_ERR, "Missing certificate");
        } else {
            return SSL_TLSEXT_ERR_OK;
        }
    }
    if (result.key_file == NULL) {
        result.key_file = result.cert_file;
    }
    SSL_CTX_free(tls_ctx);
    tls_ctx = NULL;
    if (tls_create_new_context(result.cert_file, result.key_file) != 0) {
        if (result.action != CERT_ACTION_FALLBACK) {
            die(400, LOG_ERR, "Invalid certificate");
        }
        if (tls_create_new_context(cert_file, key_file) != 0) {
            die(400, LOG_ERR, "SSL error");
        }
    }
    if ((client_sni_name = strdup(sni_name)) == NULL) {
        die_mem();
    }
    if (tls_cnx != NULL) {
        const long ctx_options = SSL_CTX_get_options(tls_ctx);
        SSL_set_SSL_CTX(tls_cnx, tls_ctx);
# ifdef SSL_CTRL_CLEAR_OPTIONS
        SSL_clear_options(tls_cnx,
                          SSL_get_options(tls_cnx) & ~ctx_options);
# endif
        SSL_set_options(tls_cnx, ctx_options);
    }
    if (tls_data_cnx != NULL) {
        const long ctx_options = SSL_CTX_get_options(tls_ctx);
        SSL_set_SSL_CTX(tls_data_cnx, tls_ctx);
# ifdef SSL_CTRL_CLEAR_OPTIONS
        SSL_clear_options(tls_data_cnx,
                          SSL_get_options(tls_cnx) & ~ctx_options);
# endif
        SSL_set_options(tls_data_cnx, ctx_options);
    }
    return SSL_TLSEXT_ERR_OK;
}

static void ssl_info_cb(const SSL *cnx, int where, int ret)
{
    (void) ret;

    if ((where & SSL_CB_HANDSHAKE_DONE) != 0) {
        if (cnx == tls_cnx) {
            tls_cnx_handshook = 1;
        } else if (cnx == tls_data_cnx) {
            tls_data_cnx_handshook = 1;
        }
    }
}

static int tls_init_ecdh_curve(void)
{
#ifdef SSL_CTRL_SET_ECDH_AUTO
    SSL_CTX_ctrl(tls_ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
    return 0;
#else
# ifndef SSL_OP_SINGLE_ECDH_USE
    errno = ENOTSUP;
    return -1;
# else
    const char *curve_name;
    EC_KEY     *curve;
    int         nid;

    curve_name = TLS_DEFAULT_ECDH_CURVE;
    if ((nid = OBJ_sn2nid(curve_name)) == NID_undef) {
        logfile(LOG_INFO, "Curve [%s] not supported", curve_name);
        errno = ENOTSUP;
        return -1;
    }
    if ((curve = EC_KEY_new_by_curve_name(nid)) == NULL) {
        logfile(LOG_INFO, "Curve [%s] is not usable", curve_name);
        errno = ENOTSUP;
        return -1;
    }
    SSL_CTX_set_options(tls_ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(tls_ctx, curve);
    EC_KEY_free(curve);

    return 0;
# endif
#endif
}

#ifndef SSL_CTRL_SET_DH_AUTO
static int tls_load_dhparams_default(void)
{
# ifdef HAVE_DH_GET_2048_256
    DH *dh;

    if ((dh = DH_get_2048_256()) == NULL) {
        die_mem();
    }
# else
#  if BN_BITS2 == 64
static const BN_ULONG dh2048_256_p[] = {
    0xDB094AE91E1A1597ULL, 0x693877FAD7EF09CAULL, 0x6116D2276E11715FULL,
    0xA4B54330C198AF12ULL, 0x75F26375D7014103ULL, 0xC3A3960A54E710C3ULL,
    0xDED4010ABD0BE621ULL, 0xC0B857F689962856ULL, 0xB3CA3F7971506026ULL,
    0x1CCACB83E6B486F6ULL, 0x67E144E514056425ULL, 0xF6A167B5A41825D9ULL,
    0x3AD8347796524D8EULL, 0xF13C6D9A51BFA4ABULL, 0x2D52526735488A0EULL,
    0xB63ACAE1CAA6B790ULL, 0x4FDB70C581B23F76ULL, 0xBC39A0BF12307F5CULL,
    0xB941F54EB1E59BB8ULL, 0x6C5BFC11D45F9088ULL, 0x22E0B1EF4275BF7BULL,
    0x91F9E6725B4758C0ULL, 0x5A8A9D306BCF67EDULL, 0x209E0C6497517ABDULL,
    0x3BF4296D830E9A7CULL, 0x16C3D91134096FAAULL, 0xFAF7DF4561B2AA30ULL,
    0xE00DF8F1D61957D4ULL, 0x5D2CEED4435E3B00ULL, 0x8CEEF608660DD0F2ULL,
    0xFFBBD19C65195999ULL, 0x87A8E61DB4B6663CULL
};
static const BN_ULONG dh2048_256_g[] = {
    0x664B4C0F6CC41659ULL, 0x5E2327CFEF98C582ULL, 0xD647D148D4795451ULL,
    0x2F63078490F00EF8ULL, 0x184B523D1DB246C3ULL, 0xC7891428CDC67EB6ULL,
    0x7FD028370DF92B52ULL, 0xB3353BBB64E0EC37ULL, 0xECD06E1557CD0915ULL,
    0xB7D2BBD2DF016199ULL, 0xC8484B1E052588B9ULL, 0xDB2A3B7313D3FE14ULL,
    0xD052B985D182EA0AULL, 0xA4BD1BFFE83B9C80ULL, 0xDFC967C1FB3F2E55ULL,
    0xB5045AF2767164E1ULL, 0x1D14348F6F2F9193ULL, 0x64E67982428EBC83ULL,
    0x8AC376D282D6ED38ULL, 0x777DE62AAAB8A862ULL, 0xDDF463E5E9EC144BULL,
    0x0196F931C77A57F2ULL, 0xA55AE31341000A65ULL, 0x901228F8C28CBB18ULL,
    0xBC3773BF7E8C6F62ULL, 0xBE3A6C1B0C6B47B1ULL, 0xFF4FED4AAC0BB555ULL,
    0x10DBC15077BE463FULL, 0x07F4793A1A0BA125ULL, 0x4CA7B18F21EF2054ULL,
    0x2E77506660EDBD48ULL, 0x3FB32C9B73134D0BULL
};
static const BN_ULONG dh2048_256_q[] = {
    0xA308B0FE64F5FBD3ULL, 0x99B1A47D1EB3750BULL, 0xB447997640129DA2ULL,
    0x8CF83642A709A097ULL
};
#  elif BN_BITS2 == 32
static const BN_ULONG dh2048_256_p[] = {
    0x1E1A1597, 0xDB094AE9, 0xD7EF09CA, 0x693877FA, 0x6E11715F, 0x6116D227,
    0xC198AF12, 0xA4B54330, 0xD7014103, 0x75F26375, 0x54E710C3, 0xC3A3960A,
    0xBD0BE621, 0xDED4010A, 0x89962856, 0xC0B857F6, 0x71506026, 0xB3CA3F79,
    0xE6B486F6, 0x1CCACB83, 0x14056425, 0x67E144E5, 0xA41825D9, 0xF6A167B5,
    0x96524D8E, 0x3AD83477, 0x51BFA4AB, 0xF13C6D9A, 0x35488A0E, 0x2D525267,
    0xCAA6B790, 0xB63ACAE1, 0x81B23F76, 0x4FDB70C5, 0x12307F5C, 0xBC39A0BF,
    0xB1E59BB8, 0xB941F54E, 0xD45F9088, 0x6C5BFC11, 0x4275BF7B, 0x22E0B1EF,
    0x5B4758C0, 0x91F9E672, 0x6BCF67ED, 0x5A8A9D30, 0x97517ABD, 0x209E0C64,
    0x830E9A7C, 0x3BF4296D, 0x34096FAA, 0x16C3D911, 0x61B2AA30, 0xFAF7DF45,
    0xD61957D4, 0xE00DF8F1, 0x435E3B00, 0x5D2CEED4, 0x660DD0F2, 0x8CEEF608,
    0x65195999, 0xFFBBD19C, 0xB4B6663C, 0x87A8E61D
};
static const BN_ULONG dh2048_256_g[] = {
    0x6CC41659, 0x664B4C0F, 0xEF98C582, 0x5E2327CF, 0xD4795451, 0xD647D148,
    0x90F00EF8, 0x2F630784, 0x1DB246C3, 0x184B523D, 0xCDC67EB6, 0xC7891428,
    0x0DF92B52, 0x7FD02837, 0x64E0EC37, 0xB3353BBB, 0x57CD0915, 0xECD06E15,
    0xDF016199, 0xB7D2BBD2, 0x052588B9, 0xC8484B1E, 0x13D3FE14, 0xDB2A3B73,
    0xD182EA0A, 0xD052B985, 0xE83B9C80, 0xA4BD1BFF, 0xFB3F2E55, 0xDFC967C1,
    0x767164E1, 0xB5045AF2, 0x6F2F9193, 0x1D14348F, 0x428EBC83, 0x64E67982,
    0x82D6ED38, 0x8AC376D2, 0xAAB8A862, 0x777DE62A, 0xE9EC144B, 0xDDF463E5,
    0xC77A57F2, 0x0196F931, 0x41000A65, 0xA55AE313, 0xC28CBB18, 0x901228F8,
    0x7E8C6F62, 0xBC3773BF, 0x0C6B47B1, 0xBE3A6C1B, 0xAC0BB555, 0xFF4FED4A,
    0x77BE463F, 0x10DBC150, 0x1A0BA125, 0x07F4793A, 0x21EF2054, 0x4CA7B18F,
    0x60EDBD48, 0x2E775066, 0x73134D0B, 0x3FB32C9B
};
static const BN_ULONG dh2048_256_q[] = {
    0x64F5FBD3, 0xA308B0FE, 0x1EB3750B, 0x99B1A47D, 0x40129DA2, 0xB4479976,
    0xA709A097, 0x8CF83642
};
#  else
#   error "unsupported BN_BITS2"
#  endif
    static const BIGNUM p = {
        (BN_ULONG *) dh2048_256_p,
        sizeof(dh2048_256_p) / sizeof(BN_ULONG),
        sizeof(dh2048_256_p) / sizeof(BN_ULONG),
        0, BN_FLG_STATIC_DATA
    };
    static const BIGNUM g = {
        (BN_ULONG *) dh2048_256_g,
        sizeof(dh2048_256_g) / sizeof(BN_ULONG),
        sizeof(dh2048_256_g) / sizeof(BN_ULONG),
        0, BN_FLG_STATIC_DATA
    };
    static const BIGNUM q = {
        (BN_ULONG *) dh2048_256_q,
        sizeof(dh2048_256_q) / sizeof(BN_ULONG),
        sizeof(dh2048_256_q) / sizeof(BN_ULONG),
        0, BN_FLG_STATIC_DATA
    };
    DH *dh;

    if ((dh = DH_new()) == NULL) {
        die_mem();
    }
    dh->p = BN_dup(&p);
    dh->g = BN_dup(&g);
    dh->q = BN_dup(&q);
    if (dh->p == NULL || dh->g == NULL || dh->q == NULL) {
        DH_free(dh);
        die_mem();
    }
# endif
    SSL_CTX_set_tmp_dh(tls_ctx, dh);
    DH_free(dh);
# ifdef SSL_OP_SINGLE_DH_USE
    SSL_CTX_set_options(tls_ctx, SSL_OP_SINGLE_DH_USE);
# endif

    return 0;
}
#endif

static int tls_load_dhparams(void)
{
    BIO *bio;
    DH  *dh;

    if ((bio = BIO_new_file(TLS_DHPARAMS_FILE, "r")) == NULL) {
        logfile(LOG_DEBUG,
                "Couldn't load the DH parameters file " TLS_DHPARAMS_FILE);
        errno = ENOENT;
        return -1;
    }
    if ((dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL)) == NULL) {
        die(400, LOG_ERR, "Invalid DH parameters file " TLS_DHPARAMS_FILE);
    }
    SSL_CTX_set_tmp_dh(tls_ctx, dh);
    DH_free(dh);
    BIO_free(bio);

    return 0;
}

static void tls_init_dhparams(void)
{
# ifdef SSL_CTRL_SET_DH_AUTO
    if (tls_load_dhparams() != 0) {
        SSL_CTX_ctrl(tls_ctx, SSL_CTRL_SET_DH_AUTO, 1, NULL);
    }
# else
    if (tls_load_dhparams() != 0) {
        tls_load_dhparams_default();
    }
# endif
}

static void tls_init_cache(void)
{
    static const char *tls_ctx_id = "pure-ftpd";

    SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(tls_ctx, (unsigned char *) tls_ctx_id,
                                   (unsigned int) strlen(tls_ctx_id));
    SSL_CTX_sess_set_cache_size(tls_ctx, 10);
    SSL_CTX_set_timeout(tls_ctx, 60 * 60L);
}

static void tls_init_options(void)
{
    static int passes;

# ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    SSL_CTX_set_options(tls_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
# endif
# ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
# endif
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv3);
# ifdef SSL_OP_NO_TLSv1
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_TLSv1);
# endif
# ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_TLSv1_1);
# endif
# ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(tls_ctx, SSL_OP_NO_TLSv1_2);
# endif
# ifdef SSL_OP_NO_TLSv1_3
    SSL_CTX_clear_options(tls_ctx, SSL_OP_NO_TLSv1_3);
# endif
    if (tlsciphersuite != NULL) {
        if (SSL_CTX_set_cipher_list(tls_ctx, tlsciphersuite) != 1) {
            logfile(LOG_ERR, MSG_TLS_CIPHER_FAILED, tlsciphersuite);
            _EXIT(EXIT_FAILURE);
        }
    }
    SSL_CTX_set_info_callback(tls_ctx, ssl_info_cb);
    if (passes == 0) {
        SSL_CTX_set_tlsext_servername_callback(tls_ctx, ssl_servername_cb);
        passes++;
    }
    SSL_CTX_set_verify_depth(tls_ctx, MAX_CERTIFICATE_DEPTH);
}

static void tls_load_cert_file(const char * const cert_file,
                               const char * const key_file)
{
    if (SSL_CTX_use_certificate_chain_file(tls_ctx, cert_file) != 1) {
        die(421, LOG_ERR,
            MSG_FILE_DOESNT_EXIST ": [%s]", cert_file);
    }
    if (SSL_CTX_use_PrivateKey_file(tls_ctx, key_file,
                                    SSL_FILETYPE_PEM) != 1) {
        die(421, LOG_ERR,
            MSG_FILE_DOESNT_EXIST ": [%s]", key_file);
    }
    if (SSL_CTX_check_private_key(tls_ctx) != 1) {
        tls_error(__LINE__, 0);
    }
}

static void tls_init_client_cert_verification(const char *cert_file)
{
    if (cert_file == NULL) {
        tls_error(__LINE__, 0);
    }
    SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                       SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(tls_ctx, cert_file, NULL) != 1) {
        tls_error(__LINE__, 0);
    }
}

static int tls_create_new_context(const char *cert_file,
                                  const char *key_file)
{
# ifdef HAVE_TLS_SERVER_METHOD
    if ((tls_ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
        tls_error(__LINE__, 0);
    }
# else
    if ((tls_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        tls_error(__LINE__, 0);
    }
# endif
    tls_init_options();
    tls_init_cache();
    tls_load_cert_file(cert_file, key_file);
    if (ssl_verify_client_cert) {
        tls_init_client_cert_verification(cert_file);
    }
    tls_init_ecdh_curve();
    tls_init_dhparams();

    return 0;
}

static void tls_init_rnd(void)
{
    unsigned int rnd;

    while (RAND_status() == 0) {
        rnd = zrand();
        RAND_seed(&rnd, (int) sizeof rnd);
    }
}

int tls_init_library(void)
{
    tls_cnx = NULL;
    tls_data_cnx = NULL;
    tls_ctx = NULL;

# if (OPENSSL_VERSION_NUMBER < 0x10100000L) || !defined(OPENSSL_INIT_LOAD_SSL_STRINGS)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
# else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS |
                        OPENSSL_INIT_LOAD_CONFIG, NULL);
# endif
    tls_init_rnd();
    tls_create_new_context(cert_file, key_file);
    tls_cnx_handshook = 0;
    tls_data_cnx_handshook = 0;

    return 0;
}

void tls_free_library(void)
{
    if (tls_data_cnx != NULL) {
        tls_close_session(&tls_data_cnx);
    }
    if (tls_cnx != NULL) {
        SSL_free(tls_cnx);
        tls_cnx = NULL;
    }
    if (tls_ctx != NULL) {
        SSL_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }
# if OPENSSL_API_COMPAT < 0x10100000L
    EVP_cleanup();
# endif
}

int tls_init_new_session(void)
{
    const SSL_CIPHER *cipher;
    int ret;
    int ret_;

    if (tls_ctx == NULL || (tls_cnx = SSL_new(tls_ctx)) == NULL) {
        tls_error(__LINE__, 0);
    }
    if (SSL_set_fd(tls_cnx, clientfd) != 1) {
        tls_error(__LINE__, 0);
    }
    SSL_set_accept_state(tls_cnx);
    for (;;) {
        ret = SSL_accept(tls_cnx);
        if (ret != 1) {
            ret_ = SSL_get_error(tls_cnx, ret);
            if (ret == -1 &&
                (ret_ == SSL_ERROR_WANT_READ ||
                 ret_ == SSL_ERROR_WANT_WRITE)) {
                continue;
            }
            die(400, LOG_WARNING, MSG_TLS_NEEDED);
        }
        break;
    }
    if ((cipher = SSL_get_current_cipher(tls_cnx)) != NULL) {
        int strength_bits = SSL_CIPHER_get_bits(cipher, NULL);

        logfile(LOG_INFO, MSG_TLS_INFO, SSL_CIPHER_get_version(cipher),
                SSL_CIPHER_get_name(cipher), strength_bits);
        if (strength_bits < MINIMAL_CIPHER_STRENGTH_BITS) {
            die(534, LOG_ERR, MSG_TLS_WEAK);
        }
    }
    return 0;
}

int tls_init_data_session(const int fd, const int passive)
{
    const SSL_CIPHER *cipher;
    int ret;
    int ret_;

    (void) passive;
    if (tls_ctx == NULL) {
        logfile(LOG_ERR, MSG_TLS_NO_CTX);
        tls_error(__LINE__, 0);
    }
    if (tls_data_cnx != NULL) {
        tls_close_session(&tls_data_cnx);
    } else if ((tls_data_cnx = SSL_new(tls_ctx)) == NULL) {
        tls_error(__LINE__, 0);
    }
    if (SSL_set_fd(tls_data_cnx, fd) != 1) {
        tls_error(__LINE__, 0);
    }
    SSL_set_accept_state(tls_data_cnx);
    for (;;) {
        ret = SSL_accept(tls_data_cnx);
        if (ret <= 0) {
            ret_ = SSL_get_error(tls_data_cnx, ret);
            if (ret == -1 && (ret_ == SSL_ERROR_WANT_READ ||
                              ret_ == SSL_ERROR_WANT_WRITE)) {
                continue;
            }
            logfile(LOG_INFO, MSG_LOGOUT);
            _EXIT(EXIT_FAILURE);
        }
        break;
    }
    if ((cipher = SSL_get_current_cipher(tls_data_cnx)) != NULL) {
        int strength_bits = SSL_CIPHER_get_bits(cipher, NULL);

        logfile(LOG_INFO, MSG_TLS_INFO, SSL_CIPHER_get_version(cipher),
                SSL_CIPHER_get_name(cipher), strength_bits);
        if (strength_bits < MINIMAL_CIPHER_STRENGTH_BITS) {
            die(534, LOG_ERR, MSG_TLS_WEAK);
        }
    }
    return 0;
}

void tls_close_session(SSL ** const cnx)
{
    unsigned int retries = 10U;
    unsigned int max_shutdowns = 2;

    if (*cnx == NULL) {
        return;
    }
retry:
    switch (SSL_shutdown(*cnx)) {
    case 0:
        if (--max_shutdowns > 0) {
            goto retry;
        }
    case 1:
        break;
    default: {
        switch (SSL_get_error(*cnx, -1)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE: {
            struct pollfd pfd;
            pfd.fd = SSL_get_fd(*cnx);
            pfd.events = POLLIN | POLLOUT | POLLERR | POLLHUP;
            pfd.revents = 0;
            if (poll(&pfd, 1U, idletime * 1000UL) > 0 && retries-- > 0U) {
                goto retry;
            }
          }
        }
        if (SSL_clear(*cnx) == 1) {
            break;
        }
        tls_error(__LINE__, 0);
      }
    }
    if (*cnx == tls_cnx) {
        tls_cnx_handshook = 0;
    } else if (*cnx == tls_data_cnx) {
        tls_data_cnx_handshook = 0;
    }
    SSL_free(*cnx);
    *cnx = NULL;
}

#endif
