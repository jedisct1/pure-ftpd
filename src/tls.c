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
# include "globals.h"
# include "alt_arc4random.h"

# ifndef DISABLE_SSL_RENEGOTIATION
#  ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#   ifndef ACCEPT_SSL_RENEGOTIATION
#    define DISABLE_SSL_RENEGOTIATION 1
#   endif
#  else
#   ifdef ACCEPT_SSL_RENEGOTIATION
#    define DISABLE_SSL_RENEGOTIATION 0
#   endif
#  endif
# endif

/*
 * Unfortunately disabled by default, because it looks like a lot of clients
 * don't support this properly yet.
 * Feel free to enable it if none of your customers complains.
 */
# ifndef ONLY_ACCEPT_REUSED_SSL_SESSIONS
#  define ONLY_ACCEPT_REUSED_SSL_SESSIONS 0
# endif

static void tls_error(const int line, int err)
{
    if (err == 0) {
        err = ERR_get_error();
    }
    if (err != 0) {
        logfile(LOG_ERR, "TLS [%s](%d): %s",
                TLS_CERTIFICATE_FILE, line,
                ERR_error_string(err, NULL));
    }
    _EXIT(EXIT_FAILURE);
}

static int tls_init_ecdh_curve(void)
{
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
}

static int tls_init_dhparams_default(void)
{
    static const unsigned char RFC3526_PRIME_2048[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
        0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
        0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
        0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
        0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF
    };
    static const unsigned char GENERATOR[] = {
        0x02
    };
    DH *dh;

    dh = DH_new();
    if (dh == NULL) {
        die_mem();
    }
    dh->p = BN_bin2bn(RFC3526_PRIME_2048, sizeof RFC3526_PRIME_2048, NULL);
    dh->g = BN_bin2bn(GENERATOR, sizeof GENERATOR, NULL);
    if (dh->p == NULL || dh->g == NULL) {
        die_mem();
    }
    SSL_CTX_set_tmp_dh(tls_ctx, dh);
    DH_free(dh);

    return 0;
}

static int tls_init_dhparams(void)
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

static void tls_init_cache(void)
{
    static const char *tls_ctx_id = "pure-ftpd";

    SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(tls_ctx, (unsigned char *) tls_ctx_id,
                                   (unsigned int) strlen(tls_ctx_id));
    SSL_CTX_sess_set_cache_size(tls_ctx, 10);
    SSL_CTX_set_timeout(tls_ctx, 60 * 60L);
}

# ifdef DISABLE_SSL_RENEGOTIATION
static void ssl_info_cb(const SSL *cnx, int where, int ret)
{
    (void) ret;

#  if DISABLE_SSL_RENEGOTIATION == 1
    if ((where & SSL_CB_HANDSHAKE_START) != 0) {
        if ((cnx == tls_cnx && tls_cnx_handshook != 0) ||
            (cnx == tls_data_cnx && tls_data_cnx_handshook != 0)) {
            die(400, LOG_ERR, "TLS renegociation");
        }
        return;
    }
#  endif
    if ((where & SSL_CB_HANDSHAKE_DONE) != 0) {
        if (cnx == tls_cnx) {
            tls_cnx_handshook = 1;
        } else if (cnx == tls_data_cnx) {
            tls_data_cnx_handshook = 1;
        }
#  if DISABLE_SSL_RENEGOTIATION == 0
        cnx->s3->flags &= ~(SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS);
        cnx->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
#  else
        cnx->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
#  endif
        return;
    }
}
# endif

int tls_init_library(void)
{
    unsigned int rnd;

    tls_cnx_handshook = 0;
    tls_data_cnx_handshook = 0;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    while (RAND_status() == 0) {
        rnd = zrand();
        RAND_seed(&rnd, (int) sizeof rnd);
    }
    if ((tls_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        tls_error(__LINE__, 0);
    }
# ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    SSL_CTX_set_options(tls_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
# endif
# ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    SSL_CTX_set_options(tls_ctx,
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
# endif
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv3);
# ifdef SSL_OP_NO_TLSv1
    SSL_CTX_clear_options(tls_ctx, SSL_OP_NO_TLSv1);
# endif
# ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(tls_ctx, SSL_OP_NO_TLSv1_1);
# endif
# ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(tls_ctx, SSL_OP_NO_TLSv1_2);
# endif
    if (tlsciphersuite != NULL) {
        if (SSL_CTX_set_cipher_list(tls_ctx, tlsciphersuite) != 1) {
            logfile(LOG_ERR, MSG_TLS_CIPHER_FAILED, tlsciphersuite);
            _EXIT(EXIT_FAILURE);
        }
    }
    if (SSL_CTX_use_certificate_chain_file(tls_ctx,
                                           TLS_CERTIFICATE_FILE) != 1) {
        die(421, LOG_ERR,
            MSG_FILE_DOESNT_EXIST ": [%s]", TLS_CERTIFICATE_FILE);
    }
    if (SSL_CTX_use_PrivateKey_file(tls_ctx, TLS_CERTIFICATE_FILE,
                                    SSL_FILETYPE_PEM) != 1) {
        tls_error(__LINE__, 0);
    }
    if (SSL_CTX_check_private_key(tls_ctx) != 1) {
        tls_error(__LINE__, 0);
    }
    tls_init_cache();
# ifdef SSL_CTRL_SET_ECDH_AUTO
    SSL_CTX_ctrl(tls_ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
# else
    tls_init_ecdh_curve();
# endif
# ifdef SSL_CTRL_SET_DH_AUTO
    if (tls_init_dhparams() != 0) {
        SSL_CTX_ctrl(tls_ctx, SSL_CTRL_SET_DH_AUTO, 1, NULL);
    }
# else
    if (tls_init_dhparams() != 0) {
        tls_init_dhparams_default();
    }
# endif
# ifdef DISABLE_SSL_RENEGOTIATION
    SSL_CTX_set_info_callback(tls_ctx, ssl_info_cb);
# endif
    SSL_CTX_set_verify_depth(tls_ctx, 6);
    if (ssl_verify_client_cert) {
        SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                           SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_load_verify_locations(tls_ctx,
                                          TLS_CERTIFICATE_FILE, NULL) != 1) {
            tls_error(__LINE__, 0);
        }
    }
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
    EVP_cleanup();
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
# if ONLY_ACCEPT_REUSED_SSL_SESSIONS
    if (SSL_session_reused(tls_data_cnx) == 0) {
        tls_error(__LINE__, 0);
    }
# endif
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
    if (*cnx == NULL) {
        return;
    }
    switch (SSL_shutdown(*cnx)) {
    case 0:
        SSL_shutdown(*cnx);
    case SSL_SENT_SHUTDOWN:
    case SSL_RECEIVED_SHUTDOWN:
        break;

    default:
        if (SSL_clear(*cnx) == 1) {
            break;
        }
        tls_error(__LINE__, 0);
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
