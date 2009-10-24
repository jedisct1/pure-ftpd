#include <config.h>

#ifdef WITH_TLS
# ifndef IN_TLS_C
#  define IN_TLS_C 1
# endif

# include "ftpd.h"
# include "tls.h"
# include "ftpwho-update.h"
# include "messages.h"

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
        logfile(LOG_ERR, "SSL/TLS [%s](%d): %s", 
                TLS_CERTIFICATE_FILE, line,
                ERR_error_string(err, NULL));
    }
    _EXIT(EXIT_FAILURE);
}

DH *get_dh512(void)
{
    static unsigned char dh512_p[]={
        0xF5,0x2A,0xFF,0x3C,0xE1,0xB1,0x29,0x40,0x18,0x11,0x8D,0x7C,
        0x84,0xA7,0x0A,0x72,0xD6,0x86,0xC4,0x03,0x19,0xC8,0x07,0x29,
        0x7A,0xCA,0x95,0x0C,0xD9,0x96,0x9F,0xAB,0xD0,0x0A,0x50,0x9B,
        0x02,0x46,0xD3,0x08,0x3D,0x66,0xA4,0x5D,0x41,0x9F,0x9C,0x7C,
        0xBD,0x89,0x4B,0x22,0x19,0x26,0xBA,0xAB,0xA2,0x5E,0xC3,0x55,
        0xE9,0x2A,0x05,0x5F,
    };
    static unsigned char dh512_g[]={
        0x02,
    };
    DH *dh;

    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
    { DH_free(dh); return(NULL); }
    return(dh);
}

DH *get_dh1024(void)
{
    static unsigned char dh1024_p[]={
        0xF4,0x88,0xFD,0x58,0x4E,0x49,0xDB,0xCD,0x20,0xB4,0x9D,0xE4,
        0x91,0x07,0x36,0x6B,0x33,0x6C,0x38,0x0D,0x45,0x1D,0x0F,0x7C,
        0x88,0xB3,0x1C,0x7C,0x5B,0x2D,0x8E,0xF6,0xF3,0xC9,0x23,0xC0,
        0x43,0xF0,0xA5,0x5B,0x18,0x8D,0x8E,0xBB,0x55,0x8C,0xB8,0x5D,
        0x38,0xD3,0x34,0xFD,0x7C,0x17,0x57,0x43,0xA3,0x1D,0x18,0x6C,
        0xDE,0x33,0x21,0x2C,0xB5,0x2A,0xFF,0x3C,0xE1,0xB1,0x29,0x40,
        0x18,0x11,0x8D,0x7C,0x84,0xA7,0x0A,0x72,0xD6,0x86,0xC4,0x03,
        0x19,0xC8,0x07,0x29,0x7A,0xCA,0x95,0x0C,0xD9,0x96,0x9F,0xAB,
        0xD0,0x0A,0x50,0x9B,0x02,0x46,0xD3,0x08,0x3D,0x66,0xA4,0x5D,
        0x41,0x9F,0x9C,0x7C,0xBD,0x89,0x4B,0x22,0x19,0x26,0xBA,0xAB,
        0xA2,0x5E,0xC3,0x55,0xE9,0x2F,0x78,0xC7,
    };
    static unsigned char dh1024_g[]={
        0x02,
    };
    DH *dh;

    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
    dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
    { DH_free(dh); return(NULL); }
    return(dh);
}

static DH *cb_tmp_dh(SSL * const ctx, const int for_export,
                     const int key_length)
{
    (void) ctx;
    if (for_export == 0 || key_length >= 1024) {
        return get_dh1024();
    }
    return get_dh512();
}

static int tls_init_diffie(void)
{
    DH *dh = NULL;
    BIO *bio = NULL;
    int ret = 0;

    if ((bio = BIO_new_file(TLS_CERTIFICATE_FILE, "r")) == NULL) {
        logfile(LOG_ERR, "SSL/TLS: Can't read [%s]",
                TLS_CERTIFICATE_FILE);
        ret = -1;
        goto end;
    }
    if ((dh = PEM_read_bio_DHparams(bio, NULL, NULL
# if OPENSSL_VERSION_NUMBER >= 0x00904000L
                                    , NULL
# endif
                                    )) == NULL) {
        ret = 1;
        goto end;
    }
    if (SSL_CTX_set_tmp_dh(tls_ctx, dh) != 1) {
        logfile(LOG_ERR, "SSL/TLS: Can't set ephemeral keys");
        ret = -1;
    }
    end:
    if (dh != NULL) {
        DH_free(dh);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }    
    if (ret != 0) {
        SSL_CTX_set_tmp_dh_callback(tls_ctx, cb_tmp_dh);
    }
    return 0;
}

static RSA *get_rsa(const unsigned long key_length)
{
    return RSA_generate_key(key_length, RSA_F4, NULL, NULL);
}

static RSA *cb_tmp_rsa(SSL * const ctx,
                       const int for_export, const int key_length)

{
    (void) ctx;
    if (for_export == 0 || key_length >= 1024) {
        return get_rsa(1024);
    }
    return get_rsa(512);
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

int tls_init_library(void) 
{
    unsigned int rnd;
    
    SSL_library_init();
    SSL_load_error_strings();
    while (RAND_status() == 0) {
        rnd = zrand();
        RAND_seed(&rnd, (int) sizeof rnd);
    }
    if ((tls_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        tls_error(__LINE__, 0);
    }
# ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
# else
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_ALL);
# endif

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
    SSL_CTX_set_tmp_rsa_callback(tls_ctx, cb_tmp_rsa);
    if (tls_init_diffie() < 0) {
        tls_error(__LINE__, 0);
    }
    tls_init_cache();
#ifdef REQUIRE_VALID_CLIENT_CERTIFICATE
    SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
    if (SSL_CTX_load_verify_locations(tls_ctx,
                                      TLS_CERTIFICATE_FILE, NULL) != 0) {
        tls_error(__LINE__, 0);
    }
#endif    
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
}

int tls_init_new_session(void)
{
    SSL_CIPHER *cipher;
    int ret;
    int ret_;
    
    if (tls_ctx == NULL || (tls_cnx = SSL_new(tls_ctx)) == NULL) {
        tls_error(__LINE__, 0);
    }
    if (SSL_set_rfd(tls_cnx, 0) != 1 || SSL_set_wfd(tls_cnx, 1) != 1) {
        tls_error(__LINE__, 0);
    }
    SSL_set_accept_state(tls_cnx);    
    for (;;) {
        ret = SSL_accept(tls_cnx);        
        if (ret <= 0) {
            ret_ = SSL_get_error(tls_cnx, ret);            
            if (ret == -1 &&
                (ret_ == SSL_ERROR_WANT_READ ||
                 ret_ == SSL_ERROR_WANT_WRITE)) {
                continue;
            }
            tls_error(__LINE__, ret_);
        }
        break;
    }
    if ((cipher = SSL_get_current_cipher(tls_cnx)) != NULL) {
        int alg_bits;
        int bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
        
        if (alg_bits < bits) {
            bits = alg_bits;
        }
        logfile(LOG_INFO, MSG_TLS_INFO, SSL_CIPHER_get_version(cipher), 
                SSL_CIPHER_get_name(cipher), bits);
        if (bits < MINIMAL_CIPHER_KEY_LEN) {
            die(534, LOG_ERR, MSG_TLS_WEAK);
        }
    }
    return 0;
}

int tls_init_data_session(const int fd, const int passive)
{
    SSL_CIPHER *cipher;
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
#if ONLY_ACCEPT_REUSED_SSL_SESSIONS
    if (SSL_session_reused(tls_data_cnx) == 0) {
        tls_error(__LINE__, 0);
    }
#endif
    if ((cipher = SSL_get_current_cipher(tls_data_cnx)) != NULL) {
        int alg_bits;
        int bits = SSL_CIPHER_get_bits(cipher, &alg_bits);

        if (alg_bits < bits) {
            bits = alg_bits;
        }
        logfile(LOG_INFO, MSG_TLS_INFO, SSL_CIPHER_get_version(cipher),
                SSL_CIPHER_get_name(cipher), bits);
        if (bits < MINIMAL_CIPHER_KEY_LEN) {
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
    case SSL_SENT_SHUTDOWN:
    case SSL_RECEIVED_SHUTDOWN:
        break;
        
    default:
        if (SSL_clear(*cnx) == 1) {
            break;
        }
        tls_error(__LINE__, 0);
    }
    SSL_free(*cnx);
    *cnx = NULL;
}

#endif
