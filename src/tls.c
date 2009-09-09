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

static int tls_init_diffie(void)
{
    DH *dh;
    BIO *bio;

    if ((bio = BIO_new_file(TLS_CERTIFICATE_FILE, "r")) == NULL) {
        logfile(LOG_ERR, "SSL/TLS: Can't read [%s]",
                TLS_CERTIFICATE_FILE);
        return -1;
    }
    if ((dh = PEM_read_bio_DHparams(bio, NULL, NULL
# if OPENSSL_VERSION_NUMBER >= 0x00904000L
                                    , NULL
# endif
                                    )) == NULL) {
        BIO_free(bio);
        logfile(LOG_DEBUG, "SSL/TLS: Can't read DH parameters");
        return 1;
    }
    if (SSL_CTX_set_tmp_dh(tls_ctx, dh) != 1) {
        logfile(LOG_ERR, "SSL/TLS: Can't set ephemeral keys");
        return -1;
    }
    DH_free(dh);    
    BIO_free(bio);

    return 0;
}

static void tls_init_cache(void)
{
    SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_SERVER);
}

int tls_init_library(void) 
{
    const char *tls_ctx_id = "pure-ftpd";    
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
    tls_init_cache();
    SSL_CTX_set_options(tls_ctx, SSL_OP_ALL);    
    if (SSL_CTX_use_certificate_chain_file(tls_ctx,
                                           TLS_CERTIFICATE_FILE) != 1) {
        die(421, LOG_ERR,
            MSG_FILE_DOESNT_EXIST ": [%s]", TLS_CERTIFICATE_FILE);
    }
    if (SSL_CTX_use_PrivateKey_file(tls_ctx, TLS_CERTIFICATE_FILE,
                                    X509_FILETYPE_PEM) != 1) {
        tls_error(__LINE__, 0);
    }
    if (SSL_CTX_check_private_key(tls_ctx) != 1) {
        tls_error(__LINE__, 0);
    }
    if (SSL_CTX_need_tmp_RSA(tls_ctx)) {
        RSA *ephemeral_key;

        if ((ephemeral_key = RSA_generate_key(RSA_EPHEMERAL_KEY_LEN, 
                                              RSA_F4, NULL, NULL)) == NULL) {
            tls_error(__LINE__, 0);
        }
        if (SSL_CTX_set_tmp_rsa(tls_ctx, ephemeral_key) != 1) {
            tls_error(__LINE__, 0);
        }
        RSA_free(ephemeral_key);
    }
    if (tls_init_diffie() < 0) {
        tls_error(__LINE__, 0);
    }
#ifdef REQUIRE_VALID_CLIENT_CERTIFICATE
    SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
    if (SSL_CTX_load_verify_locations(tls_ctx,
                                      TLS_CERTIFICATE_FILE, NULL) != 0) {
        tls_error(__LINE__, 0);
    }
#endif
    SSL_CTX_set_session_id_context(tls_ctx, (unsigned char *) tls_ctx_id,
                                   (unsigned int) strlen(tls_ctx_id));
    
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
    
    if (tls_ctx == NULL ||
        (tls_cnx = SSL_new(tls_ctx)) == NULL) {
        tls_error(__LINE__, 0);
    }
    if (SSL_set_rfd(tls_cnx, 0) != 1 ||
        SSL_set_wfd(tls_cnx, 1) != 1) {
        tls_error(__LINE__, 0);
    }
    SSL_set_accept_state(tls_cnx);
    for (;;) {
        if ((ret = SSL_accept(tls_cnx)) <= 0) {
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

int tls_init_data_session(int fd)
{
    SSL_CIPHER *cipher;
    int ret;
    int ret_;

    if (tls_ctx == NULL) {
        logfile(LOG_ERR, MSG_TLS_NO_CTX);
        tls_error(__LINE__, 0);
    }    
    if (tls_data_cnx != NULL) {
        tls_close_session(&tls_data_cnx);
    }    
    if (tls_data_cnx == NULL) {
        if ((tls_data_cnx = SSL_new(tls_ctx)) == NULL) {
            tls_error(__LINE__, 0);
        }
    }    
    if (SSL_set_fd(tls_data_cnx, fd) != 1) {
        tls_error(__LINE__, 0);
    }    
    SSL_set_accept_state(tls_data_cnx);
    for (;;) {
        if ((ret = SSL_accept(tls_data_cnx)) <= 0) {
            ret_ = SSL_get_error(tls_data_cnx, ret);
            if (ret == -1 && (ret_ == SSL_ERROR_WANT_READ ||
                              ret_ == SSL_ERROR_WANT_WRITE)) {
                continue;
            }
            tls_error(__LINE__, ret_);
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
