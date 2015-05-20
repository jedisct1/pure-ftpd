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

static int tls_init_dhparams(void)
{
    BIO *bio;
    DH *dh;

    if ((bio = BIO_new_file(TLS_DHPARAMS_FILE, "r")) == NULL) {
        logfile(LOG_INFO,
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
# ifdef SSL_CTRL_SET_DH_AUTO
    SSL_CTX_ctrl(tls_ctx, SSL_CTRL_SET_DH_AUTO, 1, NULL);
# endif
# ifdef SSL_CTRL_SET_ECDH_AUTO
    SSL_CTX_ctrl(tls_ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
# endif
    tls_init_dhparams();
    tls_init_cache();
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
