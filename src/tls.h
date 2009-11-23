#ifndef __TLS_H__
#define __TLS_H__ 1

#ifdef WITH_TLS

# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>

int tls_init_library(void);
void tls_free_library(void);
int tls_init_new_session(void);
int tls_init_data_session(const int fd, const int passive);
void tls_close_session(SSL **cnx);

# ifndef IN_TLS_C
extern
# endif
    SSL_CTX *tls_ctx;

# ifndef IN_TLS_C
extern
# endif
    SSL *tls_cnx;

# ifndef IN_TLS_C
extern
# endif
    int tls_cnx_handshaked;

# ifndef IN_TLS_C
extern
# endif
    SSL *tls_data_cnx;

# ifndef IN_TLS_C
extern
# endif
    int tls_data_cnx_handshaked;

/* The minimal number of bits we accept for a cipher */
# define MINIMAL_CIPHER_KEY_LEN 40

#endif
#endif
