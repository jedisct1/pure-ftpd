#ifndef __TLS_H__
#define __TLS_H__ 1

#ifdef WITH_TLS

# include <openssl/ssl.h>
# include <openssl/dh.h>
# include <openssl/bn.h>
# include <openssl/err.h>
# include <openssl/rand.h>
# ifdef HAVE_OPENSSL_EC_H
#  include <openssl/ec.h>
# endif

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
    int tls_cnx_handshook;

# ifndef IN_TLS_C
extern
# endif
    SSL *tls_data_cnx;

# ifndef IN_TLS_C
extern
# endif
    int tls_data_cnx_handshook;

/* The minimal number of bits we accept for a cipher */
# define MINIMAL_CIPHER_STRENGTH_BITS 128

# define MAX_CERTIFICATE_DEPTH 6

#endif
#endif
