#ifndef __THREAD_LOCAL_H__
#define __THREAD_LOCAL_H__ 1

#ifdef WITH_TLS
# include <openssl/ssl.h>
#else
typedef void *SSL_CTX;
typedef void *SSL;
#endif

#define THREAD_LOCAL(LOCAL_VAR) \
        (((ThreadLocal *) pthread_getspecific(thread_key))->_ ## LOCAL_VAR)

typedef struct ThreadLocal_ {
#define LOCAL_clientfd THREAD_LOCAL(clientfd)
    int _clientfd;
    
#define LOCAL_datafd THREAD_LOCAL(datafd)
    int _datafd;
    
#define LOCAL_xferfd THREAD_LOCAL(xferfd)
    int _xferfd;
    
#define LOCAL_tls_ctx THREAD_LOCAL(tls_ctx)
    SSL_CTX *_tls_ctx;
    
#define LOCAL_tls_cnx THREAD_LOCAL(tls_cnx)
    SSL *_tls_cnx;
    
#define LOCAL_tls_cnx_handshaked THREAD_LOCAL(tls_cnx_handshaked)
    int _tls_cnx_handshaked;
    
#define LOCAL_tls_data_cnx THREAD_LOCAL(tls_data_cnx)
    SSL *_tls_data_cnx;
    
#define LOCAL_tls_data_cnx_handshaked THREAD_LOCAL(tls_data_cnx_handshaked)
    int _tls_data_cnx_handshaked;    
} ThreadLocal;

#include <pthread.h>
#ifdef DEFINE_GLOBALS
pthread_key_t thread_key;
ThreadLocal thread_local;
# define TGLOBAL0(A) A ## _LOCAL_INIT
# define TGLOBAL(A, B) A ## _LOCAL_INIT = B
#else
extern pthread_key_t thread_key;
extern ThreadLocal thread_local;
# define TGLOBAL0(A) extern A ## _LOCAL_INIT
# define TGLOBAL(A, B) extern A ## _LOCAL_INIT
#endif

#define LOCAL_INIT(A) LOCAL_ ## A = A ## _LOCAL_INIT

int init_thread_local_storage(void);

#endif
