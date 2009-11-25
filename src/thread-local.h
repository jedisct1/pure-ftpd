#ifndef __THREAD_LOCAL_H__
#define __THREAD_LOCAL_H__ 1
    
#define THREAD_LOCAL(LOCAL_VAR) \
        (((ThreadLocal *) pthread_getspecific(thread_key))->_ ## LOCAL_VAR)

typedef struct ThreadLocal_ {
#define LOCAL_clientfd THREAD_LOCAL(clientfd)
        int _clientfd;

#define LOCAL_datafd THREAD_LOCAL(datafd)
        int _datafd;

#define LOCAL_xferfd THREAD_LOCAL(xferfd)
        int _xferfd;
} ThreadLocal;

#include <pthread.h>
#ifdef DEFINE_GLOBALS
pthread_key_t thread_key;
ThreadLocal thread_local;
#else
extern pthread_key_t thread_key;
extern ThreadLocal thread_local;
#endif

#endif
