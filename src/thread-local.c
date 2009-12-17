#include <config.h>
#include "ftpd.h"
#include "dynamic.h"
#include "ftpwho-update.h"
#include "ftpwho-read.h"
#include "globals.h"
#ifdef WITH_TLS
# include "tls.h"
#endif
#include "thread-local.h"

#ifdef __IPHONE__

int init_thread_local_storage(void)
{
    thread_children = NULL;    
    return 0;
}

void free_thread_local_storage(void)
{
    ThreadChild *thread_child = thread_children;
    ThreadChild *next_thread_child = thread_children;
    void *ret;
    
    while (thread_child != NULL) {
        pthread_cancel(thread_child->child);
        pthread_join(thread_child->child, &ret);
        next_thread_child = thread_child->next;
        thread_child->next = NULL;
        free(thread_child);
        thread_child = next_thread_child;
    }
    thread_children = NULL;
}

int alloc_thread_local_storage(void)
{
    ThreadLocal *thread_local;
        
    thread_local = malloc(sizeof *thread_local);
    memset(thread_local, 0, sizeof thread_local);
    if (thread_key == (pthread_key_t) 0) {
        pthread_key_create(&thread_key, NULL);
    }
    pthread_setspecific(thread_key, thread_local);
    LOCAL_INIT(passive);
    LOCAL_INIT(clientfd);
    LOCAL_INIT(datafd);
    LOCAL_AINIT(cmd);
    LOCAL_AINIT(wd);
    LOCAL_AINIT(account);
    LOCAL_AINIT(host);
    LOCAL_INIT(root_directory);
    LOCAL_INIT(loggedin);
    LOCAL_INIT(renamefrom);
    LOCAL_INIT(candownload);
    LOCAL_INIT(guest);
    LOCAL_INIT(chrooted);
    LOCAL_INIT(type);
    LOCAL_INIT(restartat);
    LOCAL_INIT(replycode);    
    LOCAL_INIT(peer);
    LOCAL_INIT(peerdataport);    
    LOCAL_INIT(ctrlconn);
    LOCAL_INIT(xferfd);
    LOCAL_INIT(authresult);
    LOCAL_INIT(session_start_time);
#ifdef WITH_TLS
    LOCAL_INIT(tls_ctx);
    LOCAL_INIT(tls_cnx);
    LOCAL_INIT(tls_cnx_handshaked);
    LOCAL_INIT(tls_data_cnx);    
    LOCAL_INIT(tls_data_cnx_handshaked);
#endif
#ifdef WITH_VIRTUAL_CHROOT
    LOCAL_AINIT(curdir);
    LOCAL_INIT(chroot_base);
    LOCAL_INIT(chroot_len);    
#endif
    
    return 0;
}

int spawn_client_thread(void)
{
    ThreadChild *thread_child;
    ThreadLocal *thread_local;        
    
    thread_child = malloc(sizeof *thread_child);
    thread_child->next = NULL;
    thread_local = (ThreadLocal *) pthread_getspecific(thread_key);
    if (pthread_create(&thread_child->child, NULL,
                       client_thread, thread_local) != 0) {
        free(thread_child);
        return -1;
    }
    if (thread_children == NULL) {
        thread_children = thread_child;
    } else {
        thread_children->next = thread_child;
    }
    return 0;
}

#else

extern signed char v6ready;

#endif
