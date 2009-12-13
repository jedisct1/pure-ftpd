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

int init_thread_local_storage(void)
{
    ThreadLocal *thread_local;
        
    thread_local = malloc(sizeof *thread_local);
    memset(thread_local, 0, sizeof thread_local);
    if (thread_key == NULL) {
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
