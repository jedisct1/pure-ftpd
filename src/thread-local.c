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
    pthread_key_create(&thread_key, NULL);
    pthread_setspecific(thread_key, &thread_local);
    LOCAL_INIT(passive);
    LOCAL_INIT(clientfd);
    LOCAL_INIT(datafd);
    LOCAL_AINIT(cmd);
    LOCAL_INIT(ctrlconn);    
    LOCAL_INIT(xferfd);
#ifdef WITH_TLS
    LOCAL_INIT(tls_ctx);
    LOCAL_INIT(tls_cnx);
    LOCAL_INIT(tls_cnx_handshaked);
    LOCAL_INIT(tls_data_cnx);    
    LOCAL_INIT(tls_data_cnx_handshaked);
#endif
    
    return 0;
}
