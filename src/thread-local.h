#ifndef __THREAD_LOCAL_H__
#define __THREAD_LOCAL_H__ 1

#ifdef WITH_TLS
# include <openssl/ssl.h>
#else
typedef void *SSL_CTX;
typedef void *SSL;
#endif

typedef struct ThreadChild_ {
    struct ThreadChild_ *next;
    pthread_t child;
} ThreadChild;

static ThreadChild *thread_children;

#define THREAD_LOCAL(LOCAL_VAR) \
        (((ThreadLocal *) pthread_getspecific(thread_key))->_ ## LOCAL_VAR)

typedef struct ThreadLocal_ {
#define LOCAL_passive THREAD_LOCAL(passive)
    signed char _passive;

#define LOCAL_clientfd THREAD_LOCAL(clientfd)
    int _clientfd;
    
#define LOCAL_datafd THREAD_LOCAL(datafd)
    int _datafd;
    
#define LOCAL_cmd THREAD_LOCAL(cmd)
    char _cmd[MAXPATHLEN + 32U];
    
#define LOCAL_wd THREAD_LOCAL(wd)
    char _wd[MAXPATHLEN + 1U];
    
#define LOCAL_account THREAD_LOCAL(account)
    char _account[MAX_USER_LENGTH + 1U];
    
#define LOCAL_host THREAD_LOCAL(host)
    char _host[NI_MAXHOST];
    
#define LOCAL_root_directory THREAD_LOCAL(root_directory)
    char *_root_directory;
    
#define LOCAL_loggedin THREAD_LOCAL(loggedin)
    signed char _loggedin;
    
#define LOCAL_renamefrom THREAD_LOCAL(renamefrom)
    char *_renamefrom;
    
#define LOCAL_guest THREAD_LOCAL(guest)
    signed char _guest;

#define LOCAL_candownload THREAD_LOCAL(candownload)
    signed char _candownload;

#define LOCAL_chrooted THREAD_LOCAL(chrooted)
    signed char _chrooted;

#define LOCAL_type THREAD_LOCAL(type)
    signed char _type;

#define LOCAL_restartat THREAD_LOCAL(restartat)
    off_t _restartat;

#define LOCAL_replycode THREAD_LOCAL(replycode)
    int _replycode;

#define LOCAL_peer THREAD_LOCAL(peer)
    struct sockaddr_storage _peer;
    
#define LOCAL_peerdataport THREAD_LOCAL(peerdataport)
    in_port_t _peerdataport;
    
#define LOCAL_ctrlconn THREAD_LOCAL(ctrlconn)
    struct sockaddr_storage _ctrlconn;
    
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
    
#define LOCAL_authresult THREAD_LOCAL(authresult)
    AuthResult _authresult;

#define LOCAL_session_start_time THREAD_LOCAL(session_start_time)
    time_t _session_start_time;
    
#define LOCAL_curdir THREAD_LOCAL(curdir)
    char _curdir[MAXPATHLEN];

#define LOCAL_chroot_base THREAD_LOCAL(chroot_base)
    char *_chroot_base;
    
#define LOCAL_chroot_len THREAD_LOCAL(chroot_len)
    size_t _chroot_len;
    
} ThreadLocal;

#include <pthread.h>
#ifdef DEFINE_GLOBALS
pthread_key_t thread_key;
# define TGLOBAL0(A) A ## _LOCAL_INIT
# define TGLOBAL(A, B) A ## _LOCAL_INIT = B
# define TAGLOBAL0(A, S) A ## _LOCAL_INIT[S]
#else
extern pthread_key_t thread_key;
# define TGLOBAL0(A) extern A ## _LOCAL_INIT
# define TGLOBAL(A, B) extern A ## _LOCAL_INIT
# define TAGLOBAL0(A, S) extern A ## _LOCAL_INIT[S]
#endif

#define LOCAL_INIT(A) LOCAL_ ## A = A ## _LOCAL_INIT
#define LOCAL_AINIT(A) *(LOCAL_ ## A) = 0

int init_thread_local_storage(void);
void free_thread_local_storage(void);
int alloc_thread_local_storage(void);
int spawn_client_thread(void);

#endif
