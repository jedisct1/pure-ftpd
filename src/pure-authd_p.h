#ifndef __PURE_AUTHD_P_H__
#define __PURE_AUTHD_P_H__ 1

#ifdef WITH_EXTAUTH

#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include <sys/un.h>

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) NULL)->sun_path) \
                           + strlen((ptr)->sun_path))
#endif

#ifndef AUTHD_BACKLOG
# define AUTHD_BACKLOG 42
#endif

static const char *GETOPT_OPTIONS =
    "Bg:"
#ifndef NO_GETOPT_LONG
    "h"
#endif
    "p:r:s:u:";

#ifndef NO_GETOPT_LONG
static struct option long_options[] = {
    { "daemonize", 0, NULL, 'B' },
    { "gid", 1, NULL, 'g' },
# ifndef NO_GETOPT_LONG
    { "help", 0, NULL, 'h' },
# endif
    { "pidfile", 1, NULL, 'p' },
    { "run", 1, NULL, 'r' },
    { "socket", 1, NULL, 's' },
    { "uid", 1, NULL, 'u' },
    { NULL, 0, NULL, 0 }    
};
#endif

static signed char daemonize;
static uid_t uid;
static gid_t gid;
static const char *socketpath;
static const char *authd_pid_file = AUTHD_PID_FILE;
static const char *script;
static volatile signed char exit_authd;
static volatile int kindy = -1;
static volatile signed char ended;

static void callback_client_account(const char *str);
static void callback_client_password(const char *str);
static void callback_client_sa_host(const char *str);
static void callback_client_sa_port(const char *str);
static void callback_client_peer_host(const char *str);
static void callback_client_encrypted(const char *str);
static void callback_client_end(const char *str);

typedef struct ExtauthdCallBack_ {
    const char *keyword;
    void (*func)(const char *str);
} ExtauthdCallBack;

static ExtauthdCallBack extauthd_callbacks[] = {
    { EXTAUTH_CLIENT_ACCOUNT, callback_client_account } , 
    { EXTAUTH_CLIENT_PASSWORD, callback_client_password },
    { EXTAUTH_CLIENT_SA_HOST, callback_client_sa_host },
    { EXTAUTH_CLIENT_SA_PORT, callback_client_sa_port },
    { EXTAUTH_CLIENT_PEER_HOST, callback_client_peer_host },
    { EXTAUTH_CLIENT_ENCRYPTED, callback_client_encrypted },
    { EXTAUTH_CLIENT_END, callback_client_end },
    { NULL, callback_client_end }
};

#define ENV_AUTHD_ACCOUNT "AUTHD_ACCOUNT"
#define ENV_AUTHD_PASSWORD "AUTHD_PASSWORD"
#define ENV_AUTHD_SA_HOST "AUTHD_LOCAL_IP"
#define ENV_AUTHD_SA_PORT "AUTHD_LOCAL_PORT"
#define ENV_AUTHD_PEER_HOST "AUTHD_REMOTE_IP"
#define ENV_AUTHD_ENCRYPTED "AUTHD_ENCRYPTED"

#define AUTHD_SCRIPT_TIMEOUT 60U

#endif

#endif
