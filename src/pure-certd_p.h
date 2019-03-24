#ifndef __PURE_CERTD_P_H__
#define __PURE_CERTD_P_H__ 1

#ifdef WITH_TLS

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

#ifndef CERTD_BACKLOG
# define CERTD_BACKLOG 42
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
static const char *certd_pid_file = CERTD_PID_FILE;
static const char *script;
static volatile signed char exit_certd;
static volatile int kindy = -1;
static volatile signed char ended;

static void callback_client_sni_name(const char *str);
static void callback_client_end(const char *str);

typedef struct CertdCallBack_ {
    const char *keyword;
    void (*func)(const char *str);
} CertdCallBack;

static CertdCallBack certd_callbacks[] = {
    { EXTCERT_CLIENT_SNI_NAME, callback_client_sni_name } ,
    { EXTCERT_CLIENT_END, callback_client_end },
    { NULL, callback_client_end }
};

#define ENV_CERTD_SNI_NAME "CERTD_SNI_NAME"

#define CERTD_SCRIPT_TIMEOUT 60U

#endif

#endif
