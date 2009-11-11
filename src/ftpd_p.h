#ifndef __FTPD_P_H__
#define __FTPD_P_H__ 1

#include "ftpd.h"
#include "log_unix.h"
#ifdef USE_PAM
# include "log_pam.h"
#endif
#ifdef WITH_LDAP
# include "log_ldap.h"
#endif
#ifdef WITH_MYSQL
# include "log_mysql.h"
#endif
#ifdef WITH_PGSQL
# include "log_pgsql.h"
#endif
#ifdef WITH_PUREDB
# include "log_puredb.h"
#endif
#ifdef WITH_EXTAUTH
# include "log_extauth.h"
#endif

#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef __IPHONE__
# include <setjmp.h>
static jmp_buf jb;
#endif

#define DEFAULT_BACKLOG 42
#define DEFAULT_BACKLOG_DATA 8
#define NICE_VALUE 10
#define THROTTLING_UNIT 10000UL
#define MAX_GROUPS 256
#define MAX_PASSWD_TRIES 5        /* Abort after 5 authentication failures */
#define PASSWD_FAILURE_DELAY (3UL*1000000UL)    /* Delay after each failure */
#define MAX_DIRSCAN_TRIES 50      /* Abort after 50 chdir failures */
#define DIRSCAN_FAILURE_DELAY (100000UL)  /* Delay after each chdir failure */
#define ASCII_CHUNKSIZE 65536U
#define BANNER_MAXLINES 100
#define MAX_SERVER_REPLY_LEN (MAXPATHLEN + (size_t) 50U)

#ifndef NO_STANDALONE
static volatile sig_atomic_t stop_server;
static const char *standalone_port = DEFAULT_FTP_PORT_S;
static const char *standalone_ip;
static volatile unsigned int nb_children;
static volatile int listenfd = -1;
static volatile int listenfd6 = -1;
#endif
#ifdef __IPHONE__
static volatile sig_atomic_t suspend_client_connections;
static AuthResult embedded_simple_pw_check(const char *account, const char *password);
static void (*logout_callback)(void *user_data);
static void *logout_callback_user_data;
static void (*login_callback)(void *user_data);
static void *login_callback_user_data;
static void (*log_callback)(int crit, const char *message, void *user_data);
static void *log_callback_user_data;
static int  (*simple_auth_callback)(const char *account, const char *password, void *user_data);
static void *simple_auth_callback_user_data;
#endif

struct reply {
    struct reply *next;
    char line[1];
};

static const char *GETOPT_OPTIONS =
    "0146"
#ifdef WITH_RFC2640
    "8:9:"
#endif
    "Aa:bc:"
#ifndef NO_STANDALONE
    "BC:"
#endif
    "dDeEf:"
#ifdef COOKIE
    "F:"
#endif
#ifndef NO_STANDALONE
    "g:"
#endif
    "GhHiI:jk:Kl:L:Mm:N"
#ifdef QUOTAS
    "n:"
#endif
#if defined(WITH_UPLOAD_SCRIPT)
    "o"
#endif
#ifdef WITH_ALTLOG
    "O:"
#endif
    "p:P:"
#ifdef RATIOS
    "q:Q:"
#endif
    "rRs"
#ifndef NO_STANDALONE
    "S:"
#endif
#ifdef THROTTLING
    "t:T:"
#endif
    "u:U:V:wWxX"
#ifdef WITH_OSX_BONJOUR
    "v:"
#endif
#ifdef PER_USER_LIMITS
    "y:"
#endif
#ifdef WITH_TLS
    "Y:"
#endif    
    "zZ";

#ifndef NO_GETOPT_LONG    
static struct option long_options[] = {
    { "notruncate", 0, NULL, '0' },    
    { "logpid", 0, NULL, '1' },
    { "ipv4only", 0, NULL, '4' },
    { "ipv6only", 0, NULL, '6' },    
#ifdef WITH_RFC2640
    { "fscharset", 1, NULL, '8' },
    { "clientcharset", 1, NULL, '9' },
#endif
    { "chrooteveryone", 0, NULL, 'A' },
    { "trustedgid", 1, NULL, 'a' },
    { "brokenclientscompatibility", 0, NULL, 'b' },
# ifndef NO_STANDALONE
    { "daemonize", 0, NULL, 'B' },                
    { "maxclientsperip", 1, NULL, 'C' },
# endif
    { "maxclientsnumber", 1, NULL, 'c' },    
    { "verboselog", 0, NULL, 'd' },
    { "displaydotfiles", 0, NULL, 'D' },
    { "anonymousonly", 0, NULL, 'e' },
    { "noanonymous", 0, NULL, 'E' },
    { "syslogfacility", 1, NULL, 'f' },
# ifdef COOKIE
    { "fortunesfile", 1, NULL, 'F' },
# endif
# ifndef NO_STANDALONE
    { "pidfile", 1, NULL, 'g' },
# endif
    { "norename", 0, NULL, 'G' },    
    { "help", 0, NULL, 'h' },
    { "dontresolve", 0, NULL, 'H' },
    { "maxidletime", 1, NULL, 'I' },
    { "anonymouscantupload", 0, NULL, 'i' },
    { "createhomedir", 0, NULL, 'j' },
    { "keepallfiles", 0, NULL, 'K' },    
    { "maxdiskusagepct", 1, NULL, 'k' },
    { "login", 1, NULL, 'l' },
    { "limitrecursion", 1, NULL, 'L' },
    { "anonymouscancreatedirs", 0, NULL, 'M' },
    { "maxload", 1, NULL, 'm' },
    { "natmode", 0, NULL, 'N' },
# ifdef QUOTAS
    { "quota", 1, NULL, 'n' },
# endif
# if defined(WITH_UPLOAD_SCRIPT)
    { "uploadscript", 0, NULL, 'o' },
# endif
# ifdef WITH_ALTLOG
    { "altlog", 1, NULL, 'O' },
# endif
    { "passiveportrange", 1, NULL, 'p' },
    { "forcepassiveip", 1, NULL, 'P' },
# ifdef RATIOS
    { "anonymousratio", 1, NULL, 'q' },
    { "userratio", 1, NULL, 'Q' },
# endif
    { "autorename", 0, NULL, 'r' },
    { "nochmod", 0, NULL, 'R' },    
    { "antiwarez", 0, NULL, 's' },
# ifndef NO_STANDALONE
    { "bind", 1, NULL, 'S' },
# endif
    { "anonymousbandwidth", 1, NULL, 't' },
    { "userbandwidth", 1, NULL, 'T' },
    { "umask", 1, NULL, 'U' },
    { "minuid", 1, NULL, 'u' },
    { "trustedip", 1, NULL, 'V' },
#ifdef WITH_OSX_BONJOUR
    { "bonjour", 1, NULL, 'v' },
#endif
    { "allowuserfxp", 0, NULL, 'w' },
    { "allowanonymousfxp", 0, NULL, 'W' },
    { "prohibitdotfileswrite", 0, NULL, 'x' },
    { "prohibitdotfilesread", 0, NULL, 'X' },
# ifdef PER_USER_LIMITS
    { "peruserlimits", 1, NULL, 'y' },
# endif
# ifdef WITH_TLS
    { "tls", 1, NULL, 'Y' },
# endif
    { "allowdotfiles", 0, NULL, 'z' },
    { "customerproof", 0, NULL, 'Z' },
    { NULL, 0, NULL, 0 }
};

#endif

#ifdef WITH_ALTLOG
static const AltLogPrefixes altlogprefixes[] = {
    { "clf", ALTLOG_CLF },
    { "stats", ALTLOG_STATS },
    { "w3c", ALTLOG_W3C },
    { "xferlog", ALTLOG_XFERLOG },
    { NULL, ALTLOG_NONE }
};

# define ALTLOG_DELIMITER ':'
# define ALTLOG_DEFAULT ALTLOG_CLF
#endif

#ifndef WITHOUT_PRIVSEP
# define VERSION_PRIVSEP " [privsep]"
#else
# define VERSION_PRIVSEP ""
#endif

#ifdef WITH_TLS
# define VERSION_TLS " [TLS]"
#else
# define VERSION_TLS ""
#endif

static sigset_t old_sigmask;

#ifndef NO_PROCNAME_CHANGE
# if defined(__linux__) && !defined(HAVE_SETPROCTITLE)
static char **argv0;
static size_t argv_lth;
# endif
#endif

/*
 * An authentication handler has three functions:
 * - One - parse() - is called with an optional file name, that contains a
 *   configuration file, or whatever is passed in the -l command-line switch 
 *   for this authentication.
 * - Another one, check() is called when the user has entered his password.
 *   It should fill an AuthResult structure.
 * - The last one - exit() - is called when the session is closed, and
 *   should free all internal allocated structures.
 */

typedef struct Authentication_ {
    const char * name;
    void (* parse)(const char * const file);
    void (* check)(AuthResult * const result,
                   const char *account, const char *password,
                   const struct sockaddr_storage * const sa,
                   const struct sockaddr_storage * const peer);
    void (* exit)(void);
} Authentication;

static Authentication auth_list[] = {
    { "unix", pw_unix_parse, pw_unix_check, pw_unix_exit },   /* 0 */
#ifdef USE_PAM
    { "pam", pw_pam_parse, pw_pam_check, pw_pam_exit },   /* 1 */
#endif
#ifdef WITH_MYSQL
    { "mysql", pw_mysql_parse, pw_mysql_check, pw_mysql_exit },   /* 2 */
#endif
#ifdef WITH_PGSQL
    { "pgsql", pw_pgsql_parse, pw_pgsql_check, pw_pgsql_exit },   /* 3 */
#endif
#ifdef WITH_LDAP
    { "ldap", pw_ldap_parse, pw_ldap_check, pw_ldap_exit },   /* 4 */
#endif
#ifdef WITH_PUREDB
    { "puredb", pw_puredb_parse, pw_puredb_check, pw_puredb_exit },   /* 5 */
#endif
#ifdef WITH_EXTAUTH
    { "extauth", pw_extauth_parse, pw_extauth_check, pw_extauth_exit },   /* 6 */
#endif
    { NULL, NULL, NULL, NULL }
};

#ifdef USE_PAM
# define DEFAULT_AUTHENTICATION (&auth_list[1])   /* pam */
#else
# define DEFAULT_AUTHENTICATION (&auth_list[0])   /* unix */
#endif

typedef struct Authentications_ {
    const Authentication *auth;
    char *conf_file;
    struct Authentications_ *next;
} Authentications;

static Authentications *first_authentications, *last_authentications;

typedef struct DLHandler_ {
    int clientfd;
    void *tls_clientfd;
    int xferfd;
    int f;
    void *tls_fd;
    off_t file_size;
    size_t min_dlmap_size;
    size_t dlmap_size;
    off_t cur_pos;
    off_t chunk_size;    
    off_t min_chunk_size;
    off_t default_chunk_size;
    off_t max_chunk_size;
    off_t dlmap_pos;
    off_t dlmap_fdpos;    
    off_t total_downloaded;
    size_t sizeof_map;
    unsigned char *map;
    unsigned char *map_data;    
    int ascii_mode;
    double min_sleep;
    double max_sleep;
    unsigned long bandwidth;
    struct pollfd pfds_f_in;
} DLHandler;

typedef struct ULHandler_ {
    unsigned char *buf;
    size_t sizeof_buf;
    int clientfd;
    void *tls_clientfd;
    int xferfd;
    void *tls_fd;    
    int f;
    off_t cur_pos;
    off_t chunk_size;    
    off_t min_chunk_size;
    off_t default_chunk_size;
    off_t max_chunk_size;
    off_t total_uploaded;
    int ascii_mode;
    double min_sleep;
    double max_sleep;
    unsigned long bandwidth;
    off_t max_filesize;
    unsigned long idletime;
    struct pollfd pfds[2];
    struct pollfd pfds_command;    
} ULHandler;

#define PFD_DATA 0
#define PFD_COMMANDS 1

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined (__CYGWIN__)
static struct passwd *fakegetpwnam(const char * const name);
# define getpwnam(A) fakegetpwnam(A)
# define getpwuid(A) fakegetpwnam(NULL)
#endif
#define NON_ROOT_ANON_DIR "/ftp"

#ifdef PROBE_RANDOM_AT_RUNTIME
static const char *random_device;
#endif

static struct reply *firstreply;
static struct reply *lastreply;

#endif
