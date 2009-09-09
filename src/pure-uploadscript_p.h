#ifndef __PURE_UPLOADSCRIPT_P_H__
# define __PURE_UPLOADSCRIPT_P_H__ 1

# ifndef HAVE_GETOPT_LONG
#  include "bsd-getopt_long.h"
# else
#  include <getopt.h>
# endif

# ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
# endif

static const char *GETOPT_OPTIONS =
    "Bg:"
# ifndef NO_GETOPT_LONG
    "h"
# endif
    "p:r:u:";

#ifndef NO_GETOPT_LONG
static struct option long_options[] = {
    { "daemonize", 0, NULL, 'B' },
    { "gid", 1, NULL, 'g' },
# ifndef NO_GETOPT_LONG
    { "help", 0, NULL, 'h' },
# endif
    { "pidfile", 1, NULL, 'p' },
    { "run", 1, NULL, 'r' },
    { "uid", 1, NULL, 'u' },
    { NULL, 0, NULL, 0 }    
};
#endif

static signed char daemonize;
static const char *uploadscript_pid_file = UPLOADSCRIPT_PID_FILE;
static uid_t uid;
static gid_t gid;
static const char *script;

#define OPEN_TRIES 10U
#define OPEN_DELAY 1U

#endif
