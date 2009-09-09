#include <config.h>

#ifndef WITH_EXTAUTH
#include <stdio.h>

int main(void)
{
    puts("Please compile the server with --with-extauth\n"
         "to use this feature. Thank you.");
    
    return 0;
}
#else

#include "ftpd.h"
#include "log_extauth.h"
#include "pure-authd_p.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static inline void setcloexec(const int fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int closedesc_all(const int closestdin)
{
    int fodder;
    
    if (closestdin != 0) {
        (void) close(0);
        if ((fodder = open("/dev/null", O_RDONLY)) == -1) {
            return -1;
        }
        (void) dup2(fodder, 0);
        if (fodder > 0) {
            (void) close(fodder);
        }
    }
    if ((fodder = open("/dev/null", O_WRONLY)) == -1) {
        return -1;
    }
    (void) dup2(fodder, 1);
    (void) dup2(1, 2);
    if (fodder > 2) {
        (void) close(fodder);
    }    
    return 0;
}

static void dodaemonize(void)
{
    pid_t child;
    
    if (daemonize != 0) {
        if ((child = fork()) == (pid_t) -1) {
            perror("Daemonization failed - fork");
            return;
        } else if (child != (pid_t) 0) {
            _exit(EXIT_SUCCESS);
        } else if (setsid() == (pid_t) -1) {
            perror("Daemonization failed : setsid");
        }
        (void) chdir("/");
#ifdef HAVE_CLOSEFROM
        (void) closefrom(3);
#endif
        (void) closedesc_all(1);
    }
}

static int init(void)
{
#ifndef NON_ROOT_FTP
    if (geteuid() != (uid_t) 0) {
        fprintf(stderr, 
        "Sorry, but you have to be r00t to run this program\n");
        return -1;
    }
#endif
    
    return 0;
}

static void usage(void)
{
#ifndef NO_GETOPT_LONG    
    const struct option *options = long_options;
    
    do {
        printf("-%c\t--%s\t%s\n", options->val, options->name,
               options->has_arg ? "<opt>" : "");
        options++;
    } while (options->name != NULL);
#endif
    exit(EXIT_SUCCESS);
}

static int parseoptions(int argc, char *argv[])
{
#ifndef NO_GETOPT_LONG
    int option_index = 0;
#endif
    int fodder;

    while ((fodder =
#ifndef NO_GETOPT_LONG
            getopt_long(argc, argv, GETOPT_OPTIONS, long_options, 
            &option_index)
#else
            getopt(argc, argv, GETOPT_OPTIONS)
#endif
            ) != -1) {
        switch (fodder) {
        case 'B': {
            daemonize = 1;
            break;
        }
        case 'g': {
            const char *nptr;
            char *endptr;
            
            nptr = optarg;
            endptr = NULL;
            gid = (gid_t) strtoul(nptr, &endptr, 10);
            if (!nptr || !*nptr || !endptr || *endptr) {
                perror("Illegal GID - Must be a number\n");
            }
            break;            
        }
        case 'p': {
            if ((authd_pid_file = strdup(optarg)) == NULL) {
                perror("Oh no ! More memory !");
            }
            break;
        }
#ifndef NO_GETOPT_LONG
        case 'h': {
            usage();
        }
#endif
        case 'r': {
            if ((script = strdup(optarg)) == NULL) {
                perror("Oh no ! More memory !");
            }
            break;            
        }
        case 's': {
            if ((socketpath = strdup(optarg)) == NULL) {
                perror("Oh no ! More memory !");
            }
            break;            
        }
        case 'u': {
            const char *nptr;
            char *endptr;
            
            nptr = optarg;
            endptr = NULL;
            uid = (uid_t) strtoul(nptr, &endptr, 10);
            if (!nptr || !*nptr || !endptr || *endptr) {
                perror("Illegal UID - Must be a number\n");
            }
            break;
        }
        default: 
            usage();
        }
    }
    return 0;
}

static int changeuidgid(void)
{
#ifndef NON_ROOT_FTP
    if (        
# ifdef HAVE_SETGROUPS
        setgroups(1U, &gid) ||
# endif
        setgid(gid) || setegid(gid) ||
        setuid(uid) || seteuid(uid) || chdir("/")) {
        return -1;
    }
#endif
    return 0;
}

static void newenv_str(const char * const var, const char * const str)
{
    size_t s;
    char *v;
    
    if (str == NULL || *str == 0) {
        return;
    }
    s = strlen(var) + strlen(str) + (size_t) 2U;
    if ((v = malloc(s)) == NULL) {
        return;
    }
    if (SNCHECK(snprintf(v, s, "%s=%s", var, str), s)) {
        free(v);
        return;
    }
#ifdef HAVE_PUTENV
    putenv(v);
#endif    
}

static ssize_t safe_read(const int fd, void * const buf_, size_t maxlen)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t readen;
    
    do {
        while ((readen = read(fd, buf, maxlen)) < (ssize_t) 0 && 
               errno == EINTR);
        if (readen < (ssize_t) 0 || readen > (ssize_t) maxlen) {
            return readen;
        }
        if (readen == (ssize_t) 0) {
            ret:
            return (ssize_t) (buf - (unsigned char *) buf_);
        }
        maxlen -= readen;
        buf += readen;
    } while (maxlen > (ssize_t) 0);
    goto ret;
}

int safe_write(const int fd, const void *buf_, size_t count)
{
    register const char *buf = (const char *) buf_;
    ssize_t written;
        
    while (count > (size_t) 0) {
        for (;;) {
            if ((written = write(fd, buf, count)) <= (ssize_t) 0) {
                if (errno == EAGAIN) {
                    sleep(1);
                } else if (errno != EINTR) {
                    return -1;
                }
                continue;
            }
            break;
        }
        buf += written;
        count -= written;
    }
    return 0;
}

static void updatepidfile(void)
{
    int fd;
    char buf[42];
    
    if (SNCHECK(snprintf(buf, sizeof buf, "%lu\n", 
                         (unsigned long) getpid()), sizeof buf)) {
        return;
    }
    if (unlink(authd_pid_file) != 0 && errno != ENOENT) {
        return;
    }
    if ((fd = open(authd_pid_file, O_CREAT | O_WRONLY | O_TRUNC |
                   O_NOFOLLOW, (mode_t) 0644)) == -1) {
        return;
    }
    if (safe_write(fd, buf, strlen(buf)) != 0) {
        ftruncate(fd, (off_t) 0);
    }
    close(fd);
}

static void callback_client_account(const char *str)
{
    newenv_str(ENV_AUTHD_ACCOUNT, str);
}

static void callback_client_password(const char *str)
{
    newenv_str(ENV_AUTHD_PASSWORD, str);
}

static void callback_client_sa_host(const char *str)
{
    newenv_str(ENV_AUTHD_SA_HOST, str);
}

static void callback_client_sa_port(const char *str)
{
    newenv_str(ENV_AUTHD_SA_PORT, str);
}

static void callback_client_peer_host(const char *str)
{
    newenv_str(ENV_AUTHD_PEER_HOST, str);
}

static void callback_client_encrypted(const char *str)
{
    newenv_str(ENV_AUTHD_ENCRYPTED, str);
}

static void callback_client_end(const char *str)
{
    (void) str;
    ended = 1;
}

static void process(const int clientfd)
{
    ssize_t readen;
    char *linepnt;
    char *crpoint;
    pid_t pid;
    int pfds[2];
    char line[4096];
    
    while ((readen = read(clientfd, line, sizeof line - 1U)) < (ssize_t) 0 &&
           (errno == EINTR || errno == EIO));
    if (readen <= (ssize_t) 0) {
        return;
    }
    line[readen] = 0;
    if (pipe(pfds) != 0) {
        return;
    }
    pid = fork();
    if (pid == (pid_t) -1) {
        close(pfds[0]);
        close(pfds[1]);
        return;
    }    
    if (pid != (pid_t) 0) {
        close(pfds[1]);         /* close the output side of the pipe */
        if ((readen = safe_read(pfds[0], line, 
                                sizeof line - 1U)) > (ssize_t) 0) {
            (void) safe_write(clientfd, line, readen);
        }
#ifdef HAVE_WAITPID
        (void) waitpid(pid, NULL, 0);
#else
        while (wait3(NULL, 0, NULL) != pid);
#endif
        close(pfds[0]);
        return;
    }
    /* now, we are in the child */
    close(clientfd);
    close(kindy);
    close(pfds[0]);                    /* close the input side of the pipe */
    closedesc_all(1);
    linepnt = line;
    while ((crpoint = strchr(linepnt, '\n')) != NULL) {
        register const ExtauthdCallBack *scanned;
        size_t keyword_len;
        
        *crpoint = 0;
        scanned = extauthd_callbacks;
        while (scanned->keyword != NULL) {
            keyword_len = strlen(scanned->keyword);
            if (strncmp(scanned->keyword, linepnt, keyword_len) == 0) {
                scanned->func(linepnt + keyword_len);
                break;
            }
            scanned++;
        }
        linepnt = crpoint + 1;        
    }
    if (ended == 0) {
        close(pfds[1]);
        _exit(EXIT_FAILURE);
    }
    if (dup2(pfds[1], 1) == -1) {
        close(pfds[1]);        
        _exit(EXIT_FAILURE);
    }
    close(pfds[1]);
#ifdef DO_AUTHD_TIMEOUT
    (void) alarm(AUTHD_SCRIPT_TIMEOUT);
#endif
    (void) execl(script, script, (char *) NULL);
    
    _exit(EXIT_SUCCESS);
}

int listencnx(void)
{
    struct sockaddr_un *saddr;    
    int clientfd;
    int ret = -1;
    const size_t socketpath_len = strlen(socketpath);
        
    if ((saddr = malloc(sizeof(*saddr) + socketpath_len + 
                        (size_t) 1U)) == NULL) {
        perror("No more memory to listen to anything");
        goto bye;
    }
    memcpy(saddr->sun_path, socketpath, socketpath_len + (size_t) 1U);
    saddr->sun_family = AF_UNIX;
    (void) unlink(socketpath);
    (void) umask(077);    
    if ((kindy = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("Unable to create a local socket");
        goto bye;
    }
    setcloexec(kindy);
    if (bind(kindy, (struct sockaddr *) saddr, SUN_LEN(saddr)) != 0) {
        perror("Unable to bind a local socket");
        goto bye;
    }    
    if (chmod(socketpath, 0600) != 0) {
        perror("Unable to change perms on the local socket");
        goto bye;
    }
    if (listen(kindy, AUTHD_BACKLOG) != 0) {
        perror("Unable to listen the local socket");
        goto bye;
    }
    do {
        if ((clientfd = accept(kindy, NULL, NULL)) == -1) {
            if (exit_authd != 0) {
                break;
            }
            (void) sleep(1);
            continue;
        }
        setcloexec(clientfd);
        process(clientfd);
        close(clientfd);
    } while (exit_authd == 0);
    ret = 0;
    
    bye:
    if (kindy != -1) {
        close(kindy);
        kindy = -1;
    }
    (void) unlink(socketpath);
    free(saddr);
    
    return ret;
}

static RETSIGTYPE sigterm(int sig)
{    
    (void) sig;
    
    exit_authd = 1;
    if (kindy != -1) {
        close(kindy);        
        kindy = -1;
    }
}

int main(int argc, char *argv[])
{    
    int err;
    
#ifdef HAVE_SETLOCALE
# ifdef LC_MESSAGES
    (void) setlocale(LC_MESSAGES, "");
# endif
# ifdef LC_CTYPE
    (void) setlocale(LC_CTYPE, "");
# endif
# ifdef LC_COLLATE
    (void) setlocale(LC_COLLATE, "");
# endif
#endif
    if (init() < 0) {
        return -1;
    }
    (void) signal(SIGTERM, sigterm);    
    (void) signal(SIGQUIT, sigterm);
    (void) signal(SIGINT, sigterm);
#ifdef SIGXCPU
    (void) signal(SIGXCPU, sigterm);
#endif
    if (parseoptions(argc, argv) < 0) {
        return -1;
    }
    if (script == NULL || *script != '/') {
        fprintf(stderr, "You must give -r /path/to/auth/program\n");
        return -2;
    }
    if (socketpath == NULL || *socketpath == 0) {
        fprintf(stderr, "You must give -s /path/to/socket\n");
        return -2;
    }
    if (daemonize != 0) {
        dodaemonize();
    }
    updatepidfile();
    if (changeuidgid() < 0) {
        perror("Identity change");
        (void) unlink(authd_pid_file);
        return -1;
    }
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif    
#ifdef SIGCHLD
    signal(SIGCHLD, SIG_DFL);
#endif    
    err = listencnx();    
    (void) unlink(authd_pid_file);    
    
    return err;
}

#endif
