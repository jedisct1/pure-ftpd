#include <config.h>

#ifndef WITH_UPLOAD_SCRIPT
#include <stdio.h>

int main(void)
{
    puts("Please compile the server with --with-uploadscript\n"
         "to use this feature. Thank you.");
    
    return 0;
}
#else

# include "ftpd.h"
# include "upload-pipe.h"
# include "pure-uploadscript_p.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void setcloexec(const int fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int upload_pipe_ropen(void)
{
    struct stat st;
    int upload_pipe_fd;
    unsigned int tries = OPEN_TRIES;
        
    again:
    if ((upload_pipe_fd =
         open(UPLOAD_PIPE_FILE, O_RDONLY | O_NOFOLLOW)) == -1) {
    if (tries > 0) {
        tries--;
        (void) sleep(OPEN_DELAY);
        goto again;
    }
        perror("Unable to open " UPLOAD_PIPE_FILE);
        return -1;
    }
    setcloexec(upload_pipe_fd);
    if (fstat(upload_pipe_fd, &st) < 0 ||
        (st.st_mode & 0777) != 0600 || !S_ISFIFO(st.st_mode) ||
#ifdef NON_ROOT_FTP
        st.st_uid != geteuid()
#else
        st.st_uid != (uid_t) 0
#endif
        ) {
        fprintf(stderr, "Insecure permissions on " UPLOAD_PIPE_FILE "\n");
        return -1;
    }
    return upload_pipe_fd;
}

static int readchar(const int upload_file_fd)
{
    ssize_t ret;
    unsigned char c;
    
    while ((ret = read(upload_file_fd, &c, (size_t) 1U)) < (ssize_t) 0 &&
           errno == EINTR);
    if (ret <= (ssize_t) 0) {
        return EOF;
    } 
    return (int) c;
}

static int readpipe(const int upload_file_fd,
                    char ** const r_who, char ** const r_file)
{
    static char who[MAX_USER_LENGTH + 1U];
    static char file[MAXPATHLEN + VHOST_PREFIX_MAX_LEN];
    const char * const whoend = &who[sizeof who];
    const char * const fileend = &file[sizeof file];
    char *whopnt = who;    
    char *filepnt = file;
    int c;
    
    *r_who = NULL;
    *r_file = NULL;
    do {
        c = readchar(upload_file_fd);
        if (c == EOF) {
            return -1;
        }
    } while (c != 2);
    while (whopnt != whoend) {
        c = readchar(upload_file_fd);
        if (c == EOF || (c != 1 && ISCTRLCODE(c))) {
            return -1;
        }
        if (c == 1) {
            *whopnt = 0;
            break;
        }
        *whopnt = (char) c;
        whopnt++;
    }    
    while (filepnt != fileend) {
        c = readchar(upload_file_fd);
        if (c == EOF || (c != 0 && ISCTRLCODE(c))) {
            return -1;
        }
        *filepnt = (char) c;
        if (c == 0) {
            break;
        }
        filepnt++;
    }
    *r_who = who;
    *r_file = file;
    
    return 0;
}

/* 
 * When we are using virtual hosts, the file looks like :
 * <ip address>:<path>
 */

static char *checkvirtual(char *path)
{
    static char buf[MAXPATHLEN + 1];
    char *path_pnt;
    
    if (path == NULL || *path == '/' ||
        (path_pnt = strstr(path, ":/")) == NULL) {
        return path;
    }
    *path_pnt = 0;
    if (SNCHECK(snprintf(buf, sizeof buf, VHOST_PATH "/%s%s", 
                         path, path_pnt + 1), sizeof buf)) {
        /* Better avoid processing than risking a security flaw */
        return NULL;
    }
    
    return buf;
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
        (void) closedesc_all(0);
    }
}

static int init(void)
{
    (void) close(0);
#ifndef NON_ROOT_FTP
    if (geteuid() != (uid_t) 0) {
        fprintf(stderr, "Sorry, but you have to be r00t to run this program\n");
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
            getopt_long(argc, argv, GETOPT_OPTIONS, long_options, &option_index)
#else
            getopt(argc, argv, GETOPT_OPTIONS)
#endif
            ) != -1) {
        switch (fodder) {
        case 'B': {
            daemonize = 1;
            break;
        }
        case 'p': {
            if ((uploadscript_pid_file = strdup(optarg)) == NULL) {
                perror("Oh no ! More memory !");
            }
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
#ifdef HAVE_SETGROUPS
        setgroups(1U, &gid) ||
#endif
        setgid(gid) || setegid(gid) ||
        setuid(uid) || seteuid(uid) || chdir("/")) {
        return -1;
    }
#endif
    return 0;
}

#ifdef HAVE_PUTENV
static void newenv_ull(const char * const var, const unsigned long long val)
{
    size_t s;
    char *v;
    
    s = strlen(var) + (size_t) 42U;
    if ((v = malloc(s)) == NULL) {
        return;
    }
    if (SNCHECK(snprintf(v, s, "%s=%llu", var, val), s)) {
        free(v);
        return;
    }
    putenv(v);
}

static void newenv_uo(const char * const var, const unsigned int val)
{
    size_t s;
    char *v;
    
    s = strlen(var) + (size_t) 8U;
    if ((v = malloc(s)) == NULL) {
        return;
    }
    if (SNCHECK(snprintf(v, s, "%s=%o", var, val), s)) {
        free(v);
        return;
    }
    putenv(v);
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
    putenv(v);
}
#endif

static void fillenv(const char * const who, const struct stat * const st)
{
#ifdef HAVE_PUTENV    
    struct passwd *pwd;
    struct group *grp;
    
    pwd = getpwuid(st->st_uid);
    grp = getgrgid(st->st_gid);
    newenv_ull("UPLOAD_SIZE", (unsigned long long) st->st_size);
    newenv_uo("UPLOAD_PERMS", (unsigned int) (st->st_mode & 07777));
    newenv_ull("UPLOAD_UID", (unsigned long long) st->st_uid);
    newenv_ull("UPLOAD_GID", (unsigned long long) st->st_gid);
    if (pwd != NULL) {
        newenv_str("UPLOAD_USER", pwd->pw_name);
    }
    if (grp != NULL) {
        newenv_str("UPLOAD_GROUP", grp->gr_name);
    }
    if (who != NULL) {
        newenv_str("UPLOAD_VUSER", who);
    }
#else
    (void) st;
#endif
}

static int run(const char * const who, const char * const file, 
               const int upload_pipe_fd)
{
    struct stat st;
    pid_t pid;
    
    if (script == NULL || *script == 0 ||
        file == NULL || *file == 0 ||
        lstat(file, &st) < 0 ||
        !S_ISREG(st.st_mode)) {
        return -1;
    }
    pid = fork();
    if (pid == (pid_t) 0) {
        /* Yes, there's already the cloexec flag on this fd,
         * but it's really important to close it. Be paranoid.
         */
        if (close(upload_pipe_fd) < 0 || closedesc_all(1) < 0) {
            _exit(EXIT_FAILURE);
        }
        fillenv(who, &st);
        execl(script, script, file, (char *) NULL);
        _exit(EXIT_FAILURE);
    } else if (pid != (pid_t) -1) {
#ifdef HAVE_WAITPID
        (void) waitpid(pid, NULL, 0);
#else
        {
            pid_t foundpid;
            
            while ((foundpid = wait3(NULL, 0, NULL)) != (pid_t) -1 &&
                   foundpid != pid);
        }
#endif
    }
    
    return 0;
}

int safe_write(const int fd, const void *buf_, size_t count)
{
    const char *buf = (const char *) buf_;
    ssize_t written;
        
    while (count > (size_t) 0) {
        for (;;) {
            if ((written = write(fd, buf, count)) <= (ssize_t) 0) {
                if (errno != EINTR) {
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
    char buf[42];    
    int fd;
    
    if (SNCHECK(snprintf(buf, sizeof buf, "%lu\n", 
                         (unsigned long) getpid()), sizeof buf)) {
        return;
    }
    if (unlink(uploadscript_pid_file) != 0 && errno != ENOENT) {
        return;
    }
    if ((fd = open(uploadscript_pid_file, O_CREAT | O_WRONLY | O_TRUNC |
                   O_NOFOLLOW, (mode_t) 0644)) == -1) {
        return;
    }
    if (safe_write(fd, buf, strlen(buf)) != 0) {
        ftruncate(fd, (off_t) 0);
    }
    close(fd);
}

int main(int argc, char *argv[])
{
    int upload_pipe_fd;
    char *who;
    char *file;
    
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
    if (parseoptions(argc, argv) < 0) {
        return -1;
    }
    if (script == NULL) {
        fprintf(stderr, "Sorry, but I need -r <program to run>\n\n");
        usage();
    }
    if (daemonize != 0) {
        dodaemonize();
    }
    if ((upload_pipe_fd = upload_pipe_ropen()) == -1) {
        return -1;
    }
    updatepidfile();
    if (changeuidgid() < 0) {
        perror("Identity change");
        (void) unlink(uploadscript_pid_file);
        return -1;
    }
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SIGCHLD
    signal(SIGCHLD, SIG_DFL);
#endif
    for (;;) {
        if (readpipe(upload_pipe_fd, &who, &file) != 0) {
            (void) sleep(1);
            continue;
        }        
        file = checkvirtual(file);
        if (file != NULL && who != NULL) {
            run(who, file, upload_pipe_fd);
        }
    }
    /* NOTREACHED */
#if 0
    close(upload_pipe_fd);
    (void) unlink(uploadscript_pid_file);
#endif
    
    return 0;
}

#endif


