#include <config.h>

#include "ftpd.h"
#include "quotas.h"

#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static uid_t uid;
static gid_t gid;
static const char *startpath;
static unsigned long long total_size;
static unsigned long long total_files;
static signed char isroot;
static char default_tz_for_putenv[] = "TZ=UTC+00:00";

/*
 * To avoid races/loop attacks, we keep track of inode and
 * device numbers of every directory to avoid scanning them
 * twice. It's stupidly paranoid and slow. But it's safe.
 */

typedef struct Node_ {
    ino_t inode;
    dev_t device;
} Node;

Node *nodes;
size_t nodes_size;

static void oom(void)
{
    fputs("Out of memory error!\n", stderr);
    exit(EXIT_FAILURE);
}

static int init_tz(void)
{
    char stbuf[10];                                                             
    struct tm *tm;                                                              
    time_t now;                                                                 
    
#ifdef HAVE_TZSET
    tzset();
#endif
#ifdef HAVE_PUTENV    
    time(&now);                                                                 
    if ((tm = localtime(&now)) == NULL ||
        strftime(stbuf, sizeof stbuf, "%z", tm) != (size_t) 5U) {
        return -1;
    }
    snprintf(default_tz_for_putenv, sizeof default_tz_for_putenv,
             "TZ=UTC%c%c%c:%c%c", (*stbuf == '-' ? '+' : '-'),                                       
             stbuf[1], stbuf[2], stbuf[3], stbuf[4]);
    putenv(default_tz_for_putenv);
#endif   
    return 0;
}

static int traversal(const char * const s)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    size_t slen;
    Node *nodes_pnt = nodes;
    size_t nodes_cnt = nodes_size;
    int fd;
    char *buf = NULL;
    size_t sizeof_buf = (size_t) 0U;

    if ((fd = open(s, O_RDONLY | O_DIRECTORY)) == -1) {
        if (errno != EACCES) {
            return -1;
        }
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != uid) {
            close(fd);
            return -1;
        }
        (void) fchmod(fd, st.st_mode | 0500);
        close(fd);
        if ((fd = open(s, O_RDONLY | O_DIRECTORY)) == -1) {
            return -1;
        }
    }
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        close(fd);
        return -1;
    }
    if ((st.st_mode & 0500) != 0500 && st.st_uid == uid) {
        (void) fchmod(fd, (mode_t) (st.st_mode | 0500)); /* if it fails, try anyway */
    }
    close(fd);
    while (nodes_cnt > (size_t) 0U) {
        if (nodes_pnt->inode == st.st_ino && nodes_pnt->device == st.st_dev) {
            return -1;
        }
        nodes_pnt++;
        nodes_cnt -= sizeof *nodes_pnt;
    }
    if (nodes == NULL) {
        if ((nodes = malloc(sizeof *nodes)) == NULL) {
            oom();
        }
    } else {
        Node *new_nodes;

        if ((new_nodes = realloc(nodes, nodes_size + sizeof *nodes_pnt))
            == NULL) {
            oom();
        }
        nodes = new_nodes;
    }
    {
        Node * const node = (Node *) (((unsigned char *) nodes) + nodes_size);

        node->inode = st.st_ino;
        node->device = st.st_dev;
    }
    nodes_size += sizeof *nodes_pnt;
    if ((d = opendir(s)) == NULL) {
        return -1;
    }
    slen = strlen(s) + (size_t) 2U;
    while ((de = readdir(d)) != NULL) {
        size_t wanted_sizeof_buf;
        
        if ((de->d_name[0] == '.' && de->d_name[1] == 0) ||
            (de->d_name[0] == '.' && de->d_name[1] == '.' &&
             de->d_name[2] == 0)) {
            continue;
        }
        if (strcmp(de->d_name, QUOTA_FILE) == 0) {
            continue;
        }        
        wanted_sizeof_buf = slen + strlen(de->d_name);
        if (wanted_sizeof_buf > sizeof_buf) {
            if ((buf = realloc(buf, wanted_sizeof_buf)) == NULL) {
                oom();
            }
            sizeof_buf = wanted_sizeof_buf;
        }
        snprintf(buf, sizeof_buf, "%s/%s", s, de->d_name);
        if (stat(buf, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (traversal(buf) == 0) {
                    total_files++;
                }
            } else if (S_ISREG(st.st_mode)) {
                total_size += (unsigned long long) st.st_size;
                total_files++;
            }
        }
    }
    free(buf);    
    closedir(d);

    return 0;
}

static void help(void)
{
    puts("\nUsage:\n\n"
         "pure-quotacheck -u <user> -d <directory> [-g <group>]\n\n"
         "-d <directory>: start from this directory\n"
         "-g <group/gid>: scan the directory under this gid\n"
         "-h: help\n"
         "-u <user/uid>: scan the directory under this uid\n");
    exit(EXIT_SUCCESS);
}

static int doinitsupgroups(const char *user, const uid_t uid, const gid_t gid)
{
#ifndef NON_ROOT_FTP
# ifdef HAVE_SETGROUPS
    if (setgroups(1U, &gid) != 0) {
        return -1;
    }
# else
    (void) gid;
# endif
# ifdef HAVE_INITGROUPS            
    if (user == NULL) {
        const struct passwd * const lpwd = getpwuid(uid);
        
        if (lpwd != NULL && lpwd->pw_name != NULL) {
            user = lpwd->pw_name;
        } else {        
            return -1;
        }
    }
    initgroups(user, gid);
# else
    (void) user;
    (void) uid;
# endif
#else
    (void) user;
    (void) uid;
    (void) gid;    
#endif
    return 0;
}

static int changeuidgid(void)
{
    if (setgid(gid) || setegid(gid) ||
        setuid(uid) || seteuid(uid) || chdir("/")) {
        return -1;
    }
    return 0;
}

static int writequota(const char * const quota_file)
{
    int err = -1;
    int fd;
    struct flock lock;
    ssize_t towrite;
    ssize_t written;
    struct stat st;
    char buf[84];
    const char *bufpnt = buf;

    if ((fd = open("/", O_RDONLY | O_DIRECTORY)) == -1) {
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        close(fd);
        return -1;
    }
    if ((st.st_mode & 0700) != 0700 && st.st_uid == uid) {
        (void) fchmod(fd, st.st_mode | 0700);
    }
    close(fd);
    if ((fd = open(quota_file, O_RDWR | O_CREAT | O_NOFOLLOW,
                   (mode_t) 0600)) == -1) {
        return -1;
    }
    lock.l_whence = SEEK_SET;
    lock.l_start = (off_t) 0;
    lock.l_len = (off_t) 0;
    lock.l_pid = getpid();
    lock.l_type = F_WRLCK;
    while (fcntl(fd, F_SETLKW, &lock) < 0) {
        if (errno != EINTR) {
            goto byenounlock;
        }
    }
    if (SNCHECK(snprintf(buf, sizeof buf, "%llu %llu\n",
                         total_files, total_size), sizeof buf) ||
        ftruncate(fd, (off_t) 0) != 0) {
        goto bye;
    }
    towrite = (ssize_t) strlen(buf);
    while (towrite > (ssize_t) 0) {
        for (;;) {
            if ((written = write(fd, bufpnt,
                                 (size_t) towrite)) <= (ssize_t) 0) {
                if (written == (ssize_t) 0 ||
                    (errno != EAGAIN && errno != EINTR)) {
                    (void) ftruncate(fd, (off_t) 0);
                    goto bye;
                } else {
                    continue;
                }
            }
            break;
        }
        bufpnt += written;
        towrite -=written;
    }
    err = 0;
    bye:
    lock.l_type = F_UNLCK;
    while (fcntl(fd, F_SETLK, &lock) < 0 && errno == EINTR);
    byenounlock:
    close(fd);

    return err;
}

int main(int argc, char *argv[])
{
    int fodder;

    if (geteuid() == (uid_t) 0) {
        isroot = 1;
    } else {
        uid = geteuid();
        gid = getegid();
    }    
    if (argc < 0) {
        return -1;
    }
    if (argc < 2) {
        help();
    }
    
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

    init_tz();
	
    while ((fodder = getopt(argc, argv, "d:g:u:h")) != -1) {
        switch(fodder) {
        case 'h':
            help();
            /* doesn't return */
        case 'd':
            if (startpath != NULL) {
                fprintf(stderr, "Already one startpath: [%s]\n", startpath);
                return -1;
            }
            startpath = strdup(optarg);
        if (startpath == NULL) {
                oom();
            }
            break;
        case 'g':
            {
                struct group *gr;

                if (gid > (gid_t) 0) {
                    fprintf(stderr, "You already gave a gid\n");
                    return -1;
                }
                if ((gr = getgrnam(optarg)) != NULL) {
                    gid = gr->gr_gid;
                } else {
                    gid = (gid_t) strtoul(optarg, NULL, 10);
                }
            }
            break;
        case 'u':
            {
                struct passwd *pw;

                if (uid > (uid_t) 0) {
                    fprintf(stderr, "You already gave an uid\n");
                    return -1;
                }
                if ((pw = getpwnam(optarg)) != NULL) {
                    uid = pw->pw_uid;
                    if (gid == (gid_t) 0) {
                        gid = pw->pw_gid;
                    }
                } else {
                    uid = (uid_t) strtoul(optarg, NULL, 10);
                }
            }
            break;
        case '?':
            help();
        }
    }
    if (startpath == NULL) {
        fprintf(stderr, "Missing path\n");
        return -1;
    }
    if (uid <= (uid_t) 0) {
        fprintf(stderr, "Invalid/insecure/missing uid - must be > 0\n");
        return -2;
    }
    if (gid <= (gid_t) 0) {
        fprintf(stderr, "Invalid/insecure/missing gid - must be > 0\n");
        return -2;
    }
    if (isroot != 0) {
        if (doinitsupgroups(NULL, uid, gid) 
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)            
            & 0
#endif
            != 0 ||
            chdir(startpath) != 0 || 
            chroot(startpath) != 0 || chdir("/") != 0) {
            fprintf(stderr, "Can't chroot to [%s]: [%s]\n",
                    startpath, strerror(errno));
            return -3;
        }
        if (changeuidgid() < 0) {
            fprintf(stderr, "Can't switch uid/gid: [%s]\n", strerror(errno));
            return -3;
        }        
    } else if (chdir(startpath) != 0) {
        fprintf(stderr, "Can't enter directory [%s]: [%s]\n",
                startpath, strerror(errno));
        return -3;
    }
    if (traversal(isroot != 0 ? "/" : "./") < 0) {
        fprintf(stderr, "Unable to traverse [%s]: [%s]\n",
                startpath, strerror(errno));
        free(nodes);
        
        return -4;
    }
    free(nodes);
    if (isroot != 0) {
        if (writequota("/" QUOTA_FILE) < 0) {
            err_writequota:
            fprintf(stderr, "Unable to update the quota file ("
                    QUOTA_FILE "): [%s]\n", strerror(errno));
            return -5;
        }
    } else if (chdir(startpath) != 0 || writequota(QUOTA_FILE) < 0) {
        goto err_writequota;
    }

    return 0;
}
