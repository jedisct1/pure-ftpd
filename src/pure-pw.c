#include <config.h>

#include "ftpd.h"
#include "pure-pw.h"
#include "../puredb/src/puredb_write.h"
#ifdef HAVE_POSIX_TERMIOS
# include <termios.h>
#elif defined(HAVE_TERMIO_H)
# include <termio.h>
#elif defined(HAVE_SGTTY_H)
# include <sgtty.h>
#endif

#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#ifdef PROBE_RANDOM_AT_RUNTIME
static const char *random_device;
#endif

static void disable_echo(void)
{
    if (!isatty(0)) {
        return;
    }
#ifdef ECHO
# ifdef HAVE_POSIX_TERMIOS
    {    
        struct termios p;
        
        if (tcgetattr(0, &p) != 0) {
            return;
        }
        p.c_lflag &= ~ECHO;
#  ifndef TCSAFLUSH
#   define TCSAFLUSH 0
#  endif
        tcsetattr(0, TCSAFLUSH, &p);
    }
# elif defined(HAVE_TERMIO_H) && defined(TCGETA)
    {
        struct termio tty;
        
        if (ioctl(0, TCGETA, &tty) != 0) {
            return;
        }
        tty.c_lflag &= ~ECHO;
        ioctl(0, TCSETA, &tty);
    }
# else
    {
        struct sgttyb tty;
        
        if (ioctl(0, TIOCGETP, &tty) != 0) {
            return;
        }
        tty.sg_flags &= ~ECHO;
        ioctl(0, TIOCSETN, &tty);
    }
# endif
#endif
}

static void enable_echo(void)
{
    if (!isatty(0)) {
        return;
    }    
#ifdef ECHO
# ifdef HAVE_POSIX_TERMIOS
    {
        struct termios p;
        
        if (tcgetattr(0, &p) != 0) {
            return;
        }
        p.c_lflag |= ECHO;
#  ifndef TCSAFLUSH
#   define TCSAFLUSH 0
#  endif
        tcsetattr(0, TCSAFLUSH, &p);
    }
# elif defined(HAVE_TERMIO_H) && defined(TCGETA)
    {
        struct termio tty;
        
        if (ioctl(0, TCGETA, &tty) != 0) {
            return;
        }
        tty.c_lflag |= ECHO;
        ioctl(0, TCSETA, &tty);
    }
# else
    {
        struct sgttyb tty;
        
        if (ioctl(0, TIOCGETP, &tty) != 0) {
            return;
        }
        tty.sg_flags |= ECHO;
        ioctl(0, TIOCSETN, &tty);
    }
# endif
#endif
}

/*
 * The difference between this strtok() and the libc's one is that
 * this one doesn't skip empty fields, and takes a char instead of a
 * string as a delimiter.
 * This strtok2() variant leaves zeroes.
 */

static char *my_strtok2(char *str, const char delim)
{
    static char *s;
    static char save;
    
    if (str != NULL) {
        if (*str == 0) {
            return NULL;
        }        
        s = str;
        scan:
        while (*s != 0 && *s != delim) {
            s++;
        }
        save = *s;
        *s = 0;
        
        return str;
    }
    if (s == NULL || save == 0) {        
        return NULL;
    }
    s++;
    str = s;
    
    goto scan;
}

static void filter_pw_line_sep(char *str)
{
    if (str == NULL) {
        return;
    }
    while (*str != 0) {
        if (*str == *PW_LINE_SEP) {
            *str = '_';
        }
        str++;
    }
}

static void help(void)
{
    puts("\nUsage :\n\n"
         "pure-pw useradd <login> [-f <passwd file>] -u <uid> [-g <gid>]\n"
         "                -D/-d <home directory> [-c <gecos>]\n"
         "                [-t <download bandwidth>] [-T <upload bandwidth>]\n"
         "                [-n <max number of files>] [-N <max Mbytes>]\n"
         "                [-q <upload ratio>] [-Q <download ratio>]\n"
         "                [-r <allow client ip>/<mask>] [-R <deny client ip>/<mask>]\n"
         "                [-i <allow local ip>/<mask>] [-I <deny local ip>/<mask>]\n"
     "                [-y <max number of concurrent sessions>]\n"
         "                [-z <hhmm>-<hhmm>] [-m]\n"
         "\n"
         "pure-pw usermod <login> -f <passwd file> -u <uid> [-g <gid>]\n"
         "                -D/-d <home directory> -[c <gecos>]\n"
         "                [-t <download bandwidth>] [-T <upload bandwidth>]\n"
         "                [-n <max number of files>] [-N <max Mbytes>]\n"
         "                [-q <upload ratio>] [-Q <download ratio>]\n"
         "                [-r <allow client ip>/<mask>] [-R <deny client ip>/<mask>]\n"
         "                [-i <allow local ip>/<mask>] [-I <deny local ip>/<mask>]\n"
         "                [-y <max number of concurrent sessions>]\n"     
         "                [-z <hhmm>-<hhmm>] [-m]\n"
         "\n"
         "pure-pw userdel <login> [-f <passwd file>] [-m]\n"
         "\n"
         "pure-pw passwd  <login> [-f <passwd file>] [-m]\n"
         "\n"
         "pure-pw show    <login> [-f <passwd file>]\n"
         "\n"
         "pure-pw mkdb    [<puredb database file> [-f <passwd file>]]\n"
         "                [-F <puredb file>]\n"
         "\n"
         "pure-pw list    [-f <passwd file>]\n"
         "\n"
         "-d <home directory> : chroot user (recommended)\n"
         "-D <home directory> : don't chroot user\n"
     "-<option> '' : set this option to unlimited\n"
         "-m : also update the " DEFAULT_PW_DB " database\n"
         "For a 1:10 ratio, use -q 1 -Q 10\n"
         "To allow access only between 9 am and 6 pm, use -z 0900-1800\n"
         "\n");
#ifndef WITH_PUREDB
    puts("*WARNING* : that pure-ftpd server hasn't been compiled with puredb support\n");
#endif
    exit(EXIT_SUCCESS);   
}

static void no_mem(void)
{
    fprintf(stderr, "Out of memory : [%s]\n", strerror(errno));
    exit(EXIT_FAILURE);
}

#ifdef PROBE_RANDOM_AT_RUNTIME
static void pw_zrand_probe(void)
{
    static const char * const devices[] = {
        "/dev/arandom", "/dev/urandom", "/dev/random", NULL
    };
    const char * const *device = devices;
    
    do {
        if (access(*device, F_OK | R_OK) == 0) {
            random_device = *device;
            break;
        }
        device++;
    } while (*device != NULL);
}
#endif

static unsigned int pw_zrand(void)
{
    int fd;
    int ret;
    
    if (
#ifdef PROBE_RANDOM_AT_RUNTIME
        ((fd = open(random_device, O_RDONLY | O_NONBLOCK)) == -1)
#elif defined(HAVE_DEV_ARANDOM)
        ((fd = open("/dev/arandom", O_RDONLY | O_NONBLOCK)) == -1)
#elif defined(HAVE_DEV_URANDOM)
        ((fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK)) == -1)
#else
        ((fd = open("/dev/random", O_RDONLY | O_NONBLOCK)) == -1)
#endif        
        ) {
        nax:
#ifdef HAVE_ARC4RANDOM
        return (unsigned int) arc4random();
#elif defined HAVE_RANDOM
        return (unsigned int) random();
#else
        return (unsigned int) rand();
#endif
    }
    if (read(fd, &ret, sizeof ret) != (ssize_t) sizeof ret) {
        close(fd);
        goto nax;
    }
    close(fd);    
    
    return (unsigned int) ret;
}

static char *best_crypt(const char * const pwd)
{
    static const char crcars[64] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    const char *crypted;
    
    if ((crypted = (const char *)      /* Blowfish */
         crypt("test", "$2a$07$1234567890123456789012")) != NULL &&        
        strcmp(crypted, "$2a$07$123456789012345678901uKO4"
               "/IReKqBzRzT6YaajGvw20UBdHW7m") == 0) {
        char salt[] = "$2a$07$0000000000000000000000";        
        int c = 28;
        
        do {            
            c--;
            salt[c] = crcars[pw_zrand() & 63];
        } while (c > 7);
        
        return (char *) crypt(pwd, salt);        
    } else if ((crypted = (const char *)    /* MD5 */
                crypt("test", "$1$12345678$")) != NULL &&
               strcmp(crypted, "$1$12345678$oEitTZYQtRHfNGmsFvTBA/") == 0) {
        char salt[] = "$1$00000000";
        int c = 10;
        
        do {            
            c--;
            salt[c] = crcars[pw_zrand() & 63];
        } while (c > 3);
        
        return (char *) crypt(pwd, salt);
    } else if ((crypted = (const char *)    /* Extended DES */
                crypt("test", "_.../1234")) != NULL &&
               strcmp(crypted, "_.../1234PAPUVmqGzpU") == 0) {
        char salt[] = "_.../0000";
        int c = 8;
        
        do {
            c--;
            salt[c] = crcars[pw_zrand() & 63];
        } while (c > 5);
        
        return (char *) crypt(pwd, salt);
    }
    /* Simple DES */
    {
        char salt[] = "00";
        
        salt[0] = crcars[pw_zrand() & 63];
        salt[1] = crcars[pw_zrand() & 63];
        
        return (char *) crypt(pwd, salt);        
    }    
}

char *newpasswd_filename(const char * const file)
{
    size_t sizeof_file2;
    char *file2;
    
    sizeof_file2 = strlen(file) + sizeof NEWPASSWD_SUFFIX;
    if ((file2 = malloc(sizeof_file2)) == NULL) {
        return NULL;
    }
    (void) snprintf(file2, sizeof_file2, "%s%s", file, NEWPASSWD_SUFFIX);
    
    return file2;
}

static void strip_lf(char *str)
{
    char *f;
    
    if (str == NULL) {
        return;
    }
    if ((f = strchr(str, '\r')) != NULL) {
        *f = 0;
    }    
    if ((f = strchr(str, '\n')) != NULL) {
        *f = 0;
    }
}

static int parse_pw_line(char *line, PWInfo * const pwinfo)
{
    pwinfo->login = NULL;
    pwinfo->pwd = NULL;
    pwinfo->gecos = NULL;
    pwinfo->home = NULL;
    pwinfo->allow_local_ip = pwinfo->deny_local_ip = NULL;
    pwinfo->allow_client_ip = pwinfo->deny_client_ip = NULL;    
    pwinfo->has_bw_dl = 0;
    pwinfo->has_bw_ul = 0;
    pwinfo->has_quota_files = 0;
    pwinfo->has_quota_size = 0;
    pwinfo->has_ul_ratio = 0;
    pwinfo->has_dl_ratio = 0;
    pwinfo->has_time = 0;
    pwinfo->time_begin = pwinfo->time_end = 0U;
    pwinfo->uid = (uid_t) 0;
    pwinfo->gid = (gid_t) 0;
    pwinfo->has_per_user_max = 0;
    pwinfo->per_user_max = 0U;
    
    if ((line = my_strtok2(line, *PW_LINE_SEP)) == NULL || *line == 0) {   /* account */
        return -1;
    }
    pwinfo->login = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* pwd */
        return -1;
    }
    pwinfo->pwd = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* uid */
        return -1;
    }
    pwinfo->uid = (uid_t) strtoul(line, NULL, 10);
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* gid */
        return -1;
    }
    pwinfo->gid = (gid_t) strtoul(line, NULL, 10);
    if (pwinfo->uid <= (uid_t) 0 || pwinfo->gid <= (gid_t) 0) {
        return -1;
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* gecos */
        return -1;
    }
    pwinfo->gecos = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* home */
        return -1;
    }
    if (*line != '/') {
        return -1;
    }
    pwinfo->home = line;    
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* bw_ul */
        return 0;
    }
    if (*line != 0) {
        pwinfo->has_bw_ul = 1;
        pwinfo->bw_ul = strtoul(line, NULL, 10);
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* bw_dl */
        return 0;
    } 
    if (*line != 0) {
        pwinfo->has_bw_dl = 1;
        pwinfo->bw_dl = strtoul(line, NULL, 10);
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* ratio up */
        return 0;
    }
    if (*line != 0) {
        pwinfo->ul_ratio = (unsigned int) strtoul(line, NULL, 10);
        if (pwinfo->ul_ratio > 0U) {
            pwinfo->has_ul_ratio = 1;     
        }
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* ratio down */
        return 0;
    }
    if (*line != 0) {
        pwinfo->dl_ratio = (unsigned int) strtoul(line, NULL, 10);
        if (pwinfo->dl_ratio > 0U) {
            pwinfo->has_dl_ratio = 1;
        }
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* max cnx */
        return 0;
    }
    if (*line != 0) {
    pwinfo->per_user_max = (unsigned int) strtoul(line, NULL, 10);
        if (pwinfo->per_user_max > 0U) {
            pwinfo->has_per_user_max = 1;
        }
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* files quota */
        return 0;
    }
    if (*line != 0) {
        pwinfo->has_quota_files = 1;
        pwinfo->quota_files = strtoull(line, NULL, 10);
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* size quota */
        return 0;
    }
    if (*line != 0) {
        pwinfo->has_quota_size = 1;
        pwinfo->quota_size = strtoull(line, NULL, 10);
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* allowed local ip */
        return 0;
    }
    pwinfo->allow_local_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* denied local ip */
        return 0;
    }
    pwinfo->deny_local_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* allowed client ip */
        return 0;
    }
    pwinfo->allow_client_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* denied client ip */
        return 0;
    }
    pwinfo->deny_client_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* time */
        return 0;
    }
    if (sscanf(line, "%u-%u", &pwinfo->time_begin, &pwinfo->time_end) == 2 &&
        pwinfo->time_begin < 2360 && (pwinfo->time_begin % 100) < 60 &&
        pwinfo->time_end < 2360 && (pwinfo->time_end % 100) < 60) {
        pwinfo->has_time = 1;
    }
    
    return 0;
}

static int fetch_pw_account(const char * const file, PWInfo * const pwinfo,
                            char * const line, const size_t sizeof_line,
                            const char * const login)
{
    FILE *fp;
    int ret = -1;
    
    if (file == NULL || pwinfo == NULL || line == NULL ||
        sizeof_line < (size_t) 2U || login == NULL ||
        *login == 0) {
        fprintf(stderr, "bad arguments to fetch account\n");
        return -1;
    }
    if ((fp = fopen(file, "r")) == NULL) {
        perror("Unable to open the passwd file");
        return -1;
    }
    while (fgets(line, (int) sizeof_line - 1U, fp) != NULL) {
        strip_lf(line);
        if (*line == 0 || *line == PW_LINE_COMMENT) {
            continue;
        }
        if (parse_pw_line(line, pwinfo) != 0) {
            fprintf(stderr, "Warning: invalid line [%s]\n", line);
            continue;
        }
        if (strcmp(login, pwinfo->login) != 0) {
            continue;
        }
        ret = 0;
        break;
    }
    fclose(fp);

    return ret;
}

static FILE *create_newpasswd(const char * const file,
                              const char * const file2,
                              const char * const skip_login,
                              int error_if_user_exists,
                              int error_if_not_found)
{
    FILE *fp;
    FILE *fp2;
    int fd2;
    int found = 0;
    size_t skip_login_len;
    char line[LINE_MAX];
    
    fp = fopen(file, "r");    
    if ((fd2 = open(file2, O_EXCL | O_NOFOLLOW |
                    O_CREAT | O_WRONLY, (mode_t) 0700)) == -1) {
        if (fp != NULL) {
            fclose(fp);
        }        
        return NULL;
    }
    if ((fp2 = fdopen(fd2, "w")) == NULL) {
        if (fp != NULL) {
            fclose(fp);
        }
        close(fd2);
        
        return NULL;
    }
    if (fp != NULL) {
        if (skip_login != NULL) {
            skip_login_len = strlen(skip_login);
        } else {
            skip_login_len = (size_t) 0U;
        }
        while (fgets(line, (int) sizeof line - 1U, fp) != NULL) {
            if (skip_login_len > (size_t) 0U) {
                if (strncmp(line, skip_login, skip_login_len) == 0 &&
                    line[skip_login_len] == *PW_LINE_SEP) {
                    if (error_if_user_exists != 0) {
                        goto err;
                    }
                    found = 1;
                    continue;
                }
            }
            if (fputs(line, fp2) < 0) {
                err:
                fclose(fp2);                
                unlink(file2);
                if (fp != NULL) {
                    fclose(fp);
                }                                                
                return NULL;
            }
        }
        fflush(fp2);
        fsync(fd2);
    }
    if (error_if_not_found != 0 && found == 0) {
        goto err;
    }
    if (fp != NULL) {
        fclose(fp);
    }
    
    return fp2;
}

static int add_new_pw_line(FILE * const fp2, const PWInfo * const pwinfo)
{
    if (fp2 == NULL) {
        return -1;
    }
    if (fprintf(fp2, 
                "%s" PW_LINE_SEP           /* account */
                "%s" PW_LINE_SEP           /* password */
                "%lu" PW_LINE_SEP          /* uid */
                "%lu" PW_LINE_SEP          /* gid */
                "%s" PW_LINE_SEP           /* gecos */                
                "%s" PW_LINE_SEP           /* home */
                , pwinfo->login, pwinfo->pwd,
                (unsigned long) pwinfo->uid, (unsigned long) pwinfo->gid,
                pwinfo->gecos, pwinfo->home) < 0) {
        return -1;
    }
    if (pwinfo->has_bw_ul != 0) {
        if (fprintf(fp2, "%lu",                 /* bw_ul */
                    (unsigned long) pwinfo->bw_ul) < 0) {
            return -1;
        }
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->has_bw_dl != 0) {
        if (fprintf(fp2, "%lu",                 /* bw_dl */
                    (unsigned long) pwinfo->bw_dl) < 0) {
            return -1;
        }
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->has_ul_ratio != 0) {
        if (fprintf(fp2, "%u",             /* ratio up */
                    pwinfo->ul_ratio) < 0) {
            return -1;
        }        
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->has_dl_ratio != 0) {
        if (fprintf(fp2, "%u",             /* ratio down */
                    pwinfo->dl_ratio) < 0) {
            return -1;
        }        
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->has_per_user_max != 0) {
    if (fprintf(fp2, "%u", pwinfo->per_user_max) < 0) {
        return -1;
    }
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }    
    if (pwinfo->has_quota_files != 0) {
        if (fprintf(fp2, "%llu",           /* files quota */
                    pwinfo->quota_files) < 0) {
            return -1;
        }
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->has_quota_size != 0) {    
        if (fprintf(fp2, "%llu",           /* size quota */
                    pwinfo->quota_size) < 0) {
            return -1;
        }        
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->allow_local_ip != NULL) {
        fprintf(fp2, "%s", pwinfo->allow_local_ip);   /* allowed local ip */
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->deny_local_ip != NULL) {
        fprintf(fp2, "%s", pwinfo->deny_local_ip);    /* denied local ip */
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }    
    if (pwinfo->allow_client_ip != NULL) {
        fprintf(fp2, "%s", pwinfo->allow_client_ip);  /* allowed client ip */
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->deny_client_ip != NULL) {
        fprintf(fp2, "%s", pwinfo->deny_client_ip);   /* denied local ip */
    }
    if (fprintf(fp2, PW_LINE_SEP) < 0) {    
        return -1;
    }
    if (pwinfo->has_time != 0) {
        if (fprintf(fp2, "%u-%u",                     /* time restrictions */
                    pwinfo->time_begin, pwinfo->time_end) < 0) {
            return -1;
        }
    }
    if (fprintf(fp2, "\n") < 0) {
        return -1;
    }
    
    return 0;
}

static char *do_get_passwd(void)
{
    static char pwd[LINE_MAX];
    char pwd2[LINE_MAX];    
    int tries = MAX_PASSWD_CHANGE_TRIES;
       
    *pwd = 0;
    *pwd2 = 0;
    
    again:
    printf("Password: ");
    fflush(stdout);
    disable_echo();
    if (fgets(pwd, (int) (sizeof pwd - 1U), stdin) == NULL) {
        enable_echo();
        return NULL;
    }
    strip_lf(pwd);
    printf("\nEnter it again: ");
    fflush(stdout);
    disable_echo();
    if (fgets(pwd2, (int) (sizeof pwd2 - 1U), stdin) == NULL) {
        enable_echo();
        return NULL;
    }
    strip_lf(pwd2);
    puts("");
    if (strcmp(pwd, pwd2) != 0) {
        if (*pwd2 != 0) {
            memset(pwd2, 0, strlen(pwd2));
        }
        if (*pwd != 0) {
            memset(pwd, 0, strlen(pwd));
        }
        puts("You didn't enter the same password");
        if (--tries > 0) {
            goto again;
        }
        enable_echo();
        
        return NULL;
    }
    if (*pwd2 != 0) {
        memset(pwd2, 0, strlen(pwd2));
    }
    enable_echo();
    
    return pwd;
}

static int do_list(const char * const file)
{
    FILE *fp;
    PWInfo pwinfo;
    char line[LINE_MAX];    
    
    if (file == NULL) {
        fprintf(stderr, "missing file to list accounts\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }
    if ((fp = fopen(file, "r")) == NULL) {
        perror("Unable to open the passwd file");
        return PW_ERROR_MISSING_PASSWD_FILE;        
    }
    while (fgets(line, (int) sizeof line - 1U, fp) != NULL) {
        strip_lf(line);
        if (*line == 0 || *line == PW_LINE_COMMENT) {
            continue;
        }
        if (parse_pw_line(line, &pwinfo) != 0) {
            fprintf(stderr, "Warning: invalid line [%s]\n", line);
            continue;
        }
        if (isatty(1)) {
            printf("%-19s %-39s %-19s\n", pwinfo.login, pwinfo.home, pwinfo.gecos);
        } else {
            printf("%s\t%s\t%s\n", pwinfo.login, pwinfo.home, pwinfo.gecos);            
        }
    }
    fclose(fp);

    return 0;
}

static int do_useradd(const char * const file,
                      const PWInfo * const pwinfo_)
{
    char *file2;
    FILE *fp2;
    PWInfo pwinfo = *pwinfo_;
    
    if (pwinfo.login == NULL || *(pwinfo.login) == 0) {
        fprintf(stderr, "Missing login\n");
        return PW_ERROR_MISSING_LOGIN;
    }
    if (file == NULL) {
        fprintf(stderr, "Missing passwd file\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }
    if (pwinfo.uid <= (uid_t) 0 || pwinfo.gid <= (gid_t) 0) {
        fprintf(stderr, "You must give (non-root) uid and gid\n");
        return PW_ERROR_USERADD_NOT_ROOT;
    }
    if (pwinfo.home == NULL) {
        fprintf(stderr, "Missing home directory\n");        
        return PW_ERROR_USERADD_MISSING_HOME_DIR;
    }
    if (pwinfo.gecos == NULL) {
        if ((pwinfo.gecos = strdup("")) == NULL) {
            no_mem();
        }
    }           
    if ((pwinfo.pwd = do_get_passwd()) == NULL) {
        fprintf(stderr, "Error with entering password - aborting\n");        
        return PW_ERROR_ENTER_PASSWD_PW_ERROR;
    }
    {
        char *cleartext = pwinfo.pwd;

        pwinfo.pwd = best_crypt(cleartext);
        if (*cleartext != 0) {
            memset(cleartext, 0, strlen(cleartext));
        }
    }            
    if ((file2 = newpasswd_filename(file)) == NULL) {
        no_mem();
    }
    if ((fp2 = create_newpasswd(file, file2, pwinfo.login, 1, 0)) == NULL) {
        fprintf(stderr, "Error.\n"
                "Check that [%s] doesn't already exist,\n"
                "and that [%s] can be written.\n", 
                pwinfo.login, file2);
        free(file2);        
        return PW_ERROR_USER_ALREADY_EXIST;
    }    
    if (add_new_pw_line(fp2, &pwinfo) != 0) {
        fprintf(stderr, "Unable to append a line\n");
        goto bye;
    }
    fflush(fp2);
#ifdef HAVE_FILENO
    fsync(fileno(fp2));
#endif  
    if (fclose(fp2) != 0) {
        perror("Unable to close the file");
        goto bye2;
    }
    if (rename(file2, file) != 0) {
        perror("Unable to rename the file");
        goto bye2;
    }
    free(file2);
    return 0;
    
    bye:
    fclose(fp2);
    bye2:
    unlink(file2);
    free(file2);
    
    return PW_ERROR_UNEXPECTED_ERROR;
}

static int do_usermod(const char * const file,
                      const PWInfo *pwinfo)
{
    char *file2;
    FILE *fp2;
    PWInfo fetched_info;
    static char line[LINE_MAX];

    if (pwinfo->login == NULL || *(pwinfo->login) == 0) {
        fprintf(stderr, "Missing login\n");
        return PW_ERROR_MISSING_LOGIN;
    }
    if (file == NULL) {
        fprintf(stderr, "Missing passwd file\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }
    if (fetch_pw_account(file, &fetched_info, line, sizeof line,
                         pwinfo->login) != 0) {
        fprintf(stderr, "Unable to fetch info about user [%s] in file [%s]\n",
                pwinfo->login, file);
        return PW_ERROR_UNABLE_TO_FETCH;
    }
    if (pwinfo->pwd != NULL) {
        char *cleartext = pwinfo->pwd;

        fetched_info.pwd = best_crypt(cleartext);
        if (*cleartext != 0) {
            memset(cleartext, 0, strlen(cleartext));
        }        
    }
    if (pwinfo->uid > (uid_t) 0) {
        fetched_info.uid = pwinfo->uid;
    }
    if (pwinfo->gid > (gid_t) 0) {
        fetched_info.gid = pwinfo->gid;
    }
    if (pwinfo->home != NULL) {
        fetched_info.home = pwinfo->home;
    }
    if (pwinfo->gecos != NULL) {
        fetched_info.gecos = pwinfo->gecos;
    }
    if (pwinfo->has_bw_dl != 0) {
        if (pwinfo->has_bw_dl < 0) {
            fetched_info.has_bw_dl = 0;
        } else {
            fetched_info.has_bw_dl = pwinfo->has_bw_dl;
            fetched_info.bw_dl = pwinfo->bw_dl;
        }
    }
    if (pwinfo->has_bw_ul != 0) {
        if (pwinfo->has_bw_ul < 0) {
            fetched_info.has_bw_ul = 0;            
        } else {
            fetched_info.has_bw_ul = pwinfo->has_bw_ul;
            fetched_info.bw_ul = pwinfo->bw_ul;
        }
    }
    if (pwinfo->has_quota_files != 0) {
        if (pwinfo->has_quota_files < 0) {
            fetched_info.has_quota_files = 0;
        } else {
            fetched_info.has_quota_files = pwinfo->has_quota_files;
            fetched_info.quota_files = pwinfo->quota_files;
        }
    }
    if (pwinfo->has_quota_size != 0) {
        if (pwinfo->has_quota_size < 0) {
            fetched_info.has_quota_size = 0;            
        } else {
            fetched_info.has_quota_size = pwinfo->has_quota_size;
            fetched_info.quota_size = pwinfo->quota_size;
        }
    }
    if (pwinfo->has_ul_ratio != 0) {
        if (pwinfo->has_ul_ratio < 0) {
            fetched_info.has_ul_ratio = 0;            
        } else {
            fetched_info.has_ul_ratio = pwinfo->has_ul_ratio;
            fetched_info.ul_ratio = pwinfo->ul_ratio;
        }
    }
    if (pwinfo->has_dl_ratio != 0) {
        if (pwinfo->has_dl_ratio < 0) {
            fetched_info.has_dl_ratio = 0;
        } else {
            fetched_info.has_dl_ratio = pwinfo->has_dl_ratio;
            fetched_info.dl_ratio = pwinfo->dl_ratio;
        }
    }
    if (pwinfo->allow_local_ip != NULL) {
        fetched_info.allow_local_ip = pwinfo->allow_local_ip;
    }
    if (pwinfo->deny_local_ip != NULL) {
        fetched_info.deny_local_ip = pwinfo->deny_local_ip;
    }
    if (pwinfo->allow_client_ip != NULL) {
        fetched_info.allow_client_ip = pwinfo->allow_client_ip;
    }
    if (pwinfo->deny_client_ip != NULL) {
        fetched_info.deny_client_ip = pwinfo->deny_client_ip;
    }
    if (pwinfo->has_time != 0) {
        if (pwinfo->has_time < 0) {
            fetched_info.has_time = 0;
        } else {
            fetched_info.has_time = pwinfo->has_time;
        }
        fetched_info.time_begin = pwinfo->time_begin;
        fetched_info.time_end = pwinfo->time_end;
    }
    if (pwinfo->has_per_user_max != 0) {
        if (pwinfo->has_per_user_max < 0) {
            fetched_info.has_per_user_max = 0;            
        } else {
            fetched_info.has_per_user_max = pwinfo->has_per_user_max;
            fetched_info.per_user_max = pwinfo->per_user_max;
        }
    }
    if ((file2 = newpasswd_filename(file)) == NULL) {
        no_mem();
    }
    if ((fp2 = create_newpasswd(file, file2, pwinfo->login, 0, 1)) == NULL) {
        fprintf(stderr, "Error.\n"
                "Check that [%s] already exists,\n"
                "and that [%s] can be written.\n", pwinfo->login, file2);
        free(file2);
        return PW_ERROR_USER_ALREADY_EXIST;
    }    
    if (add_new_pw_line(fp2, &fetched_info) != 0) {
        fprintf(stderr, "Unable to append a line\n");
        goto bye;
    }
    fflush(fp2);
#ifdef HAVE_FILENO
    fsync(fileno(fp2));
#endif      
    if (fclose(fp2) != 0) {
        perror("Unable to close the file");
        goto bye2;
    }
    if (rename(file2, file) != 0) {
        perror("Unable to rename the file");
        goto bye2;
    }
    free(file2);
    return 0;
    
    bye:
    fclose(fp2);
    bye2:
    unlink(file2);
    free(file2);
    
    return PW_ERROR_UNEXPECTED_ERROR;
}

static int do_userdel(const char * const file,
                      const PWInfo * const pwinfo)
{
    char *file2;
    FILE *fp2;
    
    if (pwinfo->login == NULL || *(pwinfo->login) == 0) {
        fprintf(stderr, "Missing login\n");
        return -1;
    }
    if (file == NULL) {
        fprintf(stderr, "Missing passwd file\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }    
    if ((file2 = newpasswd_filename(file)) == NULL) {
        no_mem();
    }
    if ((fp2 = create_newpasswd(file, file2, pwinfo->login, 0, 1)) == NULL) {
        fprintf(stderr, "Error.\n"
                "Check that [%s] already exists,\n"
                "and that [%s] can be written.\n", pwinfo->login, file2);
        free(file2);
        return PW_ERROR_USER_ALREADY_EXIST;
    }
    fflush(fp2);
#ifdef HAVE_FILENO
    fsync(fileno(fp2));
#endif
    if (fclose(fp2) != 0) {
        perror("Unable to close the file");
        goto bye2;
    }
    if (rename(file2, file) != 0) {
        perror("Unable to rename the file");
        goto bye2;
    }
    free(file2);
    return 0;
    
    bye2:
    unlink(file2);
    free(file2);
    
    return PW_ERROR_UNEXPECTED_ERROR;
}

static int do_show(const char * const file, const PWInfo * const pwinfo)
{
    PWInfo fetched_info;
    struct passwd *pwd;
    struct group *grp;
    const char *pwd_name = "-";
    const char *grp_name = "-";    
    static char line[LINE_MAX];
    
    if (pwinfo->login == NULL || *(pwinfo->login) == 0) {
        fprintf(stderr, "Missing login\n");
        return PW_ERROR_MISSING_LOGIN;
    }
    if (file == NULL) {
        fprintf(stderr, "Missing passwd file\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }
    if (fetch_pw_account(file, &fetched_info, line, sizeof line,
                         pwinfo->login) != 0) {
        fprintf(stderr, "Unable to fetch info about user [%s] in file [%s]\n",
                pwinfo->login, file);
        return PW_ERROR_UNABLE_TO_FETCH;
    }
    if ((pwd = getpwuid(fetched_info.uid)) != NULL && pwd->pw_name != NULL) {
        pwd_name = pwd->pw_name;
    }
    if ((grp = getgrgid(fetched_info.gid)) != NULL && grp->gr_name != NULL) {
        grp_name = grp->gr_name;
    }
    printf("\n"
           "Login              : %s\n"
           "Password           : %s\n"
           "UID                : %lu (%s)\n"
           "GID                : %lu (%s)\n"
           "Directory          : %s\n"
           "Full name          : %s\n"
           "Download bandwidth : %lu Kb (%s)\n"
           "Upload   bandwidth : %lu Kb (%s)\n"
           "Max files          : %llu (%s)\n"
           "Max size           : %llu Mb (%s)\n"
           "Ratio              : %u:%u (%s:%s)\n"
           "Allowed local  IPs : %s\n"
           "Denied  local  IPs : %s\n"           
           "Allowed client IPs : %s\n"
           "Denied  client IPs : %s\n"           
           "Time restrictions  : %04u-%04u (%s)\n"
           "Max sim sessions   : %u (%s)\n"
           "\n",
           fetched_info.login,
           fetched_info.pwd,
           (unsigned long) fetched_info.uid, pwd_name,
           (unsigned long) fetched_info.gid, grp_name,
           fetched_info.home,
           fetched_info.gecos,
           SHOW_IFEN(fetched_info.has_bw_dl, (unsigned long) fetched_info.bw_dl / 1024UL),
           SHOW_STATE(fetched_info.has_bw_dl),
           SHOW_IFEN(fetched_info.has_bw_ul, (unsigned long) fetched_info.bw_ul / 1024UL),
           SHOW_STATE(fetched_info.has_bw_ul),
           SHOW_IFEN(fetched_info.has_quota_files, (unsigned long long) fetched_info.quota_files),
           SHOW_STATE(fetched_info.has_quota_files),
           SHOW_IFEN(fetched_info.has_quota_size, (unsigned long long) fetched_info.quota_size / (1024ULL * 1024ULL)),
           SHOW_STATE(fetched_info.has_quota_size),
           SHOW_IFEN(fetched_info.has_ul_ratio, fetched_info.ul_ratio),
           SHOW_IFEN(fetched_info.has_dl_ratio, fetched_info.dl_ratio),
           SHOW_STATE(fetched_info.has_ul_ratio),
           SHOW_STATE(fetched_info.has_dl_ratio),
           SHOW_STRING(fetched_info.allow_local_ip),
           SHOW_STRING(fetched_info.deny_local_ip),           
           SHOW_STRING(fetched_info.allow_client_ip),
           SHOW_STRING(fetched_info.deny_client_ip),
           SHOW_IFEN(fetched_info.has_time, fetched_info.time_begin),
           SHOW_IFEN(fetched_info.has_time, fetched_info.time_end),
           SHOW_STATE(fetched_info.has_time),
           SHOW_IFEN(fetched_info.has_per_user_max, fetched_info.per_user_max),
           SHOW_STATE(fetched_info.per_user_max));
    
    return 0;
}

static int do_passwd(const char * const file,
                     PWInfo * const pwinfo)
{
    if (pwinfo->login == NULL || *(pwinfo->login) == 0) {
        fprintf(stderr, "Missing login\n");
        return PW_ERROR_MISSING_LOGIN;
    }
    if (file == NULL) {
        fprintf(stderr, "Missing passwd file\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }
    if ((pwinfo->pwd = do_get_passwd()) == NULL) {
        fprintf(stderr, "Error with entering password - aborting\n");        
        return PW_ERROR_ENTER_PASSWD_PW_ERROR;
    }    
    return do_usermod(file, pwinfo);
}

static int do_mkdb(const char *dbfile, const char * const file)
{
    FILE *fp;
    char *index_dbfile;
    size_t sizeof_index_dbfile;
    char *data_dbfile;
    size_t sizeof_data_dbfile;
    char *s;
    PureDBW dbw;
    int ret = PW_ERROR_UNEXPECTED_ERROR;
    char line[LINE_MAX];
    
    if (dbfile == NULL || *dbfile == 0) {
        char *dbfile_;
        
        if ((dbfile_ = getenv(ENV_DEFAULT_PW_DB)) != NULL && *dbfile_ != 0) {
            dbfile = dbfile_;
        } else {        
            dbfile = DEFAULT_PW_DB;
        }
    }
    if (file == NULL) {
        fprintf(stderr, "Missing passwd file\n");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }    
    if ((fp = fopen(file, "r")) == NULL) {
        perror("Unable to open the passwd file");
        return PW_ERROR_MISSING_PASSWD_FILE;
    }
    sizeof_index_dbfile = strlen(dbfile) + sizeof NEWPASSWD_INDEX_SUFFIX;
    if ((index_dbfile = ALLOCA(sizeof_index_dbfile)) == NULL) {
        fclose(fp);
        no_mem();
    }
    sizeof_data_dbfile = strlen(dbfile) + sizeof NEWPASSWD_DATA_SUFFIX;
    if ((data_dbfile = ALLOCA(sizeof_data_dbfile)) == NULL) {
        fclose(fp);
        ALLOCA_FREE(index_dbfile);
        no_mem();
    }
    snprintf(index_dbfile, sizeof_index_dbfile, "%s%s",
             dbfile, NEWPASSWD_INDEX_SUFFIX);
    snprintf(data_dbfile, sizeof_data_dbfile, "%s%s",
             dbfile, NEWPASSWD_DATA_SUFFIX);
    if (puredbw_open(&dbw, index_dbfile, data_dbfile, dbfile) != 0) {
        perror("Unable to create the database");
        goto err;
    }
    while (fgets(line, (int) sizeof line - 1U, fp) != NULL) {
        strip_lf(line);
        if (*line == PW_LINE_COMMENT) {
            continue;
        }
        if (*line == 0 || (s = strchr(line, *PW_LINE_SEP)) == NULL ||
            s[1] == 0) {
            continue;
        }
        *s++ = 0;
        if (puredbw_add_s(&dbw, line, s) != 0) {
            perror("Error while indexing a new entry");
            goto err;
        }
    }
    if (puredbw_close(&dbw) != 0) {
        perror("Unable to close the database");
    } else {
        ret = 0;
    }
    err:
    puredbw_free(&dbw);
    ALLOCA_FREE(index_dbfile);
    ALLOCA_FREE(data_dbfile);    
    fclose(fp);
    
    return ret;
}

static void init_zrand(void)
{
    struct timeval tv;
    struct timezone tz;
    
    gettimeofday(&tv, &tz);
#ifdef HAVE_SRANDOMDEV
    srandomdev();
#elif defined(HAVE_RANDOM)
    srandom((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#else
    srand((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#endif
}

int main(int argc, char *argv[])
{
    const char *action;
    char *file = NULL;
    char *dbfile = NULL;
    PWInfo pwinfo;
    int fodder;
    int ret = 0;
    int with_chroot = 1;
    int with_mkdb = 0;
        
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

#ifdef PROBE_RANDOM_AT_RUNTIME
    pw_zrand_probe();
#endif
    
    pwinfo.pwd = NULL;
    pwinfo.gecos = NULL;
    pwinfo.home = NULL;
    pwinfo.allow_local_ip = pwinfo.deny_local_ip = NULL;
    pwinfo.allow_client_ip = pwinfo.deny_client_ip = NULL;        
    pwinfo.has_bw_dl = 0;
    pwinfo.has_bw_ul = 0;
    pwinfo.has_quota_files = 0;
    pwinfo.has_quota_size = 0;
    pwinfo.has_ul_ratio = 0;
    pwinfo.has_dl_ratio = 0;
    pwinfo.has_time = 0;
    pwinfo.time_begin = pwinfo.time_end = 0U;
    pwinfo.has_per_user_max = 0;
    pwinfo.per_user_max = 0U;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
    pwinfo.uid = (uid_t) 42U;
    pwinfo.gid = (gid_t) 42U;
#else
    pwinfo.uid = (uid_t) 0U;
    pwinfo.gid = (gid_t) 0U;
#endif
    
    argv++;
    argc--;
    action = *argv;
    if (argc > 1) {
        argv++;
        argc--;
        pwinfo.login = *argv;
    } else {
        pwinfo.login = NULL;
    }
    filter_pw_line_sep(pwinfo.login);
    while ((fodder =
            getopt(argc, argv, 
                   "c:d:D:f:F:g:hi:I:mn:N:q:Q:r:R:t:T:u:y:z:")) != -1) {
        switch(fodder) {
        case 'c' : {
            if ((pwinfo.gecos = strdup(optarg)) == NULL) {
                no_mem();
            }
            filter_pw_line_sep(pwinfo.gecos);
            break;
        }
        case 'D' :
            with_chroot = 0;
        case 'd' : {
            char *optarg_copy;
            size_t sizeof_home;
            size_t optarg_len;
            
            if ((optarg_copy = strdup(optarg)) == NULL) {
                no_mem();
            }
            again:
            optarg_len = strlen(optarg_copy);
            if (optarg_len < (size_t) 1U) {
                fprintf(stderr, "home directory is missing\n");
                exit(EXIT_FAILURE);
            }
            if (optarg_copy[optarg_len - 1U] == '/') {
                optarg_len--;
                optarg_copy[optarg_len] = 0;
                goto again;
            }
            sizeof_home = optarg_len + sizeof "/./";
            if ((pwinfo.home = malloc(sizeof_home)) == NULL) {
                no_mem();
            }
            snprintf(pwinfo.home, sizeof_home, "%s%s", optarg_copy,
                     with_chroot != 0 ? "/./" : "");
            filter_pw_line_sep(pwinfo.home);            
            break;
        }
        case 'f' : {
            if ((file = strdup(optarg)) == NULL) {
                no_mem();
            }
            break;
        }
        case 'F' : {
            if ((dbfile = strdup(optarg)) == NULL) {
                no_mem();
            }
            break;
        }
        case 'g' : {
            struct group *gr;
            
            if (pwinfo.gid > (gid_t) 0 && pwinfo.uid <= (uid_t) 0) {
                fprintf(stderr, "You already gave a gid\n");
                exit(EXIT_FAILURE);
            }                
            if ((gr = getgrnam(optarg)) != NULL) {
                pwinfo.gid = gr->gr_gid;
            } else {
                pwinfo.gid = (gid_t) strtoul(optarg, NULL, 10);
            }            
            break;
        }
        case 'h' : {
            help();
            /* doesn't return */
        }
        case 'i' : {
            if ((pwinfo.allow_local_ip = strdup(optarg)) == NULL) {
                no_mem();
            }
            break;
        }
        case 'I' : {
            if ((pwinfo.deny_local_ip = strdup(optarg)) == NULL) {
                no_mem();
            }
            break;
        }
        case 'm' : {
            with_mkdb = 1;
            break;
        }
        case 'n' : {
            if (*optarg == 0) {
                pwinfo.has_quota_files = -1;
            } else {
                pwinfo.quota_files = strtoull(optarg, NULL, 10);
                pwinfo.has_quota_files = 1;
            }
            break;
        }
        case 'N' : {
            if (*optarg == 0) {
                pwinfo.has_quota_size = -1;
            } else {
                pwinfo.quota_size = strtoull(optarg, NULL, 10) * 
                    (1024ULL * 1024ULL);
                pwinfo.has_quota_size = 1;
            }
            break;
        }
        case 'q' : {
            if (*optarg == 0) {
                pwinfo.has_ul_ratio = -1;
            } else {
                pwinfo.ul_ratio = (unsigned int) strtoul(optarg, NULL, 10);
                if (pwinfo.ul_ratio < 1U) {
                    fprintf(stderr, "Illegal upload ratio\n");
                    exit(EXIT_FAILURE);
                }
                pwinfo.has_ul_ratio = 1;
            }
            break;
        }            
        case 'Q' : {
            if (*optarg == 0) {
                pwinfo.has_dl_ratio = -1;
            } else {
                pwinfo.dl_ratio = (unsigned int) strtoul(optarg, NULL, 10);
                if (pwinfo.dl_ratio < 1U) {
                    fprintf(stderr, "Illegal download ratio\n");
                    exit(EXIT_FAILURE);
                }            
                pwinfo.has_dl_ratio = 1;
            }
            break;
        }
        case 'r' : {
            if ((pwinfo.allow_client_ip = strdup(optarg)) == NULL) {
                no_mem();
            }
            break;
        }
        case 'R' : {
            if ((pwinfo.deny_client_ip = strdup(optarg)) == NULL) {
                no_mem();
            }
            break;
        }            
        case 't' : {
            if (*optarg == 0) {
                pwinfo.has_bw_dl = -1;
            } else {
                if ((pwinfo.bw_dl = strtoul(optarg, NULL, 10)) > 0UL) {
                    pwinfo.bw_dl *= 1024UL;                    
                    pwinfo.has_bw_dl = 1;
                }
            }
            break;
        }
        case 'T' : {
            if (*optarg == 0) {
                pwinfo.has_bw_ul = -1;
            } else {
                if ((pwinfo.bw_ul = strtoul(optarg, NULL, 10)) > 0UL) {
                    pwinfo.bw_ul *= 1024UL;
                    pwinfo.has_bw_ul = 1;
                }
            }
            break;
        }            
        case 'u' : {
            struct passwd *pw;                
            
            if (pwinfo.uid > (uid_t) 0) {
                fprintf(stderr, "You already gave an uid\n");
                exit(EXIT_FAILURE);
            }
            if ((pw = getpwnam(optarg)) != NULL) {
                pwinfo.uid = pw->pw_uid;
                if (pwinfo.gid <= (gid_t) 0) {
                    pwinfo.gid = pw->pw_gid;
                }
            } else {
                pwinfo.uid = (uid_t) strtoul(optarg, NULL, 10);
            }
            break;
        }
    case 'y' : {
        if ((pwinfo.per_user_max = (unsigned int) strtoul(optarg, NULL, 10)) <= 0U) {
                pwinfo.has_per_user_max = -1;
            } else {
                pwinfo.has_per_user_max = 1;
            }
        break;
    }
        case 'z' : {
            if (sscanf(optarg, "%u-%u", 
                       &pwinfo.time_begin, &pwinfo.time_end) == 2 &&
                pwinfo.time_begin < 2360 && (pwinfo.time_begin % 100) < 60 &&
                pwinfo.time_end < 2360 && (pwinfo.time_end % 100) < 60) {
                pwinfo.has_time = 1;
            } else if (*optarg != 0) {
                fprintf(stderr, "Time should be given as hhmm-hhmm\n"
                        "Example : 0900-1800 (9 am to 6 pm)\n");
                exit(EXIT_FAILURE);                    
            } else {
                pwinfo.has_time = -1;
            }
            break;
        }
        case '?' :
            help();
        }
    }
    if (file == NULL) {
        char *file_;
        
        if ((file_ = getenv(ENV_DEFAULT_PW_FILE)) != NULL && *file_ != 0) {
            file = file_;
        } else if ((file = strdup(DEFAULT_PW_FILE)) == NULL) {
            no_mem();
        }
    }
    (void) umask(0177);
    init_zrand();
    if (strcasecmp(action, "useradd") == 0) {
        ret = do_useradd(file, &pwinfo);
        if (with_mkdb != 0) {
            ret |= do_mkdb(dbfile, file);
        }
    } else if (strcasecmp(action, "usermod") == 0) {
        ret = do_usermod(file, &pwinfo);
        if (with_mkdb != 0) {
            ret |= do_mkdb(dbfile, file);
        }        
    } else if (strcasecmp(action, "userdel") == 0) {
        ret = do_userdel(file, &pwinfo);
        if (with_mkdb != 0) {
            ret |= do_mkdb(dbfile, file);
        }        
    } else if (strcasecmp(action, "passwd") == 0) {
        ret = do_passwd(file, &pwinfo);
        if (with_mkdb != 0) {
            ret |= do_mkdb(dbfile, file);
        }        
    } else if (strcasecmp(action, "show") == 0) {
        ret = do_show(file, &pwinfo);
    } else if (strcasecmp(action, "mkdb") == 0) {
        ret = do_mkdb(pwinfo.login, file);
    } else if (strcasecmp(action, "list") == 0) {
        ret = do_list(file);
    } else {
        ret = PW_ERROR_UNEXPECTED_ERROR;
        help();
    }
               
    return ret;
}

