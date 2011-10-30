#include <config.h>

#include "ftpd.h"
#include "ls_p.h"
#include "bsd-glob.h"
#include "messages.h"
#include "dynamic.h"
#include "ftpwho-update.h"
#include "globals.h"
#include "safe_rw.h"
#ifdef WITH_TLS
# include "tls.h"
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void wrstr(const int f, void * const tls_fd, const char *s)
{
    static char outbuf[CONF_TCP_SO_SNDBUF];
    static size_t outcnt;
    size_t l;
    
    if (s == NULL) {
        if (outcnt > (size_t) 0U) {
#ifdef WITH_TLS
            if (tls_fd != NULL) {
                if (secure_safe_write(tls_fd, outbuf, outcnt) !=
                    (ssize_t) outcnt) {
                    return;
                } 
            } else
#endif      
            {
                (void) tls_fd;
                if (safe_write(f, outbuf, outcnt, -1) != (ssize_t) outcnt) {
                    return;
                }
            }
        }
        outcnt = (size_t) 0U;
        return;
    }
    if ((l = strlen(s)) <= (size_t) 0U) {
        return;
    }
    if (l <= (sizeof outbuf - outcnt)) {
        memcpy(outbuf + outcnt, s, l); /* secure, see above */
        outcnt += l;
        return;
    }
    if (outcnt < sizeof outbuf) {
        const size_t rest = sizeof outbuf - outcnt;
        
        memcpy(outbuf + outcnt, s, rest);   /* secure, see above */
        s += rest;
        l -= rest;
    }
#ifdef WITH_TLS
    if (data_protection_level == CPL_PRIVATE) {
        if (secure_safe_write(tls_fd, outbuf, sizeof outbuf) !=
            (ssize_t) sizeof outbuf) {
            return;
        } 
    } else
#endif
    {       
        if (safe_write(f, outbuf, sizeof outbuf, -1) !=
            (ssize_t) sizeof outbuf) {
            return;
        }
    }
#ifdef WITH_TLS
    if (data_protection_level == CPL_PRIVATE) {    
        while (l > sizeof outbuf) {
            if (secure_safe_write(tls_fd, s, sizeof outbuf) !=
                (ssize_t) sizeof outbuf) {
                return;
            }
            s += sizeof outbuf;
            l -= sizeof outbuf;
        } 
    } else
#endif
    {
        while (l > sizeof outbuf) {
            if (safe_write(f, s, sizeof outbuf, -1) !=
                (ssize_t) sizeof outbuf) {
                return;
            }
            s += sizeof outbuf;
            l -= sizeof outbuf;
        }
    }
    if (l > (size_t) 0U) {
        memcpy(outbuf, s, l);          /* safe, l <= sizeof outbuf */
        outcnt = l;
    }
}

#ifdef NO_FTP_USERS
const char *getname(const uid_t uid)
{
    static char number[11];

    snprintf(number, sizeof number, "%-10d", uid);
    return number;
}

const char *getgroup(const gid_t gid)
{
    static char number[11];

    snprintf(number, sizeof number, "%-10d", gid);
    return number;
}
#else

const char *getname(const uid_t uid)
{
    struct userid *p;
    struct passwd *pwd = NULL;

    for (p = user_head; p; p = p->next) {
        if (p->uid == uid) {
            return p->name;
        }
    }
    if (
# ifndef ALWAYS_RESOLVE_IDS
        chrooted == 0 && 
# endif
        authresult.slow_tilde_expansion == 0) {
        pwd = getpwuid(uid);
    }
    if ((p = malloc(sizeof *p)) == NULL) {
        die_mem();
    }
    p->uid = uid;
    if ((p->name = malloc((size_t) 11U)) == NULL) {
        die_mem();
    }
    if (pwd != NULL) {
        if (SNCHECK(snprintf(p->name, (size_t) 11U, 
                             "%-10.10s", pwd->pw_name), (size_t) 11U)) {
            _EXIT(EXIT_FAILURE);
        }
    } else {
        if (SNCHECK(snprintf(p->name, (size_t) 11U, "%-10d", uid), 
                    (size_t) 11U)) {
            _EXIT(EXIT_FAILURE);
        }
    }
    p->next = user_head;
    user_head = p;
    
    return p->name;
}

/* eeeehm... sorry for names, ya know copy&paste :))) */
const char *getgroup(const gid_t gid)
{
    struct groupid *p;
    struct group *pwd = NULL;

    for (p = group_head; p; p = p->next) {
        if (p->gid == gid) {
            return p->name;
        }
    } 
# ifndef ALWAYS_RESOLVE_IDS   
    if (chrooted == 0) 
# endif
    {
        pwd = getgrgid(gid);
    }
    if ((p = malloc(sizeof *p)) == NULL) {
        die_mem();
    }
    p->gid = gid;
    if ((p->name = malloc((size_t) 11U)) == NULL) {
        die_mem();
    }
    if (pwd != NULL) {
        if (SNCHECK(snprintf(p->name, (size_t) 11U, "%-10.10s",
                             pwd->gr_name), (size_t) 11U)) {
            _EXIT(EXIT_FAILURE);
        }
    } else {
        if (SNCHECK(snprintf(p->name, (size_t) 11U, "%-10d", gid), 
                    (size_t) 11U)) {
            _EXIT(EXIT_FAILURE);
        }
    }
    p->next = group_head;
    group_head = p;
    
    return p->name;
}
#endif

static void addfile(const char *name, const char *suffix)
{
    struct filename *p;
    unsigned int l;

    if (!name || !suffix) {
        return;
    }
    if (matches >= max_ls_files) {
        return;
    }
    matches++;
    l = (unsigned int) (strlen(name) + strlen(suffix));
    if (l > colwidth) {
        colwidth = l;
    }
    if ((p = malloc(offsetof(struct filename, line) + l + 1U)) == NULL) {
        return;
    }
    if (SNCHECK(snprintf(p->line, l + 1U, "%s%s", name, suffix), l + 1U)) {
        _EXIT(EXIT_FAILURE);
    }
    if (tail != NULL) {
        tail->down = p;
    } else {
        head = p;
    }
    tail = p;
    filenames++;
}

/* listfile returns non-zero if the file is a directory */
static int listfile(const PureFileInfo * const fi, const char *name)
{
    int rval = 0;
    struct stat st;
    struct tm *t;
    char suffix[2] = { 0, 0 };
    char m[MAXPATHLEN + 1U];    

#ifndef MINIMAL
    if (modern_listings != 0) {
        const char *n;
        char *alloca_nameline;
        const size_t sizeof_nameline = MAXPATHLEN + 256U;

        if (fi == NULL) {
            n = name;
        } else {
            n = FI_NAME(fi);
        }
        if ((alloca_nameline = ALLOCA(sizeof_nameline)) == NULL) {
            return 0;
        }
        if ((rval = modernformat(n, alloca_nameline,
                                 sizeof_nameline, "")) < 0) {
            ALLOCA_FREE(alloca_nameline);            
            return 0;
        }
        addfile(alloca_nameline, suffix);
        ALLOCA_FREE(alloca_nameline);
        
        return rval;
    }
#endif
    if (fi == NULL) {
        if (lstat(name, &st) < 0) {
            return 0;
        }    
    } else {
        st.st_size = fi->size;
        st.st_mtime = fi->mtime;        
        st.st_mode = fi->mode;
        st.st_nlink = fi->nlink;        
        st.st_uid = fi->uid;
        st.st_gid = fi->gid;
        name = FI_NAME(fi);
    }
#if defined(WITH_VIRTUAL_CHROOT) && defined(S_IFLNK) && defined(S_IFDIR)
    if (S_ISLNK(st.st_mode) && name[0] == '.' &&
        name[1] == '.' && name[2] == 0) {
        st.st_mode &= ~S_IFLNK;
        st.st_mode |= S_IFDIR;
    }  /* Hack to please some Windows clients that dislike ../ -> ../ */
#endif
#if !defined(MINIMAL) && !defined(ALWAYS_SHOW_SYMLINKS_AS_SYMLINKS)
    if (
# ifndef ALWAYS_SHOW_RESOLVED_SYMLINKS
        broken_client_compat != 0 &&
# endif
        S_ISLNK(st.st_mode)) {
        struct stat sts;
        
        if (stat(name, &sts) == 0 && !S_ISLNK(sts.st_mode)) {
            st = sts;
        }
    } /* Show non-dangling symlinks as files/directories */
#endif
#ifdef DISPLAY_FILES_IN_UTC_TIME
    t = gmtime((time_t *) &st.st_mtime);
#else
    t = localtime((time_t *) &st.st_mtime);
#endif
    if (t == NULL) {
        logfile(LOG_ERR, "{gm,local}gtime() for [%s]", name);
        return 0;
    }
    if (opt_F) {
        if (S_ISLNK(st.st_mode))
            suffix[0] = '@';
        else if (S_ISDIR(st.st_mode)) {
            suffix[0] = '/';
            rval = 1;
        } else if (st.st_mode & 010101) {
            suffix[0] = '*';
        }
    }
    if (opt_l) {
        strncpy(m, " ---------", (sizeof m) - (size_t) 1U);
        m[(sizeof m) - (size_t) 1U] = 0;
        switch (st.st_mode & S_IFMT) {
        case S_IFREG:
            m[0] = '-';
            break;
        case S_IFLNK:
            m[0] = 'l';
            break;            /* readlink() here? */
        case S_IFDIR:
            m[0] = 'd';
            rval = 1;
            break;
        }
        if (m[0] != ' ') {
            char *alloca_nameline;
            const size_t sizeof_nameline = MAXPATHLEN + MAXPATHLEN + 128U;
            char timeline[6U];
            
            if (st.st_mode & 0400) {
                m[1] = 'r';
            }
            if (st.st_mode & 0200) {
                m[2] = 'w';
            }
            if (st.st_mode & 0100) {
                m[3] = (char) (st.st_mode & 04000 ? 's' : 'x');
            } else if (st.st_mode & 04000) {
                m[3] = 'S';
            }
            if (st.st_mode & 040) {
                m[4] = 'r';
            }
            if (st.st_mode & 020) {
                m[5] = 'w';
            }
            if (st.st_mode & 010) {
                m[6] = (char) (st.st_mode & 02000 ? 's' : 'x');
            } else if (st.st_mode & 02000) {
                m[6] = 'S';
            }
            if (st.st_mode & 04) {
                m[7] = 'r';
            }
            if (st.st_mode & 02) {
                m[8] = 'w';
            }
            if (st.st_mode & 01) {
                m[9] = (char) (st.st_mode & 01000 ? 't' : 'x');
            } else if (st.st_mode & 01000) {
                m[9] = 'T';
            }            
            if (time(NULL) - st.st_mtime > 180 * 24 * 60 * 60) {
                if (SNCHECK(snprintf(timeline, sizeof timeline, "%5d",
                                     t->tm_year + 1900), sizeof timeline)) {
                    _EXIT(EXIT_FAILURE);
                }
            } else {
                if (SNCHECK(snprintf(timeline, sizeof timeline, "%02d:%02d",
                                     t->tm_hour, t->tm_min), sizeof timeline)) {
                    _EXIT(EXIT_FAILURE);
                }
            }
            if ((alloca_nameline = ALLOCA(sizeof_nameline)) == NULL) {
                return 0;
            }
            if (SNCHECK(snprintf(alloca_nameline, sizeof_nameline,
                                 "%s %4u %s %s %10llu %s %2d %s %s", 
                                 m, (unsigned int) st.st_nlink,
                                 getname(st.st_uid),
                                 getgroup(st.st_gid), 
                                 (unsigned long long) st.st_size,
                                 months[t->tm_mon],
                                 t->tm_mday, timeline, name),
                        sizeof_nameline)) {
                ALLOCA_FREE(alloca_nameline);
                _EXIT(EXIT_FAILURE);
            }
            if (S_ISLNK(st.st_mode)) {
                char *p = alloca_nameline + strlen(alloca_nameline);                
                {
                    ssize_t sx;
                    
                    if ((sx = readlink(name, m, sizeof m - 1U)) > 0) {
                        m[sx] = 0;
                    } else {
                        m[0] = m[1] = '.';
                        m[2] = 0;
                    }
                }
                suffix[0] = 0;
                if (opt_F && stat(name, &st) == 0) {
                    if (S_ISLNK(st.st_mode)) {
                        suffix[0] = '@';
                    } else if (S_ISDIR(st.st_mode)) {
                        suffix[0] = '/';
                    } else if (st.st_mode & 010101) {
                        suffix[0] = '*';
                    }
                }
                /* 2 * MAXPATHLEN + gap should be enough, but be paranoid... */
                if (SNCHECK
                    (snprintf(p, (sizeof_nameline) - strlen(alloca_nameline),
                              " -> %s", m), 
                     (sizeof_nameline) - strlen(alloca_nameline))) {
                    ALLOCA_FREE(alloca_nameline);                    
                    _EXIT(EXIT_FAILURE);
                }
            }
            addfile(alloca_nameline, suffix);
            ALLOCA_FREE(alloca_nameline);            
        }                    /* hide non-downloadable files */
    } else {        
        if (S_ISREG(st.st_mode) ||
            S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
            addfile(name, suffix);
        }
    }
    return rval;
}

static void outputfiles(int f, void * const tls_fd)
{
    unsigned int n;
    struct filename *p;
    struct filename *q;
    char *c_buf; /* buffer with charset of client */

    (void) c_buf;
    if (!head) {
        return;
    }
    tail->down = NULL;
    tail = NULL;
    colwidth = (colwidth | 7U) + 1U;
    if (opt_l != 0 || opt_C == 0) {
        colwidth = 75U;
    }
    /* set up first column */
    p = head;
    p->top = 1;
    if (colwidth > 75U) {
        n = filenames;
    } else {
        n = (filenames + (75U / colwidth) - 1U) / (75U / colwidth);
    }
    while (n && p) {
        p = p->down;
        if (p != NULL) {
            p->top = 0;
        }
        n--;
    }

    /* while there's a neighbour to the right, point at it */
    q = head;
    while (p) {
        p->top = q->top;
        q->right = p;
        q = q->down;
        p = p->down;
    }

    /* some are at the right end */
    while (q) {
        q->right = NULL;
        q = q->down;
    }

    /* don't want wraparound, do we? */
    p = head;
    while (p && p->down && !p->down->top) {
        p = p->down;
    }
    if (p && p->down) {
        p->down = NULL;
    }

    /* print each line, which consists of each column */
    p = head;
    while (p) {
        q = p;
        p = p->down;
        while (q) {
            char pad[6];
            char *tmp = (char *) q;

            if (q->right) {
                memset(pad, '\t', sizeof pad - 1U);
                pad[(sizeof pad) - 1] = 0;
                pad[(colwidth + 7U - strlen(q->line)) / 8] = 0;
            } else {
                pad[0] = '\r';
                pad[1] = '\n';
                pad[2] = 0;
            }
#ifdef WITH_RFC2640
            c_buf = charset_fs2client(q->line);
            wrstr(f, tls_fd, c_buf);
            free(c_buf);
#else
            wrstr(f, tls_fd, q->line);
#endif
            wrstr(f, tls_fd, pad);
            q = q->right;
            free(tmp);
        }
    }

    /* reset variables for next time */
    head = tail = NULL;
    colwidth = 0U;
    filenames = 0U;
}

/* functions to to sort for qsort() */
static int cmp(const void * const a, const void * const b)
{    
    return strcmp(FI_NAME((const PureFileInfo *) a),
                  FI_NAME((const PureFileInfo *) b));
}

static int cmp_r(const void * const a, const void * const b)
{    
    return strcmp(FI_NAME((const PureFileInfo *) b),
                  FI_NAME((const PureFileInfo *) a));
}

static int cmp_t(const void * const a, const void * const b)
{    
    if (((const PureFileInfo *) a)->mtime < ((const PureFileInfo *) b)->mtime) {
        return 1;
    }
    if (((const PureFileInfo *) a)->mtime > ((const PureFileInfo *) b)->mtime) {
        return -1;
    }
    return 0;
}

static int cmp_rt(const void * const a, const void * const b)
{    
    return cmp_t(b, a);
}

static int cmp_S(const void * const a, const void * const b)
{    
    if (((const PureFileInfo *) a)->size < ((const PureFileInfo *) b)->size) {
        return 1;
    }
    if (((const PureFileInfo *) a)->size > ((const PureFileInfo *) b)->size) {
        return -1;
    }
    return 0;
}

static int cmp_rS(const void * const a, const void * const b)
{    
    return cmp_S(b, a);
}

static PureFileInfo *sreaddir(char **names_pnt)
{
    struct stat st;
    DIR *d;
    struct dirent *de;    
    PureFileInfo *files_info;
    PureFileInfo *file_info;
    size_t files_info_size;
    size_t files_info_counter = (size_t) 0U;
    char *names;
    size_t names_size;
    size_t names_counter = (size_t) 0U;
    size_t name_len;
    int (*cmp_func)(const void * const, const void * const);
    
    if ((d = opendir(".")) == NULL) {
        return NULL;
    }
    names_size = CHUNK_SIZE;
    if ((names = malloc(names_size)) == NULL) {
        closedir(d);
        return NULL;
    }
    files_info_size = CHUNK_SIZE / sizeof *files_info;
    if ((files_info = malloc(files_info_size * sizeof *files_info)) == NULL) {
        closedir(d);
        free(names);
        return NULL;
    }
    while ((de = readdir(d)) != NULL) {
        if (checkprintable(de->d_name) != 0 || lstat(de->d_name, &st) < 0) {
            continue;
        }
        name_len = strlen(de->d_name) + (size_t) 1U;        
        while (names_counter + name_len >= names_size) {
            char *new_names;
        
            if (name_len >= CHUNK_SIZE) {
                names_size += name_len + CHUNK_SIZE;
            } else {
                names_size += CHUNK_SIZE;
            }
            if ((new_names = realloc(names, names_size)) == NULL) {
                nomem:
                closedir(d);
                free(names);
                free(files_info);
                return NULL;
            }
            names = new_names;
        }
        while ((files_info_counter + (size_t) 1U) >= files_info_size) {
            PureFileInfo *new_files_info;
            
            files_info_size += (CHUNK_SIZE / sizeof *files_info);
            if ((new_files_info = realloc(files_info, 
                                          files_info_size * sizeof *files_info)) == NULL) {
                goto nomem;
            }
            files_info = new_files_info;
        }        
        memcpy(&names[names_counter], de->d_name, name_len);   /* safe */
        names[names_counter + name_len - 1] = 0;
        file_info = &files_info[files_info_counter];
        file_info->names_pnt = names_pnt;
        file_info->name_offset = names_counter;
        file_info->size = st.st_size;
        file_info->mtime = st.st_mtime;
        file_info->mode = st.st_mode;
        file_info->nlink = st.st_nlink;
        file_info->uid = st.st_uid;        
        file_info->gid = st.st_gid;
        names_counter += name_len;
        files_info_counter++;
    }    
    closedir(d);
    files_info[files_info_counter].name_offset = (size_t) -1;
    *names_pnt = names;    

    if (opt_t) {
        if (opt_r) {
            cmp_func = cmp_rt;
        } else {
            cmp_func = cmp_t;
        }
    } else if (opt_S) {
        if (opt_r) {
            cmp_func = cmp_rS;
        } else {
            cmp_func = cmp_S;
        }
    } else if (opt_r) {
        cmp_func = cmp_r;
    } else {
        cmp_func = cmp;
    }
    qsort(files_info, files_info_counter, sizeof files_info[0], cmp_func);    
    
    return files_info;
}

/* have to change to the directory first (speed hack for -R) */
static void listdir(unsigned int depth, int f, void * const tls_fd,
                    const char *name)
{
    PureFileInfo *dir;
    char *names;
    PureFileInfo *s;
    PureFileInfo *r;
    char *c_buf;
    int d;
    
    if (depth >= max_ls_depth || matches >= max_ls_files) {
        return;
    }
    if ((dir = sreaddir(&names)) == NULL) {
        addreply(226, MSG_CANT_READ_FILE, name);
        return;
    }
    s = dir;
    while (s->name_offset != (size_t) -1) {
        if (FI_NAME(s)[0] != '.') {
            d = listfile(s, NULL);
        } else if (opt_a) {
            d = listfile(s, NULL);
            if (FI_NAME(s)[1] == 0 ||
                (FI_NAME(s)[1] == '.' && FI_NAME(s)[2] == 0)) {
                d = 0;
            }
        } else {
            d = 0;
        }
        if (!d) {
            s->name_offset = (size_t) -1;
        }
        s++;
    }
    outputfiles(f, tls_fd);
    r = dir;
    while (opt_R && r != s) {
        if (r->name_offset != (size_t) -1 && !chdir(FI_NAME(r))) {
            char *alloca_subdir;
            const size_t sizeof_subdir = MAXPATHLEN + 1U;
            
            if ((alloca_subdir = ALLOCA(sizeof_subdir)) == NULL) {
                goto toomany;
            }
            if (SNCHECK(snprintf(alloca_subdir, sizeof_subdir, "%s/%s",
                                 name, FI_NAME(r)), sizeof_subdir)) {
                goto nolist;
            }
#ifdef WITH_RFC2640
            c_buf = charset_fs2client(alloca_subdir);
#else
            c_buf = alloca_subdir;
#endif
#ifndef MINIMAL
            if (modern_listings == 0) {
#endif                
#ifdef FANCY_LS_DIRECTORY_HEADERS
                wrstr(f, tls_fd, "\r\n>----------------[");
                wrstr(f, tls_fd, c_buf);
                wrstr(f, tls_fd, "]----------------<\r\n\r\n");
#else
                wrstr(f, tls_fd, "\r\n\r\n");
                wrstr(f, tls_fd, c_buf);
                wrstr(f, tls_fd, ":\r\n\r\n");                    
#endif
#ifndef MINIMAL
            }
#endif
#ifdef WITH_RFC2640            
            free(c_buf);
#endif            
            listdir(depth + 1U, f, tls_fd, alloca_subdir);
            nolist:
            ALLOCA_FREE(alloca_subdir);
            if (matches >= max_ls_files) {
                goto toomany;
            }                
            if (chdir("..")) {    /* defensive in the extreme... */
                chdir(wd);
                if (chdir(name)) {    /* someone rmdir()'d it? */
                    die(421, LOG_ERR, "chdir: %s" ,
                        strerror(errno));
                }
            }
        }
        r++;
    }
    toomany:
    free(names);
    free(dir);
    names = NULL;
}

static char *unescape_and_return_next_file(char * const str) {
    char *pnt = str;
    signed char seen_backslash = 0;    
    
    while (*pnt != 0) {
        if (seen_backslash == 0) {
            if (*pnt == '\\') {
                seen_backslash = 1;
            } else if (*pnt == ' ') {
                *pnt++ = 0;
                if (*pnt != 0) {
                    return pnt;
                }
                break;
            }
            pnt++;            
        } else {
            seen_backslash = 0;
            if (*pnt == ' ' || *pnt == '\\' || *pnt == '{' || *pnt == '}') {
                memmove(pnt - 1, pnt, strlen(pnt) + (size_t) 1U);
            }
        }
    }
    return NULL;
}

void donlist(char *arg, const int on_ctrl_conn, const int opt_l_,
             const int opt_a_, const int split_args)
{
    int c;
    void *tls_fd = NULL;
    char *c_buf;
    
    matches = 0U;

    opt_C = opt_d = opt_F = opt_R = opt_r = opt_t = opt_S = 0;
    opt_l = opt_l_;
    if (force_ls_a != 0) {
        opt_a = 1;
    } else {
        opt_a = opt_a_;
    }
    if (split_args != 0) {
        while (isspace((unsigned char) *arg)) {
            arg++;
        }
        while (arg && *arg == '-') {
            while (arg++ && isalnum((unsigned char) *arg)) {
                switch (*arg) {
                case 'a':
                    opt_a = 1;
                    break;
                case 'l':
                    opt_l = 1;
                    opt_C = 0;
                    break;
                case '1':
                    opt_l = opt_C = 0;
                    break;
                case 'C':
                    opt_l = 0;
                    opt_C = 1;
                    break;
                case 'F':
                    opt_F = 1;
                    break;
                case 'R':
                    opt_R = 1;
                    break;
                case 'd':
                    opt_d = 1;
                    break;
                case 'r':
                    opt_r = 1;
                    break;
                case 't':
                    opt_t = 1;
                    opt_S = 0;
                    break;
                case 'S':
                    opt_S = 1;
                    opt_t = 0;
                    break;
                }
            }
            while (isspace((unsigned char) *arg)) {
                arg++;
            }
        }
    }
    if (on_ctrl_conn == 0) {
        opendata();
        if ((c = xferfd) == -1) {
            return;
        }
        doreply();
#ifdef WITH_TLS
        if (data_protection_level == CPL_PRIVATE) {
            tls_init_data_session(xferfd, passive);
            tls_fd = tls_data_cnx;
        }
#endif
    } else {                           /* STAT command */
        c = clientfd;
#ifdef WITH_TLS
        if (data_protection_level == CPL_PRIVATE) {
            secure_safe_write(tls_cnx, "213-STAT" CRLF,
                              sizeof "213-STAT" CRLF - 1U);
            tls_fd = tls_cnx;
        }
        else
#endif
        {
            safe_write(c, "213-STAT" CRLF, sizeof "213-STAT" CRLF - 1U, -1);
        }
    }
    if (arg != NULL && *arg != 0) {
        int justone;

        justone = 1;            /* just one argument, so don't print dir name */

        do {
            glob_t g;
            int a;
            char *endarg;

            if (split_args == 0) {
                endarg = NULL;
            } else if ((endarg = unescape_and_return_next_file(arg)) != NULL) {
                justone = 0;
            }
#ifdef DEBUG
            if (debug != 0) {
                addreply(226, "Glob: %s", arg);
            }
#endif

            /* Expand ~ here if needed */
            
            alarm(GLOB_TIMEOUT);
            a = sglob(arg,
                      opt_a ? (GLOB_PERIOD | GLOB_LIMIT) : GLOB_LIMIT,
                      NULL, &g, max_ls_files + 2, max_ls_depth * 2);
            alarm(0);
            if (a == 0) {
                char **path;

                if (g.gl_pathc <= 0) {
                    path = NULL;
                } else {
                    path = g.gl_pathv;
                }
                if (path != NULL && path[0] != NULL && path[1] != NULL) {
                    justone = 0;
                }
                while (path != NULL && *path != NULL) {
                    struct stat st;

                    if (stat(*path, &st) == 0) {
                        if (opt_d || !(S_ISDIR(st.st_mode))) {
                            listfile(NULL, *path);
                            **path = 0;
                        }
                    } else {
                        **path = 0;
                    }
                    path++;
                }
                outputfiles(c, tls_fd);    /* in case of opt_C */
                path = g.gl_pathv;
                while (path != NULL && *path != NULL) {
                    if (matches >= max_ls_files) {
                        break;
                    }
                    if (**path != 0) {
                        if (!justone) {
#ifdef WITH_RFC2640                            
                            c_buf = charset_fs2client(*path);
#else
                            c_buf = *path;
#endif
#ifdef FANCY_LS_DIRECTORY_HEADERS                            
                            wrstr(c, tls_fd, "\r\n>-----------------[");
                            wrstr(c, tls_fd, c_buf);
                            wrstr(c, tls_fd, "]-----------------<\r\n\r\n");
#else
                            wrstr(c, tls_fd, "\r\n\r\n");
                            wrstr(c, tls_fd, c_buf);
                            wrstr(c, tls_fd, ":\r\n\r\n");
#endif
#ifdef WITH_RFC2640                            
                            free(c_buf);
#endif
                        }
                        if (!chdir(*path)) {
                            listdir(0U, c, tls_fd, *path);
                            chdir(wd);
                        }
                    }
                    path++;
                }
            } else {
                if (a == GLOB_NOSPACE) {
                    addreply(226, MSG_GLOB_NO_MEMORY, arg);
                    addreply_noformat(0, MSG_PROBABLY_DENIED);
                } else if (a == GLOB_ABEND) {
                    addreply(226, MSG_GLOB_READ_ERROR, arg);
                } else if (a != GLOB_NOMATCH) {
                    addreply(226, MSG_GLOB_READ_ERROR, arg);
                    addreply_noformat(0, MSG_PROBABLY_DENIED);
                }
            }
            globfree(&g);
            arg = endarg;
        } while (arg != NULL);
    } else {
        if (opt_d) {
            listfile(NULL, ".");
        } else {
            listdir(0U, c, tls_fd, ".");
        }
        outputfiles(c, tls_fd);
    }
    wrstr(c, tls_fd, NULL);
    if (on_ctrl_conn == 0) {
#ifdef WITH_TLS
        closedata();
#endif    
        close(c);
    } else {
        addreply_noformat(213, "End.");
        goto end;
    }
    if (opt_a || opt_C || opt_d || opt_F || opt_l || opt_r || opt_R ||
        opt_t || opt_S)
        addreply(0, "Options: %s%s%s%s%s%s%s%s%s",
                 opt_a ? "-a " : "",
                 opt_C ? "-C " : "",
                 opt_d ? "-d " : "",
                 opt_F ? "-F " : "",
                 opt_l ? "-l " : "",
                 opt_r ? "-r " : "",
                 opt_R ? "-R " : "", opt_S ? "-S " : "",
                 opt_t ? "-t" : "");
    if (matches >= max_ls_files) {
        addreply(226, MSG_LS_TRUNCATED, matches);
    } else {
        addreply(226, MSG_LS_SUCCESS, matches);
    }
    end:
    chdir(wd);
}
