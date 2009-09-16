#include <config.h>

#define FAKECHROOT_FUNCS_DEFINITION 1

#ifdef WITH_VIRTUAL_CHROOT

# include "ftpd.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

static char curdir[MAXPATHLEN];
static char *chroot_base;
static size_t chroot_len;

int fakechroot(const char *path)
{
    char *z;
    
    if (path == NULL || *path == 0) {
# ifdef EINVAL
        errno = EINVAL;
# endif
        return -1;
    }
    free(chroot_base);
    chroot_base = NULL;
    if (path[0] == '/' && path[1] == 0) {   /* chroot("/") => no chroot */
        return 0;
    }
    if ((chroot_base = strdup(path)) == NULL) {
        return -1;
    }
    simplify(chroot_base);
    z = chroot_base;
    while (*z != 0) {
        z++;
    }
    for (;;) {
        z--;
        if (z == chroot_base || *z != '/') {
            break;
        }
        *z = 0;
    }
    if ((chroot_len = strlen(chroot_base)) >= sizeof curdir) {
# ifdef ENAMETOOLONG
        errno = ENAMETOOLONG;
# endif
        return -1;
    }
    
    return 0;
}

char *fakegetcwd(char *dir, size_t size)
{
    char *curdirchr;
    size_t s;     
    
    if (chroot_base == NULL) {
        return getcwd(dir, size);
    }
    if (strncmp(curdir, chroot_base, chroot_len) != 0) {
        abort();
    }
    curdirchr = curdir + chroot_len;
    s = strlen(curdirchr);
    if (s <= (size_t) 0U) {
# ifdef EFAULT
        errno = EFAULT;
# endif
        return NULL;
    }
    {
        char *sp = curdirchr + s - 1U;
        
        while (sp != curdirchr && *sp == '/') {
            *sp = 0;
            s--;
        }
    }
    s++;     
    if (s > size || s < (size_t) 2U) {
# ifdef ENAMETOOLONG
        errno = ENAMETOOLONG;
# endif
        return NULL;
    }
    memcpy(dir, curdirchr, s);
    
    return curdirchr;
}

static int fakexlate(char *curdirtmp, size_t sizeof_curdirtmp, const char *dir)
{
    char *sl;     
    size_t curdirlen;
    
    if ((curdirlen = strlen(curdir)) >= sizeof_curdirtmp) {
        return -1;
    }
    memcpy(curdirtmp, curdir, curdirlen + (size_t) 1U);
    simplify(curdirtmp);
    loop:
    if (dir[0] == '.' && dir[1] == '.' &&
        (dir[2] == 0 || dir[2] == '/')) {
        if ((sl = strrchr(curdirtmp, '/')) != NULL) {
            *sl = 0;
        } else {
            *curdirtmp = 0;
        }
        if (strncmp(curdirtmp, chroot_base, chroot_len) != 0 ||
            curdirtmp[chroot_len] != '/') {
            snprintf(curdirtmp, sizeof_curdirtmp, "%s/", chroot_base);
        }
        if (dir[0] == '.' && dir[1] == '.' && dir[2] == '/') {
            dir += 3;
            goto loop;
        }
    } else if (*dir == '/') {
        snprintf(curdirtmp, sizeof_curdirtmp, "%s/", chroot_base);
        dir++;
        goto loop;
    } else if (*dir != 0) {
        size_t dirlen;
        size_t curdirtmplen;
        
        if ((dir[0] == '.' && dir[1] == '.' &&
             (dir[2] == 0 || dir[2] == '/')) ||            
            strstr(dir, "/../") != NULL) {
            perm:
# ifdef EPERM
            errno = EPERM;
# endif
            return -1;
        }
        dirlen = strlen(dir) + (size_t) 1U;
        if (dirlen >= (size_t) 4U &&
            (dir[dirlen - 2U] == '.' && dir[dirlen - 3U] == '.' &&
             dir[dirlen - 4U] == '/')) {
            goto perm;
        }
        curdirtmplen = strlen(curdirtmp);
        if (curdirtmplen + dirlen >= sizeof_curdirtmp) {
# ifdef ENAMETOOLONG
            errno = ENAMETOOLONG;
# endif
            return -1;
        }
        curdirtmp[curdirtmplen] = '/';
        memcpy(curdirtmp + curdirtmplen + 1U, dir, dirlen);
    }     
    simplify(curdirtmp);
    
    return 0;
}

int fakechdir(const char *dir)
{
    char curdirtmp[MAXPATHLEN];
    size_t curdirtmplen;
    
    if (chroot_base == NULL) {
        return chdir(dir);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, dir) != 0) {
        return -1;
    }
    if (chdir(curdirtmp) != 0) {
        return -1;
    }
    if ((curdirtmplen = strlen(curdirtmp)) >= sizeof curdir) {
        return -1;
    }
    memcpy(curdir, curdirtmp, curdirtmplen + (size_t) 1U);
    
    return 0;
}

int fakestat(const char *file, struct stat *st)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return stat(file, st);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return stat(curdirtmp, st);
}

int fakelstat(const char *file, struct stat *st)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return lstat(file, st);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return lstat(curdirtmp, st);
}

FILE *fakefopen(const char *file, const char *mode)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return fopen(file, mode);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return NULL;
    }
    return fopen(curdirtmp, mode);
}

int fakeaccess(const char *file, mode_t mode)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return access(file, mode);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return access(curdirtmp, mode);
}

int fakeunlink(const char *file)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return unlink(file);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return unlink(curdirtmp);
}

DIR *fakeopendir(const char *file)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return opendir(file);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return NULL;
    }
    return opendir(curdirtmp);
}

int fakechmod(const char *file, mode_t mode)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return chmod(file, mode);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return chmod(curdirtmp, mode);
}

int fakemkdir(const char *file, mode_t mode)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return mkdir(file, mode);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return mkdir(curdirtmp, mode);
}

int fakermdir(const char *file)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return rmdir(file);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return rmdir(curdirtmp);
}

# ifdef HAVE_UTIME
int fakeutime(const char *file, struct utimbuf *buf)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return utime(file, buf);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return utime(curdirtmp, buf);
}
# endif

# ifdef HAVE_UTIMES
int fakeutimes(const char *file, struct timeval *buf)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return utimes(file, buf);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return utimes(curdirtmp, buf);
}
# endif

int fakechown(const char *file, uid_t uid, gid_t gid)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return chown(file, uid, gid);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return chown(file, uid, gid);
}

# ifdef HAVE_MKFIFO
int fakemkfifo(const char *file, mode_t mode)
{
     char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return mkfifo(file, mode);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return mkfifo(file, mode);
}
# endif

# ifdef HAVE_MKNOD
int fakemknod(const char *file, mode_t mode, dev_t dev)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return mknod(file, mode, dev);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return mknod(file, mode, dev);
}
# endif

int fakelink(const char *oldpath, const char *newpath)
{
    char curdirtmp[MAXPATHLEN];
    char curdirtmp2[MAXPATHLEN];     
    
    if (chroot_base == NULL) {
        return link(oldpath, newpath);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, oldpath) != 0 ||
        fakexlate(curdirtmp2, sizeof curdirtmp2, newpath) != 0) {
        return -1;
    }
    return link(curdirtmp, curdirtmp2);
}

int fakesymlink(const char *oldpath, const char *newpath)
{
    char curdirtmp[MAXPATHLEN];
    char curdirtmp2[MAXPATHLEN];     
    
    if (chroot_base == NULL) {
        return symlink(oldpath, newpath);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, oldpath) != 0 ||
        fakexlate(curdirtmp2, sizeof curdirtmp2, newpath) != 0) {
        return -1;
    }
    return symlink(curdirtmp, curdirtmp2);
}

int fakereadlink(const char *file, char *buf, size_t bufsiz)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return readlink(file, buf, bufsiz);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return -1;
    }
    return readlink(file, buf, bufsiz);
}

int fakerename(const char *oldpath, const char *newpath)
{
    char curdirtmp[MAXPATHLEN];
    char curdirtmp2[MAXPATHLEN];     
    
    if (chroot_base == NULL) {
        return rename(oldpath, newpath);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, oldpath) != 0 ||
        fakexlate(curdirtmp2, sizeof curdirtmp2, newpath) != 0) {
        return -1;
    }
    return rename(curdirtmp, curdirtmp2);
}

/* 
 * Promotion of mode_t is problematic. For instance, on MacOS X,
 * mode_t is an unsigned short.
 */

# if SIZEOF_MODE_T <= 0
#  define VA_ARG_MODE_T unsigned int
# elif SIZEOF_MODE_T <= SIZEOF_INT
#  define VA_ARG_MODE_T unsigned int
# elif SIZEOF_MODE_T <= SIZEOF_LONG
#  define VA_ARG_MODE_T unsigned long
# elif SIZEOF_MODE_T <= SIZEOF_LONG_LONG
#  define VA_ARG_MODE_T unsigned long long
# else
#  define VA_ARG_MODE_T mode_t
# endif

int fakeopen(const char *file, int flags, ...)
{
    va_list va;
    mode_t mode;
    char curdirtmp[MAXPATHLEN];
    
    va_start(va, flags);
    if (chroot_base == NULL) {
        if ((flags & O_CREAT) != 0) {
            mode = va_arg(va, VA_ARG_MODE_T);
            va_end(va);
            return open(file, flags, mode);
        }
        va_end(va);
        return open(file, flags);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        va_end(va);
        return -1;
    }
    if ((flags & O_CREAT) != 0) {
        mode = va_arg(va, VA_ARG_MODE_T);
        va_end(va);          
        return open(curdirtmp, flags, mode);
    }
    va_end(va);
    
    return open(curdirtmp, flags);
}

char *fakerealpath(const char *file, char *resolved_path)
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return realpath(file, resolved_path);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, file) != 0) {
        return NULL;
    }
    return realpath(curdirtmp, resolved_path);
}

# if STATFS_TYPE == 1
int fakestatvfs64(const char *path, STATFS_STRUCT *str)
# elif STATFS_TYPE == 2
int fakestatvfs(const char *path, STATFS_STRUCT *str)        
# elif STATFS_TYPE == 3
int fakestatfs(const char *path, STATFS_STRUCT *str)
# endif            
# if STATFS_TYPE > 0
{
    char curdirtmp[MAXPATHLEN];
    
    if (chroot_base == NULL) {
        return STATFS(path, str);
    }
    if (fakexlate(curdirtmp, sizeof curdirtmp, path) != 0) {
        return -1;
    }    
    return STATFS(curdirtmp, str);
}
# endif
#else
extern signed char v6ready;
#endif
