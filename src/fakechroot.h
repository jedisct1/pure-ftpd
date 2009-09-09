#ifndef HAVE_FAKECHROOT_H
# define HAVE_FAKECHROOT_H 1

# if defined(WITH_VIRTUAL_CHROOT) && defined(INCLUDE_IO_WRAPPERS)
#  if !defined(FAKECHROOT_FUNCS_DEFINITION) && !defined(FAKECHROOT_EXCEPTION)
int fakechroot(const char *path);
#   ifdef chroot
#    undef chroot
#   endif
#   define chroot(A) fakechroot(A)

char *fakegetcwd(char *dir, size_t size);
#   ifdef getcwd
#    undef getcwd
#   endif
#   define getcwd(A, B) fakegetcwd(A, B)

int fakechdir(const char *dir);
#   ifdef chdir
#    undef chdir
#   endif
#   define chdir(A) fakechdir(A)

int fakestat(const char *file, struct stat *st);
#   ifdef stat
#    undef stat
#   endif
#   define stat(A, B) fakestat(A, B)

int fakelstat(const char *file, struct stat *st);
#   ifdef lstat
#    undef lstat
#   endif
#   define lstat(A, B) fakelstat(A, B)

FILE *fakefopen(const char *file, const char *mode);
#   ifdef fopen
#    undef fopen
#   endif
#   define fopen(A, B) fakefopen(A, B)

int fakeaccess(const char *file, mode_t mode);
#   ifdef access
#    undef access
#   endif
#   define access(A, B) fakeaccess(A, B)

int fakeunlink(const char *file);
#   ifdef unlink
#    undef unlink
#   endif
#   define unlink(A) fakeunlink(A)

DIR *fakeopendir(const char *file);
#   ifdef opendir
#    undef opendir
#   endif
#   define opendir(A) fakeopendir(A)

int fakechmod(const char *file, mode_t mode);
#   ifdef chmod
#    undef chmod
#   endif
#   define chmod(A, B) fakechmod(A, B)

int fakemkdir(const char *file, mode_t mode);
#   ifdef mkdir
#    undef mkdir
#   endif
#   define mkdir(A, B) fakemkdir(A, B)

int fakermdir(const char *file);
#   ifdef rmdir
#    undef rmdir
#   endif
#   define rmdir(A) fakermdir(A)

#   ifdef HAVE_UTIME
int fakeutime(const char *file, struct utimbuf *buf);
#    ifdef utime
#     undef utime
#    endif
#    define utime(A, B) fakeutime(A, B)
#   endif

#   ifdef HAVE_UTIMES
int fakeutimes(const char *file, struct timeval *buf);
#    ifdef utimes
#     undef utimes
#    endif
#    define utimes(A, B) fakeutimes(A, B)
#   endif

int fakechown(const char *file, uid_t uid, gid_t gid);
#   ifdef chown
#    undef chown
#   endif
#   define chown(A, B, C) fakechown(A, B, C)

#   ifdef HAVE_MKFIFO
int fakemkfifo(const char *file, mode_t mode);
#    ifdef mkfifo
#     undef mkfifo
#    endif
#    define mkfifo(A, B) fakemkfifo(A, B)
#   endif

#   ifdef HAVE_MKNOD
int fakemknod(const char *file, mode_t mode, dev_t dev);
#    ifdef mknod
#     undef mknod
#    endif
#    define mknod(A, B, C) fakemknod(A, B, C)
#   endif

int fakelink(const char *oldpath, const char *newpath);
#   ifdef link
#    undef link
#   endif
#   define link(A, B) fakelink(A, B)

int fakesymlink(const char *oldpath, const char *newpath);
#   ifdef symlink
#    undef symlink
#   endif
#   define symlink(A, B) fakesymlink(A, B)

int fakereadlink(const char *file, char *buf, size_t bufsiz);
#   ifdef readlink
#    undef readlink
#   endif
#   define readlink(A, B, C) fakereadlink(A, B, C)

int fakerename(const char *oldpath, const char *newpath);
#   ifdef rename
#    undef rename
#   endif
#   define rename(A, B) fakerename(A, B)

int fakeopen(const char *file, int flags, ...);
#   ifdef open
#    undef open
#   endif
#   define open fakeopen

char *fakerealpath(const char *file, char *resolved_path);
#   ifdef realpath
#    undef realpath
#   endif
#   define realpath fakerealpath

#   if STATFS_TYPE == 1
int fakestatvfs64(const char *path, STATFS_STRUCT *str);
#    ifdef statvfs64
#     undef statvfs64
#    endif
#    define statvfs64(A, B) fakestatvfs64(A, B)
#   elif STATFS_TYPE == 2
int fakestatvfs(const char *path, STATFS_STRUCT *str);
#    ifdef statvfs
#     undef statvfs
#    endif
#    define statvfs(A, B) fakestatvfs(A, B)
#   elif STATFS_TYPE == 3
int fakestatfs(const char *path, STATFS_STRUCT *str);
#    ifdef statfs
#     undef statfs
#    endif
#    define statfs(A, B) fakestatfs(A, B)
#   endif            
#  endif
# endif
#endif

