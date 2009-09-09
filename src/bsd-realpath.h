#ifndef __FAKEREALPATH_H__
#define __FAKEREALPATH_H__ 1

#if defined(__svr4__) && defined(__sun__) /* Solaris 2 aka SunOS 5 */
# undef USE_BUILTIN_REALPATH
# define USE_BUILTIN_REALPATH 1
#endif
#if defined(__atheos__)
# undef USE_BUILTIN_REALPATH
# define USE_BUILTIN_REALPATH 1
#endif
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
# undef USE_BUILTIN_REALPATH
# define USE_BUILTIN_REALPATH 1
#endif

#if !defined(HAVE_REALPATH) || defined(USE_BUILTIN_REALPATH)
char *bsd_realpath(const char *path, char resolved[MAXPATHLEN]);
# define realpath(A, B) bsd_realpath(A, B)
#endif

#endif
