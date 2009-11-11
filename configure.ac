dnl AM_ACLOCAL_INCLUDE(m4)

AC_PREREQ(2.61)
AC_INIT([pure-ftpd],[1.0.25],[bugs at pureftpd dot org])
AC_CONFIG_SRCDIR(src/ftpd.c)
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.9 dist-bzip2])
AC_CONFIG_LIBOBJ_DIR(src)

AC_SUBST(VERSION)

ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_SEARCH_LIBS([strerror],[cposix])


AC_ARG_VAR(PERL,local path to the perl interpreter)
perl_possible_path="/usr/bin:/usr/local/bin:/bin:/opt/perl/bin:/opt/perl/usr/bin:/opt/perl/usr/local/bin"
AC_PATH_PROG(PERL,perl,/usr/bin/env perl,$perl_possible_path)

AC_ARG_VAR(PYTHON,local path to the python interpreter)
python_possible_path="/usr/bin:/usr/local/bin:/bin:/opt/python/bin:/opt/python/usr/bin:/opt/python/usr/local/bin"
AC_PATH_PROG(PYTHON,python,/usr/bin/env python,$python_possible_path)

if test -d /usr/local/include; then
  CPPFLAGS="$CPPFLAGS -I/usr/local/include"
fi

if test -d /usr/kerberos/include; then
  CPPFLAGS="$CPPFLAGS -I/usr/kerberos/include"
fi

if test -d /usr/local/lib; then
  LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

if uname | fgrep SunOS > /dev/null 2> /dev/null ; then
  CPPFLAGS="$CPPFLAGS -D_XPG4_2=1"
fi

dnl Checks for header files

AC_SYS_LARGEFILE
AC_HEADER_STDC
AC_HEADER_STAT
AC_HEADER_TIME
AC_HEADER_DIRENT
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(unistd.h string.h strings.h sys/param.h ioctl.h sys/ioctl.h)
AC_CHECK_HEADERS(sys/vfs.h sys/statvfs.h sys/sendfile.h sys/uio.h)
AC_CHECK_HEADERS(sys/time.h sys/resource.h sys/capability.h)
AC_CHECK_HEADERS(shadow.h getopt.h stddef.h)
AC_CHECK_HEADERS(netinet/in_systm.h netinet/in.h sys/pstat.h sys/file.h)
AC_CHECK_HEADERS(sys/mount.h, [], [],
[#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif])
AC_CHECK_HEADERS(fcntl.h sys/fcntl.h sys/loadavg.h sys/ptrace.h)
AC_CHECK_HEADERS(security/pam_appl.h security/pam_misc.h)
AC_CHECK_HEADERS(security/pam_modules.h security/pam_filter.h)
AC_CHECK_HEADERS(pam/pam_appl.h pam/pam_misc.h pam/pam_modules.h)
AC_CHECK_HEADERS(pam/pam_filter.h)
AC_CHECK_HEADERS(sgtty.h termio.h)
AC_CHECK_HEADERS(locale.h)
AC_CHECK_HEADERS(stdarg.h varargs.h)
AC_CHECK_HEADERS(windows.h io.h)
AC_CHECK_HEADERS(crypt.h)
AC_CHECK_HEADERS(utime.h)
AC_CHECK_HEADERS(openssl/ssl.h)
AC_CHECK_HEADERS(CoreFoundation/CoreFoundation.h)
AC_CHECK_HEADERS(iconv.h)
AC_SYS_POSIX_TERMIOS

if test "x$ac_cv_sys_posix_termios" = "xyes"; then
AC_DEFINE(HAVE_POSIX_TERMIOS,,[Define if you have POSIX termios])
fi

dnl Check for endianness
AC_C_BIGENDIAN

dnl Checks for types

AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_OFF_T
AC_TYPE_MODE_T
AC_STRUCT_TM
AC_STRUCT_TIMEZONE
AC_CHECK_MEMBER(struct tm.tm_gmtoff, [AC_DEFINE(STRUCT_TM_TM_GMTOFF,,[Define if you have struct tm/tm_gmtoff])],,[
#include <sys/types.h>
#include <$ac_cv_struct_tm>
])

AC_MSG_CHECKING([whether timezone is scalar])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <$ac_cv_struct_tm>    
    ]], [[timezone = 42L]])],[
         AC_MSG_RESULT(yes)
         AC_DEFINE(HAVE_SCALAR_TIMEZONE,,[Define if your timezone is a scalar number])
    ],[    AC_MSG_RESULT(no)    ])   

AC_CHECK_TYPE(nlink_t, , [AC_DEFINE(nlink_t, int, [nlink_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
])


AC_CHECK_TYPE(dev_t, , [AC_DEFINE(dev_t, unsigned int, [dev_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
])


AC_CHECK_TYPE(ino_t, , [AC_DEFINE(ino_t, unsigned long, [ino_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
])

dnl Check for sizes
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(mode_t)

dnl Socket things

AC_CHECK_FUNC(connect, , [AC_CHECK_LIB(socket, connect)])

AC_CHECK_FUNC(gethostbyname, , [AC_CHECK_LIB(resolv, gethostbyname)])

AC_CHECK_FUNC(gethostbyname, , [AC_CHECK_LIB(nsl, gethostbyname)])

if test "x$ac_cv_lib_nsl_gethostbyname" != "xyes" && test "x$ac_cv_func_gethostbyname" != "xyes" ; then
  AC_CHECK_FUNC(gethostbyname, , [AC_CHECK_LIB(socket, gethostbyname)])
fi

if test "$ac_cv_lib_nsl_gethostbyname" = "$ac_cv_func_gethostbyname" ; then
  AC_MSG_CHECKING([if we can include libnsl + libsocket])
  LIBS="-lnsl -lsocket $LIBS"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[(void) gethostbyname]])],[my_ac_link_result=yes],[my_ac_link_result=no ])
  if test "$my_ac_link_result" = "no" ; then
    AC_MSG_RESULT([failure])
    AC_MSG_ERROR([unable to use gethostbyname()])
  else
    AC_MSG_RESULT([success])
  fi
fi

AC_CHECK_LIB(sendfile, sendfile)

dnl Types - continued

AC_CHECK_TYPE(socklen_t, , [AC_DEFINE(socklen_t, int, [socklen_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
])

AC_CHECK_TYPE(in_port_t, , [AC_DEFINE(in_port_t, unsigned short, [in_port_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
])

AC_CHECK_TYPE(sig_atomic_t, , [AC_DEFINE(sig_atomic_t, signed char, [sig_atomic_t type])],
[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <signal.h>
])

dnl Compiler characteristics

AC_PROG_GCC_TRADITIONAL
AC_C_CONST
AC_C_INLINE

dnl Options

AM_WITH_DMALLOC

AC_ARG_WITH(standalone,
[AS_HELP_STRING(--without-standalone,Don't compile the standalone server code)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(NO_STANDALONE,,[without standalone])
    no_standalone=yes
  fi ])

AC_ARG_WITH(inetd,
[AS_HELP_STRING(--without-inetd,Don't support super-servers (like inetd))],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(NO_INETD,,[without inetd])
    no_inetd=yes
  fi ])

if test "x$no_standalone" = "xyes" && test "x$no_inetd" = "xyes" ; then
  AC_MSG_ERROR(You can't disable both standalone and inetd mode.)
fi

AC_ARG_WITH(capabilities,
[AS_HELP_STRING(--without-capabilities,Don't use Linux capabilities (default=detect))],
[ if test "x$withval" = "xno" ; then
    no_capabilities=1
  fi ])
  
if test -z "$no_capabilities" ; then
  AC_CHECK_LIB(cap, cap_init, , )
  if test "x$ac_cv_lib_cap_cap_init" = "xyes"; then
    if test "x$ac_cv_header_sys_capability_h" = "xyes"; then
      AC_DEFINE(USE_CAPABILITIES,,[use capabilities])
    fi
  fi
fi

AC_ARG_WITH(shadow,
[AS_HELP_STRING(--without-shadow,Don't use shadow passwords (default=detect))],
[ if test "x$withval" = "xno" ; then
    no_shadow=1
  fi ])
  
if test -z "$no_shadow" && test "x$ac_cv_header_shadow_h" = "xyes" ; then
  AC_CHECK_FUNC(getspnam, AC_DEFINE(USE_SHADOW,,[use shadow passwords]),
    AC_CHECK_LIB(shadow, getspnam, AC_DEFINE(USE_SHADOW),
      AC_MSG_WARN(shadow.h was found, but getspnam() isn't available)
    )
  )
fi

AC_ARG_WITH(usernames,
[AS_HELP_STRING(--without-usernames,Use only numerical UIDs/GIDs)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(NO_FTP_USERS,,[without usernames])
  fi ])

AC_ARG_WITH(iplogging,
[AS_HELP_STRING(--without-iplogging,Never log remote IP addresses (privacy))],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(DONT_LOG_IP,,[without iplogging])
  fi ])

AC_ARG_WITH(humor,
[AS_HELP_STRING(--without-humor,Disable humor (enabled by default))],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(DISABLE_HUMOR,,[without humor])
  fi ])

AC_ARG_WITH(longoptions,
[AS_HELP_STRING(--without-longoptions,Ignored - just for backward compatibility)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(NO_GETOPT_LONG,,[without longoptions])
  fi ])

AC_ARG_WITH(ascii,
[AS_HELP_STRING(--without-ascii,Don't support 7-bits (ASCII) transfers)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(WITHOUT_ASCII,,[without ascii])
  fi ])

AC_ARG_WITH(globbing,
[AS_HELP_STRING(--without-globbing,Don't include globbing code)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(DISABLE_GLOBBING,,[without globbing])
  fi ])

AC_ARG_WITH(nonalnum,
[AS_HELP_STRING(--without-nonalnum,Only allow basic alphanumeric characters in file names)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(PARANOID_FILE_NAMES,,[disallow non-alphanumeric characters])
  fi ])

AC_ARG_WITH(unicode,
[AS_HELP_STRING(--without-unicode,Disable non-latin characters in file names)],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(DISABLE_UNICODE_CONTROL_CHARS,,[disallow unicode control chars])
  fi ])

AC_ARG_WITH(sendfile,
[AS_HELP_STRING(--without-sendfile,Don't use zero-copy optimizations (for network FS))],
[ if test "x$withval" = "xno" ; then
    AC_DEFINE(DISABLE_SENDFILE,,[without sendfile])
  fi ])

AC_ARG_WITH(privsep,
[AS_HELP_STRING(--without-privsep,Disable privilege separation)],
[ if test "x$withval" = "xno" ; then
    without_privsep=yes
  fi ])

AC_ARG_WITH(boring,
[AS_HELP_STRING(--with-boring,Display only boring messages)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(BORING_MODE,,[display only boring messages])
    AC_DEFINE(DISABLE_HUMOR)
  fi ])

AC_ARG_WITH(brokenrealpath,
[AS_HELP_STRING(--with-brokenrealpath,If your libc has a broken realpath() call)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(USE_BUILTIN_REALPATH,,[realpath() is broken])
  fi ])

AC_ARG_WITH(probe-random-dev,
[AS_HELP_STRING(--with-probe-random-dev,If you want to probe for /dev/*random at run-time)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(PROBE_RANDOM_AT_RUNTIME,,[probe for /dev/Xrandom at run-time])
  fi ])

AC_ARG_WITH(minimal,
[AS_HELP_STRING(--with-minimal,Build only a small minimal server)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(MINIMAL,,[with minimal])
    AC_DEFINE(NO_GETOPT_LONG)
    AC_DEFINE(DISABLE_HUMOR)
    AC_DEFINE(NO_FTP_USERS)
    AC_DEFINE(WITHOUT_ASCII)    
    AC_DEFINE(BORING_MODE)
    CFLAGS="$CFLAGS -Os -fomit-frame-pointer -fgcse -falign-functions=2 -falign-jumps=2 -fno-unroll-loops "
    LDFLAGS="$LDFLAGS -s "
  fi ])

AC_ARG_WITH(paranoidmsg,
[AS_HELP_STRING(--with-paranoidmsg,Use paranoid but not admin-friendly messages)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(PARANOID_MESSAGES,,[with paranoidmsg])
  fi ])

AC_ARG_WITH(sysquotas,
[AS_HELP_STRING(--with-sysquotas,Use system (not virtual) quotas)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(SYSTEM_QUOTAS,,[with sysquotas])
  fi ])

AC_ARG_WITH(altlog,
[AS_HELP_STRING(--with-altlog,Support alternative log format (Apache-like))],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(WITH_ALTLOG,,[with altlog]) 
  fi ])

AC_ARG_WITH(puredb,
[AS_HELP_STRING(--with-puredb,Support virtual (FTP-only) users)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(WITH_PUREDB,,[with puredb])
  fi ])

AC_ARG_WITH(extauth,
[AS_HELP_STRING(--with-extauth,Support external authentication modules)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(WITH_EXTAUTH,,[with extauth (*BETA*)])
  fi ])

AC_ARG_WITH(pam,
[AS_HELP_STRING(--with-pam,Enable PAM support (default=disabled))],
[ if test "x$withval" = "xyes" ; then
    with_pam="yes"
  fi ])

if test "x`uname`" = "xDarwin"; then
  if test "x$with_pam" = "x"; then
    with_pam="yes"
  fi
fi

if test "x$with_pam" = "xyes" ; then
  if test "x$ac_cv_header_security_pam_appl_h" != "xyes" &&
     test "x$ac_cv_header_pam_pam_appl_h" != "xyes"; then
    AC_MSG_ERROR(PAM headers not found.)  
  else
    AC_CHECK_LIB(dl, dlopen, , )
    LIBS="$LIBS -lpam"
    AC_DEFINE(USE_PAM,,[use pam])
    AC_CHECK_FUNCS(pam_getenvlist)
    AC_MSG_CHECKING([whether pam_strerror takes only one argument])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#include <security/pam_appl.h>
        ]], [[(void)pam_strerror((pam_handle_t *)NULL, -1)]])],[AC_MSG_RESULT(no)],[
            AC_DEFINE(HAVE_OLD_PAM,,[obsolete pam])
            AC_MSG_RESULT(yes)
        ])   
  fi
fi  

AC_MSG_CHECKING([whether syslog names are available])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#define SYSLOG_NAMES 1
#include <stdio.h>
#include <syslog.h>
]], [[
 (void) facilitynames
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SYSLOG_NAMES,,[define if syslog names are available])
],[
  AC_MSG_RESULT(no)
])  


AC_MSG_CHECKING([whether struct addrinfo is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
]], [[
do {
 struct addrinfo a;
 (void) a.ai_flags;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_STRUCT_ADDRINFO,,[define if you have struct addrinfo])
],[
  AC_MSG_RESULT(no)
])  


AC_MSG_CHECKING([whether sin_len is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
]], [[
do {
 struct sockaddr_in a;
 (void) a.sin_len;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SIN_LEN,,[define if you have sin_len])
],[
  AC_MSG_RESULT(no)
])  


AC_MSG_CHECKING([whether __ss_family is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
]], [[
do {
 struct sockaddr_storage a;
 (void) a.__ss_family;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE___SS_FAMILY,,[define if you have __ss_family])
],[
  AC_MSG_RESULT(no)
])  


AC_MSG_CHECKING([whether ss_len is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
]], [[
do {
 struct sockaddr_storage a;
 (void) a.ss_len;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SS_LEN,,[define if you have ss_len])
],[
  AC_MSG_RESULT(no)
])  


AC_MSG_CHECKING([whether __ss_len is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
]], [[
do {
 struct sockaddr_storage a;
 (void) a.__ss_len;
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE___SS_LEN,,[define if you have __ss_len])
],[
  AC_MSG_RESULT(no)
])  



AC_MSG_CHECKING([if a linuxish sendfile is available])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_SYS_SENDFILE_H
# include <sys/sendfile.h>
#endif
]], [[
do {
 int fd = 0;
 off_t *off = NULL;
 size_t cnt = (size_t) 0;
 
 (void) sendfile(fd, fd, off, cnt);
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(SENDFILE_LINUX,,[define if you have a linuxish sendfile])
],[
  AC_MSG_RESULT(no)
])  

AC_MSG_CHECKING([if a linuxish sendfile64 is available])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_SYS_SENDFILE_H
# include <sys/sendfile.h>
#endif
]], [[
do {
 int fd = 0;
 off_t *off = NULL;
 size_t cnt = (size_t) 0;
 
 (void) sendfile64(fd, fd, off, cnt);
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(SENDFILE64_LINUX,,[define if you have a linuxish sendfile64])
],[
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([if a freebsdish sendfile is available])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_SYS_SENDFILE_H
# include <sys/sendfile.h>
#endif
]], [[
do {
 int fd = 0;
 off_t off = (off_t) 0;
 size_t cnt = (size_t) 0;
 struct sf_hdtr *hdtr = NULL;
 
 (void) sendfile(fd, fd, off, cnt, hdtr, &off, 42);
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(SENDFILE_FREEBSD,,[define if you have a freebsdish sendfile])
],[
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([if a hpuxish sendfile is available])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/socket.h>
#include <stdio.h>
]], [[
do {
 int fd = 0;
 off_t off = (off_t) 0;
 bsize_t nbytes = (size_t) 0;
 const struct iovec *hdtrl = NULL;
 
 (void) sendfile(fd, fd, off, nbytes, hdtrl, 42);
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(SENDFILE_HPUX,,[define if you have a hpuxish sendfile])
],[
  AC_MSG_RESULT(no)
])

AC_CHECK_FUNC(sendfilev, , [AC_CHECK_LIB(sendfile, sendfilev)])

AC_MSG_CHECKING([if a solarisish sendfilev is available])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_SYS_SENDFILE_H
# include <sys/sendfile.h>
#endif
]], [[
do {
 int fd = 0, sfvcnt = 0;
 const struct sendfilevec vec;
 size_t xferred;
 
 (void) sendfilev(fd, &vec, sfvcnt, &xferred);
} while(0)
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(SENDFILEV_SOLARIS,,[define if you have a solarisish sendfilev])
],[
  AC_MSG_RESULT(no)
])


AC_ARG_WITH(cookie,
[AS_HELP_STRING(--with-cookie,Support 'fortune' cookies (-F option))],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(COOKIE,,[with cookie])
  fi ])

AC_ARG_WITH(throttling,
[AS_HELP_STRING(--with-throttling,Support bandwidth throttling (disabled by default))],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(THROTTLING,,[with throttling])
  fi ])

AC_ARG_WITH(ratios,
[AS_HELP_STRING(--with-ratios,Support for upload/download ratios)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(RATIOS,,[with ratios])
  fi ])

AC_ARG_WITH(quotas,
[AS_HELP_STRING(--with-quotas,Support .ftpquota files)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(QUOTAS,,[with quotas])
  fi ])

AC_ARG_WITH(ftpwho,
[AS_HELP_STRING(--with-ftpwho,Support for pure-ftpwho)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(FTPWHO,,[with ftpwho])
  fi ])

AC_ARG_WITH(welcomemsg,
[AS_HELP_STRING(--with-welcomemsg,Support welcome.msg backward compatibility (deprecated))],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(WITH_WELCOME_MSG,,[with welcomemsg])
  fi ])

AC_ARG_WITH(uploadscript,
[AS_HELP_STRING(--with-uploadscript,Allow running an external script after an upload (experimental))],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(WITH_UPLOAD_SCRIPT,,[with uploadscript])
  fi ])

AC_ARG_WITH(virtualhosts,
[AS_HELP_STRING(--with-virtualhosts,Handle virtual servers on different IP addresses)],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(WITH_VIRTUAL_HOSTS,,[with virtualhosts])
  fi ])

AC_ARG_WITH(virtualchroot,
[AS_HELP_STRING(--with-virtualchroot,Enable the ability to follow symlinks outside a chroot jail)],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(WITH_VIRTUAL_CHROOT,,[with virtual chroot])
  fi ])

AC_ARG_WITH(diraliases,
[AS_HELP_STRING(--with-diraliases,Enable directory aliases)],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(WITH_DIRALIASES,,[with directory aliases])
  fi ])

AC_ARG_WITH(nonroot,
[AS_HELP_STRING(--with-nonroot,[Compile a limited server designed to be started as a regular user. Only enable this option as a last resort if you really don't have root privileges on the server host.])],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(NON_ROOT_FTP,,[with nonroot])
      AC_DEFINE(WITH_VIRTUAL_CHROOT)      
      non_root_ftp=yes
      without_privsep=yes
  fi ])

if test "x$without_privsep" = "xyes" ; then
  AC_DEFINE(WITHOUT_PRIVSEP,,[disable privilege separation])
fi

AC_ARG_WITH(peruserlimits,
[AS_HELP_STRING(--with-peruserlimits,Support per-user concurrency limits)],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(PER_USER_LIMITS,,[with per-user limits])
      AC_DEFINE(FTPWHO)
  fi ])

AC_ARG_WITH(implicittls,
[AS_HELP_STRING(--with-implicittls,Implicit TLS (port 990) - DO NOT USE unless you know what you are doing)],
[ if test "x$withval" = "xyes" ; then
      AC_DEFINE(IMPLICIT_TLS,,[with implicit TLS])
      with_tls="yes"
  fi ])

AC_ARG_WITH(debug,
[AS_HELP_STRING(--with-debug,For maintainers only - please do not use)],
[ if test "x$withval" = "xyes" ; then
    CFLAGS="$CFLAGS -DDEBUG=1 -g -Wall -W -Wcast-align -Wbad-function-cast -Wstrict-prototypes -Wwrite-strings -Wreturn-type "
  fi ])

AC_ARG_WITH(everything,
[AS_HELP_STRING(--with-everything,Build a big server with almost everything)],
[ if test "x$withval" = "xyes" ; then
    AC_DEFINE(WITH_ALTLOG)
    AC_DEFINE(COOKIE)
    AC_DEFINE(THROTTLING)
    AC_DEFINE(RATIOS)
    AC_DEFINE(QUOTAS)    
    AC_DEFINE(WITH_UPLOAD_SCRIPT)
    AC_DEFINE(WITH_VIRTUAL_HOSTS)
    AC_DEFINE(WITH_PUREDB)
    AC_DEFINE(WITH_EXTAUTH)
    AC_DEFINE(FTPWHO)
    AC_DEFINE(WITH_DIRALIASES)
    AC_DEFINE(PER_USER_LIMITS)
    with_bonjour='yes'
  fi ])

AC_ARG_WITH(language,
[AS_HELP_STRING(--with-language=,< english | german | romanian | french |
french-funny | polish | spanish | danish | dutch | italian |
brazilian-portuguese | slovak | korean | swedish | norwegian | russian |
traditional-chinese | simplified-chinese | czech | turkish | hungarian |
catalan>)],
[ if test "x$withval" = "xenglish" ; then
    AC_DEFINE(MESSAGES_EN,,[english])
  elif test "x$withval" = "xgerman" ; then
    AC_DEFINE(MESSAGES_DE,,[german])  
  elif test "x$withval" = "xromanian" ; then
    AC_DEFINE(MESSAGES_RO,,[romanian])
  elif test "x$withval" = "xfrench" ; then
    AC_DEFINE(MESSAGES_FR,,[french])
  elif test "x$withval" = "xfrench-funny" ; then
    AC_DEFINE(MESSAGES_FR_FUNNY,,[french-funny])    
  elif test "x$withval" = "xpolish" ; then  
    AC_DEFINE(MESSAGES_PL,,[polish])
  elif test "x$withval" = "xspanish" ; then
    AC_DEFINE(MESSAGES_ES,,[spanish])
  elif test "x$withval" = "xdanish" ; then
    AC_DEFINE(MESSAGES_DA,,[danish])
  elif test "x$withval" = "xdutch" ; then
    AC_DEFINE(MESSAGES_NL,,[dutch])
  elif test "x$withval" = "xitalian" ; then
    AC_DEFINE(MESSAGES_IT,,[italian])
  elif test "x$withval" = "xbrazilian-portuguese" ; then
    AC_DEFINE(MESSAGES_PT_BR,,[brazilian portuguese])
  elif test "x$withval" = "xslovak" ; then
    AC_DEFINE(MESSAGES_SK,,[slovak])
  elif test "x$withval" = "xkorean" ; then
    AC_DEFINE(MESSAGES_KR,,[korean])
  elif test "x$withval" = "xswedish" ; then
    AC_DEFINE(MESSAGES_SV,,[swedish])
  elif test "x$withval" = "xnorwegian" ; then
    AC_DEFINE(MESSAGES_NO,,[norwegian])
  elif test "x$withval" = "xrussian" ; then
    AC_DEFINE(MESSAGES_RU,,[russian])
  elif test "x$withval" = "xtraditional-chinese" ; then
    AC_DEFINE(MESSAGES_ZH_TW,,[traditional chinese])
  elif test "x$withval" = "xsimplified-chinese" ; then
    AC_DEFINE(MESSAGES_ZH_CN,,[simplified chinese])
  elif test "x$withval" = "xczech" ; then
    AC_DEFINE(MESSAGES_CS_CZ,,[czech])
  elif test "x$withval" = "xturkish" ; then
    AC_DEFINE(MESSAGES_TR,,[turkish])
  elif test "x$withval" = "xhungarian" ; then
    AC_DEFINE(MESSAGES_HU,,[hungarian])
  elif test "x$withval" = "xcatalan" ; then
    AC_DEFINE(MESSAGES_CA_ES,,[catalan])
  else 
    AC_MSG_WARN(--with-language=$withval is not recognized)
  fi ])



dnl Checks for libraries.

AC_CHECK_LIB(crypt, crypt, , )

dnl Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_MMAP
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_FUNC_GETLOADAVG(src)
AC_FUNC_GETGROUPS
AC_FUNC_WAIT3
AC_FUNC_UTIME_NULL
AC_FUNC_STRTOD
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_MKTIME
AC_FUNC_LSTAT
AC_FUNC_FORK
AC_FUNC_ERROR_AT_LINE
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_CHOWN
AC_C_VOLATILE


AC_CHECK_FUNCS(initgroups setrlimit waitpid setproctitle getopt_long)
AC_CHECK_FUNCS(seteuid setreuid setresuid setegid setregid setresgid)
AC_CHECK_FUNCS(statvfs statfs putenv setenv unsetenv getpagesize realpath)
AC_CHECK_FUNCS(pread posix_fadvise ptrace)
AC_CHECK_FUNCS(strtoull strtoq)
AC_CHECK_FUNCS(strlcpy strlcat)
AC_CHECK_FUNCS(memset munmap strdup fileno mapviewoffile madvise)
AC_CHECK_FUNCS(getaddrinfo getnameinfo inet_ntop inet_pton)
AC_CHECK_FUNCS(setusershell setgroups snprintf vsnprintf vfprintf gethostname)
AC_CHECK_FUNCS(setlocale timegm)
AC_CHECK_FUNCS(tzset utime utimes mknod mkfifo)
AC_CHECK_FUNCS(random srandomdev arc4random)
AC_CHECK_FUNCS(closefrom)

AC_MSG_CHECKING([whether statvfs64() is defined])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
]], [[
for (;;) {
 struct statvfs64 a;
 if (statvfs64(".", &a) == 0 || a.f_bsize != 0) {
   break;
 }
} 
]])],[
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_STATVFS64,,[define if you have statvfs64])
],[
  AC_MSG_RESULT(no)
])  

AC_MSG_CHECKING(whether snprintf is C99 conformant)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

int main(void)
{
    char buf[4];
    
    (void) fprintf(fopen("conftestval", "w"), "%d\n",
        (int) snprintf(buf, sizeof buf, "12345678"));
    return 0;
}
]])],[CONF_SNPRINTF_TYPE=`cat conftestval`
],[],[CONF_SNPRINTF_TYPE=8])
AC_MSG_RESULT(done)
if test "x$CONF_SNPRINTF_TYPE" = "x" ; then
  AC_MSG_WARN(your operating system doesn't implement snprintf)
else
  AC_DEFINE_UNQUOTED(CONF_SNPRINTF_TYPE, $CONF_SNPRINTF_TYPE, [return value of an overflowed snprintf])
fi


AC_MSG_CHECKING(whether getgroups 0 is sane)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

int main(void)
{
    return getgroups(0, NULL) <= 0;
}
]])],[
AC_MSG_RESULT(yes)
AC_DEFINE(SAFE_GETGROUPS_0,,[Define is getgroups(0, NULL) works on your system])
],[AC_MSG_RESULT(no)
],[AC_MSG_RESULT(suppose that it doesnt)])

AC_MSG_CHECKING(whether realpath likes unreadable directories)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifndef MAXPATHLEN
# define MAXPATHLEN PATH_MAX
#endif

int main(void)
{
    char x[MAXPATHLEN];
    
    if (mkdir("x", 0300) != 0) {
        return 1;
    }
    if (mkdir("x/y", 0300) != 0) {
        rmdir("x");
        return 2;
    }    
    if (chdir("x") != 0) {
        rmdir("x/y");    
        rmdir("x");
        return 3;
    }
    if (realpath("y", x) == NULL) {
        rmdir("y");
        rmdir("../x");
        return 4;
    }
    rmdir("y");
    rmdir("../x");
    
    return 0;    
}
]])],[
AC_MSG_RESULT(yes)
AC_DEFINE(REALPATH_WORKS_WITH_UNREADABLE_DIRECTORIES,,
[Define if realpath() works on unreadable directories])
],[AC_MSG_RESULT(no)
AC_DEFINE(USE_BUILTIN_REALPATH)
],[AC_MSG_RESULT(no)
AC_DEFINE(USE_BUILTIN_REALPATH)])

AC_MSG_CHECKING(whether you already have a standard MD5 implementation)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <md5.h>

int main(void)
{
    MD5_CTX ctx;
    char b[33];
    
    MD5Init(&ctx);
    MD5Update(&ctx, (const unsigned char *) "test", 4U);
    MD5End(&ctx, b);
    b[32] = 0;

    return strcasecmp(b, "098f6bcd4621d373cade4e832627b4f6");
}
]])],[
AC_MSG_RESULT(yes)
AC_DEFINE(USE_SYSTEM_CRYPT_MD5,,[Define if you already have standard
MD5 functions])
],[AC_MSG_RESULT(no)
],[AC_MSG_RESULT(assuming no)])

AC_MSG_CHECKING(whether you already have a standard SHA1 implementation)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sha1.h>

int main(void)
{
    SHA1_CTX ctx;
    char b[41];
    
    SHA1Init(&ctx);
    SHA1Update(&ctx, (const unsigned char *) "test", 4U);
    SHA1End(&ctx, b);
    b[40] = 0;
    
    return strcasecmp(b, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
}
]])],[
AC_MSG_RESULT(yes)
AC_DEFINE(USE_SYSTEM_CRYPT_SHA1,,[Define if you already have standard
SHA1 functions])
],[AC_MSG_RESULT(no)
],[AC_MSG_RESULT(assuming no)])

AC_MSG_CHECKING([whether we are inside a Virtuozzo virtual host])
if test -d /proc/vz; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(VIRTUOZZO,,[Define if you are inside a Virtuozzo virtual
host])
else
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(default TCP send buffer size)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void)
{
    int fd,val=0,len=sizeof(int);
    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) return 1;
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &len) < 0) return 1;
    if (val <= 0) return 1;
        fprintf (fopen("conftestval", "w"), "%d\n", val);
    return 0;
}
]])],[CONF_TCP_SO_SNDBUF=`cat conftestval`],[CONF_TCP_SO_SNDBUF=65536],[CONF_TCP_SO_SNDBUF=65536])
AC_MSG_RESULT($CONF_TCP_SO_SNDBUF)

AC_DEFINE_UNQUOTED(CONF_TCP_SO_SNDBUF, $CONF_TCP_SO_SNDBUF, [default TCP send buffer])

AC_MSG_CHECKING(default TCP receive buffer size)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void)
{
    int fd,val=0,len=sizeof(int);
    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) return 1;
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len) < 0) return 1;
    if (val <= 0) return 1;
        fprintf (fopen("conftestval", "w"), "%d\n", val);
    return 0;
}
]])],[CONF_TCP_SO_RCVBUF=`cat conftestval`],[CONF_TCP_SO_RCVBUF=65536],[CONF_TCP_SO_RCVBUF=65536])
AC_MSG_RESULT($CONF_TCP_SO_RCVBUF)

AC_DEFINE_UNQUOTED(CONF_TCP_SO_RCVBUF, $CONF_TCP_SO_RCVBUF, [defaut TCP receive buffer])


AC_ARG_WITH(ldap,
[AS_HELP_STRING(--with-ldap,Users database is an LDAP directory (see doc))],
[ if test "x$withval" != "xno" ; then
    if test "x$withval" != "x" && test "x$withval" != "xyes" ; then
      LD_RUN_PATH="${withval}/lib${LD_RUN_PATH:+:}${LD_RUN_PATH}"
      LDFLAGS="$LDFLAGS -L${withval}/lib"
      CPPFLAGS="$CPPFLAGS -I${withval}/include"
    fi
    with_ldap="yes"
    AC_DEFINE(WITH_LDAP,,[with ldap])
    AC_CHECK_LIB(resolv, res_query)
    AC_CHECK_LIB(lber, ber_init, , 
    [AC_MSG_ERROR(liblber is needed for LDAP support)])
    AC_CHECK_LIB(ldap, ldap_init, ,
     [AC_MSG_WARN(Initial check for -lldap failed! May need -lssl -lcrypto) 
      AC_CHECK_LIB(ldap, ldap_bind, [ldap_ssl_libs=true], 
      [AC_MSG_ERROR(libldap is needed for LDAP support)], -lssl -lcrypto)
     ])
    if test "x$ldap_ssl_libs" = "xtrue" ; then
      LDAP_SSL_LIBS='-lssl -lcrypto'
    fi
  fi ])

AC_SUBST(LDAP_SSL_LIBS)

AC_ARG_WITH(mysql,
[AS_HELP_STRING(--with-mysql,Users database is a MySQL database (see doc))],
[ if test "x$withval" != "xno" ; then
    if test "x$withval" != "x" && test "x$withval" != "xyes" ; then
      LD_RUN_PATH="${withval}/lib${LD_RUN_PATH:+:}${LD_RUN_PATH}"    
      LDFLAGS="$LDFLAGS -L${withval}/lib -L${withval}/lib/mysql -L${withval}/mysql/lib"
      CPPFLAGS="$CPPFLAGS -I${withval}/include -I${withval}/include/mysql -I${withval}/mysql/include"
    else
      CFLAGS="$CFLAGS `mysql_config --cflags`"
      LDFLAGS="$LDFLAGS `mysql_config --libs`"
    fi
    AC_CHECK_LIB(m, floor)
    AC_CHECK_LIB(z, gzclose)
    with_mysql="yes"
    AC_DEFINE(WITH_MYSQL,,[with mysql])
    AC_CHECK_LIB(mysqlclient, mysql_init, ,
      [AC_MSG_ERROR(libmysqlclient is needed for MySQL support)])
    AC_MSG_CHECKING(whether mysql clients can run)
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdio.h>
      #include <mysql.h>    
      int main(void)
      {
          MYSQL *a = mysql_init(NULL);
          return 0;
      }
      ]])],[],[
        AC_MSG_RESULT(no)
        AC_MSG_ERROR(Your MySQL client libraries aren't properly installed)      
    ],[])
    AC_MSG_RESULT(yes)
    AC_CHECK_FUNCS(mysql_real_escape_string)
  fi ])

AC_ARG_WITH(pgsql,
[AS_HELP_STRING(--with-pgsql,Users database is a PostgreSQL database (see doc))],
[ if test "x$withval" != "xno" ; then
    if test "x$withval" != "x" && test "x$withval" != "xyes" ; then
      LD_RUN_PATH="${withval}/lib${LD_RUN_PATH:+:}${LD_RUN_PATH}"
      LDFLAGS="$LDFLAGS -L${withval}/lib -L${withval}/lib/pgsql -L${withval}/lib/postgresql -L${withval}/pgsql/lib -L${withval}/postgresql/lib"
      CPPFLAGS="$CPPFLAGS -I${withval}/include -I${withval}/include/pgsql -I${withval}/include/postgresql -I${withval}/pgsql/include -I${withval}/postgresql/include"
    else
      LD_RUN_PATH="`pg_config --libdir`${LD_RUN_PATH:+:}${LD_RUN_PATH}"
      CPPFLAGS="$CPPFLAGS -I`pg_config --includedir`"
      LDFLAGS="$LDFLAGS -L`pg_config --libdir`"
    fi
    AC_CHECK_LIB(m, floor)
    AC_CHECK_LIB(z, gzclose)
    with_pgsql="yes"
    AC_DEFINE(WITH_PGSQL,,[with pgsql])
    AC_CHECK_LIB(pq, PQconnectdb, ,
      [AC_MSG_ERROR(libpq is needed for PostgreSQL support)])        
    AC_MSG_CHECKING(whether postgresql clients can run)
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdio.h>
      #include <libpq-fe.h>
      int main(void)
      {
          PGconn *a = PQconnectdb("");
          return 0;
      }
      ]])],[],[
        AC_MSG_RESULT(no)
        AC_MSG_ERROR(Your PostgreSQL client libraries aren't properly installed)      
    ],[])    
    AC_MSG_RESULT(yes)
  fi ])

AC_ARG_WITH(tls,
[AS_HELP_STRING(--with-tls,Enable SSL/TLS support (experimental, needs OpenSSL))],
[ if test "x$withval" = "xyes" ; then
    with_tls="yes"
  fi ])

if test "x$with_tls" = "xyes" ; then
  if test "x$ac_cv_header_openssl_ssl_h" != "xyes" ; then
    AC_MSG_ERROR(OpenSSL headers not found.)  
  fi
  AC_CHECK_LIB(crypto, DH_new)
  AC_CHECK_LIB(ssl, SSL_accept)
  AC_DEFINE(WITH_TLS,,[Enable TLS])
fi

AC_ARG_WITH(certfile,
[AS_HELP_STRING(--with-certfile=,certificate file (default: /etc/ssl/private/pure-ftpd.pem))],
[ if test "x$withval" != "x" ; then
    certfile="$withval"
    AC_SUBST(certfile)
    CPPFLAGS="$CPPFLAGS -DTLS_CERTIFICATE_FILE='\"$certfile\"'"
    if test ! -e "$certfile"; then
      AC_MSG_WARN(No certificate is installed in $certfile yet)
    fi
  fi ])

AC_ARG_WITH(rfc2640,
[AS_HELP_STRING(--with-rfc2640,Enable RFC 2640 (UTF-8 encoding for file names) support (needs iconv))],
[ if test "x$withval" = "xyes" ; then
    with_rfc2640="yes"
  fi ])

if test "x$with_rfc2640" = "xyes" ; then
  if test "x$ac_cv_header_iconv_h" != "xyes" ; then
    AC_MSG_ERROR(iconv headers not found.)  
  fi
  AC_CHECK_LIB(iconv, iconv_open)
  AC_CHECK_LIB(iconv, libiconv_open)
  AC_DEFINE(WITH_RFC2640,,[Enable RFC2640 (UTF-8) support])
fi

AC_ARG_WITH(bonjour,
[AS_HELP_STRING(--with-bonjour,Enable Bonjour support on MacOS X)],
[ if test "x$withval" = "xyes" ; then
    with_bonjour="yes"
  fi ])

if test "x$with_bonjour" = "xyes" ; then
  if test "x$ac_cv_header_CoreFoundation_CoreFoundation_h" = "xyes" ; then
    AC_DEFINE(WITH_BONJOUR,,[Enable Bonjour on MacOS X])
    BONJOUR_LDADD='-framework CoreFoundation -framework CoreServices'
  fi
fi

AC_SUBST(BONJOUR_LDADD)

if test "x$sysconfdir" = 'xNONE' || test "x$sysconfdir" = 'x'; then
  CONFDIR='/etc'
else
  if test "x$sysconfdir" = 'x${prefix}/etc'; then
    if test "x$prefix" = 'xNONE' || test "x$prefix" = 'x/usr'; then
      CONFDIR='/etc'
    else
      CONFDIR="$sysconfdir"
    fi
  else
    CONFDIR="$sysconfdir"
  fi
fi  

if test "x$localstatedir" = 'xNONE' || test "x$localstatedir" = 'x'; then
  LOCALSTATEDIR='/var'
else
  if test "x$localstatedir" = 'x${prefix}/var'; then
    if test "x$prefix" = 'xNONE' || test "x$prefix" = 'x/usr' || test "x$localstatedir" = 'x${prefix}/var' ; then
      LOCALSTATEDIR='/var'
    else
      LOCALSTATEDIR="$localstatedir"
    fi
  else
    LOCALSTATEDIR="$localstatedir"
  fi
fi  

if test -r /dev/arandom; then
  AC_MSG_NOTICE([You have /dev/arandom - Great])
  AC_DEFINE(HAVE_DEV_ARANDOM,,[Define if you have /dev/arandom])
fi
if test -r /dev/urandom; then
  AC_MSG_NOTICE([You have /dev/urandom - Great])
  AC_DEFINE(HAVE_DEV_URANDOM,,[Define if you have /dev/urandom])
fi
if test -r /dev/random; then
  AC_MSG_NOTICE([You have /dev/random - Great])
  AC_DEFINE(HAVE_DEV_RANDOM,,[Define if you have /dev/random])
fi

CONFDIR=`eval echo "$CONFDIR"`
LOCALSTATEDIR=`eval echo "$LOCALSTATEDIR"`

sysconfdir="$CONFDIR"
AC_SUBST(sysconfdir)
localstatedir="$LOCALSTATEDIR"
AC_SUBST(localstatedir)

CPPFLAGS="$CPPFLAGS -DCONFDIR=\\\"$sysconfdir\\\""
CPPFLAGS="$CPPFLAGS -DSTATEDIR=\\\"$localstatedir\\\""

AC_SUBST(CONFDIR)
AC_SUBST(LOCALSTATEDIR)

AC_CONFIG_FILES(Makefile src/Makefile pam/Makefile man/Makefile
gui/Makefile configuration-file/Makefile contrib/Makefile m4/Makefile
configuration-file/pure-ftpd.conf configuration-file/pure-config.pl
configuration-file/pure-config.py puredb/Makefile puredb/src/Makefile
iphone/Makefile pure-ftpd.spec
man/pure-ftpd.8 man/pure-ftpwho.8 man/pure-mrtginfo.8 man/pure-uploadscript.8
man/pure-statsdecode.8 man/pure-quotacheck.8 man/pure-pw.8 man/pure-pwconvert.8
man/pure-authd.8)

AC_OUTPUT

AC_MSG_NOTICE([+--------------------------------------------------------+])
AC_MSG_NOTICE([| You can subscribe to the Pure-FTPd users mailing-list  |])
AC_MSG_NOTICE([| to ask for help and to stay informed of new releases.  |])
AC_MSG_NOTICE([| Go to http://www.pureftpd.org/ml/ now!                 |])
AC_MSG_NOTICE([+--------------------------------------------------------+])
