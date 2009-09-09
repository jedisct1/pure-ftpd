#ifndef __SYSLOGNAMES_H__
#define __SYSLOGNAMES_H__ 1

#ifdef SYSLOG_NAMES

struct {
    const char *c_name;
    int c_val;
} facilitynames[] =
  {
# ifdef LOG_AUTH
    { "auth", LOG_AUTH },
# endif
# ifdef LOG_AUTHPRIV
    { "authpriv", LOG_AUTHPRIV },
# endif
# ifdef LOG_CRON
    { "cron", LOG_CRON },
# endif
# ifdef LOG_DAEMON
    { "daemon", LOG_DAEMON },
# endif
# ifdef LOG_FTP
    { "ftp", LOG_FTP },
# endif
# ifdef LOG_KERN
    { "kern", LOG_KERN },
# endif
# ifdef LOG_LPR
    { "lpr", LOG_LPR },
# endif
# ifdef LOG_MAIL
    { "mail", LOG_MAIL },
# endif
# ifdef INTERNAL_MARK
    { "mark", INTERNAL_MARK },        /* INTERNAL */
# endif
# ifdef LOG_NEWS
    { "news", LOG_NEWS },
# endif      
# ifdef LOG_AUTH
    { "security", LOG_AUTH },        /* DEPRECATED */
# endif      
# ifdef LOG_SYSLOG
    { "syslog", LOG_SYSLOG },
# endif
# ifdef LOG_USER
    { "user", LOG_USER },
# endif      
# ifdef LOG_UUCP
    { "uucp", LOG_UUCP },
# endif      
# ifdef LOG_LOCAL0
    { "local0", LOG_LOCAL0 },
# endif      
# ifdef LOG_LOCAL1      
    { "local1", LOG_LOCAL1 },
# endif            
# ifdef LOG_LOCAL2      
    { "local2", LOG_LOCAL2 },
# endif            
# ifdef LOG_LOCAL3
    { "local3", LOG_LOCAL3 },
# endif            
# ifdef LOG_LOCAL4            
    { "local4", LOG_LOCAL4 },
# endif            
# ifdef LOG_LOCAL5            
    { "local5", LOG_LOCAL5 },
# endif            
# ifdef LOG_LOCAL6            
    { "local6", LOG_LOCAL6 },
# endif            
# ifdef LOG_LOCAL7            
    { "local7", LOG_LOCAL7 },
# endif            
# ifdef LOG_LOCAL8
    { "local8", LOG_LOCAL8 },
# endif            
# ifdef LOG_LOCAL9            
    { "local9", LOG_LOCAL9 },
# endif            
    { NULL, -1 }
  };

#else

extern struct {
    const char *c_name;
    int c_val;
} facilitynames[];

#endif

#endif
