#ifndef __GLOBALS_H__
#define __GLOBALS_H__ 1

#ifdef DEFINE_GLOBALS
# define GLOBAL0(A) A
# define GLOBAL(A, B) A = B
#else
# define GLOBAL0(A) extern A
# define GLOBAL(A, B) extern A
#endif

GLOBAL(char default_tz_for_putenv[], "TZ=UTC+00:00");                /* default value for TZ */
GLOBAL0(unsigned long long downloaded);                /* bytes downloaded */
GLOBAL0(unsigned long long uploaded);                /* bytes uploaded */
GLOBAL0(signed char anon_only);         /* allows only anonymous connections */
GLOBAL0(struct sockaddr_storage *trustedip);  /* IP address accepting non-anonymous connections */
GLOBAL0(volatile signed char logging);
#ifdef THROTTLING
GLOBAL0(unsigned long throttling_delay);
GLOBAL0(signed char throttling);                /* 0=don't throttle 1=throttle anon 2=all */
#endif
GLOBAL0(unsigned long throttling_bandwidth_dl);
GLOBAL0(unsigned long throttling_bandwidth_ul);
GLOBAL0(signed char allowfxp);                    /* 0=no fxp 1=authenticated 2=everybody */
GLOBAL0(signed char passive);
GLOBAL(int clientfd, 0);                   /* command connection file descriptor */
GLOBAL(int datafd, -1);                    /* data connection file descriptor */
GLOBAL0(struct sockaddr_storage ctrlconn);    /* stdin/stdout, for using the same ip number */
GLOBAL0(signed char v6ready);                    /* IPv6 supported or not */
GLOBAL0(signed char no_ipv4);                    /* IPv4 disabled or not */
GLOBAL(const size_t cmdsize, MAXPATHLEN + 16U);
GLOBAL0(char cmd[MAXPATHLEN + 32U]);        /* command line - about 30 chars for command */
GLOBAL0(char wd[MAXPATHLEN + 1U]);            /* current working directory */
GLOBAL0(char *root_directory);                /* root directory, for chroot'd environments */
GLOBAL0(signed char loggedin);                    /* != 0 if the user if logged in */
GLOBAL0(char account[MAX_USER_LENGTH + 1U]);      /* user login */
GLOBAL0(char *renamefrom);
GLOBAL0(in_port_t serverport);    /* local server port */
GLOBAL0(signed char userchroot);                /* 0=don't chroot() by default for regular users 1=chroot except members of the trusted group 2=chroot everyone */
GLOBAL0(signed char chrooted);                     /* if we already chroot()ed */
GLOBAL0(uid_t chroot_trustedgid);
GLOBAL0(signed char broken_client_compat);         /* don't enable workarounds by default */
GLOBAL0(uid_t warez);                    /* don't guard against warez */
GLOBAL0(signed char debug);                        /* don't give debug output */
GLOBAL0(signed char guest);                        /* if non-zero, it's a guest user */
GLOBAL0(uid_t useruid);                    /* smallest uid which can ftp */
GLOBAL0(signed char candownload);                /* if non-zero, don't let the user download */
GLOBAL0(double load);                    /* for reporting what the load was */
GLOBAL(time_t noopidle, (time_t) - 1);    /* when we started to receive NOOP */
GLOBAL(unsigned int firstport, 1024U);        /* first and last ports to use, if we're */
GLOBAL(unsigned int lastport, 65534U);            /* packet filter friendly. */
GLOBAL(signed char dot_write_ok, 1);           /* -x option */
GLOBAL(signed char dot_read_ok, 1);            /* -X option */
GLOBAL0(signed char dot_read_anon_ok);            /* -z option */
#ifndef DEFAULT_TO_BINARY_TYPE
GLOBAL(signed char type, 1);                    /* type - 0 = error, 1 = ascii, 2 = binary */
#else
GLOBAL(signed char type, 2);
#endif
#ifdef RATIOS
GLOBAL0(unsigned int ratio_upload);
GLOBAL0(unsigned int ratio_download);
GLOBAL0(signed char ratio_for_non_anon);
#endif
GLOBAL0(off_t restartat);
GLOBAL(unsigned long int idletime, DEFAULT_IDLE);
GLOBAL0(double idletime_noop);
GLOBAL(signed char resolve_hostnames, 1);
GLOBAL0(int allow_anon_mkdir);
GLOBAL(unsigned int max_ls_files, DEFAULT_MAX_LS_FILES);
GLOBAL(unsigned int max_ls_depth, DEFAULT_MAX_LS_DEPTH);
GLOBAL0(char *fortunes_file);
GLOBAL0(char host[NI_MAXHOST]);
GLOBAL0(int replycode);
GLOBAL0(signed char force_ls_a);
GLOBAL0(struct sockaddr_storage peer);
GLOBAL0(struct sockaddr_storage force_passive_ip);
GLOBAL0(const char *force_passive_ip_s);
GLOBAL0(in_port_t peerdataport);
GLOBAL0(double maxload);
GLOBAL(unsigned int maxusers, DEFAULT_MAX_USERS);
#ifdef PER_USER_LIMITS
GLOBAL0(unsigned int per_user_max);
GLOBAL0(unsigned int per_anon_max);
#endif
GLOBAL0(int iptropy);
GLOBAL(volatile int xferfd, -1);
#ifndef NO_STANDALONE
GLOBAL0(unsigned int maxip);
#endif
#ifndef NO_INETD
GLOBAL0(signed char standalone);
#endif
GLOBAL0(signed char epsv_all);
GLOBAL0(double maxdiskusagepct);
GLOBAL0(signed char disallow_passive);
GLOBAL(mode_t u_mask, 0133);
GLOBAL(mode_t u_mask_d, 0022);
GLOBAL(signed char state_needs_update, 1);
GLOBAL0(signed char no_syslog);
GLOBAL(int syslog_facility, DEFAULT_FACILITY);
GLOBAL0(signed char autorename);
GLOBAL0(signed char anon_noupload);
GLOBAL0(signed char nochmod);
GLOBAL0(signed char keepallfiles);

#ifndef MINIMAL
GLOBAL0(signed char modern_listings);
#endif

#ifndef NO_STANDALONE
GLOBAL0(signed char daemonize);
#endif

#ifdef FTPWHO
GLOBAL0(int shm_id);
GLOBAL0(FTPWhoEntry *shm_data);
GLOBAL0(FTPWhoEntry *shm_data_cur);
GLOBAL0(char *scoreboardfile);
#endif

#if defined(WITH_UPLOAD_SCRIPT)
GLOBAL0(signed char do_upload_script);
GLOBAL(int upload_pipe_fd, -1);
GLOBAL(int upload_pipe_lock, -1);
#endif

GLOBAL0(signed char create_home);
GLOBAL0(signed char disallow_rename);
GLOBAL0(signed char no_truncate);

GLOBAL0(size_t page_size);
GLOBAL0(int log_pid); /* 0 or LOG_PID if PID is to be logged */

#ifdef WITH_ALTLOG
GLOBAL0(const char *altlog_filename);
GLOBAL0(AltLogFormat altlog_format);
GLOBAL(int altlog_fd, -1);
#endif

#ifdef QUOTAS
GLOBAL(unsigned long long user_quota_size, ULONG_LONG_MAX);
GLOBAL(unsigned long long user_quota_files, ULONG_LONG_MAX);
#endif

#define MONTHS_NAMES "Jan", "Feb", "Mar", "Apr", "May", "Jun", \
                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
GLOBAL(const char *months[12], { MONTHS_NAMES });

#ifdef WITH_ALTLOG
# define WEEK_DAYS_NAMES "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
GLOBAL(const char *week_days[7], { WEEK_DAYS_NAMES });
#endif

GLOBAL0(AuthResult authresult);
GLOBAL0(time_t session_start_time);

#ifndef NO_STANDALONE
GLOBAL(const char *pid_file, PID_FILE);
#endif

GLOBAL0(signed char be_customer_proof);

#ifdef WITH_TLS
GLOBAL0(signed char enforce_tls_auth);
GLOBAL0(int data_protection_level); 
#endif

GLOBAL0(char *atomic_prefix);

#endif

#ifdef WITH_RFC2640
GLOBAL(char utf8, 0);	/* 0: ascii 1: utf-8 */
GLOBAL(char *charset_fs, NULL);
GLOBAL(char *charset_client, NULL);
GLOBAL(iconv_t iconv_fd_fs2client, NULL);
GLOBAL(iconv_t iconv_fd_fs2utf8, NULL);
GLOBAL(iconv_t iconv_fd_client2fs, NULL);
GLOBAL(iconv_t iconv_fd_utf82fs, NULL);
#endif

#ifndef WITH_TLS
GLOBAL0(void * tls_cnx);
GLOBAL0(void * tls_data_cnx);
#endif

#ifdef NON_ROOT_FTP
GLOBAL0(const char *home_directory);
#endif

#ifndef MINIMAL
GLOBAL0(unsigned long cwd_failures);
#endif
