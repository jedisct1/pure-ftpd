#include <config.h>

#include "ftpd.h"
#include "dynamic.h"
#include "ftpwho-update.h"
#include "globals.h"
#include "messages.h"
#ifdef WITH_DIRALIASES
# include "diraliases.h"
#endif
#ifdef WITH_TLS
# include "tls.h"
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void antiidle(void)
{
    if (noopidle == (time_t) -1) {
        noopidle = time(NULL);
    } else {
        if ((time(NULL) - noopidle) > (time_t) idletime_noop) {
            die(421, LOG_INFO, MSG_TIMEOUT_NOOP, (unsigned long) idletime_noop);
        }
    }    
}

/* 
 * Introduce a random delay, to avoid guessing existing user names by
 * mesuring delay. It's especially true when LDAP is used.
 * No need to call usleep2() because we are root at this point.
 */

static void randomdelay(void)
{
    usleep(rand() % 15000UL);          /* dummy... no need for arc4 */
}

/* 
 * Simple but fast command-line reader. We break the FTP protocol here,
 * because we deny access to files with strange characters in their name.
 * Now, I seriously doubt that clients should be allowed to upload files
 * with carriage returns, bells, cursor moves and other fancy stuff in the
 * names. It can indirectly lead to security flaws with scripts, it's
 * annoying for the sysadmin, it can be a client error, it can bring unexpected
 * results on some filesystems, etc. So control chars are replaced by "_".
 * Better be safe than 100% RFC crap compliant but unsafe. If you really want
 * RFC compliance, define RFC_CONFORMANT_PARSER. But I will hate you.
 * 
 * RFC_CONFORMANT_LINES is another thing that clients should implement
 * properly (and it's trivial to do) : lines must be ended with \r\n .
 * Guess what ? 
 * Some broken clients are just sending \n ... Grrrrrrrrrrrr !!!!!!!!!!!!!!!
 * 
 * -Frank.
 */

static size_t scanned;
static size_t readnbd;

#ifdef WITH_TLS
static void flush_cmd(void)
{
    scanned = readnbd = (size_t) 0U;
}
#endif

int sfgets(void)
{
    struct pollfd pfd;
    int pollret;
    ssize_t readnb;
    signed char seen_r = 0;
    
    if (scanned > (size_t) 0U) {       /* support pipelining */
        readnbd -= scanned;        
        memmove(cmd, cmd + scanned, readnbd);   /* safe */
        scanned = (size_t) 0U;
    }
    pfd.fd = clientfd;
#ifdef __APPLE_CC__
    pfd.events = POLLIN | POLLERR | POLLHUP;
#else
    pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP;
#endif
    while (scanned < cmdsize) {
        if (scanned >= readnbd) {      /* nothing left in the buffer */
            pfd.revents = 0;
            while ((pollret = poll(&pfd, 1U, idletime * 1000UL)) < 0 &&
                   errno == EINTR);
            if (pollret == 0) {
                return -1;
            }
            if (pollret <= 0 ||
                (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return -2;
            }
            if ((pfd.revents & (POLLIN | POLLPRI)) == 0) {
                continue;
            }
            if (readnbd >= cmdsize) {
                break;
            }
#ifdef WITH_TLS
            if (tls_cnx != NULL) {
                while ((readnb = SSL_read
                        (tls_cnx, cmd + readnbd, cmdsize - readnbd))
                       < (ssize_t) 0 && errno == EINTR);
            } else
#endif
            {
                while ((readnb = read(clientfd, cmd + readnbd,
                                      cmdsize - readnbd)) < (ssize_t) 0 &&
                       errno == EINTR);
            }
            if (readnb <= (ssize_t) 0) {
                return -2;
            }
            readnbd += readnb;
            if (readnbd > cmdsize) {
                return -2;
            }
        }
#ifdef RFC_CONFORMANT_LINES
        if (seen_r != 0) {
#endif
            if (cmd[scanned] == '\n') {
#ifndef RFC_CONFORMANT_LINES
                if (seen_r != 0) {
#endif
                    cmd[scanned - 1U] = 0;
#ifndef RFC_CONFORMANT_LINES
                } else {
                    cmd[scanned] = 0;
                }
#endif
                if (++scanned >= readnbd) {   /* non-pipelined command */
                    scanned = readnbd = (size_t) 0U;
                }
                return 0;
            }
            seen_r = 0;
#ifdef RFC_CONFORMANT_LINES
        }
#endif
        if (ISCTRLCODE(cmd[scanned])) {
            if (cmd[scanned] == '\r') {
                seen_r = 1;
            }
#ifdef RFC_CONFORMANT_PARSER                   /* disabled by default, intentionnaly */
            else if (cmd[scanned] == 0) {
                cmd[scanned] = '\n';
            }
#else
            /* replace control chars with _ */
            cmd[scanned] = '_';                
#endif
        }
        scanned++;
    }
    die(421, LOG_WARNING, MSG_LINE_TOO_LONG);   /* don't remove this */
    
    return 0;                         /* to please GCC */
}

/* Replace extra spaces before and after a string with '_' */

#ifdef MINIMAL
# define revealextraspc(X) (X)
#else
static char *revealextraspc(char * const s_)
{
    unsigned char *s = (unsigned char *) s_;
    unsigned char *sn;
    
    if (s == NULL) {
        return s_;
    }
    simplify(s_);
    while (*s != 0U && isspace(*s)) {
        *s++ = '_';
    }
    if (*s == 0U) {
        return s_;
    }
    sn = s;
    do {
        sn++;
    } while (*sn != 0U);
    do {
        sn--;        
        if (!isspace(*sn)) {
            break;
        }
        *sn = '_';
    } while (sn != s);
    
    return s_;
}
#endif

#ifdef WITH_RFC2640
char *charset_client2fs(const char * const string)
{
    char *output = NULL, *output_;
    size_t inlen, outlen, outlen_;
    
    inlen = strlen(string);
    outlen_ = outlen = inlen * (size_t) 4U + (size_t) 1U;
    if (outlen <= inlen ||
        (output_ = output = calloc(outlen, (size_t) 1U)) == NULL) {
        die_mem();
    }
    if (utf8 > 0 && strcasecmp(charset_fs, "utf-8") != 0) {
        if (iconv(iconv_fd_utf82fs, (char **) &string,
                  &inlen, &output_, &outlen_) == (size_t) -1) {
            strncpy(output, string, outlen);
        }
    } else if (utf8 <= 0 && strcasecmp(charset_fs, charset_client) != 0) {
        if (iconv(iconv_fd_client2fs, (char **) &string,
                  &inlen, &output_, &outlen_) == (size_t) -1) {
            strncpy(output, string, outlen);
        }
    } else {
        strncpy(output, string, outlen);
    }
    output[outlen - 1] = 0;    
    
    return output;
}
#endif

#ifndef MINIMAL
static void parse_file_time_change(char *arg)
{
    char *name;

    if ((name = strchr(arg, ' ')) == NULL) {
        addreply_noformat(501, MSG_MISSING_ARG);
        return;
    }
    while (*name == ' ') {
        name++;
    }
    if (*name == 0) {
        addreply_noformat(501, MSG_MISSING_ARG);
        return;
    }
    doutime(name, arg);
}
#endif

void parser(void)
{
    char *arg;
#ifndef MINIMAL
    char *sitearg;
#endif
#ifdef WITH_RFC2640
    char *narg = NULL;
#endif
    size_t n;

#ifdef IMPLICIT_TLS
    (void) tls_init_new_session();
    data_protection_level = CPL_PRIVATE;
#endif
    for (;;) {
        xferfd = -1;
        if (state_needs_update != 0) {
            state_needs_update = 0;
            setprocessname("pure-ftpd (IDLE)");
#ifdef FTPWHO
            if (shm_data_cur != NULL) {
                ftpwho_lock();
                shm_data_cur->state = FTPWHO_STATE_IDLE;
                *shm_data_cur->filename = 0;
                ftpwho_unlock();
            }
#endif
        }
        doreply();
        alarm(idletime * 2);
        switch (sfgets()) {
        case -1:
#ifdef BORING_MODE
            die(421, LOG_INFO, MSG_TIMEOUT);
#else
            die(421, LOG_INFO, MSG_TIMEOUT_PARSER);
#endif
        case -2:
            return;
        }
#ifdef DEBUG
        if (debug != 0) {
            addreply(0, "%s", cmd);
        }
#endif
        n = (size_t) 0U;
        while ((isalpha((unsigned char) cmd[n]) || cmd[n] == '@') &&
               n < cmdsize) {
            cmd[n] = (char) tolower((unsigned char) cmd[n]);
            n++;
        }
        if (n >= cmdsize) {            /* overparanoid, it should never happen */
            die(421, LOG_WARNING, MSG_LINE_TOO_LONG);
        }
        if (n == (size_t) 0U) {
            nop:
            addreply_noformat(500, "?");
            continue;
        }
#ifdef SKIP_COMMAND_TRAILING_SPACES        
        while (isspace((unsigned char) cmd[n]) && n < cmdsize) {
            cmd[n++] = 0;
        }
        arg = cmd + n;        
        while (cmd[n] != 0 && n < cmdsize) {
            n++;
        }
        n--;
        while (isspace((unsigned char) cmd[n])) {
            cmd[n--] = 0;
        }
#else
        if (cmd[n] == 0) {
            arg = cmd + n;
        } else if (isspace((unsigned char) cmd[n])) {
            cmd[n] = 0;
            arg = cmd + n + 1;
        } else {
            goto nop;
        }
#endif
        if (logging != 0) {
#ifdef DEBUG
            logfile(LOG_DEBUG, MSG_DEBUG_COMMAND " [%s] [%s]",
                   cmd, arg);
#else
            logfile(LOG_DEBUG, MSG_DEBUG_COMMAND " [%s] [%s]",
                   cmd, strcmp(cmd, "pass") ? arg : "<*>");
#endif
        }
#ifdef WITH_RFC2640
        narg = charset_client2fs(arg);
	arg = narg;
#endif
        /*
         * antiidle() is called with dummy commands, usually used by clients
         * who are wanting extra idle time. We give them some, but not too much.
         * When we jump to wayout, the idle timer is not zeroed. It means that
         * we didn't issue an 'active' command like RETR.
         */
        
#ifndef MINIMAL
        if (!strcmp(cmd, "noop")) {
            antiidle();
            donoop();
            goto wayout;
        }
#endif
        if (!strcmp(cmd, "user")) {
#ifdef WITH_TLS
            if (enforce_tls_auth > 1 && tls_cnx == NULL) {
                die(421, LOG_WARNING, MSG_TLS_NEEDED);
            }
#endif
            douser(arg);
        } else if (!strcmp(cmd, "acct")) {
            addreply(202, MSG_WHOAREYOU);
        } else if (!strcmp(cmd, "pass")) {
            if (guest == 0) {
                randomdelay();
            }
            dopass(arg);
        } else if (!strcmp(cmd, "quit")) {
            addreply(221, MSG_GOODBYE,
                     (unsigned long long) ((uploaded + 1023ULL) / 1024ULL),
                     (unsigned long long) ((downloaded + 1023ULL) / 1024ULL));
            return;
        } else if (!strcmp(cmd, "syst")) {
            antiidle();
            addreply_noformat(215, "UNIX Type: L8");
            goto wayout;
#ifdef WITH_TLS
        } else if (enforce_tls_auth > 0 &&
                   !strcmp(cmd, "auth") && !strcasecmp(arg, "tls")) {
            addreply_noformat(234, "AUTH TLS OK.");
            doreply();
            if (tls_cnx == NULL) {
                flush_cmd();
                (void) tls_init_new_session();
            }
            goto wayout;
        } else if (!strcmp(cmd, "pbsz")) {
            addreply_noformat(tls_cnx == NULL ? 503 : 200, "PBSZ=0");
        } else if (!strcmp(cmd, "prot")) {
            if (tls_cnx == NULL) {
                addreply_noformat(503, MSG_PROT_BEFORE_PBSZ);
                goto wayout;
            }
            switch (*arg) {
            case 0:
                addreply_noformat(503, MSG_MISSING_ARG);
                data_protection_level = CPL_NONE;
                break;
            case 'C':
                if (arg[1] == 0) {
                    addreply(200, MSG_PROT_OK, "clear");
                    data_protection_level = CPL_CLEAR;
                    break;
                }
            case 'S':
            case 'E':
                if (arg[1] == 0) {
                    addreply(200, MSG_PROT_UNKNOWN_LEVEL, arg, "private");
                    data_protection_level = CPL_PRIVATE;
                    break;
                }
            case 'P':
                if (arg[1] == 0) {
                    addreply(200, MSG_PROT_OK, "private");
                    data_protection_level = CPL_PRIVATE;
                    break;
                }
            default:
                addreply_noformat(534, "Fallback to [C]");
                data_protection_level = CPL_CLEAR;
                break;
            }
#endif
        } else if (!strcmp(cmd, "auth") || !strcmp(cmd, "adat")) {
            addreply_noformat(500, MSG_AUTH_UNIMPLEMENTED);
        } else if (!strcmp(cmd, "type")) {
            antiidle();
            dotype(arg);
            goto wayout;
        } else if (!strcmp(cmd, "mode")) {
            antiidle();                
            domode(arg);
            goto wayout;
#ifndef MINIMAL
        } else if (!strcmp(cmd, "feat")) {
            dofeat();
            goto wayout;
	} else if (!strcmp(cmd, "opts")) {
	    doopts(arg);
	    goto wayout;
#endif
        } else if (!strcmp(cmd, "stru")) {
            dostru(arg);
            goto wayout;
#ifndef MINIMAL
        } else if (!strcmp(cmd, "help")) {
            goto help_site;
#endif
#ifdef DEBUG
        } else if (!strcmp(cmd, "xdbg")) {
            debug++;
            addreply(200, MSG_XDBG_OK, debug);
            goto wayout;
#endif            
        } else if (loggedin == 0) {            
            /* from this point, all commands need authentication */
            addreply_noformat(530, MSG_NOT_LOGGED_IN);
            goto wayout;
        } else {
            if (!strcmp(cmd, "cwd") || !strcmp(cmd, "xcwd")) {
                antiidle();
                docwd(arg);
                goto wayout;
            } else if (!strcmp(cmd, "port")) {
                doport(arg);
#ifndef MINIMAL
            } else if (!strcmp(cmd, "eprt")) {
                doeprt(arg);
            } else if (!strcmp(cmd, "esta") &&
                       disallow_passive == 0 &&
                       STORAGE_FAMILY(force_passive_ip) == 0) {
                doesta();
            } else if (!strcmp(cmd, "estp")) {
                doestp();
#endif
            } else if (disallow_passive == 0 && 
                       (!strcmp(cmd, "pasv") || !strcmp(cmd, "p@sw"))) {
                dopasv(0);
            } else if (disallow_passive == 0 && 
                       (!strcmp(cmd, "epsv") && 
                       (broken_client_compat == 0 ||
                        STORAGE_FAMILY(ctrlconn) == AF_INET6))) {
                if (!strcasecmp(arg, "all")) {
                    epsv_all = 1;
                    addreply_noformat(220, MSG_ACTIVE_DISABLED);
                } else if (!strcmp(arg, "2") && !v6ready) {
                    addreply_noformat(522, MSG_ONLY_IPV4);
                } else {
                    dopasv(1);
                }
#ifndef MINIMAL            
            } else if (disallow_passive == 0 && !strcmp(cmd, "spsv")) {
                dopasv(2);
            } else if (!strcmp(cmd, "allo")) {
                if (*arg == 0) {
                    addreply_noformat(501, MSG_STAT_FAILURE);
                } else {
                    const off_t size = (off_t) strtoull(arg, NULL, 10);
                    
                    if (size < (off_t) 0) {
                        addreply_noformat(501, MSG_STAT_FAILURE);                        
                    } else {
                        doallo(size);
                    }
                }
#endif
            } else if (!strcmp(cmd, "pwd") || !strcmp(cmd, "xpwd")) {
#ifdef WITH_RFC2640
		char *nwd;
#endif
                antiidle();
#ifdef WITH_RFC2640
		nwd = charset_fs2client(wd);
		addreply(257, "\"%s\" " MSG_IS_YOUR_CURRENT_LOCATION, nwd);
		free(nwd);
#else
                addreply(257, "\"%s\" " MSG_IS_YOUR_CURRENT_LOCATION, wd);
#endif
                goto wayout;                
            } else if (!strcmp(cmd, "cdup") || !strcmp(cmd, "xcup")) {
                docwd("..");
            } else if (!strcmp(cmd, "retr")) {
                if (*arg != 0) {
#ifdef WITH_TLS
                    if (enforce_tls_auth == 3 &&
                        data_protection_level != CPL_PRIVATE) {
                        addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                    }
                    else
#endif
                    {
                        doretr(arg);
                    }
                } else {
                    addreply_noformat(501, MSG_NO_FILE_NAME);
                }
            } else if (!strcmp(cmd, "rest")) {
                antiidle();
                if (*arg != 0) {
                    dorest(arg);
                } else {
                    addreply_noformat(501, MSG_NO_RESTART_POINT);
                    restartat = (off_t) 0;
                }
                goto wayout;
            } else if (!strcmp(cmd, "dele")) {
                if (*arg != 0) {
                    dodele(arg);
                } else {
                    addreply_noformat(501, MSG_NO_FILE_NAME);
                }
            } else if (!strcmp(cmd, "stor")) {
                arg = revealextraspc(arg);
                if (*arg != 0) {
#ifdef WITH_TLS
                    if (enforce_tls_auth == 3 &&
                        data_protection_level != CPL_PRIVATE) {
                        addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                    } else 
#endif
                    {
                        dostor(arg, 0, autorename);
                    }
                } else {
                    addreply_noformat(501, MSG_NO_FILE_NAME);
                }
            } else if (!strcmp(cmd, "appe")) {
                arg = revealextraspc(arg);
                if (*arg != 0) {
#ifdef WITH_TLS
                    if (enforce_tls_auth == 3 &&
                        data_protection_level != CPL_PRIVATE) {
                        addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                    } else 
#endif
                    {
                        dostor(arg, 1, 0);
                    }
                } else {
                    addreply_noformat(501, MSG_NO_FILE_NAME);
                }
#ifndef MINIMAL
            } else if (!strcmp(cmd, "stou")) {
#ifdef WITH_TLS
                if (enforce_tls_auth == 3 &&
                    data_protection_level != CPL_PRIVATE) {
                    addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                } else 
#endif
                {
            	     dostou();
                }
#endif
#ifndef DISABLE_MKD_RMD
            } else if (!strcmp(cmd, "mkd") || !strcmp(cmd, "xmkd")) {
                arg = revealextraspc(arg);
                if (*arg != 0) {
                    domkd(arg);
                } else {
                    addreply_noformat(501, MSG_NO_DIRECTORY_NAME);
                }
            } else if (!strcmp(cmd, "rmd") || !strcmp(cmd, "xrmd")) {
                if (*arg != 0) {
                    dormd(arg);
                } else {
                    addreply_noformat(550, MSG_NO_DIRECTORY_NAME);
                }
#endif
#ifndef MINIMAL
            } else if (!strcmp(cmd, "stat")) {
                if (*arg != 0) {
                    modern_listings = 0;
                    donlist(arg, 1, 1, 1, 1);
                } else {
                    addreply_noformat(211, "http://www.pureftpd.org/");
                }
#endif
            } else if (!strcmp(cmd, "list")) {
#ifndef MINIMAL
                modern_listings = 0;
#endif
#ifdef WITH_TLS
                if (enforce_tls_auth == 3 &&
                    data_protection_level != CPL_PRIVATE) {
                    addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                } else
#endif
                {
                    donlist(arg, 0, 1, 0, 1);
                }
            } else if (!strcmp(cmd, "nlst")) {
#ifndef MINIMAL                
                modern_listings = 0;
#endif
#ifdef WITH_TLS
                if (enforce_tls_auth == 3 &&
                    data_protection_level != CPL_PRIVATE) {
                    addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                } else
#endif
                {
                    donlist(arg, 0, 0, 0, broken_client_compat);
                }
#ifndef MINIMAL
            } else if (!strcmp(cmd, "mfmt")) {
                parse_file_time_change(arg);
            } else if (!strcmp(cmd, "mlst")) {
# ifdef WITH_TLS
                if (enforce_tls_auth == 3 &&
                    data_protection_level != CPL_PRIVATE) {
                    addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                } else
# endif
                {
                    domlst(*arg != 0 ? arg : ".");
                }
            } else if (!strcmp(cmd, "mlsd")) {
                modern_listings = 1;
# ifdef WITH_TLS
                if (enforce_tls_auth == 3 &&
                    data_protection_level != CPL_PRIVATE) {
                    addreply_noformat(521, MSG_PROT_PRIVATE_NEEDED);
                } else
# endif
                {
                    donlist(arg, 0, 1, 1, 0);
                }
#endif
            } else if (!strcmp(cmd, "abor")) {
                addreply_noformat(226, MSG_ABOR_SUCCESS);
#ifndef MINIMAL
            } else if (!strcmp(cmd, "site")) {
                if ((sitearg = arg) != NULL) {
                    while (*sitearg != 0 && !isspace((unsigned char) *sitearg)) {
                        sitearg++;
                    }
                    if (*sitearg != 0) {
                        *sitearg++ = 0;
                    }
                }
                if (!strcasecmp(arg, "idle")) {
                    if (sitearg == NULL || *sitearg == 0) {
                        addreply_noformat(501, "SITE IDLE: " MSG_MISSING_ARG);
                    } else {
                        unsigned long int i = 0;

                        i = strtoul(sitearg, &sitearg, 10);
                        if (sitearg && *sitearg)
                            addreply(501, MSG_GARBAGE_FOUND " : %s", sitearg);
                        else if (i > MAX_SITE_IDLE)
                            addreply_noformat(501, MSG_VALUE_TOO_LARGE);
                        else {
                            idletime = i;
                            addreply(200, MSG_IDLE_TIME, idletime);
                            idletime_noop = (double) idletime * 2.0;
                        }
                    }
                } else if (!strcasecmp(arg, "time")) {
                    dositetime();
                } else if (!strcasecmp(arg, "help")) {
                    help_site:
                    
                    addreply_noformat(214, MSG_SITE_HELP CRLF
# ifdef WITH_DIRALIASES
                                      " ALIAS" CRLF
# endif
                                      " CHMOD" CRLF " IDLE" CRLF " UTIME");
                    addreply_noformat(214, "Pure-FTPd - http://pureftpd.org/");
                } else if (!strcasecmp(arg, "chmod")) {
                    char *sitearg2;
                    mode_t mode;
                    
                    parsechmod:
                    if (sitearg == NULL || *sitearg == 0) {
                        addreply_noformat(501, MSG_MISSING_ARG);
                        goto chmod_wayout;
                    }
                    sitearg2 = sitearg;
                    while (*sitearg2 != 0 && !isspace((unsigned char) *sitearg2)) {
                        sitearg2++;
                    }                    
                    while (*sitearg2 != 0 && isspace((unsigned char) *sitearg2)) {
                        sitearg2++;
                    }                    
                    if (*sitearg2 == 0) {
                        addreply_noformat(550, MSG_NO_FILE_NAME);
                        goto chmod_wayout;
                    }
                    mode = (mode_t) strtoul(sitearg, NULL, 8);
                    if (mode > (mode_t) 07777) {
                        addreply_noformat(501, MSG_BAD_CHMOD);
                        goto chmod_wayout;
                    }
                    dochmod(sitearg2, mode);
                    chmod_wayout:
                    (void) 0;
                } else if (!strcasecmp(arg, "utime")) {
                    char *sitearg2;
                    
                    if (sitearg == NULL || *sitearg == 0) {
                        addreply_noformat(501, MSG_NO_FILE_NAME);
                        goto utime_wayout;
                    }		    
                    if ((sitearg2 = strrchr(sitearg, ' ')) == NULL ||
                        sitearg2 == sitearg) {
                        addreply_noformat(501, MSG_MISSING_ARG);
                        goto utime_wayout;
                    }
                    if (strcasecmp(sitearg2, " UTC") != 0) {
                        parse_file_time_change(sitearg);
                        goto utime_wayout;			
                    }
                    *sitearg2-- = 0;
                    if ((sitearg2 = strrchr(sitearg, ' ')) == NULL ||
                        sitearg2 == sitearg) {
                        utime_no_arg:
                        addreply_noformat(501, MSG_MISSING_ARG);
                        goto utime_wayout;
                    }
                    *sitearg2-- = 0;
                    if ((sitearg2 = strrchr(sitearg, ' ')) == NULL ||
                        sitearg2 == sitearg) {
                        goto utime_no_arg;
                    }
                    *sitearg2-- = 0;
                    if ((sitearg2 = strrchr(sitearg, ' ')) == NULL ||
                        sitearg2 == sitearg) {
                        goto utime_no_arg;
                    }
                    *sitearg2++ = 0;
                    if (*sitearg2 == 0) {
                        goto utime_no_arg;			
                    }
                    doutime(sitearg, sitearg2);
                    utime_wayout:
                    (void) 0;
# ifdef WITH_DIRALIASES		    
                } else if (!strcasecmp(arg, "alias")) {
                    if (sitearg == NULL || *sitearg == 0) {
                        print_aliases();
                    } else {
                        const char *alias;
                        
                        if ((alias = lookup_alias(sitearg)) != NULL) {
                            addreply(214, MSG_ALIASES_ALIAS, sitearg, alias);
                        } else {
                            addreply(502, MSG_ALIASES_UNKNOWN, sitearg);
                        }
                    }
# endif
                } else if (*arg != 0) {
                    addreply(500, "SITE %s " MSG_UNKNOWN_EXTENSION, arg);
                } else {
                    addreply_noformat(500, "SITE: " MSG_MISSING_ARG);
                }
#endif
            } else if (!strcmp(cmd, "mdtm")) {
                domdtm(arg);
            } else if (!strcmp(cmd, "size")) {
                dosize(arg);
#ifndef MINIMAL
            } else if (!strcmp(cmd, "chmod")) {
                sitearg = arg;
                goto parsechmod;
#endif
            } else if (!strcmp(cmd, "rnfr")) {
                if (*arg != 0) {
                    dornfr(arg);
                } else {
                    addreply_noformat(550, MSG_NO_FILE_NAME);
                }
            } else if (!strcmp(cmd, "rnto")) {
                arg = revealextraspc(arg);
                if (*arg != 0) {
                    dornto(arg);
                } else {
                    addreply_noformat(550, MSG_NO_FILE_NAME);
                }
            } else {
                addreply_noformat(500, MSG_UNKNOWN_COMMAND);
            }
        }
        noopidle = (time_t) -1;
        wayout:
#ifdef WITH_RFC2640
        free(narg);
        narg = NULL;
#endif
#ifdef THROTTLING
        if (throttling_delay != 0UL) {
            usleep2(throttling_delay);
        }
#else
        (void) 0;
#endif
    }
}
