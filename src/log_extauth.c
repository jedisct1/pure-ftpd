#include <config.h>

#ifdef WITH_EXTAUTH

#include "ftpd.h"
#include "dynamic.h"
#include "ftpwho-update.h"
#include "globals.h"
#include "log_extauth.h"
#include "log_extauth_p.h"
#include "safe_rw.h"
#ifdef WITH_TLS
# include "tls.h"
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static struct sockaddr_un *saddr;
static signed char auth_finalized;

void pw_extauth_parse(const char * const file)
{
    size_t file_len;
    
    if (file == NULL || (file_len = strlen(file)) <= (size_t) 0U) {
        return;
    }
    if ((saddr = malloc(sizeof(*saddr) + file_len + 
                        (size_t) 1U)) == NULL) {
        die_mem();
    }
    memcpy(saddr->sun_path, file, file_len + (size_t) 1U);
    saddr->sun_family = AF_UNIX;    
}

void pw_extauth_exit(void)
{
    free(saddr);
}

static void callback_reply_auth_ok(const char *str, AuthResult * const result)
{
    result->auth_ok = atoi(str);
}

static void callback_reply_uid(const char *str, AuthResult * const result)
{
    result->uid = (uid_t) strtoul(str, NULL, 10);
}

static void callback_reply_gid(const char *str, AuthResult * const result)
{
    result->gid = (gid_t) strtoul(str, NULL, 10);
}

static void callback_reply_dir(const char *str, AuthResult * const result)
{
    if (*str == '/') {
        free((void *) (result->dir));
        result->dir = strdup(str);
    }
}

static void callback_reply_slow_tilde_expansion(const char *str, AuthResult * const result)
{
    result->slow_tilde_expansion = (atoi(str) != 0);
}

static void callback_reply_throttling_bandwidth_ul(const char *str, AuthResult * const result)
{
#ifdef THROTTLING
    result->throttling_bandwidth_ul = strtoul(str, NULL, 10);
    result->throttling_ul_changed = 1;
#else
    (void) str;
    (void) result;
#endif
}

static void callback_reply_throttling_bandwidth_dl(const char *str, AuthResult * const result)
{
#ifdef THROTTLING
    result->throttling_bandwidth_dl = strtoul(str, NULL, 10);
    result->throttling_dl_changed = 1;
#else
    (void) str;
    (void) result;
#endif
}

static void callback_reply_user_quota_size(const char *str, AuthResult * const result)
{
#ifdef QUOTAS
    result->user_quota_size = strtoull(str, NULL, 10);
    result->quota_size_changed = 1;
#else
    (void) str;
    (void) result;
#endif
}

static void callback_reply_user_quota_files(const char *str, AuthResult * const result)
{
#ifdef QUOTAS
    result->user_quota_files = strtoull(str, NULL, 10);
    result->quota_files_changed = 1;
#else
    (void) str;
    (void) result;
#endif
}

static void callback_reply_ratio_upload(const char *str, AuthResult * const result)
{
#ifdef RATIOS
    result->ratio_upload = (unsigned int) strtoul(str, NULL, 10);
    result->ratio_ul_changed = 1;
#else
    (void) str;
    (void) result;
#endif
}   

static void callback_reply_ratio_download(const char *str, AuthResult * const result)
{
#ifdef RATIOS
    result->ratio_download = (unsigned int) strtoul(str, NULL, 10);
    result->ratio_dl_changed = 1;
#else
    (void) str;
    (void) result;
#endif
}

static void callback_reply_per_user_max(const char *str, AuthResult * const result)
{
#ifdef PER_USER_LIMITS
    result->per_user_max = (unsigned int) strtoul(str, NULL, 10);
#else
    (void) str;
    (void) result;
#endif
}

static void callback_reply_end(const char *str, AuthResult * const result)
{
    (void) str;
    (void) result;
    auth_finalized |= 1;
}

void pw_extauth_check(AuthResult * const result,
                      const char *account, const char *password,
                      const struct sockaddr_storage * const sa,
                      const struct sockaddr_storage * const peer)
{
    int kindy = -1;
    int err;
    int tries = EXTAUTH_MAX_CONNECT_TRIES;
    ssize_t readnb;
    char *linepnt;
    char *crpoint;
    char sa_hbuf[NI_MAXHOST];
    char sa_port[NI_MAXSERV];
    char peer_hbuf[NI_MAXHOST];
    char line[4096];
    size_t line_len;
    
    result->auth_ok = 0;
    if (getnameinfo((struct sockaddr *) sa, STORAGE_LEN(*sa),
                    sa_hbuf, sizeof sa_hbuf,
                    sa_port, sizeof sa_port,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0 ||
        getnameinfo((struct sockaddr *) peer, STORAGE_LEN(*peer),
                    peer_hbuf, sizeof peer_hbuf,
                    NULL, (size_t) 0U,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return;
    }
    tryagain:
    if ((kindy = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        goto bye;
    }
    while ((err = connect(kindy, (struct sockaddr *) saddr, SUN_LEN(saddr)))
           != 0 && errno == EINTR);
    if (err != 0) {
        close(kindy);
        kindy = -1;
        if (tries > 0) {
            sleep(EXTAUTH_MAX_CONNECT_DELAY);
            tries--;
            goto tryagain;
        }
        goto bye;
    }
    if (SNCHECK(snprintf(line, sizeof line, 
                         EXTAUTH_CLIENT_ACCOUNT "%s\n"
                         EXTAUTH_CLIENT_PASSWORD "%s\n"
                         EXTAUTH_CLIENT_SA_HOST "%s\n"
                         EXTAUTH_CLIENT_SA_PORT "%s\n"
                         EXTAUTH_CLIENT_PEER_HOST "%s\n"
                         EXTAUTH_CLIENT_ENCRYPTED "%d\n"
                         EXTAUTH_CLIENT_END "\n",
                         account, password, sa_hbuf, sa_port, peer_hbuf,
                         tls_cnx != NULL),
                sizeof line)) {
        goto bye;
    }
    line_len = strlen(line);
    if (safe_write(kindy, line, line_len, -1) != (ssize_t) line_len) {
        goto bye;
    }    
    result->uid = (uid_t) 0;
    result->gid = (gid_t) 0;
    result->dir = NULL;
    result->slow_tilde_expansion = 1;    
    auth_finalized = 0;
    if ((readnb = safe_read(kindy, line, sizeof line - 1U)) <= (ssize_t) 0) {
        goto bye;
    }
    line[readnb] = 0;    
    linepnt = line;
    while ((crpoint = strchr(linepnt, '\n')) != NULL) {
        const ExtauthCallBack *scanned;
        size_t keyword_len;

        *crpoint = 0;
        scanned = extauth_callbacks;
        while (scanned->keyword != NULL) {
            keyword_len = strlen(scanned->keyword);
            if (strncmp(scanned->keyword, linepnt, keyword_len) == 0) {
                scanned->func(linepnt + keyword_len, result);
                break;
            }
            scanned++;
        }
        linepnt = crpoint + 1;        
    }
    if (auth_finalized == 0 ||
        (result->auth_ok == 1 && 
         (result->uid <= (uid_t) 0 || result->gid <= (gid_t) 0 || 
          result->dir == NULL))) {
        result->auth_ok = -1;
    }
    bye:
    if (kindy != -1) {
        close(kindy);
    }
}

#endif
