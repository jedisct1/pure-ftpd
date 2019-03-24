#include <config.h>

#ifdef WITH_TLS

#include "ftpd.h"
#include "ftpwho-update.h"
#include "globals.h"
#include "tls_extcert.h"
#include "tls_extcert_p.h"
#include "safe_rw.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static struct sockaddr_un *saddr;
static signed char cert_finalized;

void tls_extcert_parse(const char * const file)
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

void tls_extcert_exit(void)
{
    free(saddr);
    saddr = NULL;
}

static void callback_reply_action(const char *str, CertResult * const result)
{
    if (strcasecmp(str, "deny") == 0) {
        result->action = CERT_ACTION_DENY;
    } else if (strcasecmp(str, "default") == 0) {
        result->action = CERT_ACTION_DEFAULT;
    } else if (strcasecmp(str, "fallback") == 0) {
        result->action = CERT_ACTION_FALLBACK;
    } else if (strcasecmp(str, "strict") == 0) {
        result->action = CERT_ACTION_STRICT;
    } else {
        die(421, LOG_ERR, "Cert action");
    }
}

static void callback_reply_cert_file(const char *str, CertResult * const result)
{
    if (*str != '/') {
        return;
    }
    if (access(str, R_OK) != 0) {
        return;
    }
    free((void *) (result->cert_file));
    result->cert_file = strdup(str);
}

static void callback_reply_key_file(const char *str, CertResult * const result)
{
    if (*str != '/') {
        return;
    }
    if (access(str, R_OK) != 0) {
        return;
    }
    free((void *) (result->key_file));
    result->key_file = strdup(str);
}

static void callback_reply_end(const char *str, CertResult * const result)
{
    (void) str;
    (void) result;
    cert_finalized |= 1;
}

void tls_extcert_get(CertResult * const result, const char *sni_name)
{
    int kindy = -1;
    int err;
    int tries = EXTCERT_MAX_CONNECT_TRIES;
    ssize_t readnb;
    char *linepnt;
    char *crpoint;
    char line[4096];
    size_t line_len;

    result->cert_ok = 0;

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
            sleep(EXTCERT_MAX_CONNECT_DELAY);
            tries--;
            goto tryagain;
        }
        goto bye;
    }
    if (SNCHECK(snprintf(line, sizeof line,
                         EXTCERT_CLIENT_SNI_NAME "%s\n"
                         EXTCERT_CLIENT_END "\n",
                         sni_name),
                sizeof line)) {
        goto bye;
    }
    line_len = strlen(line);
    if (safe_write(kindy, line, line_len, -1) != (ssize_t) line_len) {
        goto bye;
    }
    result->cert_file = NULL;
    result->key_file = NULL;
    result->action = CERT_ACTION_DENY;
    cert_finalized = 0;
    if ((readnb = safe_read(kindy, line, sizeof line - 1U)) <= (ssize_t) 0) {
        goto bye;
    }
    line[readnb] = 0;
    linepnt = line;
    while ((crpoint = strchr(linepnt, '\n')) != NULL) {
        const ExtcertCallBack *scanned;
        size_t keyword_len;

        *crpoint = 0;
        scanned = extcert_callbacks;
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
    if (cert_finalized == 0 ||
       (result->cert_file == NULL &&
           result->action != CERT_ACTION_DENY &&
           result->action != CERT_ACTION_DEFAULT)) {
        result->cert_ok = -1;
    } else {
        result->cert_ok = 1;
    }
    bye:
    if (kindy != -1) {
        close(kindy);
    }
}

#endif
