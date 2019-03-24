#ifndef __TLS_EXTCERT_P_H__
#define __TLS_EXTCERT_P_H__ 1

#ifdef WITH_TLS

#include <sys/un.h>

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) NULL)->sun_path) \
                           + strlen((ptr)->sun_path))
#endif

#ifndef EXTCERT_MAX_CONNECT_TRIES
# define EXTCERT_MAX_CONNECT_TRIES 10
#endif
#ifndef EXTCERT_MAX_CONNECT_DELAY
# define EXTCERT_MAX_CONNECT_DELAY 1
#endif

typedef struct ExtcertCallBack_ {
    const char *keyword;
    void (*func)(const char *str, CertResult * const result);
} ExtcertCallBack;

static void callback_reply_action(const char *str, CertResult * const result);
static void callback_reply_cert_file(const char *str, CertResult * const result);
static void callback_reply_key_file(const char *str, CertResult * const result);
static void callback_reply_end(const char *str, CertResult * const result);

static ExtcertCallBack extcert_callbacks[] = {
    { EXTCERT_REPLY_ACTION, callback_reply_action },
    { EXTCERT_REPLY_CERT_FILE, callback_reply_cert_file },
    { EXTCERT_REPLY_KEY_FILE, callback_reply_key_file },
    { EXTCERT_REPLY_END, callback_reply_end },
    { NULL, callback_reply_end }
};

#endif

#endif
