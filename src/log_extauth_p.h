#ifndef __LOG_EXTAUTH_P_H__
#define __LOG_EXTAUTH_P_H__ 1

#ifdef WITH_EXTAUTH

#include <sys/un.h>

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) NULL)->sun_path) \
                           + strlen((ptr)->sun_path))
#endif

#ifndef EXTAUTH_MAX_CONNECT_TRIES
# define EXTAUTH_MAX_CONNECT_TRIES 10
#endif
#ifndef EXTAUTH_MAX_CONNECT_DELAY
# define EXTAUTH_MAX_CONNECT_DELAY 1
#endif

typedef struct ExtauthCallBack_ {
    const char *keyword;
    void (*func)(const char *str, AuthResult * const result);
} ExtauthCallBack;

static void callback_reply_auth_ok(const char *str, AuthResult * const result);
static void callback_reply_uid(const char *str, AuthResult * const result);
static void callback_reply_gid(const char *str, AuthResult * const result);
static void callback_reply_dir(const char *str, AuthResult * const result);
static void callback_reply_slow_tilde_expansion(const char *str, AuthResult * const result);
static void callback_reply_throttling_bandwidth_ul(const char *str, AuthResult * const result);
static void callback_reply_throttling_bandwidth_dl(const char *str, AuthResult * const result);
static void callback_reply_user_quota_size(const char *str, AuthResult * const result);
static void callback_reply_user_quota_files(const char *str, AuthResult * const result);
static void callback_reply_ratio_upload(const char *str, AuthResult * const result);
static void callback_reply_ratio_download(const char *str, AuthResult * const result);
static void callback_reply_per_user_max(const char *str, AuthResult * const result);
static void callback_reply_end(const char *str, AuthResult * const result);

static ExtauthCallBack extauth_callbacks[] = {
    { EXTAUTH_REPLY_AUTH_OK, callback_reply_auth_ok },
    { EXTAUTH_REPLY_UID, callback_reply_uid },
    { EXTAUTH_REPLY_GID, callback_reply_gid },
    { EXTAUTH_REPLY_DIR, callback_reply_dir },
    { EXTAUTH_REPLY_SLOW_TILDE_EXPANSION, callback_reply_slow_tilde_expansion },
    { EXTAUTH_REPLY_THROTTLING_BANDWIDTH_UL, callback_reply_throttling_bandwidth_ul },
    { EXTAUTH_REPLY_THROTTLING_BANDWIDTH_DL, callback_reply_throttling_bandwidth_dl },
    { EXTAUTH_REPLY_USER_QUOTA_SIZE, callback_reply_user_quota_size },
    { EXTAUTH_REPLY_USER_QUOTA_FILES, callback_reply_user_quota_files },
    { EXTAUTH_REPLY_RATIO_UPLOAD, callback_reply_ratio_upload },
    { EXTAUTH_REPLY_RATIO_DOWNLOAD, callback_reply_ratio_download },
    { EXTAUTH_REPLY_PER_USER_MAX, callback_reply_per_user_max },    
    { EXTAUTH_REPLY_END, callback_reply_end },
    { NULL, callback_reply_end }
};

#endif

#endif
