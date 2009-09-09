#ifndef __LOG_EXTAUTH_H__
#define __LOG_EXTAUTH_H__ 1

#ifdef WITH_EXTAUTH

void pw_extauth_parse(const char * const file);

void pw_extauth_check(AuthResult * const result,
                      const char *account, const char *password,
                      const struct sockaddr_storage * const sa,
                      const struct sockaddr_storage * const peer);

void pw_extauth_exit(void);

#define EXTAUTH_KEYWORD_SEP ":"

#define EXTAUTH_CLIENT_ACCOUNT "account" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_CLIENT_PASSWORD "password" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_CLIENT_SA_HOST "localhost" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_CLIENT_SA_PORT "localport" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_CLIENT_PEER_HOST "peer" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_CLIENT_ENCRYPTED "encrypted" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_CLIENT_END "end"

#define EXTAUTH_REPLY_AUTH_OK "auth_ok" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_UID "uid" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_GID "gid" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_DIR "dir" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_SLOW_TILDE_EXPANSION "slow_tilde_expansion" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_THROTTLING_BANDWIDTH_UL "throttling_bandwidth_ul" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_THROTTLING_BANDWIDTH_DL "throttling_bandwidth_dl" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_USER_QUOTA_SIZE "user_quota_size" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_USER_QUOTA_FILES "user_quota_files" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_RATIO_UPLOAD "ratio_upload" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_RATIO_DOWNLOAD "ratio_download" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_PER_USER_MAX "per_user_max" EXTAUTH_KEYWORD_SEP
#define EXTAUTH_REPLY_END "end"

#endif

#endif
