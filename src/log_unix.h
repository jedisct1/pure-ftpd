#ifndef __LOG_UNIX_H__
#define __LOG_UNIX_H__ 1

void pw_unix_check(AuthResult * const result,
                   const char *account, const char *password,
                   const struct sockaddr_storage * const sa,
                   const struct sockaddr_storage * const peer);

#define pw_unix_parse NULL
#define pw_unix_exit NULL

#endif
