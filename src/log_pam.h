#ifndef __LOG_PAM_H__
#define __LOG_PAM_H__ 1

void pw_pam_check(AuthResult * const result,
                  const char *account, const char *password,
                  const struct sockaddr_storage * const sa,
                  const struct sockaddr_storage * const peer);

#define pw_pam_parse NULL
#define pw_pam_exit NULL

#endif
