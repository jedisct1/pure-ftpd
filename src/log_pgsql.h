#ifndef __LOG_PGSQL_H__
#define __LOG_PGSQL_H__ 1

#define PASSWD_SQL_CRYPT "crypt"
#define PASSWD_SQL_CLEARTEXT "cleartext"
#define PASSWD_SQL_PGSQL "password"
#define PASSWD_SQL_MD5 "md5"
#define PASSWD_SQL_ANY "any"
#define PGSQL_DEFAULT_SERVER "localhost"
#define PGSQL_DEFAULT_PORT 5432
#define PGSQL_MAX_REQUEST_LENGTH ((size_t) 8192U)
#define PGSQL_TRANSACTION_START "BEGIN"
#define PGSQL_TRANSACTION_END "COMMIT"

void pw_pgsql_parse(const char * const file);

void pw_pgsql_check(AuthResult * const result,
                    const char *account, const char *password,
                    const struct sockaddr_storage * const sa,
                    const struct sockaddr_storage * const peer);

void pw_pgsql_exit(void);

#endif
