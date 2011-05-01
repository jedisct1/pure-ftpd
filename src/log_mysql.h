#ifndef __LOG_MYSQL_H__
#define __LOG_MYSQL_H__ 1

#define PASSWD_SQL_CRYPT "crypt"
#define PASSWD_SQL_CLEARTEXT "cleartext"
#define PASSWD_SQL_MYSQL "password"
#define PASSWD_SQL_MD5 "md5"
#define PASSWD_SQL_SHA1 "sha1"
#define PASSWD_SQL_ANY "any"
#define MYSQL_DEFAULT_SERVER "localhost"
#define MYSQL_DEFAULT_PORT 3306
#define MYSQL_MAX_REQUEST_LENGTH ((size_t) 8192U)
#define MYSQL_TRANSACTION_START "set autocommit=0"
#define MYSQL_TRANSACTION_END "COMMIT"

#define MYSQL_CRYPT_LEN 17U

void pw_mysql_parse(const char * const file);

void pw_mysql_check(AuthResult * const result,
                    const char *account, const char *password,
                    const struct sockaddr_storage * const sa,
                    const struct sockaddr_storage * const peer);

void pw_mysql_exit(void);

#endif
