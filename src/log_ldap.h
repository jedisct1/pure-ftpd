#ifndef __LOG_LDAP_H__
#define __LOG_LDAP_H__ 1

#define LDAP_POSIXACCOUNT "posixAccount"
#define LDAP_UID "uid"
#define LDAP_UIDNUMBER "uidNumber"
#define LDAP_GIDNUMBER "gidNumber"
#define LDAP_HOMEDIRECTORY "homeDirectory"
#define LDAP_USERPASSWORD "userPassword"
#define LDAP_LOGINSHELL "loginShell"
#define LDAP_FTPUID "FTPuid"
#define LDAP_FTPGID "FTPgid"

#define LDAP_FTPSTATUS "FTPStatus"

#ifdef QUOTAS
# define LDAP_QUOTAFILES "FTPQuotaFiles"
# define LDAP_QUOTAMBYTES "FTPQuotaMBytes"
#endif

#ifdef RATIOS
# define LDAP_DOWNLOADRATIO "FTPDownloadRatio"
# define LDAP_UPLOADRATIO "FTPUploadRatio"
#endif

#ifdef THROTTLING
# define LDAP_DOWNLOADBANDWIDTH "FTPDownloadBandwidth"
# define LDAP_UPLOADBANDWIDTH "FTPUploadBandwidth"
#endif

#define MAX_LDAP_UID_LENGTH 256U
#define DEFAULT_SHELL "ftp"
#define PASSWD_LDAP_CRYPT_PREFIX "{crypt}"
#define PASSWD_LDAP_MD5_PREFIX "{md5}"
#define PASSWD_LDAP_SMD5_PREFIX "{smd5}"
#define PASSWD_LDAP_SHA_PREFIX "{sha}"
#define PASSWD_LDAP_SSHA_PREFIX "{ssha}"
#define LDAP_DEFAULT_SERVER "localhost"
#define LDAP_DEFAULT_PORT 389
#define LDAP_DEFAULT_FILTER "(&(objectClass=posixAccount)(uid=\\L))"
#define LDAP_DEFAULT_VERSION 3

void pw_ldap_parse(const char * const file);

void pw_ldap_check(AuthResult * const result,
                   const char *account, const char *password,
                   const struct sockaddr_storage * const sa,
                   const struct sockaddr_storage * const peer);

void pw_ldap_exit(void);

#endif
