#ifndef __PURE_PW_H__
#define __PURE_PW_H__ 1

#ifndef DEFAULT_PW_FILE
# define DEFAULT_PW_FILE CONFDIR "/pureftpd.passwd"
#endif

#ifndef ENV_DEFAULT_PW_FILE
# define ENV_DEFAULT_PW_FILE "PURE_PASSWDFILE"
#endif

#ifndef DEFAULT_PW_DB
# define DEFAULT_PW_DB CONFDIR "/pureftpd.pdb"
#endif

#ifndef ENV_DEFAULT_PW_DB
# define ENV_DEFAULT_PW_DB "PURE_DBFILE"
#endif

#ifndef NEWPASSWD_SUFFIX
# define NEWPASSWD_SUFFIX ".tmp"
#endif

#ifndef NEWPASSWD_INDEX_SUFFIX
# define NEWPASSWD_INDEX_SUFFIX ".index"
#endif

#ifndef NEWPASSWD_DATA_SUFFIX
# define NEWPASSWD_DATA_SUFFIX ".data"
#endif

#ifndef LINE_MAX
# define LINE_MAX 4096
#endif

#ifndef PW_LINE_SEP
# define PW_LINE_SEP ":"
#endif

#ifndef PW_LINE_COMMENT
# define PW_LINE_COMMENT '#'
#endif

#ifndef MAX_PASSWD_CHANGE_TRIES
# define MAX_PASSWD_CHANGE_TRIES 3
#endif

#define PW_ERROR_MISSING_LOGIN (1 << 0)
#define PW_ERROR_MISSING_PASSWD_FILE (1 << 1)
#define PW_ERROR_USER_ALREADY_EXIST (1 << 2)
#define PW_ERROR_ENTER_PASSWD_PW_ERROR (1 << 3)
#define PW_ERROR_UNABLE_TO_FETCH (1 << 4)
#define PW_ERROR_USERADD_NOT_ROOT (1 << 5)
#define PW_ERROR_USERADD_MISSING_HOME_DIR (1 << 6)
#define PW_ERROR_MKDB_UNABLE_TO_OPEN_PASSWD (1 << 7)
#define PW_ERROR_UNEXPECTED_ERROR 0xff

typedef struct PWInfo_ {
    char *login;
    char *pwd;
    uid_t uid;
    gid_t gid;
    char *home;
    char *gecos;
    unsigned long bw_dl;
    unsigned long bw_ul;
    int has_bw_dl;
    int has_bw_ul;
    unsigned long long quota_files;
    unsigned long long quota_size;
    int has_quota_files;
    int has_quota_size;
    unsigned int ul_ratio;
    unsigned int dl_ratio;
    int has_ul_ratio;
    int has_dl_ratio;
    char *allow_local_ip;
    char *deny_local_ip;    
    char *allow_client_ip;
    char *deny_client_ip;
    unsigned int time_begin;
    unsigned int time_end;
    int has_time;
    int has_per_user_max;
    unsigned int per_user_max;
} PWInfo;

char *newpasswd_filename(const char * const file);

#ifndef SHOW_STATE
# define SHOW_STATE(X) (((X) != 0) ? "enabled" : "unlimited")
#endif

#ifndef SHOW_IFEN
# define SHOW_IFEN(X, Y) (((X) != 0) ? (Y) : 0)
#endif
#ifndef SHOW_IFEN_S
# define SHOW_IFEN_S(X, Y) (((X) != 0) ? (Y) : "0")
#endif

#ifndef SHOW_STRING
# define SHOW_STRING(X) (((X) != NULL) ? (X) : "-")
#endif

#endif
