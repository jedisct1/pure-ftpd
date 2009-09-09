#ifndef __LOG_MYSQL_P_H__
#define __LOG_MYSQL_P_H__ 1

#include <mysql.h>

#ifdef MYSQL_VERSION_ID
# if MYSQL_VERSION_ID < 32224
#  define mysql_field_count(X) mysql_num_fields(X)
# endif
#endif

static char *server;
static char *port_s;
static int port;
static char *socket_path;
static char *user;
static char *pw;
static char *db;
static char *crypto;
static char *transactions;
static char *sqlreq_getpw;
static char *sqlreq_getuid;
static char *sql_default_uid;
static char *sqlreq_getgid;
static char *sql_default_gid;
static char *sqlreq_getdir;
static char *tildexp_s;
static int tildexp;
#ifdef QUOTAS
static char *sqlreq_getqta_sz;
static char *sqlreq_getqta_fs;
#endif
#ifdef RATIOS
static char *sqlreq_getratio_ul;
static char *sqlreq_getratio_dl;
#endif
#ifdef THROTTLING
static char *sqlreq_getbandwidth_ul;
static char *sqlreq_getbandwidth_dl;
#endif
static signed char server_down;

static ConfigKeywords mysql_config_keywords[] = {
    { "MYSQLServer", &server },
    { "MYSQLPort", &port_s },
    { "MYSQLSocket", &socket_path },
    { "MYSQLUser", &user },
    { "MYSQLPassword", &pw },
    { "MYSQLDatabase", &db },    
    { "MYSQLCrypt", &crypto },
    { "MYSQLTransactions", &transactions },    
    { "MYSQLGetPW", &sqlreq_getpw },
    { "MYSQLGetUID", &sqlreq_getuid },    
    { "MYSQLDefaultUID", &sql_default_uid },
    { "MYSQLGetGID", &sqlreq_getgid },
    { "MYSQLDefaultGID", &sql_default_gid },
    { "MYSQLGetDir", &sqlreq_getdir },
    { "MYSQLForceTildeExpansion", &tildexp_s },
#ifdef QUOTAS
    { "MYSQLGetQTAFS", &sqlreq_getqta_fs },    
    { "MYSQLGetQTASZ", &sqlreq_getqta_sz },
#endif
#ifdef RATIOS
    { "MYSQLGetRatioUL", &sqlreq_getratio_ul },
    { "MYSQLGetRatioDL", &sqlreq_getratio_dl },
#endif
#ifdef THROTTLING
    { "MYSQLGetBandwidthUL", &sqlreq_getbandwidth_ul },
    { "MYSQLGetBandwidthDL", &sqlreq_getbandwidth_dl },
#endif
    { NULL, NULL }
};

#endif
