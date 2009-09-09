#ifndef __LOG_PGSQL_P_H__
#define __LOG_PGSQL_P_H__ 1

#include <libpq-fe.h>

static char *server;
static char *port_s;
static int port;
static char *user;
static char *pw;
static char *db;
static char *crypto;
static char *sqlreq_getpw;
static char *sqlreq_getuid;
static char *sqlreq_getgid;
static char *sqlreq_getdir;
static char *sql_default_uid;
static char *sql_default_gid;
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

static ConfigKeywords pgsql_config_keywords[] = {
    { "PGSQLServer", &server },
    { "PGSQLPort", &port_s },
    { "PGSQLUser", &user },
    { "PGSQLPassword", &pw },
    { "PGSQLDatabase", &db },    
    { "PGSQLCrypt", &crypto },
    { "PGSQLGetPW", &sqlreq_getpw },
    { "PGSQLGetUID", &sqlreq_getuid },
    { "PGSQLDefaultUID", &sql_default_uid },
    { "PGSQLGetGID", &sqlreq_getgid },
    { "PGSQLDefaultGID", &sql_default_gid },
    { "PGSQLGetDir", &sqlreq_getdir },
#ifdef QUOTAS
    { "PGSQLGetQTAFS", &sqlreq_getqta_fs },    
    { "PGSQLGetQTASZ", &sqlreq_getqta_sz },
#endif
#ifdef RATIOS
    { "PGSQLGetRatioUL", &sqlreq_getratio_ul },
    { "PGSQLGetRatioDL", &sqlreq_getratio_dl },
#endif
#ifdef THROTTLING
    { "PGSQLGetBandwidthUL", &sqlreq_getbandwidth_ul },
    { "PGSQLGetBandwidthDL", &sqlreq_getbandwidth_dl },
#endif
    { NULL, NULL }
};

#endif
