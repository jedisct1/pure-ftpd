
/* LDAP posixAccount handler for Pure-FTPd */
/* (C)opyleft 2001-2021 by Frank DENIS <j at pureftpd dot org> */

#ifndef __LOG_LDAP_P_H__
#define __LOG_LDAP_P_H__ 1

#define LDAP_DEPRECATED 1
#include <lber.h>
#include <ldap.h>

static char *ldap_uri;
static char *ldap_scheme;
static char *ldap_host;
static char *port_s;
static int port;
static char *binddn;
static char *pwd;
static char *base;
static char *ldap_filter;
static char *ldap_homedirectory;
static char *ldap_version_s;
static int ldap_version;
static char *default_uid_s;
static char *force_default_uid_s;
static int force_default_uid = 0;
static uid_t default_uid = 0;
static char *default_gid_s;
static char *force_default_gid_s;
static int force_default_gid = 0;
static gid_t default_gid = 0;
static char *use_tls_s;
static int use_tls;
static char *ldap_auth_method_s;
static int use_ldap_bind_method;
static char *ldap_default_home_directory;

static ConfigKeywords ldap_config_keywords[] = {
    { "LDAPScheme", &ldap_scheme },
    { "LDAPServer", &ldap_host },
    { "LDAPPort", &port_s },
    { "LDAPBindDN", &binddn },
    { "LDAPBindPW", &pwd },
    { "LDAPBaseDN", &base },
    { "LDAPFilter", &ldap_filter},
    { "LDAPHomeDir", &ldap_homedirectory },
    { "LDAPVersion", &ldap_version_s },
    { "LDAPDefaultUID", &default_uid_s },
    { "LDAPForceDefaultUID", &force_default_uid_s },
    { "LDAPDefaultGID", &default_gid_s },
    { "LDAPForceDefaultGID", &force_default_gid_s },
    { "LDAPUseTLS", &use_tls_s },
    { "LDAPAuthMethod", &ldap_auth_method_s },
    { "LDAPDefaultHomeDirectory", &ldap_default_home_directory },
    { NULL, NULL }
};

#endif
