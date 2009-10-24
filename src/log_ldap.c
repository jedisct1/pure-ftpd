
/* LDAP posixAccount handler for Pure-FTPd */

#include <config.h>

#ifdef WITH_LDAP
# include "ftpd.h"
# include "parser.h"
# include "log_ldap_p.h"
# include "log_ldap.h"
# include "messages.h"
# include "crypto.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

void pw_ldap_parse(const char * const file)
{
    if (generic_parser(file, ldap_config_keywords) != 0) {
        illegal_config:
        die(421, LOG_ERR, MSG_CONF_ERR ": " MSG_ILLEGAL_CONFIG_FILE_LDAP 
            ": %s" , file == NULL ? "-" : file);
    }
    if (ldap_host == NULL) {
        if ((ldap_host = strdup(LDAP_DEFAULT_SERVER)) == NULL) {
            die_mem();
        }
    }
    if (port_s == NULL) {
        port = LDAP_DEFAULT_PORT;
    } else {
        port = atoi(port_s);
        if (port <= 0 || port > 65535) {
            port = LDAP_DEFAULT_PORT;
        }
        free(port_s);
        port_s = NULL;
    }
    if (ldap_filter == NULL) {
        if ((ldap_filter = strdup(LDAP_DEFAULT_FILTER)) == NULL) {
            die_mem();
        }
    }
    {
        char *t;
        
        if (strchr(ldap_filter, '%') != NULL) {
            goto illegal_config;
        }
        if ((t = strchr(ldap_filter, '\\')) != NULL) {
            if (t[1] != 'L') {
                goto illegal_config;
            }
            *t++ = '%';
            *t = 's';        
        }
    }
    if (ldap_homedirectory == NULL) {
        if ((ldap_homedirectory = strdup(LDAP_HOMEDIRECTORY)) == NULL) {
            die_mem();
        }
    }
    if (ldap_version_s != NULL) {
        ldap_version = atoi(ldap_version_s);
        free(ldap_version_s);
        ldap_version_s = NULL;
    } else {
        ldap_version = LDAP_DEFAULT_VERSION;
    }
    if (default_uid_s != NULL) {
        default_uid = (uid_t) strtoul(default_uid_s, NULL, 10);        
        free(default_uid_s);
        default_uid_s = NULL;        
    }
    if (default_gid_s != NULL) {
        default_gid = (gid_t) strtoul(default_gid_s, NULL, 10);
        free(default_gid_s);
        default_gid_s = NULL;
    }
    use_tls = 0;
    if (use_tls_s != NULL) {
        if (strcasecmp(use_tls_s, "True") == 0) {
            use_tls = 1;
        }
        free(use_tls_s);
        use_tls_s = NULL;
    }

    /* Default to auth method bind, but for backward compatibility, if a binddn 
     * is supplied, default to password checking. */
    if (binddn == NULL) {
        use_ldap_bind_method = 1;
    } else {
        use_ldap_bind_method = 0;
    }

    if (ldap_auth_method_s != NULL) {
        if (strcasecmp(ldap_auth_method_s, "bind") == 0) {
            use_ldap_bind_method = 1;
        } else if (strcasecmp(ldap_auth_method_s, "password") == 0) {
            use_ldap_bind_method = 0;
        } else {
            die(421, LOG_ERR, MSG_LDAP_INVALID_AUTH_METHOD);
        }
        free(ldap_auth_method_s);
        ldap_auth_method_s = NULL;
    }
    if (base == NULL) {
        die(421, LOG_ERR, MSG_LDAP_MISSING_BASE);
    }
    if (binddn == NULL) {
        pwd = NULL;
    }    
}

void pw_ldap_exit(void)
{
    free((void *) ldap_host);
    ldap_host = NULL;
    free((void *) port_s);
    port_s = NULL;
    port = -1;
    free((void *) binddn);
    binddn = NULL;
    free((void *) pwd);
    pwd = NULL;
    free((void *) base);
    base = NULL;
    free((void *) ldap_filter);
    free((void *) ldap_homedirectory);
    free((void *) default_uid_s);
    default_uid_s = NULL;
    free((void *) default_gid_s);
    default_gid_s = NULL;
    free((void *) use_tls_s);
    use_tls_s = NULL;
    free((void *) ldap_auth_method_s);
    ldap_auth_method_s = NULL;
}

static LDAP *pw_ldap_connect(const char *dn, const char *password)
{
    LDAP *ld;
# ifdef LDAP_OPT_PROTOCOL_VERSION    
    int version = ldap_version;
# endif
    
    if (ldap_host == NULL || port < 0) {
        return NULL;
    }
    if ((ld = ldap_init(ldap_host, port)) == NULL) {
        return NULL;
    }
# ifdef LDAP_OPT_PROTOCOL_VERSION
    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version) !=
        LDAP_SUCCESS) {
        return NULL;
    }
# endif
    if (use_tls > 0 && ldap_start_tls_s(ld, NULL, NULL) != LDAP_SUCCESS) {
        return NULL;
    }
    if (ldap_bind_s(ld, dn, password, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
        return NULL;
    }

    return ld;
}

static LDAPMessage *pw_ldap_uid_search(LDAP * const ld, 
                                       const char *uid,
                                       char *attrs[])
{
    char *alloca_filter;
    size_t uid_size;
    size_t filter_size;
    int rc;    
    LDAPMessage *res;
    
    if (uid == NULL || *uid == 0) {
        return NULL;
    }
    uid_size = strlen(uid);
    if (uid_size > MAX_LDAP_UID_LENGTH) {
        return NULL;
    }
    filter_size = strlen(ldap_filter) + uid_size + (size_t) 1U;
    if ((alloca_filter = ALLOCA(filter_size)) == NULL) {
        return NULL;
    }
    if (SNCHECK(snprintf(alloca_filter, filter_size, ldap_filter, uid),
        filter_size)) {    
        ALLOCA_FREE(alloca_filter);
        return NULL;
    }
    rc = ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, 
                       alloca_filter, attrs, 0, &res);
    ALLOCA_FREE(alloca_filter);
    if (rc != LDAP_SUCCESS) {
        return NULL;
    }

    return res;
}

static char *pw_ldap_getvalue(LDAP * const ld,
                              LDAPMessage * const res,
                              const char * const attribute)
{
    char **vals;
    char *ret;
    
    if ((vals = ldap_get_values(ld, res, attribute)) == NULL ||
        vals[0] == NULL) {
        return NULL;
    }    
    ret = strdup(vals[0]);
    ldap_value_free(vals);
    
    return ret;
}

static void pw_ldap_getpwnam_freefields(struct passwd * const p) 
{
    free(p->pw_passwd);
    p->pw_passwd = NULL;
    free(p->pw_dir);
    p->pw_dir = NULL;
    free(p->pw_shell);
    p->pw_shell = NULL;
}

static int pw_ldap_validate_name(const char *name)
{
    if (name == NULL || *name == 0) {
        return -1;
    }
    do {
        if ((*name >= 'a' && *name <= 'z') ||
            (*name >= 'A' && *name <= 'Z') ||
            (*name >= '0' && *name <= '9') ||
            *name == ' ' || *name == '-' || *name == '@' ||
            *name == '_' || *name == '\'' || *name == '.') {
            /* God bless the Perl 'unless' keyword */
        } else {
            return -1;
        }            
        name++;
    } while (*name != 0);
    
    return 0;
}

static struct passwd *pw_ldap_getpwnam(const char *name,
                                       AuthResult * const result)
{
    static struct passwd pwret;
    LDAP *ld;
    LDAPMessage *res;
    char *attrs[] = {                  /* OpenLDAP forgot a 'const' ... */
            LDAP_HOMEDIRECTORY,
            LDAP_UIDNUMBER, LDAP_FTPUID, LDAP_GIDNUMBER, LDAP_FTPGID,
            LDAP_USERPASSWORD, LDAP_LOGINSHELL, LDAP_FTPSTATUS,
# ifdef QUOTAS
            LDAP_QUOTAFILES, LDAP_QUOTAMBYTES,
# endif
# ifdef RATIOS
            LDAP_DOWNLOADRATIO, LDAP_UPLOADRATIO,
# endif
#ifdef THROTTLING
            LDAP_DOWNLOADBANDWIDTH, LDAP_UPLOADBANDWIDTH, 
#endif
            NULL
    };
    const char *pw_uid_s = NULL;
    const char *pw_gid_s = NULL;
    const char *pw_passwd_ldap = NULL;
    const char *pw_enabled = NULL;
#ifdef QUOTAS
    const char *quota_files = NULL;
    const char *quota_mbytes = NULL;
#endif
#ifdef RATIOS
    const char *ratio_ul = NULL;
    const char *ratio_dl = NULL;
#endif
#ifdef THROTTLING
    const char *bandwidth_ul = NULL;
    const char *bandwidth_dl = NULL;
#endif
    
    memset(&pwret, 0, sizeof pwret);
    pwret.pw_name = pwret.pw_passwd = pwret.pw_gecos = pwret.pw_dir =
        pwret.pw_shell = NULL;
    pwret.pw_uid = (uid_t) 0;
    pwret.pw_gid = (gid_t) 0;
    if (pw_ldap_validate_name(name) != 0) {
        return NULL;
    }
    if ((ld = pw_ldap_connect(binddn, pwd)) == NULL) {
        return NULL;
    }
    attrs[0] = ldap_homedirectory;
    if ((res = pw_ldap_uid_search(ld, name, attrs)) == NULL) {
        goto error;
    }
    pw_ldap_getpwnam_freefields(&pwret);
    pwret.pw_name = (char *) name;
    pw_enabled = pw_ldap_getvalue(ld, res, LDAP_FTPSTATUS);
    if (pw_enabled != NULL && strcasecmp(pw_enabled, "enabled") != 0 &&
        strcasecmp(pw_enabled, "TRUE") != 0) {
        goto error;
    }

#ifdef QUOTAS
    if ((quota_files = pw_ldap_getvalue(ld, res, LDAP_QUOTAFILES)) != NULL) {
        const unsigned long long q = strtoull(quota_files, NULL, 10);
        
        if (q > 0ULL) {
            result->user_quota_files = q;
            result->quota_files_changed = 1;
        }
    }
    if ((quota_mbytes = pw_ldap_getvalue(ld, res, LDAP_QUOTAMBYTES)) 
        != NULL) {
        const unsigned long long q = strtoull(quota_mbytes, NULL, 10);
        
        if (q > 0ULL) {
            result->user_quota_size = q * (1024UL * 1024UL);
            result->quota_size_changed = 1;
        }
    }
#endif    
#ifdef RATIOS
    if ((ratio_dl = pw_ldap_getvalue(ld, res, LDAP_DOWNLOADRATIO)) != NULL) {
        const unsigned int q = strtoul(ratio_dl, NULL, 10);
        
        if (q > 0U) {
            result->ratio_download = q;
            result->ratio_dl_changed = 1;
        }
    }
    if ((ratio_ul = pw_ldap_getvalue(ld, res, LDAP_UPLOADRATIO)) != NULL) { 
        const unsigned int q = strtoul(ratio_ul, NULL, 10);
        
        if (q > 0U) {
            result->ratio_upload = q;
            result->ratio_ul_changed = 1;
        }
    }
#endif
#ifdef THROTTLING
    if ((bandwidth_dl = pw_ldap_getvalue(ld, res, LDAP_DOWNLOADBANDWIDTH)) 
    != NULL) {
        const unsigned long q = (unsigned long) strtoul(bandwidth_dl, NULL, 10);
        
        if (q > 0UL) {
            result->throttling_bandwidth_dl = q * 1024UL;
            result->throttling_dl_changed = 1;
        }
    }
    if ((bandwidth_ul = pw_ldap_getvalue(ld, res, LDAP_UPLOADBANDWIDTH)) 
        != NULL) {
        const unsigned long q = (unsigned long) strtoul(bandwidth_ul, NULL, 10);
        
        if (q > 0UL) {
            result->throttling_bandwidth_ul = q * 1024UL;
            result->throttling_ul_changed = 1;
        }
    }
#endif
    
    if (use_ldap_bind_method == 0) {
        if ((pw_passwd_ldap =
             pw_ldap_getvalue(ld, res, LDAP_USERPASSWORD)) == NULL) {
            
            /* The LDAP userPassword is empty, this happens when binding to
             LDAP without sufficient privileges. */
            logfile(LOG_WARNING, MSG_WARN_LDAP_USERPASS_EMPTY);
            goto error;
        }        
        pwret.pw_passwd = strdup(pw_passwd_ldap);
        free((void *) pw_passwd_ldap);
        pw_passwd_ldap = NULL;
    } else {
        pwret.pw_passwd = strdup("");
    }
    if (pwret.pw_passwd == NULL) {
        logfile(LOG_ERR, MSG_OUT_OF_MEMORY);
        goto error;
    }
    if ((pw_uid_s = pw_ldap_getvalue(ld, res, LDAP_FTPUID)) == NULL ||
        *pw_uid_s == 0 || 
        (pwret.pw_uid = (uid_t) strtoul(pw_uid_s, NULL, 10)) <= (uid_t) 0) {
        free((void *) pw_uid_s);
        pw_uid_s = NULL;
        if ((pw_uid_s = pw_ldap_getvalue(ld, res, LDAP_UIDNUMBER)) == NULL ||
            *pw_uid_s == 0 || 
            (pwret.pw_uid = (uid_t) strtoul(pw_uid_s, NULL, 10)) <= (uid_t) 0) {
            pwret.pw_uid = default_uid;
        }                 
    }     
    free((void *) pw_uid_s);
    pw_uid_s = NULL;
    if ((pw_gid_s = pw_ldap_getvalue(ld, res, LDAP_FTPGID)) == NULL ||
        *pw_gid_s == 0 ||
        (pwret.pw_gid = (gid_t) strtoul(pw_gid_s, NULL, 10)) <= (gid_t) 0) {
        free((void *) pw_gid_s);
        pw_gid_s = NULL;
        if ((pw_gid_s = pw_ldap_getvalue(ld, res, LDAP_GIDNUMBER)) == NULL ||
            *pw_gid_s == 0 ||
            (pwret.pw_gid = (gid_t) strtoul(pw_gid_s, NULL, 10)) <= (gid_t) 0) {
            pwret.pw_gid = default_gid;
        }                        
    } 
    free((void *) pw_gid_s);
    pw_gid_s = NULL;
    if ((pwret.pw_dir = 
         pw_ldap_getvalue(ld, res, ldap_homedirectory)) == NULL ||
        *pwret.pw_dir == 0) {
        goto error;
    }    
    if ((pwret.pw_shell = 
         pw_ldap_getvalue(ld, res, LDAP_LOGINSHELL)) == NULL) {
        pwret.pw_shell = strdup(DEFAULT_SHELL);
    }
    result->backend_data = ldap_get_dn(ld, res);

    ldap_msgfree(res);
    ldap_unbind(ld);
    
    return &pwret;
    
    error:    
    if (res != NULL) {
        ldap_msgfree(res);
    }
    ldap_unbind(ld);
    pw_ldap_getpwnam_freefields(&pwret);
    free((void *) pw_uid_s);
    free((void *) pw_gid_s);
    free((void *) pw_passwd_ldap);
    free((void *) pw_enabled);
#ifdef QUOTAS
    free((void *) quota_files);
    free((void *) quota_mbytes);
#endif
#ifdef RATIOS
    free((void *) ratio_ul);
    free((void *) ratio_dl);
#endif
#ifdef THROTTLING
    free((void *) bandwidth_ul);
    free((void *) bandwidth_dl);
#endif
    return NULL;
}

void pw_ldap_check(AuthResult * const result,
                   const char *account, const char *password,
                   const struct sockaddr_storage * const sa,
                   const struct sockaddr_storage * const peer)
{
    struct passwd *pw;
    const char *spwd;                  /* Stored pwd */
    const char *cpwd = NULL;           /* Computed pwd */
    signed char nocase = 0;            /* Insensitive strcmp */
    
    (void) sa;
    (void) peer;
    result->auth_ok = 0;
    if (account == NULL || *account == 0 || password == NULL ||
        (pw = pw_ldap_getpwnam(account, result)) == NULL) {
        return;
    }

    result->auth_ok--;                  /* -1 */

    if (use_ldap_bind_method == 1 && result->backend_data != NULL) {
        LDAP *ld;
        char *dn = (char *) result->backend_data;
        
        /* Verify password by binding to LDAP */
        if (password == NULL || *password == 0) {
            free(result->backend_data);            
            return;
        }
        if ((ld = pw_ldap_connect(dn, password)) != NULL) {
             ldap_unbind(ld);
        } else {
            free(result->backend_data);
            return;
        }
    } else {
        if (result->backend_data != NULL) {
            free(result->backend_data);
        }        
        spwd = pw->pw_passwd;
        if (strncasecmp(spwd, PASSWD_LDAP_MD5_PREFIX,
                        sizeof PASSWD_LDAP_MD5_PREFIX - 1U) == 0) {
            spwd += (sizeof PASSWD_LDAP_MD5_PREFIX - 1U);
            
            if (strlen(spwd) >= 32U) {
                nocase++;
            }
            cpwd = crypto_hash_md5(password, nocase);
        } else if (strncasecmp(spwd, PASSWD_LDAP_SHA_PREFIX,
                               sizeof PASSWD_LDAP_SHA_PREFIX - 1U) == 0) {
            spwd += (sizeof PASSWD_LDAP_SHA_PREFIX - 1U);
            if (strlen(spwd) >= 40U) {
                nocase++;
            }
            cpwd = crypto_hash_sha1(password, nocase);
        } else if (strncasecmp(spwd, PASSWD_LDAP_SSHA_PREFIX,
                               sizeof PASSWD_LDAP_SSHA_PREFIX - 1U) == 0) {
            spwd += (sizeof PASSWD_LDAP_SSHA_PREFIX - 1U);
            cpwd = crypto_hash_ssha1(password, spwd);
        } else if (strncasecmp(spwd, PASSWD_LDAP_SMD5_PREFIX,
                               sizeof PASSWD_LDAP_SMD5_PREFIX - 1U) == 0) {
            spwd += (sizeof PASSWD_LDAP_SMD5_PREFIX - 1U);
            cpwd = crypto_hash_smd5(password, spwd);
        } else if (strncasecmp(spwd, PASSWD_LDAP_CRYPT_PREFIX,
                               sizeof PASSWD_LDAP_CRYPT_PREFIX - 1U) == 0) {
            spwd += (sizeof PASSWD_LDAP_CRYPT_PREFIX - 1U);
            cpwd = (const char *) crypt(password, spwd);
        } else if (*password != 0) {
            cpwd = password;               /* Cleartext */        
        } else {
            return;                      /* Refuse null passwords */
        }
        if (cpwd == NULL) {
            return;
        }
        if (nocase != 0) {        
            if (strcasecmp(cpwd, spwd) != 0) {
                return;
            }
        }    
        if (strcmp(cpwd, spwd) != 0) {
            return;
        }
    }
    result->uid = pw->pw_uid;
    result->gid = pw->pw_gid;
    if (result->uid <= (uid_t) 0 || result->gid <= (gid_t) 0) {
        return;
    }
    if ((result->dir = strdup(pw->pw_dir)) == NULL) {
        return;
    }
    result->slow_tilde_expansion = 1;
    result->auth_ok = 1;            /* User found, authentication ok */
}
#else
extern signed char v6ready;
#endif
