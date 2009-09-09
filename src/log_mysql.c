#include <config.h>

#ifdef WITH_MYSQL

# include "ftpd.h"
# include "parser.h"
# include "log_mysql_p.h"
# include "log_mysql.h"
# include "messages.h"
# include "crypto.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

static int pw_mysql_validate_name(const char *name)
{
    if (name == NULL || *name == 0) {
        return -1;
    }
    do {
        if ((*name >= 'a' && *name <= 'z') ||
            (*name >= 'A' && *name <= 'Z') ||
            (*name >= '0' && *name <= '9') ||
            *name == ' ' || *name == '-' ||
            *name == '_' || *name == '\'' || *name == '.' ||
            *name == ':' || *name == '@') {
            /* God bless the Perl 'unless' keyword */
        } else {
            return -1;
        }            
        name++;
    } while (*name != 0);
    
    return 0;
}

static char *pw_mysql_escape_string(MYSQL * const id_sql_server,
                                    const char *from)
{
    size_t from_len;
    size_t to_len;
    char *to;
    unsigned long tolen;    
    unsigned int t;
    unsigned char t1, t2;
            
    if (from == NULL) {
        return NULL;
    }
    from_len = strlen(from);
    to_len = from_len * 2U + (size_t) 1U;
    if ((to = malloc(to_len + 2U)) == NULL) {
        return NULL;
    }
    t = zrand();
    t1 = t & 0xff;
    t2 = (t >> 8) & 0xff;
    to[to_len] = (char) t1;
    to[to_len + 1] = (char) t2;
    /*
     * I really hate giving a buffer without any size to a 3rd party function.
     * The "to" buffer is allocated on the heap, not on the stack, if
     * mysql_real_escape_string() is buggy, the stack shouldn't be already
     * smashed at this point, but data from other malloc can be corrupted and
     * bad things can happen. It make sense to wipe this area as soon as
     * possible instead of doing anything with the heap. We'll end up with
     * a segmentation violation, but without any possible exploit.
     */
#ifdef HAVE_MYSQL_REAL_ESCAPE_STRING
    tolen = mysql_real_escape_string(id_sql_server, to, from, from_len);
#else
    /* MySQL 3 is obsolete. */
    tolen = mysql_escape_string(to, from, from_len);    
#endif
    if (tolen >= to_len || 
        (unsigned char) to[to_len] != t1 ||
        (unsigned char) to[to_len + 1] != t2) {
        for (;;) {
            *to++ = 0;
        }
    }
    to[tolen] = 0;
                
    return to;
}

/*
 * Substitute digraphs for SQL requests.
 * orig_str is the original string, full of \L, \I, \P, \R and \D.
 * query is a buffer to handle the result.
 * query_len is the size of the buffer.
 * returns the buffer @ if successful, NULL otherwise.   -frank.
 */

static char *sqlsubst(const char *orig_str, char * const query,
                      size_t query_len, const char * const user,
                      const char * const ip, const char * const port,
                      const char * const peer_ip,
                      const char * const decimal_ip)
{
    char *query_pnt = query;
    const char *orig_str_scan = orig_str;
    const size_t user_len = (user == NULL ? (size_t) 0U : strlen(user));
    const size_t ip_len = (ip == NULL ? (size_t) 0U : strlen(ip));
    const size_t port_len = (port == NULL ? (size_t) 0U : strlen(port));
    const size_t peer_ip_len = (peer_ip == NULL ? (size_t) 0U : strlen(peer_ip));
    const size_t decimal_ip_len = (decimal_ip == NULL ? (size_t) 0U : strlen(decimal_ip));

    while (*orig_str_scan != 0) {
        if (*orig_str_scan == '\\' && orig_str_scan[1] != 0) {
            orig_str_scan++;
            switch(tolower((unsigned char) *orig_str_scan)) {
            case 'l' :
                if (user_len >= query_len) {
                    return NULL;
                }
                if (user_len <= (size_t) 0U) {
                    goto nextone;
                }
                memcpy(query_pnt, user, user_len);
                query_pnt += user_len;
                query_len -= user_len;
                goto nextone;
            case 'i' :
                if (ip_len >= query_len) {
                    return NULL;
                }
                if (ip_len <= (size_t) 0U) {
                    goto nextone;
                }                
                memcpy(query_pnt, ip, ip_len);
                query_pnt += ip_len;
                query_len -= ip_len;
                goto nextone;
            case 'p' :             
                if (port_len >= query_len) {
                    return NULL;
                } 
                if (port_len <= (size_t) 0U) {
                    goto nextone;
                }               
                memcpy(query_pnt, port, port_len);
                query_pnt += port_len;
                query_len -= port_len;
                goto nextone;
            case 'r' :             
                if (peer_ip_len >= query_len) {
                    return NULL;
                } 
                if (peer_ip_len <= (size_t) 0U) {
                    goto nextone;
                }               
                memcpy(query_pnt, peer_ip, peer_ip_len);
                query_pnt += peer_ip_len;
                query_len -= peer_ip_len;
                goto nextone;
            case 'd' :             
                if (decimal_ip_len >= query_len) {
                    return NULL;
                } 
                if (decimal_ip_len <= (size_t) 0U) {
                    goto nextone;
                }               
                memcpy(query_pnt, decimal_ip, decimal_ip_len);
                query_pnt += decimal_ip_len;
                query_len -= decimal_ip_len;
                goto nextone;
            default :
                if (--query_len <= (size_t) 0U) {
                    return NULL;
                }
                *query_pnt++ = '\\';
            }
        }
        if (ISCTRLCODE(*orig_str_scan)) {
            goto nextone;
        }
        if (--query_len <= (size_t) 0U) {
            return NULL;
        }
        *query_pnt++ = *orig_str_scan;
        nextone:
        orig_str_scan++;
    }
    *query_pnt = 0;

    return query;
}

static int pw_mysql_connect(MYSQL ** const id_sql_server)
{
    *id_sql_server = NULL;
    
    if ((*id_sql_server = mysql_init(NULL)) == NULL) {
        down:
        if (server_down == 0) {
	    const char *mysql_err = "mysql_init()";
	    
	    if (*id_sql_server != NULL) {
		mysql_err = mysql_error(*id_sql_server);
	    }
            server_down++;
            logfile(LOG_ERR, MSG_SQL_DOWN " [%s]", mysql_err);
        }
        return -1;
    }
    if (mysql_real_connect(*id_sql_server, server, user, pw,
                           db, port, socket_path,
#ifdef CLIENT_MULTI_STATEMENTS
			   CLIENT_MULTI_STATEMENTS
#else
			   0
#endif
			   ) == NULL) {
        goto down;
    }
    if (mysql_ping(*id_sql_server) != 0) {
        goto down;
    }        
    server_down = 0;
    
    return 0;
}

static int pw_mysql_simplequery(MYSQL * const id_sql_server,
                                const char * const query)
{
    if (mysql_real_query(id_sql_server, query, strlen(query)) != 0) {
       return -1;
    }     
    return 0;
}

static char *pw_mysql_getquery(MYSQL * const id_sql_server,
                               const char * const orig_query,
                               const char * const account,
                               const char * const ip,
                               const char * const port,
                               const char * const peer_ip,
                               const char * const decimal_ip)
{
    char query[MYSQL_MAX_REQUEST_LENGTH];    
    MYSQL_RES *qresult = NULL;
    unsigned long *lengths;
    char *answer = NULL;    
    MYSQL_ROW row;
    size_t length;
    
    if (orig_query == NULL || *orig_query == 0) {
        goto bye;
    }
    if (sqlsubst(orig_query, query, sizeof query,
                 account, ip, port, peer_ip, decimal_ip) == NULL) {
        goto bye;
    }
    if (mysql_real_query(id_sql_server, query, strlen(query)) != 0) {
        logfile(LOG_WARNING, MSG_SQL_WRONG_PARMS " : [%s]", query);
        goto bye;
    }
    if (mysql_field_count(id_sql_server) != 1) {
        goto bye;
    }
    if ((qresult = mysql_store_result(id_sql_server)) == NULL) {
        goto bye;
    }
    if (mysql_num_rows(qresult) != 1) {
        goto bye;
    }
    if ((row = mysql_fetch_row(qresult)) == NULL || row[0] == NULL) {
        goto bye;
    }
    lengths = mysql_fetch_lengths(qresult);
    if (lengths == NULL || 
        (length = (size_t) lengths[0] + (size_t) 1U) <= (size_t) 1U) {
        goto bye;
    }
    if ((answer = malloc(length)) == NULL) {
        goto bye;
    }
    strncpy(answer, row[0], length - (size_t) 1U);
    answer[length - (size_t) 1U] = 0;
    
    bye:
    if (qresult != NULL) {
	mysql_free_result(qresult);
#ifdef CLIENT_MULTI_STATEMENTS
	while (mysql_next_result(id_sql_server) == 0) {
	    qresult = mysql_store_result(id_sql_server);
	    mysql_free_result(qresult);
	}
#endif
    }    
    return answer;    
}

void pw_mysql_check(AuthResult * const result,
                    const char *account, const char *password,
                    const struct sockaddr_storage * const sa,
                    const struct sockaddr_storage * const peer)
{
    MYSQL *id_sql_server = NULL;
    const char *spwd = NULL;           /* stored password */
    const char *uid = sql_default_uid; /* stored system login/uid */
    const char *gid = sql_default_gid; /* stored system group/gid */
    const char *dir = NULL;            /* stored home directory */
#ifdef QUOTAS
    const char *sqta_fs = NULL;        /* stored quota files */    
    const char *sqta_sz = NULL;        /* stored quota size */
#endif    
#ifdef RATIOS
    const char *ratio_ul = NULL;       /* stored ratio UL */
    const char *ratio_dl = NULL;       /* stored ratio DL */
#endif    
#ifdef THROTTLING
    const char *bandwidth_ul = NULL;   /* stored bandwidth UL */
    const char *bandwidth_dl = NULL;   /* stored bandwidth DL */
#endif
    char *escaped_account = NULL;
    char *escaped_ip = NULL;
    char *escaped_port = NULL;
    char *escaped_peer_ip = NULL;
    char *escaped_decimal_ip = NULL;    
    int committed = 1;
    int crypto_crypt = 0, crypto_mysql = 0, crypto_md5 = 0, crypto_plain = 0;
    unsigned long decimal_ip_num = 0UL;
    char decimal_ip[42];
    char hbuf[NI_MAXHOST];
    char pbuf[NI_MAXSERV];
    char phbuf[NI_MAXHOST];
    
    result->auth_ok = 0;
    if (pw_mysql_validate_name(account) != 0) {
        goto bye;
    }
    if (getnameinfo((const struct sockaddr *) sa, STORAGE_LEN(*sa),
                    hbuf, sizeof hbuf, pbuf, sizeof pbuf,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0 ||
        getnameinfo((const struct sockaddr *) peer, STORAGE_LEN(*peer),
                    phbuf, sizeof phbuf, NULL, (size_t) 0U,
                    NI_NUMERICHOST) != 0) {
        goto bye;
    }
    *decimal_ip = 0;
    if (STORAGE_FAMILY(*peer) == AF_INET) {
        const unsigned char *decimal_ip_raw =
            (const unsigned char *) &(STORAGE_SIN_ADDR(*peer));
        decimal_ip_num = (decimal_ip_raw[0] << 24) | 
            (decimal_ip_raw[1] << 16) | (decimal_ip_raw[2] << 8) |
            decimal_ip_raw[3];
        if (SNCHECK(snprintf(decimal_ip, sizeof decimal_ip,
                             "%lu", decimal_ip_num), sizeof decimal_ip)) {
            goto bye;
        }
    }
    if (pw_mysql_connect(&id_sql_server) != 0) {
        goto bye;
    }
    if ((escaped_account = 
         pw_mysql_escape_string(id_sql_server, account)) == NULL) {
        goto bye;
    }
    if ((escaped_ip = 
         pw_mysql_escape_string(id_sql_server, hbuf)) == NULL) {
        goto bye;
    }
    if ((escaped_port = 
         pw_mysql_escape_string(id_sql_server, pbuf)) == NULL) {
        goto bye;
    }
    if ((escaped_peer_ip = 
         pw_mysql_escape_string(id_sql_server, phbuf)) == NULL) {
        goto bye;
    }
    if ((escaped_decimal_ip = 
         pw_mysql_escape_string(id_sql_server, decimal_ip)) == NULL) {
        goto bye;
    }
    if (transactions != NULL && strcasecmp(transactions, "on") == 0) {
        if (pw_mysql_simplequery(id_sql_server, MYSQL_TRANSACTION_START) == 0) {
            committed = 0;
        }
    }
    if ((spwd = pw_mysql_getquery(id_sql_server, sqlreq_getpw,
                                  escaped_account, escaped_ip,
                                  escaped_port, escaped_peer_ip,
                                  escaped_decimal_ip)) == NULL) {
        goto bye;
    }
    if (uid == NULL) {
        uid = pw_mysql_getquery(id_sql_server, sqlreq_getuid,
                                escaped_account, escaped_ip, 
                                escaped_port, escaped_peer_ip,
                                escaped_decimal_ip);
    }
    if (uid == NULL) {
        goto bye;
    }
    if (gid == NULL) {
        gid = pw_mysql_getquery(id_sql_server, sqlreq_getgid,
                                escaped_account, escaped_ip,
                                escaped_port, escaped_peer_ip,
                                escaped_decimal_ip);
    }
    if (gid == NULL) {
        goto bye;
    }
    if ((dir = pw_mysql_getquery(id_sql_server, sqlreq_getdir,
                                 escaped_account, escaped_ip,
                                 escaped_port, escaped_peer_ip,
                                 escaped_decimal_ip)) == NULL) {
        goto bye;
    }
    result->auth_ok--;                  /* -1 */
    if (strcasecmp(crypto, PASSWD_SQL_ANY) == 0) {
        crypto_crypt++;
        crypto_mysql++;
        crypto_md5++;
    } else if (strcasecmp(crypto, PASSWD_SQL_CRYPT) == 0) {
        crypto_crypt++;
    } else if (strcasecmp(crypto, PASSWD_SQL_MYSQL) == 0) {
        crypto_mysql++;
    } else if (strcasecmp(crypto, PASSWD_SQL_MD5) == 0) {
        crypto_md5++;
    } else {                           /* default to plaintext */
        crypto_plain++;
    }
    if (crypto_crypt != 0) {
        register const char *crypted;

        if ((crypted = (const char *) crypt(password, spwd)) != NULL &&
            strcmp(crypted, spwd) == 0) {
            goto auth_ok;
        }
    }
    if (crypto_mysql != 0) {
#if MYSQL_VERSION_ID < 40100 || defined(USE_OLD_MYSQL_SCRAMBLING)
        unsigned long hash_res[2];
        char scrambled_password[MYSQL_CRYPT_LEN];
     
# if MYSQL_VERSION_ID < 40100
        hash_password(hash_res, password);
# else
        hash_password(hash_res, password, strlen(password));	    
# endif	    
        snprintf(scrambled_password, sizeof scrambled_password, "%08lx%08lx", 
                 hash_res[0], hash_res[1]);
#else
	char scrambled_password[42]; /* 2 * 20 (sha1 hash size) + 2 */

# if MYSQL_VERSION_ID >= 40100 && MYSQL_VERSION_ID < 40101
	make_scrambled_password(scrambled_password, password, 1, NULL);
# else
	make_scrambled_password(scrambled_password, password);
# endif
#endif
        if (strcmp(scrambled_password, spwd) == 0) {
            goto auth_ok;
        }
    }
    if (crypto_md5 != 0) {
        register const char *crypted;

        if ((crypted = (const char *) crypto_hash_md5(password, 1)) != NULL &&
            strcmp(crypted, spwd) == 0) {
            goto auth_ok;
        }
    }    
    if (crypto_plain != 0) {
        if (*password != 0 &&    /* refuse null cleartext passwords */
            strcmp(password, spwd) == 0) {
            goto auth_ok;
        }
    }
    goto bye;
    
    auth_ok:
    /*
     * do *NOT* accept root uid/gid - if the database is compromized, the FTP
     * server could also be rooted.
     */
    result->uid = (uid_t) strtoul(uid, NULL, 10);
    if (result->uid <= (uid_t) 0) {
        struct passwd *pw;
        
        if ((pw = getpwnam(uid)) == NULL || pw->pw_uid <= (uid_t) 0) {
            goto bye;
        }
        result->uid = pw->pw_uid;
    }
    result->gid = (gid_t) strtoul(gid, NULL, 10);
    if (result->gid <= (gid_t) 0) {
        struct group *gr;
        
        if ((gr = getgrnam(gid)) == NULL || (gid_t) gr->gr_gid <= (gid_t) 0) {
            goto bye;
        }
        result->gid = gr->gr_gid;
    }    
    result->dir = dir;
    dir = NULL;    
#ifdef QUOTAS
    if ((sqta_fs = pw_mysql_getquery(id_sql_server, sqlreq_getqta_fs,
                                     escaped_account, escaped_ip,
                                     escaped_port, escaped_peer_ip,
                                     escaped_decimal_ip)) != NULL) {
        const unsigned long long q = strtoull(sqta_fs, NULL, 10);
        
        if (q > 0ULL) {
            result->user_quota_files = q;
            result->quota_files_changed = 1;
        }
    }
    if ((sqta_sz = pw_mysql_getquery(id_sql_server, sqlreq_getqta_sz,
                                     escaped_account, escaped_ip,
                                     escaped_port, escaped_peer_ip,
                                     escaped_decimal_ip)) != NULL) {
        const unsigned long long q = strtoull(sqta_sz, NULL, 10);
        
        if (q > 0ULL) {
            result->user_quota_size = q * (1024UL * 1024UL);
            result->quota_size_changed = 1;
        }
    }
#endif           
#ifdef RATIOS
    if ((ratio_ul = pw_mysql_getquery(id_sql_server, sqlreq_getratio_ul,
                                      escaped_account, escaped_ip,
                                      escaped_port, escaped_peer_ip,
                                      escaped_decimal_ip)) != NULL) {
        const unsigned int q = (unsigned int) strtoul(ratio_ul, NULL, 10);
        
        if (q > 0U) {
            result->ratio_upload = q;
            result->ratio_ul_changed = 1;
        }
    }
    if ((ratio_dl = pw_mysql_getquery(id_sql_server, sqlreq_getratio_dl,
                                      escaped_account, escaped_ip,
                                      escaped_port, escaped_peer_ip,
                                      escaped_decimal_ip)) != NULL) {
        const unsigned int q = (unsigned int) strtoul(ratio_dl, NULL, 10);
        
        if (q > 0U) {
            result->ratio_download = q;
            result->ratio_dl_changed = 1;
        }
    }
#endif
#ifdef THROTTLING
    if ((bandwidth_ul = pw_mysql_getquery(id_sql_server, sqlreq_getbandwidth_ul,
                                          escaped_account, escaped_ip,
                                          escaped_port, escaped_peer_ip,
                                          escaped_decimal_ip)) != NULL) {
        const unsigned long q = (unsigned long) strtoul(bandwidth_ul, NULL, 10);
        
        if (q > 0UL) {
            result->throttling_bandwidth_ul = q * 1024UL;
            result->throttling_ul_changed = 1;
        }
    }
    if ((bandwidth_dl = pw_mysql_getquery(id_sql_server, sqlreq_getbandwidth_dl,
                                          escaped_account, escaped_ip,
                                          escaped_port, escaped_peer_ip,
                                          escaped_decimal_ip)) != NULL) {
        const unsigned long q = (unsigned long) strtoul(bandwidth_dl, NULL, 10);
        
        if (q > 0UL) {
            result->throttling_bandwidth_dl = q * 1024UL;
            result->throttling_dl_changed = 1;
        }
    }
#endif
    result->slow_tilde_expansion = !tildexp;
    result->auth_ok = -result->auth_ok;
    bye:
    if (committed == 0) {
        (void) pw_mysql_simplequery(id_sql_server, MYSQL_TRANSACTION_END);
    }
    if (id_sql_server != NULL) {
        mysql_close(id_sql_server);
    }
    free((void *) spwd);
    if (uid != sql_default_uid) {
        free((void *) uid);
    }
    if (gid != sql_default_gid) {
        free((void *) gid); 
    }
    free((void *) dir);
#ifdef QUOTAS
    free((void *) sqta_fs);
    free((void *) sqta_sz);
#endif    
#ifdef RATIOS
    free((void *) ratio_ul);
    free((void *) ratio_dl);
#endif    
#ifdef THROTTLING
    free((void *) bandwidth_ul);
    free((void *) bandwidth_dl);
#endif    
    free((void *) escaped_account);
    free((void *) escaped_ip);
    free((void *) escaped_port);
    free((void *) escaped_peer_ip);
    free((void *) escaped_decimal_ip);
}

void pw_mysql_parse(const char * const file)
{
    if (generic_parser(file, mysql_config_keywords) != 0) {
        die(421, LOG_ERR, MSG_CONF_ERR ": " MSG_ILLEGAL_CONFIG_FILE_SQL ": %s",
        file);
    }    
    if (server == NULL && socket_path == NULL) {
        die(421, LOG_ERR, MSG_SQL_MISSING_SERVER);        
    }
    if (server != NULL && socket_path != NULL) {
        free(socket_path);
        socket_path = NULL;
    }
    if (tildexp_s != NULL) {
    if ((tildexp = atoi(tildexp_s)) < 0) {
        tildexp = 0;
    }
    free(tildexp_s);
    tildexp_s = NULL;    
    }        
    if (port_s != NULL) {
        port = atoi(port_s);
        if (port <= 0 || port > 65535) {
            port = MYSQL_DEFAULT_PORT;
        }
        free(port_s);
        port_s = NULL;
    }        
}

#define ZFREE(X) do { free(X); (X) = NULL; } while (0)

void pw_mysql_exit(void)
{
    ZFREE(server);
    ZFREE(port_s);
    port = -1;    
    ZFREE(socket_path);
    ZFREE(user);
    ZFREE(pw);
    ZFREE(db);
    ZFREE(crypto);
    ZFREE(transactions);
    ZFREE(sqlreq_getpw);
    ZFREE(sqlreq_getuid);
    ZFREE(sql_default_uid);
    ZFREE(sqlreq_getgid);
    ZFREE(sql_default_gid);
    ZFREE(sqlreq_getdir);
#ifdef QUOTAS
    ZFREE(sqlreq_getqta_fs);
    ZFREE(sqlreq_getqta_sz);
#endif
#ifdef RATIOS
    ZFREE(sqlreq_getratio_ul);
    ZFREE(sqlreq_getratio_dl);    
#endif
#ifdef THROTTLING
    ZFREE(sqlreq_getbandwidth_ul);
    ZFREE(sqlreq_getbandwidth_dl);    
#endif
}
#else
extern signed char v6ready;
#endif
