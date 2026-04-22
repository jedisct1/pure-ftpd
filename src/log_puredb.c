#include <config.h>

#ifdef WITH_PUREDB

#include "ftpd.h"
#include "messages.h"
#include "log_puredb.h"
#include "pure-pw.h"
#include "../puredb/src/puredb_read.h"
#include "utils.h"

#ifdef HAVE_LIBSODIUM
# include <sodium.h>
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static char *pdb_filename;

void pw_puredb_parse(const char * const file)
{
    if (file == NULL || *file == 0) {
        die(421, LOG_ERR, MSG_NO_VIRTUAL_FILE);
    }
    if ((pdb_filename = strdup(file)) == NULL) {
        die_mem();
    }
}

void pw_puredb_exit(void)
{
    free(pdb_filename);
}

/*
 * The difference between this strtok() and the libc's one is that
 * this one doesn't skip empty fields, and takes a char instead of a
 * string as a delimiter.
 * This strtok2() variant leaves zeroes.
 */

static char *my_strtok2(char *str, const char delim)
{
    static char *s;
    static char save;

    if (str != NULL) {
        if (*str == 0) {
            return NULL;
        }
        s = str;
        scan:
        while (*s != 0 && *s != delim) {
            s++;
        }
        save = *s;
        *s = 0;

        return str;
    }
    if (s == NULL || save == 0) {
        return NULL;
    }
    s++;
    str = s;

    goto scan;
}

/* Check whether an IP address matches a pattern. 1 = match 0 = nomatch */

static int ipv6_cidr_match(const unsigned char *addr,
                           const unsigned char *pattern_addr,
                           unsigned int prefix_len)
{
    unsigned int full_bytes;
    unsigned int remainder;
    unsigned char last_mask;

    if (prefix_len > 128U) {
        return 0;
    }
    full_bytes = prefix_len / 8U;
    remainder = prefix_len % 8U;
    if (full_bytes > 0U && memcmp(addr, pattern_addr, full_bytes) != 0) {
        return 0;
    }
    if (remainder != 0U) {
        last_mask = (unsigned char) (0xffU << (8U - remainder));
        if ((addr[full_bytes] & last_mask) !=
            (pattern_addr[full_bytes] & last_mask)) {
            return 0;
        }
    }
    return 1;
}

static int access_ip_match(const struct sockaddr_storage * const sa,
                           char * pattern)
{
    unsigned int ip0, ip1, ip2, ip3;
    unsigned int netbits;
    unsigned long ip;
    unsigned long mask;
    unsigned long saip;
    const unsigned char *saip_raw;
    char *comapoint;
    int sa_family;

    if (*pattern == 0) {
        return 1;
    }
    sa_family = STORAGE_FAMILY(*sa);
    if (sa_family != AF_INET && sa_family != AF_INET6) {
        return 0;
    }
    do {
        if ((comapoint = strchr(pattern, ',')) != NULL) {
            *comapoint = 0;
        }
        if (sscanf(pattern, "%u.%u.%u.%u/%u",
                   &ip0, &ip1, &ip2, &ip3, &netbits) == 5) {
            ipcheck:
            if (ip0 > 255U || ip1 > 255U || ip2 > 255U || ip3 > 255U) {
                goto ipcheck_nomatch;
            }
            if (sa_family != AF_INET || netbits == 0U ||
                netbits > 32U) {
                return -1;
            }
            ip =
                ((unsigned long) ip0 << 24) |
                ((unsigned long) ip1 << 16) |
                ((unsigned long) ip2 << 8) |
                (unsigned long) ip3;
            ipcheck_ipdone:
            mask = ~((0x80000000 >> (netbits - 1U)) - 1U);
            saip_raw = (const unsigned char *) &(STORAGE_SIN_ADDR_CONST(*sa));
            saip =
                ((unsigned long) saip_raw[0] << 24) |
                ((unsigned long) saip_raw[1] << 16) |
                ((unsigned long) saip_raw[2] << 8) |
                (unsigned long) saip_raw[3];
            if ((ip & mask) == (saip & mask)) {
                return 1;
            }
        } else if (sscanf(pattern, "%u.%u.%u.%u",
                          &ip0, &ip1, &ip2, &ip3) == 4) {
            netbits = 32U;
            goto ipcheck;
        } else {
            struct in6_addr pat6;
            char addr_buf[256];
            char *slash;
            unsigned int prefix6;
            struct addrinfo hints, *res;
            int on;

            strncpy(addr_buf, pattern, sizeof addr_buf);
            addr_buf[sizeof addr_buf - 1] = 0;
            slash = strchr(addr_buf, '/');
            prefix6 = 128U;
            if (slash != NULL) {
                char *endptr;
                unsigned long val;

                *slash = 0;
                val = strtoul(slash + 1, &endptr, 10);
                if (endptr == slash + 1 || *endptr != 0 ||
                    val == 0U || val > 128U) {
                    return -1;
                }
                prefix6 = (unsigned int) val;
            }
            if (inet_pton(AF_INET6, addr_buf, &pat6) == 1) {
                if (sa_family != AF_INET6) {
                    goto ipcheck_nomatch;
                }
                if (ipv6_cidr_match(STORAGE_SIN_ADDR6_CONST(*sa),
                                    (const unsigned char *) &pat6,
                                    prefix6) != 0) {
                    return 1;
                }
                goto ipcheck_nomatch;
            }
            if (slash != NULL) {
                goto ipcheck_nomatch;
            }
            memset(&hints, 0, sizeof hints);
            hints.ai_family = sa_family;
            hints.ai_addr = NULL;
            if ((on = getaddrinfo(addr_buf, NULL, &hints, &res)) != 0) {
                logfile(LOG_WARNING, "puredb: [%s] => [%d]", pattern, on);
            } else if (res->ai_family == AF_INET6 && sa_family == AF_INET6) {
                const struct sockaddr_in6 *sin6 =
                    (const struct sockaddr_in6 *) (void *) res->ai_addr;

                if (ipv6_cidr_match(STORAGE_SIN_ADDR6_CONST(*sa),
                                    (const unsigned char *) &sin6->sin6_addr,
                                    128U) != 0) {
                    freeaddrinfo(res);
                    return 1;
                }
                freeaddrinfo(res);
            } else if (res->ai_family == AF_INET && sa_family == AF_INET) {
                const unsigned char * const ip_raw =
                    (const unsigned char *) &
                    (((const struct sockaddr_in *) (void *)
                      (res->ai_addr))->sin_addr.s_addr);

                ip =
                    ((unsigned long) ip_raw[0] << 24) |
                    ((unsigned long) ip_raw[1] << 16) |
                    ((unsigned long) ip_raw[2] << 8) |
                    (unsigned long) ip_raw[3];
                netbits = 32U;
                freeaddrinfo(res);
                goto ipcheck_ipdone;
            } else {
                freeaddrinfo(res);
            }
        }
        ipcheck_nomatch:
        if (comapoint == NULL) {
            break;
        }
        *comapoint = ',';
        pattern = comapoint + 1;
    } while (*pattern != 0);

    return 0;
}

/* IP check. 0 = ok, -1 = denied */

static int access_ip_check(const struct sockaddr_storage * const sa,
                           char * const allow, char * const deny)
{
    if (sa == NULL) {
        return 0;
    }
    if (*allow == 0) {
        if (*deny == 0) {
            return 0;
        }
        if (access_ip_match(sa, deny) != 0) {
            return -1;
        }
        return 0;
    }
    if (*deny == 0) {
        if (access_ip_match(sa, allow) != 0) {
            return 0;
        }
        return -1;
    }
    if (access_ip_match(sa, allow) != 0 && access_ip_match(sa, deny) == 0) {
        return 0;
    }
    return -1;
}

static int time_restrictions_check(const char * const restrictions)
{
    const struct tm *tm;
    time_t now_t;
    unsigned int time_begin, time_end;
    unsigned int now;

    if (*restrictions == 0) {
        return 0;
    }
    if (sscanf(restrictions, "%u-%u", &time_begin, &time_end) != 2) {
        return -1;
    }
    if ((now_t = time(NULL)) == (time_t) -1 ||
        (tm = localtime(&now_t)) == NULL) {
        return 0;
    }
    now = (unsigned int) tm->tm_hour * 100U + (unsigned int) tm->tm_min;
    if (time_begin <= time_end) {
        if (time_begin <= now && now <= time_end) {
            return 0;
        }
        return -1;
    }
    if (now >= time_begin || now <= time_end) {
        return 0;
    }
    return -1;
}

static int pw_puredb_parseline(char *line, const char * const pwd,
                               const struct sockaddr_storage * const sa,
                               const struct sockaddr_storage * const peer,
                               AuthResult * const result)
{
    char *allow_local_ip, *deny_local_ip;
    char *allow_remote_ip, *deny_remote_ip;
    char *endptr;
    const char *time_restrictions;

    if ((line = my_strtok2(line, *PW_LINE_SEP)) == NULL || *line == 0) {   /* pwd */
        return -1;
    }
    {
        const char *crypted;
        int         ret = -1;

#ifdef crypto_pwhash_STRPREFIX
        if (crypto_pwhash_str_verify(line, pwd, strlen(pwd)) == 0) {
            /* pass */
        } else
#endif
#ifdef crypto_pwhash_scryptsalsa208sha256_STRPREFIX
        if (crypto_pwhash_scryptsalsa208sha256_str_verify
            (line, pwd, strlen(pwd)) == 0) {
            /* pass */
        } else
#endif
        {
            ret = - ((crypted = (const char *) crypt(pwd, line)) == NULL ||
                     pure_strcmp(line, crypted) != 0);
            if (ret != 0) {
                return -1;
            }
        }
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* uid */
        return -1;
    }
    result->uid = (uid_t) strtoul(line, &endptr, 10);
    if (line == endptr || *endptr != 0 || result->uid <= (uid_t) 0) {
        return -1;
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* gid */
        return -1;
    }
    result->gid = (gid_t) strtoul(line, &endptr, 10);
    if (line == endptr || *endptr != 0 || result->gid <= (gid_t) 0) {
        return -1;
    }
#ifndef ACCEPT_ROOT_VIRTUAL_USERS
    if (result->uid <= (uid_t) 0 || result->gid <= (gid_t) 0) {
        return -1;
    }
#endif
    if (my_strtok2(NULL, *PW_LINE_SEP) == NULL) {   /* gecos */
        return -1;
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL || *line == 0) {   /* home */
        return -1;
    }
    if ((result->dir = strdup(line)) == NULL || *result->dir != '/') {
        return -1;
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* bw_ul */
        return 0;
    }
#ifdef THROTTLING
    if (*line != 0) {
        result->throttling_ul_changed = 1;
        result->throttling_bandwidth_ul = strtoul(line, NULL, 10);
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* bw_dl */
        return 0;
    }
#ifdef THROTTLING
    if (*line != 0) {
        result->throttling_dl_changed = 1;
        result->throttling_bandwidth_dl = strtoul(line, NULL, 10);
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* ratio up */
        return 0;
    }
#ifdef RATIOS
    if (*line != 0) {
        result->ratio_upload = (unsigned int) strtoul(line, NULL, 10);
        if (result->ratio_upload > 0U) {
            result->ratio_ul_changed = 1;
        }
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* ratio down */
        return 0;
    }
#ifdef RATIOS
    if (*line != 0) {
        result->ratio_download = (unsigned int) strtoul(line, NULL, 10);
        if (result->ratio_download > 0U) {
            result->ratio_dl_changed = 1;
        }
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* max cnx */
        return 0;
    }
#ifdef PER_USER_LIMITS
    if (*line != 0) {
        result->per_user_max = (unsigned int) strtoull(line, NULL, 10);
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* files quota */
        return 0;
    }
#ifdef QUOTAS
    if (*line != 0) {
        result->quota_files_changed = 1;
        result->user_quota_files = strtoull(line, NULL, 10);
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* size quota */
        return 0;
    }
#ifdef QUOTAS
    if (*line != 0) {
        result->quota_size_changed = 1;
        result->user_quota_size = strtoull(line, NULL, 10);
    }
#endif
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* allowed local ip */
        return 0;
    }
    allow_local_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* denied local ip */
        return 0;
    }
    deny_local_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* allowed remote ip */
        return 0;
    }
    allow_remote_ip = line;
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* denied remote ip */
        return 0;
    }
    deny_remote_ip = line;
    if (access_ip_check(sa, allow_local_ip, deny_local_ip) != 0 ||
        access_ip_check(peer, allow_remote_ip, deny_remote_ip) != 0) {
        return -1;
    }
    if ((line = my_strtok2(NULL, *PW_LINE_SEP)) == NULL) {   /* time restrictions */
        return 0;
    }
    time_restrictions = line;
    if (time_restrictions_check(time_restrictions) != 0) {
        return -1;
    }

    return 0;
}

void pw_puredb_check(AuthResult * const result,
                     const char *account, const char *password,
                     const struct sockaddr_storage * const sa,
                     const struct sockaddr_storage * const peer)
{
    char *line = NULL;
    PureDB db;
    off_t retpos;
    size_t retlen;

    result->auth_ok = 0;
    (void) sa;
    (void) peer;
    if (puredb_open(&db, pdb_filename) != 0) {
        die(421, LOG_ERR, MSG_PDB_BROKEN);
    }
    if (puredb_find_s(&db, account, &retpos, &retlen) != 0) {
        goto bye;
    }
    if ((line = puredb_read(&db, retpos, retlen)) == NULL) {
        goto bye;
    }
    result->auth_ok--;
    if (pw_puredb_parseline(line, password, sa, peer, result) != 0) {
        goto bye;
    }
    result->slow_tilde_expansion = 1;
    result->auth_ok = -result->auth_ok;
    bye:
    puredb_read_free(line);
    puredb_close(&db);
}

#endif
