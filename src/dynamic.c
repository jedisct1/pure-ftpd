#include <config.h>

#ifndef NO_STANDALONE

/* Yes, I know, I could have used multi-hashed linked lists, 
 * binary trees and other funny stuff. It'd have been better, cleaner,
 * faster. Yeah, it'd have added many lines of complicated source code
 * to win 1/100000 sec on system with more than 500 sim users.
 * Great win, but sorry, I won't do that just to please theorical
 * algorithms wizards. -Jedi.
 */

# include "ftpd.h"
# include "dynamic.h"
# include "ftpwho-update.h"
# include "globals.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

static IPTrack *iptrack_list;

void iptrack_delete_pid(const pid_t pid)
{
    unsigned int c = 0U;
    
    if (iptrack_list == NULL) { 
        return;
    }
    do {
        if (iptrack_list[c].pid == pid) {
            iptrack_list[c].pid = (pid_t) 0;
            return;
        }
        c++;
    } while (c < maxusers);    
}

void iptrack_free(void)
{
    free(iptrack_list);
    iptrack_list = NULL;
}

static unsigned int iptrack_find_ip_or_shift
    (const struct sockaddr_storage * const ip)
{
    unsigned int c = 0U;
    
    do {
        if (iptrack_list[c].pid != (pid_t) 0 && 
            STORAGE_FAMILY(iptrack_list[c].ip) != STORAGE_FAMILY(*ip)) {
            if (STORAGE_FAMILY(iptrack_list[c].ip) == AF_INET &&
                STORAGE_SIN_ADDR(iptrack_list[c].ip) == STORAGE_SIN_ADDR(*ip)) {
                return c;
            } else if (STORAGE_FAMILY(iptrack_list[c].ip) == AF_INET6 &&
                       IN6_ARE_ADDR_EQUAL
                       (&STORAGE_SIN_ADDR6_NF(iptrack_list[c].ip),
                        &STORAGE_SIN_ADDR6_NF(*ip))) {
                return c;
            }
        }
        c++;
    } while (c < maxusers);
    c--;
    if (c != 0U) {
        memmove(&(iptrack_list[0]), &(iptrack_list[1]),    /* safe */
                (sizeof iptrack_list[0]) * c);
    }
    return c;
}

unsigned int iptrack_get(const struct sockaddr_storage * const ip)
{
    unsigned int c = 0U;
    unsigned int nb = 0U;
    
    if (iptrack_list == NULL) { 
        return 0U;
    }
    do {
        if (iptrack_list[c].pid != (pid_t) 0 && 
            STORAGE_FAMILY(iptrack_list[c].ip) == STORAGE_FAMILY(*ip)) {
            if (STORAGE_FAMILY(iptrack_list[c].ip) == AF_INET &&
                STORAGE_SIN_ADDR(iptrack_list[c].ip) == STORAGE_SIN_ADDR(*ip)) {
                nb++;
            } else if (STORAGE_FAMILY(iptrack_list[c].ip) == AF_INET6 &&
                       IN6_ARE_ADDR_EQUAL
                       (&STORAGE_SIN_ADDR6_NF(iptrack_list[c].ip),
                        &STORAGE_SIN_ADDR6_NF(*ip))) {
                nb++;
            }
        }
        c++;
    } while (c < maxusers);

    return nb;
}

void iptrack_add(const struct sockaddr_storage * const ip,
                 const pid_t pid)
{
    unsigned int c = 0U;
    
    if (iptrack_list == NULL) {
        unsigned int ci = 0U;
        
        if ((iptrack_list = malloc(maxusers * sizeof *iptrack_list)) == NULL) {
            return;
        }
        do {
            iptrack_list[ci].pid = (pid_t) 0;
            ci++;
        } while (ci < maxusers);
    }     
    do {
        if (iptrack_list[c].pid == (pid_t) 0U) {
            force:
            iptrack_list[c].pid = pid;
            iptrack_list[c].ip = *ip;
            return;
        }
        c++;
    } while (c < maxusers);    
    c = iptrack_find_ip_or_shift(ip);
    goto force;
}

#else
extern signed char v6ready;
#endif
