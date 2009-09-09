
/*
 * An IPv4-only reimplementation of getnameinfo(), getaddrinfo(),
 * freeaddrinfo() and inet_pton() for old IP stacks.
 * IPv6-enabled stacks don't need this, so we assume we have IPv4 everywhere.
 * 
 * Jedi <j at pureftpd dot org>
 * Matthias Andree <matthias.andree at stud.uni-dortmund.de>
 */

#include <config.h>

#include "ftpd.h"
#ifdef OLD_IP_STACK

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#define DEFAULT_PROTO_NAME "tcp"

/* 
 * This is a stripped-down version of getnameinfo()
 * Only host names can be resolved, and NI_NOFQDN is ignored.
 */

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa_, socklen_t salen,
                char *host, size_t hostlen,
                char *serv, size_t servlen, int flags)
{            
    struct sockaddr_in *sa = (struct sockaddr_in *) sa_;
    
    (void) salen;    
    if (sa == NULL || sa->sin_family != AF_INET) {
        return EAI_FAMILY;
    }
    if (serv != NULL && servlen > (size_t) 1U) {
        snprintf(serv, servlen, "%lu", (unsigned long) ntohs(sa->sin_port));
    }    
    if (host != NULL && hostlen > (size_t) 1U) {
        struct hostent *he;
        
        if ((flags & NI_NUMERICHOST) == 0 && 
            (he = 
             gethostbyaddr((const char *) &(sa->sin_addr),
                           sizeof sa->sin_addr, AF_INET)) != NULL &&
            he->h_name != NULL && *he->h_name != 0) {
            size_t h_name_len;
            
            if ((h_name_len = strlen(he->h_name)) >= hostlen) {
                goto resolve_numeric_ip;
            }
            memcpy(host, he->h_name, h_name_len + (size_t) 1U);
        } else {
            char *numeric_ip;
            size_t numeric_ip_len;
            
            resolve_numeric_ip:
            if ((numeric_ip = inet_ntoa(sa->sin_addr)) == NULL) {
                return EAI_SYSTEM;
            }
            if ((numeric_ip_len = strlen(numeric_ip)) >= hostlen) {
                return EAI_FAIL;
            }
            memcpy(host, numeric_ip, numeric_ip_len + (size_t) 1U);
        }
    }    
    return 0;
}
#endif

/* Stripped-down version of getaddrinfo() - Only one answer, no linked list */

#ifndef HAVE_GETADDRINFO
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
    struct addrinfo *answer;
    struct sockaddr_in *saddr; 
    const char *proto_name = DEFAULT_PROTO_NAME;
    int socktype = SOCK_STREAM;
    in_port_t port = 0U;
    
    if (res == NULL) {
        return EAI_FAIL;
    }
    *res = NULL;    
    if ((answer = malloc(sizeof *answer)) == NULL) {
        return EAI_MEMORY;
    }
    if ((saddr = malloc(sizeof *saddr)) == NULL) {
        free(answer);
        return EAI_MEMORY;
    }
    answer->ai_family = AF_INET;
    answer->ai_addrlen = sizeof *saddr;
    answer->ai_addr = (struct sockaddr *) saddr;    
    answer->ai_next = NULL;
    memset(saddr, 0, sizeof *saddr);
    saddr->sin_family = AF_INET;
#if defined(HAVE_SIN_LEN)
    saddr->sin_len = sizeof *saddr;
#endif
    if (hints != NULL) {
        struct protoent *pe;
        
        if ((pe = getprotobynumber(hints->ai_protocol)) != NULL &&
            pe->p_name != NULL && *pe->p_name != 0) {
            proto_name = pe->p_name;
        }
        if (hints->ai_socktype != 0) {
            socktype = hints->ai_socktype;
        } else if (strcasecmp(proto_name, "udp") == 0) {
            socktype = SOCK_DGRAM;
        }
    }
    if (service != NULL) {
        struct servent *se;
        
        if ((se = getservbyname(service, proto_name)) != NULL &&
            se->s_port > 0) {
            port = se->s_port;
        } else if ((port = (in_port_t) strtoul(service, NULL, 0)) <= 0U ||
                   port > 65535U) {
            port = 0U;
        }
    }
    if (hints != NULL && (hints->ai_flags & AI_PASSIVE) != 0) {
        saddr->sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (node != NULL) {
        struct hostent *he;
        
        if ((he = gethostbyname(node)) != NULL && he->h_addr_list != NULL
            && he->h_addr_list[0] != NULL && he->h_length > 0 && 
            he->h_length <= (int) sizeof saddr->sin_addr) {
            memcpy(&saddr->sin_addr, he->h_addr_list[0], he->h_length);
        }
    }
    answer->ai_socktype = socktype;
    saddr->sin_port = htons(port);
    *res = answer;
    
    return 0; 
}

void freeaddrinfo(struct addrinfo *res)
{
    if (res == NULL) {
        return;
    }
    free(res->ai_addr);
    res->ai_addr = NULL;
    free(res);
}
#endif

#if !defined(HAVE_INET_PTON) && !defined(inet_pton)
int inet_pton(int af, const char *src, void *dst)
/* written by Matthias Andree */
{
    in_addr_t ina;

    if (af != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    
    /* inet_aton would be better, but Solaris 7 e. g. doesn't have it */
    ina = inet_addr(src);
    if (ina == 0UL) {
        return 0;
    }
    memcpy(dst, &ina, sizeof ina);
    
    return 1;
}
#endif

#endif

in_port_t *storage_port(const struct sockaddr_storage * const ss)
{
    struct sockaddr_in * const si = (struct sockaddr_in *) ss;
    
    return &si->sin_port;
}

in_port_t *storage_port6(const struct sockaddr_storage * const ss)
{
    struct sockaddr_in6 * const si = (struct sockaddr_in6 *) ss;
    
    return &si->sin6_port;
}

struct in_addr *storage_sin_addr(const struct sockaddr_storage * const ss)
{
    struct sockaddr_in * const si = (struct sockaddr_in *) ss;

    return &si->sin_addr;
}

struct in6_addr *storage_sin_addr6(const struct sockaddr_storage * const ss)
{
    struct sockaddr_in6 * const si = (struct sockaddr_in6 *) ss;

    return &si->sin6_addr;
}
