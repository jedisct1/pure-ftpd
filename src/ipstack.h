#ifndef __IPSTACK_H__
#define __IPSTACK_H__ 1

#ifdef OLD_IP_STACK

#ifndef EAI_FAMILY
# define EAI_FAMILY (-1)
# define EAI_FAIL   (-2)
# define EAI_SYSTEM (-3)
# define EAI_MEMORY (-4)
#endif

#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST (1 << 0)
# define NI_MAXHOST 1025
# define NI_MAXSERV 32
# define NI_NUMERICSERV 2
#endif

#ifndef AI_PASSIVE
# define AI_PASSIVE (1 << 0)
#endif

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    int ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
#endif

#if !defined(HAVE_GETADDRINFO) && !defined(HAVE_GETNAMEINFO)
# define sockaddr_storage sockaddr_in
# define ss_family sin_family
# ifdef HAVE_SIN_LEN
#  define ss_len sin_len
#  define HAVE_SS_LEN 1
# endif
# define sockaddr_in6 sockaddr_in
# define sin6_port sin_port
# define sin6_addr sin_addr
# define in6_addr in_addr
# define s6_addr s_addr
#endif

#ifndef AF_INET6
# define AF_INET6 AF_UNSPEC
# define PF_INET6 AF_INET6
#endif

#ifndef IN6ADDR_ANY_INIT
# define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#endif
#ifndef IN6ADDR_LOOPBACK_INIT
# define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#endif

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 46
#endif
#ifndef IN6_IS_ADDR_UNSPECIFIED
# define IN6_IS_ADDR_UNSPECIFIED(a) 0
#endif
#ifndef IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) 0
#endif
#ifndef IN6_IS_ADDR_MULTICAST
# define IN6_IS_ADDR_MULTICAST(a) 0
#endif
#ifndef IN6_IS_ADDR_LINKLOCAL
# define IN6_IS_ADDR_LINKLOCAL(a) 0
#endif
#ifndef IN6_IS_ADDR_SITELOCAL
# define IN6_IS_ADDR_SITELOCAL(a) 0
#endif
#ifndef IN6_IS_ADDR_V4MAPPED
# define IN6_IS_ADDR_V4MAPPED(a) 0
#endif
#ifndef IN6_IS_ADDR_V4COMPAT
# define IN6_IS_ADDR_V4COMPAT(a) 0
#endif
#ifndef IN6_ARE_ADDR_EQUAL
# define IN6_ARE_ADDR_EQUAL(a,b) 0
#endif

#if !defined(HAVE_INET_NTOP) && !defined(inet_ntop)
# define inet_ntop(AF, SRC, DST) inet_aton(SRC, (struct in_addr *) (DST))
#endif

#if !defined(HAVE_INET_PTON) && !defined(inet_pton)
int inet_pton(int af, const char *src, void *dst);
#endif

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa_, socklen_t salen,
                char *host, size_t hostlen,
                char *serv, size_t servlen, int flags);
#endif

#ifndef HAVE_GETADDRINFO
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res);

void freeaddrinfo(struct addrinfo *res);
#endif

#endif

in_port_t *storage_port(const struct sockaddr_storage * const ss);
in_port_t *storage_port6(const struct sockaddr_storage * const ss);
struct in_addr *storage_sin_addr(const struct sockaddr_storage * const ss);
struct in6_addr *storage_sin_addr6(const struct sockaddr_storage * const ss);
    
#endif
