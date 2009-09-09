#include <config.h>

#if !defined(NO_INETD) || defined(IN_PURE_MRTGINFO)
# include "ftpd.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

# define TCP_STATE_CNX 1UL

static unsigned int count(in_port_t server_port, const char * const file)
{
    int f;
    int r;
    int c;    
    int b = 0;
    int e = 0;
    unsigned int d = 0U;
    char buf[2049];    
    
    if ((f = open(file, O_RDONLY)) == -1) {
        return 0;
    }
    buf[2048] = 0;
    
    for (;;) {
        while ((r = (int) read(f, buf + e, (size_t) (2048U - e)))
               < (ssize_t) 0 && errno == EINTR);
        if (r <= (ssize_t) 0) {    /* ignore errors. 0 is okay, in fact common. */
            break;
        }
        e += r;

        /*
         * b is the offset of the start of the first line to be parsed
         * and e the end of the available data 
         */
        c = b;
        while (c < e && buf[c] != '\n') {
            c++;
        }
        while (c < e) {
            buf[c++] = 0;
            while (b < c && buf[b] != ':' && buf[b] != '\n') {
                b++;
            }
            if (b < c && buf[b] == ':') {
                b++;
                while (b < e && buf[b] != ':') {
                    b++;
                }
                b++;
                if (strtoul(buf + b, NULL, 16) ==
                    (unsigned long) server_port) {
                    while (b < e && buf[b] != ':') {
                        b++;
                    }
                    if (buf[b] == ':') {
                        b++;
                        while (b < e && buf[b] != ' ') {
                            b++;
                        }
                        if (buf[b] == ' ') {
                            b++;
                            if (strtoul(buf + b, NULL, 16) == TCP_STATE_CNX) {
                                d++;
                            }
                        }
                    }
                }
            }
            b = c;
            while (c < e && buf[c] != '\n') {
                c++;
            }
        }
        if (e > b) {
            (void) memmove(buf, buf + b, (size_t) (e - b));   /* safe */
        }
        e -= b;
        b = 0;
    }
    close(f);
    
    return d;
}

unsigned int daemons(const in_port_t server_port)
{
    unsigned int nbcnx;
    
    nbcnx = count(server_port, "/proc/net/tcp");
    nbcnx += count(server_port, "/proc/net/tcp6");
    
    return nbcnx;
}
#else
extern signed char v6ready;
#endif
