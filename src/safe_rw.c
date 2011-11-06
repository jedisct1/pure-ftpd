
#include <config.h>

#include "ftpd.h"
#include "safe_rw.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

ssize_t
safe_write(const int fd, const void * const buf_, size_t count,
           const int timeout)
{
    struct pollfd  pfd;
    const char    *buf = (const char *) buf_;
    ssize_t        written;

    pfd.fd = fd;
    pfd.events = POLLOUT;

    while (count > (size_t) 0) {
        while ((written = write(fd, buf, count)) <= (ssize_t) 0) {
            if (errno == EAGAIN) {
                if (poll(&pfd, (nfds_t) 1, timeout) == 0) {
                    errno = ETIMEDOUT;
                    goto ret;
                }
            } else if (errno != EINTR) {
                goto ret;
            }
        }
        buf += written;
        count -= written;
    }
ret:
    return (ssize_t) (buf - (const char *) buf_);
}

ssize_t
safe_read(const int fd, void * const buf_, size_t count)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t        readnb;

    do {
        while ((readnb = read(fd, buf, count)) < (ssize_t) 0 &&
               errno == EINTR);
        if (readnb < (ssize_t) 0) {
            return readnb;
        }
        if (readnb == (ssize_t) 0) {
            break;
        }
        count -= readnb;
        buf += readnb;
    } while (count > (ssize_t) 0);

    return (ssize_t) (buf - (unsigned char *) buf_);
}

ssize_t
safe_read_partial(const int fd, void * const buf_, const size_t max_count)
{
    unsigned char * const buf = (unsigned char * const) buf_;
    ssize_t               readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 &&
           errno == EINTR);

    return readnb;
}
