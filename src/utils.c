
#include <config.h>

#include "ftpd.h"
#include "utils.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#ifdef HAVE_LIBSODIUM
# if !defined(pure_memzero) || !defined(pure_memcmp)
#  error pure_memzero/pure_memcmp not defined
# endif
#else

void pure_memzero(void * const pnt, const size_t len)
{
# ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(pnt, len);
# else
    volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
    size_t                     i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
# endif
}

int pure_memcmp(const void * const b1_, const void * const b2_, size_t len)
{
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
    size_t               i;
    unsigned char        d = (unsigned char) 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (int) ((1 & ((d - 1) >> 8)) - 1);
}

#endif

int pure_strcmp(const char * const s1, const char * const s2)
{
    return pure_memcmp(s1, s2, strlen(s1) + 1U);
}
