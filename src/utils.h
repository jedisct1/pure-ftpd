#ifndef __UTILS_H__
#define __UTILS_H__ 1

#ifdef HAVE_LIBSODIUM
# include <sodium.h>
# define pure_memzero(P, L) sodium_memzero((P), (L))
# define pure_memcmp(A, B, L) sodium_memcmp((A), (B), (L))
#else
void pure_memzero(void * const pnt, const size_t len);
int pure_memcmp(const void * const b1_, const void * const b2_, size_t len);
#endif
int pure_strcmp(const char * const s1, const char * const s2);

#endif
