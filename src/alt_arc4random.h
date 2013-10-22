
#ifndef __ALT_ARC4RANDOM_H__
#define __ALT_ARC4RANDOM_H__ 1

#include <stdlib.h>
#include "crypto.h"

#if defined(__OpenBSD__) || defined(__Bitrig__)

#define alt_arc4random() arc4random()
#ifdef HAVE_ARC4RANDOM_STIR
# define alt_arc4random_stir() arc4random_stir()
#else
# define alt_arc4random_stir() (void) 0
#endif
#ifdef HAVE_ARC4RANDOM_ADDRANDOM
# define alt_arc4random_addrandom(A, B) arc4random_addrandom(A, B)
#else
# define alt_arc4random_addrandom(A, B) (void) 0
#endif
#define alt_arc4random_uniform(A) arc4random_uniform(A)
#define alt_arc4random_buf(A, B) arc4random_buf(A, B)

#else

void         alt_arc4random_stir(void);
void         alt_arc4random_buf(void *, size_t);
crypto_uint4 alt_arc4random(void);
crypto_uint4 alt_arc4random_uniform(crypto_uint4);

#endif

int          alt_arc4random_close(void);

#endif
