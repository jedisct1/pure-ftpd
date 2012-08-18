
#ifndef __ALT_ARC4RANDOM_H__
#define __ALT_ARC4RANDOM_H__ 1

#include <stdlib.h>
#include "crypto.h"

#if defined(__OpenBSD__) || defined(__Bitrig__)

#define alt_arc4random() arc4random()
#define alt_arc4random_stir() arc4random_stir()
#define alt_arc4random_addrandom(A, B) arc4random_addrandom(A, B)
#define alt_arc4random_uniform(A) arc4random_uniform(A)
#define alt_arc4random_buf(A, B) arc4random_buf(A, B)

#else

void         alt_arc4random_stir(void);
void         alt_arc4random_addrandom(unsigned char *, int);
void         alt_arc4random_buf(void *, size_t);
crypto_uint4 alt_arc4random(void);
crypto_uint4 alt_arc4random_uniform(crypto_uint4);

#endif

int          alt_arc4random_close(void);

#endif
