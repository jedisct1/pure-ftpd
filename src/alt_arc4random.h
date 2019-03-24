
#ifndef __ALT_ARC4RANDOM_H__
#define __ALT_ARC4RANDOM_H__ 1

#include <stdlib.h>
#include <stdint.h>

#if defined(__OpenBSD__) || defined(__CloudABI__) || defined(__wasi__)

#define alt_arc4random() arc4random()
#ifdef HAVE_ARC4RANDOM_STIR
# define alt_arc4random_stir() arc4random_stir()
#else
# define alt_arc4random_stir() (void) 0
#endif
#define alt_arc4random_uniform(A) arc4random_uniform(A)
#define alt_arc4random_buf(A, B) arc4random_buf(A, B)

#else

void     alt_arc4random_stir(void);
void     alt_arc4random_buf(void *, size_t);
uint32_t alt_arc4random(void);
uint32_t alt_arc4random_uniform(uint32_t);

#endif

int      alt_arc4random_close(void);

#endif
