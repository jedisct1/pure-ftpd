#ifndef __CRYPTO_H__
#define __CRYPTO_H__ 1

#include <stdlib.h>
#include <stdint.h>

char *hexify(char * const result, const unsigned char *digest,
             const size_t size_result, size_t size_digest);

#endif
