#ifndef __CRYPTO_H__
#define __CRYPTO_H__ 1

#include <stdlib.h>
#include <stdint.h>

char *crypto_hash_sha1(const char *string, const int hex);
char *crypto_hash_ssha1(const char *string, const char *stored);
char *crypto_hash_md5(const char *string, const int hex);
char *crypto_hash_smd5(const char *string, const char *stored);
char *hexify(char * const result, const unsigned char *digest,
             const size_t size_result, size_t size_digest);

#endif
