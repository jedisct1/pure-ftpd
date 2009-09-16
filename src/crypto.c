#include <config.h>

#if defined(WITH_LDAP) || defined(WITH_MYSQL) || defined(WITH_PGSQL)

#include "ftpd.h"
#include "crypto.h"
#ifndef USE_SYSTEM_CRYPT_SHA1
# include "crypto-sha1.h"
#else
# include <sha1.h>
#endif
#ifndef USE_SYSTEM_CRYPT_MD5
# include "crypto-md5.h"
#else
# include <md5.h>
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

/* Convert a buffer to an hex string. size_digest must be an even number */

static char *hexify(char * const result, const unsigned char *digest,
                    const size_t size_result, size_t size_digest)
{
    static const char * const hexchars = "0123456789abcdef";
    char *result_pnt = result;

    /* 
     * Unless developpers are drunk, the following tests are just
     * paranoid bloat. But ehm... yeah, sometimes, they *are* drunk,
     * so...
     */
    if (size_digest < (size_t) 2U ||
        size_result <= (size_digest * (size_t) 2U)) {
        return NULL;
    }                                  /* end of the drunk section :) */
    do {
        *result_pnt++ = hexchars[(*digest >> 4) & 0xf];
        *result_pnt++ = hexchars[*digest & 0xf];
        digest++;
        size_digest--;
    } while (size_digest > (size_t) 0U);
    *result_pnt = 0;

    return result;
}

/* Encode a buffer to Base64 */

static char *base64ify(char * const result, const unsigned char *digest,
                       const size_t size_result, size_t size_digest)     
{
    static const char * const b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *result_pnt = result;
    
    if (size_result < (((size_digest + 2U) / 3U) * 4U + 1U)) {
        return NULL;
    }
    while (size_digest > (size_t) 2U) {
        const unsigned char t0 = (unsigned char) *digest++;
        const unsigned char t1 = (unsigned char) *digest++;
        const unsigned char t2 = (unsigned char) *digest++;
        
        *result_pnt++ = b64chars[(t0 >> 2) & 63];
        *result_pnt++ = b64chars[((t0 << 4) & 48) | ((t1 >> 4) & 15)];
        *result_pnt++ = b64chars[((t1 << 2) & 60) | ((t2 >> 6) & 3)];
        *result_pnt++ = b64chars[t2 & 63];
        size_digest -= (size_t) 3U;
    }    
    if (size_digest > (size_t) 0U) {
        const unsigned char t0 = (unsigned char) digest[0];

        *result_pnt++ = b64chars[(t0 >> 2) & 63];
        if (size_digest == 1U) {
            *result_pnt++ = b64chars[((t0 << 4) & 48)];
            *result_pnt++ = '=';
        } else {
            const unsigned char t1 = (unsigned char) digest[1];
            
            *result_pnt++ = b64chars[((t0 << 4) & 48) | ((t1 >> 4) & 15)];
            *result_pnt++ = b64chars[((t1 << 2) & 60)];            
        }
        *result_pnt++ = '=';        
    }
    *result_pnt = 0;
    
    return result;
}

/* Decode a Base64 encoded string */

static char *debase64ify(char * const result, const unsigned char *encoded,
                         const size_t size_result, size_t size_encoded,
                         size_t *size_decoded)
{
    const unsigned char rev64chars[] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 62U, 0U, 0U, 0U, 63U, 52U, 53U,
        54U, 55U, 56U, 57U, 58U, 59U, 60U, 61U, 0U, 0U, 0U, 255U, 0U, 0U, 0U,
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
        16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 0U, 0U, 0U, 0U, 0U,
        0U, 26U, 27U, 28U, 29U, 30U, 31U, 32U, 33U, 34U, 35U, 36U, 37U, 38U,
        39U, 40U, 41U, 42U, 43U, 44U, 45U, 46U, 47U, 48U, 49U, 50U, 51U
    };
    size_t ch = size_encoded;
    char *result_pnt = result;
    int extra = 0;
        
    if (size_result < (((size_encoded + 3U) / 4U) * 3U + 1U)) {
        return NULL;
    }    
    while (ch > (size_t) 0U) {
        if (encoded[--ch] > 'z') {
            return NULL;
        }
    }
    while (size_encoded > (size_t) 3U) {
        const unsigned char t1 = rev64chars[encoded[1]];
        const unsigned char t2 = rev64chars[encoded[2]];
        const unsigned char t3 = rev64chars[encoded[3]];        
        /* 
         * I'm very proud : bit shifts and masks were done without writing
         * down anything on a piece of paper, and the first try worked :)
         */
        *result_pnt++ = (char) ((rev64chars[encoded[0]] << 2) | ((t1 & 48) >> 4));
        *result_pnt++ = (char) (((t1 & 15) << 4) | ((t2 & 60) >> 2));
        *result_pnt++ = (char) (((t2 & 3) << 6) | t3);
        if (t3 == 255U) {
            if (t2 == 255U) {
                extra = 2;
            } else {
                extra = 1;
            }
            break;
        }        
        encoded += 4;
        size_encoded -= (size_t) 4U;        
    }
    *size_decoded = (size_t) (result_pnt - result) - extra;
    *result_pnt = 0;
    
    return result;
}

/* Compute a simple hex SHA1 digest of a C-string */

char *crypto_hash_sha1(const char *string, const int hex)
{
    SHA1_CTX ctx;    
    unsigned char digest[20];
    static char result[41];
    
    SHA1Init(&ctx);
    if (string != NULL && *string != 0) {
        SHA1Update(&ctx, (const unsigned char *) string,
                   (unsigned int) strlen(string));
    }
    SHA1Final(digest, &ctx);

    if (hex == 0) {
        return base64ify(result, digest, sizeof result, sizeof digest);
    }
    return hexify(result, digest, sizeof result, sizeof digest);
}


/* Compute a simple hex MD5 digest of a C-string */

char *crypto_hash_md5(const char *string, const int hex)
{
    MD5_CTX ctx;    
    unsigned char digest[16];
    static char result[33];    
    
    MD5Init(&ctx);
    if (string != NULL && *string != 0) {
        MD5Update(&ctx, (const unsigned char *) string,
                  (unsigned int) strlen(string));
    }
    MD5Final(digest, &ctx);

    if (hex == 0) {
        return base64ify(result, digest, sizeof result, sizeof digest);
    }
    return hexify(result, digest, sizeof result, sizeof digest);
}


/* Compute a salted SHA1 digest of a C-string */

char *crypto_hash_ssha1(const char *string, const char *stored)
{
    SHA1_CTX ctx;
    const char *salt;
    unsigned char digest[20];    
    size_t decoded_len;  
    char *hash_and_salt;
    size_t sizeof_hash_and_salt;
    static char decoded[512];
    
    if (debase64ify(decoded, (const unsigned char *) stored,
                    sizeof decoded, strlen(stored), &decoded_len) == NULL) {
        return NULL;                   /* huge salt, better abort */
    }
    if (decoded_len < sizeof digest) {
        return NULL;                   /* corrupted hash result, abort */
    }
    salt = decoded + sizeof digest;
    decoded_len -= sizeof digest;    
    SHA1Init(&ctx);
    if (string != NULL && *string != 0) {
        SHA1Update(&ctx, (const unsigned char *) string, 
                   (unsigned int) strlen(string));
    }
    if (decoded_len > (size_t) 0U) {
        SHA1Update(&ctx, (const unsigned char *) salt, decoded_len);
    }
    SHA1Final(digest, &ctx);    
    sizeof_hash_and_salt = sizeof digest + decoded_len;
    if ((hash_and_salt = ALLOCA(sizeof_hash_and_salt)) == NULL) {
        return NULL;
    }
    memcpy(hash_and_salt, digest, sizeof digest);   /* no possible overflow */
    memcpy(hash_and_salt + sizeof digest, salt, decoded_len);   /* no possible overflow */
    if (base64ify(decoded, (const unsigned char *) hash_and_salt, 
                  sizeof decoded, sizeof_hash_and_salt) == NULL) {
        ALLOCA_FREE(hash_and_salt);        
        return NULL;
    }    
    ALLOCA_FREE(hash_and_salt);
    
    return decoded;
}

/* Compute a salted MD5 digest of a C-string */

char *crypto_hash_smd5(const char *string, const char *stored)
{
    MD5_CTX ctx;
    const char *salt;
    unsigned char digest[20];    
    size_t decoded_len;  
    char *hash_and_salt;
    size_t sizeof_hash_and_salt;
    static char decoded[512];
    
    if (debase64ify(decoded, (const unsigned char *) stored,
                    sizeof decoded, strlen(stored), &decoded_len) == NULL) {
        return NULL;                   /* huge salt, better abort */
    }
    if (decoded_len < sizeof digest) {
        return NULL;                   /* corrupted hash result, abort */
    }
    salt = decoded + sizeof digest;
    decoded_len -= sizeof digest;    
    MD5Init(&ctx);
    if (string != NULL && *string != 0) {
        MD5Update(&ctx, (const unsigned char *) string, 
                  (unsigned int) strlen(string));
    }
    if (decoded_len > (size_t) 0U) {
        MD5Update(&ctx, (const unsigned char *) salt, decoded_len);
    }
    MD5Final(digest, &ctx);    
    sizeof_hash_and_salt = sizeof digest + decoded_len;
    if ((hash_and_salt = ALLOCA(sizeof_hash_and_salt)) == NULL) {
        return NULL;
    }
    memcpy(hash_and_salt, digest, sizeof digest);   /* no possible overflow */
    memcpy(hash_and_salt + sizeof digest, salt, decoded_len);   /* no possible overflow */
    if (base64ify(decoded, (const unsigned char *) hash_and_salt, 
                  sizeof decoded, sizeof_hash_and_salt) == NULL) {
        ALLOCA_FREE(hash_and_salt);        
        return NULL;
    }    
    ALLOCA_FREE(hash_and_salt);
    
    return decoded;
}

#else
extern signed char v6ready;
#endif
