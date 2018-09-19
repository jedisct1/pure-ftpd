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
#ifdef HAVE_LIBSODIUM
# include <sodium.h>
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

/* Convert a buffer to an hex string.
 * size_digest is the output length including the trailing \0
 */

#ifdef HAVE_LIBSODIUM
char *hexify(char * const result, const unsigned char *digest,
             const size_t size_result, size_t size_digest)
{
    return sodium_bin2hex(result, size_result, digest, size_digest);
}
#else
char *hexify(char * const result, const unsigned char *digest,
             const size_t size_result, size_t size_digest)
{
    static const char * const hexchars = "0123456789abcdef";
    char *result_pnt = result;

    if (size_digest <= (size_t) 0 ||
        size_result <= (size_digest * (size_t) 2U)) {
        return NULL;
    }
    do {
        *result_pnt++ = hexchars[(*digest >> 4) & 0xf];
        *result_pnt++ = hexchars[*digest & 0xf];
        digest++;
        size_digest--;
    } while (size_digest > (size_t) 0U);
    *result_pnt = 0;

    return result;
}
#endif

/* Encode a buffer to Base64 */

char *base64ify(char * const b64, const unsigned char *bin,
                size_t b64_maxlen, size_t bin_len)
{
#define B64_PAD '='

    static const char b64chars[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *b64_w = b64;

    if (b64_maxlen < (((bin_len + 2U) / 3U) * 4U + 1U)) {
        return NULL;
    }
    while (bin_len > (size_t) 2U) {
        const unsigned char t0 = (unsigned char) *bin++;
        const unsigned char t1 = (unsigned char) *bin++;
        const unsigned char t2 = (unsigned char) *bin++;

        *b64_w++ = b64chars[(t0 >> 2) & 63];
        *b64_w++ = b64chars[((t0 << 4) & 48) | ((t1 >> 4) & 15)];
        *b64_w++ = b64chars[((t1 << 2) & 60) | ((t2 >> 6) & 3)];
        *b64_w++ = b64chars[t2 & 63];
        bin_len -= (size_t) 3U;
    }
    if (bin_len > (size_t) 0U) {
        const unsigned char t0 = (unsigned char) bin[0];

        *b64_w++ = b64chars[(t0 >> 2) & 63];
        if (bin_len == 1U) {
            *b64_w++ = b64chars[((t0 << 4) & 48)];
            *b64_w++ = B64_PAD;
        } else {
            const unsigned char t1 = (unsigned char) bin[1];

            *b64_w++ = b64chars[((t0 << 4) & 48) | ((t1 >> 4) & 15)];
            *b64_w++ = b64chars[((t1 << 2) & 60)];
        }
        *b64_w++ = B64_PAD;
    }
    *b64_w = 0;

    return b64;
}

/* Decode a Base64 encoded string */

static unsigned char *
debase64ify(unsigned char * const bin, const char *b64,
            size_t bin_maxlen, size_t b64_len, size_t * const bin_len_p)
{
#define REV64_EOT      128U
#define REV64_NONE     64U
#define REV64_PAD      '='

    static const unsigned char rev64chars[256] = {
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, 62U, REV64_NONE, REV64_NONE, REV64_NONE, 63U, 52U, 53U, 54U, 55U, 56U, 57U, 58U, 59U, 60U, 61U, REV64_NONE, REV64_NONE, REV64_NONE, REV64_EOT, REV64_NONE, REV64_NONE, REV64_NONE, 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U,
        8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, 26U, 27U, 28U, 29U, 30U, 31U, 32U, 33U, 34U, 35U, 36U, 37U, 38U, 39U, 40U, 41U, 42U,
        43U, 44U, 45U, 46U, 47U, 48U, 49U, 50U, 51U, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE
    };
    const unsigned char *b64_u = (const unsigned char *) b64;
    unsigned char       *bin_w = bin;
    unsigned char        mask;
    unsigned char        t0, t1, t2, t3;
    uint32_t             t;
    size_t               i;

    if (b64_len % 4U != 0U || (i = b64_len / 4U) <= 0U ||
        bin_maxlen < i * 3U -
        (b64_u[b64_len - 1U] == REV64_PAD) - (b64_u[b64_len - 2U] == REV64_PAD)) {
        return NULL;
    }
    while (i-- > 0U) {
        t0 = rev64chars[*b64++];
        t1 = rev64chars[*b64++];
        t2 = rev64chars[*b64++];
        t3 = rev64chars[*b64++];
        t = ((uint32_t) t3) | ((uint32_t) t2 << 6) |
            ((uint32_t) t1 << 12) | ((uint32_t) t0 << 18);
        mask = t0 | t1 | t2 | t3;
        if ((mask & (REV64_NONE | REV64_EOT)) != 0U) {
            if ((mask & REV64_NONE) != 0U || i > 0U) {
                return NULL;
            }
            break;
        }
        *bin_w++ = (unsigned char) (t >> 16);
        *bin_w++ = (unsigned char) (t >> 8);
        *bin_w++ = (unsigned char) t;
    }
    if ((mask & REV64_EOT) != 0U) {
        if (((t0 | t1) & REV64_EOT) != 0U || t3 != REV64_EOT) {
            return NULL;
        }
        *bin_w++ = (unsigned char) (t >> 16);
        if (t2 != REV64_EOT) {
            *bin_w++ = (unsigned char) (t >> 8);
        }
    }
    if (bin_len_p != NULL) {
        *bin_len_p = (size_t) (bin_w - bin);
    }
    return bin;
}

/* Compute a simple hex SHA1 digest of a C-string */

char *crypto_hash_sha1(const char *string, const int hex)
{
    SHA1_CTX ctx;
    unsigned char digest[20];
    static char result[41];

    SHA1Init(&ctx);
    if (string != NULL && *string != 0) {
        SHA1Update(&ctx, (const unsigned char *) string, strlen(string));
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
        MD5Update(&ctx, (const unsigned char *) string, strlen(string));
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

    if (debase64ify(decoded, stored, sizeof decoded,
                    strlen(stored), &decoded_len) == NULL) {
        return NULL;                   /* huge salt, better abort */
    }
    if (decoded_len < sizeof digest) {
        return NULL;                   /* corrupted hash result, abort */
    }
    salt = decoded + sizeof digest;
    decoded_len -= sizeof digest;
    SHA1Init(&ctx);
    if (string != NULL && *string != 0) {
        SHA1Update(&ctx, (const unsigned char *) string, strlen(string));
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

    if (debase64ify(decoded, stored, sizeof decoded,
                    strlen(stored), &decoded_len) == NULL) {
        return NULL;                   /* huge salt, better abort */
    }
    if (decoded_len < sizeof digest) {
        return NULL;                   /* corrupted hash result, abort */
    }
    salt = decoded + sizeof digest;
    decoded_len -= sizeof digest;
    MD5Init(&ctx);
    if (string != NULL && *string != 0) {
        MD5Update(&ctx, (const unsigned char *) string, strlen(string));
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
