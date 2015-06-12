/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * OpenBSD and Bitrig can fetch random data through a sysctl call, but other
 * systems require reading a device.
 * This modified version of the arc4random*() functions keeps an open file
 * descriptor, so that we can still reseed the PRNG after a chroot() call.
 */

#include <config.h>

#if !defined(__OpenBSD__) && !defined(__Bitrig__)
#define KEYSTREAM_ONLY
#include "crypto.h"
#include "ftpd.h"
#include "safe_rw.h"
#include "alt_arc4random.h"
#include "alt_arc4random_p.h"
#include "utils.h"

#if SIZEOF_INT < 4
# error Unsupported architecture
#endif

#define KEYSZ   32
#define IVSZ    8
#define BLOCKSZ 64
#define RSBUFSZ (16 * BLOCKSZ)
static int rs_initialized;
static pid_t rs_stir_pid;
static chacha_ctx rs;           /* chacha context for random keystream */
static unsigned char rs_buf[RSBUFSZ];   /* keystream blocks */
static size_t rs_have;          /* valid bytes at end of rs_buf */
static size_t rs_count;         /* bytes till reseed */
static int random_data_source_fd = -1;

/* Warning: thread safety intentionally disabled */
#define _alt_arc4_LOCK()   do { } while(0)
#define _alt_arc4_UNLOCK() do { } while(0)

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void _rs_rekey(unsigned char *dat, size_t datlen);

static void
_rs_init(unsigned char *buf, size_t n)
{
    if (n < KEYSZ + IVSZ) {
        return;
    }
    chacha_keysetup(&rs, buf, KEYSZ * 8, 0);
    chacha_ivsetup(&rs, buf + KEYSZ);
}

static int
_rs_random_dev_open(void)
{
    struct stat        st;
    static const char *devices[] = {
        "/dev/urandom", "/dev/random", NULL
    };
    const char **      device = devices;
    int                fd;

    do {
        if (access(*device, F_OK | R_OK) == 0 &&
            (fd = open(*device, O_RDONLY)) != -1) {
            if (fstat(fd, &st) == 0 && S_ISCHR(st.st_mode)) {
                return fd;
            }
            (void) close(fd);
        }
        device++;
    } while (*device != NULL);

    return -1;
}

static void
_rs_stir(void)
{
    unsigned char rnd[KEYSZ + IVSZ];

    if (!rs_initialized) {
        random_data_source_fd = _rs_random_dev_open();
    }
    if (random_data_source_fd != -1) {
        safe_read(random_data_source_fd, rnd, sizeof rnd);
    } else {
#ifdef HAVE_RANDOM_DEV
        _exit(1);
#else
        size_t i = (size_t) 0U;
# ifdef HAVE_ARC4RANDOM
        crypto_uint4 r;
        do {
            r = arc4random();
            memcpy(&rnd[i], &r, (size_t) 4U);
            i += (size_t) 4U;
        } while (i < sizeof(rnd));
# elif defined(HAVE_RANDOM)
        unsigned short r;
        do {
            r = (unsigned short) random();
            rnd[i++] = r & 0xFF;
            rnd[i++] = (r << 8) & 0xFF;
        } while (i < sizeof(rnd));
# else
        unsigned char r;
        do {
            r = (unsigned char) rand();
            rnd[i++] = r;
        } while (i < sizeof(rnd));
# endif
#endif
    }
    if (!rs_initialized) {
        rs_initialized = 1;
        _rs_init(rnd, sizeof rnd);
    } else {
        _rs_rekey(rnd, sizeof rnd);
    }
    pure_memzero(rnd, sizeof rnd);

    /* invalidate rs_buf */
    rs_have = 0;
    pure_memzero(rs_buf, RSBUFSZ);

    rs_count = 1600000;
    rs_stir_pid = getpid();
}

static inline void
_rs_stir_if_needed(size_t len)
{
    pid_t pid = getpid();

    if (rs_count <= len || !rs_initialized) {
        _rs_stir();
    } else if (rs_stir_pid != pid) {
        abort();
    } else {
        rs_count -= len;
    }
}

static void
_rs_rekey(unsigned char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
    pure_memzero(rs_buf, RSBUFSZ);
#endif
    /* fill rs_buf with the keystream */
    chacha_encrypt_bytes(&rs, rs_buf, rs_buf, RSBUFSZ);
    /* mix in optional user provided data */
    if (dat != NULL) {
        size_t i, m;

        if (datlen < KEYSZ + IVSZ) {
            m = datlen;
        } else {
            m = KEYSZ + IVSZ;
        }
        for (i = 0; i < m; i++) {
            rs_buf[i] ^= dat[i];
        }
    }
    /* immediately reinit for backtracking resistance */
    _rs_init(rs_buf, KEYSZ + IVSZ);
    pure_memzero(rs_buf, KEYSZ + IVSZ);
    rs_have = RSBUFSZ - KEYSZ - IVSZ;
}

static void
_rs_random_buf(void *_buf, size_t n)
{
    unsigned char *buf = (unsigned char *)_buf;
    size_t m;

    _rs_stir_if_needed(n);
    while (n > 0) {
        if (rs_have > 0) {
            if (n < rs_have) {
                m = n;
            } else {
                m = rs_have;
            }
            memcpy(buf, rs_buf + RSBUFSZ - rs_have, m);
            pure_memzero(rs_buf + RSBUFSZ - rs_have, m);
            buf += m;
            n -= m;
            rs_have -= m;
        }
        if (rs_have == 0) {
            _rs_rekey(NULL, 0);
        }
    }
}

static inline void
_rs_random_u32(crypto_uint4 *val)
{
    _rs_stir_if_needed(sizeof(*val));
    if (rs_have < sizeof(*val)) {
        _rs_rekey(NULL, 0);
    }
    memcpy(val, rs_buf + RSBUFSZ - rs_have, sizeof(*val));
    pure_memzero(rs_buf + RSBUFSZ - rs_have, sizeof(*val));
    rs_have -= sizeof(*val);
}

void
alt_arc4random_stir(void)
{
    _alt_arc4_LOCK();
    _rs_stir();
    _alt_arc4_UNLOCK();
}

int
alt_arc4random_close(void)
{
    int ret = -1;

    _alt_arc4_LOCK();
    if (random_data_source_fd != -1 && close(random_data_source_fd) == 0) {
        random_data_source_fd = -1;
        ret = 0;
    }
    _alt_arc4_UNLOCK();

    return ret;
}

crypto_uint4
alt_arc4random(void)
{
    crypto_uint4 val;

    _alt_arc4_LOCK();
    _rs_random_u32(&val);
    _alt_arc4_UNLOCK();
    return val;
}

void
alt_arc4random_buf(void *_buf, size_t n)
{
    _alt_arc4_LOCK();
    _rs_random_buf(_buf, n);
    _alt_arc4_UNLOCK();
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
crypto_uint4
alt_arc4random_uniform(crypto_uint4 upper_bound)
{
    crypto_uint4 r, min;

    if (upper_bound < 2U) {
        return 0U;
    }

    /* 2**32 % x == (2**32 - x) % x */
    min = (crypto_uint4) (- upper_bound % upper_bound);

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    for (;;) {
        r = alt_arc4random();
        if (r >= min) {
            break;
        }
    }

    return r % upper_bound;
}

#else

#include "alt_arc4random.h"

int
alt_arc4random_close(void)
{
    return 0;
}

#endif
