
/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * glob(3) -- a superset of the one defined in POSIX 1003.2.
 *
 * The [!...] convention to negate a range is supported (SysV, Posix, ksh).
 *
 * Optional extra services, controlled by flags not defined by POSIX:
 *
 * GLOB_QUOTE:
 *      Escaping convention: \ inhibits any special meaning the following
 *      character might have (except \ at end of string is retained).
 * GLOB_MAGCHAR:
 *      Set in gl_flags if pattern contained a globbing character.
 * GLOB_NOMAGIC:
 *      Same as GLOB_NOCHECK, but it will only append pattern if it did
 *      not contain any magic characters.  [Used in csh style globbing]
 * GLOB_ALTDIRFUNC:
 *      Use alternately specified directory access functions.
 * GLOB_BRACE:
 *      expand {1,2}{a,b} to 1a 1b 2a 2b
 * gl_matchc:
 *      Number of matches in the current invocation of glob.
 */

#include <config.h>

#ifndef DISABLE_GLOBBING
#include "ftpd.h"
#ifdef HAVE_DIRENT_H
# include <dirent.h>
#endif
#ifdef HAVE_SYS_NDIR_H
# include <sys/ndir.h>
#endif
#ifdef HAVE_NDIR_H
# include <ndir.h>
#endif
#include "bsd-glob.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#define DOLLAR          '$'
#define DOT             '.'
#define EOS             '\0'
#define LBRACKET        '['
#define NOT             '!'
#define QUESTION        '?'
#define QUOTE           '\\'
#define RANGE           '-'
#define RBRACKET        ']'
#define SEP             '/'
#define STAR            '*'
#define UNDERSCORE      '_'
#define LBRACE          '{'
#define RBRACE          '}'
#define SLASH           '/'
#define COMMA           ','

#define M_QUOTE         0x8000
#define M_PROTECT       0x4000
#define M_MASK          0xffff
#define M_ASCII         0x00ff

typedef unsigned short Char;

#define CHAR(c)         ((Char)((c)&M_ASCII))
#define META(c)         ((Char)((c)|M_QUOTE))
#define M_ALL           META('*')
#define M_END           META(']')
#define M_NOT           META('!')
#define M_ONE           META('?')
#define M_RNG           META('-')
#define M_SET           META('[')
#define ismeta(c)       (((c)&M_QUOTE) != 0)

#define GLOB_LIMIT_MALLOC       65536

struct glob_lim {
    size_t  glim_malloc;
    size_t  glim_stat;
    size_t  glim_readdir;
};

struct glob_path_stat {
    char        *gps_path;
    struct stat     *gps_stat;
};

static int       compare(const void *, const void *);
static int       compare_gps(const void *, const void *);
static int       g_Ctoc(const Char *, char *, unsigned int);
static int       g_lstat(Char *, struct stat *, glob_t *);
static DIR      *g_opendir(Char *, glob_t *);
static Char     *g_strchr(const Char *, int);
static int       g_stat(Char *, struct stat *, glob_t *);
static int       glob0(const Char *, glob_t *, struct glob_lim *);
static int       glob1(Char *, Char *, glob_t *, struct glob_lim *, int);
static int       glob2(Char *, Char *, Char *, Char *, Char *, Char *,
                       glob_t *, struct glob_lim *, int);
static int       glob3(Char *, Char *, Char *, Char *, Char *,
                       Char *, Char *, glob_t *, struct glob_lim *, int);
static int       globextend(const Char *, glob_t *, struct glob_lim *,
                            struct stat *);
static int       globexp1(const Char *, glob_t *, struct glob_lim *, int);
static int       globexp2(const Char *, const Char *, glob_t *,
                          struct glob_lim *, int);
static int       match(Char *, Char *, Char *, int);

static int
glob_(const char *pattern, int flags, int (*errfunc)(const char *, int),
      glob_t *pglob, unsigned long maxfiles, int maxdepth)
{
    const unsigned char *patnext;
    int c;
    Char *bufnext, *bufend, patbuf[MAXPATHLEN];
    struct glob_lim limit = { 0, 0, 0 };

    if (strlen(pattern) >= PATH_MAX) {
        return GLOB_NOMATCH;
    }
    pglob->gl_maxdepth = maxdepth;
    pglob->gl_maxfiles = maxfiles;
    patnext = (unsigned char *) pattern;
    if (!(flags & GLOB_APPEND)) {
        pglob->gl_pathc = 0;
        pglob->gl_pathv = NULL;
        pglob->gl_statv = NULL;
        if (!(flags & GLOB_DOOFFS)) {
            pglob->gl_offs = 0;
        }
    }
    pglob->gl_flags = flags & ~GLOB_MAGCHAR;
    pglob->gl_errfunc = errfunc;
    pglob->gl_matchc = 0;

    if (pglob->gl_offs < 0 || pglob->gl_pathc < 0 ||
        pglob->gl_offs >= INT_MAX || pglob->gl_pathc >= INT_MAX ||
        pglob->gl_pathc >= INT_MAX - pglob->gl_offs - 1) {
        return GLOB_NOSPACE;
    }
    bufnext = patbuf;
    bufend = bufnext + MAXPATHLEN - 1;
    if (flags & GLOB_NOESCAPE) {
        while (bufnext < bufend && (c = *patnext++) != EOS) {
            *bufnext++ = c;
        }
    } else {
        /* Protect the quoted characters. */
        while (bufnext < bufend && (c = *patnext++) != EOS) {
            if (c == QUOTE) {
                if ((c = *patnext++) == EOS) {
                    c = QUOTE;
                    --patnext;
                }
                *bufnext++ = c | M_PROTECT;
            } else {
                *bufnext++ = c;
            }
        }
    }
    *bufnext = EOS;

    if (flags & GLOB_BRACE) {
        return globexp1(patbuf, pglob, &limit, 0);
    } else {
        return glob0(patbuf, pglob, &limit);
    }
}

int
glob(const char *pattern, int flags, int (*errfunc) (const char *, int),
     glob_t * pglob)
{
    return glob_(pattern, flags, errfunc, pglob, (unsigned long) -1, 0);
}

int
sglob(char *pattern, int flags, int (*errfunc) (const char *, int),
      glob_t * pglob, unsigned long maxfiles, int maxdepth)
{
    simplify(pattern);
    return glob_(pattern, flags, errfunc, pglob, maxfiles, maxdepth);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static int
globexp1(const Char *pattern, glob_t *pglob, struct glob_lim *limitp,
         int recursion)
{
    const Char* ptr = pattern;

    if (pglob->gl_maxdepth > 0 && recursion > pglob->gl_maxdepth) {
        errno = 0;
        return 0;
    }
    /* Protect a single {}, for find(1), like csh */
    if (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS) {
        return glob0(pattern, pglob, limitp);
    }
    if ((ptr = (const Char *) g_strchr(ptr, LBRACE)) != NULL) {
        return globexp2(ptr, pattern, pglob, limitp, recursion + 1);
    }
    return glob0(pattern, pglob, limitp);
}

/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static int
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
         struct glob_lim *limitp, int recursion)
{
    int         i, rv;
    Char       *lm, *ls;
    const Char *pe, *pm, *pl;
    Char        patbuf[MAXPATHLEN];

    /* copy part up to the brace */
    for (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
        ;
    *lm = EOS;
    ls = lm;

    /* Find the balanced brace */
    for (i = 0, pe = ++ptr; *pe; pe++) {
        if (*pe == LBRACKET) {
            /* Ignore everything between [] */
            for (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
                ;
            if (*pe == EOS) {
                /*
                 * We could not find a matching RBRACKET.
                 * Ignore and just look for RBRACE
                 */
                pe = pm;
            }
        } else if (*pe == LBRACE) {
            i++;
        } else if (*pe == RBRACE) {
            if (i == 0) {
                break;
            }
            i--;
        }
    }

    /* Non matching braces; just glob the pattern */
    if (i != 0 || *pe == EOS) {
        return glob0(patbuf, pglob, limitp);
    }
    for (i = 0, pl = pm = ptr; pm <= pe; pm++) {
        switch (*pm) {
        case LBRACKET:
            /* Ignore everything between [] */
            for (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
                ;
            if (*pm == EOS) {
                /*
                 * We could not find a matching RBRACKET.
                 * Ignore and just look for RBRACE
                 */
                pm = pl;
            }
            break;

        case LBRACE:
            i++;
            break;

        case RBRACE:
            if (i) {
                i--;
                break;
            }
            /* FALLTHROUGH */
        case COMMA:
            if (i && *pm == COMMA) {
                break;
            } else {
                /* Append the current string */
                for (lm = ls; (pl < pm); *lm++ = *pl++)
                    ;

                /*
                 * Append the rest of the pattern after the
                 * closing brace
                 */
                for (pl = pe + 1; (*lm++ = *pl++) != EOS; )
                    ;

                /* Expand the current pattern */
                rv = globexp1(patbuf, pglob, limitp, recursion + 1);
                if (rv && rv != GLOB_NOMATCH) {
                    return rv;
                }
                /* move after the comma, to the next string */
                pl = pm + 1;
            }
            break;

        default:
            break;
        }
    }
    return 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static int
glob0(const Char *pattern, glob_t *pglob, struct glob_lim *limitp)
{
    const Char *qpatnext;
    int c, err, oldpathc;
    Char *bufnext, patbuf[MAXPATHLEN];

    qpatnext = pattern;
    oldpathc = pglob->gl_pathc;
    bufnext = patbuf;

    /* We don't need to check for buffer overflow any more. */
    while ((c = *qpatnext++) != EOS) {
        switch (c) {
        case LBRACKET:
            c = *qpatnext;
            if (c == NOT) {
                ++qpatnext;
            }
            if (*qpatnext == EOS ||
                g_strchr(qpatnext + 1, RBRACKET) == NULL) {
                *bufnext++ = LBRACKET;
                if (c == NOT) {
                    --qpatnext;
                }
                break;
            }
            *bufnext++ = M_SET;
            if (c == NOT) {
                *bufnext++ = M_NOT;
            }
            c = *qpatnext++;
            do {
                *bufnext++ = CHAR(c);
                if (*qpatnext == RANGE &&
                    (c = qpatnext[1]) != RBRACKET) {
                    *bufnext++ = M_RNG;
                    *bufnext++ = CHAR(c);
                    qpatnext += 2;
                }
            } while ((c = *qpatnext++) != RBRACKET);
            pglob->gl_flags |= GLOB_MAGCHAR;
            *bufnext++ = M_END;
            break;
        case QUESTION:
            pglob->gl_flags |= GLOB_MAGCHAR;
            *bufnext++ = M_ONE;
            break;
        case STAR:
            pglob->gl_flags |= GLOB_MAGCHAR;
            /* collapse adjacent stars to one,
             * to avoid exponential behavior
             */
            if (bufnext == patbuf || bufnext[-1] != M_ALL) {
                *bufnext++ = M_ALL;
            }
            break;
        default:
            *bufnext++ = CHAR(c);
            break;
        }
    }
    *bufnext = EOS;

    if ((err = glob1(patbuf, patbuf+MAXPATHLEN - 1, pglob, limitp, 1)) != 0) {
        return err;
    }

    /*
     * If there was no match we are going to append the pattern
     * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
     * and the pattern did not contain any magic characters
     * GLOB_NOMAGIC is there just for compatibility with csh.
     */
    if (pglob->gl_pathc == oldpathc) {
        if ((pglob->gl_flags & GLOB_NOCHECK) ||
            ((pglob->gl_flags & GLOB_NOMAGIC) &&
                !(pglob->gl_flags & GLOB_MAGCHAR))) {
            return globextend(pattern, pglob, limitp, NULL);
        } else {
            return GLOB_NOMATCH;
        }
    }
    if (!(pglob->gl_flags & GLOB_NOSORT)) {
        if ((pglob->gl_flags & GLOB_KEEPSTAT)) {
            /* Keep the paths and stat info synced during sort */
            struct glob_path_stat *path_stat;
            int i;
            int n = pglob->gl_pathc - oldpathc;
            int o = pglob->gl_offs + oldpathc;

            if ((path_stat = calloc(n, sizeof(*path_stat))) == NULL) {
                return GLOB_NOSPACE;
            }
            for (i = 0; i < n; i++) {
                path_stat[i].gps_path = pglob->gl_pathv[o + i];
                path_stat[i].gps_stat = pglob->gl_statv[o + i];
            }
            qsort(path_stat, n, sizeof(*path_stat), compare_gps);
            for (i = 0; i < n; i++) {
                pglob->gl_pathv[o + i] = path_stat[i].gps_path;
                pglob->gl_statv[o + i] = path_stat[i].gps_stat;
            }
            free(path_stat);
        } else {
            qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
                  pglob->gl_pathc - oldpathc, sizeof(char *),
                  compare);
        }
    }
    return 0;
}

static int
compare(const void *p, const void *q)
{
    return strcmp(*(char **)p, *(char **)q);
}

static int
compare_gps(const void *_p, const void *_q)
{
    const struct glob_path_stat *p = (const struct glob_path_stat *)_p;
    const struct glob_path_stat *q = (const struct glob_path_stat *)_q;

    return strcmp(p->gps_path, q->gps_path);
}

static int
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, struct glob_lim *limitp,
      int recursion)
{
    Char pathbuf[MAXPATHLEN];

    /* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
    if (*pattern == EOS) {
        return 0;
    }
    return glob2(pathbuf, pathbuf + MAXPATHLEN - 1,
                 pathbuf, pathbuf + MAXPATHLEN - 1,
                 pattern, pattern_last, pglob, limitp, recursion);
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static int
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
      Char *pattern, Char *pattern_last, glob_t *pglob, struct glob_lim *limitp,
      int recursion)
{
    struct stat sb;
    Char *p, *q;
    int anymeta;

    /*
     * Loop over pattern segments until end of pattern or until
     * segment with meta character found.
     */
    for (anymeta = 0;;) {
        if (*pattern == EOS) {      /* End of pattern? */
            *pathend = EOS;
            if (g_lstat(pathbuf, &sb, pglob)) {
                return 0;
            }
            if (limitp->glim_stat++ >= pglob->gl_maxfiles) {
                errno = 0;
                *pathend++ = SEP;
                *pathend = EOS;
                return GLOB_NOSPACE;
            }

            if (((pglob->gl_flags & GLOB_MARK) &&
                 pathend[-1] != SEP) &&
                (S_ISDIR(sb.st_mode) ||
                    (S_ISLNK(sb.st_mode) &&
                        (g_stat(pathbuf, &sb, pglob) == 0) &&
                        S_ISDIR(sb.st_mode)))) {
                if (pathend + 1 > pathend_last) {
                    return 1;
                }
                *pathend++ = SEP;
                *pathend = EOS;
            }
            ++pglob->gl_matchc;
            return globextend(pathbuf, pglob, limitp, &sb);
        }

        /* Find end of next segment, copy tentatively to pathend. */
        q = pathend;
        p = pattern;
        while (*p != EOS && *p != SEP) {
            if (ismeta(*p)) {
                anymeta = 1;
            }
            if (q + 1 > pathend_last) {
                return 1;
            }
            *q++ = *p++;
        }

        if (!anymeta) {     /* No expansion, do next segment. */
            pathend = q;
            pattern = p;
            while (*pattern == SEP) {
                if (pathend + 1 > pathend_last) {
                    return 1;
                }
                *pathend++ = *pattern++;
            }
        } else {
            /* Need expansion, recurse. */
            return glob3(pathbuf, pathbuf_last, pathend,
                         pathend_last, pattern, p, pattern_last,
                         pglob, limitp, recursion + 1);
        }
    }
    /* NOTREACHED */
}

static int
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
      Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
      struct glob_lim *limitp, int recursion)
{
    struct dirent *dp;
    DIR *dirp;
    int err;
    char buf[MAXPATHLEN];

    /*
     * The readdirfunc declaration can't be prototyped, because it is
     * assigned, below, to two functions which are prototyped in glob.h
     * and dirent.h as taking pointers to differently typed opaque
     * structures.
     */
    struct dirent *(*readdirfunc)(void *);

    if (pathend > pathend_last) {
        return 1;
    }
    *pathend = EOS;
    errno = 0;

    if (recursion >= pglob->gl_maxdepth) {
        return GLOB_NOSPACE;
    }
    if ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
        /* TODO: don't call for ENOENT or ENOTDIR? */
        if (pglob->gl_errfunc) {
            if (g_Ctoc(pathbuf, buf, sizeof(buf))) {
                return GLOB_ABORTED;
            }
            if (pglob->gl_errfunc(buf, errno) ||
                pglob->gl_flags & GLOB_ERR) {
                return GLOB_ABORTED;
            }
        }
        return 0;
    }

    err = 0;

    /* Search directory for matching names. */
    if (pglob->gl_flags & GLOB_ALTDIRFUNC) {
        readdirfunc = pglob->gl_readdir;
    } else {
        readdirfunc = (struct dirent *(*)(void *))readdir;
    }
    while ((dp = (*readdirfunc)(dirp))) {
        unsigned char *sc;
        Char *dc;

        if (limitp->glim_readdir++ >= pglob->gl_maxfiles) {
            errno = 0;
            *pathend++ = SEP;
            *pathend = EOS;
            err = GLOB_NOSPACE;
            break;
        }

        /* Initial DOT must be matched literally. */
        if (dp->d_name[0] == DOT && *pattern != DOT) {
            continue;
        }
        dc = pathend;
        sc = (unsigned char *) dp->d_name;
        while (dc < pathend_last && (*dc++ = *sc++) != EOS)
            ;
        if (dc >= pathend_last) {
            *dc = EOS;
            err = 1;
            break;
        }

        if (!match(pathend, pattern, restpattern, pglob->gl_maxdepth)) {
            *pathend = EOS;
            continue;
        }
        err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
                    restpattern, restpattern_last, pglob, limitp, recursion);
        if (err) {
            break;
        }
    }

    if (pglob->gl_flags & GLOB_ALTDIRFUNC) {
        (*pglob->gl_closedir)(dirp);
    } else {
        closedir(dirp);
    }
    return err;
}

/*
 * Extend the gl_pathv member of a glob_t structure to accommodate a new item,
 * add the new item, and update gl_pathc.
 *
 * This assumes the BSD realloc, which only copies the block when its size
 * crosses a power-of-two boundary; for v7 realloc, this would cause quadratic
 * behavior.
 *
 * Return 0 if new item added, error code if memory couldn't be allocated.
 *
 * Invariant of the glob_t structure:
 *      Either gl_pathc is zero and gl_pathv is NULL; or gl_pathc > 0 and
 *      gl_pathv points to (gl_offs + gl_pathc + 1) items.
 */
static int
globextend(const Char *path, glob_t *pglob, struct glob_lim *limitp,
           struct stat *sb)
{
    char **pathv;
    ssize_t i;
    size_t newn, len;
    char *copy = NULL;
    const Char *p;
    struct stat **statv;

    newn = 2 + pglob->gl_pathc + pglob->gl_offs;
    if (pglob->gl_offs >= INT_MAX ||
        pglob->gl_pathc >= INT_MAX ||
        newn >= INT_MAX ||
        SIZE_MAX / sizeof(*pathv) <= newn ||
        SIZE_MAX / sizeof(*statv) <= newn) {
nospace:
        for (i = pglob->gl_offs; i < (ssize_t)(newn - 2); i++) {
            if (pglob->gl_pathv && pglob->gl_pathv[i]) {
                free(pglob->gl_pathv[i]);
            }
            if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
                pglob->gl_pathv && pglob->gl_pathv[i]) {
                free(pglob->gl_statv[i]);
            }
        }
        if (pglob->gl_pathv) {
            free(pglob->gl_pathv);
            pglob->gl_pathv = NULL;
        }
        if (pglob->gl_statv) {
            free(pglob->gl_statv);
            pglob->gl_statv = NULL;
        }
        return GLOB_NOSPACE;
    }

    pathv = realloc(pglob->gl_pathv, newn * sizeof(*pathv));
    if (pathv == NULL) {
        goto nospace;
    }
    if (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
        /* first time around -- clear initial gl_offs items */
        pathv += pglob->gl_offs;
        for (i = pglob->gl_offs; --i >= 0; ) {
            *--pathv = NULL;
        }
    }
    pglob->gl_pathv = pathv;

    if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
        statv = realloc(pglob->gl_statv, newn * sizeof(*statv));
        if (statv == NULL) {
            goto nospace;
        }
        if (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
            /* first time around -- clear initial gl_offs items */
            statv += pglob->gl_offs;
            for (i = pglob->gl_offs; --i >= 0; ) {
                *--statv = NULL;
            }
        }
        pglob->gl_statv = statv;
        if (sb == NULL) {
            statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
        } else {
            limitp->glim_malloc += sizeof(**statv);
            if (limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
                errno = 0;
                return GLOB_NOSPACE;
            }
            if ((statv[pglob->gl_offs + pglob->gl_pathc] =
                 malloc(sizeof(**statv))) == NULL) {
                goto copy_error;
            }
            memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
                   sizeof(*sb));
        }
        statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
    }

    for (p = path; *p++;)
        ;
    len = (size_t)(p - path);
    limitp->glim_malloc += len;
    if ((copy = malloc(len)) != NULL) {
        if (g_Ctoc(path, copy, len)) {
            free(copy);
            return GLOB_NOSPACE;
        }
        pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
    }
    pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

    if ((newn * sizeof(*pathv)) + limitp->glim_malloc > GLOB_LIMIT_MALLOC) {
        errno = 0;
        return GLOB_NOSPACE;
    }
copy_error:
    return copy == NULL ? GLOB_NOSPACE : 0;
}

/*
 * pattern matching function for filenames.  Each occurrence of the *
 * pattern causes a recursion level.
 */
static int
match(Char *name, Char *pat, Char *patend, int recur)
{
    int ok, negate_range;
    Char c, k;

    if (recur-- == 0) {
        return GLOB_NOSPACE;
    }
    while (pat < patend) {
        c = *pat++;
        switch (c & M_MASK) {
        case M_ALL:
            while (pat < patend && (*pat & M_MASK) == M_ALL) {
                pat++;  /* eat consecutive '*' */
            }
            if (pat == patend) {
                return 1;
            }
            do {
                if (match(name, pat, patend, recur)) {
                    return 1;
                }
            } while (*name++ != EOS);
            return 0;
        case M_ONE:
            if (*name++ == EOS) {
                return 0;
            }
            break;
        case M_SET:
            ok = 0;
            if ((k = *name++) == EOS) {
                return 0;
            }
            if ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS) {
                ++pat;
            }
            while (((c = *pat++) & M_MASK) != M_END) {
                if ((*pat & M_MASK) == M_RNG) {
                    if (c <= k && k <= pat[1]) {
                        ok = 1;
                    }
                    pat += 2;
                } else if (c == k) {
                    ok = 1;
                }
            }
            if (ok == negate_range) {
                return 0;
            }
            break;
        default:
            if (*name++ != c) {
                return 0;
            }
            break;
        }
    }
    return *name == EOS;
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
    int i;
    char **pp;

    if (pglob->gl_pathv != NULL) {
        pp = pglob->gl_pathv + pglob->gl_offs;
        for (i = pglob->gl_pathc; i--; ++pp) {
            if (*pp) {
                free(*pp);
            }
        }
        free(pglob->gl_pathv);
        pglob->gl_pathv = NULL;
    }
    if (pglob->gl_statv != NULL) {
        for (i = 0; i < pglob->gl_pathc; i++) {
            if (pglob->gl_statv[i] != NULL) {
                free(pglob->gl_statv[i]);
            }
        }
        free(pglob->gl_statv);
        pglob->gl_statv = NULL;
    }
}

static DIR *
g_opendir(Char *str, glob_t *pglob)
{
    char buf[MAXPATHLEN];

    if (!*str) {
        buf[0] = '.';
        buf[1] = 0;
    } else {
        if (g_Ctoc(str, buf, sizeof(buf))) {
            return NULL;
        }
    }

    if (pglob->gl_flags & GLOB_ALTDIRFUNC) {
        return (*pglob->gl_opendir)(buf);
    }

    return opendir(buf);
}

static int
g_lstat(Char *fn, struct stat *sb, glob_t *pglob)
{
    char buf[MAXPATHLEN];

    if (g_Ctoc(fn, buf, sizeof(buf))) {
        return -1;
    }
    if (pglob->gl_flags & GLOB_ALTDIRFUNC) {
        return (*pglob->gl_lstat)(buf, sb);
    }
    return lstat(buf, sb);
}

static int
g_stat(Char *fn, struct stat *sb, glob_t *pglob)
{
    char buf[MAXPATHLEN];

    if (g_Ctoc(fn, buf, sizeof(buf))) {
        return -1;
    }
    if (pglob->gl_flags & GLOB_ALTDIRFUNC) {
        return (*pglob->gl_stat)(buf, sb);
    }
    return stat(buf, sb);
}

static Char *
g_strchr(const Char *str, int ch)
{
    do {
        if (*str == ch) {
            return (Char *)str;
        }
    } while (*str++);
    return NULL;
}

static int
g_Ctoc(const Char *str, char *buf, unsigned int len)
{
    while (len--) {
        if ((*buf++ = *str++) == EOS) {
            return 0;
        }
    }
    return 1;
}

#else
extern signed char v6ready;
#endif
