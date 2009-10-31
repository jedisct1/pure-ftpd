/*
 * snprintf() / vsnprintf() re-implementation by Frank Denis <j at pureftpd dot org>
 *
 * These functions understand :
 * - characters ("%c") .
 * - space padding ("%3d", "%-3s") .
 * - zero padding ("%04d") .
 * - explicit '+' ("%+d", "%+3.2f") .
 * - length restrictions ("%.30s", "%-42.30s", "%.4d") .
 * - int, long, long long types ("%lld", "%-3ld", "%i") .
 * - unsigned int, long, long long types ("%llu", "%-3lu", "%u") .
 * - hex and octal unsigned types ("%llX", "%04x", "%-3o") .
 * - double and long double types ("%f", "%Lf") .
 * - floating point frac restrictions ("%.2f") .
 * - combinations of everything ("%-8.5llo") .
 * 
 * Nothing more. Return value is <size> if an overflow occured, or the
 * copied size if no overflow occured (mostly compatible with C99
 * snprintf() behavior, except that it doesn't return any value larger
 * than <size>).
 *
 * These functions are portable, they are twice faster than their BSD and GNU
 * implementations, and they don't tamper with errno. But they only know
 * a limited subset of what a full-implementation is supposed to do.
 *
 * It's enough for Pure-FTPd, though.
 */

#include <config.h>

#include "ftpd.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#if !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

/*
 * add a string to the buffer
 * \param zero if this is non-zero, we pad with zeroes, else we pad
 * with a blank.
 * \param maxlen sets the maximum size of the string to be added
 */

static void fakesnprintf_addstr(char **str, size_t *size, const char *pnt,
                                size_t maxlen, size_t padlen,
                                unsigned char zero, unsigned char minuspad)
{
    size_t maxlenc;

    /* prepare to cut off string if longer than maxlen */
    maxlenc = strlen(pnt);
    if (maxlen > 0U && maxlen < maxlenc) {
        maxlenc = maxlen;
    }
    if (padlen > 0U && minuspad == 0U && padlen > maxlenc) {
        size_t maxlenp = padlen - maxlenc;
        
        if (maxlenp > *size) {
            maxlenp = *size;
        }
        if (maxlenp > 0U) {
            memset(*str, zero != 0 ? '0' : ' ', maxlenp);
            (*size) -= maxlenp;
            (*str) += maxlenp;
        }
    }
    if (maxlenc > *size) {
        maxlenc = *size;
    }
    if (maxlenc > 0U) {
        memcpy(*str, pnt, maxlenc);
        (*size) -= maxlenc;
        (*str) += maxlenc;
    }
    if (padlen > 0U && minuspad > 0U && padlen > maxlenc) {
        size_t maxlenp = padlen - maxlenc;
        
        if (maxlenp > *size) {
            maxlenp = *size;
        }
        if (maxlenp > 0U) {
            memset(*str, ' ', maxlenp);
            (*size) -= maxlenp;
            (*str) += maxlenp;
        }
    }
}

int fakesnprintf_vsnprintf(char * const str_, const size_t size_,
                           const char *format, va_list va)
{
    char *str;
    size_t size;
    size_t maxlen;
    size_t padlen;    
    unsigned char longs;
    unsigned char zero;
    unsigned char minuspad;
    unsigned char hasmaxlen;
    unsigned char plussign;

    str = str_;
    size = size_;
    str_[size_ - 1U] = 1;
    while (size > 0U && *format != 0) {
        if (*format != '%') {
            *str++ = *format++;
            size--;
            continue;
        }
        longs = 0U;
        zero = 0U;
        minuspad = 0U;
        maxlen = 0U;
        padlen = 0U;
        hasmaxlen = 0U;
        plussign = 0U;
        
        for (;;) {
            breakpoint_nextspecial_inc:
            format++;
            breakpoint_nextspecial_noinc:
            switch (*format) {
            case 0:
                goto breakpoint_end;
            case '%':
                *str++ = '%';
                size--;
                goto breakpoint_next;
            case 'c': {
                int val;
                
                val = va_arg(va, int);
                *str++ = (char) val;
                size--;
                goto breakpoint_next;
            }
            case 'l': case 'L':
                longs++;
                goto breakpoint_nextspecial_inc;
            case '0':
                zero++;
                goto breakpoint_nextspecial_inc;
            case '.':
                format++;
                hasmaxlen = 1U;
                while ((unsigned char) *format >= '0' && 
                       (unsigned char) *format <= '9') {
                    maxlen *= 10U;
                    maxlen += (*format - '0');
                    format++;
                }
                goto breakpoint_nextspecial_noinc;
            case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9':
                do {
                    padlen *= 10U;
                    padlen += *format - '0';
                    format++;
                } while ((unsigned char) *format >= '0' && 
                         (unsigned char) *format <= '9');
                goto breakpoint_nextspecial_noinc;
            case '-':
                minuspad++;
                format++;
                goto breakpoint_nextspecial_noinc;
            case '+':
                plussign++;
                format++;
                goto breakpoint_nextspecial_noinc;                
            case 's': {
                const char *pnt;
                
                pnt = va_arg(va, const char *);
                if (pnt == NULL) {
                    pnt = "<NULL>";
                }
                fakesnprintf_addstr(&str, &size, pnt, maxlen, padlen,
                                    zero, minuspad);
                goto breakpoint_next;
            }
            case 'u': case 'o': case 'x': case 'X': {
                unsigned long long val;
                char vals[256];
                char *valspnt = vals + sizeof vals;
                const char *basics;
                unsigned int base;
                
                switch (longs) {
                case 2:
                    val = va_arg(va, unsigned long long);
                    break;
                case 1:
                    val = (unsigned long long) va_arg(va, unsigned long);
                    break;
                default:
                    val = (unsigned long long) va_arg(va, unsigned int);
                }
                basics = "0123456789abcdef";
                switch (*format) {
                case 'o':
                    base = 8U;
                    break;
                case 'X':
                    basics = "0123456789ABCDEF";
                case 'x':
                    base = 16U;
                    break;
                default:
                    base = 10U;
                }
                *--valspnt = 0;
                do {
                    *--valspnt = basics[val % base];
                    val /= base;
                } while (valspnt != &vals[0] && val > 0ULL);
                fakesnprintf_addstr(&str, &size, valspnt, maxlen, padlen,
                                    zero, minuspad);
                goto breakpoint_next;
            }
            case 'd': case 'i': {
                long long val;
                unsigned char minussign = 0U;
                char vals[256];
                char *valspnt = vals + sizeof vals;
                
                switch (longs) {
                case 2:
                    val = va_arg(va, long long);
                    break;
                case 1:
                    val = (long long) va_arg(va, long);
                    break;
                default:
                    val = (long long) va_arg(va, int);
                }
                if (val < 0LL) {
                    minussign++;
                    val = -val;
                }
                *--valspnt = 0;
                do {
                    *--valspnt = "0123456789"[val % 10LL];
                    val /= 10LL;
                } while (valspnt != &vals[1] && val > 0LL);
                if (minussign != 0) {
                    *--valspnt = '-';
                } else if (plussign != 0) {
                    *--valspnt = '+';
                }
                fakesnprintf_addstr(&str, &size, valspnt, maxlen, padlen,
                                    zero, minuspad);
                goto breakpoint_next;
            }
            case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': {
                unsigned int nfrac = 6U;
                long double val;
                unsigned long long vali;
                unsigned char minussign = 0U;
                char vals[512];
                char *valspnt = vals + sizeof vals / 2U;
                char *valsleft;
                
                if (longs != 0) {
                    val = va_arg(va, long double);
                } else {
                    val = va_arg(va, double);
                }
                if (val < 0.0L) {
                    minussign++;
                    val = -val;
                }
                vali = (unsigned long long) val;
                do {
                    *--valspnt = '0' + vali % 10ULL;
                    vali /= 10ULL;
                } while (valspnt != &vals[1] && vali > 0ULL);
                if (minussign != 0) {
                    *--valspnt = '-';
                } else if (plussign != 0) {
                    *--valspnt = '+';
                }
                valsleft = valspnt;
                valspnt = vals + sizeof vals / 2U;
                if (maxlen > (sizeof vals / 2U) - 3U) {
                    nfrac = (sizeof vals / 2U) - 3U;
                } else if (hasmaxlen != 0U) {
                    nfrac = maxlen;
                }
                if (nfrac > 0U) {
                    *valspnt++ = '.';
                }                
                while (nfrac > 0U) {
                    nfrac--;
                    val *= 10.0L;
                    *valspnt++ = '0' + (((unsigned long long) val) % 10U);
                }
                *valspnt = 0;
                fakesnprintf_addstr(&str, &size, valsleft, sizeof vals,
                                    padlen, zero, minuspad);
                goto breakpoint_next;
            }
            }
        }
        breakpoint_next:
        format++;
    }
    breakpoint_end:
    if (str_[size_ - 1U] != 1) {
        str_[size_ - 1U] = 0;
        return (int) size_;
    }
    *str = 0;
    
    return (int) (size_ - size);
}

int fakesnprintf_snprintf(char * const str, const size_t size,
                          const char * const format, ...)
{
    int ret;
    va_list va;
    
    va_start(va, format);
    ret = fakesnprintf_vsnprintf(str, size, format, va);
    va_end(va);
    
    return ret;
}

#endif                          /* !HAVE_SNPRINTF */
