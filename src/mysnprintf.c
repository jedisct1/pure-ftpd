#include <config.h>

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
# include <stdarg.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/types.h>
#include "mysnprintf.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#ifdef SNPRINTF_IS_BOGUS
int workaround_snprintf(char *str, size_t size, const char *format, ...)
{
    int v;
    int r = 0;
    
    va_list va;    
    va_start(va, format);    
    v = vsnprintf(str, size, format, va);
    if (v < 0 || (ssize_t) v >= (ssize_t) size) {
        r--;
    }
    va_end(va);
    
    return r;
}
#endif
