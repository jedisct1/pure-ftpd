#ifndef __MYSNPRINTF_H__
#define __MYSNPRINTF_H__ 1

int workaround_snprintf(char *str, size_t size, const char *format, ...);

#ifndef HAVE_SNPRINTF
# include "fakesnprintf.h"
#endif
#ifdef CONF_SNPRINTF_TYPE
# if CONF_SNPRINTF_TYPE == 8
#  define SNPRINTF_C99 1
# elif CONF_SNPRINTF_TYPE <= 0
#  define SNPRINTF_OLD 1
#  define SNPRINTF_IS_BOGUS 1
# else
#  define SNPRINTF_IS_BOGUS 1
# endif
#else
# warning Unknown snprintf() type
# define SNPRINTF_IS_BOGUS 1
#endif

#if CONF_SNPRINTF_TYPE < 0
# define SNCHECK(CALL, SIZE) ((CALL) < 0)
#elif defined(SNPRINTF_IS_BOGUS) || !defined(SNPRINTF_C99) || \
   CONF_SNPRINTF_TYPE == 4 || CONF_SNPRINTF_TYPE == 8
# define SNCHECK(CALL, SIZE) ((CALL) >= ((int) (SIZE)))
#else
# define SNCHECK(CALL, SIZE) (workaround_ ## CALL)
#endif

#endif
