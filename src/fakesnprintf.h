#ifndef __FAKESNPRINTF_H__
#define __FAKESNPRINTF_H__ 1

#if !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

int fakesnprintf_vsnprintf(char * const str_, const size_t size_,
                           const char *format, va_list va);

int fakesnprintf_snprintf(char * const str, const size_t size, 
                          const char * const format, ...);

# define snprintf  fakesnprintf_snprintf
# define vsnprintf fakesnprintf_vsnprintf

# ifdef CONF_SNPRINTF_TYPE
#  undef CONF_SNPRINTF_TYPE
# endif
# define CONF_SNPRINTF_TYPE 4

#endif

#endif                            /* FAKESNPRINTF_H */
