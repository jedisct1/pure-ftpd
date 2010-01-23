#ifndef __BONJOUR_H__
#define __BONJOUR_H__ 1

#ifdef WITH_BONJOUR

# ifdef __APPLE_CC__
#  include <CoreFoundation/CoreFoundation.h>
# endif

void doregistration(const char* name, unsigned long port);
void refreshManager(void);

#endif /* WITH_BONJOUR */

#endif
