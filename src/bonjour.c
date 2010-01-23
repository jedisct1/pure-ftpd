#include <config.h>

#ifdef WITH_BONJOUR
# include "ftpd.h"
# include "bonjour.h"
# include <dns_sd.h>
# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

static DNSServiceRef service_ref;

static void reg_reply(DNSServiceRef sdRef, DNSServiceFlags flags,
                      DNSServiceErrorType errorCode,
                      const char *name,
                      const char *regtype,
                      const char *domain,
                      void *context)
{
    (void) sdRef;
    (void) flags;
    (void) errorCode;
    (void) name;
    (void) regtype;
    (void) domain;
    (void) context;
}

void doregistration(const char *name, unsigned long port)
{    
    DNSServiceRegister(&service_ref, 0, 0, name, "_ftp._tcp.", NULL, NULL,
                       port, 0, NULL,
                       reg_reply,
                       NULL);
}

# ifdef __APPLE_CC__
void refreshManager(void)
{
    CFStringRef observedObject = CFSTR("org.pureftpd.osx");
    CFNotificationCenterRef center =
        CFNotificationCenterGetDistributedCenter();
    CFNotificationCenterPostNotification(center,
                                         CFSTR("refreshStatus"),
                                         observedObject,
                                         NULL /* no dictionary */,
                                         TRUE);
}
# else
void refreshManager(void)
{
    /* ... */
}
# endif

#else
extern signed char v6ready;
#endif
