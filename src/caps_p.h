#ifndef __CAPS_P_H__
#define __CAPS_P_H__ 1

#ifdef USE_CAPABILITIES
# ifdef HAVE_SYS_CAPABILITY_H
#  include <sys/capability.h>
# endif

cap_value_t cap_keep_startup[] = {
# if defined(USE_PAM) && defined(CAP_AUDIT_WRITE)
    CAP_AUDIT_WRITE,
# endif
    CAP_SETGID,
    CAP_SETUID,
    CAP_CHOWN,
    CAP_NET_BIND_SERVICE,
    CAP_SYS_CHROOT,
    CAP_SYS_NICE,
    CAP_DAC_READ_SEARCH
};

cap_value_t cap_keep_login[] = {
# ifdef WITHOUT_PRIVSEP
    CAP_SETUID,
    CAP_NET_BIND_SERVICE
# endif
};

#endif

#endif
