#include <config.h>

#ifdef USE_CAPABILITIES

/* sys/capability.h and sys/vfs.h both define struct statfs */
#define STATFS_ALREADY_DEFINED 1

#include "ftpd.h"
#include "messages.h"
#include "caps_p.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void apply_caps(cap_value_t * const ncaps,
                       const size_t ncaps_size)
{
#ifndef NON_ROOT_FTP
    cap_t caps;

    if (geteuid() != (uid_t) 0U) {
        return;
    }
    if ((caps = cap_init()) == (cap_t) 0 ||
        cap_clear(caps) == -1 ||
        cap_set_flag(caps, CAP_PERMITTED, ncaps_size, ncaps, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_EFFECTIVE, ncaps_size, ncaps, CAP_SET) == -1 ||
        cap_set_proc(caps) == -1 ||
        cap_free(caps) == -1) {
        die(421, LOG_ERR, MSG_CAPABILITIES " : %s" , strerror(errno));
    }
#else
    (void) ncaps;
    (void) ncaps_size;
#endif    
}

void drop_login_caps(void)
{
    apply_caps(cap_keep_login,
               sizeof(cap_keep_login) / sizeof(cap_value_t));
}

void set_initial_caps(void)
{
    apply_caps(cap_keep_startup,
               sizeof(cap_keep_startup) / sizeof(cap_value_t));
}
#else
extern signed char v6ready;
#endif
