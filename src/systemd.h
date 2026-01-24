#ifndef __SYSTEMD_H__
#define __SYSTEMD_H__ 1

int systemd_init = 0;
struct timeval sd_notify_timeout = { 10, 0 };
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#endif
