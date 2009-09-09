#ifndef __GETLOADAVG_H__
#define __GETLOADAVG_H__ 1

#ifndef HAVE_GETLOADAVG
int getloadavg(double loadavg[], int nelem);
#endif

#endif
