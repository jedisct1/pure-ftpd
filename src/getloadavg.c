#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef HAVE_GETLOADAVG

int getloadavg(double loadavg[], int nelem)
{
    if (nelem <= 0) {
        return 0;
    }
    do {
        nelem--;
        loadavg[nelem] = 0.0;
    } while (nelem != 0);
    
    return nelem;
}

#endif
