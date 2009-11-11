#include <config.h>
#include "ftpd.h"

int main(int argc, char *argv[])
{
    return pureftpd_start(argc, argv, NULL);
}
