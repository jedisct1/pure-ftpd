#include <config.h>

#include "ftpd.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif


static void usage(void)
{
    puts("Usage: pure-statsdecode [stats log file] [-]");
}

int main(int argc, char *argv[])
{
    int instamp = 0;
    int c;
    const char *file;
    FILE *fp;
    time_t date;
    struct tm *tm;
    char timestamp[42];    
    
    if (argc != 2) {
        usage();
        return 1;
    }
    
#ifdef HAVE_SETLOCALE
# ifdef LC_MESSAGES
    (void) setlocale(LC_MESSAGES, "");
# endif
# ifdef LC_CTYPE
    (void) setlocale(LC_CTYPE, "");
# endif
# ifdef LC_COLLATE
    (void) setlocale(LC_COLLATE, "");
# endif
#endif            
    
    file = argv[1];
    if (*file == '-' && file[1] == 0) {
        fp = stdin;
    } else {
        if ((fp = fopen(file, "r")) == NULL) {
            perror("Can't open file: ");
            return -1;
        }
    }
    while ((c = getc(fp)) != EOF) {
        if (instamp >= 0) {
            if (isdigit(c)) {
                if (instamp < (int) (sizeof timestamp - 1U)) {
                    timestamp[instamp] = (char) c;
                    instamp++;
                }
            } else {
                timestamp[instamp] = 0;
                instamp = -1;
                date = (time_t) strtoul(timestamp, NULL, 10);
                tm = localtime(&date);
                printf("%d/%02d/%02d %02d:%02d:%02d ",
                       tm->tm_year + 1900,
                       tm->tm_mon + 1,
                       tm->tm_mday,
                       tm->tm_hour,
                       tm->tm_min,
                       tm->tm_sec);
            }
        } else {
            if (c == '\n' || !ISCTRLCODE(c)) {
                putchar(c);
            }
        }
        if (c == '\n') {
            fflush(fp);
            instamp = 0;
        }        
    }
    fclose(fp);
    
    return 0;
}
