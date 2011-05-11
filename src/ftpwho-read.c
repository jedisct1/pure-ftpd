#include <config.h>

#ifdef PER_USER_LIMITS
# include "ftpd.h"
# include "ftpwho-update.h"
# include "globals.h"
# include "ftpwho-read.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

static int checkproc(const pid_t proc)
{    
    return kill(proc, 0) == 0 || errno == EPERM;
}

static int scoreboard_cleanup(const char * const file)
{
    pid_t pid;
    
    if (strlen(file) <= sizeof SCOREBOARD_PREFIX) {
        return -1;
    }    
    pid = (pid_t) strtoul(file + sizeof SCOREBOARD_PREFIX, NULL, 10);
    if (checkproc(pid) == 0) {
        (void) unlink(file);
        return -1;
    }
    return 0;
}

unsigned int ftpwho_read_count(const char * const user)
{
    int fd;
    unsigned int count = 0;
    DIR *dir;
    struct dirent *entry;
    char foundaccount[MAX_USER_LENGTH + 1U];
    
    if (chdir(SCOREBOARD_PATH) != 0 || (dir = opendir(".")) == NULL) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, SCOREBOARD_PREFIX,
		    sizeof SCOREBOARD_PREFIX - 1U) != 0 ||
            scoreboard_cleanup(entry->d_name) != 0 ||
            (fd = open(entry->d_name, O_RDONLY | O_NOFOLLOW)) == -1) {
            continue;
        }
        /*
         * If the client wants to send signals in order to get [p]read()
         * interrupted, choose the secure option of counting extra
         * connections. lseek() can't be interrupted, though.
         */
# ifdef HAVE_PREAD            
        if (pread(fd, foundaccount, sizeof foundaccount,
                  offsetof(FTPWhoEntry, account)) != sizeof foundaccount) {
            count++;
            goto nextone_close;
        }
# else
        if (lseek(fd, (off_t) offsetof(FTPWhoEntry, account), SEEK_SET) ==
            (off_t) -1) {
            goto nextone_close;
        }
        if (read(fd, foundaccount, sizeof foundaccount) != 
            sizeof foundaccount) {
            count++;
            goto nextone_close;
        }        
# endif
        foundaccount[(sizeof foundaccount) - 1] = 0;
        if (strcasecmp(foundaccount, user) == 0 && count < UINT_MAX) {
            count++;
        }        
        nextone_close:
        (void) close(fd);
    }
    closedir(dir);
# ifdef DEBUG
    addreply(0, "The [%s] account is already logged %u time%c", user, count,
         count > 0 ? 's' : 0);
# endif
    return count;
}

#else
extern signed char v6ready;
#endif
