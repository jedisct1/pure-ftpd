#include <config.h>

#ifdef FTPWHO
# include "ftpd.h"
# include "ftpwho-update_p.h"
# include "ftpwho-update.h"
# include "globals.h"
# ifdef WITH_PRIVSEP
#  include "privsep.h"
# endif

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

void ftpwho_exit(const int ret)
{
# ifndef HAVE_SYS_FSUID_H
    disablesignals();
# endif
    if (shm_data_cur != NULL) {
        shm_data_cur->state = FTPWHO_STATE_FREE;
        if (
# ifndef NO_INETD
            standalone == 0 && 
# endif
            chrooted != 0) {
            (void) msync((void *) shm_data_cur, sizeof (FTPWhoEntry), MS_ASYNC);
        }
        (void) munmap((void *) shm_data_cur, sizeof (FTPWhoEntry));
    }
    if (mmap_fd != -1) {    
        (void) close(mmap_fd);
    }
# ifdef WITH_PRIVSEP
    if (
# ifndef NO_INETD        
        standalone == 0 &&
# endif
        scoreboardfile != NULL) {
        (void) privsep_removeftpwhoentry();
    }
# else
    if (
#  ifndef NO_INETD
        standalone == 0 &&
#  endif
        chrooted == 0 && scoreboardfile != NULL) {
#  ifndef NON_ROOT_FTP
#   ifndef HAVE_SYS_FSUID_H        
        (void) seteuid((uid_t) 0);
#   else
        (void) setfsuid((uid_t) 0);
#   endif
#  endif
        (void) unlink(scoreboardfile);
    }
#endif
    _exit(ret);
}

void ftpwho_unlock(void) 
{
#if defined(__OpenBSD__) || defined(__ekkoBSD__)
    (void) msync(shm_data_cur, NULL, MS_ASYNC);
#endif
    lock.l_type = F_UNLCK;
    while (fcntl(mmap_fd, F_SETLK, &lock) < 0) {
        if (errno != EINTR) {
            return;
        }    
    }
}

void ftpwho_lock(void)
{
    lock.l_type = F_WRLCK;
    while (fcntl(mmap_fd, F_SETLKW, &lock) < 0) {
        if (errno != EINTR) {
            return;
        }    
    }    
}

#ifndef NO_STANDALONE
void ftpwho_unlinksbfile(const pid_t pid)
{
    size_t sbfile_size;
    char *sbfile;
    
    sbfile_size = sizeof SCOREBOARD_PATH - 1U + 1U +
        sizeof SCOREBOARD_PREFIX - 1U + 8U + 1U;
        
    if ((sbfile = ALLOCA(sbfile_size)) == NULL) {
        return;
    }
    if (SNCHECK(snprintf(sbfile, sbfile_size, 
                         SCOREBOARD_PATH "/" SCOREBOARD_PREFIX "%08lu",
                         (unsigned long) pid), sbfile_size)) {
        ALLOCA_FREE(sbfile);
        return;
    }    
    (void) unlink(sbfile);
    ALLOCA_FREE(sbfile);
}
#endif

int ftpwho_initwho(void)
{
    int fd;
    size_t scoreboardfile_size;
    struct stat st;    
    
    shm_data_cur = NULL;
    if ((fd = open(SCOREBOARD_PATH, O_RDONLY | O_DIRECTORY)) == -1) {
        if (mkdir(SCOREBOARD_PATH, (mode_t) 0700) != 0) {
            return -1;
        }
    } else {        
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
#ifdef NON_ROOT_FTP
            st.st_uid != geteuid()
#else
            st.st_uid != (uid_t) 0
#endif
            ) {
            close(fd);
            return -1;
        }
        if ((st.st_mode & 0777) != 0700) {
            if (fchmod(fd, 0700) != 0) {
                close(fd);
                return -1;
            }
        }
    }
    close(fd);
    scoreboardfile_size = sizeof SCOREBOARD_PATH - 1U + 1U +
        sizeof SCOREBOARD_PREFIX - 1U + 8U + 1U;
    if ((scoreboardfile = malloc(scoreboardfile_size)) == NULL) {
        return -1;
    }
    if (SNCHECK(snprintf(scoreboardfile, scoreboardfile_size, 
                         SCOREBOARD_PATH "/" SCOREBOARD_PREFIX "%08lu",
                         (unsigned long) getpid()), scoreboardfile_size)) {
        err:
        free(scoreboardfile);
        scoreboardfile = NULL;
        
        return -1;
    }
    /* 
     * Don't truncate: it's faster to reuse.
     * Don't check for any lock: we could get a deadlock.
     */
    if ((mmap_fd = open(scoreboardfile, 
                       O_RDWR | O_CREAT | O_NOFOLLOW, 0600)) == -1) {
        goto err;
    }
    if (fstat(mmap_fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0600) != 0600 ||
#ifdef NON_ROOT_FTP
        st.st_uid != geteuid()
#else
        st.st_uid != (uid_t) 0
#endif
        ) {
        err2:
        close(mmap_fd);
        goto err;
    }
    if (lseek(mmap_fd, (off_t) (sizeof (FTPWhoEntry) - 1U), 
              SEEK_SET) == (off_t) -1) {
        goto err2;
    }
    while (write(mmap_fd, "", (size_t) 1U) < 0 && 
           (errno == EAGAIN || errno == EINTR));
    lock.l_whence = SEEK_SET;
    lock.l_start = (off_t) 0;
    lock.l_len = (off_t) 0;
    lock.l_pid = getpid();
    if ((shm_data_cur = (FTPWhoEntry *) mmap(NULL, sizeof (FTPWhoEntry),
                                             PROT_WRITE | PROT_READ,
                                             MAP_SHARED | MAP_FILE, 
                                             mmap_fd, (off_t) 0)) == NULL) {
        goto err2;
    }
    return 0;
}

#else
extern signed char v6ready;
#endif
