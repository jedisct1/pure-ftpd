#include <config.h>

#if defined(WITH_UPLOAD_SCRIPT)
# include "ftpd.h"
# include "ftpwho-update.h"
# include "globals.h"
# include "upload-pipe.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

int upload_pipe_open(void)
{
    struct stat st;

    upload_pipe_close();
    
    anew:
    if ((upload_pipe_lock = 
         open(UPLOAD_PIPE_LOCK,
              O_CREAT | O_RDWR | O_NOFOLLOW, (mode_t) 0600)) == -1) {
        unlink(UPLOAD_PIPE_LOCK);
        return -1;
    }    
    if (fstat(upload_pipe_lock, &st) < 0 ||
        (st.st_mode & 0777) != 0600 || !S_ISREG(st.st_mode) ||
# ifdef NON_ROOT_FTP
        st.st_uid != geteuid()        
# else
        st.st_uid != (uid_t) 0
# endif
        ) {
        return -1;
    }    
    if (lstat(UPLOAD_PIPE_LOCK, &st) < 0 ||
        (st.st_mode & 0777) != 0600 || !S_ISREG(st.st_mode) ||
# ifdef NON_ROOT_FTP
        st.st_uid != geteuid()
# else
        st.st_uid != (uid_t) 0
# endif
        ) {
        unlink(UPLOAD_PIPE_LOCK);
        goto anew;
    }        
    anew2:
    if ((upload_pipe_fd =
         open(UPLOAD_PIPE_FILE, O_WRONLY | O_NOFOLLOW)) == -1) {
        if (mkfifo(UPLOAD_PIPE_FILE, (mode_t) 0600) < 0) {
            return -1;
        }
        goto anew2;
    }
    if (fstat(upload_pipe_fd, &st) < 0 ||
        (st.st_mode & 0777) != 0600 || !S_ISFIFO(st.st_mode) ||
# ifdef NON_ROOT_FTP
        st.st_uid != geteuid()
# else
        st.st_uid != (uid_t) 0
# endif
        ) {
        return -1;                       /* Don't fight, I'm too old for that */
    }
    if (lstat(UPLOAD_PIPE_FILE, &st) < 0 ||
        (st.st_mode & 0777) != 0600 || !S_ISFIFO(st.st_mode) ||
# ifdef NON_ROOT_FTP
        st.st_uid != geteuid()
# else
        st.st_uid != (uid_t) 0
# endif        
        ) {
        unlink(UPLOAD_PIPE_FILE);       /* Okay, fight a bit :) */
        goto anew2;
    }
    
    return upload_pipe_fd;
}

/* File is already prefixed by \001 */

int upload_pipe_push(const char *vuser, const char *file)
{    
    struct flock lock;
    const char starter = 2;
    
    if (upload_pipe_lock == -1 || upload_pipe_fd == -1 ||
        file == NULL || *file == 0) {
        return 0;
    }
    lock.l_whence = SEEK_SET;
    lock.l_start = (off_t) 0;
    lock.l_len = (off_t) 0;
    lock.l_pid = getpid();
    lock.l_type = F_WRLCK;
    while (fcntl(upload_pipe_lock, F_SETLKW, &lock) < 0) {
        if (errno != EINTR) {
            return -1;
        }        
    }
    (void) safe_write(upload_pipe_fd, &starter, (size_t) 1U);
    (void) safe_write(upload_pipe_fd, vuser, strlen(vuser));
    (void) safe_write(upload_pipe_fd, file, strlen(file) + (size_t) 1U);
    lock.l_type = F_UNLCK;
    while (fcntl(upload_pipe_lock, F_SETLK, &lock) < 0 && errno == EINTR);
    
    return 0;
}

void upload_pipe_close(void)
{
    if (upload_pipe_fd != -1) {
        close(upload_pipe_fd);
        upload_pipe_fd = -1;
    }
    if (upload_pipe_lock != -1) {
        close(upload_pipe_lock);
        upload_pipe_lock = -1;
    }
}
#else
extern signed char v6ready;
#endif
