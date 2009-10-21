#ifndef __FTPWHO_UPDATE_H__
#define __FTPWHO_UPDATE_H__ 1

#ifdef FTPWHO

# ifdef NON_ROOT_FTP
#  define SCOREBOARD_PATH CONFDIR "/pure-ftpd-ftpwho"
# else
#  define SCOREBOARD_PATH STATEDIR "/run/pure-ftpd"
# endif
#define SCOREBOARD_PREFIX "client-"

typedef enum {
    FTPWHO_STATE_FREE = 0,                    /* must be first (0) */
        FTPWHO_STATE_IDLE, FTPWHO_STATE_DOWNLOAD, FTPWHO_STATE_UPLOAD
} FTPWhoEntryState;

typedef struct FTPWhoEntry_ {
    FTPWhoEntryState state;        
    pid_t pid;
    struct sockaddr_storage addr;
    struct sockaddr_storage local_addr;    
    time_t date;
    time_t xfer_date;
    volatile off_t restartat;
    volatile off_t download_total_size;
    volatile off_t download_current_size;    
    char account[MAX_USER_LENGTH + 1U];
#if defined(__OpenBSD__)
    char filename[1024];
#else
# ifdef PAGE_SIZE
#  if PAGE_SIZE > 2048
    char filename[PAGE_SIZE - 1024];
#  else
    char filename[1024];
#  endif
# else
    char filename[1024];
# endif
#endif
} FTPWhoEntry;

int ftpwho_initwho(void);
void ftpwho_exit(void);
void ftpwho_lock(void);
void ftpwho_unlock(void);
#ifndef NO_STANDALONE
void ftpwho_unlinksbfile(const pid_t pid);
#endif
    
#endif

#endif
