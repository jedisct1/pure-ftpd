#include <config.h>

#ifdef QUOTAS
# include "ftpd.h"
# include "dynamic.h"
# include "ftpwho-update.h"
# include "globals.h"
# include "messages.h"
# include "quotas.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

int hasquota(void)
{
    if (guest != 0 ||
        (user_quota_files >= ULONG_LONG_MAX &&
         user_quota_size >= ULONG_LONG_MAX)) {
        return -1;
    }    
    return 0;
}

int quota_update(Quota *quota,
                 const long long files_add,
                 const long long size_add,
                 int *overflow)
{
    int fd;
    Quota old_quota = { 0ULL, 0ULL };
    Quota dummy_quota;
    struct flock lock;
    ssize_t readnb;
    int err = -1;
    char buf[84];  
    char *bufpnt = buf;
    int dummy_overflow;
    ssize_t left = (ssize_t) (sizeof buf - 1U);
    
    if (hasquota() != 0 || chrooted == 0) {
        return -2;
    }    
    if (overflow == NULL) {
        overflow = &dummy_overflow;
    }
    if (quota == NULL) {
        quota = &dummy_quota;
    }
    *overflow = 0;
    *quota = old_quota;
    if ((fd = open("/" QUOTA_FILE, O_RDWR | O_CREAT | O_NOFOLLOW, 
                   (mode_t) 0600)) == -1) {
        return -1;
    }
    lock.l_whence = SEEK_SET;
    lock.l_start = (off_t) 0;
    lock.l_len = (off_t) 0;
    lock.l_pid = getpid();
    lock.l_type = F_WRLCK;
    while (fcntl(fd, F_SETLKW, &lock) < 0) {
        if (errno != EINTR) {
            goto byenounlock;
        }    
    }
    do {
        while ((readnb = read(fd, bufpnt, left)) < (ssize_t) 0 && 
               errno == EINTR);
        if (readnb < (ssize_t) 0) {
            goto bye;        
        }
        bufpnt += readnb;
        left -= readnb;
    } while (left > (ssize_t) 0 && readnb != (ssize_t) 0);    
    *bufpnt = 0;
    if ((bufpnt = strchr(buf, ' ')) == NULL) {
        goto skipparse;
    }
    *bufpnt = 0;
    old_quota.files = quota->files = strtoull(buf, NULL, 10);
    old_quota.size = quota->size = strtoull(bufpnt + 1, NULL, 10);
    skipparse:
    if ((files_add | size_add) == 0LL) {
        goto okbye;
    }
    if (files_add < 0LL) {
        if (quota->files > (unsigned long long) -files_add) {
            quota->files -= (unsigned long long) (-files_add);
        } else {
            quota->files = 0ULL;
        }
    } else if (files_add >= 0LL) {
        quota->files += (unsigned long long) files_add;
        if (quota->files > user_quota_files) {
            *overflow = 1;
        }
    }
    if (size_add < 0LL) {
        if (quota->size > (unsigned long long) -size_add) {
            quota->size -= (unsigned long long) (-size_add);
        } else {
            quota->size = 0ULL;
        }
    } else if (size_add >= 0LL) {
        quota->size += size_add;
        if (quota->size > user_quota_size) {
            *overflow = 2;
        }
    }
    if ((old_quota.size != quota->size || old_quota.files != quota->files) &&
        !SNCHECK(snprintf(buf, sizeof buf, "%llu %llu\n",
                          quota->files, quota->size), sizeof buf) &&
        lseek(fd, (off_t) 0, SEEK_SET) != (off_t) -1 &&
        ftruncate(fd, (off_t) 0) == 0) {
        
        if (safe_write(fd, buf, strlen(buf)) != 0) {
            (void) ftruncate(fd, (off_t) 0);
            goto bye;
        }
    }
    okbye:
    err = 0;
    
    bye:
    lock.l_type = F_UNLCK;
    while (fcntl(fd, F_SETLK, &lock) < 0 && errno == EINTR);
    byenounlock:
    close(fd);
    
    return err;
}

void displayquota(Quota * const quota_)
{
    Quota quota;
    double pct;
    
    if (hasquota() != 0) {
        return;
    }
    if (quota_ == NULL) {
        if (quota_update(&quota, 0LL, 0LL, NULL) != 0) {
            return;
        }
    } else {
        quota = *quota_;
    }
    if (user_quota_files < ULONG_LONG_MAX) {
        pct = (double) quota.files * 100.0 / (double) user_quota_files;
        addreply(0, MSG_QUOTA_FILES, quota.files, (int) pct,
                 (unsigned long long) user_quota_files);
    }
    if (user_quota_size < ULONG_LONG_MAX) {
        pct = (double) quota.size * 100.0 / (double) user_quota_size;
        addreply(0, MSG_QUOTA_SIZE,
                 quota.size / 1024ULL, (int) pct, 
                 (unsigned long long) user_quota_size / 1024ULL);
    }
}

#endif

