#ifndef __QUOTAS_H__
#define __QUOTAS_H__ 1

#ifndef QUOTA_FILE
# define QUOTA_FILE ".ftpquota"
#endif

typedef struct Quota_ {
    unsigned long long files;
    unsigned long long size;
} Quota;

int quota_update(Quota * const quota,
                 const long long files_add, const long long size_add,
                 int *overflow);

void displayquota(Quota * const quota_);

int hasquota(void);

#endif
