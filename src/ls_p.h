#ifndef __LS_P_H__
#define __LS_P_H__ 1

#if defined(GLOB_ABORTED) && !defined(GLOB_ABEND)
#define GLOB_ABEND GLOB_ABORTED
#endif

#define CHUNK_SIZE page_size

static unsigned int colwidth;
static unsigned int filenames;

struct filename {
    struct filename *down;
    struct filename *right;
    int top;
    char line[1];
};

static struct filename *head;
static struct filename *tail;
static unsigned int matches;

struct userid {
    struct userid *next;
    uid_t uid;
    char *name;
};

struct groupid {
    struct groupid *next;
    gid_t gid;
    char *name;
};

#ifndef NO_FTP_USERS
static struct userid *user_head;
static struct groupid *group_head;
#endif

/* ls options */
int opt_a, opt_C, opt_d, opt_F, opt_l, opt_R, opt_r, opt_t, opt_S;

#endif
