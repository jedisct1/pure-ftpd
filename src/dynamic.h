#ifndef __DYNAMIC_H__
#define __DYNAMIC_H__ 1

#ifndef NO_STANDALONE

typedef struct IPTrack_ {
    struct sockaddr_storage ip;    
    pid_t pid;
} IPTrack;

void iptrack_delete_pid(const pid_t pid);
unsigned int iptrack_get(const struct sockaddr_storage * const ip);
void iptrack_free(void);
void iptrack_add(const struct sockaddr_storage * const ip,
                 const pid_t pid);
#endif

#endif
