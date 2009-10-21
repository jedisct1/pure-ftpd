#ifndef __PRIVSEP_P_H__
#define __PRIVSEP_P_H__ 1

#ifndef CMSG_ALIGN
# define CMSG_ALIGN(len) (((len) + sizeof(int) - (size_t) 1U) \
                              & (size_t) ~(sizeof(int) - (size_t) 1U))
#endif

#ifndef CMSG_SPACE
# define CMSG_SPACE(len) \
        (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#endif

#ifndef CMSG_LEN
# define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

#ifndef PRIVSEP_USER
# define PRIVSEP_USER "_pure-ftpd"
#endif

typedef enum PrivSepCmd_ {
    PRIVSEPCMD_NONE, 
    PRIVSEPCMD_ANSWER_ERROR, PRIVSEPCMD_ANSWER_FD,
    PRIVSEPCMD_BINDRESPORT, PRIVSEPCMD_ANSWER_BINDRESPORT,
#ifdef FTPWHO
    PRIVSEPCMD_REMOVEFTPWHOENTRY, PRIVSEPCMD_ANSWER_REMOVEFTPWHOENTRY
#endif
} PrivSepCmd;

typedef struct PrivSepQuery_BindResPort_ {
    PrivSepCmd cmd;
    int protocol;
    struct sockaddr_storage ss;
} PrivSepQuery_BindResPort;

#ifdef FTPWHO
typedef struct PrivSepQuery_RemoveFtpwhoEntry_ {
    PrivSepCmd cmd;
} PrivSepQuery_RemoveFtpwhoEntry;
#endif

typedef struct PrivSepQuery_Cmd_ {
    PrivSepCmd cmd;
} PrivSepQuery_Cmd;

typedef union PrivSepQuery_ {
    PrivSepQuery_BindResPort bindresport;
#ifdef FTPWHO
    PrivSepQuery_RemoveFtpwhoEntry removeftpwhoentry;
#endif
    PrivSepQuery_Cmd cmd;    
} PrivSepQuery;

#ifdef FTPWHO
typedef struct PrivSepAnswer_RemoveFtpwhoEntry_ {
    PrivSepCmd cmd;
} PrivSepAnswer_RemoveFtpwhoEntry;
#endif

typedef struct PrivSepAnswer_Cmd_ {
    PrivSepCmd cmd;
} PrivSepAnswer_Cmd;

typedef union PrivSepAnswer_ {
#ifdef FTPWHO
    PrivSepAnswer_RemoveFtpwhoEntry removeftpwhoentry;
#endif
    PrivSepAnswer_Cmd cmd;    
} PrivSepAnswer;

static int psfd = -1;
static uid_t privsep_uid;

#endif
