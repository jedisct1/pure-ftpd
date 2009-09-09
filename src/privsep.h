#ifndef __PRIVSEP_H__
#define __PRIVSEP_H__ 1

#ifdef WITH_PRIVSEP

int privsep_sendfd(const int psfd, const int fd);
int privsep_recvfd(const int psfd);

int privsep_init(void);
int privsep_removeftpwhoentry(void);
int privsep_bindresport(const int protocol, const struct sockaddr_storage ss);

#endif

#endif
