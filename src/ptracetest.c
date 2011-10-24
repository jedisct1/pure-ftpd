
/*
 * This little program checks whether your operating system allows a process
 * to attach to another process whose uid is only identical because it
 * revoked its privileges.
 * 
 * If it detects that your operating system may be unsafe, then it's probably
 * better to avoid usage of privilege separation if untrusted users have
 * shell access.
 *
 * Compile and run with :
 * 
 * make ptracetest
 * ./ptracetest
 * 
 * (C)opyleft 2003-2009 Jedi/Sector One <j at pureftpd dot org>.
 */

#include <config.h>
#include "ftpd.h"

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#define TEST_GID 65534
#define TEST_UID 65534
#define ZIPPER "|/-\\ "

#if !defined(HAVE_PTRACE) || !defined(HAVE_SYS_PTRACE_H) || !(defined(PT_ATTACH) || defined(PTRACE_ATTACH))

int main(void)
{
    fputs("Sorry, this test can't be compiled in this platform\n", stderr);
    
    return 255;
}

#else

# include <sys/ptrace.h>

int main(void)
{
    pid_t pid;
    int rtn = 1;

    if (geteuid() != (uid_t) 0) {
        fputs("Sorry, you need to run this program as root\n", stderr);
        return 254;
    }
    if (setgid((gid_t) TEST_GID) || setegid((gid_t) TEST_GID) ||
        setuid((uid_t) TEST_UID) || seteuid((uid_t) TEST_UID)) {
        perror("Error while switching gid/uid");
        return 254;
    }
    if ((pid = fork()) == (pid_t) -1) {
        perror("Unable to fork");
        return 254;
    }
    if (pid == (pid_t) 0) {
        size_t t = (size_t) 0U;

        fputs("Checking for traceability after uid change ", stdout);
        fflush(stdout);
        do {
            putchar(ZIPPER[t]);
            putchar('\b');
            fflush(stdout);
            (void) sleep(1U);
            t++;
        } while (t < sizeof ZIPPER - (size_t) 1U);
        putchar('\n');
        
        _exit(0);
    } else {
        int status;
        long ret;        

# ifdef PT_ATTACH
        ret = ptrace(PT_ATTACH, pid, NULL, NULL);
# else
        ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);        
# endif
        
        while (wait(&status) != pid);
        
        if (ret < 0L) {
            puts("\n"
                 "*** YOUR OPERATING SYSTEM LOOKS SAFE ***\n"
                 "\n"
                 "You can probably enable privilege separation, even if\n"
                 "untrusted users also have shell access.");
            rtn = 0;
        } else {
            puts("\n"
                 "*** YOUR OPERATING SYSTEM MAY BE _UNSAFE_ ***\n"
                 "\n"
                 "Enabling privilege separation is ok as long as untrusted\n"
                 "users don't have shell access.");
        }        
    }
    
    return rtn;
}

#endif
