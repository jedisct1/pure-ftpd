#include <config.h>

#include "ftpd.h"
#include "log_unix.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

void pw_unix_check(AuthResult * const result,
                   const char *account, const char *password,
                   const struct sockaddr_storage * const sa,
                   const struct sockaddr_storage * const peer)
{
    const char *cpwd = NULL;
    struct passwd pw, *pw_;
#ifdef USE_SHADOW
    struct spwd *spw;
#endif
    char *dir = NULL;

    (void) sa;
    (void) peer;
    result->auth_ok = 0;
    if ((pw_ = getpwnam(account)) == NULL) {
        return;
    }
    pw = *pw_;
    result->auth_ok--;
#ifdef HAVE_SETUSERSHELL
    if (pw.pw_shell == NULL) {
        return;
    }
    if (strcasecmp(pw.pw_shell, FAKE_SHELL) != 0) {
        const char *shell;
        
        setusershell();
        while ((shell = (char *) getusershell()) != NULL &&
               strcmp(pw.pw_shell, shell) != 0);
        endusershell();
        if (shell == NULL) {
            return;
        }
    }    
#endif
    if ((dir = strdup(pw.pw_dir)) == NULL) {
        return;
    }
#ifdef USE_SHADOW
    if ((((pw.pw_passwd)[0] == 'x' && (pw.pw_passwd)[1] == 0) ||
         ((pw.pw_passwd)[0] == '#' && (pw.pw_passwd)[1] == '#' &&
          strcmp(pw.pw_passwd + 2, account) == 0)) &&
        (spw = getspnam(account)) != NULL && spw->sp_pwdp != NULL) {
        cpwd = spw->sp_pwdp[0] == '@' ? NULL : spw->sp_pwdp;
        if (spw->sp_expire > 0 || spw->sp_max > 0) {
            long today = time(NULL) / (24L * 60L * 60L);

            if (spw->sp_expire > 0 && spw->sp_expire < today) {
                goto bye;               /* account expired */
            }
            if (spw->sp_max > 0 && spw->sp_lstchg > 0 &&
                (spw->sp_lstchg + spw->sp_max < today)) {
                goto bye;               /* password expired */
            }
        }
    } else
#endif
    {
        cpwd = pw.pw_passwd;
    }
    {
        register const char *crypted;
        
        if (cpwd == NULL ||
            (crypted = (const char *) crypt(password, cpwd)) == NULL ||
            strcmp(cpwd, crypted) != 0) {
            goto bye;
        }
    }
    result->uid = pw.pw_uid;
    result->gid = pw.pw_gid;
    result->dir = dir;
    result->slow_tilde_expansion = 0;
    result->auth_ok = -result->auth_ok;
    return;
    
    bye:
    free(dir);
}

