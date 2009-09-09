#include <config.h>

#include "ftpd.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

int main(void)
{
    struct passwd *pwd;
#ifdef USE_SHADOW
    struct spwd *spw;
#endif
    const char *pw;
    struct stat st;

#ifdef HAVE_SETLOCALE
# ifdef LC_MESSAGES
    (void) setlocale(LC_MESSAGES, "");
# endif
# ifdef LC_CTYPE
    (void) setlocale(LC_CTYPE, "");
# endif
# ifdef LC_COLLATE
    (void) setlocale(LC_COLLATE, "");
# endif
#endif    
    
    setpwent();
    while ((pwd = getpwent()) != NULL) {
        if (pwd->pw_name == NULL) {
            continue;
        }
        if (pwd->pw_uid <= (uid_t) 0 ||
            pwd->pw_gid <= (gid_t) 0) {
            continue;
        }
        if (stat(pwd->pw_dir, &st) != 0 ||
            !S_ISDIR(st.st_mode)) { 
            continue;
        }
#ifdef HAVE_SETUSERSHELL
        if (strcasecmp(pwd->pw_shell, FAKE_SHELL) != 0) {
            const char *shell;
            
            setusershell();
            while ((shell = (char *) getusershell()) != NULL &&
                   strcmp(pwd->pw_shell, shell) != 0);
            endusershell();
            if (shell == NULL) {
                continue;
            }
        }            
#endif
        pw = pwd->pw_passwd;
#ifdef USE_SHADOW
        if (pwd->pw_passwd != NULL && pwd->pw_name != NULL &&            
            (((pwd->pw_passwd)[0] == 'x' && (pwd->pw_passwd)[1] == 0) ||
             (strcmp(pwd->pw_passwd, "********") == 0) ||             
             ((pwd->pw_passwd)[0] == '#' && (pwd->pw_passwd)[1] == '#' &&
              strcmp(pwd->pw_passwd + 2, pwd->pw_name) == 0)) &&
            (spw = getspnam(pwd->pw_name)) != NULL && spw->sp_pwdp != NULL) {
            pw = spw->sp_pwdp[0] == '@' ? "*" : spw->sp_pwdp;            
        }
#endif
        if (pw == NULL || *pw == 0) {
            pw = "*";
        }
        {
            char *coma;
            
            if (pwd->pw_gecos != NULL && 
                (coma = strchr(pwd->pw_gecos, ',')) != NULL) {
                *coma = 0;
            }
        }
        printf("%s:%s:%lu:%lu:%s:%s/./\n", pwd->pw_name, pw,
               (unsigned long) pwd->pw_uid, (unsigned long) pwd->pw_gid,
               pwd->pw_gecos, pwd->pw_dir);        
    }
    endpwent();
    
    return 0;
}
