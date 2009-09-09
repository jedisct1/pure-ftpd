/*
 * Changed qmail-pop3 to pure-ftpd ...
 * 
 * Program:    Pluggable Authentication Modules login services
 *
 * Author:    Michael K. Johnson
 *        Red Hat Software
 *        Internet: johnsonm@redhat.com
 *
 *
 *  This majority of this code was lifted from the src.rpm for imap
 *  in the RedHat-4.2 updates directory
 *  by Kelley Lingerfelt redhat@cococo.net
 */

#include <config.h>

#ifdef USE_PAM
# include "ftpd.h"
# include "log_pam.h"
# ifdef HAVE_SECURITY_PAM_MISC_H
#  include <security/pam_misc.h>
# endif
# ifdef HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
# endif
# ifdef HAVE_SECURITY_PAM_MODULES_H
#  include <security/pam_modules.h>
# endif
# ifdef HAVE_SECURITY_PAM_FILTER_H
#  include <security/pam_filter.h>
# endif

# ifdef HAVE_PAM_PAM_MISC_H
#  include <pam/pam_misc.h>
# endif
# ifdef HAVE_PAM_PAM_APPL_H
#  include <pam/pam_appl.h>
# endif
# ifdef HAVE_PAM_PAM_MODULES_H
#  include <pam/pam_modules.h>
# endif
# ifdef HAVE_PAM_PAM_FILTER_H
#  include <pam/pam_filter.h>
# endif

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

/* Static variables used to communicate between the conversation function
 * and the server_login function
 */
static const char *PAM_username;
static const char *PAM_password;
static int PAM_error;

/* for compability with older pam stuff, before the stupid transposition */
#ifndef PAM_CRED_ESTABLISH
# define PAM_CRED_ESTABLISH  0x0002U
#endif

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */

#define GET_MEM \
    size += sizeof(struct pam_response); \
    if ((reply = realloc(reply, size)) == NULL) { \
        PAM_error = 1; \
        return PAM_CONV_ERR; \
    }

static int PAM_conv(int num_msg,
                    const struct pam_message **msg,
                    struct pam_response **resp, void *appdata_ptr)
{
    int count = 0;
    unsigned int replies = 0U;
    struct pam_response *reply = NULL;
    size_t size = (size_t) 0U;

    (void) appdata_ptr;
    *resp = NULL;
    for (count = 0; count < num_msg; count++) {
        switch (msg[count]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            GET_MEM;
            memset(&reply[replies], 0, sizeof reply[replies]);
            if ((reply[replies].resp = strdup(PAM_username)) == NULL) {
#ifdef PAM_BUF_ERR
                reply[replies].resp_retcode = PAM_BUF_ERR;
#endif
                PAM_error = 1;
                return PAM_CONV_ERR;                
            }
            reply[replies++].resp_retcode = PAM_SUCCESS;
            /* PAM frees resp */
            break;
        case PAM_PROMPT_ECHO_OFF:
            GET_MEM;
            memset(&reply[replies], 0, sizeof reply[replies]);            
            if ((reply[replies].resp = strdup(PAM_password)) == NULL) {
#ifdef PAM_BUF_ERR
                reply[replies].resp_retcode = PAM_BUF_ERR;
#endif                
                PAM_error = 1;                
                return PAM_CONV_ERR;
            }
            reply[replies++].resp_retcode = PAM_SUCCESS;            
            /* PAM frees resp */
            break;
        case PAM_TEXT_INFO:
            /* ignore it... */
            break;
        case PAM_ERROR_MSG:
        default:
            /* Must be an error of some sort... */
            free(reply);
            PAM_error = 1;
            return PAM_CONV_ERR;
        }
    }
    *resp = reply;
    
    return PAM_SUCCESS;
}

/* Solaris throws warning about incompatible pointer types, it does not
   include const on pam_message */

static struct pam_conv PAM_conversation = {
    &PAM_conv, NULL
};

#define PAM_BAIL \
    if (PAM_error != 0 || pam_error != PAM_SUCCESS) { \
        goto bye; \
    }

/* Pure-FTPd authentication module */

void pw_pam_check(AuthResult * const result,
                  const char *user, const char *pass,
                  const struct sockaddr_storage * const sa,
                  const struct sockaddr_storage * const peer)
{
    pam_handle_t *pamh;
    int pam_error;
    struct passwd pw, *pw_;
    char *dir = NULL;
    
    (void) sa;
    (void) peer;
    result->auth_ok = 0;
    PAM_password = pass;
    PAM_username = user;
    pam_error = pam_start("pure-ftpd", user, &PAM_conversation, &pamh);
    PAM_BAIL;
# ifdef PAM_TTY
    (void) pam_set_item(pamh, PAM_TTY, "pure-ftpd");
# endif
# ifdef PAM_RUSER
    (void) pam_set_item(pamh, PAM_RUSER, user);
# endif
    /*
     * PAM doesn't make any distinction between "user not found" and
     * "bad password". So we assume user not found to fallback to other
     * authentication mechanisms. This is the most logical behavior.
     */
    pam_error = pam_authenticate(pamh, 0);
    PAM_BAIL;
    pam_error = pam_acct_mgmt(pamh, 0);
    PAM_BAIL;
    /* If this point is reached, the user has been authenticated. */
    if ((pw_ = getpwnam(user)) == NULL) {
        goto bye;
    }
    pw = *pw_;
    if ((dir = strdup(pw.pw_dir)) == NULL) {
        goto bye;
    }
    result->auth_ok--;                  /* -1 */    
# ifdef HAVE_INITGROUPS
    (void) initgroups(pw.pw_name, pw.pw_gid);
# endif
    pam_error = pam_setcred(pamh, PAM_CRED_ESTABLISH);
    PAM_BAIL;    

    /*
     * Handle session entries. PAM is instructed to shut up for now.
     * 20010530 <tossu@cc.hut.fi>
     */
#ifndef WITHOUT_PAM_SESSION
    (void) pam_open_session(pamh, PAM_SILENT);
    (void) pam_close_session(pamh, PAM_SILENT);   /* It doesn't matter if it fails */
#endif
    result->dir = dir;
    dir = NULL;
    result->uid = pw.pw_uid;
    result->gid = pw.pw_gid;
    result->slow_tilde_expansion = 0;
    result->auth_ok = -result->auth_ok;  /* 1 */
    
    bye:        
    if (dir != NULL) {
        dir = NULL;
    }
    (void) pam_end(pamh, result->auth_ok == 0 ? 0 : PAM_SUCCESS);    
}
#else
extern signed char v6ready;
#endif
