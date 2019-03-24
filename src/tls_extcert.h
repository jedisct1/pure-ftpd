#ifndef __TLS_EXTCERT_H__
#define __TLS_EXTCERT_H__ 1

#ifdef WITH_TLS

typedef enum CertAction {
    CERT_ACTION_DENY,
    /* -- */
    CERT_ACTION_DEFAULT,
    CERT_ACTION_FALLBACK,
    CERT_ACTION_STRICT
} CertAction;

typedef struct CertResult {
    char       *cert_file;
    char       *key_file;
    CertAction  action;
    int         cert_ok;
} CertResult;

void tls_extcert_parse(const char * const file);
void tls_extcert_get(CertResult * const result, const char *sni_name);
void tls_extcert_exit(void);

#define EXTCERT_KEYWORD_SEP ":"

#define EXTCERT_CLIENT_SNI_NAME "sni_name" EXTCERT_KEYWORD_SEP
#define EXTCERT_CLIENT_END "end"

#define EXTCERT_REPLY_ACTION "action" EXTCERT_KEYWORD_SEP
#define EXTCERT_REPLY_CERT_FILE "cert_file" EXTCERT_KEYWORD_SEP
#define EXTCERT_REPLY_KEY_FILE "key_file" EXTCERT_KEYWORD_SEP
#define EXTCERT_REPLY_END "end"

#endif

#endif
