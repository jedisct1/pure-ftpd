#ifndef __TLS_EXTCERT_H__
#define __TLS_EXTCERT_H__ 1

#ifdef WITH_TLS

void tls_extcert_parse(const char * const file);

#define EXTCERT_KEYWORD_SEP ":"

#define EXTCERT_CLIENT_SNI_NAME "sni_name" EXTCERT_KEYWORD_SEP
#define EXTCERT_CLIENT_END "end"

#endif

#endif
