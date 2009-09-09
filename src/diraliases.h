#ifndef __DIRALIASES_H__
#define __DIRALIASES_H__ 1

#ifdef WITH_DIRALIASES

# ifndef ALIASES_FILE
#  define ALIASES_FILE CONFDIR "/pureftpd-dir-aliases"
# endif
# ifndef MAXALIASLEN
#  define MAXALIASLEN 256U        /* including trailing 0 */
# endif

typedef struct DirAlias_ {
    char *alias;
    char *dir;
    struct DirAlias_ *next;
} DirAlias;

int init_aliases(void);
char *lookup_alias(const char *alias);
void print_aliases(void);

#endif

#endif
