
/* (C)opyleft 2001-2009 Frank DENIS <j at pureftpd dot org> */

#ifndef __PUREDB_READ_H__
#define __PUREDB_READ_H__ 1

#include <limits.h>

#define PUREDB_VERSION "PDB2"
#define PUREDB_LIB_VERSION 1

#ifndef PUREDB_U32_T
# if SHRT_MAX >= 2147483647
typedef unsigned short puredb_u32_t;
# elif INT_MAX >= 2147483647
typedef unsigned int puredb_u32_t;
# else
typedef unsigned long puredb_u32_t;
# endif
# define PUREDB_U32_T 1
#endif

typedef struct PureDB_ {
    unsigned char *map;
    int fd;
    puredb_u32_t size;
} PureDB;

#define puredb_getfd(X) ((X)->fd)

#define puredb_getsize(X) ((off_t) ((X)->size))

#define puredb_read_free(X) if ((X) != NULL) free(X)

int puredb_open(PureDB * const db, const char *dbfile);

int puredb_close(PureDB * const db);

int puredb_find(PureDB * const db, const char * const tofind,
                const size_t tofind_len, off_t * const retpos, 
                size_t * const retlen);

int puredb_find_s(PureDB * const db, const char * const tofind,
                  off_t * const retpos, size_t * const retlen);

void *puredb_read(PureDB * const db, const off_t offset, const size_t len);

#endif
