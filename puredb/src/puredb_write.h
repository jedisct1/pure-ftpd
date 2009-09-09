
/* (C)opyleft 2001-2009 Frank DENIS <j at pureftpd dot org> */

#ifndef __PUREDB_WRITE_H__
#define __PUREDB_WRITE_H__ 1

#include <limits.h>

#define PUREDBW_VERSION "PDB2"
#define PUREDBW_LIB_VERSION 1

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

typedef struct Hash1_ {
    puredb_u32_t hash;
    puredb_u32_t offset_data;
} Hash1;

typedef struct Hash0_ {
    Hash1 *hash1_list;
    size_t hash1_list_size;
} Hash0;

typedef struct PureDBW_ {
    FILE *fpindex;       
    FILE *fpdata;
    char *file_index;
    char *file_data;
    char *file_final;
    puredb_u32_t data_offset_counter;
    puredb_u32_t offset_first_data;
    Hash0 hash_table0[256];
} PureDBW;

int puredbw_open(PureDBW * const dbw,
                 const char * const file_index,
                 const char * const file_data,
                 const char * const file_final);

int puredbw_close(PureDBW * const dbw);

void puredbw_free(PureDBW * const dbw);

int puredbw_add(PureDBW * const dbw,
                const char * const key, const size_t key_len,
                const char * const content, const size_t content_len);

int puredbw_add_s(PureDBW * const dbw,
                  const char * const key, const char * const content);

#endif
