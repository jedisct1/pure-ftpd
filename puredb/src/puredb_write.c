
/* (C)opyleft 2001-2009 Frank DENIS <j at pureftpd dot org> */

#include <config.h>

#include "puredb_p.h"
#include "puredb_write.h"

#ifndef HAVE_STRDUP
static char *strdup(const char *str)
{
    char *newstr;
    size_t str_len_1;
    
    if (str == NULL ||
        (str_len_1 = strlen(str) + (size_t) 1U) <= (size_t) 0U ||
        (newstr = malloc(str_len_1)) == NULL) {
        return NULL;
    }
    memcpy(newstr, str, str_len_1);
    
    return newstr;
}
#endif

static puredb_u32_t puredbw_hash(const char * const msg, size_t len)
{
    puredb_u32_t j = (puredb_u32_t) 5381U;

    while (len != 0) {
        len--;
        j += (j << 5);
        j ^= ((unsigned char) msg[len]);
    }
    j &= 0xffffffff;

    return j;
}

int puredbw_open(PureDBW * const dbw,
                 const char * const file_index,
                 const char * const file_data,
                 const char * const file_final)
{
    dbw->file_index = NULL;
    dbw->file_data = NULL;
    dbw->file_final = NULL;
    dbw->fpindex = NULL;
    dbw->fpdata = NULL;
    {
        int z = (sizeof dbw->hash_table0) / (sizeof dbw->hash_table0[0]) - 1;

        do {
            dbw->hash_table0[z].hash1_list = NULL;
            dbw->hash_table0[z].hash1_list_size = (size_t) 0U;
            z--;
        } while (z >= 0);
    }
    if ((dbw->file_index = strdup(file_index)) == NULL ||
        (dbw->file_data = strdup(file_data)) == NULL ||
        (dbw->file_final = strdup(file_final)) == NULL ||
        (dbw->fpindex = fopen(file_index, "wb")) == NULL ||
        (dbw->fpdata = fopen(file_data, "w+b")) == NULL) {

        return -1;
    }
    dbw->data_offset_counter = (puredb_u32_t) 0U;
    dbw->offset_first_data = (puredb_u32_t)
        (sizeof PUREDBW_VERSION - (size_t) 1U +
         (1U + sizeof dbw->hash_table0 / sizeof dbw->hash_table0[0]) *
         sizeof(puredb_u32_t));
    if (fwrite(PUREDBW_VERSION, (size_t) 1U,
               sizeof PUREDBW_VERSION - (size_t) 1U,
               dbw->fpindex) != (sizeof PUREDBW_VERSION - (size_t) 1U)) {
        return -1;
    }
    return 0;
}

int puredbw_add(PureDBW * const dbw,
                const char * const key, const size_t key_len,
                const char * const content, const size_t content_len)
{
    const puredb_u32_t hash = puredbw_hash(key, key_len);
    const puredb_u32_t hash_hi = hash & 0xff;
    Hash0 * const hash0 = &dbw->hash_table0[hash_hi];
    Hash1 *hash1;

    if (hash0->hash1_list == NULL) {
        hash0->hash1_list_size = sizeof(Hash1);
        if ((hash0->hash1_list = malloc(hash0->hash1_list_size)) == NULL) {
            return -1;
        }
    } else {
        Hash1 *newpnt;

        hash0->hash1_list_size += sizeof(Hash1);
        if ((newpnt = realloc(hash0->hash1_list,
                              hash0->hash1_list_size)) == NULL) {
            return -1;
        }
        hash0->hash1_list = newpnt;
    }
    dbw->offset_first_data += sizeof(puredb_u32_t) + sizeof(puredb_u32_t);
    hash1 = (Hash1 *) ((unsigned char *) hash0->hash1_list +
                       hash0->hash1_list_size - sizeof(Hash1));
    hash1->hash = hash;
    hash1->offset_data = dbw->data_offset_counter;
    dbw->data_offset_counter += sizeof(puredb_u32_t) + sizeof(puredb_u32_t) +
        + key_len + content_len;
    {
        const puredb_u32_t key_len_ = htonl((puredb_u32_t) key_len);
        if (fwrite(&key_len_, sizeof key_len_, (size_t) 1U, dbw->fpdata) !=
            (size_t) 1U) {
            return -1;
        }
    }
    if (fwrite(key, (size_t) 1U, key_len, dbw->fpdata) != key_len) {
        return -1;
    }
    {
        const puredb_u32_t content_len_ = htonl((puredb_u32_t) content_len);
        if (fwrite(&content_len_, sizeof content_len_, (size_t) 1U,
                   dbw->fpdata) != (size_t) 1U) {
            return -1;
        }
    }
    if (fwrite(content, (size_t) 1U, content_len, dbw->fpdata)
        != content_len) {

        return -1;
    }

    return 0;
}

int puredbw_add_s(PureDBW * const dbw,
                  const char * const key, const char * const content)
{
    return puredbw_add(dbw, key, strlen(key), content, strlen(content));
}

static int hash1_cmp_hook(const void * const a, const void * const b)
{
    puredb_u32_t ha = ((const Hash1 *) a)->hash;
    puredb_u32_t hb = ((const Hash1 *) b)->hash;

    if (ha < hb) {
        return -1;
    } else if (ha > hb) {
        return 1;
    }
    ha = ((const Hash1 *) a)->offset_data;
    hb = ((const Hash1 *) b)->offset_data;
    if (ha < hb) {
        return -1;
    } else if (ha > hb) {
        return 1;
    }
    return 0;
}

static int writekeys(PureDBW * const dbw)
{
    int hash_cnt = (int)
        (sizeof dbw->hash_table0 / sizeof dbw->hash_table0[0]);
    const Hash0 *hash0 = dbw->hash_table0;

    puredb_u32_t offset = (puredb_u32_t)
        ((1U + sizeof dbw->hash_table0 / sizeof dbw->hash_table0[0]) *
         sizeof(puredb_u32_t) + sizeof PUREDBW_VERSION - (size_t) 1U);
    do {
        {
            const puredb_u32_t offset_ = htonl((puredb_u32_t) offset);
            
            if (fwrite(&offset_, sizeof offset_, (size_t) 1U, dbw->fpindex) !=
                (size_t) 1U) {

                return -1;
            }
        }
        if (hash0->hash1_list_size <= 0U) {
            offset += sizeof(puredb_u32_t);
            dbw->offset_first_data += sizeof(puredb_u32_t);
        } else {
            offset += ((hash0->hash1_list_size / sizeof(Hash1)) *
                       (sizeof(puredb_u32_t) + sizeof(puredb_u32_t)));
        }
        hash0++;
        hash_cnt--;
    } while (hash_cnt != 0);
    {                                  /* extra hash0, filler */
        const puredb_u32_t null_ = (puredb_u32_t) htonl(offset);
        if (fwrite(&null_, sizeof null_, (size_t) 1U, dbw->fpindex) !=
            (size_t) 1U) {
                return -1;
        }
    }    

    hash_cnt = (int) (sizeof dbw->hash_table0 / sizeof dbw->hash_table0[0]);
    hash0 = dbw->hash_table0;
    do {
        Hash1 *hash1 = hash0->hash1_list;
        size_t list_size = hash0->hash1_list_size;

        if (hash1 == NULL) {
            const puredb_u32_t null_ = 
                (puredb_u32_t) htonl((hash0 - dbw->hash_table0) + 1U);
            
            if (fwrite(&null_, sizeof null_, (size_t) 1U, dbw->fpindex) !=
                (size_t) 1U) {
                return -1;
            }            
            goto next;
        }
        qsort((void *) hash1, hash0->hash1_list_size / sizeof(Hash1),
              sizeof(Hash1), hash1_cmp_hook);
        do {
            {
                const puredb_u32_t hash_ = htonl(hash1->hash);

                if (fwrite(&hash_, sizeof hash_, (size_t) 1U, dbw->fpindex) !=
                    (size_t) 1U) {
                    return -1;
                }
            }
            {
                const puredb_u32_t offset_data_ = htonl(hash1->offset_data +
                                                      dbw->offset_first_data);
                
                if (fwrite(&offset_data_, sizeof offset_data_,
                           (size_t) 1U, dbw->fpindex) != (size_t) 1U) {
                    return -1;
                }
            }
            hash1++;
            list_size -= sizeof(Hash1);
        } while (list_size > (size_t) 0U);
        next:
        hash0++;
        hash_cnt--;
    } while (hash_cnt != 0);

    return 0;
}

static int freestructs(PureDBW * const dbw)
{
    Hash0 *hash0 = dbw->hash_table0;
    int hash0_cnt = (int) (sizeof dbw->hash_table0 / sizeof dbw->hash_table0[0]);

    do {
        free(hash0->hash1_list);
        hash0->hash1_list = NULL;
        hash0++;
        hash0_cnt--;
    } while (hash0_cnt > 0);

    return 0;
}

static int mergefiles(PureDBW * const dbw)
{
    size_t readen;
    char buf[4096];

    rewind(dbw->fpdata);
    while ((readen = fread(buf, (size_t) 1U, sizeof buf, dbw->fpdata)) >
           (size_t) 0U) {
        if (fwrite(buf, (size_t) 1U, readen, dbw->fpindex) != readen) {
            return -1;
        }
    }
    if (fclose(dbw->fpdata) != 0) {
        return -1;
    }
    dbw->fpdata = NULL;
    fflush(dbw->fpindex);
#ifdef HAVE_FILENO
    fsync(fileno(dbw->fpindex));
#endif
    if (fclose(dbw->fpindex) != 0) {
        return -1;
    }
    dbw->fpindex = NULL;
    (void) unlink(dbw->file_data);
    if (rename(dbw->file_index, dbw->file_final) < 0)
    {
        (void) unlink(dbw->file_final);        
        if (rename(dbw->file_index, dbw->file_final) < 0) {        
            return -1;
        }
    }

    return 0;
}

static void freeall(PureDBW * const dbw)
{
    if (dbw->fpindex != NULL) {
        fclose(dbw->fpindex);
        dbw->fpindex = NULL;
    }
    if (dbw->fpdata != NULL) {
        fclose(dbw->fpdata);
        dbw->fpdata = NULL;
    }
    free(dbw->file_index);
    dbw->file_index = NULL;
    free(dbw->file_data);
    dbw->file_data = NULL;
    free(dbw->file_final);
    dbw->file_final = NULL;
}

void puredbw_free(PureDBW * const dbw)
{
    freestructs(dbw);
    freeall(dbw);
}

int puredbw_close(PureDBW * const dbw)
{
    if (writekeys(dbw) != 0) {
        return -1;
    }
    freestructs(dbw);
    if (mergefiles(dbw) != 0) {
        return -1;
    }
    freeall(dbw);

    return 0;
}


