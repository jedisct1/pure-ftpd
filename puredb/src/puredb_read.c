
/* (C)opyleft 2001-2009 Frank DENIS <j at pureftpd dot org> */

#include <config.h>

#include "puredb_p.h"
#include "puredb_read.h"

static puredb_u32_t puredb_hash(const char * const msg, size_t len)
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

static ssize_t safe_read(const int fd, void * const buf_, size_t maxlen)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t readen;
    
    do {
        while ((readen = read(fd, buf, maxlen)) < (ssize_t) 0 && 
               errno == EINTR);
        if (readen < (ssize_t) 0 || readen > (ssize_t) maxlen) {
            return readen;
        }
        if (readen == (ssize_t) 0) {
            ret:
            return (ssize_t) (buf - (unsigned char *) buf_);
        }
        maxlen -= readen;
        buf += readen;
    } while (maxlen > (ssize_t) 0);
    goto ret;
}

static int read_be_long(const PureDB * const db,
                        const puredb_u32_t offset,
                        puredb_u32_t * const result)
{
    unsigned char mapoffsetbuf[4];        
    unsigned char *mapoffset;
    
#ifdef USE_MAPPED_IO
    if (db->map != NULL) {
        mapoffset = db->map + offset;        
    } else 
#endif
    {
        if (lseek(db->fd, offset, SEEK_SET) == (off_t) -1) {
            return -1;
        }        
        if (safe_read(db->fd, mapoffsetbuf, sizeof mapoffsetbuf) != 
            (ssize_t) sizeof mapoffsetbuf) {
            return -1;
        }
        mapoffset = mapoffsetbuf;
    }
    *result = mapoffset[0] << 24 | mapoffset[1] << 16 | 
        mapoffset[2] << 8 | mapoffset[3];
    
    return 0;
}

static int read_memcmp(const PureDB * const db, const puredb_u32_t offset, 
                       const unsigned char *str, const puredb_u32_t len)
{
    unsigned char *mapoffsetbuf;
    int cmp;
    
#ifdef USE_MAPPED_IO
    if (db->map != NULL) {
        return memcmp(db->map + offset, str, (size_t) len) != 0;
    }
#endif
    if ((mapoffsetbuf = (unsigned char *) ALLOCA(len)) == NULL) {
        return -2;
    }
    if (lseek(db->fd, offset, SEEK_SET) == (off_t) -1) {
        err:
        ALLOCA_FREE(mapoffsetbuf);
        return -2;
    }        
    if (safe_read(db->fd, mapoffsetbuf, (size_t) len) != (ssize_t) len) {
        goto err;
    }
    cmp = memcmp(mapoffsetbuf, str, (size_t) len) != 0;
    ALLOCA_FREE(mapoffsetbuf);
    
    return cmp;
}

int puredb_open(PureDB * const db, const char *dbfile)
{
    struct stat st;
    
    db->map = NULL;
    if ((db->fd = open(dbfile, O_RDONLY | O_BINARY)) == -1) {
        return -1;
    }
    if (fstat(db->fd, &st) < 0 || st.st_size > (off_t) 0xffffffff ||
        (db->size = (puredb_u32_t) st.st_size) <
        ((size_t) (256U + 1U) * sizeof(puredb_u32_t) + 
         sizeof PUREDB_VERSION - (size_t) 1U)) {
        close(db->fd);
        
        return -2;
    }
#ifdef HAVE_MMAP
    if ((char *) (db->map = 
                  (unsigned char *) mmap(NULL, db->size, PROT_READ,
                                         MAP_FILE | MAP_SHARED, db->fd, 
                                         (off_t) 0)) == (char *) MAP_FAILED) {
        db->map = NULL;
    }
#elif defined(HAVE_MAPVIEWOFFILE)
    {
        HANDLE fileh;
        
        fileh = (HANDLE) _get_osfhandle(db->fd);
        if (fileh != (HANDLE) -1) {
            HANDLE fmh;
            
            fmh = CreateFileMapping(fileh, 0, PAGE_READONLY, 0, 0, 0);
            if (fmh) {
                db->map = MapViewOfFile(fmh, FILE_MAP_READ, 0, 0, db->size);
                CloseHandle(fmh);
            }
        }
    }    
#endif    
    if (read_memcmp(db, (puredb_u32_t) 0U, 
                    (const unsigned char *) PUREDB_VERSION, 
                    sizeof PUREDB_VERSION - (size_t) 1U) != 0) {
        
        return -3;
    }
    return 0;
}

int puredb_find(PureDB * const db, const char * const tofind,
                const size_t tofind_len, off_t * const retpos, 
                size_t * const retlen)
{
    puredb_u32_t hash;
    puredb_u32_t scanned_hash;    
    puredb_u32_t hash0;
    puredb_u32_t hash1;
    puredb_u32_t hash1e;
    puredb_u32_t lastslot;
    puredb_u32_t slotlo;
    puredb_u32_t slothi;
    puredb_u32_t sno;

    *retpos = (off_t) -1;
    *retlen = (size_t) 0U;
    hash = puredb_hash(tofind, tofind_len);
    hash0 = sizeof PUREDB_VERSION - (size_t) 1U +
        (hash & 0xff) * sizeof(puredb_u32_t);

    if ((hash0 + sizeof(puredb_u32_t) * 2U) > db->size) {
        return -2;                     /* corrupted table */
    }
    if (read_be_long(db, hash0, &hash1) < 0) {
        return -3;                     /* read error */
    }
    if (read_be_long(db, hash0 + sizeof(puredb_u32_t), &hash1e) < 0) {
        return -3;                     /* read error */
    }
    if (hash1e <= hash1) {
        return -2;                     /* corrupted table */        
    }    
    if (hash1 == (puredb_u32_t) 0U) {
        return -1;                     /* not found (first table) */
    }
    if (hash1 > db->size) {
        return -2;                     /* corrupted table */
    }
    lastslot = (hash1e - hash1) / (sizeof(puredb_u32_t) + sizeof(puredb_u32_t));
    if (lastslot <= 0U) {
        return -2;                     /* corrupted table */        
    }
    lastslot--;
#if !defined(MINIMAL) && !defined(NO_BINARY_LOOKUP)
    slotlo = 0U;
    slothi = lastslot;
    sno = slothi / 2U;    
    while (slotlo <= slothi) {
        if (read_be_long(db, hash1 + sno * 
                         (sizeof(puredb_u32_t) + sizeof(puredb_u32_t)),
                         &scanned_hash) < 0) {
            return -3;
        }
        if (scanned_hash == hash) {
            while (sno > 0U) {
                sno--;
                if (read_be_long(db, hash1 + sno * 
                                 (sizeof(puredb_u32_t) + sizeof(puredb_u32_t)),
                                 &scanned_hash) < 0) {
                        return -3;
                }
                if (scanned_hash != hash) {
                    sno++;
                    break;
                }
            }
            hash1 += sno * (sizeof(puredb_u32_t) + sizeof(puredb_u32_t));
            goto shortcut;
        }
        if (scanned_hash > hash) {
            if (sno <= 0U) {
                break;
            }
            slothi = sno - 1;
        } else {
            if (sno >= lastslot) {
                break;
            }
            slotlo = sno + 1;
        }
        sno = (slothi + slotlo) / 2U;        
    }
    hash1 += sno * (sizeof(puredb_u32_t) + sizeof(puredb_u32_t));
#endif
    for(;;) {
        if (read_be_long(db, hash1, &scanned_hash) < 0) {
            return -3;
        }        
        if (scanned_hash > hash) {
            return -1;                     /* not found (too late) */
        }
        if (scanned_hash == hash) {            
            puredb_u32_t data;
            puredb_u32_t key_size;
            puredb_u32_t data_size;

            shortcut:
            if (read_be_long(db, hash1 + 4, &data) < 0) {
                return -3;
            }
            if (data > db->size) {
                return -2;             /* incorrect pointer */
            }
            if (read_be_long(db, data, &key_size) < 0) {
                return -3;
            }
            if (key_size != (puredb_u32_t) tofind_len) {
                goto trynext;
            }
            if (read_memcmp(db, data + sizeof(puredb_u32_t),
                            (const unsigned char *) tofind, tofind_len) != 0) {
                goto trynext;
            }
            data += sizeof(puredb_u32_t) + tofind_len;
            if (read_be_long(db, data, &data_size) < 0) {
                return -3;
            }
            data += sizeof(puredb_u32_t);
            *retpos = (off_t) data;
            *retlen = (size_t) data_size;
            
            return 0;
        }
        trynext:
        hash1 += sizeof(puredb_u32_t) + sizeof(puredb_u32_t);
        if (lastslot == 0U) {
            break;
        }
        lastslot--;
    }
    
    return -1;                     /* not found (end of table) */
}

int puredb_find_s(PureDB * const db, const char * const tofind,
                  off_t * const retpos, size_t * const retlen)
{
    return puredb_find(db, tofind, strlen(tofind), retpos, retlen);
}

void *puredb_read(PureDB * const db, const off_t offset, const size_t len)
{
    void *buf;
    
    if ((buf = malloc(len + (size_t) 1U)) == NULL) {
        return NULL;
    }
#ifdef USE_MAPPED_IO
    if (db->map != NULL) {
        memcpy(buf, db->map + offset, len);
    } else
#endif
    {
        if (lseek(db->fd, offset, SEEK_SET) == (off_t) -1 ||
            safe_read(db->fd, buf, len) != (ssize_t) len) {
            free(buf);
            return NULL;
        }
    }
    ((unsigned char *) buf)[len] = 0U;
    
    return buf;
}

int puredb_close(PureDB * const db)
{
    int ret = 0;
    
#ifdef HAVE_MMAP
    if (db->map != NULL) {
# ifdef HAVE_MUNMAP
        (void) munmap((void *) db->map, db->size);
# endif
        db->map = NULL;
    }
#elif defined(HAVE_MAPVIEWOFFILE)
    if (db->map != NULL) {
        (void) UnmapViewOfFile(db->map);
        db->map = NULL;
    }
#endif    
    if (db->fd != -1) {
        ret = close(db->fd);
        db->fd = -1;
    }
    
    return ret;
}


