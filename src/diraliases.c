/*

0) alias file format.
 alternating lines of alias and dir
 (this enables embeded whitespace in dir and alias without quoting rules)
 optional blank lines
 optional lines beginning with '#' as comments
 (no you can't put a '#' just anywhere)
 
1) data structure for alias list nodes.
typedef struct DirAlias_ {
       char *alias;
       char *dir;
       struct DirAlias *next;
} DirAlias;

2) init routine
 A) open alias file
 B) while not EOF do
      read line
      parse line
        dir must begin with "/"
      allocate DirAlias and members
      if tail is NULL then head and tail (global DirAlias_t pointers)
       are set to member
      else tail->next is set to member and then tail is set to member

3) lookup routine
  A) given potential alias return dir or NULL
     (walk list starting with head looking for match)

4) FTP CWD command mods
  A) if chdir() fails try alias (use lookup routine)

5) FTP SITE ALIAS command
  A) list aliases

*/

#include <config.h>

#ifdef WITH_DIRALIASES

#include "ftpd.h"
#include "messages.h"
#include "diraliases.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static DirAlias *head, *tail;
static signed char aliases_up;

/* returns: 0 on success, -1 on failure */

int init_aliases(void)
{
    FILE *fp;
    char alias[MAXALIASLEN + 1U];
    char dir[MAXPATHLEN + 1U];
    
    if ((fp = fopen(ALIASES_FILE, "r")) == NULL) {
        return 0;
    }
    while (fgets(alias, sizeof alias, fp) != NULL) {
        if (*alias == '#' || *alias == '\n' || *alias == 0) {
            continue;
        }
        {
            char * const z = alias + strlen(alias) - 1U;
            
            if (*z != '\n') {
                goto bad;
            }
            *z = 0;            
        }
        do {
            if (fgets(dir, sizeof dir, fp) == NULL || *dir == 0) {
                goto bad;
            }
            {
                char * const z = dir + strlen(dir) - 1U;
                
                if (*z == '\n') {
                    *z = 0;
                }
            }
        } while (*dir == '#' || *dir == 0);
        if (head == NULL) {
            if ((head = tail = malloc(sizeof *head)) == NULL ||
                (tail->alias = strdup(alias)) == NULL ||
                (tail->dir = strdup(dir)) == NULL) {
                die_mem();
            }
            tail->next = NULL;
        } else {
            DirAlias *curr;
            
            if ((curr = malloc(sizeof *curr)) == NULL ||
                (curr->alias = strdup(alias)) == NULL ||
                (curr->dir = strdup(dir)) == NULL) {
                die_mem();
            }
            tail->next = curr;
            tail = curr;
        }
    }
    fclose(fp);
    aliases_up++;
    
    return 0;
    
    bad:
    logfile(LOG_ERR, MSG_ALIASES_BROKEN_FILE " [" ALIASES_FILE "]");
    
    return -1;
}


char *lookup_alias(const char *alias)
{
    const DirAlias *curr = head;
    
    if (aliases_up == 0) {
        return NULL;
    }
    while (curr != NULL) {
        if (strcmp(curr->alias, alias) == 0) {
            return curr->dir;
        }
        curr = curr->next;
    }
    return NULL;
}


void print_aliases(void)
{
    const DirAlias *curr = head;
    
    if (aliases_up == 0) {
        addreply_noformat(502, MSG_CONF_ERR);
        
        return;
    }
    addreply_noformat(214, MSG_ALIASES_LIST);
    while (curr != NULL) {
        char line[MAXALIASLEN + MAXPATHLEN + 3U];
        
        snprintf(line, sizeof line, " %s %s", curr->alias, curr->dir);
        addreply_noformat(0, line);
        curr = curr->next;
    }
    addreply_noformat(214, " ");
}

#endif
