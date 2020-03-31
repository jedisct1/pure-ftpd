
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

int init_aliases(void)
{
    FILE *fp;
    char alias[MAXALIASLEN + 1U];
    char dir[PATH_MAX + 1U];

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
        tail->next = NULL;
    }
    fclose(fp);
    aliases_up++;

    return 0;

    bad:
    fclose(fp);
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
        char line[MAXALIASLEN + PATH_MAX + 3U];

        snprintf(line, sizeof line, " %s %s", curr->alias, curr->dir);
        addreply_noformat(0, line);
        curr = curr->next;
    }
    addreply_noformat(214, " ");
}

#endif
