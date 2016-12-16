#ifndef __SIMPLECONF_H__
#define __SIMPLECONF_H__ 1

#include <stdlib.h>

typedef struct SimpleConfEntry_ {
    const char *in;
    const char *out;
} SimpleConfEntry;

int sc_build_command_line_from_file(const char *file_name,
                                    const SimpleConfEntry entries[],
                                    size_t entries_count, char *app_name,
                                    int *argc_p, char ***argv_p);

void sc_argv_free(int argc, char *argv[]);

#endif
