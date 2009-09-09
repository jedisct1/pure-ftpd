#ifndef __PARSER_H__
#define __PARSER_H__ 1

typedef struct ConfigKeywords_ {
    const char *keyword;
    char **value;
} ConfigKeywords;

int generic_parser(const char * const file,
                   ConfigKeywords *config_keywords);

#endif
