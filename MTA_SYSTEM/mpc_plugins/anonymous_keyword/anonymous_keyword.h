#ifndef _H_ANONYMOUS_KEYWORD_
#define _H_ANONYMOUS_KEYWORD_
#include "common_types.h"

typedef void (*ENUM_GROUP)(const char *, int);

void anonymous_keyword_init(const char *charset_path, const char *list_path);

int anonymous_keyword_run();

int anonymous_keyword_stop();

void anonymous_keyword_free();

BOOL anonymous_keyword_match(const char *charset, const char *buff,
	int length, char *keyword, char *group);

void anonymous_keyword_enum_group(ENUM_GROUP enum_func);

BOOL anonymous_keyword_refresh();

void anonymous_keyword_clear_statistic();

#endif
