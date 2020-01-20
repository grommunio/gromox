#pragma once
#include "common_types.h"

typedef void (*ENUM_GROUP)(const char *, int);

void anonymous_keyword_init(const char *charset_path, const char *list_path);
extern int anonymous_keyword_run(void);
extern int anonymous_keyword_stop(void);
extern void anonymous_keyword_free(void);
BOOL anonymous_keyword_match(const char *charset, const char *buff,
	int length, char *keyword, char *group);

void anonymous_keyword_enum_group(ENUM_GROUP enum_func);
extern BOOL anonymous_keyword_refresh(void);
extern void anonymous_keyword_clear_statistic(void);
