#pragma once
#include "single_list.h"

#define KEYWORD_ENGINE	SINGLE_LIST

KEYWORD_ENGINE* keyword_engine_init(char *charset_path, char *list_path);

void keyword_engine_free(KEYWORD_ENGINE *pengine);

const char *keyword_engine_match(KEYWORD_ENGINE *pengine, const char *charset,
	const char *buff, int length);
