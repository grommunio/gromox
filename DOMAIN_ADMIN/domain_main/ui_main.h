#pragma once
#include "common_types.h"

void ui_main_init(const char *exit_url, const char *url_link,
	const char *resource_path);
extern int ui_main_run(void);
extern int ui_main_stop(void);
extern void ui_main_free(void);
