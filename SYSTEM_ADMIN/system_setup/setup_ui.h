#pragma once
#include "config_file.h"

void setup_ui_init(CONFIG_FILE *pconfig, const char *token_path,
	const char *url_link, const char *resource_path);
extern int setup_ui_run(void);
extern int setup_ui_stop(void);
extern void setup_ui_free(void);
