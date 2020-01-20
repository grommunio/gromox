#pragma once
#include "common_types.h"

void backup_ui_init(int valid_days, const char *url_link,
	const char *resource_path);
extern int backup_ui_run(void);
extern int backup_ui_stop(void);
extern void backup_ui_free(void);
