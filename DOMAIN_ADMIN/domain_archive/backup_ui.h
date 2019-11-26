#ifndef _H_BACKUP_UI_
#define _H_BACKUP_UI_
#include "common_types.h"

void backup_ui_init(int valid_days, const char *url_link,
	const char *resource_path);

int backup_ui_run();

int backup_ui_stop();

void backup_ui_free();


#endif

