#ifndef _H_LIST_UI_
#define _H_LIST_UI_
#include "common_types.h"

void list_ui_init(const char *list_path, const char *mount_path,
	BOOL switch_on, const char *url_link, const char *resource_path);

int list_ui_run();

int list_ui_stop();

void list_ui_free();

#endif

