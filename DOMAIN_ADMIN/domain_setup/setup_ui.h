#ifndef _H_SETUP_UI_
#define _H_SETUP_UI_
#include "config_file.h"

void setup_ui_init(const char *mount_path, const char *app_path,
	const char *url_link, const char *resource_path);

int setup_ui_run();

int setup_ui_stop();

void setup_ui_free();

#endif

