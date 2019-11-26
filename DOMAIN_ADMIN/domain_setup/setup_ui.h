#ifndef _H_SETUP_UI_
#define _H_SETUP_UI_
#include "config_file.h"

void setup_ui_init(const char *mount_path, const char *app_path,
	const char *url_link, const char *resource_path);
extern int setup_ui_run(void);
extern int setup_ui_stop(void);
extern void setup_ui_free(void);

#endif

