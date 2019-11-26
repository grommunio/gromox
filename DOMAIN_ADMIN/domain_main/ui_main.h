#ifndef _H_UI_MAIN_
#define _H_UI_MAIN_
#include "common_types.h"

void ui_main_init(const char *exit_url, const char *url_link,
	const char *resource_path);

int ui_main_run();

int ui_main_stop();

void ui_main_free();


#endif

