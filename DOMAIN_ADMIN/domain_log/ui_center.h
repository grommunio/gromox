#ifndef _H_UI_CENTER_
#define _H_UI_CENTER_
#include "common_types.h"

void ui_center_init(int valid_days, const char *url_link,
	const char *resource_path);

int ui_center_run();

int ui_center_stop();

void ui_center_free();


#endif

