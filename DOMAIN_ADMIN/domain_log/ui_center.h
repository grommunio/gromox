#ifndef _H_UI_CENTER_
#define _H_UI_CENTER_
#include "common_types.h"

void ui_center_init(int valid_days, const char *url_link,
	const char *resource_path);
extern int ui_center_run(void);
extern int ui_center_stop(void);
extern void ui_center_free(void);

#endif

