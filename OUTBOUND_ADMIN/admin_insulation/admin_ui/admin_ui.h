#ifndef _H_ADMIN_UI_
#define _H_ADMIN_UI_
#include "common_types.h"

void admin_ui_init(const char *url_link, const char *resource_path);

int admin_ui_run();

int admin_ui_stop();

void admin_ui_free();


#endif

