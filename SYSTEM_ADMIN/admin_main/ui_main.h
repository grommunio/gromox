#ifndef _H_UI_MAIN_
#define _H_UI_MAIN_

void ui_main_init(const char *url_link, const char *resource_path);
extern int ui_main_run(void);
extern int ui_main_stop(void);
extern void ui_main_free(void);

#endif

