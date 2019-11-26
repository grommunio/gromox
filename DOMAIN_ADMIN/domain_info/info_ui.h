#ifndef _H_INFO_UI_
#define _H_INFO_UI_

void info_ui_init(const char *url_link, const char *resource_path);
extern int info_ui_run(void);
extern int info_ui_stop(void);
extern void info_ui_free(void);

#endif

