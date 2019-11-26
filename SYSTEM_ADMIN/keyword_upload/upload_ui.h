#ifndef _H_UPLOAD_UI_
#define _H_UPLOAD_UI_

void upload_ui_init(const char *charset_path, const char *subject_path,
	const char *from_path, const char *to_path, const char *cc_path,
	const char *content_path, const char *attachment_path,
	const char *mount_path, const char *url_link, const char *resource_path);
extern int upload_ui_run(void);
extern int upload_ui_stop(void);
extern void upload_ui_free(void);

#endif

