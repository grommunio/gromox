#pragma once

void backup_ui_init(const char *backup_path, const char *config_path,
	const char *data_path, const char *mount_path, const char *token_path,
	const char *url_link, const char *resource_path);
extern int backup_ui_run(void);
extern int backup_ui_stop(void);
extern void backup_ui_free(void);
