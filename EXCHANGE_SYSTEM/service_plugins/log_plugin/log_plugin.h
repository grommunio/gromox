#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void log_plugin_init(const char *config_path, const char* log_file_name,
	int log_level, int files_num, int cache_size);
extern void log_plugin_free(void);
extern int log_plugin_run(void);
extern int log_plugin_stop(void);
extern void log_plugin_log_info(int level, const char *format, ...);
void log_plugin_console_talk(int argc, char **argv, char *result, int length);

#ifdef __cplusplus
} /* extern "C" */
#endif
