#ifndef _H_LOG_PLUGIN_
#define _H_LOG_PLUGIN_

void log_plugin_init(const char *config_path, const char* log_file_name,
	int log_level, int files_num, int cache_size);

void log_plugin_free();

int log_plugin_run();

int log_plugin_stop();

void log_plugin_log_info(int level, char *format, ...);

void log_plugin_console_talk(int argc, char **argv, char *result, int length);

#endif //_H_LOG_PLUGIN_
