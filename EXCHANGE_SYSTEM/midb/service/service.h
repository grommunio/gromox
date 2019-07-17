#ifndef _H_SERVICE_
#define _H_SERVICE_
#include "common_types.h"
#include "plugin.h"

void service_init(int context_num, const char* plugin_path,
	const char *config_path, const char *data_path);

void service_free();

int  service_run();

int  service_stop();

int service_load_library(const char *path);

int service_unload_library(const char *path);

void* service_query(const char *service_name, const char *module);

void service_release(const char *service_name, const char *module);

int service_console_talk(int argc, char **argv, char *reason, int len);

void service_enum_plugins(ENUM_PLUGINS enum_func);

void service_enum_dependency(const char *plugin, ENUM_PLUGINS enum_func);

void service_enum_reference(const char *module, ENUM_PLUGINS enum_func);

#endif /* _H_SERVICE_ */
