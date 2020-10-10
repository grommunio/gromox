#pragma once
#ifndef __cplusplus
#	include <stdbool.h>
#endif
#include "common_types.h"
#include "plugin.h"

struct service_init_param {
	const char *prog_id, *plugin_dir, *config_dir, *data_dir;
	const char *const *plugin_list;
	bool plugin_ignloaderr;
	int context_num;
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
extern void service_init(const struct service_init_param &);
#endif
extern int service_run(void);
extern int service_stop(void);
int service_load_library(const char *path);

int service_unload_library(const char *path);

void* service_query(const char *service_name, const char *module);

void service_release(const char *service_name, const char *module);

int service_console_talk(int argc, char **argv, char *reason, int len);

void service_enum_plugins(ENUM_PLUGINS enum_func);

void service_enum_dependency(const char *plugin, ENUM_PLUGINS enum_func);

void service_enum_reference(const char *module, ENUM_PLUGINS enum_func);
extern BOOL service_register_service(const char *func_name, void *addr);

#ifdef __cplusplus
} /* extern "C" */
#endif
