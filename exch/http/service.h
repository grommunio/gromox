#pragma once
#ifndef __cplusplus
#	include <stdbool.h>
#endif
#include <gromox/common_types.hpp>
#include <gromox/plugin.hpp>

struct service_init_param {
	const char *plugin_dir, *config_dir, *data_dir, *state_dir;
	const char *const *plugin_list;
	bool plugin_ignloaderr;
	int context_num;
};

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
extern BOOL service_register_service(const char *func_name, void *addr);
