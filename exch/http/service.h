#pragma once
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/plugin.hpp>

struct service_init_param {
	const char *plugin_dir, *config_dir, *data_dir, *state_dir;
	const char *const *plugin_list;
	bool plugin_ignloaderr;
	int context_num;
};

extern void service_init(const struct service_init_param &);
extern int service_run();
extern int service_stop();
int service_load_library(const char *path);

int service_unload_library(const char *path);
extern void *service_query(const char *service_name, const char *module, const std::type_info &);
void service_release(const char *service_name, const char *module);

int service_console_talk(int argc, char **argv, char *reason, int len);
extern BOOL service_register_service(const char *func_name, void *addr, const std::type_info &);
