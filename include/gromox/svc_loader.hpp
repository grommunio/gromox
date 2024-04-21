#pragma once
#include <memory>
#include <typeinfo>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/plugin.hpp>

struct config_file;

struct service_init_param {
	std::shared_ptr<config_file> cfg;
	std::vector<gromox::static_module> plugin_list;
	unsigned int context_num = 0;
	const char *prog_id = nullptr;
};

extern void service_init(service_init_param &&);
extern int service_run_early();
extern int service_run();
extern void service_stop();
extern void *service_query(const char *service_name, const char *module, const std::type_info &);
void service_release(const char *service_name, const char *module);
extern BOOL service_register_service(const char *func_name, void *addr, const std::type_info &);
extern void service_trigger_all(unsigned int ev);
