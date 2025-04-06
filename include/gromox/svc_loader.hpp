#pragma once
#include <memory>
#include <span>
#include <typeinfo>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/plugin.hpp>

class config_file;

struct GX_EXPORT service_init_param {
	std::shared_ptr<config_file> cfg;
	std::span<const gromox::static_module> plugin_list;
	unsigned int context_num = 0;
	const char *prog_id = nullptr;
};

extern GX_EXPORT void service_init(service_init_param &&);
extern GX_EXPORT int service_run_early();
extern GX_EXPORT int service_run();
extern GX_EXPORT void service_stop();
extern GX_EXPORT void *service_query(const char *service_name, const char *module, const std::type_info &);
extern GX_EXPORT void service_release(const char *service_name, const char *module);
extern GX_EXPORT BOOL service_register_service(const char *func_name, void *addr, const std::type_info &);
extern GX_EXPORT void service_trigger_all(enum plugin_op);
