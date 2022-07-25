#pragma once
#include <string>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/hpm_common.h>
#include <gromox/plugin.hpp>

struct HTTP_CONTEXT;

struct hpm_service_node {
	void *service_addr;
	std::string service_name;
};

struct HPM_PLUGIN {
	HPM_PLUGIN() = default;
	HPM_PLUGIN(HPM_PLUGIN &&) noexcept;
	~HPM_PLUGIN();
	void operator=(HPM_PLUGIN &&) noexcept = delete;

	std::vector<hpm_service_node> list_reference;
	HPM_INTERFACE interface{};
	void *handle = nullptr;
	PLUGIN_MAIN lib_main = nullptr;
	std::string file_name;
	bool completed_init = false;
};

extern void hpm_processor_init(int context_num, std::vector<std::string> &&names, uint64_t cache_size, uint64_t max_size);
extern int hpm_processor_run();
extern void hpm_processor_stop();
BOOL hpm_processor_get_context(HTTP_CONTEXT *phttp);
void hpm_processor_put_context(HTTP_CONTEXT *phttp);
BOOL hpm_processor_check_context(HTTP_CONTEXT *phttp);
BOOL hpm_processor_write_request(HTTP_CONTEXT *phttp);
BOOL hpm_processor_check_end_of_request(HTTP_CONTEXT *phttp);
BOOL hpm_processor_proc(HTTP_CONTEXT *phttp);
int hpm_processor_retrieve_response(HTTP_CONTEXT *phttp);
BOOL hpm_processor_send(HTTP_CONTEXT *phttp,
	const void *pbuff, int length);
int hpm_processor_receive(HTTP_CONTEXT *phttp,
	char *pbuff, int length);
extern void hpm_processor_reload();
