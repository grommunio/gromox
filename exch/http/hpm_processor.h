#pragma once
#include <string>
#include <utility>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/hpm_common.h>
#include <gromox/plugin.hpp>

struct http_context;
using HTTP_CONTEXT = http_context;

struct HPM_PLUGIN : public gromox::generic_module {
	HPM_PLUGIN() = default;
	HPM_PLUGIN(HPM_PLUGIN &&o) noexcept : generic_module(std::move(o)) {}
	~HPM_PLUGIN();
	void operator=(HPM_PLUGIN &&) noexcept = delete;

	HPM_INTERFACE interface{};
	std::vector<gromox::service_node> list_reference;
};

extern void hpm_processor_init(int context_num, std::vector<std::string> &&names, uint64_t cache_size, uint64_t max_size);
extern int hpm_processor_run();
extern void hpm_processor_stop();
extern int hpm_processor_take_request(http_context *);
void hpm_processor_put_context(HTTP_CONTEXT *phttp);
extern bool hpm_processor_is_in_charge(HTTP_CONTEXT *);
BOOL hpm_processor_write_request(HTTP_CONTEXT *phttp);
BOOL hpm_processor_proc(HTTP_CONTEXT *phttp);
int hpm_processor_retrieve_response(HTTP_CONTEXT *phttp);
BOOL hpm_processor_send(HTTP_CONTEXT *phttp,
	const void *pbuff, int length);
int hpm_processor_receive(HTTP_CONTEXT *phttp,
	char *pbuff, int length);
extern void hpm_processor_trigger(unsigned int ev);
