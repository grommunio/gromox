#pragma once
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/plugin.hpp>
#include <gromox/svc_loader.hpp>
#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

/* Plugin is expected to use `using namespace ns;` too */
#define	DECLARE_SVC_API(ns, x) namespace ns { \
	x decltype(dlfuncs::get_config_path) get_config_path; \
	x decltype(dlfuncs::get_data_path) get_data_path; \
	x decltype(dlfuncs::get_context_num) get_context_num; \
	x decltype(dlfuncs::get_host_ID) get_host_ID; \
	x decltype(dlfuncs::ndr_stack_alloc) ndr_stack_alloc; \
}
#define register_service(n, f) service_register_service((n), reinterpret_cast<void *>(f), typeid(decltype(*(f))))
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(service_query((n), typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)

#define LINK_SVC_API(param) \
	get_config_path = param.get_config_path ;\
	get_data_path = param.get_data_path; \
	get_context_num = param.get_context_num; \
	get_host_ID = param.get_host_ID; \
	query_service1(ndr_stack_alloc);
