#pragma once
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/plugin.hpp>
#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

#define	DECLARE_SVC_API(x) \
	x decltype(dlfuncs::symget) imp__symget; \
	x decltype(dlfuncs::symreg) imp__symreg; \
	x decltype(dlfuncs::get_config_path) get_config_path; \
	x decltype(dlfuncs::get_data_path) get_data_path; \
	x decltype(dlfuncs::get_context_num) get_context_num; \
	x decltype(dlfuncs::get_host_ID) get_host_ID; \
	x decltype(dlfuncs::get_prog_id) get_prog_id; \
	x decltype(dlfuncs::ndr_stack_alloc) ndr_stack_alloc;
#define register_service(n, f) imp__symreg((n), reinterpret_cast<void *>(f), typeid(decltype(*(f))))
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(imp__symget((n), nullptr, typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)

#ifdef DECLARE_SVC_API_STATIC
DECLARE_SVC_API(static);
#else
DECLARE_SVC_API(extern);
#endif

#define LINK_SVC_API(param) \
	imp__symget = param.symget; \
	imp__symreg = param.symreg; \
	get_config_path = param.get_config_path ;\
	get_data_path = param.get_data_path; \
	get_context_num = param.get_context_num; \
	get_host_ID = param.get_host_ID; \
	get_prog_id = param.get_prog_id; \
	query_service1(ndr_stack_alloc);
