#pragma once
#include <cstdint>
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/dcerpc.hpp>
#include <gromox/ndr.hpp>
#include <gromox/plugin.hpp>
#include <gromox/rpc_types.hpp>
#include <gromox/svc_loader.hpp>
#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

#define DISPATCH_FAIL				0
#define DISPATCH_SUCCESS			1
#define DISPATCH_PENDING			2

/* Plugin is expected to use `using namespace ns;` too */
#define DECLARE_PROC_API(ns, x) namespace ns { \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.reg_ep) register_endpoint; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.reg_intf) register_interface; \
	x __attribute__((__unused__)) decltype(dlfuncs::get_host_ID) get_host_ID; \
	x __attribute__((__unused__)) decltype(dlfuncs::get_config_path) get_config_path; \
	x __attribute__((__unused__)) decltype(dlfuncs::get_data_path) get_data_path; \
	x __attribute__((__unused__)) decltype(dlfuncs::get_context_num) get_context_num; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.get_binding_handle) get_binding_handle; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.get_rpc_info) get_rpc_info; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.is_rpc_bigendian) is_rpc_bigendian; \
	x __attribute__((__unused__)) decltype(dlfuncs::ndr_stack_alloc) ndr_stack_alloc; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.apply_async_id) apply_async_id; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.activate_async_id) activate_async_id; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.cancel_async_id) cancel_async_id; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.rpc_build_env) rpc_build_environment; \
	x __attribute__((__unused__)) decltype(dlfuncs::rpc_new_stack) rpc_new_stack; \
	x __attribute__((__unused__)) decltype(dlfuncs::rpc_free_stack) rpc_free_stack; \
	x __attribute__((__unused__)) decltype(dlfuncs::proc.async_reply) async_reply; \
}
#define register_service(n, f) service_register_service((n), reinterpret_cast<void *>(f), typeid(decltype(*(f))))
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(service_query((n), typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)

#define LINK_PROC_API(param) \
	register_endpoint = param.proc.reg_ep; \
	register_interface = param.proc.reg_intf; \
	get_host_ID = param.get_host_ID; \
	get_config_path = param.get_config_path; \
	get_data_path = param.get_data_path; \
	get_context_num = param.get_context_num; \
	get_binding_handle = param.proc.get_binding_handle; \
	get_rpc_info = param.proc.get_rpc_info; \
	is_rpc_bigendian = param.proc.is_rpc_bigendian; \
	ndr_stack_alloc = param.ndr_stack_alloc; \
	apply_async_id = param.proc.apply_async_id; \
	activate_async_id = param.proc.activate_async_id; \
	cancel_async_id = param.proc.cancel_async_id; \
	rpc_build_environment = param.proc.rpc_build_env; \
	rpc_new_stack = param.rpc_new_stack; \
	rpc_free_stack = param.rpc_free_stack; \
	async_reply = param.proc.async_reply;
