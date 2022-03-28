#pragma once
#include <cstdint>
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/dcerpc.hpp>
#include <gromox/ndr.hpp>
#include <gromox/plugin.hpp>
#include <gromox/rpc_types.hpp>
#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

#define DISPATCH_FAIL				0
#define DISPATCH_SUCCESS			1
#define DISPATCH_PENDING			2

struct DCERPC_ENDPOINT;
struct DCERPC_INFO;
struct DCERPC_INTERFACE;
#define DECLARE_PROC_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x BOOL (*register_serviceF)(const char *, void *, const std::type_info &); \
	x DCERPC_ENDPOINT *(*register_endpoint)(const char *, int); \
	x BOOL (*register_interface)(DCERPC_ENDPOINT *, const DCERPC_INTERFACE *); \
	x void (*unregister_interface)(DCERPC_ENDPOINT *, const DCERPC_INTERFACE *); \
	x void (*log_info)(unsigned int, const char *, ...); \
	x const char *(*get_host_ID)(); \
	x const char *(*get_plugin_name)(); \
	x const char *(*get_config_path)(); \
	x const char *(*get_data_path)(); \
	x const char *(*get_state_path)(); \
	x int (*get_context_num)(); \
	x uint64_t (*get_binding_handle)(); \
	x DCERPC_INFO (*get_rpc_info)(); \
	x BOOL (*is_rpc_bigendian)(); \
	x void *(*ndr_stack_alloc)(int, size_t); \
	x int (*apply_async_id)(); \
	x void (*activate_async_id)(int); \
	x void (*cancel_async_id)(int); \
	x BOOL (*rpc_build_environment)(int); \
	x void (*rpc_new_environment)(); \
	x void (*rpc_free_environment)(); \
	x void (*async_reply)(int, void *);
#define register_service(n, f) register_serviceF((n), reinterpret_cast<void *>(f), typeid(decltype(*(f))))
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_PROC_API_STATIC
DECLARE_PROC_API(static);
#else
DECLARE_PROC_API(extern);
#endif

#define LINK_PROC_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service2("register_service", register_serviceF); \
	query_service1(register_endpoint); \
	query_service1(register_interface); \
	query_service1(unregister_interface); \
	query_service1(log_info); \
	query_service1(get_host_ID); \
	query_service1(get_plugin_name); \
	query_service1(get_config_path); \
	query_service1(get_data_path); \
	query_service1(get_state_path); \
	query_service1(get_context_num); \
	query_service1(get_binding_handle); \
	query_service1(get_rpc_info); \
	query_service1(is_rpc_bigendian); \
	query_service1(ndr_stack_alloc); \
	query_service1(apply_async_id); \
	query_service1(activate_async_id); \
	query_service1(cancel_async_id); \
	query_service1(rpc_build_environment); \
	query_service1(rpc_new_environment); \
	query_service1(rpc_free_environment); \
	query_service1(async_reply);
#define PROC_ENTRY(s) BOOL PROC_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL PROC_LibMain(int reason, void **ptrs);
}
