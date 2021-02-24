#pragma once
#include <cstdint>
#include <typeinfo>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#include <gromox/rpc_types.hpp>
#include <gromox/ndr.hpp>
#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1

#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

#define DISPATCH_FAIL				0
#define DISPATCH_SUCCESS			1
#define DISPATCH_PENDING			2

#define DCERPC_CALL_STAT_FLAG_HEADER_SIGNING		0x04
#define DCERPC_CALL_STAT_FLAG_MULTIPLEXED			0x10

struct DCERPC_INFO {
	const char *client_ip;
	int client_port;
	const char *server_ip; /* http server ip */
	int server_port;       /* http server port */
	const char *ep_host;   /* endpoint host name */
	int ep_port;           /* endpoint port */
	BOOL is_login;         /* if client login */
	const char *username;  /* username of client by http auth */
	const char *maildir;
	const char *lang;
	uint32_t stat_flags;   /* state flags of rpc context */
}; /* used for proc plugin to get dcerpc information */

struct DCERPC_INTERFACE {
	char name[128];
	GUID uuid;
	uint32_t version;
	/* the ndr_pull function for the chosen interface. */
	int (*ndr_pull)(int opnum, NDR_PULL* pndr, void **ppin);
	/* the dispatch function for the chosen interface. */
	int (*dispatch)(int opnum, const GUID*, uint64_t handle,
		void *pin, void **ppout);
	/* the ndr_push function for the chosen interface. */
	int (*ndr_push)(int opnum, NDR_PUSH *pndr, void *pout);
	/* free pout pointer produced by dispatch after ndr_push*/
	void (*unbind)(uint64_t handle);
	/* the reclaim function for the chosen interface */
	void (*reclaim)(uint32_t async_id);
};

typedef void (*TALK_MAIN)(int, char**, char*, int);

#define DECLARE_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x BOOL (*register_serviceF)(const char *, void *, const std::type_info &); \
	x void *(*register_endpoint)(const char *, int); \
	x BOOL (*register_interface)(void *, DCERPC_INTERFACE *); \
	x BOOL (*register_talk)(TALK_MAIN); \
	x void (*log_info)(int, const char *, ...); \
	x const char *(*get_host_ID)(); \
	x const char *(*get_default_domain)(); \
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
#define register_service(n, f) register_serviceF((n), reinterpret_cast<void *>(f), typeid(*(f)))
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(*(f)))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif

#define LINK_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service2("register_service", register_serviceF); \
	query_service1(register_endpoint); \
	query_service1(register_interface); \
	query_service1(register_talk); \
	query_service1(log_info); \
	query_service1(get_host_ID); \
	query_service1(get_default_domain); \
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
