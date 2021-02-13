#pragma once
#include <cstdint>
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
typedef void *(*QUERY_SERVICE)(const char *);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef int (*GET_INTEGER)(void);
typedef void (*SET_INTEGER)(int);
typedef BOOL (*GET_BOOLEAN)(void);
typedef void* (*EP_REGISTRATION)(const char*, int);
typedef BOOL (*IF_REGISTRATION)(void*, DCERPC_INTERFACE*);
typedef DCERPC_INFO (*GET_RPC_INFO)(void);
typedef uint64_t (*GET_BINDING_HANDLE)(void);
typedef void* (*NDR_STACK_ALLOC)(int, size_t);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef BOOL (*BUILD_ENVIRONMENT)(int);
typedef BOOL (*NEW_ENVIRONMENT)(void);
typedef void (*FREE_ENVIRONMENT)(void);
typedef void (*ASYNC_REPLY)(int, void*);
/* represent function type of log_info */
typedef void (*LOG_INFO)(int, const char *, ...);

#define DECLARE_API(x) \
	x QUERY_SERVICE query_service; \
	x EP_REGISTRATION register_endpoint; \
	x IF_REGISTRATION register_interface; \
	x TALK_REGISTRATION register_talk; \
	x LOG_INFO log_info; \
	x GET_ENVIRONMENT get_host_ID; \
	x GET_ENVIRONMENT get_default_domain; \
	x GET_ENVIRONMENT get_plugin_name; \
	x GET_ENVIRONMENT get_config_path; \
	x GET_ENVIRONMENT get_data_path, get_state_path; \
	x GET_INTEGER get_context_num; \
	x GET_BINDING_HANDLE get_binding_handle; \
	x GET_RPC_INFO get_rpc_info; \
	x GET_BOOLEAN is_rpc_bigendian; \
	x NDR_STACK_ALLOC ndr_stack_alloc; \
	x GET_INTEGER apply_async_id; \
	x SET_INTEGER activate_async_id; \
	x SET_INTEGER cancel_async_id; \
	x BUILD_ENVIRONMENT rpc_build_environment; \
	x NEW_ENVIRONMENT rpc_new_environment; \
	x FREE_ENVIRONMENT rpc_free_environment; \
	x ASYNC_REPLY async_reply;
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif

#define LINK_API(param) \
	query_service = (QUERY_SERVICE)param[0]; \
	register_endpoint = (EP_REGISTRATION)query_service("register_endpoint"); \
	register_interface = (IF_REGISTRATION)query_service("register_interface");\
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	get_default_domain = (GET_ENVIRONMENT)query_service("get_default_domain"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_state_path = (GET_ENVIRONMENT)query_service("get_state_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	get_binding_handle = (GET_BINDING_HANDLE)query_service("get_binding_handle"); \
	get_rpc_info = (GET_RPC_INFO)query_service("get_rpc_info"); \
	is_rpc_bigendian = (GET_BOOLEAN)query_service("is_rpc_bigendian"); \
	ndr_stack_alloc = (NDR_STACK_ALLOC)query_service("ndr_stack_alloc"); \
	apply_async_id = (GET_INTEGER)query_service("apply_async_id"); \
	activate_async_id = (SET_INTEGER)query_service("activate_async_id"); \
	cancel_async_id = (SET_INTEGER)query_service("cancel_async_id"); \
	rpc_build_environment = (BUILD_ENVIRONMENT)query_service("rpc_build_environment"); \
	rpc_new_environment = (NEW_ENVIRONMENT)query_service("rpc_new_environment"); \
	rpc_free_environment = (FREE_ENVIRONMENT)query_service("rpc_free_environment"); \
	async_reply = (ASYNC_REPLY)query_service("async_reply")
#define PROC_ENTRY(s) BOOL PROC_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL PROC_LibMain(int reason, void **ptrs);
}
