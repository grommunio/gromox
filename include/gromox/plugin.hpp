/*
 *  define the constant for plugin's return value load, unload, reload actions.
 */
#pragma once
#include <string>
#include <gromox/common_types.hpp>

/* enumeration for indicate the ation of plugin_main function */
enum plugin_op {
    PLUGIN_INIT,
    PLUGIN_FREE,
    PLUGIN_THREAD_CREATE,
	PLUGIN_THREAD_DESTROY,
	PLUGIN_RELOAD,
	PLUGIN_EARLY_INIT,
	PLUGIN_REPORT,
};

/* enumeration for the return value of xxx_load_library */
enum{
	PLUGIN_FAIL_EXECUTEMAIN = -5,
    PLUGIN_FAIL_ALLOCNODE,
    PLUGIN_NO_MAIN,
    PLUGIN_FAIL_OPEN,
    PLUGIN_ALREADY_LOADED,
    PLUGIN_LOAD_OK = 0,
};

namespace gromox {

/**
 * %xcontinue:	indicates that a hook may have done something; in any case,
 * 		subsequent hooks should be run
 * %stop:	this hook has done something and the message is processed in
 * 		the sense that no further hooks should run
 * %proc_error:	error during processing; stop hooks altogether and retain the
 *              message for later
 */
enum class hook_result {
	xcontinue = 0, stop, proc_error,
};

}

enum class http_status;
struct DCERPC_ENDPOINT;
struct DCERPC_INFO;
struct DCERPC_INTERFACE;
struct GENERIC_CONNECTION;
struct MESSAGE_CONTEXT;
struct HPM_INTERFACE;
struct http_request;
struct HTTP_AUTH_INFO;
using HOOK_FUNCTION = gromox::hook_result (*)(MESSAGE_CONTEXT *);

struct dlfuncs {
	void *(*symget)(const char *service, const char *requestor, const std::type_info &);
	BOOL (*symreg)(const char *, void *, const std::type_info &);
	const char *(*get_config_path)();
	const char *(*get_data_path)();
	unsigned int (*get_context_num)();
	const char *(*get_host_ID)();
	const char *(*get_prog_id)();
	void *(*ndr_stack_alloc)(int, size_t);
	BOOL (*rpc_new_stack)();
	void (*rpc_free_stack)();

	// PROC_
	struct {
		DCERPC_ENDPOINT *(*reg_ep)(const char *, uint16_t);
		BOOL (*reg_intf)(DCERPC_ENDPOINT *, const DCERPC_INTERFACE *);
		void (*unreg_intf)(DCERPC_ENDPOINT *, const DCERPC_INTERFACE *);
		uint64_t (*get_binding_handle)();
		DCERPC_INFO (*get_rpc_info)();
		BOOL (*is_rpc_bigendian)();
		uint32_t (*apply_async_id)();
		void (*activate_async_id)(uint32_t);
		void (*cancel_async_id)(uint32_t);
		BOOL (*rpc_build_env)(int);
		void (*async_reply)(uint32_t, void *);
	} proc;

	// HPM_
	struct {
		BOOL (*reg_intf)(HPM_INTERFACE *);
		http_request *(*get_req)(unsigned int);
		HTTP_AUTH_INFO (*get_auth_info)(unsigned int);
		GENERIC_CONNECTION *(*get_conn)(unsigned int);
		http_status (*write_response)(unsigned int, const void *, size_t);
		void (*wakeup_ctx)(unsigned int);
		void (*activate_ctx)(unsigned int);
		void (*set_ctx)(int);
		void (*set_ep_info)(unsigned int, const char *, int);
	} hpm;

	// HOOK_
	struct {
		BOOL (*register_hook)(HOOK_FUNCTION);
		BOOL (*register_local)(HOOK_FUNCTION);
		const char *(*get_admin_mailbox)();
		const char *(*get_queue_path)();
		unsigned int (*get_threads_num)();
		MESSAGE_CONTEXT *(*get_ctx)();
		void (*put_ctx)(MESSAGE_CONTEXT *);
		void (*enqueue_ctx)(MESSAGE_CONTEXT *);
		BOOL (*throw_ctx)(MESSAGE_CONTEXT *);
	} hook;
};

using PLUGIN_MAIN = BOOL (*)(enum plugin_op, const struct dlfuncs &);
using PLUGIN_DMAIN = BOOL (enum plugin_op, const struct dlfuncs &);

extern "C" GX_EXPORT PLUGIN_DMAIN
	HOOK_alias_resolve, HOOK_exmdb_local,
	PROC_exchange_emsmdb, PROC_exchange_nsp, PROC_exchange_rfr,
	HPM_ews, HPM_mh_emsmdb, HPM_mh_nsp, HPM_oab, HPM_oxdisco,
	SVC_authmgr, SVC_dnsbl_filter, SVC_exmdb_provider, SVC_ldap_adaptor,
	SVC_mysql_adaptor, SVC_timer_agent, SVC_user_filter, SVC_event_proxy,
	SVC_event_stub, SVC_midb_agent;

namespace gromox {

struct service_node {
	void *service_addr = nullptr;
	std::string service_name;
};

struct static_module {
	std::string path;
	PLUGIN_MAIN efunc;
};

struct generic_module {
	generic_module() = default;
	generic_module(generic_module &&) noexcept;
	void operator=(generic_module &&) noexcept = delete;

	std::string file_name;
	PLUGIN_MAIN lib_main = nullptr;
	bool completed_init = false;
};

}
