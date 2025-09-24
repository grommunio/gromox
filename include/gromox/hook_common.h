#pragma once 
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mail.hpp>
#include <gromox/plugin.hpp>
#define SYS_THREAD_CREATE           2
#define SYS_THREAD_DESTROY          3

enum {
	BOUND_UNKNOWN, /* unknown message type */
	BOUND_IN, /* message smtp in */
	BOUND_SELF, /* message created by hook larger than BOUND_SELF */
};

struct GX_EXPORT CONTROL_INFO {
	int queue_ID = 0, bound_type = 0;
	BOOL need_bounce = false;
	char from[UADDR_SIZE]{};
	std::vector<std::string> rcpt;
};

struct GX_EXPORT MESSAGE_CONTEXT {
	CONTROL_INFO ctrl;
	MAIL mail; /* Note limitations of MAIL's default ctor */
};

/* Plugin is expected to use `using namespace ns;` too */
#define DECLARE_HOOK_API(ns, x) namespace ns { \
	x decltype(dlfuncs::symget) imp__symget; \
	x decltype(dlfuncs::hook.register_hook) register_hook; \
	x decltype(dlfuncs::hook.register_local) register_local; \
	x decltype(dlfuncs::get_host_ID) get_host_ID; \
	x decltype(dlfuncs::get_config_path) get_config_path; \
	x decltype(dlfuncs::get_data_path) get_data_path; \
	x decltype(dlfuncs::hook.get_admin_mailbox) get_admin_mailbox; \
	x decltype(dlfuncs::hook.get_queue_path) get_queue_path; \
	x decltype(dlfuncs::get_context_num) get_context_num; \
	x decltype(dlfuncs::hook.get_threads_num) get_threads_num; \
	x decltype(dlfuncs::hook.get_ctx) get_context; \
	x decltype(dlfuncs::hook.put_ctx) put_context; \
	x decltype(dlfuncs::hook.enqueue_ctx) enqueue_context; \
	x decltype(dlfuncs::hook.throw_ctx) throw_context; \
}
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(imp__symget((n), nullptr, typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)

#define LINK_HOOK_API(param) \
	imp__symget = param.symget; \
	register_hook = param.hook.register_hook; \
	register_local = param.hook.register_local; \
	get_host_ID = param.get_host_ID; \
	get_admin_mailbox = param.hook.get_admin_mailbox; \
	get_config_path = param.get_config_path; \
	get_data_path = param.get_data_path; \
	get_queue_path = param.hook.get_queue_path; \
	get_context_num = param.get_context_num; \
	get_threads_num = param.hook.get_threads_num; \
	get_context = param.hook.get_ctx; \
	put_context = param.hook.put_ctx; \
	enqueue_context = param.hook.enqueue_ctx; \
	throw_context = param.hook.throw_ctx;
