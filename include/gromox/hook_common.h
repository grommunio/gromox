#pragma once
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mail.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/plugin.hpp>
#define SYS_THREAD_CREATE           2
#define SYS_THREAD_DESTROY          3

enum {
	BOUND_UNKNOWN, /* unknown message type */
	BOUND_IN, /* message smtp in */
	BOUND_OUT, /* message smtp out */
	BOUND_RELAY, /* message smtp relay */
	BOUND_SELF, /* message created by hook larger than BOUND_SELF */
};

struct CONTROL_INFO {
	int queue_ID = 0, bound_type = 0;
	BOOL is_spam = false, need_bounce = false;
	char from[UADDR_SIZE]{};
	MEM_FILE f_rcpt_to{};
};

struct MESSAGE_CONTEXT {
	CONTROL_INFO *pcontrol = nullptr;
	MAIL *pmail = nullptr;
};

using HOOK_FUNCTION = BOOL (*)(MESSAGE_CONTEXT *);

#define DECLARE_HOOK_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x BOOL (*register_hook)(HOOK_FUNCTION); \
	x BOOL (*register_local)(HOOK_FUNCTION); \
	x BOOL (*register_remote)(HOOK_FUNCTION); \
	x const char *(*get_host_ID)(); \
	x const char *(*get_default_domain)(); \
	x const char *(*get_admin_mailbox)(); \
	x const char *(*get_plugin_name)(); \
	x const char *(*get_config_path)(); \
	x const char *(*get_data_path)(); \
	x const char *(*get_state_path)(); \
	x const char *(*get_queue_path)(); \
	x unsigned int (*get_context_num)(); \
	x unsigned int (*get_threads_num)(); \
	x MESSAGE_CONTEXT *(*get_context)(); \
	x void (*put_context)(MESSAGE_CONTEXT *); \
	x void (*enqueue_context)(MESSAGE_CONTEXT *); \
	x BOOL (*throw_context)(MESSAGE_CONTEXT *);
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_HOOK_API_STATIC
DECLARE_HOOK_API(static);
#else
DECLARE_HOOK_API(extern);
#endif

#define LINK_HOOK_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service1(register_hook); \
	query_service1(register_local); \
	query_service1(register_remote); \
	query_service1(get_host_ID); \
	query_service1(get_default_domain); \
	query_service1(get_admin_mailbox); \
	query_service1(get_plugin_name); \
	query_service1(get_config_path); \
	query_service1(get_data_path); \
	query_service1(get_state_path); \
	query_service1(get_queue_path); \
	query_service1(get_context_num); \
	query_service1(get_threads_num); \
	query_service1(get_context); \
	query_service1(put_context); \
	query_service1(enqueue_context); \
	query_service1(throw_context);
#define HOOK_ENTRY(s) BOOL HOOK_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL HOOK_LibMain(int reason, void **ptrs);
}
