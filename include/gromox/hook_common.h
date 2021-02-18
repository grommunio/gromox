#pragma once
#include <typeinfo>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/mail.hpp>
#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1
#define SYS_THREAD_CREATE           2
#define SYS_THREAD_DESTROY          3

#define BOUND_IN					1    /* message smtp in */
#define BOUND_OUT					2    /* message smtp out */
#define BOUND_RELAY					3    /* message smtp relay */
#define	BOUND_SELF					4    /* message creted by hook */

struct CONTROL_INFO {
	int         queue_ID;
	int			bound_type;
	BOOL        is_spam;
	BOOL        need_bounce;
	char from[324];
	MEM_FILE    f_rcpt_to;
};

struct MESSAGE_CONTEXT {
	CONTROL_INFO *pcontrol;
	MAIL         *pmail;
};

typedef BOOL (*HOOK_FUNCTION)(MESSAGE_CONTEXT*);
typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef int (*GET_INTEGER)(void);
typedef BOOL(*HOOK_REGISTRATION)(HOOK_FUNCTION);
typedef BOOL(*TALK_REGISTRATION)(TALK_MAIN);
/* represent function type of log_info */
typedef void (*LOG_INFO)(int, const char *, ...);
typedef MESSAGE_CONTEXT *(*GET_CONTEXT)(void);
typedef void (*PUT_CONTEXT)(MESSAGE_CONTEXT*);
typedef BOOL (*THROW_CONTEXT)(MESSAGE_CONTEXT*);
typedef void (*ENQUEUE_CONTEXT)(MESSAGE_CONTEXT*);
typedef BOOL (*CHECKING_FUNCTION)(char*);
/* is domain list valid, if TRUE, check_domain will functionate */
typedef BOOL (*IS_DOMAINLIST_VALID)(void);

#define DECLARE_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x HOOK_REGISTRATION register_hook; \
	x HOOK_REGISTRATION register_local; \
	x TALK_REGISTRATION register_talk; \
	x LOG_INFO log_info; \
	x GET_ENVIRONMENT get_host_ID; \
	x GET_ENVIRONMENT get_default_domain; \
	x GET_ENVIRONMENT get_admin_mailbox; \
	x GET_ENVIRONMENT get_plugin_name; \
	x GET_ENVIRONMENT get_config_path; \
	x GET_ENVIRONMENT get_data_path, get_state_path; \
	x GET_ENVIRONMENT get_queue_path; \
	x GET_INTEGER get_context_num; \
	x GET_INTEGER get_threads_num; \
	x GET_CONTEXT get_context; \
	x PUT_CONTEXT put_context; \
	x ENQUEUE_CONTEXT enqueue_context; \
	x THROW_CONTEXT throw_context; \
	x CHECKING_FUNCTION check_domain; \
	x IS_DOMAINLIST_VALID is_domainlist_valid;
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(*(f)))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif

#define LINK_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service1(register_hook); \
	query_service1(register_local); \
	query_service1(register_talk); \
	query_service1(log_info); \
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
	query_service1(throw_context); \
	query_service1(check_domain); \
	query_service1(is_domainlist_valid);
#define HOOK_ENTRY(s) BOOL HOOK_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL HOOK_LibMain(int reason, void **ptrs);
}
