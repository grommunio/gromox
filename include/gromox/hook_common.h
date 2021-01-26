#pragma once
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
typedef void *(*QUERY_SERVICE)(const char *);
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
	x QUERY_SERVICE query_service; \
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
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif

#define LINK_API(param) \
	query_service = (QUERY_SERVICE)param[0]; \
	register_hook = (HOOK_REGISTRATION)query_service("register_hook"); \
	register_local = (HOOK_REGISTRATION)query_service("register_local");\
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	get_default_domain = (GET_ENVIRONMENT)query_service("get_default_domain"); \
	get_admin_mailbox = (GET_ENVIRONMENT)query_service("get_admin_mailbox"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_state_path = (GET_ENVIRONMENT)query_service("get_state_path"); \
	get_queue_path = (GET_ENVIRONMENT)query_service("get_queue_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	get_threads_num = (GET_INTEGER)query_service("get_threads_num"); \
	get_context = (GET_CONTEXT)query_service("get_context"); \
	put_context = (PUT_CONTEXT)query_service("put_context"); \
	enqueue_context = (ENQUEUE_CONTEXT)query_service("enqueue_context"); \
	throw_context = (THROW_CONTEXT)query_service("throw_context"); \
	check_domain = (CHECKING_FUNCTION)query_service("check_domain"); \
	is_domainlist_valid=(IS_DOMAINLIST_VALID)query_service("is_domainlist_valid")

extern "C" { /* dlsym */
extern GX_EXPORT BOOL HOOK_LibMain(int reason, void **ptrs);
}
