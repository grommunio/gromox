#pragma once
#include <gromox/defs.h>
#include "common_types.h"
#include "mem_file.h"
#include "mail.h"

#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1
#define SYS_THREAD_CREATE           2
#define SYS_THREAD_DESTROY          3

#define BOUND_IN					1    /* message smtp in */
#define BOUND_OUT					2    /* message smtp out */
#define BOUND_RELAY					3    /* message smtp relay */
#define	BOUND_SELF					4    /* message creted by hook */

typedef struct _CONTROL_INFO{
	int         queue_ID;
	int			bound_type;
	BOOL        is_spam;
	BOOL        need_bounce;
	char        from[256];
	MEM_FILE    f_rcpt_to;
} CONTROL_INFO;

typedef struct _MESSAGE_CONTEXT{
	CONTROL_INFO *pcontrol;
	MAIL         *pmail;
} MESSAGE_CONTEXT;

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

#ifdef __cplusplus
extern "C" {
#endif

extern QUERY_SERVICE query_service;
extern HOOK_REGISTRATION register_hook, unregister_hook;
extern HOOK_REGISTRATION register_local, register_remote;
extern TALK_REGISTRATION register_talk, unregister_talk;
extern LOG_INFO log_info;
extern GET_ENVIRONMENT get_host_ID;
extern GET_ENVIRONMENT get_default_domain;
extern GET_ENVIRONMENT get_admin_mailbox;
extern GET_ENVIRONMENT get_plugin_name;
extern GET_ENVIRONMENT get_config_path;
extern GET_ENVIRONMENT get_data_path;
extern GET_ENVIRONMENT get_queue_path;
extern GET_INTEGER get_context_num;
extern GET_INTEGER get_threads_num;
extern GET_CONTEXT get_context;
extern PUT_CONTEXT put_context;
extern ENQUEUE_CONTEXT enqueue_context;
extern THROW_CONTEXT throw_context;
extern CHECKING_FUNCTION check_domain;
extern IS_DOMAINLIST_VALID is_domainlist_valid;

	
#define DECLARE_API \
	QUERY_SERVICE query_service; \
	HOOK_REGISTRATION register_hook, unregister_hook; \
	HOOK_REGISTRATION register_local, register_remote; \
	TALK_REGISTRATION register_talk, unregister_talk; \
	LOG_INFO log_info; \
	GET_ENVIRONMENT get_host_ID; \
	GET_ENVIRONMENT get_default_domain; \
	GET_ENVIRONMENT get_admin_mailbox; \
	GET_ENVIRONMENT get_plugin_name; \
	GET_ENVIRONMENT get_config_path; \
	GET_ENVIRONMENT get_data_path; \
	GET_ENVIRONMENT get_queue_path; \
	GET_INTEGER get_context_num; \
	GET_INTEGER get_threads_num; \
    GET_CONTEXT get_context; \
    PUT_CONTEXT put_context; \
	ENQUEUE_CONTEXT enqueue_context; \
    THROW_CONTEXT throw_context; \
	CHECKING_FUNCTION check_domain; \
	IS_DOMAINLIST_VALID is_domainlist_valid

#define LINK_API(param) \
	query_service = (QUERY_SERVICE)param[0]; \
	register_hook = (HOOK_REGISTRATION)query_service("register_hook"); \
	unregister_hook = (HOOK_REGISTRATION)query_service("unregister_hook"); \
	register_local = (HOOK_REGISTRATION)query_service("register_local");\
	register_remote = (HOOK_REGISTRATION)query_service("register_remote"); \
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	unregister_talk = (TALK_REGISTRATION)query_service("unregister_talk"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	get_default_domain = (GET_ENVIRONMENT)query_service("get_default_domain"); \
	get_admin_mailbox = (GET_ENVIRONMENT)query_service("get_admin_mailbox"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_queue_path = (GET_ENVIRONMENT)query_service("get_queue_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	get_threads_num = (GET_INTEGER)query_service("get_threads_num"); \
	get_context = (GET_CONTEXT)query_service("get_context"); \
	put_context = (PUT_CONTEXT)query_service("put_context"); \
	enqueue_context = (ENQUEUE_CONTEXT)query_service("enqueue_context"); \
	throw_context = (THROW_CONTEXT)query_service("throw_context"); \
	check_domain = (CHECKING_FUNCTION)query_service("check_domain"); \
	is_domainlist_valid=(IS_DOMAINLIST_VALID)query_service("is_domainlist_valid")

extern GX_EXPORT BOOL HOOK_LibMain(int reason, void **ptrs);

#ifdef __cplusplus
} /* extern "C" */
#endif
