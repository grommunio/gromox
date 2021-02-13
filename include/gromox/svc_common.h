#pragma once
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#define PLUGIN_INIT     0
#define PLUGIN_FREE     1

#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

typedef void *(*QUERY_SERVICE)(const char *);
typedef BOOL (*SERVICE_REGISTRATION)(const char *, void *);
typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef int (*GET_INTEGER)(void);
typedef void* (*NDR_STACK_ALLOC)(int, size_t);

#define	DECLARE_API(x) \
	x QUERY_SERVICE query_service; \
	x SERVICE_REGISTRATION register_service; \
	x TALK_REGISTRATION register_talk; \
	x GET_ENVIRONMENT get_plugin_name; \
	x GET_ENVIRONMENT get_config_path; \
	x GET_ENVIRONMENT get_data_path, get_state_path; \
	x GET_INTEGER get_context_num; \
	x GET_ENVIRONMENT get_host_ID; \
	x NDR_STACK_ALLOC ndr_stack_alloc;
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif

#define LINK_API(param) \
	query_service = (QUERY_SERVICE)param[0]; \
	register_service = (SERVICE_REGISTRATION)query_service("register_service");\
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_state_path = (GET_ENVIRONMENT)query_service("get_state_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	ndr_stack_alloc = (NDR_STACK_ALLOC)query_service("ndr_stack_alloc")
#define SVC_ENTRY(s) BOOL SVC_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL SVC_LibMain(int reason, void **ptrs);
}
