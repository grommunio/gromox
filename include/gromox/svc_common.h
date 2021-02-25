#pragma once
#include <typeinfo>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#define PLUGIN_INIT     0
#define PLUGIN_FREE     1

#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

typedef void (*TALK_MAIN)(int, char**, char*, int);

#define	DECLARE_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x BOOL (*register_serviceF)(const char *, void *, const std::type_info &); \
	x BOOL (*register_talk)(TALK_MAIN); \
	x const char *(*get_plugin_name)(); \
	x const char *(*get_config_path)(); \
	x const char *(*get_data_path)(); \
	x const char *(*get_state_path)(); \
	x int (*get_context_num)(); \
	x const char *(*get_host_ID)(); \
	x void *(*ndr_stack_alloc)(int, size_t);
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
	query_service1(register_talk); \
	query_service1(get_plugin_name); \
	query_service1(get_config_path); \
	query_service1(get_data_path); \
	query_service1(get_state_path); \
	query_service1(get_context_num); \
	query_service1(get_host_ID); \
	query_service1(ndr_stack_alloc);
#define SVC_ENTRY(s) BOOL SVC_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL SVC_LibMain(int reason, void **ptrs);
}
