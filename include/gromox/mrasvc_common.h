#ifndef _H_SERVICE_COMMON_
#define _H_SERVICE_COMMON_
#include "common_types.h"

#define PLUGIN_INIT     0
#define PLUGIN_FREE     1

typedef void *(*QUERY_SERVICE)(const char *);
typedef int (*QUERY_VERSION)(void);
typedef BOOL (*SERVICE_REGISTRATION)(const char *, void *);
typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef int (*GET_INTEGER)(void);

extern QUERY_VERSION query_version;
extern QUERY_SERVICE query_service;
extern SERVICE_REGISTRATION register_service;
extern TALK_REGISTRATION register_talk;
extern TALK_REGISTRATION unregister_talk;
extern GET_ENVIRONMENT get_plugin_name;
extern GET_ENVIRONMENT get_config_path;
extern GET_ENVIRONMENT get_data_path;
extern GET_INTEGER get_context_num;
extern GET_ENVIRONMENT get_host_ID;

#define	DECLARE_API \
	QUERY_VERSION query_version; \
	QUERY_SERVICE query_service; \
	SERVICE_REGISTRATION register_service; \
	TALK_REGISTRATION register_talk; \
	TALK_REGISTRATION unregister_talk; \
	GET_ENVIRONMENT get_plugin_name; \
	GET_ENVIRONMENT get_config_path; \
	GET_ENVIRONMENT get_data_path; \
	GET_INTEGER get_context_num; \
	GET_ENVIRONMENT get_host_ID

#define LINK_API(param) \
	query_version = (QUERY_VERSION)param[0]; \
	query_service = (QUERY_SERVICE)param[1]; \
	register_service = (SERVICE_REGISTRATION)query_service("register_service");\
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	unregister_talk = (TALK_REGISTRATION)query_service("unregister_talk"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID")

#endif /* _H_SERVICE_COMMON_ */

