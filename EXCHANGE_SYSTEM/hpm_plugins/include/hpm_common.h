#ifndef _H_PLUGIN_
#define _H_PLUGIN_

#include "mem_file.h"
#include "common_types.h"

#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1

#define HPM_RETRIEVE_ERROR			0
#define HPM_RETRIEVE_WRITE			1
#define HPM_RETRIEVE_WAIT			2
#define HPM_RETRIEVE_DONE			3

typedef struct _HPM_INTERFACE {
	BOOL (*preproc)(int);
	BOOL (*proc)(int, const void*, uint64_t);
	int (*retr)(int);
	void (*term)(int);
} HPM_INTERFACE;

typedef struct _HTTP_REQUEST {
	char		method[32];
	MEM_FILE	f_request_uri;
	char		version[8];
	MEM_FILE	f_host;
	MEM_FILE    f_user_agent;
    MEM_FILE    f_accept;
	MEM_FILE	f_accept_language;
	MEM_FILE	f_accept_encoding;
	MEM_FILE	f_content_type;
	MEM_FILE	f_content_length;
	MEM_FILE	f_transfer_encoding;
	MEM_FILE	f_cookie;
    MEM_FILE    f_others;
} HTTP_REQUEST;

typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef void* (*QUERY_SERVICE)(char*);
typedef int (*QUERY_VERSION)();
typedef const char* (*GET_ENVIRONMENT)();
typedef int (*GET_INTEGER)();
typedef BOOL (*REGISTER_INTERFACE)(HPM_INTERFACE*);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef HTTP_REQUEST* (*GET_REQUEST)(int);
typedef BOOL (*WRITE_RESPONSE)(int, void*, int);
typedef void (*WAKEUP_CONTEXT)(int);
typedef void (*LOG_INFO)(int, char*, ...);

extern QUERY_VERSION query_version;
extern QUERY_SERVICE query_service;
extern TALK_REGISTRATION register_talk, unregister_talk;
extern REGISTER_INTERFACE register_interface;
extern GET_REQUEST get_request;
extern WRITE_RESPONSE write_response;
extern WAKEUP_CONTEXT wakeup_context;
extern LOG_INFO log_info;
extern GET_ENVIRONMENT get_host_ID;
extern GET_ENVIRONMENT get_default_domain;
extern GET_ENVIRONMENT get_plugin_name;
extern GET_ENVIRONMENT get_config_path;
extern GET_ENVIRONMENT get_data_path;
extern GET_INTEGER get_context_num;
	
#define DECLARE_API \
	QUERY_VERSION query_version; \
	QUERY_SERVICE query_service; \
	REGISTER_INTERFACE register_interface; \
	TALK_REGISTRATION register_talk, unregister_talk; \
	GET_REQUEST get_request; \
	WRITE_RESPONSE write_response; \
	WAKEUP_CONTEXT wakeup_context; \
	LOG_INFO log_info; \
	GET_ENVIRONMENT get_host_ID; \
	GET_ENVIRONMENT get_default_domain; \
	GET_ENVIRONMENT get_plugin_name; \
	GET_ENVIRONMENT get_config_path; \
	GET_ENVIRONMENT get_data_path; \
	GET_INTEGER get_context_num;
	
#define LINK_API(param) \
	query_version = (QUERY_VERSION)param[0]; \
	query_service = (QUERY_SERVICE)param[1]; \
	register_interface = (REGISTER_INTERFACE)query_service("register_interface");\
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	unregister_talk = (TALK_REGISTRATION)query_service("unregister_talk"); \
	get_request = (GET_REQUEST)query_service("get_request"); \
	write_response = (WRITE_RESPONSE)query_service("write_response"); \
	wakeup_context = (WAKEUP_CONTEXT)query_service("wakeup_context"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	get_default_domain = (GET_ENVIRONMENT)query_service("get_default_domain"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num");
	
#endif
