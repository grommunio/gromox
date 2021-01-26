#pragma once
#include <cstdint>
#include <gromox/mem_file.hpp>
#include <gromox/common_types.hpp>
#include <openssl/ssl.h>
#include <gromox/defs.h>
#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1

#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

#define HPM_RETRIEVE_ERROR			0
#define HPM_RETRIEVE_WRITE			1
#define HPM_RETRIEVE_NONE			2
#define HPM_RETRIEVE_WAIT			3
#define HPM_RETRIEVE_DONE			4
#define HPM_RETRIEVE_SOCKET			5

struct HPM_INTERFACE {
	BOOL (*preproc)(int);
	BOOL (*proc)(int, const void*, uint64_t);
	int (*retr)(int);
	BOOL (*send)(int, const void*, int);
	int (*receive)(int, void*, int length);
	void (*term)(int);
};

struct CONNECTION {
	char client_ip[32];
	int				client_port;
	char server_ip[32];
	int				server_port;
	int				sockd;
	SSL				*ssl;
	struct timeval	last_timestamp;
};

struct HTTP_REQUEST {
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
};

struct HTTP_AUTH_INFO {
	BOOL b_authed;
	const char* username;
	const char* password;
	const char* maildir;
	const char* lang;
};

typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef void *(*QUERY_SERVICE)(const char *);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef int (*GET_INTEGER)(void);
typedef void (*SET_INTEGER)(int);
typedef BOOL (*REGISTER_INTERFACE)(HPM_INTERFACE*);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef CONNECTION* (*GET_CONNECTION)(int);
typedef HTTP_REQUEST* (*GET_REQUEST)(int);
typedef HTTP_AUTH_INFO (*GET_AUTH_INFO)(int);
typedef BOOL (*WRITE_RESPONSE)(int, const void*, int);
typedef void (*WAKEUP_CONTEXT)(int);
typedef void (*ACTIVATE_CONTEXT)(int);
typedef void (*SET_EP_INFO)(int, const char*, int);
typedef void* (*NDR_STACK_ALLOC)(int, size_t);
typedef BOOL (*NEW_ENVIRONMENT)(void);
typedef void (*FREE_ENVIRONMENT)(void);
typedef void (*LOG_INFO)(int, const char *, ...);

#define DECLARE_API(x) \
	x QUERY_SERVICE query_service; \
	x REGISTER_INTERFACE register_interface; \
	x TALK_REGISTRATION register_talk; \
	x GET_CONNECTION get_connection; \
	x GET_REQUEST get_request; \
	x GET_AUTH_INFO get_auth_info; \
	x WRITE_RESPONSE write_response; \
	x WAKEUP_CONTEXT wakeup_context; \
	x ACTIVATE_CONTEXT activate_context; \
	x LOG_INFO log_info; \
	x GET_ENVIRONMENT get_host_ID; \
	x GET_ENVIRONMENT get_default_domain; \
	x GET_ENVIRONMENT get_plugin_name; \
	x GET_ENVIRONMENT get_config_path; \
	x GET_ENVIRONMENT get_data_path, get_state_path; \
	x GET_INTEGER get_context_num; \
	x SET_INTEGER set_context; \
	x SET_EP_INFO set_ep_info; \
	x NDR_STACK_ALLOC ndr_stack_alloc; \
	x NEW_ENVIRONMENT rpc_new_environment; \
	x FREE_ENVIRONMENT rpc_free_environment;
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif
	
#define LINK_API(param) \
	query_service = (QUERY_SERVICE)param[0]; \
	register_interface = (REGISTER_INTERFACE)query_service("register_interface");\
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	get_connection = (GET_CONNECTION)query_service("get_connection"); \
	get_request = (GET_REQUEST)query_service("get_request"); \
	get_auth_info = (GET_AUTH_INFO)query_service("get_auth_info"); \
	write_response = (WRITE_RESPONSE)query_service("write_response"); \
	wakeup_context = (WAKEUP_CONTEXT)query_service("wakeup_context"); \
	activate_context = (ACTIVATE_CONTEXT)query_service("activate_context"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	get_default_domain = (GET_ENVIRONMENT)query_service("get_default_domain"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_state_path = (GET_ENVIRONMENT)query_service("get_state_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	set_context = (SET_INTEGER)query_service("set_context"); \
	set_ep_info = (SET_EP_INFO)query_service("set_ep_info"); \
	ndr_stack_alloc = (NDR_STACK_ALLOC)query_service("ndr_stack_alloc"); \
	rpc_new_environment = (NEW_ENVIRONMENT)query_service("rpc_new_environment"); \
	rpc_free_environment = (FREE_ENVIRONMENT)query_service("rpc_free_environment")

extern "C" { /* dlsym */
extern GX_EXPORT BOOL HPM_LibMain(int reason, void **ptrs);
}
