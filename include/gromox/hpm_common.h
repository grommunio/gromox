#pragma once
#include <cstdint>
#include <typeinfo>
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
	x void *(*query_serviceF)(const char *, const std::type_info &); \
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
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(*(f)))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif
	
#define LINK_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service1(register_interface); \
	query_service1(register_talk); \
	query_service1(get_connection); \
	query_service1(get_request); \
	query_service1(get_auth_info); \
	query_service1(write_response); \
	query_service1(wakeup_context); \
	query_service1(activate_context); \
	query_service1(log_info); \
	query_service1(get_host_ID); \
	query_service1(get_default_domain); \
	query_service1(get_plugin_name); \
	query_service1(get_config_path); \
	query_service1(get_data_path); \
	query_service1(get_state_path); \
	query_service1(get_context_num); \
	query_service1(set_context); \
	query_service1(set_ep_info); \
	query_service1(ndr_stack_alloc); \
	query_service1(rpc_new_environment); \
	query_service1(rpc_free_environment);
#define HPM_ENTRY(s) BOOL HPM_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL HPM_LibMain(int reason, void **ptrs);
}
