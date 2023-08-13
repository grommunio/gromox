#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/generic_connection.hpp>
#include <gromox/icase.hpp>
#include <gromox/plugin.hpp>
#include <gromox/util.hpp>
#define NDR_STACK_IN				0
#define NDR_STACK_OUT				1

#define HPM_RETRIEVE_ERROR			0
#define HPM_RETRIEVE_WRITE			1
#define HPM_RETRIEVE_NONE			2
#define HPM_RETRIEVE_WAIT			3
#define HPM_RETRIEVE_DONE			4

struct LIB_BUFFER;

struct HPM_INTERFACE {
	BOOL (*preproc)(int);
	BOOL (*proc)(int, const void*, uint64_t);
	int (*retr)(int);
	BOOL (*send)(int, const void*, int);
	int (*receive)(int, void*, int length);
	void (*term)(int);
};

struct http_request {
	void clear();

	char method[14]{};
	bool b_chunked = false, b_end = false;
	char version[8]{};
	uint64_t content_len = 0, chunk_offset = 0, chunk_size = 0, posted_size = 0;
	std::string f_request_uri, f_host, f_user_agent, f_accept;
	std::string f_accept_language, f_accept_encoding, f_content_type;
	std::string f_cookie;
	using other_map = std::unordered_map<std::string, std::string, gromox::icasehash, gromox::icasecmp>;
	other_map f_others;
	static constexpr size_t uri_limit = 8000; /* RFC 7230 */
};
using HTTP_REQUEST = http_request;

struct HTTP_AUTH_INFO {
	BOOL b_authed;
	const char* username;
	const char* password;
	const char* maildir;
	const char* lang;
};

#define DECLARE_HPM_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x BOOL (*register_interface)(HPM_INTERFACE *); \
	x GENERIC_CONNECTION *(*get_connection)(int); \
	x HTTP_REQUEST *(*get_request)(int); \
	x HTTP_AUTH_INFO (*get_auth_info)(int); \
	x BOOL (*write_response)(int, const void *, int); \
	x void (*wakeup_context)(int); \
	x void (*activate_context)(int); \
	x const char *(*get_host_ID)(); \
	x const char *(*get_config_path)(); \
	x const char *(*get_data_path)(); \
	x const char *(*get_state_path)(); \
	x unsigned int (*get_context_num)(); \
	x void (*set_context)(int); \
	x void (*set_ep_info)(int, const char *, int); \
	x void *(*ndr_stack_alloc)(int, size_t); \
	x BOOL (*rpc_new_stack)(); \
	x void (*rpc_free_stack)();
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_HPM_API_STATIC
DECLARE_HPM_API(static);
#else
DECLARE_HPM_API(extern);
#endif
	
#define LINK_HPM_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service1(register_interface); \
	query_service1(get_connection); \
	query_service1(get_request); \
	query_service1(get_auth_info); \
	query_service1(write_response); \
	query_service1(wakeup_context); \
	query_service1(activate_context); \
	query_service1(get_host_ID); \
	query_service1(get_config_path); \
	query_service1(get_data_path); \
	query_service1(get_state_path); \
	query_service1(get_context_num); \
	query_service1(set_context); \
	query_service1(set_ep_info); \
	query_service1(ndr_stack_alloc); \
	query_service1(rpc_new_stack); \
	query_service1(rpc_free_stack);
#define HPM_ENTRY(s) BOOL HPM_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL HPM_LibMain(int reason, void **ptrs);
}
