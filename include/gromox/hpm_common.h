#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <typeinfo>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/generic_connection.hpp>
#include <gromox/http.hpp>
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

struct HPM_INTERFACE {
	BOOL (*preproc)(int);
	http_status (*proc)(int, const void*, uint64_t);
	int (*retr)(int);
	BOOL (*send)(int, const void*, int);
	int (*receive)(int, void*, int length);
	void (*term)(int);
};

enum class http_method {
	none, other, options, head, get, post, put, xdelete, patch, rpcin, rpcout
};

struct http_request {
	void clear() { *this = {}; }

	char method[14]{};
	enum http_method imethod = http_method::none;
	bool b_chunked = false, b_end = false;
	char version[8]{};
	uint64_t content_len = 0, chunk_offset = 0, chunk_size = 0, posted_size = 0;
	std::string f_request_uri, f_host, f_user_agent, f_accept;
	std::string f_accept_language, f_accept_encoding, f_content_type;
	std::string f_cookie;
	using other_map = std::unordered_map<std::string, std::string, gromox::icasehash, gromox::icasecmp>;
	other_map f_others;
	gromox::tmpfile body_fd;
	static constexpr size_t uri_limit = 8000; /* RFC 7230 */
};
using HTTP_REQUEST = http_request;

struct HTTP_AUTH_INFO {
	http_status auth_status;
	const char* username;
	const char* password;
	const char* maildir;
	const char* lang;
};

#define DECLARE_HPM_API(x) \
	x decltype(dlfuncs::symget) imp__symget; \
	x decltype(dlfuncs::hpm.reg_intf) register_interface; \
	x decltype(dlfuncs::hpm.get_conn) get_connection; \
	x decltype(dlfuncs::hpm.get_req) get_request; \
	x decltype(dlfuncs::hpm.get_auth_info) get_auth_info; \
	x decltype(dlfuncs::hpm.write_response) write_response; \
	x decltype(dlfuncs::hpm.wakeup_ctx) wakeup_context; \
	x decltype(dlfuncs::hpm.activate_ctx) activate_context; \
	x decltype(dlfuncs::get_host_ID) get_host_ID; \
	x decltype(dlfuncs::get_config_path) get_config_path; \
	x decltype(dlfuncs::get_data_path) get_data_path; \
	x decltype(dlfuncs::get_context_num) get_context_num; \
	x decltype(dlfuncs::hpm.set_ctx) set_context; \
	x decltype(dlfuncs::hpm.set_ep_info) set_ep_info; \
	x decltype(dlfuncs::ndr_stack_alloc) ndr_stack_alloc; \
	x decltype(dlfuncs::rpc_new_stack) rpc_new_stack; \
	x decltype(dlfuncs::rpc_free_stack) rpc_free_stack;
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(imp__symget((n), nullptr, typeid(decltype(*(f))))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_HPM_API_STATIC
DECLARE_HPM_API(static);
#else
DECLARE_HPM_API(extern);
#endif
	
#define LINK_HPM_API(param) \
	imp__symget = param.symget; \
	register_interface = param.hpm.reg_intf; \
	get_connection = param.hpm.get_conn; \
	get_request = param.hpm.get_req; \
	get_auth_info = param.hpm.get_auth_info; \
	write_response = param.hpm.write_response; \
	wakeup_context = param.hpm.wakeup_ctx; \
	activate_context = param.hpm.activate_ctx; \
	get_host_ID = param.get_host_ID; \
	get_config_path = param.get_config_path; \
	get_data_path = param.get_data_path; \
	get_context_num = param.get_context_num; \
	set_context = param.hpm.set_ctx; \
	set_ep_info = param.hpm.set_ep_info; \
	ndr_stack_alloc = param.ndr_stack_alloc; \
	rpc_new_stack = param.rpc_new_stack; \
	rpc_free_stack = param.rpc_free_stack;
