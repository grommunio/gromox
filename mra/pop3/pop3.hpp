#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <gromox/authmgr.hpp>
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/midb_agent.hpp>
#include <gromox/stream.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#define MAX_LINE_LENGTH (64 * 1024)

/* enumeration for the return value of pop3_parser_dispatch_cmd */
enum {
	DISPATCH_CONTINUE,
	DISPATCH_SHOULD_CLOSE = 1U << 24,
	DISPATCH_DATA = 1U << 25,
	DISPATCH_LIST = 1U << 26,

	DISPATCH_VALMASK = 0x0000FFFFU,
	DISPATCH_ACTMASK = 0xFF000000U,
};

enum {
	POP3_RETRIEVE_TERM,
	POP3_RETRIEVE_OK,
	POP3_RETRIEVE_ERROR
};

class config_file;

struct pop3_context final : public schedule_context {
	pop3_context() = default;
	NOMOVE(pop3_context);

	GENERIC_CONNECTION connection;
	char read_buffer[1024]{};
	size_t read_offset{};
	char *write_buff = nullptr;
	std::string wrdat_content;
	size_t write_length = 0, write_offset = 0, wrdat_offset = 0;
	bool wrdat_active = false;
	BOOL data_stat = false, list_stat = false;
	int until_line = 0x7FFFFFFF, cur_line = -1;
	STREAM stream; /* stream accepted from pop3 client */
	int total_mail = 0;
	uint64_t total_size = 0;

	/*
	 * @list will hold indices/iterators/pointers to @array elements, so
	 * these elements must not change their memory location when @array is
	 * modified (specifically: only append). We also want O(1) random
	 * access in @array. Therefore, deque is used.
	 */
	std::vector<MSG_UNIT> msg_array; /* mailbox message list */
	std::vector<MSG_UNIT *> delmsg_list;
	BOOL is_login = false; /* if user is logged in */
	BOOL is_stls = false; /* if last command is STLS */
	int auth_times = 0;
	char username[UADDR_SIZE]{};
	char maildir[256]{};
};

using pophnd = int(std::vector<std::string> &&, pop3_context *);
extern pophnd cmdh_capa, cmdh_stls, cmdh_user, cmdh_pass, cmdh_stat, cmdh_uidl,
	cmdh_list, cmdh_retr, cmdh_rset, cmdh_noop, cmdh_dele, cmdh_top,
	cmdh_quit, cmdh_else;
extern void pop3_parser_init(int context_num, size_t retrieving_size, gromox::time_duration timeout, int max_auth_times, int block_auth_fail, bool support_tls, bool force_tls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int pop3_parser_run();
extern tproc_status pop3_parser_process(schedule_context *);
extern void pop3_parser_stop();
extern int pop3_parser_get_context_socket(const schedule_context *);
extern gromox::time_point pop3_parser_get_context_timestamp(const schedule_context *);
extern SCHEDULE_CONTEXT **pop3_parser_get_contexts_list();
extern int pop3_parser_threads_event_proc(int action);
extern int pop3_parser_retrieve(pop3_context *);
extern void pop3_parser_log_info(pop3_context *, int level, const char *format, ...);

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_pop3_code(unsigned int code_type, unsigned int n, size_t *len);

extern void xrpc_build_env();
extern void xrpc_free_env();

extern bool (*system_services_judge_ip)(const char *host, std::string &reason);
extern bool (*system_services_judge_user)(const char *);
extern void (*system_services_ban_user)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern void (*system_services_broadcast_event)(const char *);

extern uint16_t g_listener_ssl_port;
extern unsigned int g_popcmd_debug;
extern int g_max_auth_times, g_block_auth_fail;
extern bool g_support_tls, g_force_tls;
extern std::shared_ptr<config_file> g_config_file;
