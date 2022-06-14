#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <openssl/ssl.h>
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/msg_unit.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#include "../../exch/authmgr.hpp"
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

struct CONFIG_FILE;

struct POP3_CONTEXT final : public SCHEDULE_CONTEXT {
	POP3_CONTEXT();
	~POP3_CONTEXT();
	NOMOVE(POP3_CONTEXT);

	GENERIC_CONNECTION connection;
	char read_buffer[1024]{};
	size_t read_offset{};
	char *write_buff = nullptr;
	size_t write_length = 0, write_offset = 0;
	BOOL data_stat = false, list_stat = false;
	int until_line = 0x7FFFFFFF, cur_line = -1, message_fd = -1;
	STREAM stream; /* stream accepted from pop3 client */
	int total_mail = 0;
	uint64_t total_size = 0;

	/*
	 * @list will hold indices/iterators/pointers to @array elements, so
	 * these elements must not change their memory location when @array is
	 * modified (specifically: only append). We also want O(1) random
	 * access in @array. Therefore, deque is used.
	 */
	std::vector<gromox::MSG_UNIT> msg_array; /* mailbox message list */
	std::vector<gromox::MSG_UNIT *> delmsg_list;
	BOOL is_login = false; /* if user is logged in */
	BOOL is_stls = false; /* if last command is STLS */
	int auth_times = 0;
	char username[UADDR_SIZE]{};
	char maildir[256]{};
};

extern void listener_init(uint16_t port, uint16_t port_ssl);
extern int listener_run();
extern int listener_trigger_accept();
extern void listener_stop_accept();
extern void listener_stop();

extern int pop3_cmd_handler_capa(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_stls(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_user(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_pass(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_stat(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_uidl(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_list(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_retr(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_rset(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_noop(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_dele(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_top(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_quit(const char *cmd_line, int line_length, POP3_CONTEXT *);
extern int pop3_cmd_handler_else(const char *cmd_line, int line_length, POP3_CONTEXT *);

extern void pop3_parser_init(int context_num, size_t retrieving_size, gromox::time_duration timeout, int max_auth_times, int block_auth_fail, BOOL support_stls, BOOL force_stls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int pop3_parser_run();
extern int pop3_parser_process(POP3_CONTEXT *);
extern void pop3_parser_stop();
extern int pop3_parser_get_context_socket(SCHEDULE_CONTEXT *);
extern gromox::time_point pop3_parser_get_context_timestamp(schedule_context *);
extern SCHEDULE_CONTEXT **pop3_parser_get_contexts_list();
extern int pop3_parser_threads_event_proc(int action);
extern int pop3_parser_retrieve(POP3_CONTEXT *);
extern void pop3_parser_log_info(POP3_CONTEXT *, int level, const char *format, ...);

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_pop3_code(unsigned int code_type, unsigned int n, size_t *len);

extern int system_services_run();
extern void system_services_stop();

extern BOOL (*system_services_judge_ip)(const char *);
extern BOOL (*system_services_container_add_ip)(const char *);
extern BOOL (*system_services_container_remove_ip)(const char *);
extern BOOL (*system_services_judge_user)(const char *);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern int (*system_services_list_mail)(const char *, const char *, std::vector<gromox::MSG_UNIT> &, int *num, uint64_t *size);
extern int (*system_services_delete_mail)(const char *, const char *, const std::vector<gromox::MSG_UNIT *> &);
extern void (*system_services_broadcast_event)(const char *);
extern void (*system_services_log_info)(unsigned int, const char *, ...);

extern uint16_t g_listener_ssl_port;
extern unsigned int g_popcmd_debug;
extern int g_max_auth_times, g_block_auth_fail;
extern bool g_support_stls, g_force_stls;
extern alloc_limiter<stream_block> g_blocks_allocator;
extern std::shared_ptr<CONFIG_FILE> g_config_file;
