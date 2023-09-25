#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <vector>
#include <openssl/ssl.h>
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/hpm_common.h>
#include <gromox/mapidefs.h>
#include <gromox/stream.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include "pdu_processor.h"

/* enumeration of http_parser */
enum {
	MAX_AUTH_TIMES,
	BLOCK_AUTH_FAIL,
	HTTP_SESSION_TIMEOUT,
	HTTP_SUPPORT_TLS,
};

enum class hsched_stat {
	initssl = 0, rdhead, rdbody, wrrep, wait,
};

enum class hchannel_stat {
	openstart = 0, waitinchannel, recycling, waitrecycled, opened, recycled,
};

enum class hchannel_type {
	none = 0, in, out,
};

struct fastcgi_context;

struct http_context final : public schedule_context {
	http_context();
	~http_context();
	NOMOVE(http_context);
	BOOL try_create_vconnection();
	void set_outchannel_flowcontrol(uint32_t bytes_received, uint32_t available_window);
	BOOL recycle_inchannel(const char *predecessor_cookie);
	BOOL recycle_outchannel(const char *predecessor_cookie);
	BOOL activate_inrecycling(const char *successor_cookie);
	BOOL activate_outrecycling(const char *successor_cookie);
	void log(int level, const char *format, ...) const __attribute__((format(printf, 3, 4)));
	void set_keep_alive(gromox::time_duration keepalive);

	GENERIC_CONNECTION connection;
	http_request request;
	uint64_t total_length = 0, bytes_rw = 0;
	hsched_stat sched_stat = hsched_stat::initssl;
	STREAM stream_in, stream_out;
	void *write_buff = nullptr;
	int write_offset = 0, write_length = 0;
	BOOL b_close = TRUE; /* Connection MIME Header for indicating closing */
	BOOL b_authed = false;
	int auth_times = 0;
	char username[UADDR_SIZE]{}, password[128]{}, maildir[256]{}, lang[32]{};
	DOUBLE_LIST_NODE node{};
	char host[UDOM_SIZE]{};
	uint16_t port = 0;
	hchannel_type channel_type = hchannel_type::none;
	void *pchannel = nullptr;
};
using HTTP_CONTEXT = http_context;

struct RPC_IN_CHANNEL {
	RPC_IN_CHANNEL();
	~RPC_IN_CHANNEL();
	NOMOVE(RPC_IN_CHANNEL);

	uint16_t frag_length = 0; /* indicating incoming PDU length */
	char channel_cookie[GUIDSTR_SIZE]{}, connection_cookie[GUIDSTR_SIZE]{};
	gromox::time_duration client_keepalive{};
	uint32_t life_time = 0, available_window = 0;
	uint32_t bytes_received = 0;
	char assoc_group_id[64]{};
	DOUBLE_LIST pdu_list{};
	hchannel_stat channel_stat = hchannel_stat::openstart;
};

struct RPC_OUT_CHANNEL {
	RPC_OUT_CHANNEL();
	~RPC_OUT_CHANNEL();
	NOMOVE(RPC_OUT_CHANNEL);

	uint16_t frag_length = 0;
	char channel_cookie[64]{}, connection_cookie[64]{};
	BOOL b_obsolete = false; /* out channel is obsolete, wait for new out channel */
	gromox::time_duration client_keepalive{}; /* get from in channel */
	std::atomic<uint32_t> available_window{0};
	uint32_t window_size = 0;
	uint32_t bytes_sent = 0; /* length of sent data including RPC and RTS PDU, chunk data */
	DCERPC_CALL *pcall = nullptr; /* first output pcall of PDU by out channel itself */
	DOUBLE_LIST pdu_list{};
	hchannel_stat channel_stat = hchannel_stat::openstart;
};

extern void http_parser_init(size_t context_num, gromox::time_duration timeout, int max_auth_times, int block_auth_fail, bool support_tls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int http_parser_run();
extern tproc_status http_parser_process(schedule_context *);
extern void http_parser_stop();
extern int http_parser_get_context_socket(const schedule_context *);
void http_parser_set_context(int context_id);
extern gromox::time_point http_parser_get_context_timestamp(const schedule_context *);
int http_parser_get_param(int param);
extern SCHEDULE_CONTEXT **http_parser_get_contexts_list();
int http_parser_threads_event_proc(int action);
extern bool http_parser_get_password(const char *username, char *password);
extern HTTP_CONTEXT *http_parser_get_context();
extern void http_parser_shutdown_async();
void http_parser_vconnection_async_reply(const char *host,
	int port, const char *connection_cookie, DCERPC_CALL *pcall);
extern void http_report();

extern alloc_limiter<stream_block> g_blocks_allocator;
extern unsigned int g_http_debug, g_msrpc_debug;
extern uint64_t g_rqbody_flush_size, g_rqbody_max_size;
extern bool g_http_php;
