#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <vector>
#include <openssl/ssl.h>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/hpm_common.h>
#include <gromox/mapidefs.h>
#include <gromox/mem_file.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
#include "mod_fastcgi.h"
#include "pdu_processor.h"

namespace gromox {
using time_duration = std::chrono::steady_clock::duration;
using time_point = std::chrono::time_point<std::chrono::system_clock>;
}

/* enumeration of http_parser */
enum {
	MAX_AUTH_TIMES,
	BLOCK_AUTH_FAIL,
	HTTP_SESSION_TIMEOUT,
	HTTP_SUPPORT_TLS,
};

enum {
	SCHED_STAT_INITSSL = 0,
	SCHED_STAT_RDHEAD,
	SCHED_STAT_RDBODY,
	SCHED_STAT_WRREP,
	SCHED_STAT_WAIT,
	SCHED_STAT_SOCKET
};

enum {
	CHANNEL_STAT_OPENSTART = 0,
	CHANNEL_STAT_WAITINCHANNEL,
	CHANNEL_STAT_RECYCLING,
	CHANNEL_STAT_WAITRECYCLED,
	CHANNEL_STAT_OPENED,
	CHANNEL_STAT_RECYCLED
};

enum {
	CHANNEL_TYPE_NONE = 0,
	CHANNEL_TYPE_IN,
	CHANNEL_TYPE_OUT
};

struct HTTP_CONTEXT final : public SCHEDULE_CONTEXT {
	HTTP_CONTEXT();
	~HTTP_CONTEXT();
	NOMOVE(HTTP_CONTEXT);

	GENERIC_CONNECTION connection;
	http_request request;
	uint64_t total_length = 0, bytes_rw = 0;
	unsigned int sched_stat = 0;
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
	int channel_type = 0;
	void *pchannel = nullptr;
	FASTCGI_CONTEXT *pfast_context = nullptr;
};

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
	int channel_stat = 0;
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
	int channel_stat = 0;
};

extern void http_parser_init(size_t context_num, gromox::time_duration timeout, int max_auth_times, int block_auth_fail, bool support_tls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int http_parser_run();
int http_parser_process(HTTP_CONTEXT *pcontext);
extern void http_parser_stop();
extern int http_parser_get_context_socket(SCHEDULE_CONTEXT *);
void http_parser_set_context(int context_id);
extern gromox::time_point http_parser_get_context_timestamp(schedule_context *);
int http_parser_get_param(int param);
extern SCHEDULE_CONTEXT **http_parser_get_contexts_list();
int http_parser_threads_event_proc(int action);
extern bool http_parser_get_password(const char *username, char *password);
BOOL http_parser_try_create_vconnection(HTTP_CONTEXT *pcontext);
void http_parser_set_outchannel_flowcontrol(HTTP_CONTEXT *pcontext,
	uint32_t bytes_received, uint32_t available_window);
extern BOOL http_parser_recycle_inchannel(HTTP_CONTEXT *, const char *predecessor_cookie);
extern BOOL http_parser_recycle_outchannel(HTTP_CONTEXT *, const char *predecessor_cookie);
BOOL http_parser_activate_inrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie);
BOOL http_parser_activate_outrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie);
extern HTTP_CONTEXT *http_parser_get_context();
extern void http_parser_shutdown_async();
void http_parser_vconnection_async_reply(const char *host,
	int port, const char *connection_cookie, DCERPC_CALL *pcall);
extern void http_parser_set_keep_alive(HTTP_CONTEXT *pcontext, gromox::time_duration keepalive);
extern void http_parser_log_info(HTTP_CONTEXT *pcontext, int level, const char *format, ...) __attribute__((format(printf, 3, 4)));

extern alloc_limiter<stream_block> g_blocks_allocator;
extern unsigned int g_http_debug;
