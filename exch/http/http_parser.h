#pragma once
#include <atomic>
#include <vector>
#include "mod_fastcgi.h"
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include "pdu_processor.h"
#include <gromox/stream.hpp>
#include <gromox/mem_file.hpp>
#include <ctime>
#include <sys/time.h>
#include <openssl/ssl.h>
#define OUT_CHANNEL_MAX_WAIT						10

/* enumeration of http_parser */
enum {
	MAX_AUTH_TIMES,
	BLOCK_AUTH_FAIL,
	HTTP_SESSION_TIMEOUT,
	HTTP_SUPPORT_SSL
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

struct CONNECTION {
	char client_ip[40]; /* client ip address string */
	int				client_port;        /* value of client port */
	char server_ip[40]; /* server ip address */
	int				server_port;        /* value of server port */
	int				sockd;              /* context's socket file description */
	SSL				*ssl;
	struct timeval last_timestamp;     /* last time when system got data from */
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

enum {
	CHANNEL_TYPE_NONE = 0,
	CHANNEL_TYPE_IN,
	CHANNEL_TYPE_OUT
};

struct HTTP_CONTEXT final : public SCHEDULE_CONTEXT {
	HTTP_CONTEXT();
	~HTTP_CONTEXT();

	CONNECTION connection{};
	HTTP_REQUEST request{};
	uint64_t total_length = 0, bytes_rw = 0;
	unsigned int sched_stat = 0;
	STREAM stream_in{}, stream_out{};
	void *write_buff = nullptr;
	int write_offset = 0, write_length = 0;
	BOOL b_close = TRUE; /* Connection MIME Header for indicating closing */
	BOOL b_authed = false;
	int auth_times = 0;
	char username[UADDR_SIZE]{}, password[128]{}, maildir[256]{}, lang[32]{};
	DOUBLE_LIST_NODE node{};
	char host[256]{};
	int port = 0, channel_type = 0;
	void *pchannel = nullptr;
	FASTCGI_CONTEXT *pfast_context = nullptr;
};

struct RPC_IN_CHANNEL {
	uint16_t			frag_length;			/* indicating in coming PDU length */
	char				channel_cookie[64];
	char				connection_cookie[64];
	uint32_t			life_time;
	uint32_t			client_keepalive;
	uint32_t			available_window;
	uint32_t			bytes_received;
	char				assoc_group_id[64];
	DOUBLE_LIST			pdu_list;
	int					channel_stat;
};

struct RPC_OUT_CHANNEL {
	uint16_t			frag_length;
	char				channel_cookie[64];
	char				connection_cookie[64];
	BOOL				b_obsolete;			/* out channel is obsolte, wait for new out channel */
	uint32_t			client_keepalive;	/* get from in channel */
	std::atomic<uint32_t> available_window;
	uint32_t			window_size;
	uint32_t			bytes_sent;	/* length of sent data including RPC and RTS PDU, chunk data */
	DCERPC_CALL			*pcall;		/* first output pcall of PDU by out channel itself */
	DOUBLE_LIST			pdu_list;
	int					channel_stat;
};

extern void http_parser_init(size_t context_num, unsigned int timeout, int max_auth_times, int block_auth_fail, BOOL support_ssl, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int http_parser_run();
int http_parser_process(HTTP_CONTEXT *pcontext);
extern int http_parser_stop();
extern int http_parser_get_context_socket(SCHEDULE_CONTEXT *);
void http_parser_set_context(int context_id);
extern struct timeval http_parser_get_context_timestamp(SCHEDULE_CONTEXT *);
int http_parser_get_param(int param);
int http_parser_set_param(int param, int value);
extern SCHEDULE_CONTEXT **http_parser_get_contexts_list();
int http_parser_threads_event_proc(int action);
extern bool http_parser_get_password(const char *username, char *password);
BOOL http_parser_try_create_vconnection(HTTP_CONTEXT *pcontext);
void http_parser_set_outchannel_flowcontrol(HTTP_CONTEXT *pcontext,
	uint32_t bytes_received, uint32_t available_window);
BOOL http_parser_recycle_inchannel(
	HTTP_CONTEXT *pcontext, char *predecessor_cookie);
BOOL http_parser_recycle_outchannel(
	HTTP_CONTEXT *pcontext, char *predecessor_cookie);
BOOL http_parser_activate_inrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie);
BOOL http_parser_activate_outrecycling(
	HTTP_CONTEXT *pcontext, const char *successor_cookie);
extern HTTP_CONTEXT *http_parser_get_context();
extern void http_parser_shutdown_async();
void http_parser_vconnection_async_reply(const char *host,
	int port, const char *connection_cookie, DCERPC_CALL *pcall);
void http_parser_set_keep_alive(HTTP_CONTEXT *pcontext, uint32_t keepalive);
extern void http_parser_log_info(HTTP_CONTEXT *pcontext, int level, const char *format, ...) __attribute__((format(printf, 3, 4)));
