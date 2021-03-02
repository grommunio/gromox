#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/stream.hpp>
#include <gromox/array.hpp>
#include <sys/time.h>
#include <openssl/ssl.h>

#define MAX_LINE_LENGTH    64*1024


/* enumeration of pop3_parser */
enum{
    MAX_AUTH_TIMES,
	BLOCK_AUTH_FAIL,
    POP3_SESSION_TIMEOUT,
	POP3_SUPPORT_STLS,
	POP3_FORCE_STLS
};

enum {
	POP3_RETRIEVE_TERM,
	POP3_RETRIEVE_OK,
	POP3_RETRIEVE_ERROR
};

struct CONNECTION {
	char client_ip[40]; /* client ip address string */
    int            client_port;        /* value of client port */
	char server_ip[40]; /* server ip address */
    int            server_port;        /* value of server port */
    int            sockd;              /* context's socket file description */
	SSL            *ssl;
    struct timeval last_timestamp;     /* last time when system got data from */
};

struct POP3_CONTEXT {
    SCHEDULE_CONTEXT sched_context;
    CONNECTION       connection;
	char             read_buffer[1024];
	size_t           read_offset;
	char             *write_buff;
	size_t           write_length;
	size_t           write_offset;
	BOOL             data_stat;
	BOOL             list_stat;
	int              until_line;
	int              cur_line;
	int              message_fd;
    STREAM           stream;         /* stream accepted from pop3 client */
	int              total_mail;
	uint64_t         total_size;
	ARRAY            array;          /* mailbox message list */
	SINGLE_LIST      list;           /* deleted message list */
    BOOL             is_login;       /* if user is logged in */
	BOOL             is_stls;        /* if last command is STLS */
	int              auth_times;
	char             username[256];
	char             maildir[256];
};

void pop3_parser_init(int context_num, size_t retrieving_size, int timeout,
	int max_auth_times, int block_auth_fail, BOOL support_stls, BOOL force_stls,
	const char *certificate_path, const char *cb_passwd, const char *key_path,
	const char *cdn_path);
extern int pop3_parser_run(void);
int pop3_parser_process(POP3_CONTEXT *pcontext);
extern int pop3_parser_stop(void);
extern void pop3_parser_free(void);
int pop3_parser_get_context_socket(POP3_CONTEXT *pcontext);

struct timeval pop3_parser_get_context_timestamp(POP3_CONTEXT *pcontext);

int pop3_parser_get_param(int param);

int pop3_parser_set_param(int param, int value);
extern POP3_CONTEXT *pop3_parser_get_contexts_list(void);
int pop3_parser_threads_event_proc(int action);

int pop3_parser_retrieve(POP3_CONTEXT *pcontext);
extern void pop3_parser_log_info(POP3_CONTEXT *pcontext, int level, const char *format, ...);
extern char *pop3_parser_cdn_path(void);
