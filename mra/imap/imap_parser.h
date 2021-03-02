#pragma once
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/xarray.hpp>
#include <gromox/stream.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/mime_pool.hpp>
#include <ctime>
#include <sys/time.h>
#include <openssl/ssl.h>

#define MAX_LINE_LENGTH			64*1024

#define FLAG_RECENT				0x1
#define FLAG_ANSWERED			0x2
#define FLAG_FLAGGED			0x4
#define FLAG_DELETED			0x8
#define FLAG_SEEN				0x10
#define FLAG_DRAFT				0x20

/* bits for controlling of f_digest, if not set, 
means mem_file is not initialized. */
#define FLAG_LOADED				0x80


#define MIDB_RDWR_ERROR          2

#define MIDB_NO_SERVER           1

#define MIDB_RESULT_OK           0

/* enumeration of imap_parser */
enum{
    MAX_AUTH_TIMES,
	BLOCK_AUTH_FAIL,
    IMAP_SESSION_TIMEOUT,
	IMAP_AUTOLOGOUT_TIME,
	IMAP_SUPPORT_STARTTLS,
	IMAP_FORCE_STARTTLS
};

enum {
	PROTO_STAT_NONE = 0,
	PROTO_STAT_NOAUTH,
	PROTO_STAT_USERNAME,
	PROTO_STAT_PASSWORD,
	PROTO_STAT_AUTH,
	PROTO_STAT_SELECT
};


enum {
	SCHED_STAT_NONE = 0,
	SCHED_STAT_RDCMD,
	SCHED_STAT_APPENDING,
	SCHED_STAT_APPENDED,
	SCHED_STAT_STLS,
	SCHED_STAT_WRLST,
	SCHED_STAT_WRDAT,
	SCHED_STAT_IDLING,
	SCHED_STAT_NOTIFYING,
	SCHED_STAT_AUTOLOGOUT,
	SCHED_STAT_DISCINNECTED
};

enum {
	IMAP_RETRIEVE_TERM,
	IMAP_RETRIEVE_OK,
	IMAP_RETRIEVE_ERROR
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

struct MITEM {
	SINGLE_LIST_NODE node;
	char mid[128];
	int id;
	int uid;
	char flag_bits;
	MEM_FILE f_digest;
};

struct IMAP_CONTEXT {
    SCHEDULE_CONTEXT sched_context;
    CONNECTION       connection;
	DOUBLE_LIST_NODE hash_node;
	DOUBLE_LIST_NODE sleeping_node;
	int              proto_stat;
	int              sched_stat;
	char             mid[128];
	char             file_path[256];
	int              message_fd;
	char             *write_buff;
	size_t           write_length;
	size_t           write_offset;
	time_t           selected_time;
	char             selected_folder[1024];
	BOOL b_readonly; /* is selected folder read only, this is for the examine command */
	BOOL             b_modify;
	MEM_FILE         f_flags;
	char             tag_string[32];
	int              command_len;
	char             command_buffer[64*1024];
	int              read_offset;
	char             read_buffer[64*1024];
	char             *literal_ptr;
	int              literal_len;
	int              current_len;
    STREAM           stream;                   /* stream for writing to imap client */
	int              auth_times;
	char             username[256];
	char             maildir[256];
	char             lang[32];
};

void imap_parser_init(int context_num, int average_num, size_t cache_size,
	unsigned int timeout, unsigned int autologout_time, int max_auth_times,
	int block_auth_fail, BOOL support_starttls, BOOL force_starttls,
	const char *certificate_path, const char *cb_passwd, const char *key_path);

extern int imap_parser_run(void);
int imap_parser_process(IMAP_CONTEXT *pcontext);
extern int imap_parser_stop(void);
extern void imap_parser_free(void);
int imap_parser_get_context_socket(IMAP_CONTEXT *pcontext);

struct timeval imap_parser_get_context_timestamp(IMAP_CONTEXT *pcontext);

int imap_parser_get_param(int param);

int imap_parser_set_param(int param, int value);
extern IMAP_CONTEXT *imap_parser_get_contexts_list(void);
int imap_parser_threads_event_proc(int action);

void imap_parser_touch_modify(IMAP_CONTEXT *pcontext, char *username, char *folder);

void imap_parser_echo_modify(IMAP_CONTEXT *pcontext, STREAM *pstream);

void imap_parser_modify_flags(IMAP_CONTEXT *pcontext, const char *mid_string);

void imap_parser_add_select(IMAP_CONTEXT *pcontext);

void imap_parser_remove_select(IMAP_CONTEXT *pcontext);

void imap_parser_safe_write(IMAP_CONTEXT *pcontext, const void *pbuff, size_t count);
extern LIB_BUFFER *imap_parser_get_allocator(void);
extern MIME_POOL *imap_parser_get_mpool(void);

/* get allocator for mjson mime */
extern LIB_BUFFER *imap_parser_get_jpool(void);
extern LIB_BUFFER *imap_parser_get_xpool(void);
extern LIB_BUFFER *imap_parser_get_dpool(void);
extern int imap_parser_get_sequence_ID(void);
extern void imap_parser_log_info(IMAP_CONTEXT *pcontext, int level, const char *format, ...);
