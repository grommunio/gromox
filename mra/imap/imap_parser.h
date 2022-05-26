#pragma once
#include <chrono>
#include <ctime>
#include <memory>
#include <string>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/stream.hpp>
#include <gromox/util.hpp>
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

struct DIR_NODE;
struct MJSON_MIME;

namespace gromox {
using time_duration = std::chrono::steady_clock::duration;
using time_point = std::chrono::time_point<std::chrono::system_clock>;
}

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
	SCHED_STAT_DISCONNECTED,
};

enum {
	IMAP_RETRIEVE_TERM,
	IMAP_RETRIEVE_OK,
	IMAP_RETRIEVE_ERROR
};

struct MITEM {
	SINGLE_LIST_NODE node;
	char mid[128];
	int id;
	int uid;
	char flag_bits;
	MEM_FILE f_digest;
};

struct IMAP_CONTEXT final : public SCHEDULE_CONTEXT {
	IMAP_CONTEXT();
	~IMAP_CONTEXT();
	NOMOVE(IMAP_CONTEXT);

	GENERIC_CONNECTION connection;
	std::string mid, file_path;
	DOUBLE_LIST_NODE hash_node{}, sleeping_node{};
	int proto_stat = 0, sched_stat = 0;
	int message_fd = -1;
	char *write_buff = nullptr;
	size_t write_length = 0, write_offset = 0;
	time_t selected_time = 0;
	char selected_folder[1024]{};
	BOOL b_readonly = false; /* is selected folder read only, this is for the examine command */
	BOOL b_modify = false;
	MEM_FILE f_flags{};
	char tag_string[32]{};
	int command_len = 0;
	char command_buffer[64*1024]{};
	int read_offset = 0;
	char read_buffer[64*1024]{};
	char *literal_ptr = nullptr;
	int literal_len = 0, current_len = 0;
	STREAM stream; /* stream for writing to imap client */
	int auth_times = 0;
	char username[UADDR_SIZE]{}, maildir[256]{}, lang[32]{};
};

extern void imap_parser_init(int context_num, int average_num, size_t cache_size, gromox::time_duration timeout, gromox::time_duration autologout_time, int max_auth_times, int block_auth_fail, BOOL support_starttls, BOOL force_starttls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int imap_parser_run();
int imap_parser_process(IMAP_CONTEXT *pcontext);
extern void imap_parser_stop();
extern int imap_parser_get_context_socket(SCHEDULE_CONTEXT *);
extern gromox::time_point imap_parser_get_context_timestamp(schedule_context *);
extern SCHEDULE_CONTEXT **imap_parser_get_contexts_list();
int imap_parser_threads_event_proc(int action);
void imap_parser_touch_modify(IMAP_CONTEXT *pcontext, char *username, char *folder);
void imap_parser_echo_modify(IMAP_CONTEXT *pcontext, STREAM *pstream);
void imap_parser_modify_flags(IMAP_CONTEXT *pcontext, const char *mid_string);
void imap_parser_add_select(IMAP_CONTEXT *pcontext);
void imap_parser_remove_select(IMAP_CONTEXT *pcontext);
void imap_parser_safe_write(IMAP_CONTEXT *pcontext, const void *pbuff, size_t count);
extern alloc_limiter<file_block> *imap_parser_get_allocator();
extern std::shared_ptr<MIME_POOL> imap_parser_get_mpool();
/* get allocator for mjson mime */
extern alloc_limiter<MJSON_MIME> *imap_parser_get_jpool();
extern LIB_BUFFER *imap_parser_get_xpool();
extern alloc_limiter<DIR_NODE> *imap_parser_get_dpool();
extern int imap_parser_get_sequence_ID();
extern void imap_parser_log_info(IMAP_CONTEXT *pcontext, int level, const char *format, ...);

extern unsigned int g_imapcmd_debug;
extern int g_max_auth_times, g_block_auth_fail;
extern bool g_support_starttls, g_force_starttls;
extern alloc_limiter<stream_block> g_blocks_allocator;
