#pragma once
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <openssl/ssl.h>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/flusher_common.h>
#include <gromox/mem_file.hpp>
#include <gromox/stream.hpp>
#define MAX_BLOCK_MIME_LEN                  4096
#define MAX_EXTRA_DATA_INDEX                8
#define MAX_EXTRA_DATA_TAGLEN               16
#define MAX_EXTRA_DATA_DATALEN              48

namespace gromox {
using time_point = std::chrono::time_point<std::chrono::system_clock>;
}

/* enum for state of context */
enum{
    STEP_BEGIN = 0,
    CONTEXT_ACHIEVED,   /* context is completely read and no need to schedule*/
    CONTEXT_FLUSHED,    /*
                         context is written to hard disk, need to informate
                         client OK
                         */
};

/* enumeration of last_cmd in smtp context */
enum{
    T_UNKNOWN_CMD    = -1,
    T_NONE_CMD,
    T_HELO_CMD,    
    T_EHLO_CMD,
	T_STARTTLS_CMD,
    T_LOGGED_CMD,    
    T_MAIL_CMD,
    T_RCPT_CMD,
    T_QUIT_CMD,
    T_RSET_CMD,
    T_HELP_CMD,
    T_VRFY_CMD,
    T_ETRN_CMD,
    T_DATA_CMD,
    T_END_MAIL,    
    TYPE_NUM
};

enum {
    ENCODING_UNKNOWN    = 0,
    ENCODING_7BIT,
    ENCODING_8BIT,
    ENCODING_BASE64,
    ENCODING_QUOTED_PRINTABLE
};

struct EXT_DATA {
    char             ext_data[MAX_EXTRA_DATA_INDEX][MAX_EXTRA_DATA_DATALEN];
    char             ext_tag[MAX_EXTRA_DATA_INDEX][MAX_EXTRA_DATA_TAGLEN];
    int              cur_pos;
};

struct SMTP_CONTEXT final : public SCHEDULE_CONTEXT {
	SMTP_CONTEXT();
	NOMOVE(SMTP_CONTEXT);

	GENERIC_CONNECTION connection;
	STREAM stream; /* stream accepted from smtp client */
	std::optional<STREAM> stream_second; /* stream for recording splitted data */
	unsigned int command_protocol = 0;
	int last_cmd = 0; /* indicate SMTP state of the connection */
	envelope_info menv; /* for recording the mail information */
	FLUSH_INFO flusher{}; /* the flusher for saving mail information */
	BOOL is_spam = false; /* whether the mail is spam */
	unsigned int session_num = 0; /* session number of the context */
	size_t total_length = 0; /* mail total length */
	char last_bytes[4]{}; /* last bytes for part mail */
	int pre_rstlen{}; /* previous bytes rested by last flushing */
	EXT_DATA ext_data{};
};

struct smtp_param {
	unsigned int context_num = 0;
	BOOL need_auth = false, support_pipeline = TRUE;
	BOOL support_starttls = false, force_starttls = false;
	size_t max_mail_length = 64ULL * 1024 * 1024;
	int max_mail_sessions = 0; /* max num of mails in any one session */
	size_t flushing_size = 0;
	gromox::time_duration timeout{std::chrono::seconds{0x7fffffff}};
	int auth_times = 0, blktime_auths = 60, blktime_sessions = 60;
	unsigned int cmd_prot = HT_LMTP | HT_SMTP;
	std::string cert_path, cert_passwd, key_path;
};

extern void smtp_parser_init(const smtp_param &);
extern int smtp_parser_run();
int smtp_parser_process(SMTP_CONTEXT *pcontext);
extern void smtp_parser_stop();
extern int smtp_parser_get_context_socket(SCHEDULE_CONTEXT *);
extern gromox::time_point smtp_parser_get_context_timestamp(schedule_context *);
int smtp_parser_get_extra_num(SMTP_CONTEXT *pcontext);
const char* smtp_parser_get_extra_tag(SMTP_CONTEXT *pcontext, int pos);
const char* smtp_parser_get_extra_value(SMTP_CONTEXT *pcontext, int pos);
extern SCHEDULE_CONTEXT **smtp_parser_get_contexts_list();
int smtp_parser_threads_event_proc(int action);
extern void smtp_parser_log_info(SMTP_CONTEXT *pcontext, int level, const char *format, ...);

extern LIB_BUFFER g_blocks_allocator;
extern alloc_limiter<file_block> g_files_allocator;
extern smtp_param g_param;
