#pragma once
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/stream.hpp>
#include <gromox/mem_file.hpp>
#include <sys/time.h>
#include <openssl/ssl.h>

#define MAX_BLOCK_MIME_LEN                  4096
#define MAX_EXTRA_DATA_INDEX                8
#define MAX_EXTRA_DATA_TAGLEN               16
#define MAX_EXTRA_DATA_DATALEN              48

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

/* single part mail or multi-part mail */
enum{
    SINGLE_PART_MAIL,
    MULTI_PARTS_MAIL
};

/* stats of parsing the each part of multi-parts mail */
enum{
    PARSING_MAIL_HEAD = 0,
    PARSING_NEST_MIME,        /* system is now finding the begin of nested mime*/
    PARSING_BLOCK_HEAD,
    PARSING_BLOCK_CONTENT,
    PARSING_END
};

/* enumeration of smtp_parser */
enum{
    MAX_MAIL_LENGTH,
    SMTP_NEED_AUTH,
    BLOCK_TIME_EXCEED_AUTHS,
    BLOCK_TIME_EXCEED_SESSIONS,
    MAX_FLUSHING_SIZE,
    MAX_AUTH_TIMES,
    SMTP_MAX_MAILS,
    SMTP_SUPPORT_PIPELINE,
	SMTP_SUPPORT_STARTTLS,
	SMTP_FORCE_STARTTLS,
    SMTP_SESSION_TIMEOUT
};

//////////////////////////////////////////////////////////////////////////
enum {
    ENCODING_UNKNOWN    = 0,
    ENCODING_7BIT,
    ENCODING_8BIT,
    ENCODING_BASE64,
    ENCODING_QUOTED_PRINTABLE
};

//////////////////////////////////////////////////////////////////////////

struct ENVELOP_INFO {
    char        parsed_domain[256];/* parsed domain according connection*/
    char        hello_domain[256]; /* domain name after helo */
    char        from[256];         /* envelop's from message */
    char        username[256];     /* user name for login */
    MEM_FILE    f_rcpt_to;         /* envelop's rcpt to message */
    BOOL        is_login;          /* user is logged in */
    BOOL        is_outbound;       /* in-bound or out-bound */
    BOOL        is_relay;           /* indicate whether this mail is relaying */
    int         auth_times;        /* recording the times of auth */
};

struct MAIL_HEAD {
    MEM_FILE    f_mime_from;      /* from message in mime including nick name */
    MEM_FILE    f_mime_to;        /* to message in mime */
    MEM_FILE    f_mime_cc;        /* cc message in mime */
    MEM_FILE    f_mime_delivered_to;    /* deliver to  message in mime */
    MEM_FILE    f_xmailer;        /* x mailer information in mime */
    MEM_FILE    f_subject;        /* subject information in mime */
    MEM_FILE    f_content_type;   /* content type in mime */
    MEM_FILE    f_others;          /* other mail header field */
    char        x_priority;       /* x priority */
	char x_original_ip[40]; /* oringinal ip information in mime */
    char        compose_time[64];    /* compose time in mime */
    int         mail_part;             /* single part mail or multi-parts */
};

struct MAIL_BODY {
    size_t          mail_length;
    int             parts_num;
    MEM_FILE        f_mail_parts;
};

struct MAIL_INFO {
    ENVELOP_INFO    envelop;
    MAIL_HEAD       head;
    MAIL_BODY       body;
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

struct FLUSH_INFO {
    int           flush_action; /* indicate flushing whole or part of mail */
    int           flush_result;
    int           flush_ID;
    void          *flush_ptr;    /* extended data pointer */
};

struct PARSING_BLOCK {
    int             state;
    char            block_mime[MAX_BLOCK_MIME_LEN];
    size_t          block_mime_len;
    int             last_block_ID;    /* last block ID for as filter */
    size_t          block_body_len;
    int             encode_type;
    char            block_type[256];
    MEM_FILE        f_last_blkmime;
    char            remains_encode[4];
    int             remains_len;
};

struct EXT_DATA {
    char             ext_data[MAX_EXTRA_DATA_INDEX][MAX_EXTRA_DATA_DATALEN];
    char             ext_tag[MAX_EXTRA_DATA_INDEX][MAX_EXTRA_DATA_TAGLEN];
    int              cur_pos;
};

struct SMTP_CONTEXT {
    SCHEDULE_CONTEXT sched_context;
    CONNECTION       connection;
    STREAM           stream;       /* stream accepted from smtp client */
    BOOL             is_splitted;  /* whether stream_second has data in */
    STREAM           stream_second;/* stream for recording splitted data */
    int              last_cmd;     /* indicate SMTP state of the connection */
    MAIL_INFO        mail;         /* for recording the mail information */
    FLUSH_INFO       flusher;      /* the flusher for saving mail information */
    BOOL             is_spam;      /* whether the mail is spam */
    int              session_num;  /* session number of the context */
    size_t           total_length; /* mail total length */
    char             last_bytes[4];/* last bytes for part mail */
    PARSING_BLOCK    block_info;   /* parsing block information */
    int              pre_rstlen;   /* previous bytes rested by last flushing */
    EXT_DATA         ext_data;
};

extern void smtp_parser_init(int context_num, int threads_num,
	BOOL dm_valid, BOOL need_auth, size_t max_mail_length,
	size_t max_mail_sessions, size_t blktime_sessions, size_t flushing_size,
	size_t timeout,  size_t auth_times, size_t blktime_auths,
	BOOL support_pipeline, BOOL support_starttls, BOOL force_starttls,
	const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int smtp_parser_run();
int smtp_parser_process(SMTP_CONTEXT *pcontext);
extern int smtp_parser_stop();
extern void smtp_parser_free();
long smtp_parser_get_param(int param);

int smtp_parser_set_param(int param, long value);

int smtp_parser_get_context_socket(SMTP_CONTEXT *pcontext);

struct timeval smtp_parser_get_context_timestamp(SMTP_CONTEXT *pcontext);

BOOL smtp_parser_validate_domainlist(BOOL b_valid);
extern BOOL smtp_parser_domainlist_valid();
int smtp_parser_get_extra_num(SMTP_CONTEXT *pcontext);

const char* smtp_parser_get_extra_tag(SMTP_CONTEXT *pcontext, int pos);

const char* smtp_parser_get_extra_value(SMTP_CONTEXT *pcontext, int pos);
extern SMTP_CONTEXT *smtp_parser_get_contexts_list();
int smtp_parser_threads_event_proc(int action);

void smtp_parser_reset_context_envelop(SMTP_CONTEXT *pcontext);
extern void smtp_parser_log_info(SMTP_CONTEXT *pcontext, int level, const char *format, ...);
