#ifndef _H_FLUSH_COMMON_
#define _H_FLUSH_COMMON_
#include <sys/time.h>
#include "common_types.h"
#include "mem_file.h"
#include "stream.h"

#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1
#define FLUSH_WHOLE_MAIL            0
#define FLUSH_PART_MAIL             1

#define FLUSH_NONE                  0
#define FLUSH_RESULT_OK             1
#define FLUSH_TEMP_FAIL             2
#define FLUSH_PERMANENT_FAIL        3

typedef struct _ENVELOP_INFO {
    char        parsed_domain[256];/* parsed domain according connection*/
    char        hello_domain[256]; /* domain name after helo */
    char        from[256];         /* envelop's from message */
    char        username[256];     /* user name for login */
    MEM_FILE    f_rcpt_to;         /* envelop's rcpt to message */
	BOOL        is_login;          /* user is logged in */
    BOOL        is_outbound;       /* in-bound or out-bound */
    BOOL        is_relay;          /* indicate whether this mail is relaying */
} ENVELOP_INFO;

typedef struct _CONNECTION {
    char           client_ip[16];      /* client ip address string */
    int            client_port;        /* value of client port */
    char           server_ip[16];      /* server ip address */
    int            server_port;        /* value of server port */
    int            sockd;              /* context's socket file description */
    struct timeval last_timestamp;     /* last time when system got data from */
} CONNECTION;


typedef struct _FLUSH_INFO{
    int           flush_action; /* indicate flushing whole or part of mail */
    int           flush_result;
    int           flush_ID;
    void          *flush_ptr;     /* extended data pointer */
} FLUSH_INFO;


typedef struct _FLUSH_ENTITY {
    STREAM           *pstream; 
    CONNECTION       *pconnection;
    FLUSH_INFO       *pflusher; /* the flusher for saving mail information */
    ENVELOP_INFO     *penvelop;
    BOOL             is_spam;   /* whether the mail is spam */
    int              context_ID;
} FLUSH_ENTITY;

typedef void (*CANCEL_FUNCTION)(FLUSH_ENTITY*);
typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef BOOL (*CANCEL_REGISTRATION)(CANCEL_FUNCTION);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef void* (*QUERY_SERVICE)(const char*);
typedef int (*QUERY_VERSION)(void);
typedef int (*GET_QUEUE_LENGTH)(void);
typedef BOOL (*FEEDBACK_ENTITY)(FLUSH_ENTITY*);
typedef FLUSH_ENTITY *(*QUEUE_OPERATION)(void);
typedef void (*LOG_INFO)(int, const char *, ...);
typedef const char* (*GET_EXTRA_TAGVAL)(int, int);
typedef int (*GET_EXTRA_NUM)(int);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef BOOL (*SET_FLUSH_ID)(int);
typedef int (*INC_FLUSH_ID)(void);
typedef BOOL (*CHECKING_FUNCTION)(char*);
/* is domain list valid, if TRUE, check_domain will functionate */
typedef BOOL (*IS_DOMAINLIST_VALID)(void);

extern QUERY_SERVICE query_service;
extern QUERY_VERSION query_version;
extern GET_QUEUE_LENGTH get_queue_length;
extern LOG_INFO log_info;
extern FEEDBACK_ENTITY feedback_entity;
extern CANCEL_REGISTRATION register_cancel;
extern CANCEL_REGISTRATION unregister_cancel;
extern TALK_REGISTRATION register_talk;
extern TALK_REGISTRATION unregister_talk;
extern QUEUE_OPERATION get_from_queue;
extern GET_ENVIRONMENT get_host_ID;
extern GET_ENVIRONMENT get_plugin_name;
extern GET_ENVIRONMENT get_config_path;
extern GET_ENVIRONMENT get_data_path;
extern GET_EXTRA_NUM get_extra_num;
extern GET_EXTRA_TAGVAL get_extra_tag;
extern GET_EXTRA_TAGVAL get_extra_value;
extern SET_FLUSH_ID set_flush_ID;
extern INC_FLUSH_ID inc_flush_ID;
extern CHECKING_FUNCTION check_domain;
extern IS_DOMAINLIST_VALID is_domainlist_valid;

#define DECLARE_API \
	QUERY_SERVICE query_service; \
	QUERY_VERSION query_version; \
	GET_QUEUE_LENGTH get_queue_length; \
	LOG_INFO log_info; \
	FEEDBACK_ENTITY feedback_entity; \
	CANCEL_REGISTRATION register_cancel; \
	CANCEL_REGISTRATION unregister_cancel; \
	TALK_REGISTRATION register_talk; \
	TALK_REGISTRATION unregister_talk; \
	QUEUE_OPERATION get_from_queue; \
	GET_ENVIRONMENT get_host_ID; \
	GET_ENVIRONMENT get_plugin_name; \
	GET_ENVIRONMENT get_config_path; \
	GET_ENVIRONMENT get_data_path; \
    GET_EXTRA_NUM get_extra_num; \
    GET_EXTRA_TAGVAL get_extra_tag; \
    GET_EXTRA_TAGVAL get_extra_value; \
	SET_FLUSH_ID set_flush_ID; \
	INC_FLUSH_ID inc_flush_ID; \
	CHECKING_FUNCTION check_domain; \
	IS_DOMAINLIST_VALID is_domainlist_valid

#define LINK_API(param) \
	query_version = (QUERY_VERSION)param[0]; \
	query_service = (QUERY_SERVICE)param[1]; \
	get_queue_length = (GET_QUEUE_LENGTH)query_service("get_queue_length"); \
	feedback_entity = (FEEDBACK_ENTITY)query_service("feedback_entity"); \
	register_cancel = (CANCEL_REGISTRATION)query_service("register_cancel"); \
	unregister_cancel = (CANCEL_REGISTRATION)query_service( \
							"unregister_cancel"); \
    register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	unregister_talk = (TALK_REGISTRATION)query_service("unregister_talk"); \
	get_from_queue = (QUEUE_OPERATION)query_service("get_from_queue"); \
	get_host_ID = (GET_ENVIRONMENT)query_service("get_host_ID"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	set_flush_ID = (SET_FLUSH_ID)query_service("set_flush_ID"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	inc_flush_ID = (INC_FLUSH_ID)query_service("inc_flush_ID"); \
    get_extra_num = (GET_EXTRA_NUM)query_service("get_extra_num"); \
    get_extra_tag = (GET_EXTRA_TAGVAL)query_service("get_extra_tag"); \
    get_extra_value = (GET_EXTRA_TAGVAL)query_service("get_extra_value"); \
	check_domain = (CHECKING_FUNCTION)query_service("check_domain"); \
	is_domainlist_valid=(IS_DOMAINLIST_VALID)query_service("is_domainlist_valid")
	
#endif /* _H_FLUSH_COMMON_ */

