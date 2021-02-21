#pragma once
#include <typeinfo>
#include <sys/time.h>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/stream.hpp>
#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1
#define FLUSH_WHOLE_MAIL            0
#define FLUSH_PART_MAIL             1

#define FLUSH_NONE                  0
#define FLUSH_RESULT_OK             1
#define FLUSH_TEMP_FAIL             2
#define FLUSH_PERMANENT_FAIL        3

struct ENVELOP_INFO {
    char        parsed_domain[256];/* parsed domain according connection*/
    char        hello_domain[256]; /* domain name after helo */
    char        from[256];         /* envelop's from message */
    char        username[256];     /* user name for login */
    MEM_FILE    f_rcpt_to;         /* envelop's rcpt to message */
	BOOL        is_login;          /* user is logged in */
    BOOL        is_outbound;       /* in-bound or out-bound */
    BOOL        is_relay;          /* indicate whether this mail is relaying */
};

struct CONNECTION {
	char client_ip[32]; /* client ip address string */
    int            client_port;        /* value of client port */
	char server_ip[32]; /* server ip address */
    int            server_port;        /* value of server port */
    int            sockd;              /* context's socket file description */
    struct timeval last_timestamp;     /* last time when system got data from */
};

struct FLUSH_INFO {
    int           flush_action; /* indicate flushing whole or part of mail */
    int           flush_result;
    int           flush_ID;
    void          *flush_ptr;     /* extended data pointer */
};

struct FLUSH_ENTITY {
    STREAM           *pstream; 
    CONNECTION       *pconnection;
    FLUSH_INFO       *pflusher; /* the flusher for saving mail information */
    ENVELOP_INFO     *penvelop;
    BOOL             is_spam;   /* whether the mail is spam */
    int              context_ID;
};

typedef void (*CANCEL_FUNCTION)(FLUSH_ENTITY*);
typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef BOOL (*CANCEL_REGISTRATION)(CANCEL_FUNCTION);
typedef BOOL (*TALK_REGISTRATION)(TALK_MAIN);
typedef int (*GET_QUEUE_LENGTH)(void);
typedef BOOL (*FEEDBACK_ENTITY)(FLUSH_ENTITY*);
typedef FLUSH_ENTITY *(*QUEUE_OPERATION)(void);
typedef void (*LOG_INFO)(int, const char *, ...);
typedef const char* (*GET_EXTRA_TAGVAL)(int, int);
typedef int (*GET_EXTRA_NUM)(int);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef BOOL (*SET_FLUSH_ID)(int);
typedef int (*INC_FLUSH_ID)(void);
typedef BOOL (*CHECKING_FUNCTION)(const char *);
/* is domain list valid, if TRUE, check_domain will functionate */
typedef BOOL (*IS_DOMAINLIST_VALID)(void);

#define DECLARE_API(x) \
	x void *(*query_serviceF)(const char *, const std::type_info &); \
	x GET_QUEUE_LENGTH get_queue_length; \
	x LOG_INFO log_info; \
	x FEEDBACK_ENTITY feedback_entity; \
	x CANCEL_REGISTRATION register_cancel; \
	x QUEUE_OPERATION get_from_queue; \
	x GET_ENVIRONMENT get_host_ID; \
	x GET_ENVIRONMENT get_plugin_name; \
	x GET_ENVIRONMENT get_config_path; \
	x GET_ENVIRONMENT get_data_path, get_state_path; \
	x GET_EXTRA_NUM get_extra_num; \
	x GET_EXTRA_TAGVAL get_extra_tag; \
	x GET_EXTRA_TAGVAL get_extra_value; \
	x SET_FLUSH_ID set_flush_ID; \
	x INC_FLUSH_ID inc_flush_ID; \
	x CHECKING_FUNCTION check_domain; \
	x IS_DOMAINLIST_VALID is_domainlist_valid;
#define query_service2(n, f) ((f) = reinterpret_cast<decltype(f)>(query_serviceF((n), typeid(*(f)))))
#define query_service1(n) query_service2(#n, n)
#ifdef DECLARE_API_STATIC
DECLARE_API(static);
#else
DECLARE_API(extern);
#endif

#define LINK_API(param) \
	query_serviceF = reinterpret_cast<decltype(query_serviceF)>(param[0]); \
	query_service1(get_queue_length); \
	query_service1(feedback_entity); \
	query_service1(register_cancel); \
	query_service1(get_from_queue); \
	query_service1(get_host_ID); \
	query_service1(log_info); \
	query_service1(set_flush_ID); \
	query_service1(get_plugin_name); \
	query_service1(get_config_path); \
	query_service1(get_data_path); \
	query_service1(get_state_path); \
	query_service1(inc_flush_ID); \
	query_service1(get_extra_num); \
	query_service1(get_extra_tag); \
	query_service1(get_extra_value); \
	query_service2("domain_list_query", check_domain); \
	query_service1(is_domainlist_valid);
#define FLH_ENTRY(s) BOOL FLH_LibMain(int r, void **p) { return (s)((r), (p)); }

extern "C" { /* dlsym */
extern GX_EXPORT BOOL FLH_LibMain(int reason, void **ptrs);
}
