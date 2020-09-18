#pragma once
#include <gromox/defs.h>
#include "common_types.h"
#include "mem_file.h"

#define PLUGIN_INIT                 0
#define PLUGIN_FREE                 1
#define SYS_THREAD_CREATE           2
#define SYS_THREAD_DESTROY          3

#define ACTION_BLOCK_NEW            0
#define ACTION_BLOCK_PROCESSING     1
#define ACTION_BLOCK_FREE           2

#define MESSAGE_ACCEPT              0
#define MESSAGE_REJECT              1
#define MESSAGE_RETRYING            2

/* single part mail or multi-part mail */
#define SINGLE_PART_MAIL            0
#define MULTI_PARTS_MAIL            1



typedef struct _ENVELOP_INFO{
	char		parsed_domain[256];/* parsed domain according connection*/
	char		hello_domain[256]; /* domain name after helo */
	char		from[256];         /* envelop's from message */
	char		username[256];     /* user name for login */
	MEM_FILE	f_rcpt_to;         /* envelop's rcpt to message */
	BOOL		is_login;          /* user is logged in */
	BOOL		is_outbound;       /* in-bound or out-bound */
	BOOL		is_relay;          /* indicate whether this mail is relaying */
} ENVELOP_INFO;

typedef struct _MAIL_HEAD{
	MEM_FILE	f_mime_from;      /* from message in mime including nick name */
	MEM_FILE	f_mime_to;        /* to message in mime */
	MEM_FILE	f_mime_cc;        /* cc message in mime */
	MEM_FILE	f_mime_delivered_to;    /* deliver to  message in mime */
	MEM_FILE	f_xmailer;        /* x mailer information in mime */
	MEM_FILE	f_subject;        /* subject information in mime */
	MEM_FILE	f_content_type;   /* content type in mime */
	MEM_FILE	f_others;         /* other mail header field */ 
	char		x_priority;       /* x priority */
	char		x_original_ip[16];   /* oringinal ip information in mime */
	char		compose_time[64];    /* compose time in mime */
	int			mail_part;           /* single part mail or multi-parts */
} MAIL_HEAD;

typedef struct _MAIL_BODY{
	 size_t		mail_length;
	 int		parts_num;
	 MEM_FILE	f_mail_parts;
} MAIL_BODY;

typedef struct _MAIL_ENTITY{
	ENVELOP_INFO	*penvelop;
	MAIL_HEAD		*phead;
} MAIL_ENTITY;

typedef struct _MAIL_WHOLE{
	ENVELOP_INFO	*penvelop;
	MAIL_HEAD 		*phead;
	MAIL_BODY		*pbody;
} MAIL_WHOLE;

typedef struct _CONNECTION{
	char		client_ip[16];      /* client ip address string */
	int			client_port;        /* value of client port */
	char		server_ip[16];      /* server ip address */
	int			server_port;        /* value of server port */
	int			sockd;              /* context's socket file description */
	void		*ssl;
} CONNECTION;

typedef struct _MAIL_BLOCK{
	int          block_ID;
	MEM_FILE     *fp_mime_info;
	BOOL         is_parsed;
	const char   *original_buff;
	const size_t original_length;
	char         *parsed_buff;
	size_t       parsed_length;
} MAIL_BLOCK;

typedef int (*JUDGE_FUNCTION)(int, ENVELOP_INFO*, CONNECTION*, char*, int);
typedef int (*AUDITOR_FUNCTION)(int, MAIL_ENTITY*, CONNECTION*, char*, int);
typedef int (*FILTER_FUNCTION)(int, int, MAIL_BLOCK*, char*, int);
typedef int (*STATISTIC_FUNCTION)(int, MAIL_WHOLE*, CONNECTION*, char*, int);
typedef void (*TALK_MAIN)(int, char**, char*, int);
typedef void *(*QUERY_SERVICE)(const char *);
typedef const char *(*GET_ENVIRONMENT)(void);
typedef int (*GET_INTEGER)(void);
/* represent function type of register_judge and unregister_judge */
typedef BOOL(*JUDGE_REGISTRATION)(JUDGE_FUNCTION);
/* represent function type of register_auditor and unregister_auditor */
typedef BOOL(*AUDITOR_REGISTRATION)(AUDITOR_FUNCTION);
/* represent function type of register_filter and  unregister_filter */
typedef BOOL (*FILTER_REGISTRATION)(const char *, FILTER_FUNCTION);
/* represent function type of register_statistic and unregister_statistic */
typedef BOOL(*STATISTIC_REGISTRATION)(STATISTIC_FUNCTION);
/* represent function type of register_talk and unregister_talk */
typedef BOOL(*TALK_REGISTRATION)(TALK_MAIN);
/* represent function type of log_info */
typedef void (*LOG_INFO)(int, const char *, ...);
/* temporary black list */
typedef BOOL (*TMP_BLACKLIST)(char*, long);
/* set the extra data used by other plugins */
typedef BOOL (*SET_EXTRA_VALUE)(int, char*, char*);
/* mark context as spam */
typedef void (*MARK_CONTEXT_SPAM)(int);
/* get the information of MAIL_ENTITY of a context */
typedef MAIL_ENTITY (*GET_MAIL_ENTITY)(int);
/* get connection of a context */
typedef CONNECTION* (*GET_CONNECTION)(int);
/* does system force user to authentificate before send mail data */
typedef BOOL (*IS_NEED_AUTH)(void);
/* check_domain, check_relay */
typedef BOOL (*CHECKING_FUNCTION)(char*);
/* is domain list valid, if TRUE, check_domain will functionate */
typedef BOOL (*IS_DOMAINLIST_VALID)(void);

#ifdef __cplusplus
extern "C" {
#endif

extern QUERY_SERVICE query_service;
extern JUDGE_REGISTRATION register_judge, unregister_judge;
extern AUDITOR_REGISTRATION register_auditor, unregister_auditor;
extern FILTER_REGISTRATION register_filter, unregister_filter;
extern STATISTIC_REGISTRATION register_statistic, unregister_statistic;
extern TALK_REGISTRATION register_talk, unregister_talk;
extern SET_EXTRA_VALUE set_extra_value;
extern MARK_CONTEXT_SPAM mark_context_spam;
extern GET_MAIL_ENTITY get_mail_entity;
extern GET_CONNECTION get_connection;
extern LOG_INFO log_info;
extern TMP_BLACKLIST user_filter_add;
extern TMP_BLACKLIST ip_filter_add;
extern IS_NEED_AUTH  is_need_auth;
extern IS_DOMAINLIST_VALID is_domainlist_valid;
extern GET_ENVIRONMENT get_default_domain;
extern GET_ENVIRONMENT get_plugin_name;
extern GET_ENVIRONMENT get_config_path;
extern GET_ENVIRONMENT get_data_path;
extern GET_INTEGER get_context_num;
extern CHECKING_FUNCTION check_domain;
extern CHECKING_FUNCTION check_relay;
	
#define DECLARE_API \
	QUERY_SERVICE query_service; \
	JUDGE_REGISTRATION register_judge, unregister_judge; \
	AUDITOR_REGISTRATION register_auditor, unregister_auditor; \
	FILTER_REGISTRATION register_filter, unregister_filter; \
	STATISTIC_REGISTRATION register_statistic, unregister_statistic; \
	TALK_REGISTRATION register_talk, unregister_talk; \
	SET_EXTRA_VALUE set_extra_value; \
	MARK_CONTEXT_SPAM mark_context_spam; \
	GET_MAIL_ENTITY get_mail_entity; \
	GET_CONNECTION get_connection; \
	LOG_INFO log_info; \
	TMP_BLACKLIST user_filter_add; \
	TMP_BLACKLIST ip_filter_add; \
	IS_NEED_AUTH  is_need_auth; \
	IS_DOMAINLIST_VALID is_domainlist_valid;\
	GET_ENVIRONMENT get_default_domain; \
	GET_ENVIRONMENT get_plugin_name; \
	GET_ENVIRONMENT get_config_path; \
	GET_ENVIRONMENT get_data_path; \
	GET_INTEGER get_context_num; \
	CHECKING_FUNCTION check_domain; \
	CHECKING_FUNCTION check_relay

#define LINK_API(param) \
	query_service = (QUERY_SERVICE)param[0]; \
	register_judge = (JUDGE_REGISTRATION)query_service("register_judge"); \
	unregister_judge = (JUDGE_REGISTRATION)query_service("unregister_judge"); \
	register_auditor = (AUDITOR_REGISTRATION)query_service("register_auditor");\
	unregister_auditor = (AUDITOR_REGISTRATION)query_service( \
							"unregister_auditor"); \
	register_filter	= (FILTER_REGISTRATION)query_service("register_filter"); \
	unregister_filter = (FILTER_REGISTRATION)query_service( \
							"unregister_filter"); \
	register_statistic = (STATISTIC_REGISTRATION)query_service( \
			                "register_statistic"); \
	unregister_statistic = (STATISTIC_REGISTRATION)query_service( \
			                "unregister_statistic"); \
	register_talk = (TALK_REGISTRATION)query_service("register_talk"); \
	unregister_talk = (TALK_REGISTRATION)query_service("unregister_talk"); \
	set_extra_value = (SET_EXTRA_VALUE)query_service("set_extra_value"); \
	mark_context_spam = (MARK_CONTEXT_SPAM)query_service("mark_context_spam"); \
	get_mail_entity = (GET_MAIL_ENTITY)query_service("get_mail_entity"); \
	get_connection = (GET_CONNECTION)query_service("get_connection"); \
	log_info = (LOG_INFO)query_service("log_info"); \
	ip_filter_add = (TMP_BLACKLIST)query_service("ip_filter_add"); \
	user_filter_add = (TMP_BLACKLIST)query_service("user_filter_add"); \
	is_need_auth = (IS_NEED_AUTH)query_service("is_need_auth"); \
	is_domainlist_valid=(IS_DOMAINLIST_VALID)query_service("is_domainlist_valid");\
	get_default_domain = (GET_ENVIRONMENT)query_service("get_default_domain"); \
	get_plugin_name = (GET_ENVIRONMENT)query_service("get_plugin_name"); \
	get_config_path = (GET_ENVIRONMENT)query_service("get_config_path"); \
	get_data_path = (GET_ENVIRONMENT)query_service("get_data_path"); \
	get_context_num = (GET_INTEGER)query_service("get_context_num"); \
	check_domain = (CHECKING_FUNCTION)query_service("check_domain"); \
	check_relay = (CHECKING_FUNCTION)query_service("check_relay")

extern GX_EXPORT BOOL AS_LibMain(int reason, void **ptrs);

#ifdef __cplusplus
} /* extern "C" */
#endif
