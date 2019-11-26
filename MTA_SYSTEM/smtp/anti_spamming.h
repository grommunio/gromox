#ifndef _H_ANTI_SPAMMING_
#define _H_ANTI_SPAMMING_

#ifndef __cplusplus
#	include <stdbool.h>
#endif
#include "common_types.h"
#include "smtp_parser.h"
#include "plugin.h"

/* enumeration for indicating the reslut of filter */
enum{
    MESSAGE_ACCEPT,   /* this message is not spam */
    MESSAGE_REJECT,   /* reject this spam with answer string 550 ... */
    MESSAGE_RETRYING, /* reject this mail with answer string 450 ... */
};

/* enumeration for indicating the callback type of filter function */
enum{
    ACTION_BLOCK_NEW,         /* a new block is now available */
    ACTION_BLOCK_PROCESSING,  /* processing a block */
    ACTION_BLOCK_FREE,        /* a block is now free */
};

/* struct only for anti-spamming auditor */
typedef struct _MAIL_ENTITY{
    ENVELOP_INFO    *penvelop;
    MAIL_HEAD       *phead;
} MAIL_ENTITY;

typedef struct _MAIL_WHOLE{
    ENVELOP_INFO    *penvelop;
    MAIL_HEAD       *phead;
    MAIL_BODY       *pbody;
} MAIL_WHOLE;
/* struct only for anti-spamming filter */
typedef struct _MAIL_BLOCK{
    int        block_ID;
    MEM_FILE   *fp_mime_info;
    BOOL       is_parsed;
    char       *original_buff;
    size_t     original_length;
    char       *parsed_buff;
    size_t     parsed_length;
} MAIL_BLOCK;

typedef int (*JUDGE_FUNCTION)(int, ENVELOP_INFO*, CONNECTION*, char*, int);
typedef int (*AUDITOR_FUNCTION)(int, MAIL_ENTITY*, CONNECTION*, char*, int);
typedef int (*FILTER_FUNCTION)(int, int, MAIL_BLOCK*, char*, int);
typedef int (*STATISTIC_FUNCTION)(int, MAIL_WHOLE*, CONNECTION*, char*, int);

extern void anti_spamming_init(const char *path, const char *const *names, bool ignerr);
extern int anti_spamming_run(void);
int anti_spamming_unload_library(const char* path);

int anti_spamming_load_library(const char* path);

int anti_spamming_reload_library(const char* path);

int anti_spamming_pass_judges(SMTP_CONTEXT* pcontext, char *reason,
    int length);

int anti_spamming_pass_auditors(SMTP_CONTEXT* pcontext, char *reason,
    int length);

void anti_spamming_inform_filters(const char *type, SMTP_CONTEXT *pcontext,
    int action, int block_ID);

int anti_spamming_pass_filters(const char *type, SMTP_CONTEXT* pcontext,
    MAIL_BLOCK *pblock, char *reason, int length);

int anti_spamming_pass_statistics(SMTP_CONTEXT* pcontext, char *reason,
    int length);

int anti_spamming_console_talk(int argc, char **argv, char *result,int length);

void anti_spamming_enum_plugins(ENUM_PLUGINS enum_func);

void anti_spamming_threads_event_proc(int action);
extern int anti_spamming_stop(void);
extern void anti_spamming_free(void);

#endif

