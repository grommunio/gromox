#ifndef _H_TRANSPORTER_
#define _H_TRANSPORTER_
#include "message_dequeue.h"
#include "plugin.h"
#include "mail.h"

enum{
	TRANSPORTER_MIN_THREADS,
	TRANSPORTER_MAX_THREADS,
	TRANSPORTER_CREATED_THREADS
};

void transporter_init(const char *path, int threads_min, int threads_max,
	int free_num, int mime_ratio, BOOL dm_valid);
extern int transporter_run(void);
extern int transporter_stop(void);
extern void transporter_free(void);
extern void transporter_wakeup_one_thread(void);
int transporter_unload_library(const char* path);

int transporter_load_library(const char* path);

int transporter_console_talk(int argc, char** argv, char *result, int length);
extern const char *transporter_get_local(void);
extern const char *transporter_get_remote(void);
void transporter_enum_plugins(ENUM_PLUGINS enum_func);

int transporter_get_param(int param);

void transporter_validate_domainlist(BOOL b_valid);
extern BOOL transporter_domainlist_valid(void);

#endif /* _H_TRANSPORTER_ */
