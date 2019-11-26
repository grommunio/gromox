#ifndef _H_MATCH_ENGINE_
#define _H_MATCH_ENGINE_
#include "common_types.h"
#include "double_list.h"
#include <time.h>

typedef struct _LOOKUP_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} LOOKUP_COLLECT;

typedef struct _MESSAGE_ITEM {
	DOUBLE_LIST_NODE node;
	time_t time;
	char from[256];
	char recipient[256];
	char reason[1024];
	char dir[256];
	char file_name[256];
} MESSAGE_ITEM;

void message_lookup_init(const char *mount_path);

int message_lookup_run();

int message_lookup_stop();

void message_lookup_free();

LOOKUP_COLLECT* message_lookup_collect_init();

void message_lookup_collect_free(LOOKUP_COLLECT *pcollect);

int message_lookup_collect_total(LOOKUP_COLLECT *pcollect);

void message_lookup_collect_begin(LOOKUP_COLLECT *pcollect);

int message_lookup_collect_done(LOOKUP_COLLECT *pcollect);

MESSAGE_ITEM* message_lookup_collect_get_value(LOOKUP_COLLECT *pcollect);

int message_lookup_collect_forward(LOOKUP_COLLECT *pcollect);

BOOL message_lookup_match(char *from, char *to, const char *reason,
	LOOKUP_COLLECT *pcollect);


#endif

