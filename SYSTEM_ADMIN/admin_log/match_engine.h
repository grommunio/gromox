#ifndef _H_MATCH_ENGINE_
#define _H_MATCH_ENGINE_
#include "single_list.h"
#include <time.h>

#define MAX_LINE_LENGTH 1023
#define MAX_ITEM_NUMBER	4096

typedef struct _MATCH_NODE {
	SINGLE_LIST_NODE node;
	char line[MAX_LINE_LENGTH + 1];
} MATCH_NODE;

typedef struct _MATCH_COLLECTION {
	SINGLE_LIST list;
	SINGLE_LIST_NODE *pnode;
} MATCH_COLLECT;

void match_engine_init(const char *mount_path);
extern int match_engine_run(void);
extern int match_engine_stop(void);
extern void match_engine_free(void);
extern MATCH_COLLECT *match_engine_collect_init(void);
void match_engine_collect_free(MATCH_COLLECT *pcollect);

int match_engine_collect_total(MATCH_COLLECT *pcollect);

void match_engine_collect_begin(MATCH_COLLECT *pcollect);

int match_engine_collect_done(MATCH_COLLECT *pcollect);

char* match_engine_collect_get_value(MATCH_COLLECT *pcollect);

int match_engine_collect_forward(MATCH_COLLECT *pcollect);

BOOL match_engine_match(time_t start_time, time_t end_time, const char *ip,
	const char *from, const char *to, MATCH_COLLECT *pcollect);


#endif

