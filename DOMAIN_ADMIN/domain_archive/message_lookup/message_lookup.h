#ifndef _H_MATCH_ENGINE_
#define _H_MATCH_ENGINE_
#include "common_types.h"
#include "double_list.h"
#include <stdint.h>

typedef struct _LOOKUP_COLLECT {
	DOUBLE_LIST message_list;
	DOUBLE_LIST_NODE *pnode;
} LOOKUP_COLLECT;


typedef struct _MESSAGE_ITEM {
	DOUBLE_LIST_NODE node;
	uint64_t mail_id;
	int server_id;
} MESSAGE_ITEM;

typedef struct _VAL_SCOPE {
	uint64_t begin;
	uint64_t end;
} VAL_SCOPE;

typedef struct _HEADER_VAL {
	char *field;
	char *value;
} HEADER_VAL;

void message_lookup_init(const char *cidb_path);

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

BOOL message_lookup_search(int server_id, const char *charset,
	const char *unit, const char *sender, const char *rcpt,
	const char *from, const char *to, const char *cc,
	const char *subject, const char *content, const char *filename,
	BOOL *attached, int *priority, VAL_SCOPE *atime, VAL_SCOPE *rtime,
	VAL_SCOPE *ctime, VAL_SCOPE *size, uint64_t *reference,
	VAL_SCOPE *id, HEADER_VAL *header, LOOKUP_COLLECT *pcollect);

BOOL message_lookup_match(int server_id, uint64_t mail_id,
	char *path, char *digest);

#endif

