#ifndef _H_SEARCH_ENGINE_
#define _H_SEARCH_ENGINE_
#include "common_types.h"
#include "double_list.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_ITEM_ALL				-1

/* original defined in daemon/domain_classifier/domain_classifier.h */
#define LOG_ITEM_OK                 0
#define LOG_ITEM_SPAM_MAIL          1
#define LOG_ITEM_SPAM_VIRUS         2
#define LOG_ITEM_SPAM_INSULATION    3
#define LOG_ITEM_NO_USER            4
#define LOG_ITEM_TIMEOUT            5
#define LOG_ITEM_RETRYING           6
#define LOG_ITEM_OUTGOING_OK		7

#define BOUND_TYPE_IN				0
#define BOUND_TYPE_OUT				1

/* original defined in daemon/domain_classifier/domain_classifier.h */
typedef struct _ITEM_DATA {
	time_t time;
	in_addr_t ip;
	char from[64];
	char to[64];
	int type;
	int queue_id;
} ITEM_DATA;

typedef struct _SEARCH_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} SEARCH_COLLECT;

typedef struct _SEARCH_NODE {
	DOUBLE_LIST_NODE node;
	ITEM_DATA item;
} SEARCH_NODE;

void search_engine_init();

int search_engine_run();

int search_engine_stop();

void search_engine_free();

SEARCH_COLLECT* search_engine_collect_init();

void search_engine_collect_free(SEARCH_COLLECT *pcollect);

int search_engine_collect_total(SEARCH_COLLECT *pcollect);

void search_engine_collect_begin(SEARCH_COLLECT *pcollect);

int search_engine_collect_done(SEARCH_COLLECT *pcollect);

ITEM_DATA* search_engine_collect_get_value(SEARCH_COLLECT *pcollect);

int search_engine_collect_forward(SEARCH_COLLECT *pcollect);

BOOL search_engine_search(const char *domain, const char *ip, const char *from,
	const char *rcpt, time_t start_point, time_t end_point,
	SEARCH_COLLECT *pcollect);



#endif
