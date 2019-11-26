#ifndef _H_DOMAIN_CLASSIFIER_
#define _H_DOMAIN_CLASSIFIER_
#include "common_types.h"
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Caution! Also defined in cgi/search_engin/search_engine.h. */
#define LOG_ITEM_OK					0
#define LOG_ITEM_SPAM_MAIL	        1
#define LOG_ITEM_SPAM_VIRUS			2
#define LOG_ITEM_SPAM_INSULATION	3
#define LOG_ITEM_NO_USER			4
#define LOG_ITEM_TIMEOUT			5
#define LOG_ITEM_RETRYING			6
#define LOG_ITEM_OUTGOING_OK		7

typedef struct _LOG_ITEM {
	time_t time;        /* log item's time stamp */
	in_addr_t ip;       /* ip address of log item */
	char from[64];      /* from address */
	char to[64*8];      /* to addresses */
	int type;           /* type of processing result */
	int queue_id;       /* queue ID of received mail */
} LOG_ITEM;

/* Caution! Also defined in cgi/search_engin/search_engine.h. */
typedef struct _ITEM_DATA {
	time_t time;
	in_addr_t ip;
	char from[64];
	char to[64];
	int type;
	int queue_id;
} ITEM_DATA;

void domain_classifier_init(time_t now_time, const char *orignal_path,
	int hash_num, int table_size);
extern int domain_classifier_run(void);
extern int domain_classifier_stop(void);
extern void domain_classifier_free(void);

#endif
