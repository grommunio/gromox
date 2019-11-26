#ifndef _H_MESSAGE_DEQUEUE_
#define _H_MESSAGE_DEQUEUE_

#include "common_types.h"
#include "single_list.h"

enum{
	MESSAGE_TAPE = 1,
	MESSAGE_MESS
};

enum{
	BOUND_UNKNOWN,	/* unknown message type */
	BOUND_IN,		/* message smtp in */
	BOUND_OUT,		/* message smtp out */
	BOUND_RELAY,	/* message smtp relay */
	BOUND_SELF		/* message creted by hook larger than BOUND_SELF*/
};

enum{
	MESSAGE_DEQUEUE_HOLDING,
	MESSAGE_DEQUEUE_PROCESSING,
	MESSAGE_DEQUEUE_DEQUEUED,
	MESSAGE_DEQUEUE_ALLOCATED
};

/* message struct for dequeuing from mail queue */
typedef struct _MESSAGE {
	SINGLE_LIST_NODE	node;				/* node for list */
	int					flush_ID;			/* flush_ID by smtp server */
	int					bound_type;			/* BOUND_IN, BOUND_OUT, BOUND_RELAY ... */
	BOOL				is_spam;			/* is this a spam mail */
	int					message_option;		/* tape message or mess message */
	int					message_data;		/* tape position or mess ID*/
	void				*begin_address;		/* message buffer address */
	size_t				size;				/* size of allocated buffer */
	void				*mail_begin;		/* mail begin address */
	size_t				mail_length;		/* mail length */
	char				*envelop_from;		/* envelop mail from */
	char				*envelop_rcpt;		/* envelop rcpt to */
} MESSAGE;

void message_dequeue_init(const char *path, int tapse_units,
	size_t max_memory);

int message_dequeue_run();

int message_dequeue_stop();

void message_dequeue_free();

MESSAGE* message_dequeue_get();

void message_dequeue_put(MESSAGE *pmessage);

int message_dequeue_get_param(int param);

void message_dequeue_save(MESSAGE *pmessage);

#endif
