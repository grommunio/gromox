#ifndef _H_POP3_
#define _H_POP3_
#include "common_types.h"
#include "double_list.h"

typedef struct _POP3_SESSION {
	char server_ip[16];
	int port;
	char username[256];
	char password[256];
	int sockd;
	DOUBLE_LIST uid_list;
	DOUBLE_LIST del_list;
	DOUBLE_LIST_NODE *pnode_iter;
	BOOL b_touch;
} POP3_SESSION;

typedef struct _UID_ITEM {
	DOUBLE_LIST_NODE node;
	BOOL b_done;
	int id;
	char uid[256];
} UID_ITEM;

void pop3_init(POP3_SESSION *psession, const char *ip, int port,
	const char *username, const char *password);

BOOL pop3_login(POP3_SESSION *psession);

BOOL pop3_uidl(POP3_SESSION *psession);

BOOL pop3_retr(POP3_SESSION *psession, UID_ITEM *puid, char *path);

BOOL pop3_delete(POP3_SESSION *psession, UID_ITEM *puid);

void pop3_mark(POP3_SESSION *psession, UID_ITEM *puid);

BOOL pop3_update(POP3_SESSION *psession);

void pop3_free(POP3_SESSION *psession);

UID_ITEM *pop3_uidl_head(POP3_SESSION *psession);

UID_ITEM *pop3_uidl_next(POP3_SESSION *psession);

#endif
