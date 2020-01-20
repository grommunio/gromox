#pragma once
#include "ext_buffer.h"

#define CALL_ID_CONNECT													0x00
#define CALL_ID_LISTEN_NOTIFICATION										0x01
#define CALL_ID_PING_STORE												0x02
#define CALL_ID_SUBSCRIBE_NOTIFICATION									0x73
#define CALL_ID_UNSUBSCRIBE_NOTIFICATION								0x74

#define RESPONSE_CODE_SUCCESS											0x00
#define RESPONSE_CODE_ACCESS_DENY										0x01
#define RESPONSE_CODE_MAX_REACHED										0x02
#define RESPONSE_CODE_LACK_MEMORY										0x03
#define RESPONSE_CODE_MISCONFIG_PREFIX									0x04
#define RESPONSE_CODE_MISCONFIG_MODE									0x05
#define RESPONSE_CODE_CONNECT_INCOMPLETE								0x06
#define RESPONSE_CODE_PULL_ERROR										0x07
#define RESPONSE_CODE_DISPATCH_ERROR									0x08
#define RESPONSE_CODE_PUSH_ERROR										0x09

typedef struct _REQ_CONNECT {
	char *prefix;
	char *remote_id;
	BOOL b_private;
} REQ_CONNECT;

typedef struct _REQ_LISTEN_NOTIFICATION {
	char *remote_id;
} REQ_LISTEN_NOTIFICATION;

typedef struct _REQ_SUBSCRIBE_NOTIFICATION {
	uint16_t notificaton_type;
	BOOL b_whole;
	uint64_t folder_id;
	uint64_t message_id;
} REQ_SUBSCRIBE_NOTIFICATION;

typedef struct _REQ_UNSUBSCRIBE_NOTIFICATION {
	uint32_t sub_id;
} REQ_UNSUBSCRIBE_NOTIFICATION;

typedef union _REQUEST_PAYLOAD {
	REQ_CONNECT connect;
	REQ_LISTEN_NOTIFICATION	listen_notification;
	REQ_SUBSCRIBE_NOTIFICATION subscribe_notification;
	REQ_UNSUBSCRIBE_NOTIFICATION unsubscribe_notification;
} REQUEST_PAYLOAD;

typedef struct _EXMDB_REQUEST {
	uint8_t call_id;
	char *dir;
	REQUEST_PAYLOAD payload;
} EXMDB_REQUEST;

typedef struct _RESP_SUBSCRIBE_NOTIFICATION {
	uint32_t sub_id;
} RESP_SUBSCRIBE_NOTIFICATION;

typedef union _RESPONSE_PAYLOAD {
	RESP_SUBSCRIBE_NOTIFICATION subscribe_notification;
} RESPONSE_PAYLOAD;

typedef struct _EXMDB_RESPONSE {
	uint8_t call_id;
	RESPONSE_PAYLOAD payload;
} EXMDB_RESPONSE;

typedef struct _DB_NOTIFY_DATAGRAM {
	char *dir;
	BOOL b_table;
	LONG_ARRAY id_array;
	DB_NOTIFY db_notify;
} DB_NOTIFY_DATAGRAM;

int exmdb_ext_pull_request(const BINARY *pbin_in,
	EXMDB_REQUEST *prequest);

int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out);

int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXT_BUFFER_ALLOC auto_alloc, EXMDB_RESPONSE *presponse);

int exmdb_ext_push_response(const EXMDB_RESPONSE *presponse,
	BINARY *pbin_out);

int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	EXT_BUFFER_ALLOC auto_alloc, DB_NOTIFY_DATAGRAM *pnotify);
