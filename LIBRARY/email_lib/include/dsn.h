#pragma once
#include "common_types.h"
#include "double_list.h"


#define DSN_FIELDS			DOUBLE_LIST

typedef BOOL (*RCPTS_FIELDS_ENUM)(DSN_FIELDS*, void*);

typedef BOOL (*DSN_FIELDS_ENUM)(const char*, const char*, void*);

typedef struct _DSN {
	DSN_FIELDS message_fields;
	DOUBLE_LIST rcpts_fields;
} DSN;


#ifdef __cplusplus
extern "C" {
#endif

void dsn_init(DSN *pdsn);

BOOL dsn_retrieve(DSN *pdsn, char *in_buff, size_t length);

void dsn_clear(DSN *pdsn);

DSN_FIELDS* dsn_get_message_fileds(DSN *pdsn);

DSN_FIELDS* dsn_new_rcpt_fields(DSN *pdsn);
BOOL dsn_append_field(DSN_FIELDS *pfields,
	const char *tag, const char *value);

BOOL dsn_enum_rcpts_fields(DSN *pdsn,
	RCPTS_FIELDS_ENUM enum_func, void *pparam);

BOOL dsn_enum_fields(DSN_FIELDS *pfields,
	DSN_FIELDS_ENUM enum_func, void *pparam);

BOOL dsn_serialize(DSN *pdsn, char *out_buff, size_t max_length);

void dsn_free(DSN *pdsn);

#ifdef __cplusplus
}
#endif
