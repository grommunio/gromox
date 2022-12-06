#pragma once
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#define DSN_FIELDS			DOUBLE_LIST

using RCPTS_FIELDS_ENUM = bool (*)(DSN_FIELDS *, void *);
using DSN_FIELDS_ENUM = bool (*)(const char *, const char *, void *);

struct GX_EXPORT DSN {
	DSN();
	~DSN();

	DSN_FIELDS message_fields;
	DOUBLE_LIST rcpts_fields;
};

extern GX_EXPORT bool dsn_retrieve(DSN *, char *in_buff, size_t length);
void dsn_clear(DSN *pdsn);
DSN_FIELDS* dsn_get_message_fileds(DSN *pdsn);
DSN_FIELDS* dsn_new_rcpt_fields(DSN *pdsn);
extern GX_EXPORT bool dsn_append_field(DSN_FIELDS *, const char *tag, const char *value);
extern GX_EXPORT bool dsn_enum_rcpts_fields(DSN *, RCPTS_FIELDS_ENUM, void *pparam);
extern GX_EXPORT bool dsn_enum_fields(DSN_FIELDS *, DSN_FIELDS_ENUM, void *pparam);
extern GX_EXPORT bool dsn_serialize(DSN *, char *out, size_t maxlen);
