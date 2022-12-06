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

	bool retrieve(char *in_buff, size_t length);
	void clear();
	DSN_FIELDS *get_message_fields();
	DSN_FIELDS *new_rcpt_fields();
	static bool append_field(DSN_FIELDS *, const char *tag, const char *value);
	bool enum_rcpts_fields(RCPTS_FIELDS_ENUM, void *);
	static bool enum_fields(DSN_FIELDS *, DSN_FIELDS_ENUM, void *);
	bool serialize(char *out, size_t maxlen);

	DSN_FIELDS message_fields;
	DOUBLE_LIST rcpts_fields;
};
