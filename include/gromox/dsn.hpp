#pragma once
#include <string>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>

namespace gromox {

struct GX_EXPORT dsn_field {
	std::string tag, value;
};

struct GX_EXPORT rcpt_dsn {
	std::vector<dsn_field> fields;
};

using RCPTS_FIELDS_ENUM = bool (*)(const std::vector<dsn_field> &, void *);
using DSN_FIELDS_ENUM = bool (*)(const char *, const char *, void *);

struct GX_EXPORT DSN {
	bool load_from_str_move(char *in_buff, size_t length);
	void clear() {
		message_fields.clear();
		rcpts_fields.clear();
	}
	std::vector<dsn_field> *get_message_fields() { return &message_fields; }
	std::vector<dsn_field> *new_rcpt_fields();
	static bool append_field(std::vector<dsn_field> *, const char *tag, const char *value);
	bool enum_rcpts_fields(RCPTS_FIELDS_ENUM, void *) const;
	static bool enum_fields(const std::vector<dsn_field> &, DSN_FIELDS_ENUM, void *);
	bool serialize(char *out, size_t maxlen) const;

	std::vector<dsn_field> message_fields;
	std::vector<rcpt_dsn> rcpts_fields;
};

}
