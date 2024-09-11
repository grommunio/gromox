#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

struct MIME;
struct message_content;

namespace oxcmail {

using namemap = std::unordered_map<int, PROPERTY_NAME>;

struct MIME_ENUM_PARAM {
	MIME_ENUM_PARAM(namemap &r) : phash(r) {}
	NOMOVE(MIME_ENUM_PARAM);

	bool b_result = false;
	int attach_id = 0;
	const char *charset = nullptr, *str_zone = nullptr;
	GET_PROPIDS get_propids{};
	EXT_BUFFER_ALLOC alloc{};
	message_content *pmsg = nullptr;
	namemap phash;
	uint16_t last_propid = 0;
	uint64_t nttime_stamp = 0;
	const MIME *pplain = nullptr, *phtml = nullptr, *penriched = nullptr;
	const MIME *pcalendar = nullptr, *preport = nullptr;
	unsigned int plain_count = 0, html_count = 0;
	unsigned int enriched_count = 0, calendar_count = 0;
};

static constexpr unsigned int MAXIMUM_SEARCHING_DEPTH = 10;

extern unsigned int select_parts(const MIME *, MIME_ENUM_PARAM &, unsigned int level);
extern gromox::errno_t bodyset_html(TPROPVAL_ARRAY &, std::string &&, const char *);
extern gromox::errno_t bodyset_plain(TPROPVAL_ARRAY &, std::string &&, const char *);
extern gromox::errno_t bodyset_enriched(TPROPVAL_ARRAY &, std::string &&, const char *);

}
