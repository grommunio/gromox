// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gromox/dsn.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/util.hpp>

using namespace gromox;

bool DSN::retrieve(char *in_buff, size_t length)
{
	auto pdsn = this;
	MIME_FIELD mime_field;
	size_t current_offset = 0;

	clear();
	auto pfields = &pdsn->message_fields;
	while (current_offset < length) {
		if (0 == strncmp(in_buff + current_offset, "\r\n", 2)) {
			if (pfields->size() > 0) {
				pfields = new_rcpt_fields();
				if (NULL == pfields) {
					clear();
					return false;
				}
			}
			current_offset += 2;
			continue;
		}
		auto parsed_length = parse_mime_field(in_buff + current_offset,
		                     length - current_offset, &mime_field);
		current_offset += parsed_length;
		if (0 == parsed_length) {
			break;
		}
		if (!DSN::append_field(pfields, mime_field.name.c_str(),
		    mime_field.value.c_str())) {
			clear();
			return false;
		}
	}
	if (pfields != &pdsn->message_fields && pfields->size() == 0)
		rcpts_fields.clear();
	return true;
}

std::vector<dsn_field> *DSN::new_rcpt_fields() try
{
	return &rcpts_fields.emplace_back().fields;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1213: ENOMEM");
	return nullptr;
}

bool DSN::append_field(std::vector<dsn_field> *pfields, const char *tag,
    const char *value) try
{
	pfields->push_back(dsn_field{tag, value});
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1212: ENOMEM");
	return false;
}

bool DSN::enum_rcpts_fields(RCPTS_FIELDS_ENUM enum_func, void *pparam)
{
	for (const auto &r : rcpts_fields)
		if (!enum_func(r.fields, pparam))
			return false;
	return true;
}

bool DSN::enum_fields(const std::vector<dsn_field> &pfields,
    DSN_FIELDS_ENUM enum_func, void *pparam)
{
	for (const auto &f : pfields)
		if (!enum_func(f.tag.c_str(), f.value.c_str(), pparam))
			return false;
	return true;
}

bool DSN::serialize(char *out_buff, size_t max_length)
{
	size_t offset;

	offset = 0;
	for (const auto &f : message_fields)
		offset += gx_snprintf(out_buff + offset, max_length - offset,
		          "%s: %s\r\n", f.tag.c_str(), f.value.c_str());
	if (offset + 2 >= max_length - 1) {
		return false;
	}
	out_buff[offset] = '\r';
	offset ++;
	out_buff[offset] = '\n';
	offset ++;
	out_buff[offset] = '\0';
	for (const auto &r : rcpts_fields) {
		for (const auto &f : r.fields)
			offset += gx_snprintf(out_buff + offset, max_length - offset,
			          "%s: %s\r\n", f.tag.c_str(), f.value.c_str());
		if (offset + 2 >= max_length - 1) {
			return false;
		}
		out_buff[offset] = '\r';
		offset ++;
		out_buff[offset] = '\n';
		offset ++;
		out_buff[offset] = '\0';
	}
	return true;
}
