#pragma once
#include <memory>
#include <string>
#include <vector>
#include <vmime/message.hpp>
#include <gromox/mapidefs.h>

struct attachment_list;
struct MAIL;
struct message_content;
struct tarray_set;

namespace gromox {

struct GX_EXPORT bounce_template {
	std::string from, subject;
	std::unique_ptr<char[], stdlib_delete> content;
	size_t ctlen = 0, body_start = 0;
};

extern GX_EXPORT gromox::errno_t bounce_gen_init(const char *cfgdir, const char *datadir);
extern GX_EXPORT std::vector<std::string> bounce_gen_langpref(const message_content &, gromox::proptag_t);
extern GX_EXPORT std::vector<std::string> bounce_gen_langpref(const vmime::message &);
extern GX_EXPORT const bounce_template *bounce_gen_lookup(std::vector<std::string> &&langs, const char *tname);
extern GX_EXPORT const char *bounce_gen_postmaster();

extern GX_EXPORT std::string bounce_gen_rcpts(const tarray_set &);
extern GX_EXPORT std::string bounce_gen_thrindex(const vmime::message &);
extern GX_EXPORT std::string bounce_gen_subject(const vmime::message &);

}
