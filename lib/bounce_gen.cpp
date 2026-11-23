// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2026 grommunio GmbH
// This file is part of Gromox.
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <netdb.h>
#include <string>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <vmime/message.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

namespace gromox {

using template_map = std::map<std::string, bounce_template>; /* encoding -> template details */
static std::string g_bounce_postmaster;
static std::map<std::string, template_map> g_resource_list; /* template name -> encodings */

/**
 * @tpl_file: template filename
 */
static errno_t bounce_gen_load(int dfd, const char *de_name)
{
	std::string tpl_name, tpl_encoding;
	bounce_template bt;

	{
		tpl_name = de_name;
		auto pos = tpl_name.find('.');
		if (pos == tpl_name.npos)
			return 0;
		tpl_encoding = tpl_name.substr(pos + 1);
		tpl_name.erase(pos);
	}
	{
		wrapfd fd(::openat(dfd, de_name, O_RDONLY));
		if (fd.get() < 0)
			return -errno;
		bt.content.reset(HX_slurp_fd(fd.get(), &bt.ctlen));
		if (bt.content == nullptr) {
			errno_t se = errno;
			mlog(LV_ERR, "Bounce template %s: %s",
				de_name, strerror(se));
			return se;
		}
	}

		size_t j = 0;
		while (j < bt.ctlen) {
			MIME_FIELD mf;
			auto parsed = parse_mime_field(&bt.content[j], bt.ctlen - j, &mf);
			j += parsed;
			if (parsed == 0) {
				mlog(LV_ERR, "Bounce template %s: Format error", de_name);
				return EIO;
			}
			if (strcasecmp(mf.name.c_str(), "From") == 0)
				bt.from = std::move(mf.value);
			else if (strcasecmp(mf.name.c_str(), "Subject") == 0)
				bt.subject = std::move(mf.value);
			if (bt.content[j] == '\n') {
				++j;
				break;
			} else if (bt.content[j] == '\r' && bt.content[j+1] == '\n') {
				j += 2;
				break;
			}
		}
		bt.body_start = j;

	g_resource_list[std::move(tpl_name)].emplace(std::move(tpl_encoding), std::move(bt));
	return 0;
}

static constexpr cfg_directive bounce_gen_dflt[] = {
	{"bounce_postmaster", "postmaster@"},
	CFG_TABLE_END,
};

errno_t bounce_gen_init(const char *cfgdir, const char *datadir) try
{
	textmaps_init();
	/*
	 * NOTE: bounce_gen_init may get called multiple times within a process
	 * image (e.g. ews_init, PROC_exchange_emsmdb, SVC_exmdb_provider).
	 */
	auto cfg = config_file_initd("gromox.cfg", cfgdir, bounce_gen_dflt);
	if (cfg == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd gromox.cfg: %s",
		       strerror(errno));
		return EIO;
	}
	auto str = cfg->get_value("bounce_postmaster");
	if (strchr(str, '@') == nullptr) {
		mlog(LV_ERR, "gromox.cfg: \"bounce_postmaster\" directive has bogus value: no @ character");
		return EINVAL;
	}
	g_bounce_postmaster = str;
	if (str[strlen(str)-1] == '@') {
		std::string hn;
		auto ret = canonical_hostname(hn);
		if (ret != 0) {
			mlog(LV_ERR, "canonical_hostname: %s", strerror(ret));
			return EINVAL;
		}
		g_bounce_postmaster += std::move(hn);
		mlog(LV_INFO, "bounce_gen: postmaster set to <%s>", g_bounce_postmaster.c_str());
	}

	auto di = opendir_sd("bounces", datadir);
	if (di.m_dir == nullptr) {
		mlog(LV_ERR, "bounce_producer: opendir_sd(\"bounces\") %s: %s",
			di.m_path.c_str(), strerror(errno));
		return EIO;
	}

	struct dirent *de;
	while ((de = readdir(di.m_dir.get())) != nullptr) {
		if (*de->d_name == '.')
			continue;
		auto ret = bounce_gen_load(dirfd(di.m_dir.get()), de->d_name);
		if (ret != 0)
			return ret;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ENOMEM;
}

/**
 * @sv: Accept-Language header value, e.g. "fr-CH, fr;q=0.7, *;q=0.5"
 *
 * Breaks down the list and returns the choice list in XPG form. q values are
 * ignored, just send them in the right order to begin with.
 */
static std::vector<std::string> acceptlanguage_to_xpglist(std::string_view sv)
{
	std::vector<std::string> list;
	for (auto &&ch : gx_split(sv, ',')) {
		auto pos = ch.find(';');
		if (pos != ch.npos)
			ch.erase(pos);
		pos = ch.find('-');
		if (pos != ch.npos)
			ch[pos] = '_';
		list.emplace_back(std::move(ch));
	}
	return list;
}

/**
 * @msg:    Original message that warrants a reply
 * @al_tag: Property tag corresponding to PS_INTERNET_HEADERS:Accept-Language,
 *          or 0 for foregoing this.
 *
 * Scans a message and return preferred languages (in XPG locale form) to
 * respond with.
 */
std::vector<std::string> bounce_gen_langpref(const message_content &msg,
    proptag_t al_tag)
{
	std::vector<std::string> list;
	if (PROP_ID(al_tag) != PROP_ID(PR_NULL)) {
		auto pv = msg.proplist.get<const char>(al_tag);
		if (pv != nullptr)
			list = acceptlanguage_to_xpglist(pv);
	}
	if (auto cpid = msg.proplist.get<const int32_t>(PR_MESSAGE_LOCALE_ID)) {
		if (auto lang = lcid_to_ltag(*cpid)) {
			auto l2 = acceptlanguage_to_xpglist({lang});
			list.insert(list.end(), std::make_move_iterator(l2.begin()),
				std::make_move_iterator(l2.end()));
		}
	}
	list.emplace_back("en");
	return list;
}

std::vector<std::string> bounce_gen_langpref(const vmime::message &msg)
{
	std::vector<std::string> list;
	if (auto hdr = msg.getHeader()) {
		if (auto fld = hdr->findField("Accept-Language"))
			list = acceptlanguage_to_xpglist(fld->getValue()->generate());
		if (auto fld = hdr->findField("X-Accept-Language")) {
			auto l2 = acceptlanguage_to_xpglist(fld->getValue()->generate());
			list.insert(list.end(), std::make_move_iterator(l2.begin()),
				std::make_move_iterator(l2.end()));
		}
		if (auto fld = hdr->findField("Content-Language")) {
			auto l2 = acceptlanguage_to_xpglist(fld->getValue()->generate());
			list.insert(list.end(), std::make_move_iterator(l2.begin()),
				std::make_move_iterator(l2.end()));
		}
	}
	list.emplace_back("en");
	return list;
}

/**
 * @langlist: A list of languages to try
 * @tname:    Message template to use
 */
const bounce_template *
bounce_gen_lookup(std::vector<std::string> &&langlist, const char *tname)
{
	auto i = g_resource_list.find(tname);
	if (i == g_resource_list.end())
		return nullptr;
	for (auto &&choice : langlist) {
		auto j = i->second.find(choice);
		if (j != i->second.end())
			return &j->second;
		auto pos = choice.find('_');
		if (pos == choice.npos)
			continue;
		choice.erase(pos);
		j = i->second.find(choice);
		if (j != i->second.end())
			return &j->second;
	}
	return nullptr;
}

const char *bounce_gen_postmaster() { return g_bounce_postmaster.c_str(); }

std::string bounce_gen_rcpts(const tarray_set &rcpts)
{
	std::string r;
	for (size_t i = 0; i < rcpts.count; ++i) {
		auto str = rcpts.pparray[i]->get<const char>(PR_SMTP_ADDRESS);
		if (str == nullptr)
			continue;
		if (!r.empty())
			r += ", ";
		r += str;
	}
	return r;
}

}
