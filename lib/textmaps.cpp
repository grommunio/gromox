// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

namespace {

struct icasehash {
	size_t operator()(std::string s) const {
		std::transform(s.begin(), s.end(), s.begin(), HX_toupper);
		return std::hash<std::string>{}(std::move(s));
	}
};

struct icasecmp {
	bool operator()(const std::string &a, const std::string &b) const {
		return strcasecmp(a.c_str(), b.c_str()) == 0;
	}
};

}

using namespace std::string_literals;
using namespace gromox;
using int_to_str_t = std::unordered_map<unsigned int, std::string>;
using str_to_int_t = std::unordered_map<std::string, unsigned int, icasehash, icasecmp>;
using str_to_str_t = std::unordered_map<std::string, std::string, icasehash, icasecmp>;
using folder_name_map_t = std::unordered_map<std::string, std::unordered_map<unsigned int, std::string>>;
static int_to_str_t g_cpid2name_map, g_lcid2tag_map;
static str_to_int_t g_cpname2id_map, g_lctag2id_map;
static str_to_str_t g_ext2mime_map, g_mime2ext_map, g_lang2cset_map, g_ignore_map;
static folder_name_map_t folder_name_map;
static Json::Value g_cpl_dict;
static std::once_flag g_textmaps_done;

static void xmap_read(const char *file, const char *dirs,
    int_to_str_t &fm, str_to_int_t &bm)
{
	auto filp = fopen_sd(file, dirs);
	if (filp == nullptr) {
		mlog(LV_ERR, "textmaps: fopen_sd %s: %s", file, strerror(errno));
		return;
	}
	hxmc_t *line = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(line); });
	while (HX_getl(&line, filp.get()) != nullptr) {
		char *e = nullptr;
		auto a = strtoul(line, &e, 0);
		if (e == nullptr)
			continue;
		while (HX_isspace(*e))
			++e;
		if (*e == '\0')
			continue;
		auto eol = e;
		while (!HX_isspace(*eol) && *eol != '\0')
			++eol;
		*eol = '\0';
		HX_strlower(e);
		fm.emplace(a, e);
		bm.emplace(e, a);
	}
}

static void smap_read(const char *file, const char *dirs,
    str_to_str_t &fm, str_to_str_t &bm)
{
	auto filp = fopen_sd(file, dirs);
	if (filp == nullptr) {
		mlog(LV_ERR, "textmaps: fopen_sd %s: %s", file, strerror(errno));
		return;
	}
	hxmc_t *line = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(line); });
	while (HX_getl(&line, filp.get()) != nullptr) {
		char *value = line;
		while (!HX_isspace(*value))
			++value;
		if (*value == '\0')
			continue;
		*value++ = '\0';
		while (HX_isspace(*value))
			++value;
		if (*value == '\0')
			continue;
		auto eol = value;
		while (!HX_isspace(*eol) && *eol != '\0')
			++eol;
		*eol = '\0';
		HX_strlower(value);
		fm.emplace(line, value);
		if (&bm != &g_ignore_map)
			bm.emplace(value, line);
	}
}

namespace gromox {

static void folder_namedb_read(const char *file, const char *dirs, folder_name_map_t &fm)
{
	auto filp = fopen_sd(file, dirs);
	if (filp == nullptr) {
		mlog(LV_ERR, "textmaps: fopen_sd %s: %s", file, strerror(errno));
		return;
	}
	hxmc_t *line = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(line); });
	folder_name_map_t::mapped_type *current_locale = nullptr;
	while (HX_getl(&line, filp.get()) != nullptr) {
		HX_chomp(line);
		if (*line == '\0')
			continue;
		if (*line == '[') { // ]
			auto value = strchr(line + 1, ']');
			if (value == nullptr)
				continue;
			*value = '\0';
			current_locale = &fm[line+1];
			continue;
		} else if (current_locale == nullptr) {
			continue;
		}
		char *value = strchr(line, '=');
		if (value == nullptr)
			continue;
		*value++ = '\0';
		char *end;
		auto id = strtoul(line, &end, 16);
		if (end == line)
			continue;
		current_locale->emplace(id, value);
	}
}

/*
 * Trivial mechanism to give translations for the special per-domain ABK groups
 * to NSP clients, based on CPID (which is silly - the LCID should be used, but
 * clients do not pass it when reading the GAB).
 */
static int cpl_read(const char *filename, const char *dirs, Json::Value &dict)
{
	auto fp = fopen_sd(filename, dirs);
	if (fp == nullptr) {
		mlog(LV_ERR, "textmaps: fopen_sd %s: %s",
		        filename, strerror(errno));
		return -1;
	}
	size_t sl = 0;
	std::unique_ptr<char[], stdlib_delete> sd(HX_slurp_fd(fileno(fp.get()), &sl));
	if (sd == nullptr) {
		mlog(LV_ERR, "textmaps: slurp %s: %s",
		        filename, strerror(errno));
		return -1;
	}
	if (!json_from_str({sd.get(), sl}, dict)) {
		mlog(LV_ERR, "textmaps: invalid JSON data in %s", filename);
		return -1;
	}
	return 0;
}

errno_t cpl_get_string(cpid_t codepage, const char *tag, char *value, size_t len)
{
	const auto &dict = g_cpl_dict;
	auto l1key = std::to_string(codepage);
	if (dict.isMember(l1key)) {
		const auto &l2ref = dict[l1key][tag];
		if (l2ref == Json::Value::null)
			return ENOENT;
		gx_strlcpy(value, l2ref.asString().c_str(), len);
		return 0;
	}
	/* use first entry as default */
	auto it = dict.begin();
	if (it == dict.end())
		return ENOENT;
	const auto &l2ref = (*it)[tag];
	if (l2ref == Json::Value::null)
		return ENOENT;
	gx_strlcpy(value, l2ref.asString().c_str(), len);
	return 0;
}

bool verify_cpid(uint32_t id)
{
	return g_cpid2name_map.find(id) != g_cpid2name_map.cend() &&
	       id != CP_UTF16 && id != CP_UTF16BE &&
	       id != CP_UTF32 && id != CP_UTF32BE &&
	       id != CP_UTF7 && id != CP_UTF8;
}

const char *cpid_to_cset(cpid_t id)
{
	auto i = g_cpid2name_map.find(id);
	return i != g_cpid2name_map.cend() ? i->second.c_str() : nullptr;
}

cpid_t cset_to_cpid(const char *s)
{
	auto i = g_cpname2id_map.find(s);
	return i != g_cpname2id_map.cend() ? static_cast<cpid_t>(i->second) : CP_ACP;
}

const char *lcid_to_ltag(uint32_t id)
{
	auto i = g_lcid2tag_map.find(id);
	return i != g_lcid2tag_map.cend() ? i->second.c_str() : nullptr;
}

uint32_t ltag_to_lcid(const char *s)
{
	auto i = g_lctag2id_map.find(s);
	return i != g_lctag2id_map.cend() ? i->second : 0;
}

const char *mime_to_extension(const char *s)
{
	auto i = g_mime2ext_map.find(s);
	return i != g_mime2ext_map.cend() ? i->second.c_str() : nullptr;
}

const char *extension_to_mime(const char *s)
{
	auto i = g_ext2mime_map.find(s);
	return i != g_ext2mime_map.cend() ? i->second.c_str() : nullptr;
}

const char *lang_to_charset(const char *s)
{
	auto i = g_lang2cset_map.find(s);
	return i != g_lang2cset_map.cend() ? i->second.c_str() : nullptr;
}

/**
 * @xpg_loc:	XPG-style locale string (e.g. "es_CA.UTF-8@valencia")
 *
 * Returns the closest language match for the folder_lang table.
 */
const char *folder_namedb_resolve(const char *xpg_loc) try
{
	std::string rloc = xpg_loc;
	/* Always ignore .encoding part */
	auto pos = rloc.find('.');
	if (pos != rloc.npos)
		rloc.erase(pos, rloc.find('@', pos));
	auto iter = folder_name_map.find(rloc);
	if (iter != folder_name_map.end())
		return iter->first.c_str();
	/* Try without @variant part */
	pos = rloc.find('@');
	if (pos != rloc.npos)
		rloc.erase(pos);
	iter = folder_name_map.find(rloc);
	if (iter != folder_name_map.end())
		return iter->first.c_str();
	/* Try without _territory part */
	pos = rloc.find('_');
	if (pos != rloc.npos)
		rloc.erase(pos);
	iter = folder_name_map.find(rloc);
	if (iter != folder_name_map.end())
		return iter->first.c_str();
	return nullptr;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1560: ENOMEM");
	return nullptr;
}

/**
 * @locale:	Language string matching those found in data/folder_names.txt.
 * 		Use e.g. common_util_i18n_to_lang to convert from XPG locale strings.
 * @tid:	Text id in data/folder_names.txt; coincides with PRIVATE_FID_*
 * 		most of the time.
 */
const char *folder_namedb_get(const char *locale, unsigned int tid)
{
	auto loc_it = folder_name_map.find(locale);
	if (loc_it != folder_name_map.end()) {
		auto id_it = loc_it->second.find(tid);
		if (id_it != loc_it->second.end())
			return id_it->second.c_str();
	}
	auto en = folder_name_map.find("en");
	if (en == folder_name_map.end())
		return "FLG-ERR-1";
	auto id_it = en->second.find(tid);
	if (id_it == en->second.end())
		return "FLG-ERR-2";
	return id_it->second.c_str();
}

void textmaps_init(const char *datapath)
{
	if (datapath == nullptr)
		datapath = PKGDATADIR;
	std::call_once(g_textmaps_done, [=]() {
		xmap_read("cpid.txt", datapath, g_cpid2name_map, g_cpname2id_map);
		mlog(LV_INFO, "textmaps: cpid: %zu IDs, %zu names",
		        g_cpid2name_map.size(), g_cpname2id_map.size());
		xmap_read("lcid.txt", datapath, g_lcid2tag_map, g_lctag2id_map);
		mlog(LV_INFO, "textmaps: lcid: %zu IDs, %zu names",
		        g_lcid2tag_map.size(), g_lctag2id_map.size());
		smap_read("lang_charset.txt", datapath, g_lang2cset_map, g_ignore_map);
		mlog(LV_INFO, "textmaps: lang_charset: %zu mappings",
		        g_lang2cset_map.size());
		smap_read("mime_extension.txt", datapath, g_ext2mime_map, g_mime2ext_map);
		mlog(LV_INFO, "textmaps: mime_extension: %zu exts, %zu mimetypes",
		        g_ext2mime_map.size(), g_mime2ext_map.size());
		folder_namedb_read("folder_names.txt", datapath, folder_name_map);
		mlog(LV_INFO, "textmaps: %zu translations in folder namedb", folder_name_map.size());
		cpl_read("codepage_lang.json", datapath, g_cpl_dict);
	});
}

}
