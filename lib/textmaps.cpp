// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>

namespace gromox {

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

using namespace std::string_literals;
using int_to_str_t = std::unordered_map<unsigned int, std::string>;
using str_to_int_t = std::unordered_map<std::string, unsigned int, icasehash, icasecmp>;
using str_to_str_t = std::unordered_map<std::string, std::string, icasehash, icasecmp>;
static int_to_str_t g_cpid2name_map, g_lcid2tag_map;
static str_to_int_t g_cpname2id_map, g_lctag2id_map;
static str_to_str_t g_ext2mime_map, g_mime2ext_map;
static std::once_flag g_textmaps_done;

static void xmap_read(const char *file, const char *dirs,
    int_to_str_t &fm, str_to_int_t &bm)
{
	auto filp = fopen_sd(file, dirs);
	if (filp == nullptr) {
		fprintf(stderr, "[textmaps]: fopen_sd %s: %s\n", file, strerror(errno));
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
		fprintf(stderr, "[textmaps]: fopen_sd %s: %s\n", file, strerror(errno));
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
		HX_strlower(value);
		fm.emplace(line, value);
		bm.emplace(value, line);
	}
}

bool verify_cpid(uint32_t id)
{
	return g_cpid2name_map.find(id) != g_cpid2name_map.cend() &&
	       id != 1200 && id != 1201 && id != 12000 && id != 12001 &&
	       id != 65000 && id != 65001;
}

const char *cpid_to_cset(uint32_t id)
{
	auto i = g_cpid2name_map.find(id);
	return i != g_cpid2name_map.cend() ? i->second.c_str() : nullptr;
}

uint32_t cset_to_cpid(const char *s)
{
	auto i = g_cpname2id_map.find(s);
	return i != g_cpname2id_map.cend() ? i->second : 0;
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

void textmaps_init(const char *datapath)
{
	std::call_once(g_textmaps_done, [=]() {
		xmap_read("cpid.txt", datapath, g_cpid2name_map, g_cpname2id_map);
		fprintf(stderr, "[textmaps]: cpid: %zu IDs, %zu names\n",
		        g_cpid2name_map.size(), g_cpname2id_map.size());
		xmap_read("lcid.txt", datapath, g_lcid2tag_map, g_lctag2id_map);
		fprintf(stderr, "[textmaps]: lcid: %zu IDs, %zu names\n",
		        g_lcid2tag_map.size(), g_lctag2id_map.size());
		smap_read("mime_extension.txt", datapath, g_ext2mime_map, g_mime2ext_map);
		fprintf(stderr, "[textmaps]: mime_extension: %zu exts, %zu mimetypes\n",
		        g_ext2mime_map.size(), g_mime2ext_map.size());
	});
}

}
