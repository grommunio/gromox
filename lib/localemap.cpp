// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grammm GmbH
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
#include <gromox/paths.h>
#include <gromox/localemap.hpp>
#include <gromox/common_types.hpp>

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
using fwd_map_t  = std::unordered_map<unsigned int, std::string>;
using back_map_t = std::unordered_map<std::string, unsigned int, icasehash, icasecmp>;
static fwd_map_t g_cpid_map, g_lcid_map;
static back_map_t g_charset_map, g_ltag_map;
static std::once_flag g_cpid_done;

static void xmap_read2(const std::string &file, fwd_map_t &fm, back_map_t &bm)
{
	std::ifstream input(file);
	if (!input.is_open()) {
		fprintf(stderr, "[localemap]: error reading %s: %s\n",
		        file.c_str(), strerror(errno));
		return;
	}
	for (std::string line; std::getline(input, line); ) {
		char *e = nullptr;
		auto a = strtoul(line.c_str(), &e, 0);
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

static void xmap_read(const std::string &file, fwd_map_t &fm, back_map_t &bm)
{
	xmap_read2(file, fm, bm);
	fprintf(stderr, "[localemap]: %s: loaded %zu IDs\n", file.c_str(), fm.size());
	fprintf(stderr, "[localemap]: %s: loaded %zu names\n", file.c_str(), bm.size());
}

bool verify_cpid(uint32_t id)
{
	return g_cpid_map.find(id) != g_cpid_map.cend() &&
	       id != 1200 && id != 1201 && id != 12000 && id != 12001 &&
	       id != 65000 && id != 65001;
}

const char *cpid_to_cset(uint32_t id)
{
	auto i = g_cpid_map.find(id);
	return i != g_cpid_map.cend() ? i->second.c_str() : nullptr;
}

uint32_t cset_to_cpid(const char *s)
{
	auto i = g_charset_map.find(s);
	return i != g_charset_map.cend() ? i->second : 0;
}

const char *lcid_to_ltag(uint32_t id)
{
	auto i = g_lcid_map.find(id);
	return i != g_lcid_map.cend() ? i->second.c_str() : nullptr;
}

uint32_t ltag_to_lcid(const char *s)
{
	auto i = g_ltag_map.find(s);
	return i != g_ltag_map.cend() ? i->second : 0;
}

void localemap_init(const char *datapath)
{
	std::call_once(g_cpid_done, [=]() {
		xmap_read(datapath + "/cpid.txt"s, g_cpid_map, g_charset_map);
		xmap_read(datapath + "/lcid.txt"s, g_lcid_map, g_ltag_map);
	});
}

}
