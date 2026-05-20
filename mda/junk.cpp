// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <libHX/ctype_helper.h>

namespace {
struct junk_rule {
	std::string header, value;
	auto operator<=>(const junk_rule &o) const {
		auto c = strcasecmp(header.c_str(), o.header.c_str()) <=> 0;
		return c != 0 ? c : strcasecmp(value.c_str(), o.value.c_str()) <=> 0;
	}
};
using junk_rule_list = std::vector<junk_rule>;
}

static inline void ws_trim_inplace(std::string &s)
{
	auto b = std::find_if_not(s.begin(), s.end(), [](unsigned char ch) { return HX_isspace(ch); });
	auto e = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char ch) { return HX_isspace(ch); }).base();
	if (b >= e)
		return;
	s.assign(b, e);
}

static inline std::pair<std::string, std::string> split_eq(std::string_view sv)
{
	auto eq = sv.find('=');
	if (eq == sv.npos)
		return {};
	return {std::string(sv.substr(0, eq)), std::string(sv.substr(eq + 1))};
}

static std::vector<std::string> split_com(std::string_view sv)
{
	std::vector<std::string> r;
	for (auto &&e : gromox::gx_split(sv, ';')) {
		for (auto &&f : gromox::gx_split(e, ',')) {
			ws_trim_inplace(f);
			r.emplace_back(std::move(f));
		}
	}
	return r;
}

static std::vector<junk_rule> parse_junk_rules(const char *cfg_value)
{
	std::vector<junk_rule> rlist;
	if (cfg_value == nullptr || *cfg_value == '\0')
		return rlist;
	for (const auto &entry : gromox::gx_split(cfg_value, ';')) {
		auto [k, v] = split_eq(entry);
		ws_trim_inplace(k);
		ws_trim_inplace(v);
		if (!k.empty())
			rlist.emplace_back(std::move(k), std::move(v));
	}
	std::sort(rlist.begin(), rlist.end());
	return rlist;
}

static bool junk_rlist_matches(const std::vector<junk_rule> &rlist,
    const std::string &ehdr, const std::string &eval)
{
	auto rule = std::lower_bound(rlist.begin(), rlist.end(), ehdr,
		    [&](const junk_rule &r, const std::string &eh) {
		    	return strcasecmp(r.header.c_str(), eh.c_str()) < 0;
		    });
	for (; rule != rlist.cend() &&
	     strcasecmp(rule->header.c_str(), ehdr.c_str()) == 0;
	     ++rule) {
		if (rule->value.empty() ||
		    strcasecmp(rule->value.c_str(), eval.c_str()) == 0)
			return true;
		for (auto &&subval : split_com(eval))
			if (strcasecmp(rule->value.c_str(), subval.c_str()) == 0)
				return true;
	}
	return false;
}
