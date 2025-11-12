// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
/* <regex> is said to be too slow, so don't bother switching to it */
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <regex.h>
#include <string>
#include <utility>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include "rewrite.hpp"

using namespace gromox;

namespace {

struct regex_plus : regex_t {
	regex_plus() = default;
	regex_plus(const char *s) { set = regcomp(this, s, REG_ICASE) == 0; }
	regex_plus(regex_plus &&o) {
		if (set)
			regfree(this);
		memcpy(static_cast<regex_t *>(this), static_cast<regex_t *>(&o), sizeof(o));
		o.set = false;
	}
	~regex_plus() { if (set) regfree(this); }
	void operator=(regex_plus &&) = delete;
	bool set = false;
};

struct rewrite_rule {
	regex_plus search_pattern;
	std::string replace_string;
};

}

static std::vector<rewrite_rule> g_rewrite_list;

int mod_rewrite_run(const char *sdlist) try
{
	auto file_ptr = fopen_sd("rewrite.txt", sdlist);
	if (file_ptr == nullptr) {
		if (errno == ENOENT) {
			mlog(LV_INFO, "mod_rewrite: defaulting to built-in rule list");
			g_rewrite_list.emplace_back("/Microsoft-Server-ActiveSync\\(/\\|$\\)", "/sync/index.php\\1");
			return g_rewrite_list.back().search_pattern.set ? 0 : -EINVAL;
		}
		int se = errno;
		mlog(LV_ERR, "mod_rewrite: fopen_sd rewrite.txt: %s", strerror(errno));
		return -(errno = se);
	}
	hxmc_t *line = nullptr;
	auto cl_0 = HX::make_scope_exit([&]() { HXmc_free(line); });
	while (HX_getl(&line, file_ptr.get()) != nullptr) {
		if (*line == '#')
			continue;
		auto lhs = line;
		while (HX_isspace(*lhs))
			++lhs;
		auto rhs = strstr(lhs, " => ");
		if (rhs == nullptr)
			continue;
		*rhs = '\0';
		HX_strrtrim(lhs);
		rhs += 4;
		while (HX_isspace(*rhs))
			++rhs;
		HX_chomp(rhs);
		HX_strrtrim(rhs);
		g_rewrite_list.emplace_back(lhs, rhs);
		if (!g_rewrite_list.back().search_pattern.set) {
			mlog(LV_ERR, "rewrite.txt: problem parsing %s", lhs);
			g_rewrite_list.pop_back();
			continue;
		}
	}
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

bool mod_rewrite_process(const char *uri_buff, size_t uri_len,
    std::string &f_request_uri) try
{
	std::string uri(uri_buff, uri_len);
	for (const auto &node : g_rewrite_list) {
		std::vector<regmatch_t> matches(node.search_pattern.re_nsub + 1);
		if (regexec(&node.search_pattern, uri.c_str(),
		    node.search_pattern.re_nsub + 1, matches.data(), 0) != 0)
			continue;
		f_request_uri.clear();
		auto ri = node.replace_string.c_str();
		do {
			auto seglen = strcspn(ri, "\\");
			f_request_uri.append(ri, seglen);
			ri += seglen;
			if (*ri != '\\')
				break;
			char *end = nullptr;
			auto capnum = strtoul(&ri[1], &end, 10);
			if (end != &ri[1] && capnum < matches.size())
				f_request_uri.append(&uri[matches[capnum].rm_so],
					matches[capnum].rm_eo - matches[capnum].rm_so);
			ri = end;
		} while (*ri != '\0');
		return true;
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1086: ENOMEM");
	return false;
}
