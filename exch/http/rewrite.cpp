// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <regex.h>
#include <string>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include "http_parser.hpp"
#include "rewrite.hpp"
#define MAX_LINE					16*1024

using namespace gromox;

namespace {

class rewrite_list;
class rewrite_rule {
	public:
	rewrite_rule() = default;
	rewrite_rule(rewrite_rule &&) noexcept;
	~rewrite_rule();
	void operator=(rewrite_rule &&) = delete;
	bool try_replace(char *uri, int uri_size);

	private:
	regex_t search_pattern{};
	std::string replace_string;
	bool reg_set = false;

	friend class rewrite_list;
};
using REWRITE_NODE = rewrite_rule;

class rewrite_list : public std::vector<rewrite_rule> {
	public:
	int emplace(const char *from, const char *to);
};

}

static rewrite_list g_rewrite_list;

rewrite_rule::rewrite_rule(rewrite_rule &&o) noexcept :
    replace_string(std::move(o.replace_string))
{
	if (reg_set)
		regfree(&search_pattern);
	memcpy(&search_pattern, &o.search_pattern, sizeof(search_pattern));
	reg_set = o.reg_set;
	o.reg_set = false;
}

rewrite_rule::~rewrite_rule()
{
	if (reg_set)
		regfree(&search_pattern);
}

bool rewrite_rule::try_replace(char *buf, int size)
{
	char *pos;
	int last_pos;
	int i, len, offset;
	int rp_offsets[10];
	regmatch_t pmatch[10]; /* regoff_t is int so size is int */
	char original_rp[8192];
	char original_buf[8192];

	if (regexec(&search_pattern, buf, 10, pmatch, 0))
		return FALSE;
	auto &rp = replace_string;
	if ('\\' == rp[0] && '0' == rp[1]) {
		gx_strlcpy(buf, &rp[2], size);
		return TRUE;
	}
	gx_strlcpy(original_buf, buf, std::size(original_buf));
	gx_strlcpy(original_rp, rp.c_str(), std::size(original_rp));
	for (i = 0; i < 10; ++i)
		rp_offsets[i] = -1;
	for (pos=original_rp; '\0'!=*pos; pos++) {
		if (pos[0] == '\\' && pos[1] > '0' && pos[1] <= '9') {
			rp_offsets[pos[1]-'0'] = pos + 2 - original_rp;
			*pos = '\0';
		}
	}
	last_pos = 0;
	for (i=1,offset=0; i<=10&&offset<size; i++) {
		if (i == 10 || pmatch[i].rm_so < 0 || pmatch[i].rm_eo < 0) {
			len = strlen(original_buf + last_pos);
			if (offset + len >= size)
				break;
			strcpy(buf + offset, original_buf + last_pos);
			return TRUE;
		}
		if (-1 != rp_offsets[i]) {
			len = pmatch[i].rm_so - last_pos;
			if (offset + len >= size)
				break;
			memcpy(buf + offset, original_buf + last_pos, len);
			offset += len;
			len = strlen(original_rp + rp_offsets[i]);
			if (offset + len >= size)
				break;
			strcpy(buf + offset, original_rp + rp_offsets[i]);
		} else {
			len = pmatch[i].rm_eo - last_pos;
			if (offset + len >= size)
				break;
			memcpy(buf + offset, original_buf + last_pos, len);
		}
		offset += len;
		last_pos = pmatch[i].rm_eo;
	}
	return FALSE;
}

int rewrite_list::emplace(const char *from, const char *to)
{
	static constexpr size_t ebufsize = 512;
	auto errbuf = std::make_unique<char[]>(ebufsize);
	rewrite_rule node;

	node.replace_string = to;
	auto ret = regcomp(&node.search_pattern, from, REG_ICASE);
	if (ret != 0) {
		regerror(ret, &node.search_pattern, errbuf.get(), ebufsize);
		mlog(LV_ERR, "mod_rewrite %s: regcomp: %s", from, errbuf.get());
		return -EINVAL;
	}
	node.reg_set = true;
	g_rewrite_list.push_back(std::move(node));
	return 0;
}

static int mod_rewrite_default()
{
	mlog(LV_INFO, "mod_rewrite: defaulting to built-in rule list");
	return g_rewrite_list.emplace("\\(/Microsoft-Server-ActiveSync\\)", "\\1/grommunio-sync/index.php");
}

int mod_rewrite_run(const char *sdlist) try
{
	int line_no;
	char *ptoken;
	char line[MAX_LINE];
	static constexpr size_t ebufsize = 512;
	auto errbuf = std::make_unique<char[]>(ebufsize);
	
	line_no = 0;
	auto file_ptr = fopen_sd("rewrite.txt", sdlist);
	if (file_ptr == nullptr && errno == ENOENT)
		return mod_rewrite_default();
	if (file_ptr == nullptr) {
		int se = errno;
		mlog(LV_ERR, "mod_rewrite: fopen_sd rewrite.txt: %s", strerror(errno));
		return -(errno = se);
	}
	while (fgets(line, std::size(line), file_ptr.get())) {
		line_no ++;
		if (*line == '#' || newline_size(line, 2) > 0)
			/* skip empty line or comments */
			continue;
		/* prevent line exceed maximum length ---MAX_LEN */
		line[sizeof(line) - 1] = '\0';
		HX_chomp(line);
		HX_strrtrim(line);
		HX_strltrim(line);
		ptoken = strstr(line, "=>");
		if (NULL == ptoken) {
			mlog(LV_ERR, "mod_rewrite: invalid line %d, cannot "
						"find seperator \"=>\"", line_no);
			continue;
		}
		*ptoken = '\0';
		HX_strrtrim(line);
		ptoken += 2;
		HX_strltrim(ptoken);
		if ('\\' != ptoken[0] || ptoken[1] < '0' || ptoken[1] > '9') {
			mlog(LV_ERR, "mod_rewrite: invalid line %d, cannot"
				" find replace sequence number", line_no);
			continue;
		}
		auto err = g_rewrite_list.emplace(line, ptoken);
		if (err != 0)
			return err;
	}
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

bool mod_rewrite_process(const char *uri_buff, size_t uri_len,
    std::string &f_request_uri) try
{
	char tmp_buff[http_request::uri_limit];
	
	if (uri_len >= sizeof(tmp_buff))
		return FALSE;
	for (auto &node : g_rewrite_list) {
		memcpy(tmp_buff, uri_buff, uri_len);
		tmp_buff[uri_len] = '\0';
		if (node.try_replace(tmp_buff, std::size(tmp_buff))) {
			f_request_uri = tmp_buff;
			return TRUE;
		}
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1086: ENOMEM");
	return false;
}
