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
#include "http_parser.h"
#include "mod_rewrite.h"
#define MAX_LINE					16*1024

using namespace gromox;

namespace {
struct REWRITE_NODE {
	REWRITE_NODE() = default;
	REWRITE_NODE(REWRITE_NODE &&) noexcept;
	~REWRITE_NODE();
	void operator=(REWRITE_NODE &&) = delete;
	regex_t search_pattern{};
	std::string replace_string;
	bool reg_set = false;
};
}

static std::vector<REWRITE_NODE> g_rewrite_list;

REWRITE_NODE::REWRITE_NODE(REWRITE_NODE &&o) noexcept :
    replace_string(std::move(o.replace_string))
{
	if (reg_set)
		regfree(&search_pattern);
	memcpy(&search_pattern, &o.search_pattern, sizeof(search_pattern));
	reg_set = o.reg_set;
	o.reg_set = false;
}

REWRITE_NODE::~REWRITE_NODE()
{
	if (reg_set)
		regfree(&search_pattern);
}

static BOOL mod_rewrite_rreplace(char *buf,
	int size, regex_t *re, const char *rp)
{
	char *pos;
	int last_pos;
	int i, len, offset;
	int rp_offsets[10];
	regmatch_t pmatch[10]; /* regoff_t is int so size is int */
	char original_rp[8192];
	char original_buf[8192];

	if (0 != regexec(re, buf, 10, pmatch, 0)) {
		return FALSE;
	}
	if ('\\' == rp[0] && '0' == rp[1]) {
		gx_strlcpy(buf, rp + 2, size);
		return TRUE;
	}
	gx_strlcpy(original_buf, buf, std::size(original_buf));
	gx_strlcpy(original_rp, rp, std::size(original_rp));
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

static int mod_rewrite_default()
{
	REWRITE_NODE node;
	static constexpr size_t ebufsize = 512;
	auto errbuf = std::make_unique<char[]>(ebufsize);

	mlog(LV_NOTICE, "mod_rewrite: defaulting to built-in rule list");
	if (g_http_php) {
	node.replace_string = "\\0/EWS/exchange.php";
	auto ret = regcomp(&node.search_pattern, "/EWS/Exchange.asmx", REG_ICASE);
	if (ret != 0) {
		regerror(ret, &node.search_pattern, errbuf.get(), ebufsize);
		mlog(LV_ERR, "mod_rewrite: regcomp: %s", errbuf.get());
		return -EINVAL;
	}
	node.reg_set = true;
	g_rewrite_list.push_back(std::move(node));
	}

	node.replace_string = "\\1/grommunio-sync/index.php";
	auto ret = regcomp(&node.search_pattern, "\\(/Microsoft-Server-ActiveSync\\)", REG_ICASE);
	if (ret != 0) {
		regerror(ret, &node.search_pattern, errbuf.get(), ebufsize);
		mlog(LV_ERR, "mod_rewrite: regcomp: %s", errbuf.get());
		return -EINVAL;
	}
	node.reg_set = true;
	g_rewrite_list.push_back(std::move(node));

	return 0;
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
		REWRITE_NODE node;
		node.replace_string = ptoken;
		auto ret = regcomp(&node.search_pattern, line, REG_ICASE);
		if (ret != 0) {
			regerror(ret, &node.search_pattern, errbuf.get(), ebufsize);
			mlog(LV_ERR, "mod_rewrite: line %d: %s", line_no, errbuf.get());
			return -EINVAL;
		}
		node.reg_set = true;
		g_rewrite_list.push_back(std::move(node));
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
		if (mod_rewrite_rreplace(tmp_buff, sizeof(tmp_buff),
		    &node.search_pattern, node.replace_string.c_str())) {
			f_request_uri = tmp_buff;
			return TRUE;
		}
	}
	return FALSE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1086: ENOMEM");
	return false;
}
