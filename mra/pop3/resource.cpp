// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamically
 *
 */
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include "pop3.hpp"
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

static constexpr std::pair<unsigned int, const char *> g_default_code_table[] = {
	{1700, "+OK"},
	{1701, "-ERR timeout"},
	{1702, "-ERR line too long"},
	{1703, "-ERR command unknown"},
	{1704, "-ERR command parameter error"},
	{1705, "-ERR input username first"},
	{1706, "-ERR too many failures, user will be blocked for a while"},
	{1707, "-ERR message not found"},
	{1708, "-ERR login first"},
	{1709, "-ERR failed to open message"},
	{1710, "+OK quit <host>"},
	{1711, "+OK <host> pop service ready"},
	{1712, "-ERR access denied by ipaddr filter for <ip>"},
	{1713, "-ERR <host> pop service unavailable"},
	{1714, "-ERR Wrong username or password, or administratively blocked"},
	{1715, "-ERR cannot get mailbox location from database"},
	{1716, "-ERR failed to open/read inbox index"},
	{1717, "-ERR access denied by user filter for <user>"},
	{1718, "-ERR error internal"},
	{1719, "-ERR fail to retrieve message"},
	{1720, "-ERR cannot relogin under login stat"},
	{1721, "-ERR midb read/write error"},
	{1722, "-ERR fail to execute command in midb"},
	{1723, "-ERR failed to initialize TLS"},
	{1724, "+OK begin TLS negotiation"},
	{1725, "-ERR TLS negotiation only begin in AUTHORIZATION state"},
	{1726, "-ERR must issue a STLS command first"},
	{1727, "-ERR Unspecified error received from midb_agent"},
};

static std::unordered_map<unsigned int, std::string> g_def_code_table;

int resource_run()
{
	for (size_t i = 0; i < arsizeof(g_default_code_table); ++i)
		g_def_code_table.emplace(g_default_code_table[i].first,
			resource_parse_stcode_line(g_default_code_table[i].second));
    return 0;
}

void resource_stop()
{
	g_def_code_table.clear();
}

const char *resource_get_pop3_code(unsigned int code_type, unsigned int n, size_t *len)
{
#define FIRST_PART      1
#define SECOND_PART     2
	auto it = g_def_code_table.find(code_type);
	if (it == g_def_code_table.end())
		return "OMG";
	int ret_len = it->second[0];
	auto ret_ptr = &it->second[1];
    if (FIRST_PART == n)    {
        *len = ret_len - 1;
        return ret_ptr;
    }
    if (SECOND_PART == n)   {
        ret_ptr = ret_ptr + ret_len + 1;
		ret_len = it->second[ret_len+1];
        if (ret_len > 0) {
            *len = ret_len - 1;
            return ret_ptr;
        }
    }
	debug_info("[resource]: rcode does not exist (resource_get_pop3_code)");
    return NULL;
}
