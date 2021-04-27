// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <cerrno>
#include <string>
#include <unordered_map>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "resource.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

static constexpr std::pair<unsigned int, const char *> g_default_code_table[] = {
    { 2170000, "+OK" },
    { 2170001, "-ERR time out" },
    { 2170002, "-ERR line too long" },
	{2170003, "-ERR command unknown"},
    { 2170004, "-ERR command parameter error" },
    { 2170005, "-ERR input username first" },
	{2170006, "-ERR too many failures, user will be blocked for a while"},
    { 2170007, "-ERR message not found" },
    { 2170008, "-ERR login first" },
	{2170009, "-ERR failed to open message"},
    { 2170010, "+OK quit <host>" },
    { 2170011, "+OK <host> pop service ready" },
	{2170012, "-ERR access denied by ipaddr filter for <ip>"},
    { 2170013, "-ERR <host> pop service unavailable" },
    { 2170014, "-ERR login auth fail, because: <reason>" },
    { 2170015, "-ERR cannot get mailbox location from database" },
	{2170016, "-ERR failed to open/read inbox index"},
	{2170017, "-ERR access denied by user filter for <user>"},
    { 2170018, "-ERR error internal" },
    { 2170019, "-ERR fail to retrieve message" },
    { 2170020, "-ERR cannot relogin under login stat" },
	{ 2170021, "-ERR midb read/write error" },
	{2170022, "-ERR fail to execute command in midb"},
	{ 2170023, "-ERR failed to initialize TLS"},
	{ 2170024, "+OK begin TLS negotiation"},
	{ 2170025, "-ERR TLS negotiation only begin in AUTHORIZATION state"},
	{ 2170026,  "-ERR must issue a STLS command first"}
};

static std::unordered_map<unsigned int, std::string> g_def_code_table;

int resource_run()
{
	for (size_t i = 0; i < GX_ARRAY_SIZE(g_default_code_table); ++i)
		g_def_code_table.emplace(g_default_code_table[i].first,
			resource_parse_stcode_line(g_default_code_table[i].second));
    return 0;
}

int resource_stop()
{
	g_def_code_table.clear();
    return 0;
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
