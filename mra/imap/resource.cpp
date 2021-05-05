// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <algorithm>
#include <cerrno>
#include <list>
#include <string>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "resource.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

namespace {

struct LANG_FOLDER {
	char lang[32];
	char *folders[4];
	char charset[256];
	char draft[256];
	char sent[256];
	char trash[256];
	char junk[256];

	bool operator==(const char *s) const { return strcasecmp(lang, s) == 0; }
};

}

static constexpr std::pair<unsigned int, const char *> g_default_code_table[] = {
	{1601, "BYE logging out"},
	{1602, "+ idling"},
	{1603, "+ ready for additional command text"},
	{1604, "BYE disconnected by autologout"},
	{1700, "OK <domain> service ready"},
	{1701, "OK CAPABILITY completed"},
	{1702, "OK NOOP completed"},
	{1703, "OK LOGOUT completed"},
	{1704, "OK begin TLS negotiation now"},
	{1705, "OK logged in"},
	{1706, "OK CREATED completed"},
	{1707, "OK DELETE completed"},
	{1708, "OK RENAME completed"},
	{1709, "OK SUBSCRIBE completed"},
	{1710, "OK UNSUBSCRIBE completed"},
	{1711, "OK LIST completed"},
	{1712, "OK XLIST completed"},
	{1713, "OK LSUB completed"},
	{1714, "OK STATUS completed"},
	{1715, "OK <APPENDUID> APPEND completed"},
	{1716, "OK CHECK completed"},
	{1717, "OK CLOSE completed"},
	{1718, "OK UNSELECT completed"},
	{1719, "OK SEARCH completed"},
	{1720, "OK FETCH completed"},
	{1721, "OK STORE completed"},
	{1722, "OK <COPYUID> COPY completed"},
	{1723, "OK UID SEARCH completed"},
	{1724, "OK UID STORE completed"},
	{1725, "OK <COPYUID> UID COPY completed"},
	{1726, "OK EXPUNGE completed"},
	{1727, "OK IDLE completed"},
	{1728, "OK UID FETCH completed"},
	{1729, "OK ID completed"},
	{1730, "OK UID EXPUNGE completed"},
	{1800, "BAD command not supported or parameter error"},
	{1801, "BAD TLS negotiation only begin in not authenticated state"},
	{1802, "BAD must issue a STARTTLS command first"},
	{1803, "BAD cannot relogin in authenticated state"},
	{1804, "BAD cannot process in not authenticated state"},
	{1805, "BAD can only process in select state"},
	{1806, "BAD can not store with read-only status"},
	{1807, "BAD one or more flags not supported"},
	{1808, "BAD internal error, fail to retrieve from stream object"},
	{1809, "BAD internal error, fail to get stream buffer"},
	{1810, "BAD internal error, fail to dump stream object"},
	{1811, "BAD time out"},
	{1812, "BAD internal error, fail to read file"},
	{1813, "BAD search parameter syntax error"},
	{1814, "BAD internal error, failed to init SSL object"},
	{1815, "BAD <host> service not available"},
	{1816, "BAD access is denied from your IP address <remote_ip>"},
	{1817, "BAD literal size too large"},
	{1818, "BAD expected DONE"},
	{1819, "BAD decode username error"},
	{1820, "BAD decode password error"},
	{1901, "NO access denied by user filter"},
	{1902, "NO cannot get mailbox location from database"},
	{1903, "NO too many failures, user will be blocked for a while"},
	{1904, "NO login auth fail, <reason>"},
	{1905, "NO server internal error, missing MIDB connection"},
	{1906, "NO server internal error, fail to communicate with MIDB"},
	{1907, "NO server internal error, <reason>"},
	{1908, "NO cannot parse message, format error"},
	{1909, "NO fail to save message"},
	{1910, "NO folder name format error"},
	{1911, "NO CREATE can not create reserved folder name"},
	{1912, "NO DELETE can not delete subfolder"},
	{1913, "NO DELETE can not delete reserved folder name"},
	{1914, "NO RENAME can not rename reserved folder name"},
	{1915, "NO server internal error: out of memery"},
	{1916, "NO COPY failed"},
	{1917, "NO UID COPY failed"},
	{2000, "midb command not found"},
	{2001, "midb command parameter error"},
	{2002, "midb hash table full"},
	{2003, "midb fail to read and load folder"},
	{2004, "midb out of memory"},
	{2005, "mail not found"},
	{2006, "mail digest error"},
	{2007, "folder already exist"},
	{2008, "reach the limitation of folders"},
	{2009, "mailbox is full"},
	{2010, "midb fail to delete the folder"},
};

static std::unordered_map<unsigned int, std::string> g_def_code_table;
static std::list<LANG_FOLDER> g_lang_list;

static BOOL resource_load_imap_lang_list();

int resource_run()
{
	if (FALSE == resource_load_imap_lang_list()) {
		printf("[resource]: Failed to load IMAP languages\n");
		return -3;
	}
	for (size_t i = 0; i < GX_ARRAY_SIZE(g_default_code_table); ++i) {
		g_def_code_table.emplace(g_default_code_table[i].first,
			resource_parse_stcode_line(g_default_code_table[i].second));
    }
    
    return 0;
}

int resource_stop()
{
        g_def_code_table.clear();
    return 0;
}

const char *resource_get_imap_code(unsigned int code_type, unsigned int n, size_t *len)
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
	debug_info("[resource]: rcode does not exist (resource_get_imap_code)");
	*len = 15;
	return "unknown error\r\n";
}

static int resource_construct_lang_list(std::list<LANG_FOLDER> &plist)
{
	char *ptr;
	size_t temp_len;
	char temp_buff[256];
	char line[MAX_FILE_LINE_LEN];
	
	const char *filename = resource_get_string("IMAP_LANG_PATH");
	if (NULL == filename) {
		filename = "imap_lang.txt";
	}
	auto file_ptr = fopen_sd(filename, resource_get_string("data_file_path"));
	if (file_ptr == nullptr) {
		printf("[resource]: fopen_sd %s: %s\n", filename, strerror(errno));
        return -1;
    }

	std::list<LANG_FOLDER> temp_list;
	for (int total = 0; fgets(line, MAX_FILE_LINE_LEN, file_ptr.get()); ++total) try {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
		   /* skip empty line or comments */
		   continue;
		}

		ptr = strchr(line, ':');
		if (NULL == ptr) {
			printf("[resource]: line %d format error in %s\n", total + 1,
                filename);
			return -1;
		}
		
		*ptr = '\0';
		LANG_FOLDER lf, *plang = &lf;
		gx_strlcpy(plang->lang, line, GX_ARRAY_SIZE(plang->lang));
		HX_strrtrim(plang->lang);
		HX_strltrim(plang->lang);
		plang->folders[0] = plang->draft;
		plang->folders[1] = plang->sent;
		plang->folders[2] = plang->trash;
		plang->folders[3] = plang->junk;
		if (0 == strlen(plang->lang) ||
			FALSE == get_digest(ptr + 1, "default-charset",
			plang->charset, 256) || 0 == strlen(plang->charset) ||
			FALSE == get_digest(ptr + 1, "draft", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->draft, &temp_len) ||
			FALSE == get_digest(ptr + 1, "sent", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->sent, &temp_len) ||
			FALSE == get_digest(ptr + 1, "trash", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->trash, &temp_len) ||
			FALSE == get_digest(ptr + 1, "junk", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->junk, &temp_len)) {
			printf("[resource]: line %d format error in %s\n", total + 1, filename);
			return -1;
		}
		temp_list.push_back(std::move(lf));
	} catch (const std::bad_alloc &) {
		printf("[resource]: out of memory while loading file %s\n", filename);
		return -1;
	}

	const char *dfl_lang = resource_get_string("DEFAULT_LANG");
	if (dfl_lang == NULL) {
		dfl_lang = "en";
		resource_set_string("DEFAULT_LANG", dfl_lang);
	}
	auto it = std::find(temp_list.cbegin(), temp_list.cend(), dfl_lang);
	if (it == temp_list.cend()) {
		printf("[resource]: cannot find default lang (%s) in %s\n", dfl_lang, filename);
		return -1;
	}
	if (temp_list.size() > 127) {
		printf("[resource]: too many langs in %s\n", filename);
		return -1;
	}
	plist = std::move(temp_list);
	return 0;
}

static BOOL resource_load_imap_lang_list()
{
	return resource_construct_lang_list(g_lang_list) == 0 ? TRUE : false;
}

const char* resource_get_default_charset(const char *lang)
{
	auto i = std::find(g_lang_list.cbegin(), g_lang_list.cend(), lang);
	if (i != g_lang_list.cend())
		return i->charset;
	i = std::find(g_lang_list.cbegin(), g_lang_list.cend(),
	    resource_get_string("DEFAULT_LANG"));
	return i != g_lang_list.cend() ? i->charset : nullptr;
}

const char *const *resource_get_folder_strings(const char *lang)
{
	auto i = std::find(g_lang_list.cbegin(), g_lang_list.cend(), lang);
	if (i != g_lang_list.cend())
		return i->folders;
	i = std::find(g_lang_list.cbegin(), g_lang_list.cend(),
	    resource_get_string("DEFAULT_LANG"));
	return i != g_lang_list.cend() ? i->folders : nullptr;
}

const char *resource_get_error_string(unsigned int code)
{
	size_t temp_len = 0;
	return resource_get_imap_code(2000 + code, 1, &temp_len);
}
