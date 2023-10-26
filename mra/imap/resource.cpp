// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamically
 *
 */
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <string>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/midb.hpp>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include "imap.hpp"
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

namespace {

struct LANG_FOLDER {
	char lang[32]{};
	char charset[256]{};
	bool operator==(const char *s) const { return strcasecmp(lang, s) == 0; }
};

}

static constexpr std::pair<unsigned int, const char *> g_default_code_table[] = {
	{1601, "BYE logging out"},
	{1602, "+ idling"},
	{1603, "+ ready for additional command text"},
	{1604, "BYE disconnected by autologout"},
	{1700, "OK Service ready"},
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
	{1811, "BAD timeout"},
	{1812, "BAD internal error, fail to read file"},
	{1813, "BAD search parameter syntax error"},
	{1814, "BAD internal error, failed to init SSL object"},
	{1815, "BAD Service not available"},
	{1816, "BAD access is denied from your IP address <remote_ip>"},
	{1817, "BAD command too long or unacceptable size for literal"},
	{1818, "BAD expected DONE"},
	{1819, "BAD decode username error"},
	{1820, "BAD decode password error"},
	{1901, "NO access denied by user filter"},
	{1902, "NO cannot get mailbox location from database"},
	{1903, "NO too many failures, user will be blocked for a while"},
	{1904, "NO Wrong username or password, or administratively blocked"},
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
	{1915, "NO server internal error: out of memory"},
	{1916, "NO COPY failed"},
	{1917, "NO UID COPY failed"},
	{1918, "NO Memory allocation failure"},
	{1919, "NO Unspecified error received from midb_agent"},
	{1920, "NO midb_agent: out of memory"},
	{1921, "NO Too many messages in folder / midb returned too many results / IMAP buffer not big enough"},
	{1922, "NO Too many messages in result"},
	{1923, "NO Unable to read message file"},
	{2000 | MIDB_E_UNKNOWN_COMMAND, "midb: unknown command"},
	{2000 | MIDB_E_PARAMETER_ERROR, "midb: command parameter error"},
	{2000 | MIDB_E_HASHTABLE_FULL, "Unable to read midb.sqlite, see midb logs"},
	{2000 | MIDB_E_NO_FOLDER, "midb: folder does not exist/failed to read folder"},
	{2000 | MIDB_E_NO_MEMORY, "midb: out of memory"},
	{2000 | MIDB_E_NO_MESSAGE, "mail not found"},
	{2000 | MIDB_E_DIGEST, "mail digest error"},
	{2000 | MIDB_E_FOLDER_EXISTS, "folder already exists"},
	{2000 | MIDB_E_FOLDER_LIMIT, "reached the limitation of folders"},
	{2000 | MIDB_E_MAILBOX_FULL, "mailbox is full (either bytes or messages)"},
	{2000 | MIDB_E_NO_DELETE, "midb: failed to delete the folder"},
	{2000 | MIDB_E_STORE_NOT_LOADED, "midb: store not loaded"},
	{2000 | MIDB_E_STORE_BUSY, "midb: store is being used"},
	{2000 | MIDB_E_NETIO, "midb: incomplete read/write; network interrupt"},
	{2000 | MIDB_E_CREATEFOLDER, "midb: cu_create_folder failed"},
	{2000 | MIDB_E_DISK_ERROR, "midb: error during disk I/O"},
	{2000 | MIDB_E_IMAIL_DIGEST, "midb: MAIL::get_digest failed"},
	{2000 | MIDB_E_IMAIL_RETRIEVE, "midb: MAIL::retrieve failed"},
	{2000 | MIDB_E_MDB_ALLOCID, "exmdb: allocate_eid/allocate_cn RPC failed"},
	{2000 | MIDB_E_MDB_DELETEFOLDER, "exmdb: empty_folder/delete_folder RPC failed"},
	{2000 | MIDB_E_MDB_DELETEMESSAGES, "exmdb: delete_messages RPC failed"},
	{2000 | MIDB_E_MDB_GETFOLDERPROPS, "exmdb: get_folder_props RPC failed"},
	{2000 | MIDB_E_MDB_GETMSGPROPS, "exmdb: get_msg_props RPC failed"},
	{2000 | MIDB_E_MDB_GETSTOREPROPS, "exmdb: get_store_props RPC failed"},
	{2000 | MIDB_E_MDB_MOVECOPY, "exmdb: move_copy RPC failed"},
	{2000 | MIDB_E_MDB_PARTIAL, "exmdb: RPC completed with partial result"},
	{2000 | MIDB_E_MDB_SETFOLDERPROPS, "exmdb: set_folder_props RPC failed"},
	{2000 | MIDB_E_MDB_SETMSGPROPS, "exmdb: set_msg_props RPC failed"},
	{2000 | MIDB_E_MDB_WRITEMESSAGE, "exmdb: write_message RPC failed"},
	{2000 | MIDB_E_MNG_CTMATCH, "midb: ct_match failed"},
	{2000 | MIDB_E_MNG_SORTFOLDER, "midb: sort_folder failed"},
	{2000 | MIDB_E_OXCMAIL_IMPORT, "oxcmail_import failed"},
	{2000 | MIDB_E_SHORT_READ, "midb: short read on a file"},
	{2000 | MIDB_E_SQLPREP, "sqlite3_prepare failed"},
	{2000 | MIDB_E_SQLUNEXP, "Unexpected return code from lastrow sqlite3_step"},
	{2000 | MIDB_E_SSGETID, "User unresolvable"},
};

static std::unordered_map<unsigned int, std::string> g_def_code_table;
static constexpr LANG_FOLDER g_lang_list[] =
	{{"en", "us-ascii"}, {"zh_TW", "gbk"}, {"zh_CN", "big5"}, {"ja", "iso-2022-jp"}};

int resource_run()
{
	const char *dfl_lang = g_config_file->get_value("default_lang");
	if (dfl_lang == nullptr) {
		dfl_lang = "en";
		g_config_file->set_value("default_lang", dfl_lang);
	}
	auto it = std::find(std::begin(g_lang_list), std::end(g_lang_list), dfl_lang);
	if (it == std::end(g_lang_list)) {
		mlog(LV_ERR, "resource: cannot find default lang (%s) in <built-in list>\n", dfl_lang);
		return -1;
	}
	for (size_t i = 0; i < std::size(g_default_code_table); ++i) {
		g_def_code_table.emplace(g_default_code_table[i].first,
			resource_parse_stcode_line(g_default_code_table[i].second));
    }
    
    return 0;
}

void resource_stop()
{
        g_def_code_table.clear();
}

const char *resource_get_imap_code(unsigned int code_type, unsigned int n, size_t *len)
{
#define FIRST_PART      1
#define SECOND_PART     2
	thread_local char reason[40];
	auto it = g_def_code_table.find(code_type);
	if (it == g_def_code_table.end()) {
		*len = snprintf(reason, std::size(reason), "Unknown IMAPCODE %u\r\n", code_type);
		return reason;
	}
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
	mlog(LV_DEBUG, "resource: rcode does not exist (resource_get_imap_code)");
	*len = 15;
	return "unknown error\r\n";
}

const char* resource_get_default_charset(const char *lang)
{
	auto i = std::find(std::begin(g_lang_list), std::end(g_lang_list), lang);
	if (i != std::end(g_lang_list))
		return i->charset;
	i = std::find(std::begin(g_lang_list), std::end(g_lang_list),
	    g_config_file->get_value("default_lang"));
	return i != std::end(g_lang_list) ? i->charset : nullptr;
}

const char *resource_get_error_string(unsigned int code)
{
	size_t temp_len = 0;
	return resource_get_imap_code(2000 + code, 1, &temp_len);
}
