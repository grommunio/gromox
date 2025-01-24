// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
/* 
 * collection of functions for handling the imap command
 */ 
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/io.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/midb.hpp>
#include <gromox/midb_agent.hpp>
#include <gromox/mjson.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/range_set.hpp>
#include <gromox/scope.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>
#include "imap.hpp"
#define MAX_DIGLEN		256*1024

/*
 *
 * The inbox name, "INBOX", is specified as case-insensitive, but most code in
 * here does not handle folder names like "inbox/foo/bar", i.e. subordinates of
 * inbox where inbox is not exactly spelled "INBOX". Blech.
 *
 */

using namespace std::string_literals;
using namespace gromox;
namespace exmdb_client = exmdb_client_remote;
using LLU = unsigned long long;
using mdi_list = std::vector<std::string>; /* message data item (RFC 3501 §6.4.5) */

namespace {

struct dir_tree {
	dir_tree() = default;
	~dir_tree();
	NOMOVE(dir_tree);

	void load_from_memfile(const std::vector<enum_folder_t> &);
	DIR_NODE *match(const char *path);
	static DIR_NODE *get_child(DIR_NODE *);

	SIMPLE_TREE stree{};
};
using DIR_TREE = dir_tree;
using DIR_TREE_ENUM = void (*)(DIR_NODE *, void*);

enum {
	TYPE_WILDS = 1,
	TYPE_WILDP
};

struct builtin_folder {
	uint64_t fid;
	const char *use_flags;
};

}

/* RFC 6154 does not document \Inbox, but Thunderbird evaluates it. */
/* RFC 6154 says \Junk, but Thunderbird evaluates \Spam */
static constexpr const builtin_folder g_folder_list[] = {
	{PRIVATE_FID_INBOX, "\\Inbox"},
	{PRIVATE_FID_DRAFT, "\\Drafts"},
	{PRIVATE_FID_SENT_ITEMS, "\\Sent"},
	{PRIVATE_FID_DELETED_ITEMS, "\\Trash"},
	{PRIVATE_FID_JUNK, "\\Junk \\Spam"},
};

void dir_tree::load_from_memfile(const std::vector<enum_folder_t> &pfile) try
{
	auto ptree = this;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];
	SIMPLE_TREE_NODE *pnode, *pnode_parent;

	auto proot = ptree->stree.get_root();
	if (NULL == proot) {
		auto pdir = std::make_unique<DIR_NODE>();
		pdir->stree.pdata = pdir.get();
		pdir->name[0] = '\0';
		pdir->b_loaded = TRUE;
		proot = &pdir->stree;
		ptree->stree.set_root(std::move(pdir));
	}

	for (const auto &pfile_path : pfile) {
		gx_strlcpy(temp_path, pfile_path.second.c_str(), std::size(temp_path));
		auto len = strlen(temp_path);
		pnode = proot;
		if (len == 0 || temp_path[len-1] != '/') {
			temp_path[len++] = '/';
			temp_path[len] = '\0';
		}
		ptr1 = temp_path;
		while ((ptr2 = strchr(ptr1, '/')) != NULL) {
			*ptr2 = '\0';
			pnode_parent = pnode;
			pnode = pnode->get_child();
			if (NULL != pnode) {
				do {
					auto pdir = static_cast<DIR_NODE *>(pnode->pdata);
					if (strcasecmp(pdir->name, ptr1) == 0)
						break;
				} while ((pnode = pnode->get_sibling()) != nullptr);
			}

			if (NULL == pnode) {
				auto pdir = std::make_unique<DIR_NODE>();
				pdir->stree.pdata = pdir.get();
				gx_strlcpy(pdir->name, ptr1, std::size(pdir->name));
				pdir->b_loaded = FALSE;
				pnode = &pdir->stree;
				ptree->stree.add_child(pnode_parent,
					std::move(pdir), SIMPLE_TREE_ADD_LAST);
			}
			ptr1 = ptr2 + 1;
		}
		static_cast<DIR_NODE *>(pnode->pdata)->b_loaded = TRUE;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2903: ENOMEM");
}

static void dir_tree_clear(DIR_TREE *ptree)
{
	auto pnode = ptree->stree.get_root();
	if (pnode != nullptr)
		ptree->stree.destroy_node(pnode, [](tree_node *p) { delete static_cast<DIR_NODE *>(p->pdata); });
}

DIR_NODE *dir_tree::match(const char *path)
{
	auto ptree = this;
	int len;
	DIR_NODE *pdir = nullptr;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];

	auto pnode = ptree->stree.get_root();
	if (pnode == nullptr)
		return NULL;
	if (*path == '\0')
		return static_cast<DIR_NODE *>(pnode->pdata);
	len = strlen(path);
	if (len >= 4096)
		return NULL;
	memcpy(temp_path, path, len);
	if (temp_path[len-1] != '/')
		temp_path[len++] = '/';
	temp_path[len] = '\0';
	
	ptr1 = temp_path;
	for (unsigned int level = 0; (ptr2 = strchr(ptr1, '/')) != nullptr; ++level) {
		*ptr2 = '\0';
		pnode = pnode->get_child();
		if (pnode == nullptr)
			return NULL;
		do {
			pdir = static_cast<DIR_NODE *>(pnode->pdata);
			if (strcasecmp(pdir->name, ptr1) == 0)
				break;
			if (level == 0 && strcasecmp(pdir->name, "INBOX") == 0 &&
			    strcasecmp(ptr1, "inbox") == 0)
				break;
		} while ((pnode = pnode->get_sibling()) != nullptr);
		if (pnode == nullptr)
			return NULL;
		ptr1 = ptr2 + 1;
	}
	return pdir;
}

DIR_NODE *dir_tree::get_child(DIR_NODE* pdir)
{
	auto pnode = pdir->stree.get_child();
	return pnode != nullptr ? static_cast<DIR_NODE *>(pnode->pdata) : nullptr;
}

dir_tree::~dir_tree()
{
	auto ptree = this;
	dir_tree_clear(ptree);
	ptree->stree.clear();
}

static const builtin_folder *special_folder(uint64_t fid)
{
	for (const auto &s : g_folder_list)
		if (fid == s.fid)
			return &s;
	return nullptr;
}

/**
 * @list:    rangeset to inspect
 * @num:     number to test for
 * @max_uid: meaning of the star when found in @list
 */
static bool iseq_contains(const imap_seq_list &list,
	unsigned int num, unsigned int max_uid)
{
	auto i = std::lower_bound(list.cbegin(), list.cend(), num,
	         [](const range_node<uint32_t> &rn, uint32_t vv) { return rn.hi < vv; });
	if (i == list.cend())
		return false;
	return i->lo <= num && num <= i->hi && num <= max_uid;
}

static std::string quote_encode(const char *u7)
{
	std::unique_ptr<char[], stdlib_delete> q(HX_strquote(u7, HXQUOTE_DQUOTE, nullptr));
	return "\""s + q.get() + "\"";
}

static std::string quote_encode(const std::string &u7)
{
	return quote_encode(u7.c_str());
}

static BOOL icp_parse_fetch_args(mdi_list &plist,
    BOOL *pb_detail, BOOL *pb_data, char *string, char **argv, int argc) try
{
	int tmp_argc;
	if ('(' == string[0]) {
		if (string[strlen(string)-1] != ')')
			return FALSE;
		tmp_argc = parse_imap_args(string + 1,
			strlen(string) - 2, argv, argc);
	} else {
		tmp_argc = parse_imap_args(string, strlen(string), argv, argc);
	}
	if (tmp_argc < 1)
		return FALSE;

	bool b_macro = false;
	plist.emplace_back("UID");
	for (int i = 0; i < tmp_argc; ++i) {
		if (std::any_of(plist.cbegin(), plist.cend(),
		    [&](const std::string &e) { return strcasecmp(e.c_str(), argv[i]) == 0; }))
			/* weed out duplicates */
			continue;
		if (0 == strcasecmp(argv[i], "ALL") ||
			0 == strcasecmp(argv[i], "FAST") ||
			0 == strcasecmp(argv[i], "FULL")) {
			b_macro = TRUE;
			plist.emplace_back(argv[i]);
		} else if (0 == strcasecmp(argv[i], "BODY") ||
			0 == strcasecmp(argv[i], "BODYSTRUCTURE") ||
			0 == strcasecmp(argv[i], "ENVELOPE") ||
			0 == strcasecmp(argv[i], "FLAGS") ||
			0 == strcasecmp(argv[i], "INTERNALDATE") ||
			0 == strcasecmp(argv[i], "RFC822") ||
			0 == strcasecmp(argv[i], "RFC822.HEADER") ||
			0 == strcasecmp(argv[i], "RFC822.SIZE") ||
			0 == strcasecmp(argv[i], "RFC822.TEXT") ||
			0 == strcasecmp(argv[i], "UID")) {
			plist.emplace_back(argv[i]);
		} else if (0 == strncasecmp(argv[i], "BODY[", 5) ||
			0 == strncasecmp(argv[i], "BODY.PEEK[", 10)) {
			const char *pend = strchr(argv[i], ']');
			if (pend == nullptr)
				return FALSE;
			const char *ptr = strchr(argv[i], '[') + 1;
			const char *last_ptr = ptr;
			if (strncasecmp(ptr, "MIME", 4) == 0)
				return FALSE;
			while (']' != *ptr) {
				if ('.' == *ptr) {
					size_t len = ptr - last_ptr, j = 0;
					if (len == 0)
						return FALSE;
					for (j = 0; j < len; ++j)
						if (!HX_isdigit(last_ptr[j]))
							break;
					if (j < len)
						break;
					last_ptr = ptr + 1;
				}
				ptr ++;
			}
			
			size_t len = pend - last_ptr;
			if ((len == 0 && *last_ptr == '.') || len >= 1024)
				return FALSE;
			char buff[1024], temp_buff[1024], *tmp_argv1[128];
			memcpy(buff, last_ptr, len);
			buff[len] = '\0';
			if (0 != len &&
				0 != strcasecmp(buff, "HEADER") &&
				0 != strcasecmp(buff, "TEXT") &&
				0 != strcasecmp(buff, "MIME") &&
				0 != strncasecmp(buff, "HEADER.FIELDS ", 14) &&
				0 != strncasecmp(buff, "HEADER.FIELDS.NOT ", 18)) {
				for (size_t j = 0; j < len; ++j)
					if (!HX_isdigit(buff[j]))
						return FALSE;
			} else if (0 == strncasecmp(buff, "HEADER.FIELDS ", 14)) {
				memcpy(temp_buff, buff + 14, strlen(buff) - 14);
				int result;
				if ('(' == buff[14]) {
					if (buff[strlen(buff)-1] != ')')
						return FALSE;
					result = parse_imap_args(temp_buff + 1, strlen(buff) - 16,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				} else {
					result = parse_imap_args(temp_buff, strlen(buff) - 14,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				}
				if (result < 1)
					return FALSE;
			} else if (0 == strncasecmp(buff, "HEADER.FIELDS.NOT ", 18)) {
				memcpy(temp_buff, buff + 18, strlen(buff) - 18);
				int result;
				if ('(' == buff[18]) {
					if (buff[strlen(buff)-1] != ')')
						return FALSE;
					result = parse_imap_args(temp_buff + 1, strlen(buff) - 20,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				} else {
					result = parse_imap_args(temp_buff, strlen(buff) - 18,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				}
				if (result < 1)
					return FALSE;
			}
			ptr = pend + 1;
			const char *ptr1 = nullptr;
			if ('\0' != *ptr) {
				pend = strchr(ptr + 1, '>');
				if (*ptr != '<' || pend == nullptr || pend[1] != '\0')
					return FALSE;
				ptr ++;
				size_t count = 0;
				last_ptr = ptr;
				while ('>' != *ptr) {
					if (HX_isdigit(*ptr)) {
						/* do nothing */
					} else if ('.' == *ptr) {
						ptr1 = ptr;
						count ++;
					} else {
						return FALSE;
					}
					ptr ++;
				}
				if (count > 1)
					return FALSE;
				if ((count == 1 && ptr1 == last_ptr) || ptr1 == pend - 1)
					return FALSE;
			}
			plist.emplace_back(argv[i]);
		} else {
			return FALSE;
		}
	}
	if (tmp_argc > 1 && b_macro)
		return FALSE;
	/* full load the mail digests from MIDB */
	*pb_detail = FALSE;
	/* stream object contain file information */
	*pb_data = FALSE;
	for (size_t i = 0; i < plist.size(); ++i) {
		auto kw = plist[i].c_str();
		if (strcasecmp(kw, "ALL") == 0 || strcasecmp(kw, "FAST") == 0 ||
		    strcasecmp(kw, "FULL") == 0) {
			plist.emplace_back("INTERNALDATE");
			plist.emplace_back("RFC822.SIZE");
			if (strcasecmp(kw, "ALL") == 0 || strcasecmp(kw, "FULL") == 0) {
				plist.emplace_back("ENVELOPE");
				if (strcasecmp(kw, "FULL") == 0)
					plist.emplace_back("BODY");
			}
			*pb_detail = TRUE;
			kw = "FLAGS";
		} else if (strcasecmp(kw, "RFC822") == 0 ||
		    strcasecmp(kw, "RFC822.HEADER") == 0 ||
		    strcasecmp(kw, "RFC822.TEXT") == 0) {
			*pb_data = TRUE;
			*pb_detail = TRUE;
		} else if (strcasecmp(kw, "BODY") == 0 ||
		    strcasecmp(kw, "BODYSTRUCTURE") == 0 ||
		    strcasecmp(kw, "ENVELOPE") == 0 ||
		    strcasecmp(kw, "INTERNALDATE") == 0 ||
		    strcasecmp(kw, "RFC822.SIZE") == 0) {
			*pb_detail = TRUE;
		} else if (strncasecmp(kw, "BODY[", 5) == 0 ||
		    strncasecmp(kw, "BODY.PEEK[", 10) == 0) {
			if (strcasestr(kw, "FIELDS") == nullptr)
				*pb_data = TRUE;
			*pb_detail = TRUE;
		}
	}
	/* move to front (UID goes in front of plist) */
	for (const auto kw : {"RFC822.TEXT", "RFC822.HEADER", "ENVELOPE", "RFC822.SIZE", "INTERNALDATE", "FLAGS", "UID"})
		std::stable_partition(plist.begin(), plist.end(),
			[kw](const std::string &e) { return strcasecmp(e.c_str(), kw) == 0; });
	/* move to back */
	for (const auto kw : {"BODY", "BODYSTRUCTURE", "RFC822"})
		std::stable_partition(plist.begin(), plist.end(),
			[kw](const std::string &e) { return strcasecmp(e.c_str(), kw) != 0; });
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2131: ENOMEM");
	return false;
}

static void icp_convert_flags_string(int flag_bits, char *flags_string)
{
	flags_string[0] = '(';
	bool b_first = false;
	int len = 1;
	if (flag_bits & FLAG_RECENT) {
		len += sprintf(flags_string + len, "\\Recent");
		b_first = TRUE;
	}
	if (flag_bits & FLAG_ANSWERED) {
		if (b_first)
			flags_string[len++] = ' ';
		else
			b_first = TRUE;
		len += sprintf(flags_string + len, "\\Answered");
	}
	if (flag_bits & FLAG_FLAGGED) {
		if (b_first)
			flags_string[len++] = ' ';
		else
			b_first = TRUE;
		len += sprintf(flags_string + len, "\\Flagged");
	}
	if (flag_bits & FLAG_DELETED) {
		if (b_first)
			flags_string[len++] = ' ';
		else
			b_first = TRUE;
		len += sprintf(flags_string + len, "\\Deleted");
	}
	if (flag_bits & FLAG_SEEN) {
		if (b_first)
			flags_string[len++] = ' ';
		else
			b_first = TRUE;
		len += sprintf(flags_string + len, "\\Seen");
	}
	if (flag_bits & FLAG_DRAFT) {
		if (b_first)
			flags_string[len++] = ' ';
		else
			b_first = TRUE;
		len += sprintf(flags_string + len, "\\Draft");
	}
	flags_string[len] = ')';
	flags_string[len + 1] = '\0';
}

static int icp_match_field(mjson_io &io, const char *cmd_tag,
    const char *file_path, size_t offset, size_t length, BOOL b_not,
    const char *tags, size_t offset1, ssize_t length1, std::string &value) try
{
	auto pbody = strchr(cmd_tag, '[');
	if (length > 128 * 1024)
		return -1;
	auto fd = io.find(file_path);
	if (io.invalid(fd))
		return -1;
	auto buff = io.substr(fd, offset, length);

	char temp_buff[1024], *tmp_argv[128];
	int tmp_argc;
	gx_strlcpy(temp_buff, tags, std::size(temp_buff));
	if (tags[0] == '(')
		tmp_argc = parse_imap_args(temp_buff + 1,
			strlen(tags) - 2, tmp_argv, sizeof(tmp_argv));
	else
		tmp_argc = parse_imap_args(temp_buff,
			strlen(tags), tmp_argv, sizeof(tmp_argv));

	size_t len, buff_len = 0;
	std::string buff1;
	bool b_hit = false;
	MIME_FIELD mime_field;
	while ((len = parse_mime_field(&buff[buff_len], length - buff_len,
	       &mime_field)) != 0) {
		b_hit = FALSE;
		for (int i = 0; i < tmp_argc; ++i) {
			if (strcasecmp(tmp_argv[i], mime_field.name.c_str()) != 0)
				continue;
			if (!b_not) {
				buff1 += std::string_view(&buff[buff_len], len);
				break;
			}
			b_hit = TRUE;
		}
		if (b_not && !b_hit)
			buff1 += std::string_view(&buff[buff_len], len);
		buff_len += len;
	}
	buff1 += "\r\n";
	const auto len1 = buff1.size();
	if (length1 == -1)
		length1 = len1;
	if (offset1 >= len1) {
		value += "BODY"s + pbody + " NIL";
	} else {
		if (offset1 + length1 > len1)
			length1 = len1 - offset1;
		value += "BODY"s + pbody;
		value += " {" + std::to_string(length1) + "}\r\n";
		value += std::string_view(buff1).substr(offset1);
	}
	return 0;
} catch (const std::bad_alloc &) {
	return -1;
}

static int pstruct_null(MJSON *pjson,
    const std::string &cmd_tag, std::string &buf, const char *pbody,
    const char *temp_id, const char *data_item, size_t offset, ssize_t length,
    const char *storage_path)
{
	auto pmime = pjson->get_mime(temp_id);
	/* Non-[MIME-IMB] messages, and non-multipart
	   [MIME-IMB] messages with no encapsulated
	   message, only have a part 1
	*/
	if (pmime == nullptr && strcmp(temp_id, "1") == 0)
		pmime = pjson->get_mime("");
	if (pmime == nullptr) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	size_t part_length = 0, temp_len = 0;
	if (0 == strcmp(temp_id, "")) {
		part_length = pmime->get_entire_length();
		temp_len = pmime->get_head_offset();
	} else {
		part_length = pmime->get_content_length();
		temp_len = pmime->get_content_offset();
	}
	if (length == -1)
		length = part_length;
	if (offset >= part_length) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	if (offset + length > part_length)
		length = part_length - offset;
	if (storage_path == nullptr)
		buf += fmt::format("BODY{} <<{{file}}{}|{}|{}\r\n",
		       pbody, pjson->get_mail_filename(),
		       temp_len + offset, length);
	else
		buf += fmt::format("BODY{} <<{{rfc822}}{}/{}|{}|{}\r\n",
		       pbody, storage_path,
		       pjson->get_mail_filename(),
		       temp_len + offset, length);
	return 0;
}

static int pstruct_mime(MJSON *pjson,
    const std::string &cmd_tag, std::string &buf, const char *pbody,
    const char *temp_id, const char *data_item, size_t offset, ssize_t length,
    const char *storage_path)
{
	if ((strcasecmp(&data_item[1], "MIME") == 0 && *temp_id == '\0') ||
	    (strcasecmp(&data_item[1], "HEADER") == 0 && *temp_id != '\0')) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	auto pmime = pjson->get_mime(temp_id);
	if (pmime == nullptr) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	size_t head_length = pmime->get_head_length();
	if (length == -1)
		length = head_length;
	if (offset >= head_length) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	if (offset + length > head_length)
		length = head_length - offset;
	if (storage_path == nullptr)
		buf += fmt::format("BODY{} <<{{file}}{}|{}|{}\r\n",
		       pbody, pjson->get_mail_filename(),
		       pmime->get_head_offset() + offset, length);
	else
		buf += fmt::format("BODY{} <<{{rfc822}}{}/{}|{}|{}\r\n",
		       pbody, storage_path,
		       pjson->get_mail_filename(),
		       pmime->get_head_offset() + offset, length);
	return 0;
}

static int pstruct_text(MJSON *pjson,
    const std::string &cmd_tag, std::string &buf, const char *pbody,
    const char *temp_id, const char *data_item, size_t offset, ssize_t length,
    const char *storage_path)
{
	if (*temp_id != '\0') {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	auto pmime = pjson->get_mime(temp_id);
	if (pmime == nullptr) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	size_t ct_length = pmime->get_content_length();
	if (length == -1)
		length = ct_length;
	if (offset >= ct_length) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	if (offset + length > ct_length)
		length = ct_length - offset;
	if (storage_path == nullptr)
		buf += fmt::format("BODY{} <<{{file}}{}|{}|{}\r\n",
		       pbody, pjson->get_mail_filename(),
		       pmime->get_content_offset() + offset, length);
	else
		buf += fmt::format("BODY{} <<{{rfc822}}{}|{}|{}\r\n",
		       pbody, storage_path,
		       pjson->get_mail_filename(),
		       pmime->get_content_offset() + offset, length);
	return 0;
}

static int pstruct_else(imap_context &ctx, MJSON *pjson,
    const std::string &cmd_tag, std::string &buf, const char *pbody,
    const char *temp_id, const char *data_item, size_t offset, ssize_t length,
    const char *storage_path)
{
	auto b_not = strncasecmp(&data_item[1], "HEADER.FIELDS ", 14) != 0;
	data_item += b_not ? 19 : 15;
	auto pmime = pjson->get_mime(temp_id);
	if (pmime == nullptr) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	std::string eml_path;
	if (storage_path == nullptr) {
		eml_path = ctx.maildir + "/eml/"s + pjson->get_mail_filename();
		if (!ctx.io_actor.exists(eml_path)) {
			std::string content;
			if (exmdb_client::imapfile_read(ctx.maildir, "eml",
			    pjson->get_mail_filename(), &content))
				ctx.io_actor.place(eml_path, std::move(content));
		}
	} else {
		eml_path = ctx.maildir + "/tmp/imap.rfc822/"s + storage_path + "/" + pjson->get_mail_filename();
	}
	std::string b2;
	int len = icp_match_field(ctx.io_actor, cmd_tag.c_str(), eml_path.c_str(),
	          pmime->get_head_offset(), pmime->get_head_length(),
	          b_not, data_item, offset, length, b2);
	if (len == -1)
		buf += "BODY"s + pbody + " NIL";
	else
		buf += std::move(b2);
	return 0;
}

static int icp_print_structure(imap_context &ctx, MJSON *pjson,
    const std::string &cmd_tag, std::string &buf, const char *pbody,
    const char *temp_id, const char *data_item, size_t offset, ssize_t length,
    const char *storage_path) try
{
	if (data_item == nullptr)
		return pstruct_null(pjson, cmd_tag, buf,
		       pbody, temp_id, data_item, offset, length, storage_path);
	if (strcasecmp(&data_item[1], "MIME") == 0 ||
	    strcasecmp(&data_item[1], "HEADER") == 0)
		return pstruct_mime(pjson, cmd_tag, buf,
		       pbody, temp_id, data_item, offset, length, storage_path);
	if (strcasecmp(&data_item[1], "TEXT") == 0)
		return pstruct_text(pjson, cmd_tag, buf,
		       pbody, temp_id, data_item, offset, length, storage_path);
	if (strcmp(temp_id, "") != 0) {
		buf += "BODY"s + pbody + " NIL";
		return 0;
	}
	return pstruct_else(ctx, pjson, cmd_tag, buf, pbody,
	       temp_id, data_item, offset, length, storage_path);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1465: ENOMEM");
	return -1;
}

static int icp_process_fetch_item(imap_context &ctx,
    BOOL b_data, MITEM *pitem, int item_id, mdi_list &pitem_list) try
{
	auto pcontext = &ctx;
	int errnum;
	MJSON mjson;
	std::string buf;
	
	if (pitem->flag_bits & FLAG_LOADED) {
		auto eml_path = std::string(pcontext->maildir) + "/eml";
		if (!mjson.load_from_json(pitem->digest)) {
			mlog(LV_ERR, "E-1921: load_from_json %s/%s oopsied", ctx.maildir, ctx.mid.c_str());
			return 1923;
		}
		mjson.path = eml_path;
		auto eml_file = eml_path + "/"s + pitem->mid;
		if (!ctx.io_actor.exists(eml_file)) {
			std::string content;
			if (exmdb_client::imapfile_read(ctx.maildir, "eml", pitem->mid, &content))
				ctx.io_actor.place(eml_file, std::move(content));
		}
	}

	BOOL b_first = FALSE;
	buf = "* " + std::to_string(item_id) + " FETCH (";
	for (auto &kwss : pitem_list) {
		if (!b_first)
			b_first = TRUE;
		else
			buf += ' ';
		auto kw = kwss.data();
		if (strcasecmp(kw, "BODY") == 0) {
			buf += "BODY ";
			if (mjson.has_rfc822_part()) {
				auto rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				if (rfc_path.size() <= 0 ||
				    !mjson.rfc822_build(ctx.io_actor, rfc_path.c_str()))
					goto FETCH_BODY_SIMPLE;
				std::string b2;
				auto len = mjson.rfc822_fetch(ctx.io_actor, rfc_path.c_str(),
				           pcontext->defcharset, false, b2);
				if (len == -1)
					goto FETCH_BODY_SIMPLE;
				buf += std::move(b2);
			} else {
 FETCH_BODY_SIMPLE:
				std::string b2;
				auto len = mjson.fetch_structure(ctx.io_actor,
				           ctx.defcharset, false, b2);
				if (len == -1)
					buf += "NIL";
				else
					buf += std::move(b2);
			}
		} else if (strcasecmp(kw, "BODYSTRUCTURE") == 0) {
			buf += "BODYSTRUCTURE ";
			if (mjson.has_rfc822_part()) {
				auto rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				if (rfc_path.size() <= 0 ||
				    !mjson.rfc822_build(ctx.io_actor, rfc_path.c_str()))
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				std::string b2;
				auto len = mjson.rfc822_fetch(ctx.io_actor, rfc_path.c_str(),
				           pcontext->defcharset, TRUE, b2);
				if (len == -1)
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				buf += std::move(b2);
			} else {
 FETCH_BODYSTRUCTURE_SIMPLE:
				std::string b2;
				auto len = mjson.fetch_structure(ctx.io_actor,
				           ctx.defcharset, TRUE, b2);
				if (len == -1)
					buf += "NIL";
				else
					buf += std::move(b2);
			}
		} else if (strcasecmp(kw, "ENVELOPE") == 0) {
			buf += "ENVELOPE ";
			std::string b2;
			auto len = mjson.fetch_envelope(pcontext->defcharset, b2);
			if (len == -1)
				buf += "NIL";
			else
				buf += std::move(b2);
		} else if (strcasecmp(kw, "FLAGS") == 0) {
			char flags_string[128];
			icp_convert_flags_string(pitem->flag_bits, flags_string);
			buf += "FLAGS ";
			buf += flags_string;
		} else if (strcasecmp(kw, "INTERNALDATE") == 0) {
			time_t tmp_time;
			struct tm tmp_tm;

			if (!parse_rfc822_timestamp(mjson.get_mail_received(), &tmp_time))
				tmp_time = strtol(mjson.get_mail_filename(), nullptr, 0);
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			localtime_r(&tmp_time, &tmp_tm);
			char b2[80];
			strftime(b2, std::size(b2), "INTERNALDATE \"%d-%b-%Y %T %z\"", &tmp_tm);
			buf += b2;
		} else if (strcasecmp(kw, "RFC822") == 0) {
			buf += fmt::format("RFC822 <<{{file}}{}|0|{}\r\n",
			       mjson.get_mail_filename(),
			       mjson.get_mail_length());
			if (!pcontext->b_readonly &&
			    !(pitem->flag_bits & FLAG_SEEN)) {
				midb_agent::set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, nullptr, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_bcast_flags(*pcontext, pitem->uid);
			}
		} else if (strcasecmp(kw, "RFC822.HEADER") == 0) {
			auto pmime = mjson.get_mime("");
			if (pmime != nullptr)
				buf += fmt::format("RFC822.HEADER <<{{file}}{}|0|{}\r\n",
				       mjson.get_mail_filename(),
				       pmime->get_head_length());
			else
				buf += "RFC822.HEADER NIL";
		} else if (strcasecmp(kw, "RFC822.SIZE") == 0) {
			buf += "RFC822.SIZE ";
			buf += std::to_string(mjson.get_mail_length());
		} else if (strcasecmp(kw, "RFC822.TEXT") == 0) {
			auto pmime = mjson.get_mime("");
			size_t ct_length = pmime != nullptr ? pmime->get_content_length() : 0;
			if (pmime != nullptr)
				buf += fmt::format("RFC822.TEXT <<{{file}}{}|{}|{}\r\n",
				       mjson.get_mail_filename(),
				       pmime->get_content_offset(),
				       ct_length);
			else
				buf += "RFC822.TEXT NIL";
			if (!pcontext->b_readonly &&
			    !(pitem->flag_bits & FLAG_SEEN)) {
				midb_agent::set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, nullptr, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_bcast_flags(*pcontext, pitem->uid);
			}
		} else if (strcasecmp(kw, "UID") == 0) {
			buf += "UID ";
			buf += std::to_string(pitem->uid);
		} else if (strncasecmp(kw, "BODY[", 5) == 0 ||
		    strncasecmp(kw, "BODY.PEEK[", 10) == 0) {
			auto pbody = strchr(kw, '[');
			auto pend = strchr(pbody + 1, ']');
			if (pend == nullptr)
				return 1800;
			size_t offset = 0, length = -1;
			if (pend[1] == '<') {
				offset = strtol(pend + 2, nullptr, 0);
				auto pdot = strchr(pend + 2, '.');
				if (NULL != pdot) {
					length = strtol(pdot + 1, nullptr, 0);
					/* trim the length information for response tag */
					pdot[0] = '>';
					pdot[1] = '\0';
				}
			}
			auto len = pend - (pbody + 1);
			char temp_buff[1024];
			memcpy(temp_buff, pbody + 1, len);
			temp_buff[len] = '\0';
			char *ptr = nullptr;
			for (decltype(len) i = 0; i < len; ++i) {
				if (temp_buff[i] == '.' || HX_isdigit(temp_buff[i]))
					continue;
				ptr = temp_buff + i - 1;
				if (i > 0)
					*ptr = '\0';
				break;
			}
			const char *temp_id;
			if (ptr == nullptr)
				temp_id = temp_buff;
			else if (ptr < temp_buff)
				/*
				 * This is still crap, @ptr is invalid, the
				 * comparison is undefined (pointers must point
				 * into the object)
				 */
				temp_id = "";
			else
				temp_id = temp_buff;
			if (*temp_id != '\0' && mjson.has_rfc822_part()) {
				auto rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				if (rfc_path.size() > 0 &&
				    mjson.rfc822_build(ctx.io_actor, rfc_path.c_str())) {
					MJSON temp_mjson;
					char mjson_id[64], final_id[64];
					if (mjson.rfc822_get(ctx.io_actor,
					    &temp_mjson, rfc_path.c_str(),
					    temp_id, mjson_id, final_id))
						len = icp_print_structure(ctx,
						      &temp_mjson, kwss.c_str(), buf,
							pbody, final_id, ptr, offset, length,
						      mjson.get_mail_filename());
					else
						len = icp_print_structure(ctx,
						      &mjson, kwss.c_str(), buf,
						      pbody, temp_id, ptr, offset, length, nullptr);
				} else {
					len = icp_print_structure(ctx, &mjson, kwss, buf,
					      pbody, temp_id, ptr, offset, length, nullptr);
				}
			} else {
				len = icp_print_structure(ctx, &mjson, kwss, buf,
				      pbody, temp_id, ptr, offset, length, nullptr);
			}
			if (len < 0)
				return 1918;
			if (!pcontext->b_readonly &&
			    !(pitem->flag_bits & FLAG_SEEN) &&
			    strncasecmp(kw, "BODY[", 5) == 0) {
				midb_agent::set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, nullptr, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_bcast_flags(*pcontext, pitem->uid);
			}
		}
	}
	buf += ")\r\n";
	if (pcontext->stream.write(buf.data(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	if (!pcontext->b_readonly && pitem->flag_bits & FLAG_RECENT) {
		pitem->flag_bits &= ~FLAG_RECENT;
		if (!(pitem->flag_bits & FLAG_SEEN)) {
			midb_agent::unset_flags(pcontext->maildir,
				pcontext->selected_folder, pitem->mid,
				FLAG_RECENT, nullptr, &errnum);
			imap_parser_bcast_flags(*pcontext, pitem->uid);
		}
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1464: ENOMEM");
	return 1918;
}

static void icp_store_flags(const char *cmd, const std::string &mid,
    int id, unsigned int uid, unsigned int flag_bits, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;
	char buff[1024];
	int string_length;
	char flags_string[128];
	
	string_length = 0;
	if (0 == strcasecmp(cmd, "FLAGS") ||
		0 == strcasecmp(cmd, "FLAGS.SILENT")) {
		midb_agent::unset_flags(pcontext->maildir, pcontext->selected_folder,
			mid, FLAG_ANSWERED | FLAG_FLAGGED | FLAG_DELETED |
			FLAG_SEEN | FLAG_DRAFT | FLAG_RECENT, nullptr, &errnum);
		midb_agent::set_flags(pcontext->maildir, pcontext->selected_folder,
			mid, flag_bits, nullptr, &errnum);
		if (0 == strcasecmp(cmd, "FLAGS")) {
			icp_convert_flags_string(flag_bits, flags_string);
			if (uid != 0)
				string_length = gx_snprintf(buff, std::size(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			else
				string_length = gx_snprintf(buff, std::size(buff),
					"* %d FETCH (FLAGS %s)\r\n",
					id, flags_string);
		}
	} else if (0 == strcasecmp(cmd, "+FLAGS") ||
		0 == strcasecmp(cmd, "+FLAGS.SILENT")) {
		midb_agent::set_flags(pcontext->maildir, pcontext->selected_folder,
			mid, flag_bits, nullptr, &errnum);
		if (0 == strcasecmp(cmd, "+FLAGS") && 
			MIDB_RESULT_OK == midb_agent::get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid, &flag_bits, &errnum)) {
			icp_convert_flags_string(flag_bits, flags_string);
			if (uid != 0)
				string_length = gx_snprintf(buff, std::size(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			else
				string_length = gx_snprintf(buff, std::size(buff),
					"* %d FETCH (FLAGS %s)\r\n",
					id, flags_string);
		}
	} else if (0 == strcasecmp(cmd, "-FLAGS") ||
		0 == strcasecmp(cmd, "-FLAGS.SILENT")) {
		midb_agent::unset_flags(pcontext->maildir, pcontext->selected_folder,
			mid, flag_bits, nullptr, &errnum);
		if (0 == strcasecmp(cmd, "-FLAGS") &&
			MIDB_RESULT_OK == midb_agent::get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid, &flag_bits, &errnum)) {
			icp_convert_flags_string(flag_bits, flags_string);
			if (uid != 0)
				string_length = gx_snprintf(buff, std::size(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			else
				string_length = gx_snprintf(buff, std::size(buff),
					"* %d FETCH (FLAGS %s)\r\n",
					id, flags_string);
		}
	}
	if (string_length != 0)
		imap_parser_safe_write(pcontext, buff, string_length);
}

static BOOL icp_convert_imaptime(const char *str_time, time_t *ptime)
{
	time_t tmp_time;
	char tmp_buff[3];
	struct tm tmp_tm{};
	auto str_zone = strptime(str_time, "%d-%b-%Y %T ", &tmp_tm);
	if (str_zone == nullptr)
		return FALSE;
	if (strlen(str_zone) < 5)
		return FALSE;

	int factor;
	if (*str_zone == '-')
		factor = 1;
	else if (*str_zone == '+')
		factor = -1;
	else
		return FALSE;
	if (!HX_isdigit(str_zone[1]) || !HX_isdigit(str_zone[2]) ||
	    !HX_isdigit(str_zone[3]) || !HX_isdigit(str_zone[4]))
		return FALSE;
	tmp_buff[0] = str_zone[1];
	tmp_buff[1] = str_zone[2];
	tmp_buff[2] = '\0';
	int hour = strtol(tmp_buff, nullptr, 0);
	if (hour < 0 || hour > 23)
		return FALSE;
	tmp_buff[0] = str_zone[3];
	tmp_buff[1] = str_zone[4];
	tmp_buff[2] = '\0';
	int minute = strtol(tmp_buff, nullptr, 0);
	if (minute < 0 || minute > 59)
		return FALSE;
	tmp_time = timegm(&tmp_tm);
	tmp_time += factor*(60*60*hour + 60*minute);
	*ptime = tmp_time;
	return TRUE;
}

static BOOL icp_wildcard_match(const char *folder, const char *mask)
{
	while (true) {
		if (*folder == '\0' && *mask == '\0')
			return true;
		if (*mask != '*' && *mask != '%') {
			if (HX_toupper(*folder) != HX_toupper(*mask))
				return false;
			++folder;
			++mask;
			continue;
		}
		/* Find longest match for wildcards */
		auto span = *mask == '*' ? strlen(folder) : strcspn(folder, "/");
		++mask;
		while (true) {
			if (icp_wildcard_match(&folder[span], mask))
				return true;
			if (span-- == 0)
				break;
		}
		return false;
	}
}

/**
 * See sysfolder_to_imapfolder for some notes.
 */
static BOOL icp_imapfolder_to_sysfolder(const char *imap_folder,
    std::string &sys_folder) try
{
	std::string t;
	t.resize(strlen(imap_folder));
	if (mutf7_to_utf8(imap_folder, strlen(imap_folder), t.data(), t.size() + 1) < 0)
		return FALSE;
	t.resize(strlen(t.c_str()));
	if (t.size() > 0 && t.back() == '/')
		t.pop_back();
	if (strncasecmp(t.c_str(), "inbox", 5) == 0 &&
	    (t[5] == '\0' || t[5] == '/'))
		memcpy(t.data(), "INBOX", 5);
	sys_folder = base64_encode(t);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2418: ENOMEM");
	return false;
}

static BOOL icp_sysfolder_to_imapfolder(const enum_folder_t &sys_folder,
    std::string &imap_folder) try
{
	if (sys_folder.first == PRIVATE_FID_INBOX) {
		imap_folder = "INBOX";
		return TRUE;
	}
	auto t = base64_decode(sys_folder.second);
	if (t.empty())
		return FALSE;
	imap_folder.resize(utf8_to_mb_len(t.c_str()));
	if (utf8_to_mutf7(t.c_str(), t.size(), imap_folder.data(), imap_folder.size() + 1) <= 0)
		return FALSE;
	imap_folder.resize(strlen(imap_folder.c_str()));
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2417: ENOMEM");
	return false;
}

static void icp_convert_folderlist(std::vector<enum_folder_t> &pfile) try
{
	std::string o;
	
	for (auto &e : pfile)
		if (icp_sysfolder_to_imapfolder(e, o))
			e.second = std::move(o);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1814: ENOMEM");
}

static std::string flagbits_to_s(bool seen, bool answ, bool flagged, bool draft)
{
	std::string s = "(";
	if (seen)    s += 'S';
	if (answ)    s += 'A';
	if (flagged) s += 'F';
	if (draft)   s += 'U';
	s += ')';
	return s;
}

int icp_capability(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170001: OK CAPABILITY completed */
	char ext_str[128];
	capability_list(ext_str, std::size(ext_str), pcontext);
	auto buf = fmt::format("* CAPABILITY {}\r\n{} {}",
	           ext_str, argv[0], resource_get_imap_code(1701, 1));
	imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1918;
}

int icp_id(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	std::string buf;
	if (parse_bool(g_config_file->get_value("enable_rfc2971_commands")))
		/* IMAP_CODE_2170029: OK ID completed */
		buf = fmt::format("* ID (\"name\" \"gromox-imap\" "
		      "version \"{}\")\r\n{} {}", PACKAGE_VERSION,
		      argv[0], resource_get_imap_code(1729, 1));
	else
		buf = argv[0] + " "s + resource_get_imap_code(1800, 1);
	imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1918;
}

int icp_noop(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1702;
}

int icp_logout(int argc, char **argv, imap_context &ctx) try
{
	/* IMAP_CODE_2160001: BYE logging out */
	/* IMAP_CODE_2170003: OK LOGOUT completed */
	auto buf = "* "s + resource_get_imap_code(1601, 1) +
	           argv[0] + " " + resource_get_imap_code(1703, 1);
	imap_parser_safe_write(&ctx, buf.c_str(), buf.size());
	return DISPATCH_SHOULD_CLOSE;
} catch (const std::bad_alloc &) {
	return 1918;
}

int icp_starttls(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	if (pcontext->connection.ssl != nullptr)
		return 1800;
	if (!g_support_tls)
		return 1800;
	if (pcontext->proto_stat > iproto_stat::noauth)
		return 1801;
	pcontext->sched_stat = isched_stat::stls;	
	return 1704;
}

int icp_authenticate(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	if (g_support_tls && g_force_tls && pcontext->connection.ssl == nullptr)
		return 1802;
	if (argc != 3 || strcasecmp(argv[2], "LOGIN") != 0)
		return 1800;
	if (pcontext->is_authed())
		return 1803;
	gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
	pcontext->proto_stat = iproto_stat::username;
	static constexpr char prompt[] = "+ VXNlciBOYW1lAA==\r\n";
	imap_parser_safe_write(pcontext, prompt, strlen(prompt));
    return DISPATCH_CONTINUE;
}

static int icp_username2(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	size_t temp_len;
	
	if (decode64_ex(argv[0], strlen(argv[0]),
	    pcontext->username, std::size(pcontext->username),
	    &temp_len) != 0) {
		pcontext->proto_stat = iproto_stat::noauth;
		return 1819 | DISPATCH_TAG;
	}
	pcontext->proto_stat = iproto_stat::password;
	static constexpr char prompt[] = "+ UGFzc3dvcmQA\r\n";
	imap_parser_safe_write(pcontext, prompt, strlen(prompt));
    return DISPATCH_CONTINUE;
}

int icp_username(int argc, char **argv, imap_context &ctx)
{
	return icp_dval(argc, argv, ctx, icp_username2(argc, argv, ctx));
}

static inline const char *tag_or_bug(const char *s)
{
	return *s != '\0' ? s : "BUG";
}

static bool store_owner_over(const char *actor, const char *mbox, const char *mboxdir)
{
	if (mbox == nullptr)
		return true; /* No impersonation of another store */
	if (strcmp(actor, mbox) == 0)
		return true; /* Silly way of logging in to your own mailbox but ok */
	uint32_t perms = 0;
	imrpc_build_env();
	auto ok = exmdb_client::get_mbox_perm(mboxdir, actor, &perms) &&
	          perms & frightsGromoxStoreOwner;
	imrpc_free_env();
	return ok;
}

static int icp_password2(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	size_t temp_len;
	char temp_password[256];
	
	pcontext->proto_stat = iproto_stat::noauth;
	if (decode64_ex(argv[0], strlen(argv[0]),
	    temp_password, std::size(temp_password), &temp_len) != 0)
		return 1820 | DISPATCH_TAG;

	auto target_mbox = strchr(pcontext->username, '!');
	if (target_mbox != nullptr)
		*target_mbox++ = '\0';
	HX_strltrim(pcontext->username);
	if (!system_services_judge_user(pcontext->username)) {
		imap_parser_log_info(pcontext, LV_WARN, "LOGIN phase2 rejected: denied by user filter");
		return 1901 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
    }
	sql_meta_result mres_auth, mres /* target */;
	if (!system_services_auth_login(pcontext->username, temp_password,
	    USER_PRIVILEGE_IMAP, mres_auth)) {
		safe_memset(temp_password, 0, std::size(temp_password));
		imap_parser_log_info(pcontext, LV_WARN, "LOGIN phase2 rejected: %s",
			mres_auth.errstr.c_str());
		pcontext->auth_times ++;
		if (pcontext->auth_times < g_max_auth_times)
			return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
		system_services_ban_user(pcontext->username, g_block_auth_fail);
		return 1903 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
	}
	safe_memset(temp_password, 0, std::size(temp_password));
	if (target_mbox == nullptr) {
		mres = std::move(mres_auth);
	} else {
		if (mysql_adaptor_meta(target_mbox, WANTPRIV_METAONLY, mres) != 0)
			return 1902 | DISPATCH_CONTINUE | DISPATCH_TAG;
		if (!store_owner_over(mres_auth.username.c_str(), mres.username.c_str(),
		    mres.maildir.c_str())) {
			imap_parser_log_info(pcontext, LV_WARN, "LOGIN phase2 rejected: %s", mres.errstr.c_str());
			++pcontext->auth_times;
			if (pcontext->auth_times < g_max_auth_times)
				return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
			system_services_ban_user(pcontext->username, g_block_auth_fail);
			return 1903 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
		}
	}
	gx_strlcpy(pcontext->username, mres.username.c_str(), std::size(pcontext->username));
	gx_strlcpy(pcontext->maildir, mres.maildir.c_str(), std::size(pcontext->maildir));
	if (*pcontext->maildir == '\0')
		return 1902 | DISPATCH_TAG;
	if (mres.lang.empty())
		mres.lang = znul(g_config_file->get_value("default_lang"));
	gx_strlcpy(pcontext->defcharset, resource_get_default_charset(mres.lang.c_str()),
		std::size(pcontext->defcharset));
	pcontext->proto_stat = iproto_stat::auth;
	imap_parser_log_info(pcontext, LV_DEBUG, "LOGIN ok");
	char caps[128];
	capability_list(caps, std::size(caps), pcontext);
	auto buf = fmt::format("{} OK [CAPABILITY {}] Logged in\r\n",
		   tag_or_bug(pcontext->tag_string), caps);
	imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1918;
}

int icp_password(int argc, char **argv, imap_context &ctx)
{
	return icp_dval(argc, argv, ctx, icp_password2(argc, argv, ctx));
}

int icp_login(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	char temp_password[256];
    
	if (g_support_tls && g_force_tls && pcontext->connection.ssl == nullptr)
		return 1802;
	if (argc != 4 || strlen(argv[2]) >= std::size(pcontext->username) ||
	    strlen(argv[3]) > 255)
		return 1800;
	if (pcontext->is_authed())
		return 1803;
	auto target_mbox = strchr(argv[2], '!');
	if (target_mbox != nullptr)
		*target_mbox++ = '\0';
	gx_strlcpy(pcontext->username, argv[2], std::size(pcontext->username));
	HX_strltrim(pcontext->username);
	if (!system_services_judge_user(pcontext->username)) {
		imap_parser_log_info(pcontext, LV_WARN, "LOGIN phase0 rejecting \"%s\": denied by user filter",
			pcontext->username);
		return 1901 | DISPATCH_SHOULD_CLOSE;
    }
	strcpy(temp_password, argv[3]);
	HX_strltrim(temp_password);

	sql_meta_result mres_auth, mres /* target */;
	if (!system_services_auth_login(pcontext->username, temp_password,
	    USER_PRIVILEGE_IMAP, mres_auth)) {
		imap_parser_log_info(pcontext, LV_WARN, "LOGIN phase1 rejecting \"%s\": %s",
			pcontext->username, mres.errstr.c_str());
		pcontext->auth_times++;
		if (pcontext->auth_times < g_max_auth_times) {
			gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
			return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
		}
		system_services_ban_user(pcontext->username, g_block_auth_fail);
		return 1903 | DISPATCH_SHOULD_CLOSE;
	}
	safe_memset(temp_password, 0, std::size(temp_password));
	if (target_mbox == nullptr) {
		mres = std::move(mres_auth);
	} else {
		if (mysql_adaptor_meta(target_mbox, WANTPRIV_METAONLY, mres) != 0)
			return 1902 | DISPATCH_CONTINUE | DISPATCH_TAG;
		if (!store_owner_over(mres_auth.username.c_str(), mres.username.c_str(),
		    mres.maildir.c_str())) {
			imap_parser_log_info(pcontext, LV_WARN, "LOGIN phase1 rejected: %s", mres.errstr.c_str());
			++pcontext->auth_times;
			if (pcontext->auth_times < g_max_auth_times)
				return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
			system_services_ban_user(pcontext->username, g_block_auth_fail);
			return 1903 | DISPATCH_SHOULD_CLOSE;
		}
	}
	gx_strlcpy(pcontext->username, mres.username.c_str(), std::size(pcontext->username));
	gx_strlcpy(pcontext->maildir, mres.maildir.c_str(), std::size(pcontext->maildir));
	if (*pcontext->maildir == '\0')
		return 1902;
	if (mres.lang.empty())
		mres.lang = znul(g_config_file->get_value("default_lang"));
	gx_strlcpy(pcontext->defcharset, resource_get_default_charset(mres.lang.c_str()),
		std::size(pcontext->defcharset));
	pcontext->proto_stat = iproto_stat::auth;
	imap_parser_log_info(pcontext, LV_DEBUG, "LOGIN ok");
	return 1705;
}

int icp_idle(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	if (!pcontext->is_authed())
		return 1804;
	if (argc != 2)
		return 1800;
	gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
	pcontext->sched_stat = isched_stat::idling;
	size_t len = 0;
	auto reply = resource_get_imap_code(1602, 1, &len);
	pcontext->connection.write(reply, len);
	return 0;
}

static int m2icode(int r, int e)
{
	switch (r) {
	case MIDB_RESULT_OK:
		return 0;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	case MIDB_RESULT_ERROR:
		return DISPATCH_MIDB | static_cast<uint16_t>(e);
	case MIDB_LOCAL_ENOMEM:
		return 1920;
	case MIDB_TOO_MANY_RESULTS:
		return 1921;
	default:
		return 1919;
	}
}

/**
 * Get a listing of all mails in the folder to build the uid<->seqid mapping.
 */
int content_array::refresh(imap_context &ctx, const std::string &folder,
    bool fresh_numbers)
{
	XARRAY xa;
	int errnum = 0;
	imap_seq_list all_seq;
	all_seq.insert(1, SEQ_STAR);
	auto ssr = midb_agent::fetch_simple_uid(ctx.maildir, folder,
	           all_seq, &xa, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	if (fresh_numbers) {
		for (size_t i = 0; i < xa.m_vec.size(); ++i)
			xa.m_vec[i].id = i + 1;
		*this = std::move(xa);
	} else {
		auto start = m_vec.size();
		for (auto &newmail : xa.m_vec) {
			if (get_itemx(newmail.uid) != nullptr)
				continue; /* already known */
			auto uid = newmail.uid;
			append(std::move(newmail), uid);
			m_vec[start].id = start + 1;
			++start;
		}
	}
	n_recent = std::count_if(m_vec.cbegin(), m_vec.cend(),
	           [](const MITEM &m) { return m.flag_bits & FLAG_RECENT; });
	auto iter = std::find_if(m_vec.cbegin(), m_vec.cend(),
	            [](const MITEM &m) { return !(m.flag_bits & FLAG_SEEN); });
	firstunseen = iter == m_vec.end() ? 0 : iter - m_vec.cbegin() + 1;
	return 0;
}

static int icp_selex(int argc, char **argv, imap_context &ctx, bool readonly) try
{
	auto pcontext = &ctx;
	int errnum;
	std::string sys_name;
    
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], sys_name))
		return 1800;
	if (iproto_stat::select == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = iproto_stat::auth;
		pcontext->selected_folder.clear();
	}
	
	uint32_t uidvalid = 0, uidnext = 0;
	auto ssr = midb_agent::summary_folder(pcontext->maildir, sys_name,
	           nullptr, nullptr, nullptr, &uidvalid, &uidnext, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	ret = pcontext->contents.refresh(*pcontext, sys_name, true);
	if (ret != 0)
		return ret;
	pcontext->selected_folder = sys_name;
	pcontext->proto_stat = iproto_stat::select;
	pcontext->b_readonly = readonly;
	imap_parser_add_select(pcontext);

	auto buf = fmt::format(
		"* {} EXISTS\r\n"
		"* {} RECENT\r\n"
		"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
		"* OK {}\r\n",
		pcontext->contents.n_exists(),
		pcontext->contents.n_recent, readonly ?
		"[PERMANENTFLAGS ()] no permanent flags permitted" :
		"[PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited");
	if (pcontext->contents.firstunseen != 0)
		buf += fmt::format("* OK [UNSEEN {}] message {} is first unseen\r\n",
			pcontext->contents.firstunseen,
			pcontext->contents.firstunseen);
	auto s_readonly = readonly ? "READ-ONLY" : "READ-WRITE";
	auto s_command  = readonly ? "EXAMINE" : "SELECT";
	buf += fmt::format("* OK [UIDVALIDITY {}] UIDs valid\r\n"
	       "* OK [UIDNEXT {}] predicted next UID\r\n", uidvalid, uidnext);
	if (g_rfc9051_enable)
		buf += fmt::format("* LIST () \"/\" {}\r\n", quote_encode(argv[2]));
	buf += fmt::format("{} OK [{}] {} completed\r\n",
		argv[0], s_readonly, s_command);
	imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1915;
}

int icp_select(int argc, char **argv, imap_context &ctx)
{
	return icp_selex(argc, argv, ctx, false);
}

int icp_examine(int argc, char **argv, imap_context &ctx)
{
	return icp_selex(argc, argv, ctx, true);
}

int icp_create(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0)
		return 1800;
	if (strpbrk(argv[2], "%*?") != nullptr)
		return 1910;
	std::vector<enum_folder_t> folder_list;
	auto ssr = midb_agent::enum_folders(pcontext->maildir, folder_list, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	icp_convert_folderlist(folder_list);
	std::string sys_name = argv[2]; // Go back to non-encoded string
	if (sys_name.size() > 0 && sys_name.back() == '/')
		sys_name.pop_back();
	if (std::any_of(folder_list.cbegin(), folder_list.cend(),
	    [&](const enum_folder_t &e) { return strcasecmp(e.second.c_str(), sys_name.c_str()) == 0; }))
		return 1926;
	auto len = sys_name.size();
	for (size_t i = 0; i <= len; ++i) {
		if (sys_name[i] != '/' && sys_name[i] != '\0')
			continue;
		sys_name[i] = '\0';
		if (std::any_of(folder_list.cbegin(), folder_list.cend(),
		    [&](const enum_folder_t &e) { return strcasecmp(e.second.c_str(), sys_name.c_str()) == 0; })) {
			sys_name[i] = '/';
			continue;
		}
		std::string converted_name;
		if (!icp_imapfolder_to_sysfolder(sys_name.c_str(), converted_name))
			return 1800;
		ssr = midb_agent::make_folder(pcontext->maildir,
		      converted_name, &errnum);
		ret = m2icode(ssr, errnum);
		if (ret != 0)
			return ret;
		sys_name[i] = '/';
	}
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1706;
}

int icp_delete(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;
	std::string encoded_name;

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], encoded_name))
		return 1800;

	{
		std::vector<enum_folder_t> folder_list;
		auto ssr = midb_agent::enum_folders(pcontext->maildir,
			   folder_list, &errnum);
		auto ret = m2icode(ssr, errnum);
		if (ret != 0)
			return ret;
		icp_convert_folderlist(folder_list);
		dir_tree folder_tree;
		folder_tree.load_from_memfile(std::move(folder_list));
		auto dh = folder_tree.match(argv[2]);
		if (dh == nullptr)
			return 1925;
		if (folder_tree.get_child(dh) != nullptr)
			return 1924;
	}

	auto ssr = midb_agent::remove_folder(pcontext->maildir,
	           encoded_name, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1707;
}

int icp_rename(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;
	std::string encoded_name, encoded_name1;

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| 0 == strlen(argv[3]) || strlen(argv[3]) >= 1024)
		return 1800;
	if (!icp_imapfolder_to_sysfolder(argv[2], encoded_name) ||
	    !icp_imapfolder_to_sysfolder(argv[3], encoded_name1))
		return 1800;
	if (strpbrk(argv[3], "%*?") != nullptr)
		return 1910;
	auto ssr = midb_agent::rename_folder(pcontext->maildir,
	           encoded_name, encoded_name1, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1708;
}

int icp_subscribe(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;
	std::string sys_name;

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], sys_name))
		return 1800;
	auto ssr = midb_agent::subscribe_folder(pcontext->maildir,
	           sys_name, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1709;
}

int icp_unsubscribe(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;
	std::string sys_name;

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], sys_name))
		return 1800;
	auto ssr = midb_agent::unsubscribe_folder(pcontext->maildir,
	           sys_name, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1710;
}

int icp_list(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int errnum;
	
	if (!pcontext->is_authed())
		return 1804;
	/*
	 * Return option (list all folder and in doing so, yield special-use flags):
	 * 	LIST "" % RETURN (SPECIAL-USE)
	 *
	 * Selection option (list only special use folders):
	 * 	LIST (SPECIAL-USE) "" %
	 */
	if (argc < 3)
		return 1800;
	int apos = 2;
	auto filter_special = strcasecmp(argv[2], "(SPECIAL-USE)") == 0;
	if (filter_special)
		++apos;
	if (argc < apos + 2)
		return 1800;
	auto reference = argv[apos++];
	auto mboxname = argv[apos++];
	bool return_special = filter_special;
	if (argc >= apos + 2 && strcasecmp(argv[apos], "RETURN") == 0 &&
	    strcasecmp(argv[apos+1], "(SPECIAL-USE)") == 0)
		return_special = true;
	if (strlen(reference) + strlen(mboxname) >= 1024)
		return 1800;
	if (*mboxname == '\0') {
		if (pcontext->proto_stat == iproto_stat::select)
			imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170011: OK LIST completed */
		auto buf = fmt::format("* LIST (\\Noselect) \"/\" \"\"\r\n{} {}",
		           argv[0], resource_get_imap_code(1711, 1));
		imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
		return DISPATCH_CONTINUE;
	}

	auto search_pattern = std::string(reference) + mboxname;
	std::vector<enum_folder_t> folder_list;
	auto ssr = midb_agent::enum_folders(pcontext->maildir,
	           folder_list, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	icp_convert_folderlist(folder_list);
	dir_tree folder_tree;
	folder_tree.load_from_memfile(folder_list);
	pcontext->stream.clear();
	for (const auto &enf_entry : folder_list) {
		const auto &sys_name = enf_entry.second;
		auto special = special_folder(enf_entry.first);
		if (filter_special && !special)
			continue;
		if (!icp_wildcard_match(sys_name.c_str(), search_pattern.c_str()))
			continue;
		auto pdir = folder_tree.match(sys_name.c_str());
		auto have_cld = pdir != nullptr && folder_tree.get_child(pdir) != nullptr;
		auto buf = fmt::format("* LIST (\\Has{}Children{}{}) \"/\" {}\r\n",
		           have_cld ? "" : "No",
		           return_special && special != nullptr ? " " : "",
		           return_special && special != nullptr ? special->use_flags : "",
		           quote_encode(sys_name));
		if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
			return 1922;
	}
	folder_list.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170011: OK LIST completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1711, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int icp_xlist(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int errnum;
	
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4)
		return 1800;
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024)
		return 1800;
	std::string search_pattern = argv[2];
	search_pattern += *argv[3] == '\0' ? "*" : argv[3];
	std::vector<enum_folder_t> folder_list;
	auto ssr = midb_agent::enum_folders(pcontext->maildir,
	           folder_list, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	icp_convert_folderlist(folder_list);
	dir_tree folder_tree;
	folder_tree.load_from_memfile(folder_list);
	pcontext->stream.clear();

	for (const auto &fentry : folder_list) {
		const auto &sys_name = fentry.second;
		if (!icp_wildcard_match(sys_name.c_str(), search_pattern.c_str()))
			continue;
		auto special = special_folder(fentry.first);
		auto pdir = folder_tree.match(sys_name.c_str());
		auto have = pdir != nullptr && folder_tree.get_child(pdir) != nullptr;
		auto buf  = fmt::format("* XLIST (\\Has{}Children{}{}) \"/\" {}\r\n",
		            have ? "" : "No",
		            special != nullptr ? " " : "",
		            special != nullptr ? special->use_flags : "",
		            quote_encode(sys_name));
		if (pcontext->stream.write(buf.c_str(), buf.size()) != 0)
			return 1922;
	}
	folder_list.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170012: OK XLIST completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1712, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int icp_lsub(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int errnum;
	
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4)
		return 1800;
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024)
		return 1800;
	if ('\0' == argv[3][0]) {
		if (pcontext->proto_stat == iproto_stat::select)
			imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170011: OK LIST completed */
		auto buf = fmt::format("* LSUB (\\Noselect) \"/\" \"\"\r\n{} {}",
		           argv[0], resource_get_imap_code(1711, 1));
		imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
		return DISPATCH_CONTINUE;
	}
	auto search_pattern = std::string(argv[2]) + argv[3];
	std::vector<enum_folder_t> sub_list;
	auto ssr = midb_agent::enum_subscriptions(pcontext->maildir,
	           sub_list, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	icp_convert_folderlist(sub_list);
	std::vector<enum_folder_t> folder_list;
	midb_agent::enum_folders(pcontext->maildir, folder_list, &errnum);
	icp_convert_folderlist(folder_list);
	dir_tree folder_tree;
	folder_tree.load_from_memfile(folder_list);
	folder_list.clear();
	pcontext->stream.clear();

	for (const auto &fentry : sub_list) {
		const auto &sys_name = fentry.second;
		if (!icp_wildcard_match(sys_name.c_str(), search_pattern.c_str()))
			continue;
		auto pdir = folder_tree.match(sys_name.c_str());
		auto have = pdir != nullptr && folder_tree.get_child(pdir) != nullptr;
		auto buf  = fmt::format("* LSUB (\\Has{}Children) \"/\" {}\r\n",
		            have ? "" : "No", quote_encode(sys_name));
		if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
			return 1922;
	}
	sub_list.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170013: OK LSUB completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1713, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int icp_status(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int i;
	int errnum;
	BOOL b_first;
	int temp_argc;
	char *temp_argv[16];
	std::string sys_name;
    
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], sys_name) ||
	    argv[3][0] != '(' || argv[3][strlen(argv[3])-1] != ')')
		return 1800;
	temp_argc = parse_imap_args(argv[3] + 1,
		strlen(argv[3]) - 2, temp_argv, sizeof(temp_argv));
	if (temp_argc == -1)
		return 1800;

	size_t exists = 0, recent = 0, unseen = 0;
	uint32_t uidvalid = 0, uidnext = 0;
	auto ssr = midb_agent::summary_folder(pcontext->maildir, sys_name,
	           &exists, &recent, &unseen, &uidvalid, &uidnext, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	/* IMAP_CODE_2170014: OK STATUS completed */
	auto buf = fmt::format("* STATUS {} (", quote_encode(argv[2]));
	b_first = TRUE;
	for (i=0; i<temp_argc; i++) {
		if (!b_first)
			buf += ' ';
		else
			b_first = FALSE;
		if (strcasecmp(temp_argv[i], "MESSAGES") == 0)
			buf += fmt::format("MESSAGES {}", exists);
		else if (strcasecmp(temp_argv[i], "RECENT") == 0)
			buf += fmt::format("RECENT {}", recent);
		else if (strcasecmp(temp_argv[i], "UIDNEXT") == 0)
			buf += fmt::format("UIDNEXT {}", uidnext);
		else if (strcasecmp(temp_argv[i], "UIDVALIDITY") == 0)
			buf += fmt::format("UIDVALIDITY {}", uidvalid);
		else if (strcasecmp(temp_argv[i], "UNSEEN") == 0)
			buf += fmt::format("UNSEEN {}", unseen);
		else
			return 1800;
	}
	buf += ")\r\n";
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1714, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int icp_append(int argc, char **argv, imap_context &ctx) try
{
	if (!ctx.is_authed())
		return 1804;
	unsigned int uid;
	int errnum, i;
	int temp_argc;
	char* temp_argv[5];
	char *str_received = nullptr, *flags_string = nullptr;
	std::string sys_name;
	
	if (argc < 4 || argc > 6 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], sys_name))
		return 1800;
	if (6 == argc) {
		flags_string = argv[3];
		str_received = argv[4];
	} else if (5 == argc) {
		if (argv[3][0] == '(')
			flags_string = argv[3];
		else
			str_received = argv[3];
	} 
	std::string flag_buff = "()";
	if (NULL != flags_string) {
		if (flags_string[0] != '(' ||
		    flags_string[strlen(flags_string)-1] != ')')
			return 1800;
		temp_argc = parse_imap_args(flags_string + 1, strlen(flags_string) - 2,
		            temp_argv, sizeof(temp_argv));
		if (temp_argc == -1)
			return 1800;
		flag_buff = flagbits_to_s(
		            std::any_of(&temp_argv[0], &temp_argv[temp_argc],
		            [](const char *s) { return strcasecmp(s, "\\Answered") == 0; }),
		            std::any_of(&temp_argv[0], &temp_argv[temp_argc],
		            [](const char *s) { return strcasecmp(s, "\\Flagged") == 0; }),
		            std::any_of(&temp_argv[0], &temp_argv[temp_argc],
		            [](const char *s) { return strcasecmp(s, "\\Seen") == 0; }),
		            std::any_of(&temp_argv[0], &temp_argv[temp_argc],
		            [](const char *s) { return strcasecmp(s, "\\Draft") == 0; }));
	}
	std::string mid_string;
	time_t tmp_time = time(nullptr);
	if (str_received != nullptr &&
	    icp_convert_imaptime(str_received, &tmp_time)) {
		char txt[GUIDSTR_SIZE];
		GUID::random_new().to_str(txt, std::size(txt), 32);
		mid_string = fmt::format("{}.g{}", tmp_time, txt);
	} else {
		mid_string = fmt::format("{}.n{}", tmp_time,
			     imap_parser_get_sequence_ID());
	}
	mid_string += "."s + znul(g_config_file->get_value("host_id"));
	auto pcontext = &ctx;
	imrpc_build_env();
	auto cl_0 = make_scope_exit(imrpc_free_env);
	if (!exmdb_client::imapfile_write(ctx.maildir, "eml",
	    mid_string, argv[argc-1])) {
		mlog(LV_ERR, "E-1763: write %s/eml/%s failed", ctx.maildir, mid_string.c_str());
		return 1909;
	}

	auto ssr = midb_agent::insert_mail(pcontext->maildir, sys_name,
	           mid_string.c_str(), flag_buff.c_str(), tmp_time, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	imap_parser_log_info(pcontext, LV_DEBUG, "message %s is appended OK", mid_string.c_str());
	imap_parser_bcast_touch(nullptr, pcontext->username, pcontext->selected_folder);
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	auto imap_reply_str = resource_get_imap_code(1715, 1);
	auto imap_reply_str1 = resource_get_imap_code(1715, 2);
	std::string buf;
	for (i=0; i<10; i++) {
		// wait for midb's actions showing up... woah terrible
		uint32_t uidvalid = 0;
		if (midb_agent::summary_folder(pcontext->maildir,
		    sys_name, nullptr, nullptr, nullptr, &uidvalid, nullptr,
		    &errnum) == MIDB_RESULT_OK &&
		    midb_agent::get_uid(pcontext->maildir, sys_name,
		    mid_string.c_str(), &uid) == MIDB_RESULT_OK) {
			buf = fmt::format("{} {} [APPENDUID {} {}] {}",
			      argv[0], imap_reply_str, uidvalid,
			      uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (i == 10)
		buf = fmt::format("{} {} {}", argv[0], imap_reply_str,
		      imap_reply_str1);
	imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1456: ENOMEM");
	return 1918;
}

static inline bool is_flag_name(const char *flag)
{
	static constexpr const char *names[] = {"\\Answered", "\\Flagged", "\\Seen", "\\Draft"};
	for (auto s : names)
		if (strcasecmp(flag, s) == 0)
			return true;
	return false;
}

static int icp_append_begin2(int argc, char **argv, imap_context &ctx) try
{
	if (!ctx.is_authed())
		return 1804 | DISPATCH_BREAK;
	char *str_received = nullptr, *flags_string = nullptr;
	char* temp_argv[5];
	char str_flags[128];
	std::string sys_name;
	
	if (argc < 3 || argc > 5 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[2], sys_name))
		return 1800 | DISPATCH_BREAK;
	if (5 == argc) {
		flags_string = argv[3];
		str_received = argv[4];
	} else if (4 == argc) {
		if (argv[3][0] == '(')
			flags_string = argv[3];
		else
			str_received = argv[3];
	}
	if (NULL != flags_string) {
		gx_strlcpy(str_flags, flags_string, std::size(str_flags));
		if (flags_string[0] != '(' ||
		    flags_string[strlen(flags_string)-1] != ')')
			return 1800 | DISPATCH_BREAK;
		auto temp_argc = parse_imap_args(&flags_string[1],
		                 strlen(flags_string) - 2,
		                 temp_argv, std::size(temp_argv));
		if (temp_argc == -1)
			return 1800 | DISPATCH_BREAK;
		for (int i = 0; i < temp_argc; ++i)
			if (!is_flag_name(temp_argv[i]))
				return 1800 | DISPATCH_BREAK;
	}
	auto pcontext = &ctx;
	pcontext->mid = fmt::format("{}.{}.{}",
	                time(nullptr), imap_parser_get_sequence_ID(),
	                znul(g_config_file->get_value("host_id")));
	ctx.append_stream.clear();
	ctx.append_folder = sys_name;
	ctx.append_flags  = flagbits_to_s(
	                    strcasestr(str_flags, "\\Seen") != nullptr,
	                    strcasestr(str_flags, "\\Answered") != nullptr,
	                    strcasestr(str_flags, "\\Flagged") != nullptr,
	                    strcasestr(str_flags, "\\Draft") != nullptr);
	if (str_received == nullptr || *str_received == '\0' ||
	    !icp_convert_imaptime(str_received, &ctx.append_time))
		ctx.append_time = time(nullptr);
	gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
	pcontext->stream.clear();
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1918 | DISPATCH_BREAK;
}

int icp_append_begin(int argc, char **argv, imap_context &ctx)
{
	return icp_dval(argc, argv, ctx, icp_append_begin2(argc, argv, ctx));
}

static int icp_append_end2(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	std::string content;
	void *strb;
	unsigned int strb_size = STREAM_BLOCK_SIZE;
	ctx.append_stream.reset_reading();
	while ((strb = ctx.append_stream.get_read_buf(&strb_size)) != nullptr) {
		content.append(static_cast<char *>(strb), strb_size);
		strb_size = STREAM_BLOCK_SIZE;
	}
	imrpc_build_env();
	auto cl_0 = make_scope_exit(imrpc_free_env);
	if (!exmdb_client::imapfile_write(ctx.maildir, "eml",
	    ctx.mid, content)) {
		mlog(LV_ERR, "E-1764: write to %s/eml/%s failed",
			pcontext->maildir, pcontext->mid.c_str());
		return 1909 | DISPATCH_TAG;
	}

	int errnum;
	auto sys_name = ctx.append_folder.c_str();
	auto ssr = midb_agent::insert_mail(pcontext->maildir, sys_name,
	           pcontext->mid.c_str(), ctx.append_flags.c_str(),
	           ctx.append_time, &errnum);
	auto cmid = std::move(pcontext->mid);
	pcontext->mid.clear();
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret | DISPATCH_TAG;
	imap_parser_log_info(pcontext, LV_DEBUG, "message %s is appended OK", cmid.c_str());
	imap_parser_bcast_touch(nullptr, pcontext->username, pcontext->selected_folder);
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	auto imap_reply_str = resource_get_imap_code(1715, 1);
	auto imap_reply_str1 = resource_get_imap_code(1715, 2);
	std::string buf;
	unsigned int i;
	for (i=0; i<10; i++) {
		uint32_t uidvalid = 0;
		unsigned int uid = 0;
		if (midb_agent::summary_folder(pcontext->maildir,
		    sys_name, nullptr, nullptr, nullptr, &uidvalid,
		    nullptr, &errnum) == MIDB_RESULT_OK &&
		    midb_agent::get_uid(pcontext->maildir, sys_name,
		    cmid.c_str(), &uid) == MIDB_RESULT_OK) {
			buf = fmt::format("{} {} [APPENDUID {} {}] {}",
			      pcontext->tag_string, imap_reply_str, uidvalid,
			      uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (i == 10)
		buf = fmt::format("{} {} {}", pcontext->tag_string,
		      imap_reply_str, imap_reply_str1);
	imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1460: ENOMEM");
	return 1918;
}

int icp_append_end(int argc, char **argv, imap_context &ctx)
{
	return icp_dval(argc, argv, ctx, icp_append_end2(argc, argv, ctx));
}

int icp_check(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	imap_parser_echo_modify(pcontext, NULL);
	return 1716;
}

int icp_close(int argc, char **argv, imap_context &ctx)
{
	if (ctx.proto_stat != iproto_stat::select)
		return 1805;
	icp_clsfld(ctx);
	return 1717;
}

static bool zero_uid_bit(const MITEM &i)
{
	return i.uid == 0 || !(i.flag_bits & FLAG_DELETED);
}

int icp_expunge(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (pcontext->b_readonly)
		return 1806;
	XARRAY xarray;
	int errnum;
	auto ssr = midb_agent::list_deleted(pcontext->maildir,
	           pcontext->selected_folder, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	auto num = xarray.get_capacity();
	if (num == 0) {
		imap_parser_echo_modify(pcontext, nullptr);
		return 1726;
	}
	std::vector<MITEM *> exp_list;
	imrpc_build_env();
	auto cl_0 = make_scope_exit(imrpc_free_env);
	for (size_t i = 0; i < num; ++i) {
		auto pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem))
			continue;
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		exp_list.push_back(pitem);
	}
	ssr = midb_agent::remove_mail(pcontext->maildir,
	      pcontext->selected_folder, exp_list, &errnum);
	ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	pcontext->stream.clear();
	for (size_t i = 0; i < xarray.get_capacity(); ++i) {
		auto pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem))
			continue;
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		if (!exmdb_client::imapfile_delete(ctx.maildir, "eml", pitem->mid))
			mlog(LV_WARN, "W-2030: remove %s/eml/%s failed",
				ctx.maildir, pitem->mid.c_str());
		else
			imap_parser_log_info(pcontext, LV_DEBUG, "message %s has been deleted",
				pitem->mid.c_str());
	}
	if (!exp_list.empty())
		imap_parser_bcast_expunge(*pcontext, exp_list);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170026: OK EXPUNGE completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1726, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1246: ENOMEM");
	return 1918;
}

int icp_unselect(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = iproto_stat::auth;
	pcontext->selected_folder.clear();
	return 1718;
}

int icp_search(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 3 || argc > 1024)
		return 1800;
	std::string buff;
	auto ssr = midb_agent::search(pcontext->maildir,
	           pcontext->selected_folder, pcontext->defcharset,
	            argc - 2, &argv[2], buff, &errnum);
	buff.insert(0, "* SEARCH ");
	auto result = m2icode(ssr, errnum);
	if (result != 0)
		return result;
	buff.append("\r\n");
	pcontext->stream.clear();
	if (pcontext->stream.write(buff.c_str(), buff.size()) != STREAM_WRITE_OK)
		return 1922;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170019: OK SEARCH completed */
	buff = fmt::format("{} {}", argv[0], resource_get_imap_code(1719, 1));
	if (pcontext->stream.write(buff.c_str(), buff.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
}

/**
 * Convert sequence numbers to a UID list, resolving "*" along the way.
 *
 * @range_string:	sequence numbers, e.g. "1,2:3,4:*,*:5,*:*,*"
 * @uid_list:		split-up range
 */
static errno_t parse_imap_seqx(const imap_context &ctx, char *range_string,
    imap_seq_list &uid_list) try
{
	imap_seq_list seq_list;
	auto err = parse_imap_seq(seq_list, range_string);
	if (err != 0)
		return err;
	for (auto &seq : seq_list) {
		if (seq.lo == SEQ_STAR && seq.hi == SEQ_STAR) {
			/* MAX:MAX */
			seq.lo = seq.hi = ctx.contents.m_vec.size();
		} else if (seq.lo == SEQ_STAR) {
			/* MAX:99 = (99:MAX) */
			seq.lo = seq.hi;
			seq.hi = ctx.contents.m_vec.size();
		} else if (seq.hi == SEQ_STAR) {
			/* 99:MAX */
			seq.hi = ctx.contents.m_vec.size();
		}
		if (seq.lo < 1)
			seq.lo = 1;
		if (seq.hi > ctx.contents.m_vec.size())
			seq.hi = ctx.contents.m_vec.size();
		for (size_t i = seq.lo; i <= seq.hi; ++i) {
			auto uid = ctx.contents.m_vec[i-1].uid;
			uid_list.insert(uid);
		}
	}
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

static int fetch_trivial_uid(imap_context &ctx, const imap_seq_list &range_list,
    XARRAY &xa) try
{
	for (auto &range : range_list)
		for (unsigned int uid = range.lo; uid <= range.hi; ++uid) {
			auto mitem = ctx.contents.get_itemx(uid);
			if (mitem != nullptr)
				xa.append(MITEM{*mitem}, mitem->uid);
		}
	return 0;
} catch (const std::bad_alloc &) {
	return MIDB_LOCAL_ENOMEM;
}

int icp_fetch(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int i, num, errnum = 0;
	BOOL b_data;
	BOOL b_detail;
	char* tmp_argv[128];
	imap_seq_list list_uid;
	mdi_list list_data;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 4 || parse_imap_seqx(*pcontext, argv[2], list_uid) != 0)
		return 1800;
	if (!icp_parse_fetch_args(list_data, &b_detail,
	    &b_data, argv[3], tmp_argv, std::size(tmp_argv)))
		return 1800;
	XARRAY xarray;
	auto ssr = b_detail ?
	           midb_agent::fetch_detail_uid(pcontext->maildir,
	           pcontext->selected_folder, list_uid, &xarray, &errnum) :
	           fetch_trivial_uid(*pcontext, list_uid, xarray);
	auto result = m2icode(ssr, errnum);
	if (result != 0)
		return result;
	pcontext->stream.clear();
	num = xarray.get_capacity();
	imrpc_build_env();
	auto cl_0 = make_scope_exit(imrpc_free_env);
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		/*
		 * fetch_detail_uid might have yielded new mails, so filter
		 * with respect to current sequence assignment.
		 */
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		result = icp_process_fetch_item(ctx, b_data,
		         pitem, ct_item->id, list_data);
		if (result != 0)
			return result;
	}
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170020: OK FETCH completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1720, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	if (b_data) {
		pcontext->write_buff = pcontext->command_buffer;
		pcontext->sched_stat = isched_stat::wrdat;
	} else {
		pcontext->sched_stat = isched_stat::wrlst;
	}
	return DISPATCH_BREAK;
}

static bool store_flagkeyword(const char *str)
{
	static constexpr const char *names[] =
		{"FLAGS", "FLAGS.SILENT", "+FLAGS", "+FLAGS.SILENT",
		"-FLAGS", "-FLAGS.SILENT"};
	for (auto elem : names)
		if (strcasecmp(str, elem) == 0)
			return true;
	return false;
}

int icp_store(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum, i;
	int flag_bits;
	int temp_argc;
	char *temp_argv[8];
	imap_seq_list list_uid;

	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 5 || parse_imap_seqx(*pcontext, argv[2], list_uid) != 0 ||
	    !store_flagkeyword(argv[3]))
		return 1800;
	if ('(' == argv[4][0] && ')' == argv[4][strlen(argv[4]) - 1]) {
		temp_argc = parse_imap_args(argv[4] + 1, strlen(argv[4]) - 2,
		            temp_argv, std::size(temp_argv));
		if (temp_argc == -1)
			return 1800;
	} else {
		temp_argc = 1;
		temp_argv[0] = argv[4];
	}
	if (pcontext->b_readonly)
		return 1806;
	flag_bits = 0;
	for (i=0; i<temp_argc; i++) {
		if (strcasecmp(temp_argv[i], "\\Answered") == 0)
			flag_bits |= FLAG_ANSWERED;
		else if (strcasecmp(temp_argv[i], "\\Flagged") == 0)
			flag_bits |= FLAG_FLAGGED;
		else if (strcasecmp(temp_argv[i], "\\Deleted") == 0)
			flag_bits |= FLAG_DELETED;
		else if (strcasecmp(temp_argv[i], "\\Seen") == 0)
			flag_bits |= FLAG_SEEN;
		else if (strcasecmp(temp_argv[i], "\\Draft") == 0)
			flag_bits |= FLAG_DRAFT;
		else if (strcasecmp(temp_argv[i], "\\Recent") == 0)
			flag_bits |= FLAG_RECENT;			
		else
			return 1807;
	}
	XARRAY xarray;
	auto ssr = midb_agent::fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_uid, &xarray, &errnum);
	auto result = m2icode(ssr, errnum);
	if (result != 0)
		return result;
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		icp_store_flags(argv[3], pitem->mid,
			ct_item->id, 0, flag_bits, ctx);
		imap_parser_bcast_flags(*pcontext, pitem->uid);
	}
	imap_parser_echo_modify(pcontext, NULL);
	return 1721;
}

int icp_copy(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	unsigned int uid;
	int errnum;
	BOOL b_first;
	BOOL b_copied;
	int i, j;
	std::string sys_name;
	imap_seq_list list_uid;
    
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 4 || parse_imap_seqx(*pcontext, argv[2], list_uid) != 0 ||
	    strlen(argv[3]) == 0 || strlen(argv[3]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[3], sys_name))
		return 1800;
	XARRAY xarray;
	auto ssr = midb_agent::fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_uid, &xarray, &errnum);
	auto result = m2icode(ssr, errnum);
	if (result != 0)
		return result;
	uint32_t uidvalidity = 0;
	if (midb_agent::summary_folder(pcontext->maildir,
	    sys_name, nullptr, nullptr, nullptr, &uidvalidity, nullptr,
	    &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	int num = xarray.get_capacity();
	std::string uid_string, uid_string1;
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		pitem = pcontext->contents.get_itemx(pitem->uid);
		if (pitem == nullptr)
			continue;
		if (midb_agent::copy_mail(pcontext->maildir,
		    pcontext->selected_folder, pitem->mid, sys_name,
		    pitem->mid, &errnum) != MIDB_RESULT_OK) {
			b_copied = FALSE;
			break;
		}
		if (uidvalidity == 0)
			continue;
		for (j = 0; j < 10; j++) {
			if (midb_agent::get_uid(pcontext->maildir,
			    sys_name, pitem->mid, &uid) != MIDB_RESULT_OK) {
				usleep(500000);
				continue;
			}
			if (b_first) {
				uid_string += ',';
				uid_string1 += ',';
			} else {
				b_first =  TRUE;
			}
			uid_string += std::to_string(pitem->uid);
			uid_string1 += std::to_string(uid);
			break;
		}
		if (j == 10)
			uidvalidity = 0;
	}
	if (!b_copied) {
		std::vector<MITEM *> exp_list;
		for (;i>0; i--) {
			auto pitem = xarray.get_item(i - 1);
			if (pitem->uid == 0)
				continue;
			exp_list.push_back(pitem);
		}
		midb_agent::remove_mail(pcontext->maildir,
			sys_name, exp_list, &errnum);
	}
	pcontext->stream.clear();
	std::string buf;
	if (b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170022: OK <COPYUID> COPY completed */
		auto imap_reply_str = resource_get_imap_code(1722, 1);
		auto imap_reply_str1 = resource_get_imap_code(1722, 2);
		if (uidvalidity != 0)
			buf = fmt::format("{} {} [COPYUID {} {} {}] {}",
			      argv[0], imap_reply_str, uidvalidity,
			      uid_string, uid_string1, imap_reply_str1);
		else
			buf = fmt::format("{} {} {}", argv[0],
			      imap_reply_str, imap_reply_str1);
	} else {
		/* IMAP_CODE_2190016: NO COPY failed */
		buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1916, 1));
	}
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1245: ENOMEM");
	return 1918;
}

int icp_uid_search(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int errnum;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 3 || argc > 1024)
		return 1800;
	std::string buff;
	auto ssr = midb_agent::search_uid(pcontext->maildir,
	           pcontext->selected_folder, pcontext->defcharset,
	           argc - 3, &argv[3], buff, &errnum);
	buff.insert(0, "* SEARCH ");
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	buff.append("\r\n");
	pcontext->stream.clear();
	if (pcontext->stream.write(buff.c_str(), buff.size()) != STREAM_WRITE_OK)
		return 1922;
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170023: OK UID SEARCH completed */
	buff = fmt::format("{} {}", argv[0], resource_get_imap_code(1723, 1));
	if (pcontext->stream.write(buff.c_str(), buff.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2396: ENOMEM");
	return 1918;
}

int icp_uid_fetch(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int num;
	int errnum;
	int i;
	BOOL b_data;
	BOOL b_detail;
	char* tmp_argv[128];
	imap_seq_list list_seq;
	mdi_list list_data;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 5 || parse_imap_seq(list_seq, argv[3]) != 0)
		return 1800;
	if (!icp_parse_fetch_args(list_data, &b_detail,
	    &b_data, argv[4], tmp_argv, std::size(tmp_argv)))
		return 1800;
	if (std::none_of(list_data.cbegin(), list_data.cend(),
	    [](const std::string &e) { return strcasecmp(e.c_str(), "UID") == 0; }))
		list_data.emplace_back("UID");
	XARRAY xarray;
	auto ssr = b_detail ?
	           midb_agent::fetch_detail_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum) :
	           midb_agent::fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	pcontext->stream.clear();
	num = xarray.get_capacity();
	imrpc_build_env();
	auto cl_0 = make_scope_exit(imrpc_free_env);
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		ret = icp_process_fetch_item(ctx, b_data,
		      pitem, ct_item->id, list_data);
		if (ret != 0)
			return ret;
	}
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170028: OK UID FETCH completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1728, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	if (b_data) {
		pcontext->write_buff = pcontext->command_buffer;
		pcontext->sched_stat = isched_stat::wrdat;
	} else {
		pcontext->sched_stat = isched_stat::wrlst;
	}
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2397: ENOMEM");
	return 1918;
}

int icp_uid_store(int argc, char **argv, imap_context &ctx)
{
	auto pcontext = &ctx;
	int errnum, i, flag_bits, temp_argc;
	char *temp_argv[8];
	imap_seq_list list_seq;

	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 6 || parse_imap_seq(list_seq, argv[3]) != 0 ||
	    !store_flagkeyword(argv[4]))
		return 1800;
	if ('(' == argv[5][0] && ')' == argv[5][strlen(argv[5]) - 1]) {
		temp_argc = parse_imap_args(argv[5] + 1, strlen(argv[5]) - 2,
		            temp_argv, std::size(temp_argv));
		if (temp_argc == -1)
			return 1800;
	} else {
		temp_argc = 1;
		temp_argv[0] = argv[5];
	}
	if (pcontext->b_readonly)
		return 1806;
	flag_bits = 0;
	for (i=0; i<temp_argc; i++) {
		if (strcasecmp(temp_argv[i], "\\Answered") == 0)
			flag_bits |= FLAG_ANSWERED;
		else if (strcasecmp(temp_argv[i], "\\Flagged") == 0)
			flag_bits |= FLAG_FLAGGED;
		else if (strcasecmp(temp_argv[i], "\\Deleted") == 0)
			flag_bits |= FLAG_DELETED;
		else if (strcasecmp(temp_argv[i], "\\Seen") == 0)
			flag_bits |= FLAG_SEEN;
		else if (strcasecmp(temp_argv[i], "\\Draft") == 0)
			flag_bits |= FLAG_DRAFT;
		else if (strcasecmp(temp_argv[i], "\\Recent") == 0)
			flag_bits |= FLAG_RECENT;			
		else
			return 1807;
	}
	XARRAY xarray;
	auto ssr = midb_agent::fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		icp_store_flags(argv[4], pitem->mid,
			ct_item->id, pitem->uid, flag_bits, ctx);
		imap_parser_bcast_flags(*pcontext, pitem->uid);
	}
	imap_parser_echo_modify(pcontext, NULL);
	return 1724;
}

int icp_uid_copy(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	unsigned int uid;
	int errnum;
	BOOL b_first;
	BOOL b_copied;
	int i, j;
	std::string sys_name;
	imap_seq_list list_seq;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 5 || parse_imap_seq(list_seq, argv[3]) != 0 ||
	    strlen(argv[4]) == 0 || strlen(argv[4]) >= 1024 ||
	    !icp_imapfolder_to_sysfolder(argv[4], sys_name))
		return 1800;
	XARRAY xarray;
	auto ssr = midb_agent::fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	uint32_t uidvalidity = 0;
	if (midb_agent::summary_folder(pcontext->maildir,
	    sys_name, nullptr, nullptr, nullptr, &uidvalidity,
	    nullptr, &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	int num = xarray.get_capacity();
	std::string uid_string;
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		if (midb_agent::copy_mail(pcontext->maildir,
		    pcontext->selected_folder, pitem->mid, sys_name,
		    pitem->mid, &errnum) != MIDB_RESULT_OK) {
			b_copied = FALSE;
			break;
		}
		if (uidvalidity == 0)
			continue;
		for (j = 0; j < 10; j++) {
			if (midb_agent::get_uid(pcontext->maildir,
			    sys_name, pitem->mid, &uid) != MIDB_RESULT_OK) {
				usleep(500000);
				continue;
			}
			if (b_first)
				uid_string += ',';
			else
				b_first =  TRUE;
			uid_string += std::to_string(uid);
			break;
		}
		if (j == 10)
			uidvalidity = 0;
	}
	if (!b_copied) {
		std::vector<MITEM *> exp_list;
		for (;i>0; i--) {
			auto pitem = xarray.get_item(i - 1);
			if (pitem->uid == 0)
				continue;
			exp_list.push_back(pitem);
		}
		midb_agent::remove_mail(pcontext->maildir,
			sys_name, exp_list, &errnum);
	}
	pcontext->stream.clear();
	std::string buf;
	if (b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170025: OK <COPYUID> UID COPY completed */
		auto imap_reply_str = resource_get_imap_code(1725, 1);
		auto imap_reply_str1 = resource_get_imap_code(1725, 2);
		if (uidvalidity != 0)
			buf = fmt::format("{} {} [COPYUID {} {} {}] {}", argv[0],
				imap_reply_str, uidvalidity, argv[3],
				uid_string, imap_reply_str1);
		else
			buf = fmt::format("{} {} {}", argv[0], imap_reply_str,
			      imap_reply_str1);
	} else {
		/* IMAP_CODE_2190017: NO UID COPY failed */
		buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1917, 1));
	}
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1244: ENOMEM");
	return 1918;
}

int icp_uid_expunge(int argc, char **argv, imap_context &ctx) try
{
	auto pcontext = &ctx;
	int errnum;
	int max_uid;
	imap_seq_list list_seq;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (pcontext->b_readonly)
		return 1806;
	if (argc < 4 || parse_imap_seq(list_seq, argv[3]) != 0)
		return 1800;
	XARRAY xarray;
	auto ssr = midb_agent::list_deleted(pcontext->maildir,
	           pcontext->selected_folder, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	auto num = xarray.get_capacity();
	if (0 == num) {
		imap_parser_echo_modify(pcontext, nullptr);
		return 1730;
	}
	auto pitem = xarray.get_item(num - 1);
	max_uid = pitem->uid;
	std::vector<MITEM *> exp_list;
	imrpc_build_env();
	auto cl_0 = make_scope_exit(imrpc_free_env);
	for (size_t i = 0; i < num; ++i) {
		pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem) ||
		    !iseq_contains(list_seq, pitem->uid, max_uid))
			continue;
		exp_list.push_back(pitem);
	}
	ssr = midb_agent::remove_mail(pcontext->maildir,
	      pcontext->selected_folder, exp_list, &errnum);
	ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	pcontext->stream.clear();
	for (size_t i = 0; i < xarray.get_capacity(); ++i) {
		pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem) ||
		    !iseq_contains(list_seq, pitem->uid, max_uid))
			continue;
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		if (!exmdb_client::imapfile_delete(ctx.maildir, "eml", pitem->mid))
			mlog(LV_WARN, "W-2086: remove %s/eml/%s failed",
				ctx.maildir, pitem->mid.c_str());
		else
			imap_parser_log_info(pcontext, LV_DEBUG, "message %s has been deleted",
				pitem->mid.c_str());
	}
	if (!exp_list.empty())
		imap_parser_bcast_expunge(*pcontext, exp_list);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170026: OK UID EXPUNGE completed */
	auto buf = fmt::format("{} {}", argv[0], resource_get_imap_code(1726, 1));
	if (pcontext->stream.write(buf.c_str(), buf.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1243: ENOMEM");
	return 1918;
}

void icp_clsfld(imap_context &ctx) try
{
	auto pcontext = &ctx;
	int errnum, result, i;
	BOOL b_deleted;
	std::string prev_selected;
	
	if (pcontext->selected_folder.empty())
		return;
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = iproto_stat::auth;
	prev_selected = std::move(pcontext->selected_folder);
	pcontext->selected_folder.clear();
	if (pcontext->b_readonly)
		return;
	XARRAY xarray;
	result = midb_agent::list_deleted(pcontext->maildir,
	         prev_selected, &xarray, &errnum);
	std::string buf;
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		buf = fmt::format("* {}", resource_get_imap_code(1905, 1));
		break;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		buf = fmt::format("* {}", resource_get_imap_code(1906, 1));
		break;
	case MIDB_LOCAL_ENOMEM:
		buf = fmt::format("* {}", resource_get_imap_code(1920, 1));
		break;
	default:
		/* IMAP_CODE_2190007: NO server internal error, */
		buf = fmt::format("* {}{}", resource_get_imap_code(1907, 1),
		      resource_get_error_string(errnum));
		break;
	}
	if (result != MIDB_RESULT_OK) {
		imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
		return;
	}
	b_deleted = FALSE;
	int num = xarray.get_capacity();
	std::vector<MITEM *> exp_list;
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem))
			continue;
		exp_list.push_back(pitem);
	}
	result = midb_agent::remove_mail(pcontext->maildir,
	         prev_selected, exp_list, &errnum);
	switch(result) {
	case MIDB_RESULT_OK: {
		imrpc_build_env();
		auto cl_0 = make_scope_exit(imrpc_free_env);
		for (i = 0; i < num; ++i) {
			auto pitem = xarray.get_item(i);
			if (zero_uid_bit(*pitem))
				continue;
			if (!exmdb_client::imapfile_delete(ctx.maildir, "eml", pitem->mid))
				mlog(LV_WARN, "W-2087: remove %s/eml/%s failed",
				        ctx.maildir, pitem->mid.c_str());
			else
				imap_parser_log_info(pcontext, LV_DEBUG,
					"message %s has been deleted", pitem->mid.c_str());
			b_deleted = TRUE;
		}
		break;
	}
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		buf = fmt::format("* {}", resource_get_imap_code(1905, 1));
		break;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		buf = fmt::format("* {}", resource_get_imap_code(1906, 1));
		break;
	case MIDB_LOCAL_ENOMEM:
		buf = fmt::format("* {}", resource_get_imap_code(1920, 1));
		break;
	default:
		/* IMAP_CODE_2190007: NO server internal error, */
		buf = fmt::format("* {}{}", resource_get_imap_code(1907, 1),
		      resource_get_error_string(errnum));
		break;
	}
	if (result != MIDB_RESULT_OK) {
		imap_parser_safe_write(pcontext, buf.c_str(), buf.size());
		return;
	}
	if (b_deleted)
		imap_parser_bcast_touch(pcontext,
			pcontext->username, prev_selected);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1242: ENOMEM");
}

/**
 * Helper function. Takes a multi-purpose dispatch return code
 * (imap_cmd_parser.h), "unpacks" it, possibly sends a response line to the
 * client before yielding the unpacked dispatch action.
 */
int icp_dval(int argc, char **argv, imap_context &ctx, unsigned int ret)
{
	auto code = ret & DISPATCH_VALMASK;
	if (code == 0)
		return ret & DISPATCH_ACTMASK;
	bool trycreate = code == MIDB_E_NO_FOLDER_TRYCREATE;
	auto estr = (ret & DISPATCH_MIDB) ? resource_get_error_string(code) : nullptr;
	if (ret & DISPATCH_MIDB)
		code = 1907;
	auto str = resource_get_imap_code(code, 1);
	char buff[1024];
	const char *tag = (ret & DISPATCH_TAG) ? tag_or_bug(ctx.tag_string) :
	                  argc == 0 ? "*" : tag_or_bug(argv[0]);
	if (trycreate && strncmp(str, "NO ", 3) == 0)
		str += 2; /* avoid double NO */
	auto len = gx_snprintf(buff, std::size(buff), "%s%s %s%s", tag,
	      trycreate ? " NO [TRYCREATE]" : "", str, znul(estr));
	imap_parser_safe_write(&ctx, buff, len);
	return ret & DISPATCH_ACTMASK;
}
