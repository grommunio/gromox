// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
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
#include <gromox/mjson.hpp>
#include <gromox/range_set.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>
#include "imap.hpp"
#include "../midb_agent.hpp"
#define MAX_DIGLEN		256*1024

using namespace std::string_literals;
using namespace gromox;
namespace exmdb_client = exmdb_client_remote;
using LLU = unsigned long long;
using mdi_list = std::vector<std::string>; /* message data item (RFC 3501 §6.4.5) */

namespace {

struct dir_tree {
	dir_tree(alloc_limiter<DIR_NODE> *);
	~dir_tree();
	void load_from_memfile(const std::vector<std::string> &);
	DIR_NODE *match(const char *path);
	static DIR_NODE *get_child(DIR_NODE *);

	SIMPLE_TREE tree{};
	alloc_limiter<DIR_NODE> *ppool = nullptr;
};
using DIR_TREE = dir_tree;
using DIR_TREE_ENUM = void (*)(DIR_NODE *, void*);

enum {
	TYPE_WILDS = 1,
	TYPE_WILDP
};

}

static constexpr const char *g_folder_list[] = {"draft", "sent", "trash", "junk"};
/* RFC 6154 says \Junk, but Thunderbird evaluates \Spam */
static constexpr const char *g_xproperty_list[] = {"\\Drafts", "\\Sent", "\\Trash", "\\Junk \\Spam"};

static void dir_tree_enum_delete(SIMPLE_TREE_NODE *pnode)
{
	auto pdir = static_cast<DIR_NODE *>(pnode->pdata);
	pdir->ppool->put(pdir);
}

dir_tree::dir_tree(alloc_limiter<DIR_NODE> *a) : ppool(a)
{}

void dir_tree::load_from_memfile(const std::vector<std::string> &pfile)
{
	auto ptree = this;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];
	SIMPLE_TREE_NODE *pnode, *pnode_parent;

	auto proot = ptree->tree.get_root();
	if (NULL == proot) {
		auto pdir = ptree->ppool->get();
		pdir->node.pdata = pdir;
		pdir->name[0] = '\0';
		pdir->b_loaded = TRUE;
		pdir->ppool = ptree->ppool;
		ptree->tree.set_root(&pdir->node);
		proot = &pdir->node;
	}

	for (const auto &pfile_path : pfile) {
		gx_strlcpy(temp_path, pfile_path.c_str(), std::size(temp_path));
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
					if (strcmp(pdir->name, ptr1) == 0)
						break;
				} while ((pnode = pnode->get_sibling()) != nullptr);
			}

			if (NULL == pnode) {
				auto pdir = ptree->ppool->get();
				pdir->node.pdata = pdir;
				gx_strlcpy(pdir->name, ptr1, std::size(pdir->name));
				pdir->b_loaded = FALSE;
				pdir->ppool = ptree->ppool;
				pnode = &pdir->node;
				ptree->tree.add_child(pnode_parent, pnode,
					SIMPLE_TREE_ADD_LAST);
			}
			ptr1 = ptr2 + 1;
		}
		static_cast<DIR_NODE *>(pnode->pdata)->b_loaded = TRUE;
	}
}

static void dir_tree_clear(DIR_TREE *ptree)
{
	auto pnode = ptree->tree.get_root();
	if (pnode != nullptr)
		ptree->tree.destroy_node(pnode, dir_tree_enum_delete);
}

DIR_NODE *dir_tree::match(const char *path)
{
	auto ptree = this;
	int len;
	DIR_NODE *pdir = nullptr;
	char *ptr1, *ptr2;
	char temp_path[4096 + 1];

	auto pnode = ptree->tree.get_root();
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
	while ((ptr2 = strchr(ptr1, '/')) != NULL) {
		*ptr2 = '\0';
		pnode = pnode->get_child();
		if (pnode == nullptr)
			return NULL;
		do {
			pdir = static_cast<DIR_NODE *>(pnode->pdata);
			if (strcmp(pdir->name, ptr1) == 0)
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
	auto pnode = pdir->node.get_child();
	return pnode != nullptr ? static_cast<DIR_NODE *>(pnode->pdata) : nullptr;
}

dir_tree::~dir_tree()
{
	auto ptree = this;
	dir_tree_clear(ptree);
	ptree->tree.clear();
	ptree->ppool = NULL;
}

static inline bool special_folder(const char *name)
{
	if (strcasecmp(name, "inbox") == 0)
		return true;
	for (auto s : g_folder_list)
		if (strcmp(name, s) == 0)
			return true;
	return false;
}

static BOOL icp_hint_seq(const imap_seq_list &list,
	unsigned int num, unsigned int max_uid)
{
	for (const auto &seq : list) {
		if (seq.hi == SEQ_STAR) {
			if (seq.lo == SEQ_STAR) {
				if (num == max_uid)
					return TRUE;
			} else {
				if (num >= seq.lo)
					return TRUE;
			}
		} else {
			if (seq.hi >= num && seq.lo <= num)
				return TRUE;
		}
	}
	return FALSE;
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

static BOOL imap_cmd_parser_parse_fetch_args(mdi_list &plist,
    BOOL *pb_detail, BOOL *pb_data, char *string, char **argv, int argc) try
{
	int count;
	char *ptr;
	char *ptr1;
	char *pend;
	int result;
	BOOL b_macro;
	int tmp_argc;
	char *last_ptr;
	char buff[1024];
	char temp_buff[1024];
	char* tmp_argv1[128];

	if ('(' == string[0]) {
		if (')' != string[strlen(string) - 1]) {
			return FALSE;
		}
		tmp_argc = parse_imap_args(string + 1,
			strlen(string) - 2, argv, argc);
	} else {
		tmp_argc = parse_imap_args(string, strlen(string), argv, argc);
	}
	if (tmp_argc < 1)
		return FALSE;
	b_macro = FALSE;
	for (int i = 0; i < tmp_argc; ++i) {
		if (std::find_if(plist.cbegin(), plist.cend(),
		    [&](const std::string &e) { return strcasecmp(e.c_str(), argv[i]) == 0; }) != plist.cend())
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
			pend = strchr(argv[i], ']');
			if (pend == nullptr)
				return FALSE;
			ptr = strchr(argv[i], '[') + 1;
			last_ptr = ptr;
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
			ptr1 = NULL;
			if ('\0' != *ptr) {
				pend = strchr(ptr + 1, '>');
				if (*ptr != '<' || pend == nullptr || pend[1] != '\0')
					return FALSE;
				ptr ++;
				count = 0;
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
				if(0 == strcasecmp(kw, "FULL")) {
					plist.emplace_back("BODY");
				}
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
			if (search_string(kw, "FIELDS", strlen(kw)) == nullptr)
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
	mlog(LV_ERR, "E-1271: ENOMEM");
	return false;
}

static void imap_cmd_parser_convert_flags_string(int flag_bits, char *flags_string)
{
	int len;
	BOOL b_first;
	
	flags_string[0] = '(';
	b_first = FALSE;
	len = 1;
	if (flag_bits & FLAG_RECENT) {
		len += sprintf(flags_string + len, "\\Recent");
		b_first = TRUE;
	}
	if (flag_bits & FLAG_ANSWERED) {
		if (b_first) {
			flags_string[len++] = ' ';
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Answered");
	}
	if (flag_bits & FLAG_FLAGGED) {
		if (b_first) {
			flags_string[len++] = ' ';
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Flagged");
	}
	if (flag_bits & FLAG_DELETED) {
		if (b_first) {
			flags_string[len++] = ' ';
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Deleted");
	}
	if (flag_bits & FLAG_SEEN) {
		if (b_first) {
			flags_string[len++] = ' ';
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Seen");
	}
	if (flag_bits & FLAG_DRAFT) {
		if (b_first) {
			flags_string[len++] = ' ';
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Draft");
	}
	flags_string[len] = ')';
	flags_string[len + 1] = '\0';
}

static int imap_cmd_parser_match_field(const char *cmd_tag,
	const char *file_path, size_t offset, size_t length, BOOL b_not,
    const char *tags, size_t offset1, ssize_t length1, char *value,
    size_t val_len) try
{
	int i;
	BOOL b_hit;
	int tmp_argc, fd;
	char* tmp_argv[128];
	char buff[128*1024];
	char temp_buff[1024];
	MIME_FIELD mime_field;

	auto pbody = strchr(cmd_tag, '[');
	if (length > 128 * 1024)
		return -1;
	fd = open(file_path, O_RDONLY);
	if (fd == -1)
		return -1;
	if (lseek(fd, offset, SEEK_SET) < 0)
		mlog(LV_ERR, "E-1431: lseek: %s", strerror(errno));
	gx_strlcpy(temp_buff, tags, std::size(temp_buff));
	if (tags[0] == '(')
		tmp_argc = parse_imap_args(temp_buff + 1,
			strlen(tags) - 2, tmp_argv, sizeof(tmp_argv));
	else
		tmp_argc = parse_imap_args(temp_buff,
			strlen(tags), tmp_argv, sizeof(tmp_argv));

	auto ret = read(fd, buff, length);
	if (ret < 0 || static_cast<size_t>(ret) != length) {
		close(fd);
		return -1;
	}
	close(fd);
	size_t len, buff_len = 0;
	std::string buff1;
	while ((len = parse_mime_field(buff + buff_len, length - buff_len,
	       &mime_field)) != 0) {
		b_hit = FALSE;
		for (i=0; i<tmp_argc; i++) {
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
	if (-1 == length1) {
		length1 = len1;
	}
	int l2;
	if (offset1 >= len1) {
		l2 = gx_snprintf(value, val_len, "BODY%s NIL", pbody);
	} else {
		if (offset1 + length1 > len1)
			length1 = len1 - offset1;
		l2 = gx_snprintf(value, val_len,
		     "BODY%s {%zd}\r\n%s", pbody, length1, &buff1[offset1]);
	}
	return l2 >= 0 && static_cast<size_t>(l2) >= val_len - 1 ? -1 : l2;
} catch (const std::bad_alloc &) {
	return -1;
}

static int imap_cmd_parser_print_structure(IMAP_CONTEXT *pcontext, MJSON *pjson,
    const std::string &cmd_tag, char *buff, int max_len, const char *pbody,
    const char *temp_id, const char *temp_tag, size_t offset, ssize_t length,
	const char *storage_path)
{
	int len;
	BOOL b_not;
	int buff_len;
	int part_type;
	size_t temp_len;
	MJSON_MIME *pmime;
	
	buff_len = 0;
	if (NULL == temp_tag) {
		pmime = pjson->get_mime(temp_id);
		/* Non-[MIME-IMB] messages, and non-multipart
		   [MIME-IMB] messages with no encapsulated
		   message, only have a part 1
		*/
		if (pmime == nullptr && strcmp(temp_id, "1") == 0)
			pmime = pjson->get_mime("");
		if (NULL != pmime) {
			if (0 == strcmp(temp_id, "")) {
				part_type = MJSON_MIME_ENTIRE;
				temp_len = pmime->get_offset(MJSON_MIME_HEAD);
			} else {
				part_type = MJSON_MIME_CONTENT;
				temp_len = pmime->get_offset(MJSON_MIME_CONTENT);
			}
			if (length == -1)
				length = pmime->get_length(part_type);
			if (offset >= pmime->get_length(part_type)) {
				buff_len += gx_snprintf(buff + buff_len,
					max_len - buff_len, "BODY%s NIL", pbody);
			} else {
				if (offset + length > pmime->get_length(part_type))
					length = pmime->get_length(part_type) - offset;
				if (storage_path == nullptr)
					buff_len += gx_snprintf(buff + buff_len, max_len - buff_len,
					            "BODY%s {%zd}\r\n<<{file}%s|%zd|%zd\r\n", pbody,
					            length, pjson->get_mail_filename(),
							temp_len + offset, length);
				else
					buff_len += gx_snprintf(buff + buff_len, max_len - buff_len,
					            "BODY%s {%zd}\r\n<<{rfc822}%s/%s|%zd|%zd\r\n",
								pbody, length, storage_path,
					            pjson->get_mail_filename(),
								temp_len + offset, length);
			}
		} else {
			buff_len += gx_snprintf(buff + buff_len,
				max_len - buff_len, "BODY%s NIL", pbody);
		}
	} else if (strcasecmp("MIME", temp_tag + 1) == 0 ||
	    strcasecmp("HEADER", temp_tag + 1) == 0) {
		if ((0 == strcasecmp("MIME", temp_tag + 1)
		    && 0 == strcmp(temp_id, "")) ||
		    (0 == strcasecmp("HEADER", temp_tag + 1)
		    && 0 != strcmp(temp_id, ""))) {
			buff_len += gx_snprintf(buff + buff_len,
				max_len - buff_len, "BODY%s NIL", pbody);
		} else if ((pmime = pjson->get_mime(temp_id)) != nullptr) {
			if (length == -1)
				length = pmime->get_length(MJSON_MIME_HEAD);
			if (offset >= pmime->get_length(MJSON_MIME_HEAD)) {
				buff_len += gx_snprintf(buff + buff_len,
					    max_len - buff_len, "BODY%s NIL", pbody);
			} else {
				if (offset + length > pmime->get_length(MJSON_MIME_HEAD))
					length = pmime->get_length(MJSON_MIME_HEAD) - offset;
				if (storage_path == nullptr)
					buff_len += gx_snprintf(
						    buff + buff_len, max_len - buff_len,
						    "BODY%s {%zd}\r\n<<{file}%s|%zd|%zd\r\n",
						    pbody, length, pjson->get_mail_filename(),
						    pmime->get_offset(MJSON_MIME_HEAD)
						    + offset, length);
				else
					buff_len += gx_snprintf(
						    buff + buff_len, max_len - buff_len,
						    "BODY%s {%zd}\r\n<<{rfc822}%s/%s|%zd|%zd\r\n",
						    pbody, length, storage_path,
						    pjson->get_mail_filename(),
						    pmime->get_offset(MJSON_MIME_HEAD)
						    + offset, length);
			}
		} else {
			buff_len += gx_snprintf(buff + buff_len,
				    max_len - buff_len, "BODY%s NIL", pbody);
		}
	} else if (0 == strcasecmp("TEXT", temp_tag + 1)) {
		if (0 != strcmp(temp_id, "")) {
			buff_len += gx_snprintf(buff + buff_len,
			            max_len - buff_len, "BODY%s NIL", pbody);
		} else if ((pmime = pjson->get_mime(temp_id)) != nullptr) {
			if (length == -1)
				length = pmime->get_length(MJSON_MIME_CONTENT);
			if (offset >= pmime->get_length(MJSON_MIME_CONTENT)) {
				buff_len += gx_snprintf(buff + buff_len,
					    max_len - buff_len, "BODY%s NIL", pbody);
			} else {
				if (offset + length > pmime->get_length(MJSON_MIME_CONTENT))
					length = pmime->get_length(MJSON_MIME_CONTENT) - offset;
				if (storage_path == nullptr)
					buff_len += gx_snprintf(
						    buff + buff_len, max_len - buff_len,
						    "BODY%s {%zd}\r\n<<{file}%s|%zd|%zd\r\n",
						    pbody, length, pjson->get_mail_filename(),
						    pmime->get_offset(MJSON_MIME_CONTENT)
						    + offset, length);
				else
					buff_len += gx_snprintf(
						    buff + buff_len, max_len - buff_len,
						    "BODY%s {%zd}\r\n<<{rfc822}%s/%s|%zd|%zd\r\n",
						    pbody, length, storage_path,
						    pjson->get_mail_filename(),
						    pmime->get_offset(MJSON_MIME_CONTENT)
						    + offset, length);
			}
		} else {
			buff_len += gx_snprintf(buff + buff_len,
			            max_len - buff_len, "BODY%s NIL", pbody);
		}
	} else if (strcmp(temp_id, "") != 0) {
		buff_len += gx_snprintf(buff + buff_len,
			    max_len - buff_len, "BODY%s NIL", pbody);
	} else {
		if (0 == strncasecmp(temp_tag + 1, "HEADER.FIELDS ", 14)) {
			temp_tag += 15;
			b_not = FALSE;
		} else {
			temp_tag += 19;
			b_not = TRUE;
		}
		pmime = pjson->get_mime(temp_id);
		if (NULL != pmime) {
			std::string eml_path;
			try {
				eml_path = storage_path == nullptr ?
				           std::string(pcontext->maildir) + "/eml/" + pjson->get_mail_filename() :
				           std::string(pcontext->maildir) + "/tmp/imap.rfc822/" + storage_path + "/" + pjson->get_mail_filename();
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1465: ENOMEM");
			}

			len = imap_cmd_parser_match_field(cmd_tag.c_str(), eml_path.c_str(),
			      pmime->get_offset(MJSON_MIME_HEAD),
			      pmime->get_length(MJSON_MIME_HEAD),
			      b_not, temp_tag, offset, length, buff + buff_len,
			      max_len - buff_len);
			if (len == -1)
				buff_len += gx_snprintf(buff + buff_len,
					    max_len - buff_len, "BODY%s NIL", pbody);
			else
				buff_len += len;
		} else {
			buff_len += gx_snprintf(buff + buff_len,
				    max_len - buff_len, "BODY%s NIL", pbody);
		}
	}
	return buff_len;
}

static int imap_cmd_parser_process_fetch_item(IMAP_CONTEXT *pcontext,
    BOOL b_data, MITEM *pitem, int item_id, mdi_list &pitem_list)
{
	int errnum;
	MJSON mjson(imap_parser_get_jpool());
	char buff[MAX_DIGLEN];
	
	if (pitem->flag_bits & FLAG_LOADED) {
		std::string eml_path;
		try {
			eml_path = std::string(pcontext->maildir) + "/eml";
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1464: ENOMEM");
			return 1918;
		}
		if (eml_path.size() == 0)
			return 1923;
		if (!mjson.load_from_json(pitem->digest, eml_path.c_str()))
			return 1923;
	}

	BOOL b_first = FALSE;
	int buff_len = 0;
	buff_len += gx_snprintf(&buff[buff_len], std::size(buff) - buff_len,
	            "* %d FETCH (", item_id);
	for (auto &kwss : pitem_list) {
		if (!b_first) {
			b_first = TRUE;
		} else {
			buff[buff_len++] = ' ';
		}
		auto kw = kwss.data();
		if (strcasecmp(kw, "BODY") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            std::size(buff) - buff_len, "BODY ");
			if (mjson.rfc822_check()) {
				std::string rfc_path;
				try {
					rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				} catch (const std::bad_alloc &) {
					mlog(LV_ERR, "E-1461: ENOMEM");
				}
				if (rfc_path.size() <= 0 ||
				    !mjson.rfc822_build(rfc_path.c_str()))
					goto FETCH_BODY_SIMPLE;
				auto len = mjson.rfc822_fetch(rfc_path.c_str(),
				           pcontext->defcharset,
					FALSE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					goto FETCH_BODY_SIMPLE;
				buff_len += len;
			} else {
 FETCH_BODY_SIMPLE:
				auto len = mjson.fetch_structure(pcontext->defcharset,
					FALSE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					buff_len += gx_snprintf(buff + buff_len,
					            std::size(buff) - buff_len, "NIL");
				else
					buff_len += len;
			}
		} else if (strcasecmp(kw, "BODYSTRUCTURE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            std::size(buff) - buff_len, "BODYSTRUCTURE ");
			if (mjson.rfc822_check()) {
				std::string rfc_path;
				try {
					rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				} catch (const std::bad_alloc &) {
					mlog(LV_ERR, "E-1462: ENOMEM");
				}
				if (rfc_path.size() <= 0 ||
				    !mjson.rfc822_build(rfc_path.c_str()))
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				auto len = mjson.rfc822_fetch(rfc_path.c_str(),
				           pcontext->defcharset,
					TRUE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				buff_len += len;
			} else {
 FETCH_BODYSTRUCTURE_SIMPLE:
				auto len = mjson.fetch_structure(pcontext->defcharset,
					TRUE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					buff_len += gx_snprintf(buff + buff_len,
					            std::size(buff) - buff_len, "NIL");
				else
					buff_len += len;
			}
		} else if (strcasecmp(kw, "ENVELOPE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            std::size(buff) - buff_len, "ENVELOPE ");
			auto len = mjson.fetch_envelope(pcontext->defcharset,
				buff + buff_len, MAX_DIGLEN - buff_len);
			if (len == -1)
				buff_len += gx_snprintf(buff + buff_len,
				            std::size(buff) - buff_len, "NIL");
			else
				buff_len += len;
		} else if (strcasecmp(kw, "FLAGS") == 0) {
			char flags_string[128];
			imap_cmd_parser_convert_flags_string(
				pitem->flag_bits, flags_string);
			buff_len += gx_snprintf(buff + buff_len,
			            std::size(buff) - buff_len, "FLAGS %s", flags_string);
		} else if (strcasecmp(kw, "INTERNALDATE") == 0) {
			time_t tmp_time;
			struct tm tmp_tm;

			if (!parse_rfc822_timestamp(mjson.get_mail_received(), &tmp_time))
				tmp_time = strtol(mjson.get_mail_filename(), nullptr, 0);
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			localtime_r(&tmp_time, &tmp_tm);
			buff_len += strftime(buff + buff_len, MAX_DIGLEN - buff_len,
							"INTERNALDATE \"%d-%b-%Y %T %z\"", &tmp_tm);
		} else if (strcasecmp(kw, "RFC822") == 0) {
			buff_len += gx_snprintf(&buff[buff_len], std::size(buff) - buff_len,
			            "RFC822 {%zd}\r\n<<{file}%s|0|%zd\r\n",
			            mjson.get_mail_length(),
			            mjson.get_mail_filename(),
			            mjson.get_mail_length());
			if (!pcontext->b_readonly &&
			    !(pitem->flag_bits & FLAG_SEEN)) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_bcast_flags(*pcontext, pitem->uid);
			}
		} else if (strcasecmp(kw, "RFC822.HEADER") == 0) {
			auto pmime = mjson.get_mime("");
			if (pmime != nullptr)
				buff_len += gx_snprintf(&buff[buff_len], std::size(buff) - buff_len,
				            "RFC822.HEADER {%zd}\r\n<<{file}%s|0|%zd\r\n",
				            pmime->get_length(MJSON_MIME_HEAD),
				            mjson.get_mail_filename(),
				            pmime->get_length(MJSON_MIME_HEAD));
			else
				buff_len += gx_snprintf(buff + buff_len,
				            std::size(buff) - buff_len, "RFC822.HEADER NIL");
		} else if (strcasecmp(kw, "RFC822.SIZE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            std::size(buff) - buff_len,
			            "RFC822.SIZE %zd", mjson.get_mail_length());
		} else if (strcasecmp(kw, "RFC822.TEXT") == 0) {
			auto pmime = mjson.get_mime("");
			if (pmime != nullptr)
				buff_len += gx_snprintf(buff + buff_len,
				            std::size(buff) - buff_len,
				            "RFC822.TEXT {%zd}\r\n<<{file}%s|%zd|%zd\r\n",
				            pmime->get_length(MJSON_MIME_CONTENT),
				            mjson.get_mail_filename(),
				            pmime->get_offset(MJSON_MIME_CONTENT),
				            pmime->get_length(MJSON_MIME_CONTENT));
			else
				buff_len += gx_snprintf(buff + buff_len,
				            std::size(buff) - buff_len, "RFC822.TEXT NIL");
			if (!pcontext->b_readonly &&
			    !(pitem->flag_bits & FLAG_SEEN)) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_bcast_flags(*pcontext, pitem->uid);
			}
		} else if (strcasecmp(kw, "UID") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            std::size(buff) - buff_len, "UID %d", pitem->uid);
		} else if (strncasecmp(kw, "BODY[", 5) == 0 ||
		    strncasecmp(kw, "BODY.PEEK[", 10) == 0) {
			auto pbody = strchr(kw, '[');
			auto pend = strchr(pbody + 1, ']');
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
			if (0 != strcmp(temp_id, "") &&
			    mjson.rfc822_check()) {
				std::string rfc_path;
				try {
					rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				} catch (const std::bad_alloc &) {
					mlog(LV_ERR, "E-1463: ENOMEM");
				}
				if (rfc_path.size() > 0 &&
				    mjson.rfc822_build(rfc_path.c_str())) {
					MJSON temp_mjson(imap_parser_get_jpool());
					char mjson_id[64], final_id[64];
					if (mjson.rfc822_get(&temp_mjson, rfc_path.c_str(),
					    temp_id, mjson_id, final_id))
						len = imap_cmd_parser_print_structure(
						      pcontext, &temp_mjson, kwss.c_str(),
							buff + buff_len, MAX_DIGLEN - buff_len,
							pbody, final_id, ptr, offset, length,
						      mjson.get_mail_filename());
					else
						len = imap_cmd_parser_print_structure(pcontext,
						      &mjson, kwss.c_str(),
						      buff + buff_len, MAX_DIGLEN - buff_len,
						      pbody, temp_id, ptr, offset, length, nullptr);
				} else {
					len = imap_cmd_parser_print_structure(pcontext,
					      &mjson, kwss,
					      buff + buff_len, MAX_DIGLEN - buff_len,
					      pbody, temp_id, ptr, offset, length, nullptr);
				}
			} else {
				len = imap_cmd_parser_print_structure(pcontext,
				      &mjson, kwss,
				      buff + buff_len, MAX_DIGLEN - buff_len,
				      pbody, temp_id, ptr, offset, length, nullptr);
			}
			buff_len += len;
			if (!pcontext->b_readonly &&
			    !(pitem->flag_bits & FLAG_SEEN) &&
			    strncasecmp(kw, "BODY[", 5) == 0) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_bcast_flags(*pcontext, pitem->uid);
			}
		}
	}
	buff_len += gx_snprintf(&buff[buff_len], std::size(buff) - buff_len, ")\r\n");
	if (pcontext->stream.write(buff, buff_len) != STREAM_WRITE_OK)
		return 1922;
	if (!pcontext->b_readonly && pitem->flag_bits & FLAG_RECENT) {
		pitem->flag_bits &= ~FLAG_RECENT;
		if (!(pitem->flag_bits & FLAG_SEEN)) {
			system_services_unset_flags(pcontext->maildir,
				pcontext->selected_folder, pitem->mid, FLAG_RECENT, &errnum);
			imap_parser_bcast_flags(*pcontext, pitem->uid);
		}
	}
	return 0;
}

static void imap_cmd_parser_store_flags(const char *cmd, const std::string &mid,
	int id, unsigned int uid, int flag_bits, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char buff[1024];
	int string_length;
	char flags_string[128];
	
	string_length = 0;
	if (0 == strcasecmp(cmd, "FLAGS") ||
		0 == strcasecmp(cmd, "FLAGS.SILENT")) {
		system_services_unset_flags(pcontext->maildir,
			pcontext->selected_folder, mid, FLAG_ANSWERED|
			FLAG_FLAGGED|FLAG_DELETED|FLAG_SEEN|FLAG_DRAFT|FLAG_RECENT, &errnum);
		system_services_set_flags(pcontext->maildir,
			pcontext->selected_folder, mid, flag_bits, &errnum);
		if (0 == strcasecmp(cmd, "FLAGS")) {
			imap_cmd_parser_convert_flags_string(flag_bits, flags_string);
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
		system_services_set_flags(pcontext->maildir,
		pcontext->selected_folder, mid, flag_bits, &errnum);
		if (0 == strcasecmp(cmd, "+FLAGS") && 
			MIDB_RESULT_OK == system_services_get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid, &flag_bits, &errnum)) {
			imap_cmd_parser_convert_flags_string(flag_bits, flags_string);
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
		system_services_unset_flags(pcontext->maildir,
			pcontext->selected_folder, mid, flag_bits, &errnum);
		if (0 == strcasecmp(cmd, "-FLAGS") &&
			MIDB_RESULT_OK == system_services_get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid, &flag_bits, &errnum)) {
			imap_cmd_parser_convert_flags_string(flag_bits, flags_string);
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

static BOOL imap_cmd_parser_convert_imaptime(const char *str_time, time_t *ptime)
{
	int factor;
	time_t tmp_time;
	char tmp_buff[3];
	struct tm tmp_tm;
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	auto str_zone = strptime(str_time, "%d-%b-%Y %T ", &tmp_tm);
	if (str_zone == nullptr)
		return FALSE;
	if (strlen(str_zone) < 5)
		return FALSE;
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
	tmp_time = make_gmtime(&tmp_tm);
	tmp_time += factor*(60*60*hour + 60*minute);
	*ptime = tmp_time;
	return TRUE;
}

static BOOL imap_cmd_parser_wildcard_match(const char *folder, const char *mask)
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
			if (imap_cmd_parser_wildcard_match(&folder[span], mask))
				return true;
			if (span-- == 0)
				break;
		}
		return false;
	}
}

static const char *foldername_get(const char *lang, unsigned int fid)
{
	lang = folder_namedb_resolve(lang);
	if (lang == nullptr)
		lang = "en";
	return folder_namedb_get(lang, fid);
}

/**
 * See sysfolder_to_imapfolder for some notes.
 */
static BOOL imap_cmd_parser_imapfolder_to_sysfolder(
	const char *lang, const char *imap_folder, char *sys_folder)
{
	char *ptoken;
	char temp_name[512];
	char temp_folder[512];
	char converted_name[512];
	
	if (mutf7_to_utf8(imap_folder, strlen(imap_folder), temp_name, 512) < 0)
		return FALSE;
	auto len = strlen(temp_name);
	if (len > 0 && temp_name[len-1] == '/') {
		len --;
		temp_name[len] = '\0';
	}
	
	ptoken = strchr(temp_name, '/');
	if (NULL == ptoken) {
		gx_strlcpy(temp_folder, temp_name, std::size(temp_folder));
	} else {
		memcpy(temp_folder, temp_name, ptoken - temp_name);
		temp_folder[ptoken - temp_name] = '\0';
	}
	if (strcasecmp(temp_folder, "INBOX") == 0)
		strcpy(temp_folder, "inbox");
	else if (auto s = foldername_get(lang, PRIVATE_FID_DRAFT);
	    s != nullptr && strcmp(temp_folder, s) == 0)
		gx_strlcpy(temp_folder, "draft", std::size(temp_folder));
	else if (s = foldername_get(lang, PRIVATE_FID_SENT_ITEMS);
	    s != nullptr && strcmp(temp_folder, s) == 0)
		gx_strlcpy(temp_folder, "sent", std::size(temp_folder));
	else if (s = foldername_get(lang, PRIVATE_FID_DELETED_ITEMS);
	    s != nullptr && strcmp(temp_folder, s) == 0)
		gx_strlcpy(temp_folder, "trash", std::size(temp_folder));
	else if (s = foldername_get(lang, PRIVATE_FID_JUNK);
	    s != nullptr && strcmp(temp_folder, s) == 0)
		gx_strlcpy(temp_folder, "junk", std::size(temp_folder));
	if (NULL != ptoken) {
		len = gx_snprintf(converted_name, std::size(converted_name),
		      "%s%s", temp_folder, ptoken);
		encode_hex_binary(converted_name,
			strlen(converted_name), sys_folder, 1024);
	} else if (special_folder(temp_folder)) {
		strcpy(sys_folder, temp_folder);
	} else {
		encode_hex_binary(temp_folder,
			strlen(temp_folder), sys_folder, 1024);
	}
	return TRUE;
}

/**
 * What makes the inbox folder special for...
 * ...Gromox: PRIVATE_FID_INBOX defines the inbox folder
 * ...Outlook: not special (at best, its presence in the receive folder table)
 * ...MIDB: the fixed name "inbox" specifies the inbox
 * ...IMAP: the fixed name "INBOX" specifies the inbox
 *
 * What makes the wastebasket/sent/etc. folder special for...
 * ...Gromox: PRIVATE_FID_WASTEBASKET defines the wastebasket folder
 * ...Outlook: PR_IPM_WASTEBASKET_ENTRYID specifies the wastebasket
 * ...MIDB: the fixed name "trash" specifies the wastebasket
 * ...IMAP: not special
 *
 * Because the MIDB protocol uses a fixed identifier and the actual folder name
 * is "lost" in the protocol (similar to "INBOX" in IMAP), we re-synthesize the
 * folder name. The name shown for the wastebasket in IMAP thus does not
 * necessarily coincide with the name seen in MAPI.
 */
static BOOL imap_cmd_parser_sysfolder_to_imapfolder(
	const char *lang, const char *sys_folder, char *imap_folder)
{
	char *ptoken;
	char temp_name[512];
	char temp_folder[512];
	char converted_name[512];
	
	if (0 == strcmp("inbox", sys_folder)) {
		strcpy(imap_folder, "INBOX");
		return TRUE;
	} else if (0 == strcmp("draft", sys_folder)) {
		auto s = foldername_get(lang, PRIVATE_FID_DRAFT);
		utf8_to_mutf7(s, strlen(s), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("sent", sys_folder)) {
		auto s = foldername_get(lang, PRIVATE_FID_SENT_ITEMS);
		utf8_to_mutf7(s, strlen(s), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("trash", sys_folder)) {
		auto s = foldername_get(lang, PRIVATE_FID_DELETED_ITEMS);
		utf8_to_mutf7(s, strlen(s), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("junk", sys_folder)) {
		auto s = foldername_get(lang, PRIVATE_FID_JUNK);
		utf8_to_mutf7(s, strlen(s), imap_folder, 1024);
		return TRUE;
	}
	if (!decode_hex_binary(sys_folder, temp_name, std::size(temp_name)))
		return FALSE;
	ptoken = strchr(temp_name, '/');
	if (NULL == ptoken) {
		gx_strlcpy(temp_folder, temp_name, std::size(temp_folder));
	} else {
		memcpy(temp_folder, temp_name, ptoken - temp_name);
		temp_folder[ptoken - temp_name] = '\0';
	}
	if (strcmp(temp_folder, "inbox") == 0)
		strcpy(temp_folder, "INBOX");
	else if (strcmp(temp_folder, "draft") == 0)
		gx_strlcpy(temp_folder, znul(foldername_get(lang, PRIVATE_FID_DRAFT)), std::size(temp_folder));
	else if (strcmp(temp_folder, "sent") == 0)
		gx_strlcpy(temp_folder, znul(foldername_get(lang, PRIVATE_FID_SENT_ITEMS)), std::size(temp_folder));
	else if (strcmp(temp_folder, "trash") == 0)
		gx_strlcpy(temp_folder, znul(foldername_get(lang, PRIVATE_FID_DELETED_ITEMS)), std::size(temp_folder));
	else if (strcmp(temp_folder, "junk") == 0)
		gx_strlcpy(temp_folder, znul(foldername_get(lang, PRIVATE_FID_JUNK)), std::size(temp_folder));
	if (ptoken != nullptr)
		snprintf(converted_name, 512, "%s%s", temp_folder, ptoken);
	else
		strcpy(converted_name, temp_folder);
	if (utf8_to_mutf7(converted_name, strlen(converted_name),
	    imap_folder, 1024) <= 0)
		return FALSE;
	return TRUE;
}

static void imap_cmd_parser_convert_folderlist(const char *lang,
   std::vector<std::string> &pfile) try
{
	char converted_name[1024];
	
	for (auto &e : pfile)
		if (imap_cmd_parser_sysfolder_to_imapfolder(lang, e.c_str(), converted_name))
			e = converted_name;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1814: ENOMEM");
}

int imap_cmd_parser_capability(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170001: OK CAPABILITY completed */
	auto imap_reply_str = resource_get_imap_code(1701, 1, &string_length);
	char ext_str[128];
	capability_list(ext_str, std::size(ext_str), pcontext);
	string_length = gx_snprintf(buff, std::size(buff),
	                "* CAPABILITY %s\r\n%s %s",
	                ext_str, argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_id(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	if (parse_bool(g_config_file->get_value("enable_rfc2971_commands"))) {
		/* IMAP_CODE_2170029: OK ID completed */
		auto imap_reply_str = resource_get_imap_code(1729, 1, &string_length);
		snprintf(buff, sizeof(buff), "* ID (\"name\" \"gromox-imap\" "
		         "version \"%s\")\r\n%s %s", PACKAGE_VERSION,
		         argv[0], imap_reply_str);
	} else {
		snprintf(buff, sizeof(buff), "%s %s", argv[0],
		         resource_get_imap_code(1800, 1, &string_length));
	}
	imap_parser_safe_write(pcontext, buff, strlen(buff));
	return DISPATCH_CONTINUE;

}

int imap_cmd_parser_noop(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1702;
}

int imap_cmd_parser_logout(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	/* IMAP_CODE_2160001: BYE logging out */
	auto imap_reply_str = resource_get_imap_code(1601, 1, &string_length);
	/* IMAP_CODE_2170003: OK LOGOUT completed */
	auto imap_reply_str2 = resource_get_imap_code(1703, 1, &string_length);
	
	string_length = gx_snprintf(buff, std::size(buff), "* %s%s %s",
			imap_reply_str, argv[0], imap_reply_str2);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_SHOULD_CLOSE;
}

int imap_cmd_parser_starttls(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->connection.ssl != nullptr)
		return 1800;
	if (!g_support_tls)
		return 1800;
	if (pcontext->proto_stat > iproto_stat::noauth)
		return 1801;
	pcontext->sched_stat = isched_stat::stls;	
	return 1704;
}

int imap_cmd_parser_authenticate(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	if (g_support_tls && g_force_tls && pcontext->connection.ssl == nullptr)
		return 1802;
	if (argc != 3 || strcasecmp(argv[2], "LOGIN") != 0)
		return 1800;
	if (pcontext->is_authed())
		return 1803;
	gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
	pcontext->proto_stat = iproto_stat::username;
	string_length = gx_snprintf(buff, std::size(buff), "+ VXNlciBOYW1lAA==\r\n");
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

static int imap_cmd_parser_username2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t temp_len;
	size_t string_length = 0;
	
	if (strlen(argv[0]) == 0 ||
	    decode64_ex(argv[0], strlen(argv[0]),
	    pcontext->username, std::size(pcontext->username),
	    &temp_len) != 0) {
		pcontext->proto_stat = iproto_stat::noauth;
		return 1819 | DISPATCH_TAG;
	}
	pcontext->proto_stat = iproto_stat::password;
	string_length = gx_snprintf(buff, std::size(buff), "+ UGFzc3dvcmQA\r\n");
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_username(int argc, char **argv, IMAP_CONTEXT *ctx)
{
	return imap_cmd_parser_dval(argc, argv, ctx,
	       imap_cmd_parser_username2(argc, argv, ctx));
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

static int imap_cmd_parser_password2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	size_t temp_len;
	char temp_password[256];
	
	pcontext->proto_stat = iproto_stat::noauth;
	if (strlen(argv[0]) == 0 || decode64_ex(argv[0], strlen(argv[0]),
	    temp_password, std::size(temp_password), &temp_len) != 0)
		return 1820 | DISPATCH_TAG;

	auto target_mbox = strchr(pcontext->username, '!');
	if (target_mbox != nullptr)
		*target_mbox++ = '\0';
	HX_strltrim(pcontext->username);
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		imap_parser_log_info(pcontext, LV_NOTICE, "user %s is "
			"denied by user filter", pcontext->username);
		return 1901 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
    }
	sql_meta_result mres_auth, mres /* target */;
	if (!system_services_auth_login(pcontext->username, temp_password,
	    USER_PRIVILEGE_IMAP, mres_auth)) {
		safe_memset(temp_password, 0, std::size(temp_password));
		imap_parser_log_info(pcontext, LV_WARN, "PASSWORD2 failed: %s",
			mres_auth.errstr.c_str());
		pcontext->auth_times ++;
		if (pcontext->auth_times < g_max_auth_times)
			return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
		if (system_services_add_user_into_temp_list != nullptr)
			system_services_add_user_into_temp_list(pcontext->username,
				g_block_auth_fail);
		return 1903 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
	}
	safe_memset(temp_password, 0, std::size(temp_password));
	if (target_mbox == nullptr) {
		mres = std::move(mres_auth);
	} else {
		if (system_services_auth_meta(target_mbox, WANTPRIV_METAONLY, mres) != 0)
			return 1902 | DISPATCH_CONTINUE | DISPATCH_TAG;
		if (!store_owner_over(mres_auth.username.c_str(), mres.username.c_str(),
		    mres.maildir.c_str())) {
			imap_parser_log_info(pcontext, LV_WARN, "PASSWORD2 failed: %s", mres.errstr.c_str());
			++pcontext->auth_times;
			if (pcontext->auth_times < g_max_auth_times)
				return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
			if (system_services_add_user_into_temp_list != nullptr)
				system_services_add_user_into_temp_list(pcontext->username,
					g_block_auth_fail);
			return 1903 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
		}
	}
	gx_strlcpy(pcontext->username, mres.username.c_str(), std::size(pcontext->username));
	gx_strlcpy(pcontext->maildir, mres.maildir.c_str(), std::size(pcontext->maildir));
	gx_strlcpy(pcontext->lang, mres.lang.c_str(), std::size(pcontext->lang));
	if (*pcontext->maildir == '\0')
		return 1902 | DISPATCH_TAG;
	if (*pcontext->lang == '\0')
		gx_strlcpy(pcontext->lang, znul(g_config_file->get_value("default_lang")), sizeof(pcontext->lang));
	gx_strlcpy(pcontext->defcharset, resource_get_default_charset(pcontext->lang), std::size(pcontext->defcharset));
	pcontext->proto_stat = iproto_stat::auth;
	imap_parser_log_info(pcontext, LV_DEBUG, "login success");
	char caps[128], buff[160];
	capability_list(caps, std::size(caps), pcontext);
	auto z = gx_snprintf(buff, std::size(buff),
		 "%s OK [CAPABILITY %s] Logged in\r\n",
		 tag_or_bug(pcontext->tag_string), caps);
	imap_parser_safe_write(pcontext, buff, z);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_password(int argc, char **argv, IMAP_CONTEXT *ctx)
{
	return imap_cmd_parser_dval(argc, argv, ctx,
	       imap_cmd_parser_password2(argc, argv, ctx));
}

int imap_cmd_parser_login(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
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
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		imap_parser_log_info(pcontext, LV_WARN, "user %s is "
			"denied by user filter", pcontext->username);
		return 1901 | DISPATCH_SHOULD_CLOSE;
    }
	strcpy(temp_password, argv[3]);
	HX_strltrim(temp_password);

	sql_meta_result mres_auth, mres /* target */;
	if (!system_services_auth_login(pcontext->username, temp_password,
	    USER_PRIVILEGE_IMAP, mres_auth)) {
		imap_parser_log_info(pcontext, LV_WARN, "LOGIN failed: %s", mres.errstr.c_str());
		pcontext->auth_times++;
		if (pcontext->auth_times < g_max_auth_times) {
			gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
			return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
		}
		if (system_services_add_user_into_temp_list != nullptr)
			system_services_add_user_into_temp_list(pcontext->username,
				g_block_auth_fail);
		return 1903 | DISPATCH_SHOULD_CLOSE;
	}
	safe_memset(temp_password, 0, std::size(temp_password));
	if (target_mbox == nullptr) {
		mres = std::move(mres_auth);
	} else {
		if (system_services_auth_meta(target_mbox, WANTPRIV_METAONLY, mres) != 0)
			return 1902 | DISPATCH_CONTINUE | DISPATCH_TAG;
		if (!store_owner_over(mres_auth.username.c_str(), mres.username.c_str(),
		    mres.maildir.c_str())) {
			imap_parser_log_info(pcontext, LV_WARN, "LOGIN failed: %s", mres.errstr.c_str());
			++pcontext->auth_times;
			if (pcontext->auth_times < g_max_auth_times)
				return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
			if (system_services_add_user_into_temp_list != nullptr)
				system_services_add_user_into_temp_list(pcontext->username,
					g_block_auth_fail);
			return 1903 | DISPATCH_SHOULD_CLOSE;
		}
	}
	gx_strlcpy(pcontext->username, mres.username.c_str(), std::size(pcontext->username));
	gx_strlcpy(pcontext->maildir, mres.maildir.c_str(), std::size(pcontext->maildir));
	gx_strlcpy(pcontext->lang, mres.lang.c_str(), std::size(pcontext->lang));
	if (*pcontext->maildir == '\0')
		return 1902;
	if (*pcontext->lang == '\0')
		gx_strlcpy(pcontext->lang, znul(g_config_file->get_value("default_lang")), sizeof(pcontext->lang));
	gx_strlcpy(pcontext->defcharset, resource_get_default_charset(pcontext->lang), std::size(pcontext->defcharset));
	pcontext->proto_stat = iproto_stat::auth;
	imap_parser_log_info(pcontext, LV_DEBUG, "login success");
	return 1705;
}

int imap_cmd_parser_idle(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
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
int content_array::refresh(imap_context &ctx, const char *folder,
    bool with_expunges)
{
	XARRAY xa;
	int errnum = 0;
	imap_seq_list all_seq;
	all_seq.insert(1, SEQ_STAR);
	auto ssr = system_services_fetch_simple_uid(ctx.maildir, folder,
	           all_seq, &xa, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	if (with_expunges) {
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

static int imap_cmd_parser_selex(int argc, char **argv,
    IMAP_CONTEXT *pcontext, bool readonly) try
{
	int errnum;
	size_t string_length = 0;
	char temp_name[1024];
	char buff[1024];
    
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	if (iproto_stat::select == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = iproto_stat::auth;
		pcontext->selected_folder[0] = '\0';
	}
	
	uint32_t uidvalid = 0, uidnext = 0;
	auto ssr = system_services_summary_folder(pcontext->maildir, temp_name,
	           nullptr, nullptr, nullptr, &uidvalid, &uidnext, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	ret = pcontext->contents.refresh(*pcontext, temp_name, true);
	if (ret != 0)
		return ret;
	strcpy(pcontext->selected_folder, temp_name);
	pcontext->proto_stat = iproto_stat::select;
	pcontext->b_readonly = readonly;
	imap_parser_add_select(pcontext);

	/* Effectively canonicalize(d) argv[2] */
	if (!imap_cmd_parser_sysfolder_to_imapfolder(pcontext->lang, temp_name, buff))
		return 1800;
	gx_strlcpy(temp_name, buff, std::size(temp_name));

	string_length = gx_snprintf(buff, std::size(buff),
		"* %zu EXISTS\r\n"
		"* %u RECENT\r\n"
		"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
		"* OK %s\r\n",
		pcontext->contents.n_exists(),
		pcontext->contents.n_recent, readonly ?
		"[PERMANENTFLAGS ()] no permanent flags permitted" :
		"[PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited");
	if (pcontext->contents.firstunseen != 0)
		string_length += gx_snprintf(&buff[string_length], std::size(buff) - string_length,
			"* OK [UNSEEN %u] message %u is first unseen\r\n",
			pcontext->contents.firstunseen,
			pcontext->contents.firstunseen);
	auto s_readonly = readonly ? "READ-ONLY" : "READ-WRITE";
	auto s_command  = readonly ? "EXAMINE" : "SELECT";
	string_length += gx_snprintf(&buff[string_length], std::size(buff) - string_length,
		"* OK [UIDVALIDITY %llu] UIDs valid\r\n"
		"* OK [UIDNEXT %d] predicted next UID\r\n",
		LLU{uidvalid}, uidnext);
	if (g_rfc9051_enable)
		string_length += gx_snprintf(&buff[string_length], std::size(buff) - string_length,
			"* LIST () \"/\" %s\r\n", quote_encode(temp_name).c_str());
	string_length += gx_snprintf(&buff[string_length], std::size(buff) - string_length,
		"%s OK [%s] %s completed\r\n",
		argv[0], s_readonly, s_command);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1915;
}

int imap_cmd_parser_select(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	return imap_cmd_parser_selex(argc, argv, pcontext, false);
}

int imap_cmd_parser_examine(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	return imap_cmd_parser_selex(argc, argv, pcontext, true);
}

static void writefolderlines(std::vector<std::string> &file) try
{
	file.emplace_back("inbox");
	for (auto folder : g_folder_list)
		file.emplace_back(folder);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1813: ENOMEM");
}

int imap_cmd_parser_create(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char temp_name[1024];
	char temp_name1[1024];
	char converted_name[1024];

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	if (strpbrk(argv[2], "%*?") != nullptr)
		return 1910;
	if (special_folder(temp_name))
		return 1911;
	std::vector<std::string> temp_file;
	auto ssr = system_services_enum_folders(pcontext->maildir, temp_file, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	writefolderlines(temp_file);
	imap_cmd_parser_convert_folderlist(pcontext->lang, temp_file);
	strcpy(temp_name, argv[2]);
	auto len = strlen(temp_name);
	if (len > 0 && temp_name[len-1] == '/') {
		len --;
		temp_name[len] = '\0';
	}
	for (size_t i = 0; i <= len; ++i) {
		if (temp_name[i] != '/' && temp_name[i] != '\0') {
			temp_name1[i] = temp_name[i];
			continue;
		}
		temp_name1[i] = '\0';
#if __cplusplus < 202000L
		if (std::find_if(temp_file.cbegin(), temp_file.cend(),
		    [&](const auto &elem) { return strcasecmp(elem.c_str(), temp_name1) == 0; }) != temp_file.cend()) {
			temp_name1[i] = temp_name[i];
			continue;
		}
#else
		if (std::find(temp_file.cbegin(), temp_file.cend(), temp_name1) !=
		    temp_file.cend()) {
			temp_name1[i] = temp_name[i];
			continue;
		}
#endif
		if (!imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang,
		    temp_name1, converted_name))
			return 1800;
		ssr = system_services_make_folder(pcontext->maildir,
		      converted_name, &errnum);
		ret = m2icode(ssr, errnum);
		if (ret != 0)
			return ret;
		temp_name1[i] = temp_name[i];
	}
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1706;
}

int imap_cmd_parser_delete(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char encoded_name[1024];

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], encoded_name))
		return 1800;
	if (special_folder(encoded_name))
		return 1913;
	auto ssr = system_services_remove_folder(pcontext->maildir,
	           encoded_name, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1707;
}

int imap_cmd_parser_rename(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char encoded_name[1024];
	char encoded_name1[1024];

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| 0 == strlen(argv[3]) || strlen(argv[3]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], encoded_name) ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[3], encoded_name1))
		return 1800;
	if (strpbrk(argv[3], "%*?") != nullptr)
		return 1910;
	if (special_folder(encoded_name) || special_folder(encoded_name1))
		return 1914;
	auto ssr = system_services_rename_folder(pcontext->maildir,
	           encoded_name, encoded_name1, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1708;
}

int imap_cmd_parser_subscribe(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char temp_name[1024];

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	auto ssr = system_services_subscribe_folder(pcontext->maildir,
	           temp_name, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1709;
}

int imap_cmd_parser_unsubscribe(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char temp_name[1024];

	if (!pcontext->is_authed())
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	auto ssr = system_services_unsubscribe_folder(pcontext->maildir,
	           temp_name, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	return 1710;
}

int imap_cmd_parser_list(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	int len;
	int errnum;
	size_t string_length = 0;
	char buff[256*1024];
	
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
		auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff),
			"* LIST (\\Noselect) \"/\" \"\"\r\n%s %s",
			argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}

	auto search_pattern = std::string(reference) + mboxname;
	std::vector<std::string> temp_file;
	if (!filter_special) {
		auto ssr = system_services_enum_folders(pcontext->maildir,
		           temp_file, &errnum);
		auto ret = m2icode(ssr, errnum);
		if (ret != 0)
			return ret;
	}

	imap_cmd_parser_convert_folderlist(pcontext->lang, temp_file);
	dir_tree temp_tree(imap_parser_get_dpool());
	temp_tree.load_from_memfile(temp_file);
	len = 0;
	if (imap_cmd_parser_wildcard_match("INBOX", search_pattern.c_str())) {
		if (filter_special) {
			len += gx_snprintf(&buff[len], std::size(buff) - len,
			       "* LIST (\\Inbox) \"/\" \"INBOX\"\r\n");
		} else {
			auto pdir = temp_tree.match("INBOX");
			auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
			len = gx_snprintf(&buff[len], std::size(buff) - len,
			      "* LIST (%s\\Has%sChildren) \"/\" \"INBOX\"\r\n",
			      return_special ? "\\Inbox " : "", have ? "" : "No");
		}
	}
	for (unsigned int i = 0; i < 4; ++i) {
		char temp_name[1024];
		imap_cmd_parser_sysfolder_to_imapfolder(pcontext->lang, g_folder_list[i], temp_name);
		if (imap_cmd_parser_wildcard_match(temp_name, search_pattern.c_str())) {
			if (filter_special) {
				len += gx_snprintf(&buff[len], std::size(buff),
				       "* LIST (%s) \"/\" %s\r\n",
				       g_xproperty_list[i], quote_encode(temp_name).c_str());
			} else {
				auto pdir = temp_tree.match(temp_name);
				auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
				len += gx_snprintf(&buff[len], std::size(buff) - len,
				       "* LIST (%s%s\\Has%sChildren) \"/\" %s\r\n",
				       return_special ? g_xproperty_list[i] : "",
				       return_special ? " " : "",
				       have ? "" : "No", quote_encode(temp_name).c_str());
			}
		}
	}
	for (const auto &temp_name : temp_file) {
		if (!imap_cmd_parser_wildcard_match(temp_name.c_str(), search_pattern.c_str()))
			continue;
		if (filter_special) {
			len += gx_snprintf(&buff[len], std::size(buff) - len,
			       "* LIST () \"/\" %s\r\n",
			       quote_encode(temp_name).c_str());
			continue;
		}
		auto pdir = temp_tree.match(temp_name.c_str());
		auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
		len += gx_snprintf(&buff[len], std::size(buff) - len,
		       "* LIST (\\Has%sChildren) \"/\" %s\r\n",
		       have ? "" : "No", quote_encode(temp_name).c_str());
	}
	temp_file.clear();
	pcontext->stream.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170011: OK LIST completed */
	auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
	len += gx_snprintf(&buff[len], std::size(buff) - len, "%s %s", argv[0], imap_reply_str);
	if (pcontext->stream.write(buff, len) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int imap_cmd_parser_xlist(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	int errnum;
	int i, len;
	size_t string_length = 0;
	char buff[256*1024];
	
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4)
		return 1800;
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024)
		return 1800;
	std::string search_pattern = argv[2];
	search_pattern += *argv[3] == '\0' ? "*" : argv[3];
	std::vector<std::string> temp_file;
	auto ssr = system_services_enum_folders(pcontext->maildir,
	           temp_file, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	imap_cmd_parser_convert_folderlist(pcontext->lang, temp_file);
	dir_tree temp_tree(imap_parser_get_dpool());
	temp_tree.load_from_memfile(temp_file);
	len = 0;
	if (imap_cmd_parser_wildcard_match("INBOX", search_pattern.c_str())) {
		auto pdir = temp_tree.match("INBOX");
		auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
		/*
		 * RFC 6154 does not document \Inbox, but Thunderbird
		 * evaluates it.
		 */
		len = gx_snprintf(&buff[len], std::size(buff) - len,
		      "* XLIST (\\Inbox \\Has%sChildren) \"/\" \"INBOX\"\r\n",
		      have ? "" : "No");
	}
	for (i=0; i<4; i++) {
		char temp_name[1024];
		imap_cmd_parser_sysfolder_to_imapfolder(
			pcontext->lang, g_folder_list[i], temp_name);
		if (imap_cmd_parser_wildcard_match(temp_name, search_pattern.c_str())) {
			auto pdir = temp_tree.match(temp_name);
			auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
			len += gx_snprintf(&buff[len], std::size(buff) - len,
			       "* XLIST (%s \\Has%sChildren) \"/\" %s\r\n",
			       g_xproperty_list[i], have ? "" : "No",
			       quote_encode(temp_name).c_str());
		}
	}
	for (const auto &temp_name : temp_file) {
		if (!imap_cmd_parser_wildcard_match(temp_name.c_str(), search_pattern.c_str()))
			continue;
		auto pdir = temp_tree.match(temp_name.c_str());
		auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
		len += gx_snprintf(&buff[len], std::size(buff) - len,
		       "* XLIST (\\Has%sChildren) \"/\" %s\r\n",
		       have ? "" : "No", quote_encode(temp_name).c_str());
	}
	temp_file.clear();
	pcontext->stream.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170012: OK XLIST completed */
	auto imap_reply_str = resource_get_imap_code(1712, 1, &string_length);
	len += gx_snprintf(&buff[len], std::size(buff) - len,
			"%s %s", argv[0], imap_reply_str);
	if (pcontext->stream.write(buff, len) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int imap_cmd_parser_lsub(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	int len;
	int errnum;
	size_t string_length = 0;
	char buff[256*1024];
	
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
		auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff),
			"* LSUB (\\Noselect) \"/\" \"\"\r\n%s %s",
			argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	auto search_pattern = std::string(argv[2]) + argv[3];
	std::vector<std::string> temp_file;
	auto ssr = system_services_enum_subscriptions(pcontext->maildir,
	           temp_file, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	imap_cmd_parser_convert_folderlist(pcontext->lang, temp_file);
	std::vector<std::string> temp_file1;
	system_services_enum_folders(pcontext->maildir, temp_file1, &errnum);
	writefolderlines(temp_file1);
	imap_cmd_parser_convert_folderlist(pcontext->lang, temp_file1);
	dir_tree temp_tree(imap_parser_get_dpool());
	temp_tree.load_from_memfile(temp_file1);
	temp_file1.clear();
	len = 0;
	for (const auto &temp_name : temp_file) {
		if (!imap_cmd_parser_wildcard_match(temp_name.c_str(), search_pattern.c_str()))
			continue;
		auto pdir = temp_tree.match(temp_name.c_str());
		auto have = pdir != nullptr && temp_tree.get_child(pdir) != nullptr;
		len += gx_snprintf(&buff[len], std::size(buff) - len,
		       "* LSUB (\\Has%sChildren) \"/\" %s\r\n",
		       have ? "" : "No", quote_encode(temp_name).c_str());
	}
	temp_file.clear();
	pcontext->stream.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170013: OK LSUB completed */
	auto imap_reply_str = resource_get_imap_code(1713, 1, &string_length);
	len += gx_snprintf(&buff[len], std::size(buff) - len,
			"%s %s", argv[0], imap_reply_str);
	if (pcontext->stream.write(buff, len) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	return 1915;
}

int imap_cmd_parser_status(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	int i;
	int errnum;
	BOOL b_first;
	int temp_argc;
	char buff[1024];
	size_t string_length = 0;
	char *temp_argv[16];
	char temp_name[1024];
    
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name) ||
	    argv[3][0] != '(' || argv[3][strlen(argv[3])-1] != ')')
		return 1800;
	temp_argc = parse_imap_args(argv[3] + 1,
		strlen(argv[3]) - 2, temp_argv, sizeof(temp_argv));
	if (temp_argc == -1)
		return 1800;

	size_t exists = 0, recent = 0, unseen = 0;
	uint32_t uidvalid = 0, uidnext = 0;
	auto ssr = system_services_summary_folder(pcontext->maildir, temp_name,
	           &exists, &recent, &unseen, &uidvalid, &uidnext, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	/* IMAP_CODE_2170014: OK STATUS completed */
	auto imap_reply_str = resource_get_imap_code(1714, 1, &string_length);
	string_length = gx_snprintf(buff, std::size(buff), "* STATUS %s (",
	                quote_encode(argv[2]).c_str());
	b_first = TRUE;
	for (i=0; i<temp_argc; i++) {
		if (!b_first)
			buff[string_length++] = ' ';
		else
			b_first = FALSE;
		if (strcasecmp(temp_argv[i], "MESSAGES") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 std::size(buff) - string_length, "MESSAGES %zu", exists);
		else if (strcasecmp(temp_argv[i], "RECENT") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 std::size(buff) - string_length, "RECENT %zu", recent);
		else if (strcasecmp(temp_argv[i], "UIDNEXT") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 std::size(buff) - string_length, "UIDNEXT %llu", LLU{uidnext});
		else if (strcasecmp(temp_argv[i], "UIDVALIDITY") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 std::size(buff) - string_length, "UIDVALIDITY %llu",
			                 LLU{uidvalid});
		else if (strcasecmp(temp_argv[i], "UNSEEN") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 std::size(buff) - string_length, "UNSEEN %zu", unseen);
		else
			return 1800;
	}
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	string_length += gx_snprintf(buff + string_length,
	                 std::size(buff) - string_length, ")\r\n%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
} catch (const std::bad_alloc &) {
	return 1915;
}

int imap_cmd_parser_append(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum, i;
	BOOL b_seen;
	BOOL b_draft;
	int temp_argc;
	BOOL b_flagged;
	BOOL b_answered;
	time_t tmp_time;
	size_t string_length = 0, string_length1 = 0;
	char* temp_argv[5];
	char *str_received = nullptr, *flags_string = nullptr;
	char flag_buff[16];
	char temp_name[1024];
	char buff[1024];
	
	if (!pcontext->is_authed())
		return 1804;
	if (argc < 4 || argc > 6 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	b_answered = FALSE;
	b_flagged = FALSE;
	b_seen = FALSE;
	b_draft = FALSE;
	if (6 == argc) {
		flags_string = argv[3];
		str_received = argv[4];
	} else if (5 == argc) {
		if ('(' == argv[3][0]) {
			flags_string = argv[3];
			str_received = NULL;
		} else {
			str_received = argv[3];
			flags_string = NULL;
		}
	} else if (4 == argc) {
		flags_string = NULL;
		str_received = NULL;
	} 
	if (NULL != flags_string) {
		if (flags_string[0] != '(' ||
		    flags_string[strlen(flags_string)-1] != ')')
			return 1800;
		temp_argc = parse_imap_args(flags_string + 1, strlen(flags_string) - 2,
		            temp_argv, sizeof(temp_argv));
		if (temp_argc == -1)
			return 1800;
		for (i=0; i<temp_argc; i++) {
			if (strcasecmp(temp_argv[i], "\\Answered") == 0)
				b_answered = TRUE;
			else if (strcasecmp(temp_argv[i], "\\Flagged") == 0)
				b_flagged = TRUE;
			else if (strcasecmp(temp_argv[i], "\\Seen") == 0)
				b_seen = TRUE;
			else if (strcasecmp(temp_argv[i], "\\Draft") == 0)
				b_draft = TRUE;
			else
				return 1800;
		}
	}
	MAIL imail;
	if (!imail.load_from_str_move(argv[argc-1], strlen(argv[argc-1])))
		return 1908;
	strcpy(flag_buff, "(");
	if (b_seen)
		strcat(flag_buff, "S");
	if (b_answered)
		strcat(flag_buff, "A");
	if (b_flagged)
		strcat(flag_buff, "F");
	if (b_draft)
		strcat(flag_buff, "U");
	strcat(flag_buff, ")");
	if (str_received == nullptr ||
	    !imap_cmd_parser_convert_imaptime(str_received, &tmp_time))
		time(&tmp_time);
	std::string mid_string, eml_path;
	int fd = -1;
	try {
		mid_string = std::to_string(tmp_time) + "." +
		             std::to_string(imap_parser_get_sequence_ID()) + "." +
		             znul(g_config_file->get_value("host_id"));
		eml_path = std::string(pcontext->maildir) + "/eml/" + mid_string;
		fd = open(eml_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, FMODE_PRIVATE);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1456: ENOMEM");
	}
	if (fd < 0 || !imail.to_file(fd)) {
		if (-1 != fd) {
			close(fd);
			if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
				mlog(LV_WARN, "W-1370: remove %s: %s",
				        eml_path.c_str(), strerror(errno));
		}
		return 1909;
	}
	close(fd);
	imail.clear();

	auto ssr = system_services_insert_mail(pcontext->maildir, temp_name,
	           mid_string.c_str(), flag_buff, tmp_time, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	imap_parser_log_info(pcontext, LV_DEBUG, "message %s is appended OK", eml_path.c_str());
	imap_parser_bcast_touch(nullptr, pcontext->username, pcontext->selected_folder);
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	auto imap_reply_str = resource_get_imap_code(1715, 1, &string_length);
	auto imap_reply_str1 = resource_get_imap_code(1715, 2, &string_length1);
	for (i=0; i<10; i++) {
		uint32_t uidvalid = 0;
		if (system_services_summary_folder(pcontext->maildir,
		    temp_name, nullptr, nullptr, nullptr, &uidvalid, nullptr,
		    &errnum) == MIDB_RESULT_OK &&
		    system_services_get_uid(pcontext->maildir, temp_name,
		    mid_string.c_str(), &uid) == MIDB_RESULT_OK) {
			string_length = gx_snprintf(buff, std::size(buff),
			                "%s %s [APPENDUID %llu %d] %s",
			                argv[0], imap_reply_str, LLU{uidvalid},
				uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (i == 10)
		string_length = gx_snprintf(buff, std::size(buff), "%s %s %s",
				argv[0], imap_reply_str, imap_reply_str1);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

static inline bool is_flag_name(const char *flag)
{
	static constexpr const char *names[] = {"\\Answered", "\\Flagged", "\\Seen", "\\Draft"};
	for (auto s : names)
		if (strcasecmp(flag, s) == 0)
			return true;
	return false;
}

static int imap_cmd_parser_append_begin2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int temp_argc, len;
	char buff[1024];
	char *str_received = nullptr, *flags_string = nullptr;
	char* temp_argv[5];
	char str_flags[128];
	char temp_name[1024];
	
	if (!pcontext->is_authed())
		return 1804 | DISPATCH_BREAK;
	if (argc < 3 || argc > 5 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800 | DISPATCH_BREAK;
	if (5 == argc) {
		flags_string = argv[3];
		str_received = argv[4];
	} else if (4 == argc) {
		if ('(' == argv[3][0]) {
			flags_string = argv[3];
			str_received = NULL;
		} else {
			str_received = argv[3];
			flags_string = NULL;
		}
	} else if (3 == argc) {
		flags_string = NULL;
		str_received = NULL;
	}
	if (NULL != flags_string) {
		gx_strlcpy(str_flags, flags_string, std::size(str_flags));
		if (flags_string[0] != '(' ||
		    flags_string[strlen(flags_string)-1] != ')')
			return 1800 | DISPATCH_BREAK;
		temp_argc = parse_imap_args(flags_string + 1, strlen(flags_string) - 2,
		            temp_argv, sizeof(temp_argv));
		if (temp_argc == -1)
			return 1800 | DISPATCH_BREAK;
		for (int i = 0; i < temp_argc; ++i)
			if (!is_flag_name(temp_argv[i]))
				return 1800 | DISPATCH_BREAK;
	}
	try {
		pcontext->mid = std::to_string(time(nullptr)) + "." +
			std::to_string(imap_parser_get_sequence_ID()) + "." +
			znul(g_config_file->get_value("host_id"));
		pcontext->file_path = pcontext->maildir + "/tmp/"s + pcontext->mid;
	} catch (const std::bad_alloc &) {
		return 1918 | DISPATCH_BREAK;
	}
	int fd = open(pcontext->file_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, FMODE_PRIVATE);
	if (fd == -1)
		return 1909 | DISPATCH_BREAK;
	len = sizeof(uint32_t);
	len += gx_snprintf(&buff[len], std::size(buff) - len, "%s", temp_name);
	buff[len++] = '\0';
	if (flags_string != nullptr)
		len += gx_snprintf(&buff[len], std::size(buff) - len, "%s", str_flags);
	buff[len++] = '\0';
	if (str_received != nullptr)
		len += gx_snprintf(&buff[len], std::size(buff) - len, "%s", str_received);
	buff[len++] = '\0';
	cpu_to_le32p(buff, len);
	write(fd, buff, len);
	pcontext->message_fd = fd;
	gx_strlcpy(pcontext->tag_string, argv[0], std::size(pcontext->tag_string));
	pcontext->stream.clear();
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_append_begin(int argc, char **argv, IMAP_CONTEXT *ctx)
{
	return imap_cmd_parser_dval(argc, argv, ctx,
	       imap_cmd_parser_append_begin2(argc, argv, ctx));
}

static int imap_cmd_parser_append_end2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int i;
	unsigned int uid;
	int errnum;
	BOOL b_seen;
	BOOL b_draft;
	int name_len;
	int flags_len;
	BOOL b_flagged;
	BOOL b_answered;
	char *str_flags;
	time_t tmp_time;
	size_t string_length = 0, string_length1 = 0;
	char *str_internal;
	char flag_buff[16];
	char temp_name[1024];
	struct stat node_stat;
	char buff[1024];
	
	b_answered = FALSE;
	b_flagged = FALSE;
	b_seen = FALSE;
	b_draft = FALSE;
	if (0 != fstat(pcontext->message_fd, &node_stat)) {
		close(pcontext->message_fd);
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1342: remove %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->message_fd = -1;
		pcontext->mid.clear();
		pcontext->file_path.clear();
		return 1909 | DISPATCH_TAG;
	}
	lseek(pcontext->message_fd, 0, SEEK_SET);
	std::unique_ptr<char[], stdlib_delete> pbuff(me_alloc<char>(((node_stat.st_size - 1) / (64 * 1024) + 1) * 64 * 1024));
	if (pbuff == nullptr || read(pcontext->message_fd, pbuff.get(),
	    node_stat.st_size) != node_stat.st_size) {
		pbuff.reset();
		close(pcontext->message_fd);
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1343: remove %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->message_fd = -1;
		pcontext->mid.clear();
		pcontext->file_path.clear();
		return 1909 | DISPATCH_TAG;
	}
	close(pcontext->message_fd);
	pcontext->message_fd = -1;
	uint32_t mfd_len = 0;
	memcpy(&mfd_len, pbuff.get(), sizeof(mfd_len));
	MAIL imail;
	if (!imail.load_from_str_move(&pbuff[mfd_len], node_stat.st_size - mfd_len)) {
		imail.clear();
		pbuff.reset();
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1344: remove %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->mid.clear();
		pcontext->file_path.clear();
		return 1909;
	}
	auto str_name = pbuff.get() + sizeof(uint32_t);
	name_len = strlen(str_name);
	str_flags = str_name + name_len + 1;
	flags_len = strlen(str_flags);
	str_internal = str_flags + flags_len + 1;
	gx_strlcpy(temp_name, str_name, std::size(temp_name));
	if (search_string(str_flags, "\\Seen", flags_len) != nullptr)
		b_seen = TRUE;
	if (search_string(str_flags, "\\Answered", flags_len) != nullptr)
		b_answered = TRUE;
	if (search_string(str_flags, "\\Flagged", flags_len) != nullptr)
		b_flagged = TRUE;
	if (search_string(str_flags, "\\Draft", flags_len) != nullptr)
		b_draft = TRUE;
	strcpy(flag_buff, "(");
	if (b_seen)
		strcat(flag_buff, "S");
	if (b_answered)
		strcat(flag_buff, "A");
	if (b_flagged)
		strcat(flag_buff, "F");
	if (b_draft)
		strcat(flag_buff, "U");
	strcat(flag_buff, ")");
	if (str_internal[0] == '\0' ||
	    !imap_cmd_parser_convert_imaptime(str_internal, &tmp_time))
		time(&tmp_time);
	std::string eml_path;
	int fd = -1;
	try {
		eml_path = std::string(pcontext->maildir) + "/eml/" + pcontext->mid;
		fd = open(eml_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, FMODE_PRIVATE);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1460: ENOMEM");
	}
	if (fd < 0 || !imail.to_file(fd)) {
		imail.clear();
		pbuff.reset();
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1345: remove %s: %s",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->mid.clear();
		pcontext->file_path.clear();
		if (-1 != fd) {
			close(fd);
			if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
				mlog(LV_WARN, "W-1346: remove %s: %s",
				        eml_path.c_str(), strerror(errno));
		}
		return 1909;
	}
	close(fd);
	imail.clear();
	pbuff.reset();
	if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
		mlog(LV_WARN, "W-1336: remove %s: %s",
			pcontext->file_path.c_str(), strerror(errno));
	pcontext->file_path.clear();
	auto ssr = system_services_insert_mail(pcontext->maildir, temp_name,
	           pcontext->mid.c_str(), flag_buff, tmp_time, &errnum);
	auto ret = m2icode(ssr, errnum);
	pcontext->mid.clear();
	if (ret != 0)
		return ret;
	pcontext->mid.clear();
	imap_parser_log_info(pcontext, LV_DEBUG, "message %s is appended OK", eml_path.c_str());
	imap_parser_bcast_touch(nullptr, pcontext->username, pcontext->selected_folder);
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	auto imap_reply_str = resource_get_imap_code(1715, 1, &string_length);
	auto imap_reply_str1 = resource_get_imap_code(1715, 2, &string_length1);
	for (i=0; i<10; i++) {
		uint32_t uidvalid = 0;
		if (system_services_summary_folder(pcontext->maildir,
		    temp_name, nullptr, nullptr, nullptr, &uidvalid,
		    nullptr, &errnum) == MIDB_RESULT_OK &&
		    system_services_get_uid(pcontext->maildir, temp_name,
		    pcontext->mid.c_str(), &uid) == MIDB_RESULT_OK) {
			string_length = gx_snprintf(buff, std::size(buff), "%s %s [APPENDUID %llu %d] %s",
				pcontext->tag_string, imap_reply_str, LLU{uidvalid},
				uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (i == 10)
		string_length = gx_snprintf(buff, std::size(buff), "%s %s %s",
			pcontext->tag_string, imap_reply_str, imap_reply_str1);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_append_end(int argc, char **argv, IMAP_CONTEXT *ctx)
{
	return imap_cmd_parser_dval(argc, argv, ctx,
	       imap_cmd_parser_append_end2(argc, argv, ctx));
}

int imap_cmd_parser_check(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	imap_parser_echo_modify(pcontext, NULL);
	return 1716;
}

int imap_cmd_parser_close(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	imap_cmd_parser_clsfld(pcontext);
	return 1717;
}

static bool zero_uid_bit(const MITEM &i)
{
	return i.uid == 0 || !(i.flag_bits & FLAG_DELETED);
}

int imap_cmd_parser_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	int errnum;
	size_t string_length = 0;
	char buff[1024];
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (pcontext->b_readonly)
		return 1806;
	XARRAY xarray;
	auto ssr = system_services_list_deleted(pcontext->maildir,
	           pcontext->selected_folder, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	auto num = xarray.get_capacity();
	if (num == 0) {
		imap_parser_echo_modify(pcontext, nullptr, true);
		return 1726;
	}
	std::vector<MITEM *> exp_list;
	for (size_t i = 0; i < num; ++i) {
		auto pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem))
			continue;
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		exp_list.push_back(pitem);
	}
	ssr = system_services_remove_mail(pcontext->maildir,
	      pcontext->selected_folder, exp_list, &errnum);
	ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	pcontext->stream.clear();
	unsigned int del_num = 0;
	for (size_t i = 0; i < xarray.get_capacity(); ++i) try {
		auto pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem))
			continue;
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		auto eml_path = std::string(pcontext->maildir) + "/eml/" + pitem->mid;
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-2030: remove %s: %s",
				eml_path.c_str(), strerror(errno));
		imap_parser_log_info(pcontext, LV_DEBUG, "message %s has been deleted", eml_path.c_str());
		string_length = gx_snprintf(buff, std::size(buff),
			"* %u EXPUNGE\r\n", ct_item->id - del_num);
		if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
			return 1922;
		del_num ++;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1459: ENOMEM");
	}
	if (!exp_list.empty())
		imap_parser_bcast_expunge(*pcontext, exp_list);
	imap_parser_echo_modify(pcontext, nullptr, true);
	/* IMAP_CODE_2170026: OK EXPUNGE completed */
	auto imap_reply_str = resource_get_imap_code(1726, 1, &string_length);
	string_length = gx_snprintf(buff, std::size(buff),
		"%s %s", argv[0], imap_reply_str);
	if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1246: ENOMEM");
	return 1918;
}

int imap_cmd_parser_unselect(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = iproto_stat::auth;
	pcontext->selected_folder[0] = '\0';
	return 1718;
}

int imap_cmd_parser_search(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	size_t string_length = 0;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 3 || argc > 1024)
		return 1800;
	std::string buff;
	auto ssr = system_services_search(pcontext->maildir,
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
	buff.clear();
	if (pcontext->proto_stat == iproto_stat::select)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170019: OK SEARCH completed */
	auto imap_reply_str = resource_get_imap_code(1719, 1, &string_length);
	buff += argv[0];
	buff += " ";
	buff += imap_reply_str;
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

int imap_cmd_parser_fetch(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int i, num, errnum = 0;
	BOOL b_data;
	BOOL b_detail;
	char buff[1024];
	size_t string_length = 0;
	char* tmp_argv[128];
	imap_seq_list list_uid;
	mdi_list list_data;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 4 || parse_imap_seqx(*pcontext, argv[2], list_uid) != 0)
		return 1800;
	if (!imap_cmd_parser_parse_fetch_args(list_data, &b_detail,
	    &b_data, argv[3], tmp_argv, std::size(tmp_argv)))
		return 1800;
	XARRAY xarray;
	auto ssr = b_detail ?
	           system_services_fetch_detail_uid(pcontext->maildir,
	           pcontext->selected_folder, list_uid, &xarray, &errnum) :
	           fetch_trivial_uid(*pcontext, list_uid, xarray);
	auto result = m2icode(ssr, errnum);
	if (result != 0)
		return result;
	pcontext->stream.clear();
	num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		/*
		 * fetch_detail_uid might have yielded new mails, so filter
		 * with respect to current sequence assignment.
		 */
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		result = imap_cmd_parser_process_fetch_item(pcontext, b_data,
		         pitem, ct_item->id, list_data);
		if (result != 0)
			return result;
	}
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170020: OK FETCH completed */
	{
	auto imap_reply_str = resource_get_imap_code(1720, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	}
	string_length = strlen(buff);
	if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
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

int imap_cmd_parser_store(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
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
	auto ssr = system_services_fetch_simple_uid(pcontext->maildir,
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
		imap_cmd_parser_store_flags(argv[3], pitem->mid,
			ct_item->id, 0, flag_bits, pcontext);
		imap_parser_bcast_flags(*pcontext, pitem->uid);
	}
	imap_parser_echo_modify(pcontext, NULL);
	return 1721;
}

int imap_cmd_parser_copy(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	unsigned int uid;
	int errnum;
	BOOL b_first;
	BOOL b_copied;
	int i, j;
	size_t string_length = 0, string_length1 = 0;
	char buff[64*1024];
	char temp_name[1024];
	imap_seq_list list_uid;
	char uid_string[64*1024];
	char uid_string1[64*1024];
    
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 4 || parse_imap_seqx(*pcontext, argv[2], list_uid) != 0 ||
	    strlen(argv[3]) == 0 || strlen(argv[3]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[3], temp_name))
		return 1800;
	XARRAY xarray;
	auto ssr = system_services_fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_uid, &xarray, &errnum);
	auto result = m2icode(ssr, errnum);
	if (result != 0)
		return result;
	uint32_t uidvalidity = 0;
	if (system_services_summary_folder(pcontext->maildir,
	    temp_name, nullptr, nullptr, nullptr, &uidvalidity, nullptr,
	    &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	string_length = 0;
	string_length1 = 0;
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		pitem = pcontext->contents.get_itemx(pitem->uid);
		if (pitem == nullptr)
			continue;
		if (system_services_copy_mail(pcontext->maildir,
		    pcontext->selected_folder, pitem->mid, temp_name,
		    pitem->mid, &errnum) != MIDB_RESULT_OK) {
			b_copied = FALSE;
			break;
		}
		if (uidvalidity == 0)
			continue;
		for (j = 0; j < 10; j++) {
			if (system_services_get_uid(pcontext->maildir,
			    temp_name, pitem->mid, &uid) != MIDB_RESULT_OK) {
				usleep(500000);
				continue;
			}
			if (b_first) {
				uid_string[string_length++] = ',';
				uid_string1[string_length1++] = ',';
			} else {
				b_first =  TRUE;
			}
			string_length += gx_snprintf(uid_string + string_length,
					 std::size(uid_string) - string_length, "%d", pitem->uid);
			string_length1 += gx_snprintf(uid_string1 + string_length1,
					  std::size(uid_string1) - string_length1, "%d", uid);
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
		system_services_remove_mail(pcontext->maildir,
			temp_name, exp_list, &errnum);
	}
	pcontext->stream.clear();
	if (b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170022: OK <COPYUID> COPY completed */
		auto imap_reply_str = resource_get_imap_code(1722, 1, &string_length);
		auto imap_reply_str1 = resource_get_imap_code(1722, 2, &string_length1);
		if (uidvalidity != 0)
			string_length = gx_snprintf(buff, std::size(buff),
				"%s %s [COPYUID %llu %s %s] %s", argv[0],
				imap_reply_str, LLU{uidvalidity},
				uid_string, uid_string1, imap_reply_str1);
		else
			string_length = gx_snprintf(buff, std::size(buff),
				"%s %s %s", argv[0], imap_reply_str, imap_reply_str1);
	} else {
		/* IMAP_CODE_2190016: NO COPY failed */
		auto imap_reply_str = resource_get_imap_code(1916, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff),
			"%s %s", argv[0], imap_reply_str);
	}
	if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1245: ENOMEM");
	return 1918;
}

int imap_cmd_parser_uid_search(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	size_t string_length = 0;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 3 || argc > 1024)
		return 1800;
	std::string buff;
	auto ssr = system_services_search_uid(pcontext->maildir,
	           pcontext->selected_folder, pcontext->defcharset,
	           argc - 3, &argv[3], buff, &errnum);
	buff.insert(0, "* SEARCH ");
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	buff.append("\r\n");
	pcontext->stream.clear();
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170023: OK UID SEARCH completed */
	auto imap_reply_str = resource_get_imap_code(1723, 1, &string_length);
	buff += argv[0];
	buff += " ";
	buff += imap_reply_str;
	if (pcontext->stream.write(buff.c_str(), buff.size()) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_fetch(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int num;
	int errnum;
	int i;
	BOOL b_data;
	BOOL b_detail;
	char buff[1024];
	size_t string_length = 0;
	char* tmp_argv[128];
	imap_seq_list list_seq;
	mdi_list list_data;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 5 || parse_imap_seq(list_seq, argv[3]) != 0)
		return 1800;
	if (!imap_cmd_parser_parse_fetch_args(list_data, &b_detail,
	    &b_data, argv[4], tmp_argv, std::size(tmp_argv)))
		return 1800;
	if (std::find_if(list_data.cbegin(), list_data.cend(),
	    [](const std::string &e) { return strcasecmp(e.c_str(), "UID") == 0; }) == list_data.cend())
		list_data.emplace_back("UID");
	XARRAY xarray;
	auto ssr = b_detail ?
	           system_services_fetch_detail_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum) :
	           system_services_fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	pcontext->stream.clear();
	num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		ret = imap_cmd_parser_process_fetch_item(pcontext, b_data,
		      pitem, ct_item->id, list_data);
		if (ret != 0)
			return ret;
	}
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170028: OK UID FETCH completed */
	{
	auto imap_reply_str = resource_get_imap_code(1728, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	}
	string_length = strlen(buff);
	if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
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

int imap_cmd_parser_uid_store(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
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
	auto ssr = system_services_fetch_simple_uid(pcontext->maildir,
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
		imap_cmd_parser_store_flags(argv[4], pitem->mid,
			ct_item->id, pitem->uid, flag_bits, pcontext);
		imap_parser_bcast_flags(*pcontext, pitem->uid);
	}
	imap_parser_echo_modify(pcontext, NULL);
	return 1724;
}

int imap_cmd_parser_uid_copy(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	unsigned int uid;
	int errnum;
	BOOL b_first;
	BOOL b_copied;
	int i, j;
	size_t string_length = 0, string_length1 = 0;
	char buff[64*1024];
	char temp_name[1024];
	imap_seq_list list_seq;
	char uid_string[64*1024];
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (argc < 5 || parse_imap_seq(list_seq, argv[3]) != 0 ||
	    strlen(argv[4]) == 0 || strlen(argv[4]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[4], temp_name))
		return 1800;
	XARRAY xarray;
	auto ssr = system_services_fetch_simple_uid(pcontext->maildir,
	           pcontext->selected_folder, list_seq, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	uint32_t uidvalidity = 0;
	if (system_services_summary_folder(pcontext->maildir,
	    temp_name, nullptr, nullptr, nullptr, &uidvalidity,
	    nullptr, &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	string_length = 0;
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		auto pitem = xarray.get_item(i);
		if (system_services_copy_mail(pcontext->maildir,
		    pcontext->selected_folder, pitem->mid, temp_name,
		    pitem->mid, &errnum) != MIDB_RESULT_OK) {
			b_copied = FALSE;
			break;
		}
		if (uidvalidity == 0)
			continue;
		for (j = 0; j < 10; j++) {
			if (system_services_get_uid(pcontext->maildir,
			    temp_name, pitem->mid, &uid) != MIDB_RESULT_OK) {
				usleep(500000);
				continue;
			}
			if (b_first) {
				uid_string[string_length++] = ',';
			} else {
				b_first =  TRUE;
			}
			string_length += gx_snprintf(uid_string + string_length,
			                 std::size(uid_string) - string_length, "%d", uid);
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
		system_services_remove_mail(pcontext->maildir,
			temp_name, exp_list, &errnum);
	}
	pcontext->stream.clear();
	if (b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170025: OK <COPYUID> UID COPY completed */
		auto imap_reply_str = resource_get_imap_code(1725, 1, &string_length);
		auto imap_reply_str1 = resource_get_imap_code(1725, 2, &string_length1);
		if (uidvalidity != 0)
			string_length = gx_snprintf(buff, std::size(buff),
				"%s %s [COPYUID %llu %s %s] %s", argv[0],
				imap_reply_str, LLU{uidvalidity}, argv[3],
				uid_string, imap_reply_str1);
		else
			string_length = gx_snprintf(buff, std::size(buff), "%s %s %s",
					argv[0], imap_reply_str, imap_reply_str1);
	} else {
		/* IMAP_CODE_2190017: NO UID COPY failed */
		auto imap_reply_str = resource_get_imap_code(1917, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "%s %s", argv[0], imap_reply_str);
	}
	if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1244: ENOMEM");
	return 1918;
}

int imap_cmd_parser_uid_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext) try
{
	int errnum;
	int max_uid;
	char buff[1024];
	size_t string_length = 0;
	imap_seq_list list_seq;
	
	if (pcontext->proto_stat != iproto_stat::select)
		return 1805;
	if (pcontext->b_readonly)
		return 1806;
	if (argc < 4 || parse_imap_seq(list_seq, argv[3]) != 0)
		return 1800;
	XARRAY xarray;
	auto ssr = system_services_list_deleted(pcontext->maildir,
	           pcontext->selected_folder, &xarray, &errnum);
	auto ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;
	auto num = xarray.get_capacity();
	if (0 == num) {
		imap_parser_echo_modify(pcontext, NULL);
		return 1730;
	}
	auto pitem = xarray.get_item(num - 1);
	max_uid = pitem->uid;
	std::vector<MITEM *> exp_list;
	for (size_t i = 0; i < num; ++i) {
		pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem) ||
		    !icp_hint_seq(list_seq, pitem->uid, max_uid))
			continue;
		exp_list.push_back(pitem);
	}
	ssr = system_services_remove_mail(pcontext->maildir,
	      pcontext->selected_folder, exp_list, &errnum);
	ret = m2icode(ssr, errnum);
	if (ret != 0)
		return ret;

	pcontext->stream.clear();
	unsigned int del_num = 0;
	for (size_t i = 0; i < xarray.get_capacity(); ++i) try {
		pitem = xarray.get_item(i);
		if (zero_uid_bit(*pitem) ||
		    !icp_hint_seq(list_seq, pitem->uid, max_uid))
			continue;
		auto ct_item = pcontext->contents.get_itemx(pitem->uid);
		if (ct_item == nullptr)
			continue;
		auto eml_path = std::string(pcontext->maildir) + "/eml/" + pitem->mid;
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-2086: remove %s: %s",
				eml_path.c_str(), strerror(errno));
		imap_parser_log_info(pcontext, LV_DEBUG, "message %s has been deleted", eml_path.c_str());
		string_length = gx_snprintf(buff, std::size(buff),
			"* %u EXPUNGE\r\n", ct_item->id - del_num);
		if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
			return 1922;
		del_num ++;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1458: ENOMEM");
	}
	if (!exp_list.empty())
		imap_parser_bcast_expunge(*pcontext, exp_list);
	imap_parser_echo_modify(pcontext, nullptr, true);
	/* IMAP_CODE_2170026: OK UID EXPUNGE completed */
	auto imap_reply_str = resource_get_imap_code(1726, 1, &string_length);
	string_length = gx_snprintf(buff, std::size(buff),
		"%s %s", argv[0], imap_reply_str);
	if (pcontext->stream.write(buff, string_length) != STREAM_WRITE_OK)
		return 1922;
	pcontext->write_offset = 0;
	pcontext->sched_stat = isched_stat::wrlst;
	return DISPATCH_BREAK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1243: ENOMEM");
	return 1918;
}

void imap_cmd_parser_clsfld(IMAP_CONTEXT *pcontext) try
{
	int errnum, result, i;
	BOOL b_deleted;
	char prev_selected[sizeof(pcontext->selected_folder)], buff[1024];
	size_t string_length = 0;
	const char *estring;
	
	if (*pcontext->selected_folder == '\0')
		return;
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = iproto_stat::auth;
	strcpy(prev_selected, pcontext->selected_folder);
	pcontext->selected_folder[0] = '\0';
	if (pcontext->b_readonly)
		return;
	XARRAY xarray;
	result = system_services_list_deleted(pcontext->maildir,
	         prev_selected, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER: {
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		auto imap_reply_str = resource_get_imap_code(1905, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	case MIDB_RDWR_ERROR: {
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		auto imap_reply_str = resource_get_imap_code(1906, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	case MIDB_LOCAL_ENOMEM: {
		auto imap_reply_str = resource_get_imap_code(1920, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	default: {
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		auto imap_reply_str = resource_get_imap_code(1907, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff),
			"* %s%s", imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
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
	result = system_services_remove_mail(pcontext->maildir,
	         prev_selected, exp_list, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		for (i = 0; i < num; ++i) try {
			auto pitem = xarray.get_item(i);
			if (zero_uid_bit(*pitem))
				continue;
			auto eml_path = std::string(pcontext->maildir) + "/eml/" + pitem->mid;
			if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
				mlog(LV_WARN, "W-2087: remove %s: %s",
				        eml_path.c_str(), strerror(errno));
			imap_parser_log_info(pcontext, LV_DEBUG, "message %s has been deleted", eml_path.c_str());
			b_deleted = TRUE;
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1457: ENOMEM");
		}
		break;
	case MIDB_NO_SERVER: {
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		auto imap_reply_str = resource_get_imap_code(1905, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	case MIDB_RDWR_ERROR: {
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		auto imap_reply_str = resource_get_imap_code(1906, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	case MIDB_LOCAL_ENOMEM: {
		auto imap_reply_str = resource_get_imap_code(1920, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	default: {
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		auto imap_reply_str = resource_get_imap_code(1907, 1, &string_length);
		string_length = gx_snprintf(buff, std::size(buff),
			"* %s%s", imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
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
int imap_cmd_parser_dval(int argc, char **argv, IMAP_CONTEXT *ctx, unsigned int ret)
{
	auto code = ret & DISPATCH_VALMASK;
	if (code == 0)
		return ret & DISPATCH_ACTMASK;
	bool trycreate = code == MIDB_E_NO_FOLDER;
	size_t len = 0;
	auto estr = (ret & DISPATCH_MIDB) ? resource_get_error_string(code) : nullptr;
	if (ret & DISPATCH_MIDB)
		code = 1907;
	auto str = resource_get_imap_code(code, 1, &len);
	char buff[1024];
	const char *tag = (ret & DISPATCH_TAG) ? tag_or_bug(ctx->tag_string) :
	                  argc == 0 ? "*" : tag_or_bug(argv[0]);
	len = gx_snprintf(buff, std::size(buff), "%s%s %s%s", tag,
	      trycreate ? " NO [TRYCREATE]" : "", str, znul(estr));
	imap_parser_safe_write(ctx, buff, len);
	return ret & DISPATCH_ACTMASK;
}
