// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
/* 
 * collection of functions for handling the imap command
 */ 
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/mjson.hpp>
#include <gromox/util.hpp>
#include "dir_tree.hpp"
#include "imap_cmd_parser.h"
#include "resource.h"
#include "system_services.h"
#define MAX_DIGLEN		256*1024

using namespace std::string_literals;
using namespace gromox;

namespace {

struct SEQUENCE_NODE {
	DOUBLE_LIST_NODE node;
	int min;
	int max;
};

}

enum {
	TYPE_WILDS = 1,
	TYPE_WILDP
};

static constexpr const char *g_folder_list[] = {"draft", "sent", "trash", "junk"};
static constexpr const char *g_xproperty_list[] = {"Drafts", "Sent", "Trash", "Spam"};

static inline bool special_folder(const char *name)
{
	if (strcasecmp(name, "inbox") == 0)
		return true;
	for (auto s : g_folder_list)
		if (strcmp(name, s) == 0)
			return true;
	return false;
}

static BOOL imap_cmd_parser_hint_sequence(DOUBLE_LIST *plist,
	unsigned int num, unsigned int max_uid)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pseq = static_cast<SEQUENCE_NODE *>(pnode->pdata);
		if (-1 == pseq->max) {
			if (-1 == pseq->min) {
				if (num == max_uid)
					return TRUE;
			} else {
				if (num >= static_cast<size_t>(pseq->min))
					return TRUE;
			}
		} else {
			if (pseq->max >= 0 && static_cast<size_t>(pseq->max) >= num &&
			    pseq->min >= 0 && static_cast<size_t>(pseq->min) <= num)
				return TRUE;
		}
	}
	return FALSE;
}

static BOOL imap_cmd_parser_parse_sequence(DOUBLE_LIST *plist,
    SEQUENCE_NODE *nodes, char *string)
{
	int i, j;
	int len, temp;
	char *last_colon;
	char *last_break;
	
	len = strlen(string);
	if (string[len-1] == ',')
		len --;
	else
		string[len] = ',';

	double_list_init(plist);
	last_break = string;
	last_colon = NULL;
	for (i=0,j=0; i<=len&&j<1024; i++) {
		if (!HX_isdigit(string[i]) && string[i] != '*'
			&& ',' != string[i] && ':' != string[i]) {
			double_list_free(plist);
			return FALSE;
		}
		if (':' == string[i]) {
			if (NULL != last_colon) {
				double_list_free(plist);
				return FALSE;
			} else {
				last_colon = string + i;
				*last_colon = '\0';
			}
		} else if (',' == string[i]) {
			if (0 == string + i - last_break) {
				double_list_free(plist);
				return FALSE;
			}
			string[i] = '\0';
			nodes[j].node.pdata = &nodes[j];
			if (NULL != last_colon) {
				if (0 == strcmp(last_break, "*")) {
					nodes[j].max = -1;
					if (0 == strcmp(last_colon + 1, "*")) {
						nodes[j].min = -1;
					} else {
						nodes[j].min = strtol(last_colon + 1, nullptr, 0);
						if (nodes[j].min <= 0) {
							double_list_free(plist);
							return FALSE;
						}
					}
				} else {
					nodes[j].min = strtol(last_break, nullptr, 0);
					if (nodes[j].min <= 0) {
						double_list_free(plist);
						return FALSE;
					}
					if (0 == strcmp(last_colon + 1, "*")) {
						nodes[j].max = -1;
					} else {
						nodes[j].max = strtol(last_colon + 1, nullptr, 0);
						if (nodes[j].max <= 0) {
							double_list_free(plist);
							return FALSE;
						}
					}
				}
				last_colon = NULL;
			} else {
				if ('*' == *last_break ||
				    (nodes[j].min = strtol(last_break, nullptr, 0)) <= 0) {
					double_list_free(plist);
					return FALSE;
				}
				nodes[j].max = nodes[j].min;
			}
			if (-1 != nodes[j].max && nodes[j].max < nodes[j].min) {
				temp = nodes[j].max;
				nodes[j].max = nodes[j].min;
				nodes[j].min = temp;
			}
			last_break = string + i + 1;
			double_list_append_as_tail(plist, &nodes[j].node);
			j ++;
		}
	}
	if (1024 == j) {
		double_list_free(plist);
		return FALSE;
	}
	return TRUE;
}

static void imap_cmd_parser_find_arg_node(DOUBLE_LIST *plist,
	const char *arg_name, DOUBLE_LIST *plist_to)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		if (0 == strcasecmp((char*)pnode->pdata, arg_name)) {
			double_list_remove(plist, pnode);
			double_list_append_as_tail(plist_to, pnode);
			break;
		}
	}
}

static BOOL imap_cmd_parser_parse_fetch_args(DOUBLE_LIST *plist,
	DOUBLE_LIST_NODE *nodes, BOOL *pb_detail, BOOL *pb_data,
	char *string, char **argv, int argc)
{
	int len;
	int i, j;
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
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;

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
	double_list_init(plist);
	for (i=0; i<tmp_argc; i++) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
		     pnode = double_list_get_after(plist, pnode))
			if (strcasecmp(static_cast<char *>(pnode->pdata), argv[i]) == 0)
				break;
		if (pnode != nullptr)
			continue;
		if (0 == strcasecmp(argv[i], "ALL") ||
			0 == strcasecmp(argv[i], "FAST") ||
			0 == strcasecmp(argv[i], "FULL")) {
			b_macro = TRUE;
			nodes[i].pdata = argv[i];
			double_list_append_as_tail(plist, &nodes[i]);
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
			nodes[i].pdata = argv[i];
			double_list_append_as_tail(plist, &nodes[i]);
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
					len = ptr - last_ptr;
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
			
			len = pend - last_ptr;
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
				for (j = 0; j < len; ++j)
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
			nodes[i].pdata = argv[i];
			double_list_append_as_tail(plist, &nodes[i]);
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
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto kw = static_cast<const char *>(pnode->pdata);
		if (strcasecmp(kw, "ALL") == 0 || strcasecmp(kw, "FAST") == 0 ||
		    strcasecmp(kw, "FULL") == 0) {
			i ++;
			nodes[i].pdata = deconst("INTERNALDATE");
			double_list_append_as_tail(plist, &nodes[i]);
			i ++;
			nodes[i].pdata = deconst("RFC822.SIZE");
			double_list_append_as_tail(plist, &nodes[i]);
			if (strcasecmp(kw, "ALL") == 0 || strcasecmp(kw, "FULL") == 0) {
				i ++;
				nodes[i].pdata = deconst("ENVELOPE");
				double_list_append_as_tail(plist, &nodes[i]);
				if(0 == strcasecmp(kw, "FULL")) {
					i ++;
					nodes[i].pdata = deconst("BODY");
					double_list_append_as_tail(plist, &nodes[i]);
				}
			}
			*pb_detail = TRUE;
			pnode->pdata = deconst("FLAGS");
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
	/* sort args and make simple at the head */
	double_list_init(&temp_list);
	imap_cmd_parser_find_arg_node(plist, "UID", &temp_list);
	imap_cmd_parser_find_arg_node(plist, "FLAGS", &temp_list);
	imap_cmd_parser_find_arg_node(plist, "INTERNALDATE", &temp_list);
	imap_cmd_parser_find_arg_node(plist, "RFC822.SIZE", &temp_list);
	imap_cmd_parser_find_arg_node(plist, "ENVELOPE", &temp_list);
	imap_cmd_parser_find_arg_node(plist, "RFC822.HEADER", &temp_list);
	imap_cmd_parser_find_arg_node(plist, "RFC822.TEXT", &temp_list);
	double_list_append_list(&temp_list, plist);
	*plist = temp_list;
	double_list_free(&temp_list);
	imap_cmd_parser_find_arg_node(plist, "BODY", plist);
	imap_cmd_parser_find_arg_node(plist, "BODYSTRUCTURE", plist);
	imap_cmd_parser_find_arg_node(plist, "RFC822", plist);
	return TRUE;
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
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Answered");
	}
	if (flag_bits & FLAG_FLAGGED) {
		if (b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Flagged");
	}
	if (flag_bits & FLAG_DELETED) {
		if (b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Deleted");
	}
	if (flag_bits & FLAG_SEEN) {
		if (b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Seen");
	}
	if (flag_bits & FLAG_DRAFT) {
		if (b_first) {
			flags_string[len] = ' ';
			len ++;
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
	char *tags, size_t offset1, ssize_t length1, char *value, size_t val_len)
{
	int i;
	BOOL b_hit;
	int tmp_argc, fd;
	char* tmp_argv[128];
	char buff[128*1024];
	char buff1[128*1024];
	char temp_buff[1024];
	MIME_FIELD mime_field;
	
	auto pbody = strchr(cmd_tag, '[');
	if (length > 128 * 1024)
		return -1;
	fd = open(file_path, O_RDONLY);
	if (fd == -1)
		return -1;
	if (lseek(fd, offset, SEEK_SET) < 0)
		fprintf(stderr, "E-1431: lseek: %s\n", strerror(errno));
	gx_strlcpy(temp_buff, tags, arsizeof(temp_buff));
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
	size_t len, len1 = 0, buff_len = 0;
	while ((len = parse_mime_field(buff + buff_len, length - buff_len,
	       &mime_field)) != 0) {
		b_hit = FALSE;
		for (i=0; i<tmp_argc; i++) {
			auto tag_len = strlen(tmp_argv[i]);
			if (tag_len != mime_field.field_name_len ||
			    strncasecmp(tmp_argv[i], mime_field.field_name, tag_len) != 0)
				continue;
			if (!b_not) {
				memcpy(buff1 + len1, buff + buff_len, len);
				len1 += len;
				break;
			}
			b_hit = TRUE;
		}
		if (b_not && !b_hit) {
			memcpy(buff1 + len1, buff + buff_len, len);
			len1 += len;
		}
		buff_len += len;
	}
	buff1[len1] = '\r';
	len1 ++;
	buff1[len1] = '\n';
	len1 ++;
	buff1[len1] = '\0';
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
		     "BODY%s {%zd}\r\n%s", pbody, length1, buff1 + offset1);
	}
	return l2 >= 0 && static_cast<size_t>(l2) >= val_len - 1 ? -1 : l2;
}

static int imap_cmd_parser_print_structure(IMAP_CONTEXT *pcontext,
	MJSON *pjson, char *cmd_tag, char *buff, int max_len, const char *pbody,
	const char *temp_id, char *temp_tag, size_t offset, ssize_t length,
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
				fprintf(stderr, "E-1465: ENOMEM\n");
			}

			len = imap_cmd_parser_match_field(cmd_tag, eml_path.c_str(),
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

static void imap_cmd_parser_process_fetch_item(IMAP_CONTEXT *pcontext,
	BOOL b_data, MITEM *pitem, int item_id, DOUBLE_LIST *pitem_list)
{
	int errnum;
	MJSON mjson(imap_parser_get_jpool());
	char buff[MAX_DIGLEN];
	
	if (pitem->flag_bits & FLAG_LOADED) {
		pitem->f_digest.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		auto len = pitem->f_digest.read(buff, arsizeof(buff));
		if (len == MEM_END_OF_FILE)
			return;
		std::string eml_path;
		try {
			eml_path = std::string(pcontext->maildir) + "/eml";
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1464: ENOMEM\n");
		}
		if (eml_path.size() == 0 ||
		    !mjson.retrieve(buff, len, eml_path.c_str()))
			return;
	}

	BOOL b_first = FALSE;
	int buff_len = 0;
	buff_len += gx_snprintf(buff + buff_len, arsizeof(buff) - buff_len,
	            "* %d FETCH (", item_id);
	for (auto pnode = double_list_get_head(pitem_list); pnode != nullptr;
		pnode=double_list_get_after(pitem_list, pnode)) {
		if (!b_first) {
			b_first = TRUE;
		} else {
			buff[buff_len] = ' ';
			buff_len ++;
		}
		auto kw = static_cast<const char *>(pnode->pdata);
		if (strcasecmp(kw, "BODY") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            arsizeof(buff) - buff_len, "BODY ");
			if (mjson.rfc822_check()) {
				std::string rfc_path;
				try {
					rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				} catch (const std::bad_alloc &) {
					fprintf(stderr, "E-1461: ENOMEM\n");
				}
				if (rfc_path.size() <= 0 ||
				    !mjson.rfc822_build(imap_parser_get_mpool(), rfc_path.c_str()))
					goto FETCH_BODY_SIMPLE;
				auto len = mjson.rfc822_fetch(rfc_path.c_str(),
					resource_get_default_charset(pcontext->lang),
					FALSE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					goto FETCH_BODY_SIMPLE;
				buff_len += len;
			} else {
 FETCH_BODY_SIMPLE:
				auto len = mjson.fetch_structure(resource_get_default_charset(pcontext->lang),
					FALSE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					buff_len += gx_snprintf(buff + buff_len,
					            arsizeof(buff) - buff_len, "NIL");
				else
					buff_len += len;
			}
		} else if (strcasecmp(kw, "BODYSTRUCTURE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            arsizeof(buff) - buff_len, "BODYSTRUCTURE ");
			if (mjson.rfc822_check()) {
				std::string rfc_path;
				try {
					rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				} catch (const std::bad_alloc &) {
					fprintf(stderr, "E-1462: ENOMEM\n");
				}
				if (rfc_path.size() <= 0 ||
				    !mjson.rfc822_build(imap_parser_get_mpool(), rfc_path.c_str()))
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				auto len = mjson.rfc822_fetch(rfc_path.c_str(),
					resource_get_default_charset(pcontext->lang),
					TRUE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				buff_len += len;
			} else {
 FETCH_BODYSTRUCTURE_SIMPLE:
				auto len = mjson.fetch_structure(resource_get_default_charset(pcontext->lang),
					TRUE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (len == -1)
					buff_len += gx_snprintf(buff + buff_len,
					            arsizeof(buff) - buff_len, "NIL");
				else
					buff_len += len;
			}
		} else if (strcasecmp(kw, "ENVELOPE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            arsizeof(buff) - buff_len, "ENVELOPE ");
			auto len = mjson.fetch_envelope(resource_get_default_charset(pcontext->lang),
				buff + buff_len, MAX_DIGLEN - buff_len);
			if (len == -1)
				buff_len += gx_snprintf(buff + buff_len,
				            arsizeof(buff) - buff_len, "NIL");
			else
				buff_len += len;
		} else if (strcasecmp(kw, "FLAGS") == 0) {
			char flags_string[128];
			imap_cmd_parser_convert_flags_string(
				pitem->flag_bits, flags_string);
			buff_len += gx_snprintf(buff + buff_len,
			            arsizeof(buff) - buff_len, "FLAGS %s", flags_string);
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
			buff_len += gx_snprintf(buff + buff_len, arsizeof(buff) - buff_len,
			            "RFC822 ({%zd}\r\n<<{file}%s|0|%zd\r\n)",
			            mjson.get_mail_length(),
			            mjson.get_mail_filename(),
			            mjson.get_mail_length());
			if (!pcontext->b_readonly &&
				0 == (pitem->flag_bits & FLAG_SEEN)) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_modify_flags(pcontext, pitem->mid);
			}
		} else if (strcasecmp(kw, "RFC822.HEADER") == 0) {
			auto pmime = mjson.get_mime("");
			if (pmime != nullptr)
				buff_len += gx_snprintf(buff + buff_len, arsizeof(buff) - buff_len,
				            "RFC822.HEADER ({%zd}\r\n<<{file}%s|0|%zd\r\n)",
				            pmime->get_length(MJSON_MIME_HEAD),
				            mjson.get_mail_filename(),
				            pmime->get_length(MJSON_MIME_HEAD));
			else
				buff_len += gx_snprintf(buff + buff_len,
				            arsizeof(buff) - buff_len, "RFC822.HEADER NIL");
		} else if (strcasecmp(kw, "RFC822.SIZE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            arsizeof(buff) - buff_len,
			            "RFC822.SIZE %zd", mjson.get_mail_length());
		} else if (strcasecmp(kw, "RFC822.TEXT") == 0) {
			auto pmime = mjson.get_mime("");
			if (pmime != nullptr)
				buff_len += gx_snprintf(buff + buff_len,
				            arsizeof(buff) - buff_len,
				            "RFC822.TEXT ({%zd}\r\n<<{file}%s|%zd|%zd\r\n)",
				            pmime->get_length(MJSON_MIME_CONTENT),
				            mjson.get_mail_filename(),
				            pmime->get_offset(MJSON_MIME_CONTENT),
				            pmime->get_length(MJSON_MIME_CONTENT));
			else
				buff_len += gx_snprintf(buff + buff_len,
				            arsizeof(buff) - buff_len, "RFC822.TEXT NIL");
			if (!pcontext->b_readonly &&
				0 == (pitem->flag_bits & FLAG_SEEN)) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_modify_flags(pcontext, pitem->mid);
			}
		} else if (strcasecmp(kw, "UID") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            arsizeof(buff) - buff_len, "UID %d", pitem->uid);
		} else if (strncasecmp(kw, "BODY[", 5) == 0 ||
		    strncasecmp(kw, "BODY.PEEK[", 10) == 0) {
			auto pbody = strchr(static_cast<char *>(pnode->pdata), '[');
			auto ptr = pbody + 1;
			auto pend = strchr(ptr, ']');
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
			auto len = pend - ptr;
			char temp_buff[1024];
			memcpy(temp_buff, ptr, len);
			temp_buff[len] = '\0';
			ptr = NULL;
			for (decltype(len) i = 0; i < len; ++i) {
				if (temp_buff[i] == '.' || HX_isdigit(temp_buff[i]))
					continue;
				ptr = &temp_buff[i];
				*ptr = '\0';
				break;
			}
			const char *temp_id;
			if (ptr == nullptr)
				temp_id = temp_buff;
			else if (ptr < temp_buff)
				temp_id = "";
			else
				temp_id = temp_buff;
			if (0 != strcmp(temp_id, "") &&
			    mjson.rfc822_check()) {
				std::string rfc_path;
				try {
					rfc_path = std::string(pcontext->maildir) + "/tmp/imap.rfc822";
				} catch (const std::bad_alloc &) {
					fprintf(stderr, "E-1463: ENOMEM\n");
				}
				if (rfc_path.size() > 0 &&
				    mjson.rfc822_build(imap_parser_get_mpool(), rfc_path.c_str())) {
					MJSON temp_mjson(imap_parser_get_jpool());
					char mjson_id[64], final_id[64];
					if (mjson.rfc822_get(&temp_mjson, rfc_path.c_str(),
					    temp_id, mjson_id, final_id))
						len = imap_cmd_parser_print_structure(
						      pcontext, &temp_mjson, static_cast<char *>(pnode->pdata),
							buff + buff_len, MAX_DIGLEN - buff_len,
							pbody, final_id, ptr, offset, length,
						      mjson.get_mail_filename());
					else
						len = imap_cmd_parser_print_structure(pcontext,
						      &mjson, static_cast<char *>(pnode->pdata),
						      buff + buff_len, MAX_DIGLEN - buff_len,
						      pbody, temp_id, ptr, offset, length, nullptr);
				} else {
					len = imap_cmd_parser_print_structure(pcontext,
					      &mjson, static_cast<char *>(pnode->pdata),
					      buff + buff_len, MAX_DIGLEN - buff_len,
					      pbody, temp_id, ptr, offset, length, nullptr);
				}
			} else {
				len = imap_cmd_parser_print_structure(pcontext,
				      &mjson, static_cast<char *>(pnode->pdata),
				      buff + buff_len, MAX_DIGLEN - buff_len,
				      pbody, temp_id, ptr, offset, length, nullptr);
			}
			buff_len += len;
			if (!pcontext->b_readonly &&
				0 == (pitem->flag_bits & FLAG_SEEN) &&
			    strncasecmp(kw, "BODY[", 5) == 0) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_modify_flags(pcontext, pitem->mid);
			}
		}
	}
	buff_len += gx_snprintf(buff + buff_len, arsizeof(buff) - buff_len, ")\r\n");
	pcontext->stream.write(buff, buff_len);
	if (!pcontext->b_readonly && pitem->flag_bits & FLAG_RECENT) {
		pitem->flag_bits &= ~FLAG_RECENT;
		if (0 == (pitem->flag_bits & FLAG_SEEN)) {
			system_services_unset_flags(pcontext->maildir,
				pcontext->selected_folder, pitem->mid, FLAG_RECENT, &errnum);
			imap_parser_modify_flags(pcontext, pitem->mid);
		}
	}
}

static void imap_cmd_parser_store_flags(const char *cmd, const char *mid,
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
			FLAG_FLAGGED|FLAG_DELETED|FLAG_SEEN|FLAG_DRAFT, &errnum);
		system_services_set_flags(pcontext->maildir,
			pcontext->selected_folder, mid, flag_bits, &errnum);
		if (0 == strcasecmp(cmd, "FLAGS")) {
			imap_cmd_parser_convert_flags_string(flag_bits, flags_string);
			if (uid != 0)
				string_length = gx_snprintf(buff, arsizeof(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			else
				string_length = gx_snprintf(buff, arsizeof(buff),
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
				string_length = gx_snprintf(buff, arsizeof(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			else
				string_length = gx_snprintf(buff, arsizeof(buff),
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
				string_length = gx_snprintf(buff, arsizeof(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			else
				string_length = gx_snprintf(buff, arsizeof(buff),
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

static BOOL imap_cmd_parser_imapfolder_to_sysfolder(
	const char *lang, const char *imap_folder, char *sys_folder)
{
	int i,len;
	char *ptoken;
	char temp_name[512];
	char temp_folder[512];
	char converted_name[512];
	
	if (utf7_to_utf8(imap_folder, strlen(imap_folder), temp_name, 512) < 0)
		return FALSE;
	len = strlen(temp_name);
	if ('/' == temp_name[len - 1]) {
		len --;
		temp_name[len] = '\0';
	}
	
	ptoken = strchr(temp_name, '/');
	if (NULL == ptoken) {
		gx_strlcpy(temp_folder, temp_name, arsizeof(temp_folder));
	} else {
		memcpy(temp_folder, temp_name, ptoken - temp_name);
		temp_folder[ptoken - temp_name] = '\0';
	}
	if (0 == strcasecmp(temp_folder, "INBOX")) {
		strcpy(temp_folder, "inbox");
	} else {
		auto f_strings = resource_get_folder_strings(lang);
		for (i=0; i<4; i++) {
			if (0 == strcmp(f_strings[i], temp_folder)) {
				gx_strlcpy(temp_folder, g_folder_list[i], arsizeof(temp_folder));
				break;
			}
		}
	}
	if (NULL != ptoken) {
		len = gx_snprintf(converted_name, arsizeof(converted_name), "%s%s", temp_folder, ptoken);
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

static BOOL imap_cmd_parser_sysfolder_to_imapfolder(
	const char *lang, const char *sys_folder, char *imap_folder)
{
	int i;
	char *ptoken;
	char temp_name[512];
	char temp_folder[512];
	char converted_name[512];
	
	if (0 == strcmp("inbox", sys_folder)) {
		strcpy(imap_folder, "INBOX");
		return TRUE;
	} else if (0 == strcmp("draft", sys_folder)) {
		auto f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[0], strlen(f_strings[0]), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("sent", sys_folder)) {
		auto f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[1], strlen(f_strings[1]), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("trash", sys_folder)) {
		auto f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[2], strlen(f_strings[2]), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("junk", sys_folder)) {
		auto f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[3], strlen(f_strings[3]), imap_folder, 1024);
		return TRUE;
	}
	if (!decode_hex_binary(sys_folder, temp_name, arsizeof(temp_name)))
		return FALSE;
	ptoken = strchr(temp_name, '/');
	if (NULL == ptoken) {
		gx_strlcpy(temp_folder, temp_name, arsizeof(temp_folder));
	} else {
		memcpy(temp_folder, temp_name, ptoken - temp_name);
		temp_folder[ptoken - temp_name] = '\0';
	}
	if (0 == strcmp(temp_folder, "inbox")) {
		strcpy(temp_folder, "INBOX");
	} else {
		auto f_strings = resource_get_folder_strings(lang);
		for (i=0; i<4; i++) {
			if (0 == strcmp(g_folder_list[i], temp_folder)) {
				gx_strlcpy(temp_folder, f_strings[i], arsizeof(temp_folder));
				break;
			}
		}
	}
	if (ptoken != nullptr)
		snprintf(converted_name, 512, "%s%s", temp_folder, ptoken);
	else
		strcpy(converted_name, temp_folder);
	if (utf8_to_utf7(converted_name, strlen(converted_name),
	    imap_folder, 1024) <= 0)
		return FALSE;
	return TRUE;
}

static void imap_cmd_parser_convert_folderlist(
	const char *lang, MEM_FILE *pfile)
{
	MEM_FILE temp_file;
	char temp_name[512];
	char converted_name[1024];
	
	mem_file_init(&temp_file, imap_parser_get_allocator());
	while (pfile->readline(temp_name, arsizeof(temp_name)) != MEM_END_OF_FILE)
		if (imap_cmd_parser_sysfolder_to_imapfolder(lang, temp_name, converted_name))
			temp_file.writeline(converted_name);
	pfile->clear();
	temp_file.copy_to(*pfile);
	mem_file_free(&temp_file);
}

int imap_cmd_parser_capability(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170001: OK CAPABILITY completed */
	auto imap_reply_str = resource_get_imap_code(1701, 1, &string_length);
	char ext_str[16]{};
	if (g_support_starttls)
		HX_strlcat(ext_str, " STARTTLS", arsizeof(ext_str));
	if (parse_bool(resource_get_string("enable_rfc2971_commands")))
		HX_strlcat(ext_str, " ID", arsizeof(ext_str));
	string_length = gx_snprintf(buff, arsizeof(buff),
	                "* CAPABILITY IMAP4rev1 XLIST SPECIAL-USE "
	                "UNSELECT UIDPLUS IDLE AUTH=LOGIN%s\r\n%s %s",
	                ext_str, argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_id(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	if (parse_bool(resource_get_string("enable_rfc2971_commands"))) {
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
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
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
	
	string_length = gx_snprintf(buff, arsizeof(buff), "* %s%s %s",
			imap_reply_str, argv[0], imap_reply_str2);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_SHOULD_CLOSE;
}

int imap_cmd_parser_starttls(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->connection.ssl != nullptr)
		return 1800;
	if (!g_support_starttls)
		return 1800;
	if (pcontext->proto_stat > PROTO_STAT_NOAUTH)
		return 1801;
	pcontext->sched_stat = SCHED_STAT_STLS;	
	return 1704;
}

int imap_cmd_parser_authenticate(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t string_length = 0;
	
	if (g_support_starttls && g_force_starttls &&
	    pcontext->connection.ssl == nullptr)
		return 1802;
	if (argc != 3 || strcasecmp(argv[2], "LOGIN") != 0)
		return 1800;
	if (pcontext->proto_stat >= PROTO_STAT_AUTH)
		return 1803;
	gx_strlcpy(pcontext->tag_string, argv[0], arsizeof(pcontext->tag_string));
	pcontext->proto_stat = PROTO_STAT_USERNAME;
	string_length = gx_snprintf(buff, arsizeof(buff), "+ VXNlciBOYW1lAA==\r\n");
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
	    pcontext->username, arsizeof(pcontext->username),
	    &temp_len) != 0) {
		pcontext->proto_stat = PROTO_STAT_NOAUTH;
		return 1819 | DISPATCH_TAG;
	}
	pcontext->proto_stat = PROTO_STAT_PASSWORD;
	string_length = gx_snprintf(buff, arsizeof(buff), "+ UGFzc3dvcmQA\r\n");
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_username(int argc, char **argv, IMAP_CONTEXT *ctx)
{
	return imap_cmd_parser_dval(argc, argv, ctx,
	       imap_cmd_parser_username2(argc, argv, ctx));
}

static int imap_cmd_parser_password2(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	size_t temp_len;
	char reason[256];
	char temp_password[256];
	
	pcontext->proto_stat = PROTO_STAT_NOAUTH;
	if (strlen(argv[0]) == 0 || decode64_ex(argv[0], strlen(argv[0]),
	    temp_password, arsizeof(temp_password), &temp_len) != 0)
		return 1820 | DISPATCH_TAG;
	HX_strltrim(pcontext->username);
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		imap_parser_log_info(pcontext, LV_NOTICE, "user %s is "
			"denied by user filter", pcontext->username);
		return 1901 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
    }
	if (system_services_auth_login(pcontext->username, temp_password,
	    pcontext->maildir, arsizeof(pcontext->maildir), pcontext->lang,
	    arsizeof(pcontext->lang), reason, arsizeof(reason),
	    USER_PRIVILEGE_IMAP)) {
		if (*pcontext->maildir == '\0')
			return 1902 | DISPATCH_TAG;
		if (*pcontext->lang == '\0')
			gx_strlcpy(pcontext->lang, resource_get_string("DEFAULT_LANG"), arsizeof(pcontext->lang));
		pcontext->proto_stat = PROTO_STAT_AUTH;
		imap_parser_log_info(pcontext, LV_DEBUG, "login success");
		return 1705 | DISPATCH_TAG;
	}
	imap_parser_log_info(pcontext, LV_WARN, "PASSWORD2 failed: %s", reason);
	pcontext->auth_times ++;
	if (pcontext->auth_times >= g_max_auth_times) {
		if (system_services_add_user_into_temp_list != nullptr)
			system_services_add_user_into_temp_list(pcontext->username,
				g_block_auth_fail);
		return 1903 | DISPATCH_TAG | DISPATCH_SHOULD_CLOSE;
	}
	return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
}

int imap_cmd_parser_password(int argc, char **argv, IMAP_CONTEXT *ctx)
{
	return imap_cmd_parser_dval(argc, argv, ctx,
	       imap_cmd_parser_password2(argc, argv, ctx));
}

int imap_cmd_parser_login(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char reason[256];
	char temp_password[256];
    
	if (g_support_starttls && g_force_starttls &&
	    pcontext->connection.ssl == nullptr)
		return 1802;
	if (argc != 4 || strlen(argv[2]) >= arsizeof(pcontext->username) ||
	    strlen(argv[3]) > 255)
		return 1800;
	if (pcontext->proto_stat >= PROTO_STAT_AUTH)
		return 1803;
	gx_strlcpy(pcontext->username, argv[2], arsizeof(pcontext->username));
	HX_strltrim(pcontext->username);
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		imap_parser_log_info(pcontext, LV_WARN, "user %s is "
			"denied by user filter", pcontext->username);
		return 1901 | DISPATCH_SHOULD_CLOSE;
    }
	strcpy(temp_password, argv[3]);
	HX_strltrim(temp_password);
	if (system_services_auth_login(pcontext->username, temp_password,
	    pcontext->maildir, arsizeof(pcontext->maildir), pcontext->lang,
	    arsizeof(pcontext->lang), reason, arsizeof(reason),
	    USER_PRIVILEGE_IMAP)) {
		if (*pcontext->maildir == '\0')
			return 1902;
		if (*pcontext->lang == '\0')
			gx_strlcpy(pcontext->lang, resource_get_string("DEFAULT_LANG"), arsizeof(pcontext->lang));
		pcontext->proto_stat = PROTO_STAT_AUTH;
		imap_parser_log_info(pcontext, LV_DEBUG, "login success");
		return 1705;
	}
	imap_parser_log_info(pcontext, LV_WARN, "LOGIN failed: %s", reason);
	pcontext->auth_times++;
	if (pcontext->auth_times >= g_max_auth_times) {
		if (system_services_add_user_into_temp_list != nullptr)
			system_services_add_user_into_temp_list(pcontext->username,
				g_block_auth_fail);
		return 1903 | DISPATCH_SHOULD_CLOSE;
	}
	gx_strlcpy(pcontext->tag_string, argv[0], arsizeof(pcontext->tag_string));
	return 1904 | DISPATCH_CONTINUE | DISPATCH_TAG;
}

int imap_cmd_parser_idle(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc != 2)
		return 1800;
	gx_strlcpy(pcontext->tag_string, argv[0], arsizeof(pcontext->tag_string));
	pcontext->sched_stat = SCHED_STAT_IDLING;
	return 1602;
}

int imap_cmd_parser_select(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int exists;
	int recent;
	unsigned int uidnext;
	unsigned long uidvalid;
	int firstunseen;
	size_t string_length = 0;
	char temp_name[1024];
	char buff[1024];
    
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = PROTO_STAT_AUTH;
		pcontext->selected_folder[0] = '\0';
	}
	
	switch (system_services_summary_folder(pcontext->maildir, temp_name,
	        &exists, &recent, nullptr, &uidvalid, &uidnext, &firstunseen, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	strcpy(pcontext->selected_folder, temp_name);
	pcontext->proto_stat = PROTO_STAT_SELECT;
	pcontext->b_readonly = FALSE;
	imap_parser_add_select(pcontext);
	if (firstunseen != -1)
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
			"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n"
			"* %d EXISTS\r\n"
			"* %d RECENT\r\n"
			"* OK [UNSEEN %d] message %d is first unseen\r\n"
			"* OK [UIDVALIDITY %u] UIDs valid\r\n"
			"* OK [UIDNEXT %d] predicted next UID\r\n"
			"%s OK [READ-WRITE] SELECT completed\r\n", 
			exists, recent, firstunseen, firstunseen,
			(unsigned int)uidvalid, uidnext, argv[0]);
	else
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
			"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n"
			"* %d EXISTS\r\n"
			"* %d RECENT\r\n"
			"* OK [UIDVALIDITY %u] UIDs valid\r\n"
			"* OK [UIDNEXT %d] predicted next UID\r\n"
			"%s OK [READ-WRITE] SELECT completed\r\n", 
			exists, recent, (unsigned int)uidvalid, uidnext, argv[0]);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_examine(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int exists;
	int recent;
	unsigned int uidnext;
	unsigned long uidvalid;
	int firstunseen;
	size_t string_length = 0;
	char temp_name[1024];
	char buff[1024];
    
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_remove_select(pcontext);
		pcontext->proto_stat = PROTO_STAT_AUTH;
		pcontext->selected_folder[0] = '\0';
	}
	switch (system_services_summary_folder(pcontext->maildir, temp_name,
	        &exists, &recent, nullptr, &uidvalid, &uidnext, &firstunseen, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	strcpy(pcontext->selected_folder, temp_name);
	pcontext->proto_stat = PROTO_STAT_SELECT;
	pcontext->b_readonly = TRUE;
	imap_parser_add_select(pcontext);
	if (firstunseen != -1)
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
			"* OK [PERMANENTFLAGS ()] no permanenet flag permited\r\n"
			"* %d EXISTS\r\n"
			"* %d RECENT\r\n"
			"* OK [UNSEEN %d] message %d is first unseen\r\n"
			"* OK [UIDVALIDITY %u] UIDs valid\r\n"
			"* OK [UIDNEXT %d] predicted next UID\r\n"
			"%s OK [READ-ONLY] EXAMINE completed\r\n",
			exists, recent, firstunseen, firstunseen,
			(unsigned int)uidvalid, uidnext, argv[0]);
	else
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
			"* OK [PERMANENTFLAGS ()] no permanenet flag permited\r\n"
			"* %d EXISTS\r\n"
			"* %d RECENT\r\n"
			"* OK [UIDVALIDITY %u] UIDs valid\r\n"
			"* OK [UIDNEXT %d] predicted next UID\r\n"
			"%s OK [READ-ONLY] EXAMINE completed\r\n",
			exists, recent, (unsigned int)uidvalid, uidnext, argv[0]);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_create(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, len;
	BOOL b_found;
	MEM_FILE temp_file;
	char temp_name[1024];
	char temp_name1[1024];
	char temp_folder[1024];
	char converted_name[1024];

	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	if (strpbrk(argv[2], "%*?") != nullptr)
		return 1910;
	if (special_folder(temp_name))
		return 1911;
	mem_file_init(&temp_file, imap_parser_get_allocator());
	switch (system_services_enum_folders(
	        pcontext->maildir, &temp_file, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		mem_file_free(&temp_file);
		return 1905;
	case MIDB_RDWR_ERROR:
		mem_file_free(&temp_file);
		return 1906;
	default:
		mem_file_free(&temp_file);
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	temp_file.writeline("inbox");
	temp_file.writeline("draft");
	temp_file.writeline("sent");
	temp_file.writeline("trash");
	temp_file.writeline("junk");
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	strcpy(temp_name, argv[2]);
	len = strlen(temp_name);
	if ('/' == temp_name[len - 1]) {
		len --;
		temp_name[len] = '\0';
	}
	for (i=0; i<=len; i++) {
		if (temp_name[i] != '/' && temp_name[i] != '\0') {
			temp_name1[i] = temp_name[i];
			continue;
		}
		temp_name1[i] = '\0';
		b_found = FALSE;
		temp_file.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (temp_file.readline(temp_folder,
		       arsizeof(temp_folder)) != MEM_END_OF_FILE) {
			if (0 == strcmp(temp_folder, temp_name1)) {
				b_found = TRUE;
				break;
			}
		}
		if (b_found) {
			temp_name1[i] = temp_name[i];
			continue;
		}
		imap_cmd_parser_imapfolder_to_sysfolder(
			pcontext->lang, temp_name1, converted_name);
		switch (system_services_make_folder(
			pcontext->maildir, converted_name, &errnum)) {
		case MIDB_RESULT_OK:
			break;
		case MIDB_NO_SERVER:
			mem_file_free(&temp_file);
			return 1905;
		case MIDB_RDWR_ERROR:
			mem_file_free(&temp_file);
			return 1906;
		default:
			mem_file_free(&temp_file);
			return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
		}
		temp_name1[i] = temp_name[i];
	}
	mem_file_free(&temp_file);
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	return 1706;
}

int imap_cmd_parser_delete(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char encoded_name[1024];

	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], encoded_name))
		return 1800;
	if (special_folder(encoded_name))
		return 1913;
	switch (system_services_remove_folder(
	        pcontext->maildir, encoded_name, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	return 1707;
}

int imap_cmd_parser_rename(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char encoded_name[1024];
	char encoded_name1[1024];

	if (pcontext->proto_stat < PROTO_STAT_AUTH)
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
	switch (system_services_rename_folder(pcontext->maildir,
	        encoded_name, encoded_name1, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	return 1708;
}

int imap_cmd_parser_subscribe(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char temp_name[1024];

	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	switch (system_services_subscribe_folder(
	        pcontext->maildir, temp_name, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	return 1709;
}

int imap_cmd_parser_unsubscribe(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char temp_name[1024];

	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 3 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name))
		return 1800;
	switch (system_services_unsubscribe_folder(
	        pcontext->maildir, temp_name, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	return 1710;
}

int imap_cmd_parser_list(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int len;
	int errnum;
	size_t string_length = 0;
	MEM_FILE temp_file;
	char buff[256*1024];
	char temp_name[1024];
	char search_pattern[1024];
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 4 || (strcasecmp(argv[2], "(SPECIAL-USE)") == 0 && argc < 5))
		return 1800;
	if (0 != strcasecmp(argv[2], "(SPECIAL-USE)")) {
		if (strlen(argv[2]) + strlen(argv[3]) >= 1024)
			return 1800;
		if ('\0' == argv[3][0]) {
			if (pcontext->proto_stat == PROTO_STAT_SELECT)
				imap_parser_echo_modify(pcontext, NULL);
			/* IMAP_CODE_2170011: OK LIST completed */
			auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
			string_length = gx_snprintf(buff, arsizeof(buff),
				"* LIST (\\Noselect) \"/\" \"\"\r\n%s %s",
				argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		snprintf(search_pattern, 1024, "%s%s", argv[2], argv[3]);
		mem_file_init(&temp_file, imap_parser_get_allocator());
		switch (system_services_enum_folders(
		        pcontext->maildir, &temp_file, &errnum)) {
		case MIDB_RESULT_OK:
			break;
		case MIDB_NO_SERVER:
			mem_file_free(&temp_file);
			return 1905;
		case MIDB_RDWR_ERROR:
			mem_file_free(&temp_file);
			return 1906;
		default:
			mem_file_free(&temp_file);
			return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
		}
		temp_file.writeline("inbox");
		temp_file.writeline("draft");
		temp_file.writeline("sent");
		temp_file.writeline("trash");
		temp_file.writeline("junk");
		imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
		dir_tree temp_tree(imap_parser_get_dpool());
		temp_tree.retrieve(&temp_file);
		len = 0;
		temp_file.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (temp_file.readline(temp_name, arsizeof(temp_name)) != MEM_END_OF_FILE) {
			if (!imap_cmd_parser_wildcard_match(temp_name, search_pattern))
				continue;
			auto pdir = temp_tree.match(temp_name);
			if (pdir != nullptr && temp_tree.get_child(pdir) != nullptr)
				len += gx_snprintf(buff + len, arsizeof(buff) - len,
				       "* LIST (\\HasChildren) \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
			else
				len += gx_snprintf(buff + len, arsizeof(buff) - len,
				       "* LIST (\\HasNoChildren) \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
		}
		mem_file_free(&temp_file);
		pcontext->stream.clear();
		if (pcontext->proto_stat == PROTO_STAT_SELECT)
			imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170011: OK LIST completed */
		auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
		len += gx_snprintf(buff + len, arsizeof(buff) - len,
				"%s %s", argv[0], imap_reply_str);
		pcontext->stream.write(buff, len);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	}

	if (strlen(argv[3]) + strlen(argv[4]) >= 1024)
		return 1800;
	if ('\0' == argv[4][0]) {
		if (pcontext->proto_stat == PROTO_STAT_SELECT)
			imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170011: OK LIST completed */
		auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
		                "* LIST (\\Noselect) \"/\" \"\"\r\n%s %s",
		                argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	snprintf(search_pattern, 1024, "%s%s", argv[3], argv[4]);
	mem_file_init(&temp_file, imap_parser_get_allocator());
	temp_file.writeline("inbox");
	temp_file.writeline("draft");
	temp_file.writeline("sent");
	temp_file.writeline("trash");
	temp_file.writeline("junk");
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	len = 0;
	while (temp_file.readline(temp_name, arsizeof(temp_name)) != MEM_END_OF_FILE)
		if (imap_cmd_parser_wildcard_match(temp_name, search_pattern))
			len += gx_snprintf(buff + len, arsizeof(buff) - len,
			       "* LIST () \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
	mem_file_free(&temp_file);
	pcontext->stream.clear();
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170011: OK LIST completed */
	auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
	len += gx_snprintf(buff + len, arsizeof(buff) - len, "%s %s", argv[0], imap_reply_str);
	pcontext->stream.write(buff, len);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_xlist(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, len;
	size_t string_length = 0;
	MEM_FILE temp_file;
	char buff[256*1024];
	char temp_name[1024];
	char search_pattern[1024];
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 4)
		return 1800;
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024)
		return 1800;
	snprintf(search_pattern, 1024, "%s%s", argv[2], *argv[3] == '\0' ? "*" : argv[3]);
	mem_file_init(&temp_file, imap_parser_get_allocator());
	switch (system_services_enum_folders(
	        pcontext->maildir, &temp_file, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		mem_file_free(&temp_file);
		return 1905;
	case MIDB_RDWR_ERROR:
		mem_file_free(&temp_file);
		return 1906;
	default:
		mem_file_free(&temp_file);
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	dir_tree temp_tree(imap_parser_get_dpool());
	temp_tree.retrieve(&temp_file);
	len = 0;
	if (imap_cmd_parser_wildcard_match("INBOX", search_pattern)) {
		auto pdir = temp_tree.match("INBOX");
		if (pdir != nullptr && temp_tree.get_child(pdir) != nullptr)
			len = gx_snprintf(buff + len, arsizeof(buff),
				"* XLIST (\\Inbox \\HasChildren) \"/\" \"INBOX\"\r\n");
		else
			len = gx_snprintf(buff + len, arsizeof(buff),
				"* XLIST (\\Inbox \\HasNoChildren) \"/\" \"INBOX\"\r\n");
	}
	for (i=0; i<4; i++) {
		imap_cmd_parser_sysfolder_to_imapfolder(
			pcontext->lang, g_folder_list[i], temp_name);
		if (imap_cmd_parser_wildcard_match(temp_name, search_pattern)) {
			auto pdir = temp_tree.match(temp_name);
			if (pdir != nullptr && temp_tree.get_child(pdir) != nullptr)
				len += gx_snprintf(buff + len, arsizeof(buff) - len,
					"* XLIST (\\%s \\HasChildren) \"/\" \"%s\"\r\n",
					g_xproperty_list[i], temp_name);
			else
				len += gx_snprintf(buff + len, arsizeof(buff) - len,
					"* XLIST (\\%s \\HasNoChildren) \"/\" \"%s\"\r\n",
					g_xproperty_list[i], temp_name);
		}
	}
	temp_file.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (temp_file.readline(temp_name, arsizeof(temp_name)) != MEM_END_OF_FILE) {
		if (!imap_cmd_parser_wildcard_match(temp_name, search_pattern))
			continue;
		auto pdir = temp_tree.match(temp_name);
		if (pdir != nullptr && temp_tree.get_child(pdir) != nullptr)
			len += gx_snprintf(buff + len, arsizeof(buff) - len,
				"* XLIST (\\HasChildren) \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
		else
			len += gx_snprintf(buff + len, arsizeof(buff) - len,
				"* XLIST (\\HasNoChildren) \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
	}
	mem_file_free(&temp_file);
	pcontext->stream.clear();
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170012: OK XLIST completed */
	auto imap_reply_str = resource_get_imap_code(1712, 1, &string_length);
	len += gx_snprintf(buff + len, arsizeof(buff) - len,
			"%s %s", argv[0], imap_reply_str);
	
	pcontext->stream.write(buff, len);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_lsub(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int len;
	int errnum;
	size_t string_length = 0;
	MEM_FILE temp_file;
	MEM_FILE temp_file1;
	char buff[256*1024];
	char temp_name[1024];
	char search_pattern[1024];
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 4)
		return 1800;
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024)
		return 1800;
	if ('\0' == argv[3][0]) {
		if (pcontext->proto_stat == PROTO_STAT_SELECT)
			imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170011: OK LIST completed */
		auto imap_reply_str = resource_get_imap_code(1711, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* LSUB (\\Noselect) \"/\" \"\"\r\n%s %s",
			argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	snprintf(search_pattern, 1024, "%s%s", argv[2], argv[3]);		
	mem_file_init(&temp_file, imap_parser_get_allocator());
	switch (system_services_enum_subscriptions(
	        pcontext->maildir, &temp_file, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		mem_file_free(&temp_file);
		return 1905;
	case MIDB_RDWR_ERROR:
		mem_file_free(&temp_file);
		return 1906;
	default:
		mem_file_free(&temp_file);
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	mem_file_init(&temp_file1, imap_parser_get_allocator());
	system_services_enum_folders(pcontext->maildir, &temp_file1, &errnum);
	temp_file1.writeline("inbox");
	temp_file1.writeline("draft");
	temp_file1.writeline("sent");
	temp_file1.writeline("trash");
	temp_file1.writeline("junk");
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file1);
	dir_tree temp_tree(imap_parser_get_dpool());
	temp_tree.retrieve(&temp_file1);
	mem_file_free(&temp_file1);
	len = 0;
	while (temp_file.readline(temp_name, arsizeof(temp_name)) != MEM_END_OF_FILE) {
		if (!imap_cmd_parser_wildcard_match(temp_name, search_pattern))
			continue;
		auto pdir = temp_tree.match(temp_name);
		if (pdir != nullptr && temp_tree.get_child(pdir) != nullptr)
			len += gx_snprintf(buff + len, arsizeof(buff) - len,
				"* LSUB (\\HasChildren) \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
		else
			len += gx_snprintf(buff + len, arsizeof(buff) - len,
				"* LSUB (\\HasNoChildren) \"/\" {%zu}\r\n%s\r\n", strlen(temp_name), temp_name);
	}
	mem_file_free(&temp_file);
	pcontext->stream.clear();
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170013: OK LSUB completed */
	auto imap_reply_str = resource_get_imap_code(1713, 1, &string_length);
	len += gx_snprintf(buff + len, arsizeof(buff) - len,
			"%s %s", argv[0], imap_reply_str);
	pcontext->stream.write(buff, len);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_status(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int i;
	int errnum;
	int exists;
	int recent;
	int unseen;
	unsigned int uidnext;
	BOOL b_first;
	unsigned long uidvalid;
	int temp_argc;
	char buff[1024];
	size_t string_length = 0;
	char *temp_argv[16];
	char temp_name[1024];
    
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
		return 1804;
	if (argc < 4 || strlen(argv[2]) == 0 || strlen(argv[2]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[2], temp_name) ||
	    argv[3][0] != '(' || argv[3][strlen(argv[3])-1] != ')')
		return 1800;
	temp_argc = parse_imap_args(argv[3] + 1,
		strlen(argv[3]) - 2, temp_argv, sizeof(temp_argv));
	if (temp_argc == -1)
		return 1800;
	switch (system_services_summary_folder(
		pcontext->maildir, temp_name, &exists, &recent,
	        &unseen, &uidvalid, &uidnext, nullptr, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	/* IMAP_CODE_2170014: OK STATUS completed */
	auto imap_reply_str = resource_get_imap_code(1714, 1, &string_length);
	string_length = gx_snprintf(buff, arsizeof(buff), "* STATUS {%zu}\r\n%s (", strlen(argv[2]), argv[2]);
	b_first = TRUE;
	for (i=0; i<temp_argc; i++) {
		if (!b_first) {
			buff[string_length] = ' ';
			string_length ++;
		} else {
			b_first = FALSE;
		}
		if (strcasecmp(temp_argv[i], "MESSAGES") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 arsizeof(buff) - string_length, "MESSAGES %d", exists);
		else if (strcasecmp(temp_argv[i], "RECENT") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 arsizeof(buff) - string_length, "RECENT %d", recent);
		else if (strcasecmp(temp_argv[i], "UIDNEXT") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 arsizeof(buff) - string_length, "UIDNEXT %d", uidnext);
		else if (strcasecmp(temp_argv[i], "UIDVALIDITY") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 arsizeof(buff) - string_length, "UIDVALIDITY %u",
					(unsigned int)uidvalid);
		else if (strcasecmp(temp_argv[i], "UNSEEN") == 0)
			string_length += gx_snprintf(buff + string_length,
			                 arsizeof(buff) - string_length, "UNSEEN %d", unseen);
		else
			return 1800;
	}
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	string_length += gx_snprintf(buff + string_length,
	                 arsizeof(buff) - string_length, ")\r\n%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_append(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum, i;
	BOOL b_seen;
	BOOL b_draft;
	unsigned long uidvalid;
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
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
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
	MAIL imail(imap_parser_get_mpool());
	if (!imail.retrieve(argv[argc-1], strlen(argv[argc-1])))
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
		             resource_get_string("host_id");
		eml_path = std::string(pcontext->maildir) + "/eml/" + mid_string;
		fd = open(eml_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0666);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1456: ENOMEM\n");
	}
	if (fd < 0 || !imail.to_file(fd)) {
		if (-1 != fd) {
			close(fd);
			if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
				fprintf(stderr, "W-1370: remove %s: %s\n",
				        eml_path.c_str(), strerror(errno));
		}
		return 1909;
	}
	close(fd);
	imail.clear();

	switch (system_services_insert_mail(pcontext->maildir,
	        temp_name, mid_string.c_str(), flag_buff, tmp_time, &errnum)) {
	case MIDB_RESULT_OK:
		imap_parser_log_info(pcontext, LV_DEBUG, "message %s is appended OK", eml_path.c_str());
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	imap_parser_touch_modify(NULL, pcontext->username,
							pcontext->selected_folder);
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	auto imap_reply_str = resource_get_imap_code(1715, 1, &string_length);
	auto imap_reply_str1 = resource_get_imap_code(1715, 2, &string_length1);
	for (i=0; i<10; i++) {
		if (system_services_summary_folder(pcontext->maildir,
		    temp_name, nullptr, nullptr, nullptr, &uidvalid, nullptr,
		    nullptr, &errnum) == MIDB_RESULT_OK &&
		    system_services_get_uid(pcontext->maildir, temp_name,
		    mid_string.c_str(), &uid) == MIDB_RESULT_OK) {
			string_length = gx_snprintf(buff, arsizeof(buff),
			                "%s %s [APPENDUID %u %d] %s",
				argv[0], imap_reply_str, (unsigned int)uidvalid,
				uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (i == 10)
		string_length = gx_snprintf(buff, arsizeof(buff), "%s %s %s",
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
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH)
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
		gx_strlcpy(str_flags, flags_string, arsizeof(str_flags));
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
			resource_get_string("HOST_ID");
		pcontext->file_path = pcontext->maildir + "/tmp/"s + pcontext->mid;
	} catch (const std::bad_alloc &) {
		return 1918 | DISPATCH_BREAK;
	}
	int fd = open(pcontext->file_path.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0666);
	if (fd == -1)
		return 1909 | DISPATCH_BREAK;
	len = sizeof(uint32_t);
	len += gx_snprintf(buff + len, arsizeof(buff) - len, "%s", temp_name);
	buff[len] = '\0';
	len ++;
	if (flags_string != nullptr)
		len += gx_snprintf(buff + len, arsizeof(buff) - len, "%s", str_flags);
	buff[len] = '\0';
	len ++;
	if (str_received != nullptr)
		len += gx_snprintf(buff + len, arsizeof(buff) - len, "%s", str_received);
	buff[len] = '\0';
	len ++;
	cpu_to_le32p(buff, len);
	write(fd, buff, len);
	pcontext->message_fd = fd;
	gx_strlcpy(pcontext->tag_string, argv[0], arsizeof(pcontext->tag_string));
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
	int tmp_len;
	BOOL b_seen;
	BOOL b_draft;
	int name_len;
	unsigned long uidvalid;
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
			fprintf(stderr, "W-1342: remove %s: %s\n",
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
			fprintf(stderr, "W-1343: remove %s: %s\n",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->message_fd = -1;
		pcontext->mid.clear();
		pcontext->file_path.clear();
		return 1909 | DISPATCH_TAG;
	}
	close(pcontext->message_fd);
	pcontext->message_fd = -1;
	memcpy(&tmp_len, pbuff.get(), sizeof(tmp_len));
	MAIL imail(imap_parser_get_mpool());
	if (!imail.retrieve(pbuff.get() + tmp_len, node_stat.st_size - tmp_len)) {
		imail.clear();
		pbuff.reset();
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1344: remove %s: %s\n",
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
	gx_strlcpy(temp_name, str_name, arsizeof(temp_name));
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
		fd = open(eml_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0666);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1460: ENOMEM\n");
	}
	if (fd < 0 || !imail.to_file(fd)) {
		imail.clear();
		pbuff.reset();
		if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
			fprintf(stderr, "W-1345: remove %s: %s\n",
				pcontext->file_path.c_str(), strerror(errno));
		pcontext->mid.clear();
		pcontext->file_path.clear();
		if (-1 != fd) {
			close(fd);
			if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
				fprintf(stderr, "W-1346: remove %s: %s\n",
				        eml_path.c_str(), strerror(errno));
		}
		return 1909;
	}
	close(fd);
	imail.clear();
	pbuff.reset();
	if (remove(pcontext->file_path.c_str()) < 0 && errno != ENOENT)
		fprintf(stderr, "W-1336: remove %s: %s\n",
			pcontext->file_path.c_str(), strerror(errno));
	pcontext->file_path.clear();
	switch (system_services_insert_mail(pcontext->maildir, temp_name,
	        pcontext->mid.c_str(), flag_buff, tmp_time, &errnum)) {
	case MIDB_RESULT_OK:
		pcontext->mid.clear();
		imap_parser_log_info(pcontext, LV_DEBUG, "message %s is appended OK", eml_path.c_str());
		break;
	case MIDB_NO_SERVER:
		pcontext->mid.clear();
		return 1905 | DISPATCH_TAG;
	case MIDB_RDWR_ERROR:
		pcontext->mid.clear();
		return 1906 | DISPATCH_TAG;
	default:
		pcontext->mid.clear();
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB | DISPATCH_TAG;
	}
	imap_parser_touch_modify(NULL, pcontext->username,
							pcontext->selected_folder);
	if (pcontext->proto_stat == PROTO_STAT_SELECT)
		imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	auto imap_reply_str = resource_get_imap_code(1715, 1, &string_length);
	auto imap_reply_str1 = resource_get_imap_code(1715, 2, &string_length1);
	for (i=0; i<10; i++) {
		if (system_services_summary_folder(pcontext->maildir,
		    temp_name, nullptr, nullptr, nullptr, &uidvalid,
		    nullptr, nullptr, &errnum) == MIDB_RESULT_OK &&
		    system_services_get_uid(pcontext->maildir, temp_name,
		    pcontext->mid.c_str(), &uid) == MIDB_RESULT_OK) {
			string_length = gx_snprintf(buff, arsizeof(buff), "%s %s [APPENDUID %u %d] %s",
				pcontext->tag_string, imap_reply_str, (unsigned int)uidvalid,
				uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (i == 10)
		string_length = gx_snprintf(buff, arsizeof(buff), "%s %s %s",
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
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	imap_parser_echo_modify(pcontext, NULL);
	return 1716;
}

int imap_cmd_parser_close(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	imap_cmd_parser_clsfld(pcontext);
	return 1717;
}

static bool zero_uid_bit(const MITEM &i)
{
	return i.uid == 0 || !(i.flag_bits & FLAG_DELETED);
}

int imap_cmd_parser_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int del_num;
	BOOL b_deleted;
	size_t string_length = 0;
	char buff[1024];
	SINGLE_LIST temp_list;
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (pcontext->b_readonly)
		return 1806;
	b_deleted = FALSE;
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_list_deleted(pcontext->maildir,
	         pcontext->selected_folder, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	auto num = xarray.get_capacity();
	single_list_init(&temp_list);
	for (size_t i = 0; i < num; ++i) {
		auto pitem = static_cast<MITEM *>(xarray.get_item(i));
		if (zero_uid_bit(*pitem))
			continue;
		pitem->node.pdata = pitem;
		single_list_append_as_tail(&temp_list, &pitem->node);
	}
	result = system_services_remove_mail(pcontext->maildir,
	         pcontext->selected_folder, &temp_list, &errnum);
	switch(result) {
	case MIDB_RESULT_OK: {
		pcontext->stream.clear();
		del_num = 0;
		for (size_t i = 0; i < xarray.get_capacity(); ++i) try {
			auto pitem = static_cast<MITEM *>(xarray.get_item(i));
			if (zero_uid_bit(*pitem))
				continue;
			auto eml_path = std::string(pcontext->maildir) + "/eml/" + pitem->mid;
			remove(eml_path.c_str());
			imap_parser_log_info(pcontext, LV_ERR, "message %s has been deleted", eml_path.c_str());
			string_length = gx_snprintf(buff, arsizeof(buff),
				"* %d EXPUNGE\r\n", pitem->id - del_num);
			pcontext->stream.write(buff, string_length);
			b_deleted = TRUE;
			del_num ++;
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1459: ENOMEM\n");
		}
		if (b_deleted)
			imap_parser_touch_modify(pcontext, pcontext->username,
										pcontext->selected_folder);
		imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170026: OK EXPUNGE completed */
		auto imap_reply_str = resource_get_imap_code(1726, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
			"%s %s", argv[0], imap_reply_str);
		pcontext->stream.write(buff, string_length);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	}
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
}

int imap_cmd_parser_unselect(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = PROTO_STAT_AUTH;
	pcontext->selected_folder[0] = '\0';
	return 1718;
}

int imap_cmd_parser_search(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int buff_len;
	size_t string_length = 0;
	char buff[256*1024];
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 3 || argc > 1024)
		return 1800;
	strcpy(buff, "* SEARCH ");
	buff_len = sizeof(buff) - 11;
	result = system_services_search(pcontext->maildir,
		pcontext->selected_folder, resource_get_default_charset(
		pcontext->lang), argc - 2, &argv[2], buff + 9, &buff_len,
		&errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	buff_len += 9;
	buff[buff_len] = '\r';
	buff_len ++;
	buff[buff_len] = '\n';
	buff_len ++;
	pcontext->stream.clear();
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170019: OK SEARCH completed */
	auto imap_reply_str = resource_get_imap_code(1719, 1, &string_length);
	buff_len += gx_snprintf(buff + buff_len, arsizeof(buff) - buff_len,
	            "%s %s", argv[0], imap_reply_str);
	pcontext->stream.write(buff, buff_len);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_fetch(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, num;
	int result;
	BOOL b_data;
	MITEM *pitem;
	BOOL b_detail;
	char buff[1024];
	size_t string_length = 0;
	char* tmp_argv[128];
	DOUBLE_LIST list_seq;
	DOUBLE_LIST list_data;
	DOUBLE_LIST_NODE nodes[1024];
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 4 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[2]))
		return 1800;
	if (!imap_cmd_parser_parse_fetch_args(&list_data, nodes, &b_detail,
	    &b_data, argv[3], tmp_argv, arsizeof(tmp_argv)))
		return 1800;
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	if (b_detail)
		result = system_services_fetch_detail(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	else
		result = system_services_fetch_simple(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	pcontext->stream.clear();
	num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray.get_item(i);
		imap_cmd_parser_process_fetch_item(pcontext,
			b_data, pitem, pitem->id, &list_data);
	}
	if (b_detail)
		system_services_free_result(&xarray);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170020: OK FETCH completed */
	{
	auto imap_reply_str = resource_get_imap_code(1720, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	}
	string_length = strlen(buff);
	pcontext->stream.write(buff, string_length);
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	if (b_data) {
		pcontext->write_buff = pcontext->command_buffer;
		pcontext->sched_stat = SCHED_STAT_WRDAT;
	} else {
		pcontext->sched_stat = SCHED_STAT_WRLST;
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
	int errnum, result, i;
	MITEM *pitem;
	int flag_bits;
	int temp_argc;
	char *temp_argv[8];
	DOUBLE_LIST list_seq;
	SEQUENCE_NODE sequence_nodes[1024];

	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 5 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[2]) || !store_flagkeyword(argv[3]))
		return 1800;
	if ('(' == argv[4][0] && ')' == argv[4][strlen(argv[4]) - 1]) {
		temp_argc = parse_imap_args(argv[4] + 1, strlen(argv[4]) - 2,
		            temp_argv, arsizeof(temp_argv));
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
		else
			return 1807;
	}
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray.get_item(i);
		imap_cmd_parser_store_flags(argv[3], pitem->mid,
			pitem->id, 0, flag_bits, pcontext);
		imap_parser_modify_flags(pcontext, pitem->mid);
	}
	imap_parser_echo_modify(pcontext, NULL);
	return 1721;
}

int imap_cmd_parser_copy(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum;
	int result;
	MITEM *pitem;
	BOOL b_first;
	BOOL b_copied;
	int i, j;
	unsigned long uidvalidity;
	size_t string_length = 0, string_length1 = 0;
	char buff[64*1024];
	char temp_name[1024];
	DOUBLE_LIST list_seq;
	SINGLE_LIST temp_list;
	char uid_string[64*1024];
	char uid_string1[64*1024];
	SEQUENCE_NODE sequence_nodes[1024];
    
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 4 || !imap_cmd_parser_parse_sequence(&list_seq, sequence_nodes, argv[2]) ||
	    strlen(argv[3]) == 0 || strlen(argv[3]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[3], temp_name))
		return 1800;
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	if (system_services_summary_folder(pcontext->maildir,
	    temp_name, nullptr, nullptr, nullptr, &uidvalidity, nullptr,
	    nullptr, &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	string_length = 0;
	string_length1 = 0;
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray.get_item(i);
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
				uid_string[string_length] = ',';
				string_length++;
				uid_string1[string_length1] = ',';
				string_length1++;
			} else {
				b_first =  TRUE;
			}
			string_length += gx_snprintf(uid_string + string_length,
					 arsizeof(uid_string) - string_length, "%d", pitem->uid);
			string_length1 += gx_snprintf(uid_string1 + string_length1,
					  arsizeof(uid_string1) - string_length1, "%d", uid);
			break;
		}
		if (j == 10)
			uidvalidity = 0;
	}
	if (!b_copied) {
		single_list_init(&temp_list);
		for (;i>0; i--) {
			pitem = (MITEM*)xarray.get_item(i - 1);
			if (pitem->uid == 0)
				continue;
			pitem->node.pdata = pitem;
			single_list_append_as_tail(&temp_list, &pitem->node);
		}
		system_services_remove_mail(pcontext->maildir,
			temp_name, &temp_list, &errnum);
	}
	pcontext->stream.clear();
	if (b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170022: OK <COPYUID> COPY completed */
		auto imap_reply_str = resource_get_imap_code(1722, 1, &string_length);
		auto imap_reply_str1 = resource_get_imap_code(1722, 2, &string_length1);
		if (uidvalidity != 0)
			string_length = gx_snprintf(buff, arsizeof(buff),
				"%s %s [COPYUID %u %s %s] %s", argv[0],
				imap_reply_str, (unsigned int)uidvalidity,
				uid_string, uid_string1, imap_reply_str1);
		else
			string_length = gx_snprintf(buff, arsizeof(buff),
				"%s %s %s", argv[0], imap_reply_str, imap_reply_str1);
	} else {
		/* IMAP_CODE_2190016: NO COPY failed */
		auto imap_reply_str = resource_get_imap_code(1916, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
			"%s %s", argv[0], imap_reply_str);
	}
	pcontext->stream.write(buff, string_length);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_search(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int buff_len;
	size_t string_length = 0;
	char buff[256*1024];
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 3 || argc > 1024)
		return 1800;
	strcpy(buff, "* SEARCH ");
	buff_len = sizeof(buff) - 11;
	result = system_services_search_uid(pcontext->maildir,
	         pcontext->selected_folder, resource_get_default_charset(pcontext->lang),
	         argc - 3, &argv[3], buff + 9, &buff_len, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	buff_len += 9;
	buff[buff_len] = '\r';
	buff_len ++;
	buff[buff_len] = '\n';
	buff_len ++;
	pcontext->stream.clear();
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170023: OK UID SEARCH completed */
	auto imap_reply_str = resource_get_imap_code(1723, 1, &string_length);
	buff_len += gx_snprintf(buff + buff_len, arsizeof(buff) - buff_len,
	            "%s %s", argv[0], imap_reply_str);
	pcontext->stream.write(buff, buff_len);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_fetch(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int num;
	int errnum;
	int i;
	int result;
	BOOL b_data;
	MITEM *pitem;
	BOOL b_detail;
	char buff[1024];
	size_t string_length = 0;
	char* tmp_argv[128];
	DOUBLE_LIST list_seq;
	DOUBLE_LIST list_data;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE nodes[1024];
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 5 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3]))
		return 1800;
	if (!imap_cmd_parser_parse_fetch_args(&list_data, nodes, &b_detail,
	    &b_data, argv[4], tmp_argv, arsizeof(tmp_argv)))
		return 1800;
	for (pnode=double_list_get_head(&list_data); NULL!=pnode;
	     pnode = double_list_get_after(&list_data, pnode))
		if (strcasecmp(static_cast<char *>(pnode->pdata), "UID") == 0)
			break;
	if (NULL == pnode) {
		nodes[1023].pdata = deconst("UID");
		double_list_insert_as_head(&list_data, &nodes[1023]);
	}
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	if (b_detail)
		result = system_services_fetch_detail_uid(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	else
		result = system_services_fetch_simple_uid(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	pcontext->stream.clear();
	num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray.get_item(i);
		imap_cmd_parser_process_fetch_item(pcontext,
			b_data, pitem, pitem->id, &list_data);
	}
	if (b_detail)
		system_services_free_result(&xarray);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170028: OK UID FETCH completed */
	{
	auto imap_reply_str = resource_get_imap_code(1728, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	}
	string_length = strlen(buff);
	pcontext->stream.write(buff, string_length);
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	if (b_data) {
		pcontext->write_buff = pcontext->command_buffer;
		pcontext->sched_stat = SCHED_STAT_WRDAT;
	} else {
		pcontext->sched_stat = SCHED_STAT_WRLST;
	}
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_store(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum, i, result;
	MITEM *pitem;
	int flag_bits;
	int temp_argc;
	char *temp_argv[8];
	DOUBLE_LIST list_seq;
	SEQUENCE_NODE sequence_nodes[1024];

	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 6 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3]) || !store_flagkeyword(argv[4]))
		return 1800;
	if ('(' == argv[5][0] && ')' == argv[5][strlen(argv[5]) - 1]) {
		temp_argc = parse_imap_args(argv[5] + 1, strlen(argv[5]) - 2,
		            temp_argv, arsizeof(temp_argv));
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
		else
			return 1807;
	}
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple_uid(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray.get_item(i);
		imap_cmd_parser_store_flags(argv[4], pitem->mid,
			pitem->id, pitem->uid, flag_bits, pcontext);
		imap_parser_modify_flags(pcontext, pitem->mid);
	}
	imap_parser_echo_modify(pcontext, NULL);
	return 1724;
}

int imap_cmd_parser_uid_copy(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum;
	int result;
	BOOL b_first;
	MITEM *pitem;
	BOOL b_copied;
	int i, j;
	unsigned long uidvalidity;
	size_t string_length = 0, string_length1 = 0;
	char buff[64*1024];
	char temp_name[1024];
	DOUBLE_LIST list_seq;
	SINGLE_LIST temp_list;
	char uid_string[64*1024];
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (argc < 5 || !imap_cmd_parser_parse_sequence(&list_seq, sequence_nodes, argv[3]) ||
	    strlen(argv[4]) == 0 || strlen(argv[4]) >= 1024 ||
	    !imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang, argv[4], temp_name))
		return 1800;
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple_uid(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	if (system_services_summary_folder(pcontext->maildir,
	    temp_name, nullptr, nullptr, nullptr, &uidvalidity,
	    nullptr, nullptr, &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	string_length = 0;
	int num = xarray.get_capacity();
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray.get_item(i);
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
				uid_string[string_length] = ',';
				string_length ++;
			} else {
				b_first =  TRUE;
			}
			string_length += gx_snprintf(uid_string + string_length,
			                 arsizeof(uid_string) - string_length, "%d", uid);
			break;
		}
		if (j == 10)
			uidvalidity = 0;
	}
	if (!b_copied) {
		single_list_init(&temp_list);
		for (;i>0; i--) {
			pitem = (MITEM*)xarray.get_item(i - 1);
			if (pitem->uid == 0)
				continue;
			pitem->node.pdata = pitem;
			single_list_append_as_tail(&temp_list, &pitem->node);
		}
		system_services_remove_mail(pcontext->maildir,
			temp_name, &temp_list, &errnum);
	}
	pcontext->stream.clear();
	if (b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170025: OK <COPYUID> UID COPY completed */
		auto imap_reply_str = resource_get_imap_code(1725, 1, &string_length);
		auto imap_reply_str1 = resource_get_imap_code(1725, 2, &string_length1);
		if (uidvalidity != 0)
			string_length = gx_snprintf(buff, arsizeof(buff),
				"%s %s [COPYUID %u %s %s] %s", argv[0],
				imap_reply_str, (unsigned int)uidvalidity, argv[3],
				uid_string, imap_reply_str1);
		else
			string_length = gx_snprintf(buff, arsizeof(buff), "%s %s %s",
					argv[0], imap_reply_str, imap_reply_str1);
	} else {
		/* IMAP_CODE_2190017: NO UID COPY failed */
		auto imap_reply_str = resource_get_imap_code(1917, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff), "%s %s", argv[0], imap_reply_str);
	}
	pcontext->stream.write(buff, string_length);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int del_num;
	int max_uid;
	BOOL b_deleted;
	char buff[1024];
	size_t string_length = 0;
    DOUBLE_LIST list_seq;
	SINGLE_LIST temp_list;
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (pcontext->proto_stat != PROTO_STAT_SELECT)
		return 1805;
	if (pcontext->b_readonly)
		return 1806;
	if (argc < 4 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3]))
		return 1800;
	b_deleted = FALSE;
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_list_deleted(pcontext->maildir,
	         pcontext->selected_folder, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
	auto num = xarray.get_capacity();
	if (0 == num) {
		imap_parser_echo_modify(pcontext, NULL);
		return 1730;
	}
	auto pitem = static_cast<MITEM *>(xarray.get_item(num - 1));
	max_uid = pitem->uid;
	single_list_init(&temp_list);
	for (size_t i = 0; i < num; ++i) {
		pitem = static_cast<MITEM *>(xarray.get_item(i));
		if (zero_uid_bit(*pitem) ||
		    !imap_cmd_parser_hint_sequence(&list_seq, pitem->uid,
		    max_uid))
			continue;
		pitem->node.pdata = pitem;
		single_list_append_as_tail(&temp_list, &pitem->node);
	}
	result = system_services_remove_mail(pcontext->maildir,
	         pcontext->selected_folder, &temp_list, &errnum);
	switch(result) {
	case MIDB_RESULT_OK: {
		pcontext->stream.clear();
		del_num = 0;
		for (size_t i = 0; i < xarray.get_capacity(); ++i) try {
			pitem = static_cast<MITEM *>(xarray.get_item(i));
			if (zero_uid_bit(*pitem) ||
			    !imap_cmd_parser_hint_sequence(&list_seq, pitem->uid,
			    max_uid))
				continue;
			auto eml_path = std::string(pcontext->maildir) + "/eml/" + pitem->mid;
			remove(eml_path.c_str());
			imap_parser_log_info(pcontext, LV_ERR, "message %s has been deleted", eml_path.c_str());
			string_length = gx_snprintf(buff, arsizeof(buff),
				"* %d EXPUNGE\r\n", pitem->id - del_num);
			pcontext->stream.write(buff, string_length);
			b_deleted = TRUE;
			del_num ++;
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1458: ENOMEM\n");
		}
		if (b_deleted)
			imap_parser_touch_modify(pcontext, pcontext->username,
										pcontext->selected_folder);
		imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170026: OK UID EXPUNGE completed */
		auto imap_reply_str = resource_get_imap_code(1726, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
			"%s %s", argv[0], imap_reply_str);
		pcontext->stream.write(buff, string_length);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	}
	case MIDB_NO_SERVER:
		return 1905;
	case MIDB_RDWR_ERROR:
		return 1906;
	default:
		return static_cast<uint16_t>(errnum) | DISPATCH_MIDB;
	}
}

void imap_cmd_parser_clsfld(IMAP_CONTEXT *pcontext)
{
	int errnum, result, i;
	BOOL b_deleted;
	char buff[1024];
	char prev_selected[128];
	size_t string_length = 0;
	SINGLE_LIST temp_list;
	const char *estring;
	
	if (*pcontext->selected_folder == '\0')
		return;
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = PROTO_STAT_AUTH;
	strcpy(prev_selected, pcontext->selected_folder);
	pcontext->selected_folder[0] = '\0';
	if (pcontext->b_readonly)
		return;
	XARRAY xarray(imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_list_deleted(pcontext->maildir,
	         prev_selected, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER: {
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		auto imap_reply_str = resource_get_imap_code(1905, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	case MIDB_RDWR_ERROR: {
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		auto imap_reply_str = resource_get_imap_code(1906, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	default: {
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		auto imap_reply_str = resource_get_imap_code(1907, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* %s%s", imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	}
	b_deleted = FALSE;
	int num = xarray.get_capacity();
	single_list_init(&temp_list);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray.get_item(i));
		if (zero_uid_bit(*pitem))
			continue;
		pitem->node.pdata = pitem;
		single_list_append_as_tail(&temp_list, &pitem->node);
	}
	result = system_services_remove_mail(pcontext->maildir,
	         prev_selected, &temp_list, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		for (i = 0; i < num; ++i) try {
			auto pitem = static_cast<MITEM *>(xarray.get_item(i));
			if (zero_uid_bit(*pitem))
				continue;
			auto eml_path = std::string(pcontext->maildir) + "/eml/" + pitem->mid;
			remove(eml_path.c_str());
			imap_parser_log_info(pcontext, LV_ERR, "message %s has been deleted", eml_path.c_str());
			b_deleted = TRUE;
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1457: ENOMEM\n");
		}
		break;
	case MIDB_NO_SERVER: {
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		auto imap_reply_str = resource_get_imap_code(1905, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	case MIDB_RDWR_ERROR: {
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		auto imap_reply_str = resource_get_imap_code(1906, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	default: {
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		auto imap_reply_str = resource_get_imap_code(1907, 1, &string_length);
		string_length = gx_snprintf(buff, arsizeof(buff),
			"* %s%s", imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	}
	if (b_deleted)
		imap_parser_touch_modify(pcontext,
			pcontext->username, prev_selected);
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
	size_t len = 0;
	auto estr = (ret & DISPATCH_MIDB) ? resource_get_error_string(code) : nullptr;
	if (ret & DISPATCH_MIDB)
		code = 1907;
	auto str = resource_get_imap_code(code, 1, &len);
	char buff[1024];
	const char *tag = nullptr;
	if (ret & DISPATCH_TAG)
		tag = *ctx->tag_string != '\0' ? ctx->tag_string : "BUG";
	else
		tag = argc > 0 ? argv[0] : "*";
	len = gx_snprintf(buff, arsizeof(buff), "%s %s%s", tag, str, znul(estr));
	imap_parser_safe_write(ctx, buff, len);
	return ret & DISPATCH_ACTMASK;
}
