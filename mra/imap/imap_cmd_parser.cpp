// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
/* 
 * collection of functions for handling the imap command
 */ 
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include "imap_cmd_parser.h"
#include "system_services.h"
#include <gromox/mail_func.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/dir_tree.hpp>
#include "resource.h"
#include <gromox/mjson.hpp>
#include <gromox/util.hpp>
#include <gromox/mail.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>


#define MAX_DIGLEN		256*1024

struct SEQUENCE_NODE {
	DOUBLE_LIST_NODE node;
	int min;
	int max;
};

enum {
	TYPE_WILDS = 1,
	TYPE_WILDP
};

static const char *g_folder_list[] = {"draft", "sent", "trash", "junk"};
static const char *g_xproperty_list[] = {"Drafts", "Sent", "Trash", "Spam"};

static BOOL imap_cmd_parser_hint_sequence(DOUBLE_LIST *plist,
	unsigned int num, unsigned int max_uid)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		auto pseq = static_cast<SEQUENCE_NODE *>(pnode->pdata);
		if (-1 == pseq->max) {
			if (-1 == pseq->min) {
				if (num == max_uid) {
					return TRUE;
				}
			} else {
				if (num >= pseq->min) {
					return TRUE;
				}
			}
		} else {
			if (pseq->max >= num && pseq->min <= num) {
				return TRUE;
			}
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
	if (',' == string[len - 1]) {
		len --;
	} else {
		string[len] = ',';
	}
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
						nodes[j].min = atoi(last_colon + 1);
						if (nodes[j].min <= 0) {
							double_list_free(plist);
							return FALSE;
						}
					}
				} else {
					nodes[j].min = atoi(last_break);
					if (nodes[j].min <= 0) {
						double_list_free(plist);
						return FALSE;
					}
					if (0 == strcmp(last_colon + 1, "*")) {
						nodes[j].max = -1;
					} else {
						nodes[j].max = atoi(last_colon + 1);
						if (nodes[j].max <= 0) {
							double_list_free(plist);
							return FALSE;
						}
					}
				}
				last_colon = NULL;
			} else {
				if ('*' == *last_break ||
					(nodes[j].min = atoi(last_break)) <= 0) {
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
	} else {
		return TRUE;
	}
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
	if (tmp_argc < 1) {
		return FALSE;
	}
	b_macro = FALSE;
	double_list_init(plist);
	for (i=0; i<tmp_argc; i++) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			if (0 == strcasecmp((char*)pnode->pdata, argv[i])) {
				break;
			}
		}
		if (NULL != pnode) {
			continue;
		}
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
			if (NULL == pend) {
				return FALSE;
			}
			ptr = strchr(argv[i], '[') + 1;
			last_ptr = ptr;
			if (0 == strncasecmp(ptr, "MIME", 4)) {
				return FALSE;
			}
			while (']' != *ptr) {
				if ('.' == *ptr) {
					len = ptr - last_ptr;
					if (0 == len) {
						return FALSE;
					}
					for (j=0; j<len; j++) {
						if (!HX_isdigit(last_ptr[j]))
							break;
					}
					if (j < len) {
						break;
					}
					last_ptr = ptr + 1;
				}
				ptr ++;
			}
			
			len = pend - last_ptr;
			if ((0 == len && '.' == *last_ptr) || len >= 1024) {
				return FALSE;
			}
			memcpy(buff, last_ptr, len);
			buff[len] = '\0';
			if (0 != len &&
				0 != strcasecmp(buff, "HEADER") &&
				0 != strcasecmp(buff, "TEXT") &&
				0 != strcasecmp(buff, "MIME") &&
				0 != strncasecmp(buff, "HEADER.FIELDS ", 14) &&
				0 != strncasecmp(buff, "HEADER.FIELDS.NOT ", 18)) {
				for (j=0; j<len; j++) {
					if (!HX_isdigit(buff[j]))
						return FALSE;
				}
			} else if (0 == strncasecmp(buff, "HEADER.FIELDS ", 14)) {
				memcpy(temp_buff, buff + 14, strlen(buff) - 14);
				if ('(' == buff[14]) {
					if (')' != buff[strlen(buff) - 1]) {
						return FALSE;
					}
					result = parse_imap_args(temp_buff + 1, strlen(buff) - 16,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				} else {
					result = parse_imap_args(temp_buff, strlen(buff) - 14,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				}
				if (result < 1) {
					return FALSE;
				}
			} else if (0 == strncasecmp(buff, "HEADER.FIELDS.NOT ", 18)) {
				memcpy(temp_buff, buff + 18, strlen(buff) - 18);
				if ('(' == buff[18]) {
					if (')' != buff[strlen(buff) - 1]) {
						return FALSE;
					}
					result = parse_imap_args(temp_buff + 1, strlen(buff) - 20,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				} else {
					result = parse_imap_args(temp_buff, strlen(buff) - 18,
								tmp_argv1, sizeof(tmp_argv1)/sizeof(char*));
				}
				if (result < 1) {
					return FALSE;
				}
			}
			ptr = pend + 1;
			ptr1 = NULL;
			if ('\0' != *ptr) {
				pend = strchr(ptr + 1, '>');
				if ('<' != *ptr || NULL == pend || '\0' != *(pend + 1)) {
					return FALSE;
				}
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
				if (count > 1) {
					return FALSE;
				}
				if ((count == 1 && ptr1 == last_ptr) || ptr1 == pend - 1)
					return FALSE;
			}
			nodes[i].pdata = argv[i];
			double_list_append_as_tail(plist, &nodes[i]);
		} else {
			return FALSE;
		}
	}
	if (tmp_argc > 1 && TRUE == b_macro) {
		return FALSE;
	}
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
		if (TRUE == b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Answered");
	}
	if (flag_bits & FLAG_FLAGGED) {
		if (TRUE == b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Flagged");
	}
	if (flag_bits & FLAG_DELETED) {
		if (TRUE == b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Deleted");
	}
	if (flag_bits & FLAG_SEEN) {
		if (TRUE == b_first) {
			flags_string[len] = ' ';
			len ++;
		} else {
			b_first = TRUE;
		}
		len += sprintf(flags_string + len, "\\Seen");
	}
	if (flag_bits & FLAG_DRAFT) {
		if (TRUE == b_first) {
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
	char *tags, size_t offset1, size_t length1, char *value, int val_len)
{
	int i;
	BOOL b_hit;
	int tag_len;
	int tmp_argc;
	int len, len1;
	int buff_len, fd;
	char* tmp_argv[128];
	char buff[128*1024];
	char buff1[128*1024];
	char temp_buff[1024];
	MIME_FIELD mime_field;
	
	auto pbody = strchr(cmd_tag, '[');
	if (length > 128*1024) {
		return -1;
	}
	
	fd = open(file_path, O_RDONLY);
	if (-1 == fd) {
		return -1;
	}
	lseek(fd, offset, SEEK_SET);
	HX_strlcpy(temp_buff, tags, GX_ARRAY_SIZE(temp_buff));
	if ('(' == tags[0]) {
		tmp_argc = parse_imap_args(temp_buff + 1,
			strlen(tags) - 2, tmp_argv, sizeof(tmp_argv));
	} else {
		tmp_argc = parse_imap_args(temp_buff,
			strlen(tags), tmp_argv, sizeof(tmp_argv));
	}
	if (length != read(fd, buff, length)) {
		close(fd);
		return -1;
	}
	close(fd);
	len1 = 0;
	buff_len = 0;
	while ((len = parse_mime_field(buff + buff_len, length - buff_len,
	       &mime_field)) != 0) {
		b_hit = FALSE;
		for (i=0; i<tmp_argc; i++) {
			tag_len = strlen(tmp_argv[i]);
			if (tag_len == mime_field.field_name_len
				&& 0 == strncasecmp(tmp_argv[i],
				mime_field.field_name, tag_len)) {
				if (FALSE == b_not) {
					memcpy(buff1 + len1, buff + buff_len, len);
					len1 += len;
					break;
				}
				b_hit = TRUE;
			}
		}
		if (TRUE == b_not && FALSE == b_hit) {
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
	if (offset1 >= len1) {
		len = gx_snprintf(value, val_len, "BODY%s NIL", pbody);
	} else {
		if (offset1 + length1 > len1) {
			length1 = len1 - offset1;
		}
		len = gx_snprintf(value, val_len,
			"BODY%s {%ld}\r\n%s", pbody, length1, buff1 + offset1);
	}
	if (len >= val_len - 1) {
		return -1;
	} else {
		return len;
	}
}

static int imap_cmd_parser_print_structure(IMAP_CONTEXT *pcontext,
	MJSON *pjson, char *cmd_tag, char *buff, int max_len, const char *pbody,
	const char *temp_id, char *temp_tag, size_t offset, size_t length,
	const char *storage_path)
{
	int len;
	BOOL b_not;
	int buff_len;
	int part_type;
	size_t temp_len;
	MJSON_MIME *pmime;
	char temp_path[256];
	
	buff_len = 0;
	if (NULL == temp_tag) {
		pmime = mjson_get_mime(pjson, temp_id);
		/* Non-[MIME-IMB] messages, and non-multipart
		   [MIME-IMB] messages with no encapsulated
		   message, only have a part 1
		*/
		if (NULL == pmime && 0 == strcmp(temp_id, "1")) {
			pmime = mjson_get_mime(pjson, "");
		}
		if (NULL != pmime) {
			if (0 == strcmp(temp_id, "")) {
				part_type = MJSON_MIME_ENTIRE;
				temp_len = mjson_get_mime_offset(pmime, MJSON_MIME_HEAD);
			} else {
				part_type = MJSON_MIME_CONTENT;
				temp_len = mjson_get_mime_offset(pmime, MJSON_MIME_CONTENT);
			}
			if (-1 == length) {
				length = mjson_get_mime_length(pmime, part_type);
			}
			if (offset >= mjson_get_mime_length(pmime, part_type)) {
				buff_len += gx_snprintf(buff + buff_len,
					max_len - buff_len, "BODY%s NIL", pbody);
			} else {
				if (offset + length > mjson_get_mime_length(
					pmime, part_type)) {
					length = mjson_get_mime_length(
						pmime, part_type) - offset;
				}
				if (NULL == storage_path) {
					buff_len += gx_snprintf(buff + buff_len, max_len - buff_len,
							"BODY%s {%ld}\r\n<<{file}%s|%ld|%ld\r\n", pbody,
							length, mjson_get_mail_filename(pjson),
							temp_len + offset, length);
				} else {
					buff_len += gx_snprintf(buff + buff_len, max_len - buff_len,
								"BODY%s {%ld}\r\n<<{rfc822}%s/%s|%ld|%ld\r\n",
								pbody, length, storage_path,
								mjson_get_mail_filename(pjson),
								temp_len + offset, length);
				}
			}
		} else {
			buff_len += gx_snprintf(buff + buff_len,
				max_len - buff_len, "BODY%s NIL", pbody);
		}
	} else {
		if (0 == strcasecmp("MIME", temp_tag + 1) ||
			0 == strcasecmp("HEADER", temp_tag + 1)) {
			if ((0 == strcasecmp("MIME", temp_tag + 1)
				&& 0 == strcmp(temp_id, "")) ||
				(0 == strcasecmp("HEADER", temp_tag + 1)
				&& 0 != strcmp(temp_id, ""))) {
				buff_len += gx_snprintf(buff + buff_len,
					max_len - buff_len, "BODY%s NIL", pbody);
			} else {
				pmime = mjson_get_mime(pjson, temp_id);
				if (NULL != pmime) {
					if (-1 == length) {
						length = mjson_get_mime_length(
								pmime, MJSON_MIME_HEAD);
					}
					if (offset >= mjson_get_mime_length(
						pmime, MJSON_MIME_HEAD)) {
						buff_len += gx_snprintf(buff + buff_len,
							max_len - buff_len, "BODY%s NIL", pbody);
					} else {
						if (offset + length > mjson_get_mime_length(
							pmime, MJSON_MIME_HEAD)) {
							length = mjson_get_mime_length(pmime,
										MJSON_MIME_HEAD) - offset;
						}
						if (NULL == storage_path) {
							buff_len += gx_snprintf(
								buff + buff_len, max_len - buff_len,
								"BODY%s {%ld}\r\n<<{file}%s|%ld|%ld\r\n",
								pbody, length, mjson_get_mail_filename(pjson),
								mjson_get_mime_offset(pmime, MJSON_MIME_HEAD)
								+ offset, length);
						} else {
							buff_len += gx_snprintf(
								buff + buff_len, max_len - buff_len,
								"BODY%s {%ld}\r\n<<{rfc822}%s/%s|%ld|%ld\r\n",
								pbody, length, storage_path,
								mjson_get_mail_filename(pjson),
								mjson_get_mime_offset(pmime, MJSON_MIME_HEAD)
								+ offset, length);
						}
					}
				} else {
					buff_len += gx_snprintf(buff + buff_len,
						max_len - buff_len, "BODY%s NIL", pbody);
				}
			}
		} else if (0 == strcasecmp("TEXT", temp_tag + 1)) {
			if (0 != strcmp(temp_id, "")) {
				buff_len += gx_snprintf(buff + buff_len,
					max_len - buff_len, "BODY%s NIL", pbody);
			} else {
				pmime = mjson_get_mime(pjson, temp_id);
				if (NULL != pmime) {
					if (-1 == length) {
						length = mjson_get_mime_length(
							pmime, MJSON_MIME_CONTENT);
					}
					if (offset >= mjson_get_mime_length(
						pmime, MJSON_MIME_CONTENT)) {
						buff_len += gx_snprintf(buff + buff_len,
							max_len - buff_len, "BODY%s NIL", pbody);
					} else {
						if (offset + length > mjson_get_mime_length(
							pmime, MJSON_MIME_CONTENT)) {
							length = mjson_get_mime_length(pmime,
									MJSON_MIME_CONTENT) - offset;
						}
						if (NULL == storage_path) {
							buff_len += gx_snprintf(
								buff + buff_len, max_len - buff_len,
								"BODY%s {%ld}\r\n<<{file}%s|%ld|%ld\r\n",
								pbody, length, mjson_get_mail_filename(pjson),
								mjson_get_mime_offset(pmime, MJSON_MIME_CONTENT)
								+ offset, length);
						} else {
							buff_len += gx_snprintf(
								buff + buff_len, max_len - buff_len,
								"BODY%s {%ld}\r\n<<{rfc822}%s/%s|%ld|%ld\r\n",
								pbody, length, storage_path,
								mjson_get_mail_filename(pjson),
								mjson_get_mime_offset(pmime, MJSON_MIME_CONTENT)
								+ offset, length);
						}
					}
				} else {
					buff_len += gx_snprintf(buff + buff_len,
						max_len - buff_len, "BODY%s NIL", pbody);
				}
			}
		} else {
			if (0 != strcmp(temp_id, "")) {
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
				pmime = mjson_get_mime(pjson, temp_id);
				if (NULL != pmime) {
					if (NULL == storage_path) {
						snprintf(temp_path, 256, "%s/eml/%s",
							pcontext->maildir, mjson_get_mail_filename(pjson));
					} else {
						snprintf(temp_path,
							256, "%s/tmp/imap.rfc822/%s/%s",
							pcontext->maildir, storage_path, 
							mjson_get_mail_filename(pjson));
					}
					
					len = imap_cmd_parser_match_field(cmd_tag, temp_path,
							mjson_get_mime_offset(pmime, MJSON_MIME_HEAD),
							mjson_get_mime_length(pmime, MJSON_MIME_HEAD),
							b_not, temp_tag, offset, length, buff + buff_len,
							max_len - buff_len);
					if (-1 == len) {
						buff_len += gx_snprintf(buff + buff_len,
							max_len - buff_len, "BODY%s NIL", pbody);
					} else {
						buff_len += len;
					}
				} else {
					buff_len += gx_snprintf(buff + buff_len,
						max_len - buff_len, "BODY%s NIL", pbody);
				}
			}
		}
	}
	return buff_len;
}

static void imap_cmd_parser_process_fetch_item(IMAP_CONTEXT *pcontext,
	BOOL b_data, MITEM *pitem, int item_id, DOUBLE_LIST *pitem_list)
{
	char *ptr;
	int errnum;
	int i, len;
	char *pdot;
	char *pend;
	char *pbody;
	MJSON mjson;
	BOOL b_first;
	int buff_len;
	const char *temp_id;
	size_t offset;
	size_t length;
	time_t tmp_time;
	struct tm tmp_tm;
	MJSON temp_mjson;
	MJSON_MIME *pmime;
	char mjson_id[64];
	char final_id[64];
	char temp_path[256];
	char temp_buff[1024];
	char buff[MAX_DIGLEN];
	char flags_string[128];
	DOUBLE_LIST_NODE *pnode;
	
	if (pitem->flag_bits & FLAG_LOADED) {
		mem_file_seek(&pitem->f_digest,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		len = mem_file_read(&pitem->f_digest, buff, MAX_DIGLEN);
		if (MEM_END_OF_FILE == len) {
			return;
		}
		mjson_init(&mjson, imap_parser_get_jpool());
		snprintf(temp_path, 256, "%s/eml", pcontext->maildir);
		if (FALSE == mjson_retrieve(&mjson, buff, len, temp_path)) {
			mjson_free(&mjson);
			return;
		}
	}
	buff_len = 0;
	buff_len += gx_snprintf(buff + buff_len, GX_ARRAY_SIZE(buff) - buff_len,
	            "* %d FETCH (", item_id);
	b_first = FALSE;
	for (pnode=double_list_get_head(pitem_list); NULL!=pnode;
		pnode=double_list_get_after(pitem_list, pnode)) {
		if (FALSE == b_first) {
			b_first = TRUE;
		} else {
			buff[buff_len] = ' ';
			buff_len ++;
		}
		auto kw = static_cast<const char *>(pnode->pdata);
		if (strcasecmp(kw, "BODY") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            GX_ARRAY_SIZE(buff) - buff_len, "BODY ");
			if (TRUE == mjson_rfc822_check(&mjson)) {
				snprintf(temp_path, 256,
					"%s/tmp/imap.rfc822", pcontext->maildir);
				if (TRUE == mjson_rfc822_build(&mjson,
					imap_parser_get_mpool(), temp_path)) {
					len = mjson_rfc822_fetch(&mjson, temp_path,
						resource_get_default_charset(pcontext->lang),
						FALSE, buff + buff_len, MAX_DIGLEN - buff_len);
					if (-1 == len) {
						goto FETCH_BODY_SIMPLE;
					} else {
						buff_len += len;
					}
				} else {
					goto FETCH_BODY_SIMPLE;
				}
			} else {
 FETCH_BODY_SIMPLE:
				len = mjson_fetch_structure(&mjson,
					resource_get_default_charset(pcontext->lang),
					FALSE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (-1 == len) {
					buff_len += gx_snprintf(buff + buff_len,
					            GX_ARRAY_SIZE(buff) - buff_len, "NIL");
				} else {
					buff_len += len;
				}
			}
		} else if (strcasecmp(kw, "BODYSTRUCTURE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            GX_ARRAY_SIZE(buff) - buff_len, "BODYSTRUCTURE ");
			if (TRUE == mjson_rfc822_check(&mjson)) {
				snprintf(temp_path, 256,
					"%s/tmp/imap.rfc822", pcontext->maildir);
				if (TRUE == mjson_rfc822_build(&mjson,
					imap_parser_get_mpool(), temp_path)) {
					len = mjson_rfc822_fetch(&mjson, temp_path,
						resource_get_default_charset(pcontext->lang),
						TRUE, buff + buff_len, MAX_DIGLEN - buff_len);
					if (-1 == len) {
						goto FETCH_BODYSTRUCTURE_SIMPLE;
					} else {
						buff_len += len;
					}
				} else {
					goto FETCH_BODYSTRUCTURE_SIMPLE;
				}
			} else {
 FETCH_BODYSTRUCTURE_SIMPLE:
				len = mjson_fetch_structure(&mjson,
					resource_get_default_charset(pcontext->lang),
					TRUE, buff + buff_len, MAX_DIGLEN - buff_len);
				if (-1 == len) {
					buff_len += gx_snprintf(buff + buff_len,
					            GX_ARRAY_SIZE(buff) - buff_len, "NIL");
				} else {
					buff_len += len;
				}
			}
		} else if (strcasecmp(kw, "ENVELOPE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            GX_ARRAY_SIZE(buff) - buff_len, "ENVELOPE ");
			len = mjson_fetch_envelope(&mjson,
				resource_get_default_charset(pcontext->lang),
				buff + buff_len, MAX_DIGLEN - buff_len);
			if (-1 == len) {
				buff_len += gx_snprintf(buff + buff_len,
				            GX_ARRAY_SIZE(buff) - buff_len, "NIL");
			} else {
				buff_len += len;
			}
		} else if (strcasecmp(kw, "FLAGS") == 0) {
			imap_cmd_parser_convert_flags_string(
				pitem->flag_bits, flags_string);
			buff_len += gx_snprintf(buff + buff_len,
			            GX_ARRAY_SIZE(buff) - buff_len, "FLAGS %s", flags_string);
		} else if (strcasecmp(kw, "INTERNALDATE") == 0) {
			if (FALSE == parse_rfc822_timestamp(
				mjson_get_mail_received(&mjson), &tmp_time)) {
				tmp_time = atol(mjson_get_mail_filename(&mjson));
			}
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			localtime_r(&tmp_time, &tmp_tm);
			buff_len += strftime(buff + buff_len, MAX_DIGLEN - buff_len,
							"INTERNALDATE \"%d-%b-%Y %T %z\"", &tmp_tm);
		} else if (strcasecmp(kw, "RFC822") == 0) {
			buff_len += gx_snprintf(buff + buff_len, GX_ARRAY_SIZE(buff) - buff_len,
							"RFC822 ({%ld}\r\n<<{file}%s|0|%ld\r\n)",
							mjson_get_mail_length(&mjson),
							mjson_get_mail_filename(&mjson),
							mjson_get_mail_length(&mjson));
			if (FALSE == pcontext->b_readonly &&
				0 == (pitem->flag_bits & FLAG_SEEN)) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_modify_flags(pcontext, pitem->mid);
			}
		} else if (strcasecmp(kw, "RFC822.HEADER") == 0) {
			pmime = mjson_get_mime(&mjson, "");
			if (NULL != pmime) {
				buff_len += gx_snprintf(buff + buff_len, GX_ARRAY_SIZE(buff) - buff_len,
							"RFC822.HEADER ({%ld}\r\n<<{file}%s|0|%ld\r\n)",
							mjson_get_mime_length(pmime, MJSON_MIME_HEAD),
							mjson_get_mail_filename(&mjson),
							mjson_get_mime_length(pmime, MJSON_MIME_HEAD));
			} else {
				buff_len += gx_snprintf(buff + buff_len,
				            GX_ARRAY_SIZE(buff) - buff_len, "RFC822.HEADER NIL");
			}
		} else if (strcasecmp(kw, "RFC822.SIZE") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            GX_ARRAY_SIZE(buff) - buff_len,
							"RFC822.SIZE %ld", mjson_get_mail_length(&mjson));
		} else if (strcasecmp(kw, "RFC822.TEXT") == 0) {
			pmime = mjson_get_mime(&mjson, "");
			if (NULL != pmime) {
				buff_len += gx_snprintf(buff + buff_len,
				            GX_ARRAY_SIZE(buff) - buff_len,
							"RFC822.TEXT ({%ld}\r\n<<{file}%s|%ld|%ld\r\n)",
							mjson_get_mime_length(pmime, MJSON_MIME_CONTENT),
							mjson_get_mail_filename(&mjson),
							mjson_get_mime_offset(pmime, MJSON_MIME_CONTENT),
							mjson_get_mime_length(pmime, MJSON_MIME_CONTENT));
			} else {
				buff_len += gx_snprintf(buff + buff_len,
				            GX_ARRAY_SIZE(buff) - buff_len, "RFC822.TEXT NIL");
			}
			if (FALSE == pcontext->b_readonly &&
				0 == (pitem->flag_bits & FLAG_SEEN)) {
				system_services_set_flags(pcontext->maildir,
					pcontext->selected_folder, pitem->mid,
					FLAG_SEEN, &errnum);
				pitem->flag_bits |= FLAG_SEEN;
				imap_parser_modify_flags(pcontext, pitem->mid);
			}
		} else if (strcasecmp(kw, "UID") == 0) {
			buff_len += gx_snprintf(buff + buff_len,
			            GX_ARRAY_SIZE(buff) - buff_len, "UID %d", pitem->uid);
		} else if (strncasecmp(kw, "BODY[", 5) == 0 ||
		    strncasecmp(kw, "BODY.PEEK[", 10) == 0) {
			pbody = strchr(static_cast<char *>(pnode->pdata), '[');
			ptr = pbody + 1;
			pend = strchr(ptr, ']');
			offset = 0;
			length = -1;
			if ('<' == *(pend + 1)) {
				offset = atol(pend + 2);
				pdot = strchr(pend + 2, '.');
				if (NULL != pdot) {
					length = atol(pdot + 1);
					/* trim the length information for response tag */
					*pdot = '>';
					*(pdot + 1) = '\0';
				}
			}
			len = pend - ptr;
			memcpy(temp_buff, ptr, len);
			temp_buff[len] = '\0';
			ptr = NULL;
			for (i=0; i<len; i++) {
				if (temp_buff[i] == '.' || HX_isdigit(temp_buff[i]))
					continue;
				ptr = temp_buff + i - 1;
				*ptr = '\0';
				break;
			}
			if (NULL != ptr) {
				if (ptr < temp_buff) {
					temp_id = "";
				} else {
					temp_id = temp_buff;
				}
			} else {
				temp_id = temp_buff;
			}
			if (0 != strcmp(temp_id, "") &&
				TRUE == mjson_rfc822_check(&mjson)) {
				snprintf(temp_path, 256,
					"%s/tmp/imap.rfc822", pcontext->maildir);
				if (TRUE == mjson_rfc822_build(&mjson,
					imap_parser_get_mpool(), temp_path)) {
					mjson_init(&temp_mjson, imap_parser_get_jpool());
					if (TRUE == mjson_rfc822_get(&mjson, &temp_mjson,
						temp_path, temp_id, mjson_id, final_id)) {
						len = imap_cmd_parser_print_structure(
						      pcontext, &temp_mjson, static_cast<char *>(pnode->pdata),
							buff + buff_len, MAX_DIGLEN - buff_len,
							pbody, final_id, ptr, offset, length,
							mjson_get_mail_filename(&mjson));
					} else {
						len = imap_cmd_parser_print_structure(pcontext,
						      &mjson, static_cast<char *>(pnode->pdata),
						      buff + buff_len, MAX_DIGLEN - buff_len,
						      pbody, temp_id, ptr, offset, length, nullptr);
					}
					mjson_free(&temp_mjson);
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
			if (FALSE == pcontext->b_readonly &&
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
	buff_len += gx_snprintf(buff + buff_len, GX_ARRAY_SIZE(buff) - buff_len, ")\r\n");
	stream_write(&pcontext->stream, buff, buff_len);
	if (pitem->flag_bits & FLAG_LOADED) {
		mjson_free(&mjson);
	}
	if (FALSE == pcontext->b_readonly && pitem->flag_bits & FLAG_RECENT) {
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
			if (0 != uid) {
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			} else {
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"* %d FETCH (FLAGS %s)\r\n",
					id, flags_string);
			}
		}
	} else if (0 == strcasecmp(cmd, "+FLAGS") ||
		0 == strcasecmp(cmd, "+FLAGS.SILENT")) {
		system_services_set_flags(pcontext->maildir,
		pcontext->selected_folder, mid, flag_bits, &errnum);
		if (0 == strcasecmp(cmd, "+FLAGS") && 
			MIDB_RESULT_OK == system_services_get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid, &flag_bits, &errnum)) {
			imap_cmd_parser_convert_flags_string(flag_bits, flags_string);
			if (0 != uid) {
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			} else {
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"* %d FETCH (FLAGS %s)\r\n",
					id, flags_string);
			}
		}
	} else if (0 == strcasecmp(cmd, "-FLAGS") ||
		0 == strcasecmp(cmd, "-FLAGS.SILENT")) {
		system_services_unset_flags(pcontext->maildir,
			pcontext->selected_folder, mid, flag_bits, &errnum);
		if (0 == strcasecmp(cmd, "-FLAGS") &&
			MIDB_RESULT_OK == system_services_get_flags(pcontext->maildir,
		    pcontext->selected_folder, mid, &flag_bits, &errnum)) {
			imap_cmd_parser_convert_flags_string(flag_bits, flags_string);
			if (0 != uid) {
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"* %d FETCH (FLAGS %s UID %d)\r\n",
					id, flags_string, uid);
			} else {
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"* %d FETCH (FLAGS %s)\r\n",
					id, flags_string);
			}
		}
	}
	if (0 != string_length) {
		imap_parser_safe_write(pcontext, buff, string_length);
	}
}

static BOOL imap_cmd_parser_covert_imaptime(
	const char *str_time, time_t *ptime)
{
	int hour;
	int minute;
	int factor;
	time_t tmp_time;
	char tmp_buff[3];
	struct tm tmp_tm;
	const char *str_zone;
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	str_zone = strptime(str_time, "d-%b-%Y %T ", &tmp_tm);
	if (NULL == str_zone) {
		return FALSE;
	}
	if (strlen(str_zone) < 5) {
		return FALSE;
	}
	if ('-' == str_zone[0]) {
		factor = 1;
	} else if ('+' == str_zone[0]) {
		factor = -1;
	} else {
		return FALSE;
	}
	if (!HX_isdigit(str_zone[1]) || !HX_isdigit(str_zone[2]) ||
	    !HX_isdigit(str_zone[3]) || !HX_isdigit(str_zone[4]))
		return FALSE;
	tmp_buff[0] = str_zone[1];
	tmp_buff[1] = str_zone[2];
	tmp_buff[2] = '\0';
	hour = atoi(tmp_buff);
	if (hour < 0 || hour > 23) {
		return FALSE;
	}
	tmp_buff[0] = str_zone[3];
	tmp_buff[1] = str_zone[4];
	tmp_buff[2] = '\0';
	minute = atoi(tmp_buff);
	if (minute < 0 || minute > 59) {
		return FALSE;
	}
	tmp_time = make_gmtime(&tmp_tm);
	tmp_time += factor*(60*60*hour + 60*minute);
	*ptime = tmp_time;
	return TRUE;
}

static BOOL imap_cmd_parser_wildcard_match(const char *data, const char *mask)
{
	int type;
	BOOL icase;
	const char *ma = mask;
	const char *na = data;
	const char *lsm = nullptr, *lsn = nullptr;
	
	if (0 == strncasecmp(data, "inbox", 5)) {
		icase = TRUE;
	} else {
		icase = FALSE;
	}
	/* null strings should never match */
	if (ma == nullptr || na == nullptr || *ma == '\0' || *na == '\0')
		return FALSE;
	/* find the end of each string */
	while (*(++mask)) {
		/* do nothing */
	}
	mask--;
	while (*(++data)) {
		/* do nothing */
	}
	data--;
	while (data >= na) {
		/* If the mask runs out of chars before the string, fall back on
		* a wildcard or fail. */
		if (mask < ma) {
			if (lsm) {
				data = --lsn;
				mask = lsm;
				if ('/' == *data && TYPE_WILDP == type) {
					lsm = nullptr;
				}
				if (data < na) {
					lsm = nullptr;
				}
			} else {
				return FALSE;
			}
		}
		switch (*mask) {
		case '*':                /* Matches anything */
			do {
				mask--;                    /* Zap redundant wilds */
			} while ((mask >= ma) && ((*mask == '*') || (*mask == '%')));
			type = TYPE_WILDS;
			lsm = mask;
			lsn = data;
			if (mask < ma) {
				return TRUE;
			}
			continue;                 /* Next char, please */
		case '%':
			do {
				mask--;                    /* Zap redundant wilds */
			} while ((mask >= ma) && (*mask == '%'));
			type = TYPE_WILDP;
			lsm = mask;
			lsn = data;
			continue;                 /* Next char, please */
		}
		if ((icase && data - na < 5) ? HX_toupper(*mask) == HX_toupper(*data) :
			(*mask == *data)) {     /* If matching char */
			mask--;
			data--;
			continue;                 /* Next char, please */
		}
		if (lsm) {                  /* To to fallback on '*' */
			data = --lsn;
			mask = lsm;
			if ('/' == *data && TYPE_WILDP == type) {
				lsm = nullptr;
			}
			if (data < na) {
				lsm = nullptr; /* Rewind to saved pos */
			}
			continue;                 /* Next char, please */
		}
		return FALSE;             /* No fallback=No match */
	}
	while ((mask >= ma) && ((*mask == '*') || (*mask == '%'))) {
		mask--;                        /* Zap leftover %s & *s */
	}
	return (mask >= ma) ? FALSE : TRUE;   /* Start of both = match */
}

static BOOL imap_cmd_parser_imapfolder_to_sysfolder(
	const char *lang, const char *imap_folder, char *sys_folder)
{
	int i,len;
	char *ptoken;
	char **f_strings;
	char temp_name[512];
	char temp_folder[512];
	char converted_name[512];
	
	if (utf7_to_utf8(imap_folder, strlen(imap_folder), temp_name, 512) < 0) {
		return FALSE;
	}
	len = strlen(temp_name);
	if ('/' == temp_name[len - 1]) {
		len --;
		temp_name[len] = '\0';
	}
	
	ptoken = strchr(temp_name, '/');
	if (NULL == ptoken) {
		HX_strlcpy(temp_folder, temp_name, GX_ARRAY_SIZE(temp_folder));
	} else {
		memcpy(temp_folder, temp_name, ptoken - temp_name);
		temp_folder[ptoken - temp_name] = '\0';
	}
	if (0 == strcasecmp(temp_folder, "INBOX")) {
		strcpy(temp_folder, "inbox");
	} else {
		f_strings = resource_get_folder_strings(lang);
		for (i=0; i<4; i++) {
			if (0 == strcmp(f_strings[i], temp_folder)) {
				HX_strlcpy(temp_folder, g_folder_list[i], GX_ARRAY_SIZE(temp_folder));
				break;
			}
		}
	}
	if (NULL != ptoken) {
		len = gx_snprintf(converted_name, GX_ARRAY_SIZE(converted_name), "%s%s", temp_folder, ptoken);
		encode_hex_binary(converted_name,
			strlen(converted_name), sys_folder, 1024);
	} else {
		if (0 == strcmp("inbox", temp_folder) ||
			0 == strcmp("sent", temp_folder) ||
			0 == strcmp("draft", temp_folder) ||
			0 == strcmp("junk", temp_folder) ||
			0 == strcmp("trash", temp_folder)) {
			strcpy(sys_folder, temp_folder);	
		} else {
			encode_hex_binary(temp_folder,
				strlen(temp_folder), sys_folder, 1024);
		}
	}
	return TRUE;
}

static BOOL imap_cmd_parser_sysfolder_to_imapfolder(
	const char *lang, const char *sys_folder, char *imap_folder)
{
	int i;
	char *ptoken;
	char **f_strings;
	char temp_name[512];
	char temp_folder[512];
	char converted_name[512];
	
	if (0 == strcmp("inbox", sys_folder)) {
		strcpy(imap_folder, "INBOX");
		return TRUE;
	} else if (0 == strcmp("draft", sys_folder)) {
		f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[0], strlen(f_strings[0]), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("sent", sys_folder)) {
		f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[1], strlen(f_strings[1]), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("trash", sys_folder)) {
		f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[2], strlen(f_strings[2]), imap_folder, 1024);
		return TRUE;
	} else if (0 == strcmp("junk", sys_folder)) {
		f_strings = resource_get_folder_strings(lang);
		utf8_to_utf7(f_strings[3], strlen(f_strings[3]), imap_folder, 1024);
		return TRUE;
	}
	if (FALSE == decode_hex_binary(sys_folder, temp_name, 512)) {
		return FALSE;
	}
	ptoken = strchr(temp_name, '/');
	if (NULL == ptoken) {
		HX_strlcpy(temp_folder, temp_name, GX_ARRAY_SIZE(temp_folder));
	} else {
		memcpy(temp_folder, temp_name, ptoken - temp_name);
		temp_folder[ptoken - temp_name] = '\0';
	}
	if (0 == strcmp(temp_folder, "inbox")) {
		strcpy(temp_folder, "INBOX");
	} else {
		f_strings = resource_get_folder_strings(lang);
		for (i=0; i<4; i++) {
			if (0 == strcmp(g_folder_list[i], temp_folder)) {
				HX_strlcpy(temp_folder, f_strings[i], GX_ARRAY_SIZE(temp_folder));
				break;
			}
		}
	}
	if (NULL != ptoken) {
		snprintf(converted_name, 512, "%s%s", temp_folder, ptoken);
	} else {
		strcpy(converted_name, temp_folder);
	}
	if (utf8_to_utf7(converted_name, strlen(converted_name),
		imap_folder, 1024) <= 0) {
		return FALSE;
	}
	return TRUE;
}

static void imap_cmd_parser_convert_folderlist(
	const char *lang, MEM_FILE *pfile)
{
	MEM_FILE temp_file;
	char temp_name[512];
	char converted_name[1024];
	
	mem_file_init(&temp_file, imap_parser_get_allocator());
	while (MEM_END_OF_FILE != mem_file_readline(pfile, temp_name, 512)) {
		if (TRUE == imap_cmd_parser_sysfolder_to_imapfolder(
			lang, temp_name, converted_name)) {
			mem_file_writeline(&temp_file, converted_name);
		}
	}
	mem_file_clear(pfile);
	mem_file_copy(&temp_file, pfile);
	mem_file_free(&temp_file);
}

int imap_cmd_parser_capability(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
	const char* imap_reply_str;
	
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170001: OK CAPABILITY completed */
	imap_reply_str = resource_get_imap_code(IMAP_CODE_2170001, 1, &string_length);
	char starttls_str[16]{};
	if (pcontext->connection.ssl != nullptr)
		HX_strlcpy(starttls_str, " STARTTLS", GX_ARRAY_SIZE(starttls_str));
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
	                "* CAPABILITY IMAP4rev1 XLIST SPECIAL-USE "
	                "ID UNSELECT UIDPLUS IDLE AUTH=LOGIN%s\r\n%s %s",
	                starttls_str, argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_id(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
	const char* imap_reply_str;
	
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	if (parse_bool(resource_get_string("enable_rfc2971_commands"))) {
		/* IMAP_CODE_2170029: OK ID completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170029, 1, &string_length);
		snprintf(buff, sizeof(buff), "* ID (\"name\" \"gromox-imap\" "
		         "version \"%s\")\r\n%s %s", PACKAGE_VERSION,
		         argv[0], imap_reply_str);
	} else {
		snprintf(buff, sizeof(buff), "%s %s", argv[0],
		         resource_get_imap_code(IMAP_CODE_2180000, 1, &string_length));
	}
	imap_parser_safe_write(pcontext, buff, strlen(buff));
	return DISPATCH_CONTINUE;

}

int imap_cmd_parser_noop(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
    const char* imap_reply_str;
    
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170002: OK NOOP completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170002, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_logout(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
    int string_length;
	const char *imap_reply_str, *imap_reply_str2;
	
	/* IMAP_CODE_2160001: BYE logging out */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2160001, 1, &string_length);
	/* IMAP_CODE_2170003: OK LOGOUT completed */
	imap_reply_str2 = resource_get_imap_code(
		IMAP_CODE_2170003, 1, &string_length);
	
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "* %s%s %s",
			imap_reply_str, argv[0], imap_reply_str2);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_SHOULD_CLOSE;
}

int imap_cmd_parser_starttls(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
	const char *imap_reply_str;
	
	if (NULL != pcontext->connection.ssl) {
		/* IMAP_CODE_2180000: BAD command not supported or parameter error */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		SSL_write(pcontext->connection.ssl, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (FALSE == imap_parser_get_param(IMAP_SUPPORT_STARTTLS)) {
		/* IMAP_CODE_2180000 */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		write(pcontext->connection.sockd, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (pcontext->proto_stat > PROTO_STAT_NOAUTH) {
		/*IMAP_CODE_2180001: BAD TLS negotiation
		only begin in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180001, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		write(pcontext->connection.sockd, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	/* IMAP_CODE_2170004: OK begin TLS negotiation now */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170004, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	write(pcontext->connection.sockd, buff, string_length);
	pcontext->sched_stat = SCHED_STAT_STLS;	
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_authenticate(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
	const char *imap_reply_str;
	
	if (TRUE == imap_parser_get_param(IMAP_SUPPORT_STARTTLS) &&
		TRUE == imap_parser_get_param(IMAP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		/* IMAP_CODE_2180002: BAD must issue a STARTTLS command first */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180002, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		write(pcontext->connection.sockd, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (3 != argc || 0 != strcasecmp(argv[2], "LOGIN")) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (pcontext->proto_stat >= PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180003: BAD cannot relogin in authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180003, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	HX_strlcpy(pcontext->tag_string, argv[0], GX_ARRAY_SIZE(pcontext->tag_string));
	pcontext->proto_stat = PROTO_STAT_USERNAME;
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "+ VXNlciBOYW1lAA==\r\n");
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_username(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	size_t temp_len;
	int string_length;
	const char *imap_reply_str;
	
	if (0 == strlen(argv[0]) || 0 != decode64_ex(argv[0],
		strlen(argv[0]), pcontext->username, 256, &temp_len)) {
		pcontext->proto_stat = PROTO_STAT_NOAUTH;
		/* IMAP_CODE_2180019: BAD decode username error */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180019, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	pcontext->proto_stat = PROTO_STAT_PASSWORD;
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "+ UGFzc3dvcmQA\r\n");
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_password(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	size_t temp_len;
	char reason[256];
	int string_length;
	int string_length1;
	char buff[64*1024];
	char temp_password[256];
	const char *imap_reply_str;
	const char* imap_reply_str1;
	
	pcontext->proto_stat = PROTO_STAT_NOAUTH;
	if (0 == strlen(argv[0]) || 0 != decode64_ex(argv[0],
		strlen(argv[0]), temp_password, 256, &temp_len)) {
		/* IMAP_CODE_2180020: BAD decode password error */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180020, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	HX_strltrim(pcontext->username);
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		/* IMAP_CODE_2190001: NO access denied by user filter */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190001, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		imap_parser_log_info(pcontext, 8, "user %s is "
			"denied by user filter", pcontext->username);
		return DISPATCH_SHOULD_CLOSE;
    }
	if (TRUE == system_services_auth_login(pcontext->username,
		temp_password, pcontext->maildir, pcontext->lang, reason, 256)) {
		if ('\0' == pcontext->maildir[0]) {
			/* IMAP_CODE_2190002: NO cannot get
				mailbox location from database */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190002, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
					pcontext->tag_string, imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		if ('\0' == pcontext->lang[0]) {
			HX_strlcpy(pcontext->lang, resource_get_string("DEFAULT_LANG"), GX_ARRAY_SIZE(pcontext->lang));
		}
		pcontext->proto_stat = PROTO_STAT_AUTH;
		imap_parser_log_info(pcontext, 8, "login success");
		/* IMAP_CODE_2170005: OK logged in */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	} else {		
		imap_parser_log_info(pcontext, 8, "login fail");
		pcontext->auth_times ++;
		if (pcontext->auth_times >= imap_parser_get_param(MAX_AUTH_TIMES)) {
			if (system_services_add_user_into_temp_list != nullptr)
				system_services_add_user_into_temp_list(pcontext->username,
					imap_parser_get_param(BLOCK_AUTH_FAIL));
			/* IMAP_CODE_2190003: NO too many failures,
				user will be blocked for a while */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190003, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_SHOULD_CLOSE;
		}
		/* IMAP_CODE_2190004: NO login auth fail, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190004, 1, &string_length);
		imap_reply_str1 = resource_get_imap_code(
			IMAP_CODE_2190004, 2, &string_length1);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s%s",
			pcontext->tag_string, imap_reply_str, reason, imap_reply_str1);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
}

int imap_cmd_parser_login(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char reason[256];
	int string_length;
	int string_length1;
	char buff[64*1024];
	char temp_password[256];
    const char* imap_reply_str;
	const char* imap_reply_str1;
    
	if (TRUE == imap_parser_get_param(IMAP_SUPPORT_STARTTLS) &&
		TRUE == imap_parser_get_param(IMAP_FORCE_STARTTLS) &&
		NULL == pcontext->connection.ssl) {
		/* IMAP_CODE_2180002: BAD must issue a STARTTLS command first */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180002, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		write(pcontext->connection.sockd, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (4 != argc || strlen(argv[2]) > 255 || strlen(argv[3]) > 255) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (pcontext->proto_stat >= PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180003: BAD cannot relogin in authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180003, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	strcpy(pcontext->username, argv[2]);
	HX_strltrim(pcontext->username);
	if (system_services_judge_user != nullptr &&
	    !system_services_judge_user(pcontext->username)) {
		/* IMAP_CODE_2190001: NO access denied by user filter */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190001, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		imap_parser_log_info(pcontext, 8, "user %s is "
			"denied by user filter", pcontext->username);
		return DISPATCH_SHOULD_CLOSE;
    }
	strcpy(temp_password, argv[3]);
	HX_strltrim(temp_password);
	if (TRUE == system_services_auth_login(pcontext->username,
		temp_password, pcontext->maildir, pcontext->lang, reason, 256)) {
		if ('\0' == pcontext->maildir[0]) {
			/* IMAP_CODE_2190002: NO cannot get
			mailbox location from database */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190002, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		if ('\0' == pcontext->lang[0]) {
			HX_strlcpy(pcontext->lang, resource_get_string("DEFAULT_LANG"), GX_ARRAY_SIZE(pcontext->lang));
		}
		pcontext->proto_stat = PROTO_STAT_AUTH;
		imap_parser_log_info(pcontext, 8, "login success");
		/* IMAP_CODE_2170005: OK logged in */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	} else {		
		imap_parser_log_info(pcontext, 8, "login fail");
		pcontext->auth_times ++;
		if (pcontext->auth_times >= imap_parser_get_param(MAX_AUTH_TIMES)) {
			if (system_services_add_user_into_temp_list != nullptr)
				system_services_add_user_into_temp_list(pcontext->username,
					imap_parser_get_param(BLOCK_AUTH_FAIL));
			/* IMAP_CODE_2190003: NO too many failures, user will be blocked for a while */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190003, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_SHOULD_CLOSE;
		}
		
		/* IMAP_CODE_2190004: NO login auth fail, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190004, 1, &string_length);
		imap_reply_str1 = resource_get_imap_code(
			IMAP_CODE_2190004, 2, &string_length1);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s%s", argv[0],
							imap_reply_str, reason, imap_reply_str1);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
}

int imap_cmd_parser_idle(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
    const char* imap_reply_str;
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (2 != argc) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	HX_strlcpy(pcontext->tag_string, argv[0], GX_ARRAY_SIZE(pcontext->tag_string));
	pcontext->sched_stat = SCHED_STAT_IDLING;
	/* IMAP_CODE_2160002: + Idling */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2160002, 1, &string_length);
	imap_parser_safe_write(pcontext, imap_reply_str, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_select(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int exists;
	int recent;
	unsigned int uidnext;
	unsigned long uidvalid;
	int firstunseen;
	int string_length;
	char temp_name[1024];
	char buff[1024];
	const char *estring, *imap_reply_str;
    
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024 ||
		FALSE == imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang,
		argv[2], temp_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
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
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	strcpy(pcontext->selected_folder, temp_name);
	pcontext->proto_stat = PROTO_STAT_SELECT;
	pcontext->b_readonly = FALSE;
	imap_parser_add_select(pcontext);
	if (-1 != firstunseen) {
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
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
	} else {
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
			"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] limited\r\n"
			"* %d EXISTS\r\n"
			"* %d RECENT\r\n"
			"* OK [UIDVALIDITY %u] UIDs valid\r\n"
			"* OK [UIDNEXT %d] predicted next UID\r\n"
			"%s OK [READ-WRITE] SELECT completed\r\n", 
			exists, recent, (unsigned int)uidvalid, uidnext, argv[0]);
	}
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
	int string_length;
	char temp_name[1024];
	char buff[1024];
	const char *estring, *imap_reply_str;
    
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot
		process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024 ||
		FALSE == imap_cmd_parser_imapfolder_to_sysfolder(pcontext->lang,
		argv[2], temp_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
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
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	strcpy(pcontext->selected_folder, temp_name);
	pcontext->proto_stat = PROTO_STAT_SELECT;
	pcontext->b_readonly = TRUE;
	imap_parser_add_select(pcontext);
	if (-1 != firstunseen) {
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
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
	} else {
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
			"* OK [PERMANENTFLAGS ()] no permanenet flag permited\r\n"
			"* %d EXISTS\r\n"
			"* %d RECENT\r\n"
			"* OK [UIDVALIDITY %u] UIDs valid\r\n"
			"* OK [UIDNEXT %d] predicted next UID\r\n"
			"%s OK [READ-ONLY] EXAMINE completed\r\n",
			exists, recent, (unsigned int)uidvalid, uidnext, argv[0]);
	}
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_create(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, len;
	BOOL b_found;
	char buff[1024];
	int string_length;
	MEM_FILE temp_file;
	char temp_name[1024];
	char temp_name1[1024];
	char temp_folder[1024];
	char converted_name[1024];
	const char *estring, *imap_reply_str;

	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], temp_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (NULL != strchr(argv[2], '*') || NULL != strchr(argv[2], '%')
		|| NULL != strchr(argv[2], '?')) {
		/* IMAP_CODE_2190010: NO folder name format error */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190010, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (0 == strcasecmp(temp_name, "inbox") ||
		0 == strcmp(temp_name, "draft") ||
		0 == strcmp(temp_name, "sent") ||
		0 == strcmp(temp_name, "trash") ||
		0 == strcmp(temp_name, "junk")) {
		/* IMAP_CODE_2190011: NO CREATE can not create reserved folder name */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190011, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	mem_file_init(&temp_file, imap_parser_get_allocator());
	switch (system_services_enum_folders(
	        pcontext->maildir, &temp_file, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		mem_file_free(&temp_file);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		mem_file_free(&temp_file);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		mem_file_free(&temp_file);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	mem_file_writeline(&temp_file, "inbox");
	mem_file_writeline(&temp_file, "draft");
	mem_file_writeline(&temp_file, "sent");
	mem_file_writeline(&temp_file, "trash");
	mem_file_writeline(&temp_file, "junk");
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	strcpy(temp_name, argv[2]);
	len = strlen(temp_name);
	if ('/' == temp_name[len - 1]) {
		len --;
		temp_name[len] = '\0';
	}
	for (i=0; i<=len; i++) {
		if ('/' == temp_name[i] || '\0' == temp_name[i]) {
			temp_name1[i] = '\0';
			b_found = FALSE;
			mem_file_seek(&temp_file, MEM_FILE_READ_PTR,
								0, MEM_FILE_SEEK_BEGIN);
			while (MEM_END_OF_FILE != mem_file_readline(
				&temp_file, temp_folder, 1024)) {
				if (0 == strcmp(temp_folder, temp_name1)) {
					b_found = TRUE;
					break;
				}
			}
			if (FALSE == b_found) {		
				imap_cmd_parser_imapfolder_to_sysfolder(
					pcontext->lang, temp_name1, converted_name);
				switch (system_services_make_folder(
				        pcontext->maildir, converted_name, &errnum)) {
				case MIDB_RESULT_OK:
					break;
				case MIDB_NO_SERVER:
					mem_file_free(&temp_file);
					/* IMAP_CODE_2190005: NO server internal
						error, missing MIDB connection */
					imap_reply_str = resource_get_imap_code(
						IMAP_CODE_2190005, 1, &string_length);
					string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
						"%s %s", argv[0], imap_reply_str);
					imap_parser_safe_write(pcontext, buff, string_length);
					return DISPATCH_CONTINUE;
				case MIDB_RDWR_ERROR:
					mem_file_free(&temp_file);
					/* IMAP_CODE_2190006: NO server internal
						error, fail to communicate with MIDB */
					imap_reply_str = resource_get_imap_code(
						IMAP_CODE_2190006, 1, &string_length);
					string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
						"%s %s", argv[0], imap_reply_str);
					imap_parser_safe_write(pcontext, buff, string_length);
					return DISPATCH_CONTINUE;
				default:
					mem_file_free(&temp_file);
					estring = resource_get_error_string(errnum);
					/* IMAP_CODE_2190007: NO server internal error, */
					imap_reply_str = resource_get_imap_code(
						IMAP_CODE_2190007, 1, &string_length);
					string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
								argv[0], imap_reply_str, estring);
					imap_parser_safe_write(pcontext, buff, string_length);
					return DISPATCH_CONTINUE;
				}
			}
		}
		temp_name1[i] = temp_name[i];
	}
	mem_file_free(&temp_file);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170006: OK CREATED completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170006, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
		"%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_delete(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char buff[1024];
	int string_length;
	char encoded_name[1024];
	const char *estring, *imap_reply_str;

	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], encoded_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (0 == strcmp(encoded_name, "inbox") ||
		0 == strcmp(encoded_name, "draft") ||
		0 == strcmp(encoded_name, "sent") ||
		0 == strcmp(encoded_name, "trash") ||
		0 == strcmp(encoded_name, "junk")) {
		/* IMAP_CODE_2190013: NO DELETE can not delete reserved folder name */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190013, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	switch (system_services_remove_folder(
	        pcontext->maildir, encoded_name, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170007: OK DELETE completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170007, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_rename(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char buff[1024];
	int string_length;
	char encoded_name[1024];
	char encoded_name1[1024];
	const char *estring, *imap_reply_str;

	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| 0 == strlen(argv[3]) || strlen(argv[3]) >= 1024 ||
		FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], encoded_name) ||
		FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[3], encoded_name1)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (NULL != strchr(argv[3], '?') || NULL != strchr(argv[3], '*') ||
		NULL != strchr(argv[3], '%')) {
		/* IMAP_CODE_2190010: NO folder name format error */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190010, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (0 == strcmp(encoded_name, "inbox") ||
		0 == strcmp(encoded_name1, "inbox") ||
		0 == strcmp(encoded_name, "draft") ||
		0 == strcmp(encoded_name1, "draft") ||
		0 == strcmp(encoded_name, "sent") ||
		0 == strcmp(encoded_name1, "sent") ||
		0 == strcmp(encoded_name, "trash") ||
		0 == strcmp(encoded_name1, "trash") ||
		0 == strcmp(encoded_name, "junk") ||
		0 == strcmp(encoded_name1, "junk")) {
		
		/* IMAP_CODE_2190014: NO RENAME can not rename reserved folder name */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190014, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	switch (system_services_rename_folder(pcontext->maildir,
	        encoded_name, encoded_name1, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170008: OK RENAME completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170008, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_subscribe(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char buff[1024];
	int string_length;
	char temp_name[1024];
	const char *estring, *imap_reply_str;

	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| (FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], temp_name))) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	switch (system_services_subscribe_folder(
	        pcontext->maildir, temp_name, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170009: OK SUBSCRIBE completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170009, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_unsubscribe(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	char buff[1024];
	int string_length;
	char temp_name[1024];
	const char *estring, *imap_reply_str;

	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 3 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| (FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], temp_name))) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	switch (system_services_unsubscribe_folder(
	        pcontext->maildir, temp_name, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170010: OK UNSUBSCRIBE completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170010, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_list(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int len;
	int errnum;
	DIR_NODE *pdir;
	int string_length;
	MEM_FILE temp_file;
	DIR_TREE temp_tree;
	char buff[256*1024];
	char temp_name[1024];
	char search_pattern[1024];
	const char *estring, *imap_reply_str;
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || (0 == strcasecmp(argv[2], "(SPECIAL-USE)") && argc < 5)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (0 != strcasecmp(argv[2], "(SPECIAL-USE)")) {
		if (strlen(argv[2]) + strlen(argv[3]) >= 1024) {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		if ('\0' == argv[3][0]) {
			if (PROTO_STAT_SELECT == pcontext->proto_stat) {
				imap_parser_echo_modify(pcontext, NULL);
			}
			/* IMAP_CODE_2170011: OK LIST completed */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2170011, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
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
			/* IMAP_CODE_2190005: NO server internal
				error, missing MIDB connection */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190005, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		case MIDB_RDWR_ERROR:
			mem_file_free(&temp_file);
			/* IMAP_CODE_2190006: NO server internal
				error, fail to communicate with MIDB */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190006, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		default:
			mem_file_free(&temp_file);
			estring = resource_get_error_string(errnum);
			/* IMAP_CODE_2190007: NO server internal error, */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2190007, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s%s", argv[0], imap_reply_str, estring);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		mem_file_writeline(&temp_file, "inbox");
		mem_file_writeline(&temp_file, "draft");
		mem_file_writeline(&temp_file, "sent");
		mem_file_writeline(&temp_file, "trash");
		mem_file_writeline(&temp_file, "junk");
		imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
		dir_tree_init(&temp_tree, imap_parser_get_dpool());
		dir_tree_retrieve(&temp_tree, &temp_file);
		len = 0;
		mem_file_seek(&temp_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_readline(
			&temp_file, temp_name, 1024)) {
			if (TRUE == imap_cmd_parser_wildcard_match(
				temp_name, search_pattern)) {
				pdir = dir_tree_match(&temp_tree, temp_name);
				if (NULL != pdir && NULL != dir_tree_get_child(pdir)) {
					len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
						"* LIST (\\HasChildren) \"/\" \"%s\"\r\n", temp_name);
				} else {
					len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
						"* LIST (\\HasNoChildren) \"/\" \"%s\"\r\n", temp_name);
				}
			}
		}
		mem_file_free(&temp_file);
		dir_tree_free(&temp_tree);
		stream_clear(&pcontext->stream);
		if (PROTO_STAT_SELECT == pcontext->proto_stat) {
			imap_parser_echo_modify(pcontext, &pcontext->stream);
		}
		/* IMAP_CODE_2170011: OK LIST completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170011, 1, &string_length);
		len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
				"%s %s", argv[0], imap_reply_str);
		stream_write(&pcontext->stream, buff, len);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	} else {
		if (strlen(argv[3]) + strlen(argv[4]) >= 1024) {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		if ('\0' == argv[4][0]) {
			if (PROTO_STAT_SELECT == pcontext->proto_stat) {
				imap_parser_echo_modify(pcontext, NULL);
			}
			/* IMAP_CODE_2170011: OK LIST completed */
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2170011, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"* LIST (\\Noselect) \"/\" \"\"\r\n%s %s",
				argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		snprintf(search_pattern, 1024, "%s%s", argv[3], argv[4]);
		mem_file_init(&temp_file, imap_parser_get_allocator());
		mem_file_writeline(&temp_file, "inbox");
		mem_file_writeline(&temp_file, "draft");
		mem_file_writeline(&temp_file, "sent");
		mem_file_writeline(&temp_file, "trash");
		mem_file_writeline(&temp_file, "junk");
		imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
		len = 0;
		while (MEM_END_OF_FILE != mem_file_readline(
			&temp_file, temp_name, 1024)) {
			if (TRUE == imap_cmd_parser_wildcard_match(
				temp_name, search_pattern)) {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* LIST () \"/\" \"%s\"\r\n", temp_name);
			}
		}
		mem_file_free(&temp_file);
		stream_clear(&pcontext->stream);
		if (PROTO_STAT_SELECT == pcontext->proto_stat) {
			imap_parser_echo_modify(pcontext, &pcontext->stream);
		}
		/* IMAP_CODE_2170011: OK LIST completed */
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2170011, 1, &string_length);
		len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len, "%s %s", argv[0], imap_reply_str);
		stream_write(&pcontext->stream, buff, len);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	}	
}

int imap_cmd_parser_xlist(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, len;
	DIR_NODE *pdir;
	int string_length;
	MEM_FILE temp_file;
	DIR_TREE temp_tree;
	char buff[256*1024];
	char temp_name[1024];
	char search_pattern[1024];
	const char *estring, *imap_reply_str;
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	snprintf(search_pattern, 1024, "%s%s", argv[2], *argv[3] == '\0' ? "*" : argv[3]);
	mem_file_init(&temp_file, imap_parser_get_allocator());
	switch (system_services_enum_folders(
	        pcontext->maildir, &temp_file, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		mem_file_free(&temp_file);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		mem_file_free(&temp_file);
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		mem_file_free(&temp_file);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	dir_tree_init(&temp_tree, imap_parser_get_dpool());
	dir_tree_retrieve(&temp_tree, &temp_file);
	len = 0;
	if (TRUE == imap_cmd_parser_wildcard_match("INBOX", search_pattern)) {
		pdir = dir_tree_match(&temp_tree, "INBOX");
		if (NULL != pdir && NULL != dir_tree_get_child(pdir)) {
			len = gx_snprintf(buff + len, GX_ARRAY_SIZE(buff),
				"* XLIST (\\Inbox \\HasChildren) \"/\" \"INBOX\"\r\n");
		} else {
			len = gx_snprintf(buff + len, GX_ARRAY_SIZE(buff),
				"* XLIST (\\Inbox \\HasNoChildren) \"/\" \"INBOX\"\r\n");
		}
	}
	for (i=0; i<4; i++) {
		imap_cmd_parser_sysfolder_to_imapfolder(
			pcontext->lang, g_folder_list[i], temp_name);
		if (TRUE == imap_cmd_parser_wildcard_match(
			temp_name, search_pattern)) {
			pdir = dir_tree_match(&temp_tree, temp_name);
			if (NULL != pdir && NULL != dir_tree_get_child(pdir)) {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* XLIST (\\%s \\HasChildren) \"/\" \"%s\"\r\n",
					g_xproperty_list[i], temp_name);
			} else {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* XLIST (\\%s \\HasNoChildren) \"/\" \"%s\"\r\n",
					g_xproperty_list[i], temp_name);
			}
		}
	}
	mem_file_seek(&temp_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(
		&temp_file, temp_name, 1024)) {
		if (TRUE == imap_cmd_parser_wildcard_match(
			temp_name, search_pattern)) {
			pdir = dir_tree_match(&temp_tree, temp_name);
			if (NULL != pdir && NULL != dir_tree_get_child(pdir)) {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* XLIST (\\HasChildren) \"/\" \"%s\"\r\n", temp_name);
			} else {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* XLIST (\\HasNoChildren) \"/\" \"%s\"\r\n", temp_name);
			}
		}
	}
	mem_file_free(&temp_file);
	dir_tree_free(&temp_tree);
	stream_clear(&pcontext->stream);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	}
	/* IMAP_CODE_2170012: OK XLIST completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170012, 1, &string_length);
	len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
			"%s %s", argv[0], imap_reply_str);
	
	stream_write(&pcontext->stream, buff, len);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_lsub(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int len;
	int errnum;
	DIR_NODE *pdir;
	int string_length;
	MEM_FILE temp_file;
	MEM_FILE temp_file1;
	DIR_TREE temp_tree;
	char buff[256*1024];
	char temp_name[1024];
	char search_pattern[1024];
	const char *estring, *imap_reply_str;
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (strlen(argv[2]) + strlen(argv[3]) >= 1024) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if ('\0' == argv[3][0]) {
		if (PROTO_STAT_SELECT == pcontext->proto_stat) {
			imap_parser_echo_modify(pcontext, NULL);
		}
		/* IMAP_CODE_2170011: OK LIST completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170011, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
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
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		mem_file_free(&temp_file);
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		mem_file_free(&temp_file);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file);
	mem_file_init(&temp_file1, imap_parser_get_allocator());
	system_services_enum_folders(pcontext->maildir, &temp_file1, &errnum);
	mem_file_writeline(&temp_file1, "inbox");
	mem_file_writeline(&temp_file1, "draft");
	mem_file_writeline(&temp_file1, "sent");
	mem_file_writeline(&temp_file1, "trash");
	mem_file_writeline(&temp_file1, "junk");
	imap_cmd_parser_convert_folderlist(pcontext->lang, &temp_file1);
	dir_tree_init(&temp_tree, imap_parser_get_dpool());
	dir_tree_retrieve(&temp_tree, &temp_file1);
	mem_file_free(&temp_file1);
	len = 0;
	while (MEM_END_OF_FILE != mem_file_readline(
		&temp_file, temp_name, 1024)) {
		if (TRUE == imap_cmd_parser_wildcard_match(
			temp_name, search_pattern)) {
			pdir = dir_tree_match(&temp_tree, temp_name);
			if (NULL != pdir && NULL != dir_tree_get_child(pdir)) {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* LSUB (\\HasChildren) \"/\" \"%s\"\r\n", temp_name);
			} else {
				len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
					"* LSUB (\\HasNoChildren) \"/\" \"%s\"\r\n", temp_name);
			}
		}
	}
	mem_file_free(&temp_file);
	dir_tree_free(&temp_tree);
	stream_clear(&pcontext->stream);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
	}
	/* IMAP_CODE_2170013: OK LSUB completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170013, 1, &string_length);
	len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len,
			"%s %s", argv[0], imap_reply_str);
	stream_write(&pcontext->stream, buff, len);
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
	int string_length;
	char *temp_argv[16];
	char temp_name[1024];
	const char *estring, *imap_reply_str;
    
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot
		process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || 0 == strlen(argv[2]) || strlen(argv[2]) >= 1024
		|| FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], temp_name) || '(' != argv[3][0]
		|| ')' != argv[3][strlen(argv[3]) - 1]) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	temp_argc = parse_imap_args(argv[3] + 1,
		strlen(argv[3]) - 2, temp_argv, sizeof(temp_argv));
	if (-1 == temp_argc) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	switch (system_services_summary_folder(
		pcontext->maildir, temp_name, &exists, &recent,
	        &unseen, &uidvalid, &uidnext, nullptr, &errnum)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	/* IMAP_CODE_2170014: OK STATUS completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170014, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "* STATUS %s (", argv[2]);
	b_first = TRUE;
	for (i=0; i<temp_argc; i++) {
		if (FALSE == b_first) {
			buff[string_length] = ' ';
			string_length ++;
		} else {
			b_first = FALSE;
		}
		if (0 == strcasecmp(temp_argv[i], "MESSAGES")) {
			string_length += gx_snprintf(buff + string_length,
			                 GX_ARRAY_SIZE(buff) - string_length, "MESSAGES %d", exists);
		} else if (0 == strcasecmp(temp_argv[i], "RECENT")) {
			string_length += gx_snprintf(buff + string_length,
			                 GX_ARRAY_SIZE(buff) - string_length, "RECENT %d", recent);
		} else if (0 == strcasecmp(temp_argv[i], "UIDNEXT")) {
			string_length += gx_snprintf(buff + string_length,
			                 GX_ARRAY_SIZE(buff) - string_length, "UIDNEXT %d", uidnext);
		} else if (0 == strcasecmp(temp_argv[i], "UIDVALIDITY")) {
			string_length += gx_snprintf(buff + string_length,
			                 GX_ARRAY_SIZE(buff) - string_length, "UIDVALIDITY %u",
					(unsigned int)uidvalid);
		} else if (0 == strcasecmp(temp_argv[i], "UNSEEN")) {
			string_length += gx_snprintf(buff + string_length,
			                 GX_ARRAY_SIZE(buff) - string_length, "UNSEEN %d", unseen);
		} else {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
	}
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	string_length += gx_snprintf(buff + string_length,
	                 GX_ARRAY_SIZE(buff) - string_length, ")\r\n%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_append(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum;
	int i, fd;
	MAIL imail;
	BOOL b_seen;
	BOOL b_draft;
	unsigned long uidvalid;
	int temp_argc;
	BOOL b_flagged;
	BOOL b_answered;
	time_t tmp_time;
	int string_length;
	int string_length1;
	char* temp_argv[5];
	char *str_received;
	char *flags_string;
	char flag_buff[16];
	char file_name[128];
	char temp_path[256];
	char temp_name[1024];
	char buff[1024];
	const char *estring, *imap_reply_str;
	const char* imap_reply_str1;
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || argc > 6 || 0 == strlen(argv[2])
		|| strlen(argv[2]) >= 1024 || FALSE ==
		imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], temp_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
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
		if ('(' != flags_string[0] || ')' != flags_string[
			strlen(flags_string) - 1] || -1 == (temp_argc =
			parse_imap_args(flags_string + 1, strlen(flags_string)
			- 2, temp_argv, sizeof(temp_argv)))) {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
		for (i=0; i<temp_argc; i++) {
			if (0 == strcasecmp(temp_argv[i], "\\Answered")) {
				b_answered = TRUE;
			} else if (0 == strcasecmp(temp_argv[i], "\\Flagged")) {
				b_flagged = TRUE;
			} else if (0 == strcasecmp(temp_argv[i], "\\Seen")) {
				b_seen = TRUE;
			} else if (0 == strcasecmp(temp_argv[i], "\\Draft")) {
				b_draft = TRUE;
			} else {
				imap_reply_str = resource_get_imap_code(
					IMAP_CODE_2180000, 1, &string_length);
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
				imap_parser_safe_write(pcontext, buff, string_length);
				return DISPATCH_CONTINUE;
			}
		}
	}
	mail_init(&imail, imap_parser_get_mpool());
	if (FALSE == mail_retrieve(&imail,
		argv[argc - 1], strlen(argv[argc - 1]))) {
		mail_free(&imail);
		/* IMAP_CODE_2190008: NO cannot parse message, format error */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190008, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	strcpy(flag_buff, "(");
	if (TRUE == b_seen) {
		strcat(flag_buff, "S");
	}
	if (TRUE == b_answered) {
		strcat(flag_buff, "A");
	}
	if (TRUE == b_flagged) {
		strcat(flag_buff, "F");
	}
	if (TRUE == b_draft) {
		strcat(flag_buff, "U");
	}
	strcat(flag_buff, ")");
	if (NULL == str_received || FALSE ==
		imap_cmd_parser_covert_imaptime(str_received, &tmp_time)) {
		time(&tmp_time);
	}
	snprintf(file_name, 127, "%ld.%d.%s", tmp_time,
		imap_parser_get_sequence_ID(), resource_get_string("HOST_ID"));
	snprintf(temp_path, 255, "%s/eml/%s", pcontext->maildir, file_name);
	fd = open(temp_path, O_CREAT|O_RDWR|O_TRUNC, 0666);
	if (-1 == fd || FALSE == mail_to_file(&imail, fd)) {
		mail_free(&imail);
		if (-1 != fd) {
			close(fd);
			remove(temp_path);
		}
		/* IMAP_CODE_2190009: NO fail to save message */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190009, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	close(fd);
	mail_free(&imail);
	switch (system_services_insert_mail(pcontext->maildir,
	        temp_name, file_name, flag_buff, tmp_time, &errnum)) {
	case MIDB_RESULT_OK:
		imap_parser_log_info(pcontext, 8,
			"message %s is appended OK", temp_path);
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_parser_touch_modify(NULL, pcontext->username,
							pcontext->selected_folder);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170015, 1, &string_length);
	imap_reply_str1 = resource_get_imap_code(
		IMAP_CODE_2170015, 2, &string_length1);
	for (i=0; i<10; i++) {
		if (system_services_summary_folder(pcontext->maildir,
		    temp_name, nullptr, nullptr, nullptr, &uidvalid, nullptr,
		    nullptr, &errnum) == MIDB_RESULT_OK &&
		    system_services_get_uid(pcontext->maildir, temp_name,
		    file_name, &uid) == MIDB_RESULT_OK) {
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			                "%s %s [APPENDUID %u %d] %s",
				argv[0], imap_reply_str, (unsigned int)uidvalid,
				uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (10 == i) {
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s %s",
				argv[0], imap_reply_str, imap_reply_str1);
	}
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_append_begin(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int temp_argc;
	int i, fd, len;
	char buff[1024];
	int string_length;
	char *str_received;
	char *flags_string;
	char* temp_argv[5];
	char str_flags[128];
	char temp_name[1024];
	const char* imap_reply_str;
	
	if (pcontext->proto_stat < PROTO_STAT_AUTH) {
		/* IMAP_CODE_2180004: BAD cannot process in not authenticated state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180004, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_BREAK;
	}
	if (argc < 3 || argc > 5 || 0 == strlen(argv[2])
		|| strlen(argv[2]) >= 1024 || FALSE ==
		imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[2], temp_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_BREAK;
	}
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
		HX_strlcpy(str_flags, flags_string, GX_ARRAY_SIZE(str_flags));
		if ('(' != flags_string[0] || ')' != flags_string[
			strlen(flags_string) - 1] || -1 == (temp_argc =
			parse_imap_args(flags_string + 1, strlen(flags_string)
			- 2, temp_argv, sizeof(temp_argv)))) {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_BREAK;
		}
		for (i=0; i<temp_argc; i++) {
			if (0 == strcasecmp(temp_argv[i], "\\Answered") ||
				0 == strcasecmp(temp_argv[i], "\\Flagged") ||
				0 == strcasecmp(temp_argv[i], "\\Seen") ||
				0 == strcasecmp(temp_argv[i], "\\Draft")) {
				/* do nothing */
			} else {
				imap_reply_str = resource_get_imap_code(
					IMAP_CODE_2180000, 1, &string_length);
				string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
					"%s %s", argv[0], imap_reply_str);
				imap_parser_safe_write(pcontext, buff, string_length);
				return DISPATCH_BREAK;
			}
		}
	}
	snprintf(pcontext->mid, 127, "%ld.%d.%s", time(NULL),
		imap_parser_get_sequence_ID(), resource_get_string("HOST_ID"));
	snprintf(pcontext->file_path, 255, "%s/tmp/%s",
				pcontext->maildir, pcontext->mid);
	fd = open(pcontext->file_path, O_CREAT|O_RDWR|O_TRUNC, 0666);
	if (-1 == fd) {
		/* IMAP_CODE_2190009: NO fail to save message */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190009, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_BREAK;
	}
	len = sizeof(int);
	len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len, "%s", temp_name);
	buff[len] = '\0';
	len ++;
	if (NULL != flags_string) {
		len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len, "%s", str_flags);
	}
	buff[len] = '\0';
	len ++;
	if (NULL != str_received) {
		len += gx_snprintf(buff + len, GX_ARRAY_SIZE(buff) - len, "%s", str_received);
	}
	buff[len] = '\0';
	len ++;
	*(int*)buff = len;
	write(fd, buff, len);
	pcontext->message_fd = fd;
	HX_strlcpy(pcontext->tag_string, argv[0], GX_ARRAY_SIZE(pcontext->tag_string));
	stream_clear(&pcontext->stream);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_append_end(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int i;
	int fd;
	unsigned int uid;
	int errnum;
	MAIL imail;
	int tmp_len;
	BOOL b_seen;
	BOOL b_draft;
	int name_len;
	unsigned long uidvalid;
	int flags_len;
	char *str_name;
	BOOL b_flagged;
	BOOL b_answered;
	char *str_flags;
	time_t tmp_time;
	int string_length;
	int string_length1;
	char *str_internal;
	char flag_buff[16];
	char temp_path[256];
	char temp_name[1024];
	struct stat node_stat;
	char buff[1024];
	const char *estring, *imap_reply_str;
	const char *imap_reply_str1;
	
	b_answered = FALSE;
	b_flagged = FALSE;
	b_seen = FALSE;
	b_draft = FALSE;
	if (0 != fstat(pcontext->message_fd, &node_stat)) {
		close(pcontext->message_fd);
		remove(pcontext->file_path);
		pcontext->message_fd = -1;
		pcontext->mid[0] = '\0';
		pcontext->file_path[0] = '\0';
		/* IMAP_CODE_2190009: NO fail to save message */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190009, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	lseek(pcontext->message_fd, 0, SEEK_SET);
	auto pbuff = static_cast<char *>(malloc(((node_stat.st_size - 1) / (64 * 1024) + 1) * 64 * 1024));
	if (NULL == pbuff || node_stat.st_size != read(
		pcontext->message_fd, pbuff, node_stat.st_size)) {
		if (NULL != pbuff) {
			free(pbuff);
		}
		close(pcontext->message_fd);
		remove(pcontext->file_path);
		pcontext->message_fd = -1;
		pcontext->mid[0] = '\0';
		pcontext->file_path[0] = '\0';
		/* IMAP_CODE_2190009: NO fail to save message */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190009, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
			pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	close(pcontext->message_fd);
	pcontext->message_fd = -1;
	tmp_len = *(int*)pbuff;
	mail_init(&imail, imap_parser_get_mpool());
	if (FALSE == mail_retrieve(&imail, pbuff + tmp_len,
		node_stat.st_size - tmp_len)) {
		mail_free(&imail);
		free(pbuff);
		remove(pcontext->file_path);
		pcontext->mid[0] = '\0';
		pcontext->file_path[0] = '\0';
		/* IMAP_CODE_2190009: NO fail to save message */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190009, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	str_name = pbuff + sizeof(int);
	name_len = strlen(str_name);
	str_flags = str_name + name_len + 1;
	flags_len = strlen(str_flags);
	str_internal = str_flags + flags_len + 1;
	HX_strlcpy(temp_name, str_name, GX_ARRAY_SIZE(temp_name));
	if (NULL != search_string(str_flags, "\\Seen", flags_len)) {
		b_seen = TRUE;
	}
	if (NULL != search_string(str_flags, "\\Answered", flags_len)) {
		b_answered = TRUE;
	}
	if (NULL != search_string(str_flags, "\\Flagged", flags_len)) {
		b_flagged = TRUE;
	}
	if (NULL != search_string(str_flags, "\\Draft", flags_len)) {
		b_draft = TRUE;
	}
	strcpy(flag_buff, "(");
	if (TRUE == b_seen) {
		strcat(flag_buff, "S");
	}
	if (TRUE == b_answered) {
		strcat(flag_buff, "A");
	}
	if (TRUE == b_flagged) {
		strcat(flag_buff, "F");
	}
	if (TRUE == b_draft) {
		strcat(flag_buff, "U");
	}
	strcat(flag_buff, ")");
	if ('\0' == str_internal[0] ||
		FALSE == imap_cmd_parser_covert_imaptime(str_internal, &tmp_time)) {
		time(&tmp_time);
	}
	snprintf(temp_path, 255, "%s/eml/%s", pcontext->maildir, pcontext->mid);
	fd = open(temp_path, O_CREAT|O_RDWR|O_TRUNC, 0666);
	if (-1 == fd || FALSE == mail_to_file(&imail, fd)) {
		mail_free(&imail);
		free(pbuff);
		remove(pcontext->file_path);
		pcontext->mid[0] = '\0';
		pcontext->file_path[0] = '\0';
		if (-1 != fd) {
			close(fd);
			remove(temp_path);
		}
		/* IMAP_CODE_2190009: NO fail to save message */
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2190009, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	close(fd);
	mail_free(&imail);
	free(pbuff);
	remove(pcontext->file_path);
	pcontext->file_path[0] = '\0';
	switch (system_services_insert_mail(pcontext->maildir,
	        temp_name, pcontext->mid, flag_buff, tmp_time, &errnum)) {
	case MIDB_RESULT_OK:
		pcontext->mid[0] = '\0';
		imap_parser_log_info(pcontext, 8,
			"message %s is appended OK", temp_path);
		break;
	case MIDB_NO_SERVER:
		pcontext->mid[0] = '\0';
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
				pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		pcontext->mid[0] = '\0';
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s",
			pcontext->tag_string, imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		pcontext->mid[0] = '\0';
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
			pcontext->tag_string, imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_parser_touch_modify(NULL, pcontext->username,
							pcontext->selected_folder);
	if (PROTO_STAT_SELECT == pcontext->proto_stat) {
		imap_parser_echo_modify(pcontext, NULL);
	}
	/* IMAP_CODE_2170015: OK <APPENDUID> APPEND completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170015, 1, &string_length);
	imap_reply_str1 = resource_get_imap_code(
		IMAP_CODE_2170015, 2, &string_length1);
	for (i=0; i<10; i++) {
		if (system_services_summary_folder(pcontext->maildir,
		    temp_name, nullptr, nullptr, nullptr, &uidvalid,
		    nullptr, nullptr, &errnum) == MIDB_RESULT_OK &&
		    system_services_get_uid(pcontext->maildir, temp_name,
		    pcontext->mid, &uid) == MIDB_RESULT_OK) {
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s [APPENDUID %u %d] %s",
				pcontext->tag_string, imap_reply_str, (unsigned int)uidvalid,
				uid, imap_reply_str1);
			break;
		}
		usleep(50000);
	}
	if (10 == i) {
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s %s",
			pcontext->tag_string, imap_reply_str, imap_reply_str1);
	}
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_check(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
    const char* imap_reply_str;
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170016: OK CHECK completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170016, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
		"%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_close(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
    const char* imap_reply_str;
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_cmd_parser_clsfld(pcontext);
	/* IMAP_CODE_2170017: OK CLOSE completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170017, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, num;
	int result;
	int del_num;
	XARRAY xarray;
	BOOL b_deleted;
	int string_length;
	char buff[1024];
	char temp_file[256];
	SINGLE_LIST temp_list;
	const char *estring, *imap_reply_str;
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (TRUE == pcontext->b_readonly) {
		/* IMAP_CODE_2180006: BAD can not expunge with read-only status*/
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	b_deleted = FALSE;
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_list_deleted(pcontext->maildir,
	         pcontext->selected_folder, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	num = xarray_get_capacity(&xarray);
	single_list_init(&temp_list);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray_get_item(&xarray, i));
		if (0 == pitem->uid || 0 == (pitem->flag_bits & FLAG_DELETED)) {
			continue;
		}
		pitem->node.pdata = pitem;
		single_list_append_as_tail(&temp_list, &pitem->node);
	}
	result = system_services_remove_mail(pcontext->maildir,
	         pcontext->selected_folder, &temp_list, &errnum);
	single_list_free(&temp_list);
	switch(result) {
	case MIDB_RESULT_OK:
		stream_clear(&pcontext->stream);
		del_num = 0;
		for (i=0; i<xarray_get_capacity(&xarray); i++) {
			auto pitem = static_cast<MITEM *>(xarray_get_item(&xarray, i));
			if (0 == pitem->uid || 0 == (pitem->flag_bits & FLAG_DELETED)) {
				continue;
			}
			snprintf(temp_file, 256, "%s/eml/%s",
					pcontext->maildir, pitem->mid);
			remove(temp_file);
			imap_parser_log_info(pcontext, 8,
				"message %s is deleted", temp_file);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"* %d EXPUNGE\r\n", pitem->id - del_num);
			stream_write(&pcontext->stream, buff, string_length);
			b_deleted = TRUE;
			del_num ++;
		}
		xarray_free(&xarray);
		if (TRUE == b_deleted) {
			imap_parser_touch_modify(pcontext, pcontext->username,
										pcontext->selected_folder);
		}
		imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170026: OK EXPUNGE completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170026, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		stream_write(&pcontext->stream, buff, string_length);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
}

int imap_cmd_parser_unselect(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	char buff[1024];
	int string_length;
    const char* imap_reply_str;
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = PROTO_STAT_AUTH;
	pcontext->selected_folder[0] = '\0';
	/* IMAP_CODE_2170018: OK UNSELECT completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170018, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
		"%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
    return DISPATCH_CONTINUE;
}

int imap_cmd_parser_search(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int buff_len;
	int string_length;
	char buff[256*1024];
	const char *estring, *imap_reply_str;
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 3 || argc > 1024) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	memcpy(buff, "* SEARCH ", 9);
	buff_len = sizeof(buff) - 11;
	result = system_services_search(pcontext->maildir,
		pcontext->selected_folder, resource_get_default_charset(
		pcontext->lang), argc - 2, &argv[2], buff + 9, &buff_len,
		&errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	buff_len += 9;
	buff[buff_len] = '\r';
	buff_len ++;
	buff[buff_len] = '\n';
	buff_len ++;
	stream_clear(&pcontext->stream);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170019: OK SEARCH completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170019, 1, &string_length);
	buff_len += gx_snprintf(buff + buff_len, GX_ARRAY_SIZE(buff) - buff_len,
	            "%s %s", argv[0], imap_reply_str);
	stream_write(&pcontext->stream, buff, buff_len);
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
	XARRAY xarray;
	char buff[1024];
	int string_length;
	char* tmp_argv[128];
	DOUBLE_LIST list_seq;
	DOUBLE_LIST list_data;
	const char *estring, *imap_reply_str;
	DOUBLE_LIST_NODE nodes[1024];
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[2]))
		goto FETCH_PARAM_ERR;
	if (FALSE == imap_cmd_parser_parse_fetch_args(
		&list_data, nodes, &b_detail, &b_data, argv[3],
		tmp_argv, sizeof(tmp_argv)/sizeof(char*))) {
		goto FETCH_PARAM_ERR;
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	if (TRUE == b_detail) {
		result = system_services_fetch_detail(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	} else {
		result = system_services_fetch_simple(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	}
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	stream_clear(&pcontext->stream);
	num = xarray_get_capacity(&xarray);
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray_get_item(&xarray, i);
		imap_cmd_parser_process_fetch_item(pcontext,
			b_data, pitem, pitem->id, &list_data);
	}
	if (TRUE == b_detail) {
		system_services_free_result(&xarray);
	}
	xarray_free(&xarray);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170020: OK FETCH completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170020, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	string_length = strlen(buff);
	stream_write(&pcontext->stream, buff, string_length);
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	if (TRUE == b_data) {
		pcontext->write_buff = pcontext->command_buffer;
		pcontext->sched_stat = SCHED_STAT_WRDAT;
	} else {
		pcontext->sched_stat = SCHED_STAT_WRLST;
	}
	return DISPATCH_BREAK;
 FETCH_PARAM_ERR:
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2180000, 1, &string_length);
	string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
		"%s %s", argv[0], imap_reply_str);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_store(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int i, num;
	MITEM *pitem;
	XARRAY xarray;
	int flag_bits;
	int temp_argc;
	char buff[1024];
	int string_length;
	char *temp_argv[8];
	DOUBLE_LIST list_seq;
	const char *estring, *imap_reply_str;
	SEQUENCE_NODE sequence_nodes[1024];

	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 5 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[2]) || (0 != strcasecmp(argv[3],
		"FLAGS") && 0 != strcasecmp(argv[3], "FLAGS.SILENT") &&
		0 != strcasecmp(argv[3], "+FLAGS") && 0 != strcasecmp(argv[3],
		"+FLAGS.SILENT") && 0 != strcasecmp(argv[3], "-FLAGS") &&
		0 != strcasecmp(argv[3], "-FLAGS.SILENT"))) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if ('(' == argv[4][0] && ')' == argv[4][strlen(argv[4]) - 1]) {
		if (-1 == (temp_argc = parse_imap_args(
			argv[4] + 1, strlen(argv[4]) - 2, temp_argv,
			sizeof(temp_argv)/sizeof(char*)))) {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
	} else {
		temp_argc = 1;
		temp_argv[0] = argv[4];
	}
	if (TRUE == pcontext->b_readonly) {
		/* IMAP_CODE_2180006: BAD can not store with read-only status */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	flag_bits = 0;
	for (i=0; i<temp_argc; i++) {
		if (0 == strcasecmp(temp_argv[i], "\\Answered")) {
			flag_bits |= FLAG_ANSWERED;
		} else if (0 == strcasecmp(temp_argv[i], "\\Flagged")) {
			flag_bits |= FLAG_FLAGGED;
		} else if (0 == strcasecmp(temp_argv[i], "\\Deleted")) {
			flag_bits |= FLAG_DELETED;
		} else if (0 == strcasecmp(temp_argv[i], "\\Seen")) {
			flag_bits |= FLAG_SEEN;
		} else if (0 == strcasecmp(temp_argv[i], "\\Draft")) {
			flag_bits |= FLAG_DRAFT;
		} else {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180007, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	num = xarray_get_capacity(&xarray);
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray_get_item(&xarray, i);
		imap_cmd_parser_store_flags(argv[3], pitem->mid,
			pitem->id, 0, flag_bits, pcontext);
		imap_parser_modify_flags(pcontext, pitem->mid);
	}
	xarray_free(&xarray);
	imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170021: OK STORE completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170021, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	string_length = strlen(buff);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_copy(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum;
	int result;
	MITEM *pitem;
	BOOL b_first;
	BOOL b_copied;
	XARRAY xarray;
	int i, j, num;
	unsigned long uidvalidity;
	int string_length;
	int string_length1;
	char buff[64*1024];
	char temp_name[1024];
	DOUBLE_LIST list_seq;
	SINGLE_LIST temp_list;
	char uid_string[64*1024];
	char uid_string1[64*1024];
	const char *estring, *imap_reply_str;
	const char* imap_reply_str1;
	SEQUENCE_NODE sequence_nodes[1024];
    
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[2]) || strlen(argv[3]) == 0 || strlen(argv[3])
		>= 1024 || FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[3], temp_name)) {
		imap_reply_str = resource_get_imap_code(IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (system_services_summary_folder(pcontext->maildir,
	    temp_name, nullptr, nullptr, nullptr, &uidvalidity, nullptr,
	    nullptr, &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	string_length = 0;
	string_length1 = 0;
	num = xarray_get_capacity(&xarray);
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray_get_item(&xarray, i);
		if (system_services_copy_mail(pcontext->maildir,
		    pcontext->selected_folder, pitem->mid, temp_name,
		    pitem->mid, &errnum) != MIDB_RESULT_OK) {
			b_copied = FALSE;
			break;
		}
		if (0 != uidvalidity) {
			for (j=0; j<10; j++) {
				if (MIDB_RESULT_OK == system_services_get_uid(
					pcontext->maildir, temp_name, pitem->mid, &uid)) {
					if (TRUE == b_first) {
						uid_string[string_length] = ',';
						string_length ++;
						uid_string1[string_length1] = ',';
						string_length1 ++;
					} else {
						b_first =  TRUE;
					}
					string_length += gx_snprintf(uid_string + string_length,
					                 GX_ARRAY_SIZE(uid_string) - string_length, "%d", pitem->uid);
					string_length1 += gx_snprintf(uid_string1 + string_length1,
					                  GX_ARRAY_SIZE(uid_string1) - string_length1, "%d", uid);
					break;
				}
				usleep(50000);
			}
			if (10 == j) {
				uidvalidity = 0;
			}
		}
	}
	if (FALSE == b_copied) {
		single_list_init(&temp_list);
		for (;i>0; i--) {
			pitem = (MITEM*)xarray_get_item(&xarray, i - 1);
			if (0 == pitem->uid) {
				continue;
			}
			pitem->node.pdata = pitem;
			single_list_append_as_tail(&temp_list, &pitem->node);
		}
		system_services_remove_mail(pcontext->maildir,
			temp_name, &temp_list, &errnum);
		single_list_free(&temp_list);
	}
	xarray_free(&xarray);
	stream_clear(&pcontext->stream);
	if (TRUE == b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170022: OK <COPYUID> COPY completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170022, 1, &string_length);
		imap_reply_str1 = resource_get_imap_code(
			IMAP_CODE_2170022, 2, &string_length1);
		if (0 != uidvalidity) {
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s [COPYUID %u %s %s] %s", argv[0],
				imap_reply_str, (unsigned int)uidvalidity,
				uid_string, uid_string1, imap_reply_str1);
		} else {
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s %s", argv[0], imap_reply_str, imap_reply_str1);
		}
	} else {
		/* IMAP_CODE_2190016: NO COPY failed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190016, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
	}
	stream_write(&pcontext->stream, buff, string_length);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_search(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int buff_len;
	int string_length;
	char buff[256*1024];
	const char *estring, *imap_reply_str;
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	
	if (argc < 3 || argc > 1024) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	
	
	memcpy(buff, "* SEARCH ", 9);
	buff_len = sizeof(buff) - 11;
	result = system_services_search_uid(pcontext->maildir,
	         pcontext->selected_folder, resource_get_default_charset(pcontext->lang),
	         argc - 3, &argv[3], buff + 9, &buff_len, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	buff_len += 9;
	buff[buff_len] = '\r';
	buff_len ++;
	buff[buff_len] = '\n';
	buff_len ++;
	stream_clear(&pcontext->stream);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170023: OK UID SEARCH completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170023, 1, &string_length);
	buff_len += gx_snprintf(buff + buff_len, GX_ARRAY_SIZE(buff) - buff_len,
	            "%s %s", argv[0], imap_reply_str);
	stream_write(&pcontext->stream, buff, buff_len);
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
	XARRAY xarray;
	BOOL b_detail;
	char buff[1024];
	int string_length;
	char* tmp_argv[128];
	DOUBLE_LIST list_seq;
	DOUBLE_LIST list_data;
	DOUBLE_LIST_NODE *pnode;
	const char *estring, *imap_reply_str;
	DOUBLE_LIST_NODE nodes[1024];
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
		string_length = strlen(buff);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 5 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3]))
		goto UID_FETCH_PARAM_ERR;
	if (FALSE == imap_cmd_parser_parse_fetch_args(
		&list_data, nodes, &b_detail, &b_data, argv[4],
		tmp_argv, sizeof(tmp_argv)/sizeof(char*))) {
		goto UID_FETCH_PARAM_ERR;
	}
	for (pnode=double_list_get_head(&list_data); NULL!=pnode;
		pnode=double_list_get_after(&list_data, pnode)) {
		if (0 == strcasecmp((char*)pnode->pdata, "UID")) {
			break;
		}
	}
	if (NULL == pnode) {
		nodes[1023].pdata = deconst("UID");
		double_list_insert_as_head(&list_data, &nodes[1023]);
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	if (TRUE == b_detail) {
		result = system_services_fetch_detail_uid(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	} else {
		result = system_services_fetch_simple_uid(pcontext->maildir,
		         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	}
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
		string_length = strlen(buff);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
		string_length = strlen(buff);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		snprintf(buff, sizeof(buff), "%s %s%s", argv[0], imap_reply_str, estring);
		string_length = strlen(buff);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	stream_clear(&pcontext->stream);
	num = xarray_get_capacity(&xarray);
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray_get_item(&xarray, i);
		imap_cmd_parser_process_fetch_item(pcontext,
			b_data, pitem, pitem->id, &list_data);
	}
	if (TRUE == b_detail) {
		system_services_free_result(&xarray);
	}
	xarray_free(&xarray);
	imap_parser_echo_modify(pcontext, &pcontext->stream);
	/* IMAP_CODE_2170028: OK UID FETCH completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170028, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	string_length = strlen(buff);
	stream_write(&pcontext->stream, buff, string_length);
	pcontext->write_length = 0;
	pcontext->write_offset = 0;
	if (TRUE == b_data) {
		pcontext->write_buff = pcontext->command_buffer;
		pcontext->sched_stat = SCHED_STAT_WRDAT;
	} else {
		pcontext->sched_stat = SCHED_STAT_WRLST;
	}
	return DISPATCH_BREAK;
	
 UID_FETCH_PARAM_ERR:
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2180000, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	string_length = strlen(buff);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_uid_store(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int num;
	int errnum;
	int i;
	int result;
	MITEM *pitem;
	XARRAY xarray;
	int flag_bits;
	int temp_argc;
	char buff[1024];
	char *temp_argv[8];
	int string_length;
	DOUBLE_LIST list_seq;
	const char *estring, *imap_reply_str;
	SEQUENCE_NODE sequence_nodes[1024];

	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 6 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3]) || (0 != strcasecmp(argv[4],
		"FLAGS") && 0 != strcasecmp(argv[4], "FLAGS.SILENT") &&
		0 != strcasecmp(argv[4], "+FLAGS") && 0 != strcasecmp(argv[4],
		"+FLAGS.SILENT") && 0 != strcasecmp(argv[4], "-FLAGS") &&
		0 != strcasecmp(argv[4], "-FLAGS.SILENT"))) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if ('(' == argv[5][0] && ')' == argv[5][strlen(argv[5]) - 1]) {
		if (-1 == (temp_argc = parse_imap_args(
			argv[5] + 1, strlen(argv[5]) - 2, temp_argv,
			sizeof(temp_argv)/sizeof(char*)))) {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180000, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
	} else {
		temp_argc = 1;
		temp_argv[0] = argv[5];
	}
	if (TRUE == pcontext->b_readonly) {
		/* IMAP_CODE_2180006: BAD can not store with read-only status */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	flag_bits = 0;
	for (i=0; i<temp_argc; i++) {
		if (0 == strcasecmp(temp_argv[i], "\\Answered")) {
			flag_bits |= FLAG_ANSWERED;
		} else if (0 == strcasecmp(temp_argv[i], "\\Flagged")) {
			flag_bits |= FLAG_FLAGGED;
		} else if (0 == strcasecmp(temp_argv[i], "\\Deleted")) {
			flag_bits |= FLAG_DELETED;
		} else if (0 == strcasecmp(temp_argv[i], "\\Seen")) {
			flag_bits |= FLAG_SEEN;
		} else if (0 == strcasecmp(temp_argv[i], "\\Draft")) {
			flag_bits |= FLAG_DRAFT;
		} else {
			imap_reply_str = resource_get_imap_code(
				IMAP_CODE_2180007, 1, &string_length);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s", argv[0], imap_reply_str);
			imap_parser_safe_write(pcontext, buff, string_length);
			return DISPATCH_CONTINUE;
		}
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple_uid(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	num = xarray_get_capacity(&xarray);
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray_get_item(&xarray, i);
		imap_cmd_parser_store_flags(argv[4], pitem->mid,
			pitem->id, pitem->uid, flag_bits, pcontext);
		imap_parser_modify_flags(pcontext, pitem->mid);
	}
	xarray_free(&xarray);
	imap_parser_echo_modify(pcontext, NULL);
	/* IMAP_CODE_2170024: OK UID STORE completed */
	imap_reply_str = resource_get_imap_code(
		IMAP_CODE_2170024, 1, &string_length);
	snprintf(buff, sizeof(buff), "%s %s", argv[0], imap_reply_str);
	string_length = strlen(buff);
	imap_parser_safe_write(pcontext, buff, string_length);
	return DISPATCH_CONTINUE;
}

int imap_cmd_parser_uid_copy(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	unsigned int uid;
	int errnum;
	int result;
	BOOL b_first;
	MITEM *pitem;
	BOOL b_copied;
	XARRAY xarray;
	int i, j, num;
	unsigned long uidvalidity;
	int string_length;
	int string_length1;
	char buff[64*1024];
	char temp_name[1024];
	DOUBLE_LIST list_seq;
	SINGLE_LIST temp_list;
	char uid_string[64*1024];
	const char *estring, *imap_reply_str;
	const char* imap_reply_str1;
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 5 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3]) || 0 == strlen(argv[4]) || strlen(argv[4])
		>= 1024 || FALSE == imap_cmd_parser_imapfolder_to_sysfolder(
		pcontext->lang, argv[4], temp_name)) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_fetch_simple_uid(pcontext->maildir,
	         pcontext->selected_folder, &list_seq, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
			error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (system_services_summary_folder(pcontext->maildir,
	    temp_name, nullptr, nullptr, nullptr, &uidvalidity,
	    nullptr, nullptr, &errnum) != MIDB_RESULT_OK)
		uidvalidity = 0;
	b_copied = TRUE;
	b_first = FALSE;
	string_length = 0;
	num = xarray_get_capacity(&xarray);
	for (i=0; i<num; i++) {
		pitem = (MITEM*)xarray_get_item(&xarray, i);
		if (system_services_copy_mail(pcontext->maildir,
		    pcontext->selected_folder, pitem->mid, temp_name,
		    pitem->mid, &errnum) != MIDB_RESULT_OK) {
			b_copied = FALSE;
			break;
		}
		if (0 != uidvalidity) {
			for (j=0; j<10; j++) {
				if (MIDB_RESULT_OK == system_services_get_uid(
					pcontext->maildir, temp_name, pitem->mid, &uid)) {
					if (TRUE == b_first) {
						uid_string[string_length] = ',';
						string_length ++;
					} else {
						b_first =  TRUE;
					}
					string_length += gx_snprintf(uid_string + string_length,
					                 GX_ARRAY_SIZE(uid_string) - string_length, "%d", uid);
					break;
				}
				usleep(50000);
			}
			if (10 == j) {
				uidvalidity = 0;
			}
		}
	}
	if (FALSE == b_copied) {
		single_list_init(&temp_list);
		for (;i>0; i--) {
			pitem = (MITEM*)xarray_get_item(&xarray, i - 1);
			if (0 == pitem->uid) {
				continue;
			}
			pitem->node.pdata = pitem;
			single_list_append_as_tail(&temp_list, &pitem->node);
		}
		system_services_remove_mail(pcontext->maildir,
			temp_name, &temp_list, &errnum);
		single_list_free(&temp_list);
	}
	xarray_free(&xarray);
	stream_clear(&pcontext->stream);
	if (TRUE == b_copied) {
		imap_parser_echo_modify(pcontext, &pcontext->stream);
		/* IMAP_CODE_2170025: OK <COPYUID> UID COPY completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170025, 1, &string_length);
		imap_reply_str1 = resource_get_imap_code(
			IMAP_CODE_2170025, 2, &string_length1);
		if (0 != uidvalidity) {
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"%s %s [COPYUID %u %s %s] %s", argv[0],
				imap_reply_str, (unsigned int)uidvalidity, argv[3],
				uid_string, imap_reply_str1);
		} else {
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s %s",
					argv[0], imap_reply_str, imap_reply_str1);
		}
	} else {
		/* IMAP_CODE_2190017: NO UID COPY failed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190017, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s", argv[0], imap_reply_str);
	}
	stream_write(&pcontext->stream, buff, string_length);
	pcontext->write_offset = 0;
	pcontext->sched_stat = SCHED_STAT_WRLST;
	return DISPATCH_BREAK;
}

int imap_cmd_parser_uid_expunge(int argc, char **argv, IMAP_CONTEXT *pcontext)
{
	int errnum;
	int i, num;
	int result;
	int del_num;
	int max_uid;
	XARRAY xarray;
	BOOL b_deleted;
	char buff[1024];
	int string_length;
	char temp_path[256];
    DOUBLE_LIST list_seq;
	SINGLE_LIST temp_list;
	const char *estring, *imap_reply_str;
	SEQUENCE_NODE sequence_nodes[1024];
	
	if (PROTO_STAT_SELECT != pcontext->proto_stat) {
		/* IMAP_CODE_2180005: BAD can only process in select state */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (TRUE == pcontext->b_readonly) {
		/* IMAP_CODE_2180006: BAD can not expunge with read-only status*/
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	if (argc < 4 || !imap_cmd_parser_parse_sequence(&list_seq,
	    sequence_nodes, argv[3])) {
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2180000, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	b_deleted = FALSE;
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_list_deleted(pcontext->maildir,
	         pcontext->selected_folder, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	num = xarray_get_capacity(&xarray);
	if (0 == num) {
		xarray_free(&xarray);
		imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170030: OK UID EXPUNGE completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170030, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
	auto pitem = static_cast<MITEM *>(xarray_get_item(&xarray, num - 1));
	max_uid = pitem->uid;
	single_list_init(&temp_list);
	for (i=0; i<num; i++) {
		pitem = static_cast<MITEM *>(xarray_get_item(&xarray, i));
		if (0 == pitem->uid || 0 == (pitem->flag_bits & FLAG_DELETED) ||
		    !imap_cmd_parser_hint_sequence(&list_seq, pitem->uid,
			max_uid)) {
			continue;
		}
		pitem->node.pdata = pitem;
		single_list_append_as_tail(&temp_list, &pitem->node);
	}
	result = system_services_remove_mail(pcontext->maildir,
	         pcontext->selected_folder, &temp_list, &errnum);
	single_list_free(&temp_list);
	switch(result) {
	case MIDB_RESULT_OK:
		stream_clear(&pcontext->stream);
		del_num = 0;
		for (i=0; i<xarray_get_capacity(&xarray); i++) {
			pitem = static_cast<MITEM *>(xarray_get_item(&xarray, i));
			if (0 == pitem->uid || 0 == (pitem->flag_bits & FLAG_DELETED) ||
			    !imap_cmd_parser_hint_sequence(&list_seq, pitem->uid,
				max_uid)) {
				continue;
			}
			snprintf(temp_path, 256, "%s/eml/%s",
				pcontext->maildir, pitem->mid);
			remove(temp_path);
			imap_parser_log_info(pcontext, 8,
				"message %s is deleted", temp_path);
			string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
				"* %d EXPUNGE\r\n", pitem->id - del_num);
			stream_write(&pcontext->stream, buff, string_length);
			b_deleted = TRUE;
			del_num ++;
		}
		xarray_free(&xarray);
		if (TRUE == b_deleted) {
			imap_parser_touch_modify(pcontext, pcontext->username,
										pcontext->selected_folder);
		}
		imap_parser_echo_modify(pcontext, NULL);
		/* IMAP_CODE_2170026: OK UID EXPUNGE completed */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2170026, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		stream_write(&pcontext->stream, buff, string_length);
		pcontext->write_offset = 0;
		pcontext->sched_stat = SCHED_STAT_WRLST;
		return DISPATCH_BREAK;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"%s %s", argv[0], imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "%s %s%s",
					argv[0], imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return DISPATCH_CONTINUE;
	}
}

void imap_cmd_parser_clsfld(IMAP_CONTEXT *pcontext)
{
	int errnum;
	int result;
	int i, num;
	XARRAY xarray;
	BOOL b_deleted;
	char buff[1024];
	char temp_path[256];
	char temp_file[256];
	char prev_selected[128];
	int string_length;
	SINGLE_LIST temp_list;
	const char *estring, *imap_reply_str;
	
	if ('\0' == pcontext->selected_folder[0]) {
		return;
	}
	snprintf(temp_path, 256, "%s/eml", pcontext->maildir);
	imap_parser_remove_select(pcontext);
	pcontext->proto_stat = PROTO_STAT_AUTH;
	strcpy(prev_selected, pcontext->selected_folder);
	pcontext->selected_folder[0] = '\0';
	if (TRUE == pcontext->b_readonly) {
		return;
	}
	xarray_init(&xarray, imap_parser_get_xpool(), sizeof(MITEM));
	result = system_services_list_deleted(pcontext->maildir,
	         prev_selected, &xarray, &errnum);
	switch(result) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"* %s%s", imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	b_deleted = FALSE;
	num = xarray_get_capacity(&xarray);
	single_list_init(&temp_list);
	for (i=0; i<num; i++) {
		auto pitem = static_cast<MITEM *>(xarray_get_item(&xarray, i));
		if (0 == pitem->uid || 0 == (pitem->flag_bits & FLAG_DELETED)) {
			continue;
		}
		pitem->node.pdata = pitem;
		single_list_append_as_tail(&temp_list, &pitem->node);
	}
	result = system_services_remove_mail(pcontext->maildir,
	         prev_selected, &temp_list, &errnum);
	single_list_free(&temp_list);
	switch(result) {
	case MIDB_RESULT_OK:
		for (i=0; i<num; i++) {
			auto pitem = static_cast<MITEM *>(xarray_get_item(&xarray, i));
			if (0 == pitem->uid || 0 == (pitem->flag_bits & FLAG_DELETED)) {
				continue;
			}
			snprintf(temp_file, 256, "%s/%s", temp_path, pitem->mid);
			remove(temp_file);
			imap_parser_log_info(pcontext, 8,
				"message %s is deleted", temp_file);
			b_deleted = TRUE;
		}
		break;
	case MIDB_NO_SERVER:
		xarray_free(&xarray);
		/* IMAP_CODE_2190005: NO server internal
			error, missing MIDB connection */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190005, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	case MIDB_RDWR_ERROR:
		xarray_free(&xarray);
		/* IMAP_CODE_2190006: NO server internal
		error, fail to communicate with MIDB */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190006, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "* %s", imap_reply_str);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	default:
		xarray_free(&xarray);
		estring = resource_get_error_string(errnum);
		/* IMAP_CODE_2190007: NO server internal error, */
		imap_reply_str = resource_get_imap_code(
			IMAP_CODE_2190007, 1, &string_length);
		string_length = gx_snprintf(buff, GX_ARRAY_SIZE(buff),
			"* %s%s", imap_reply_str, estring);
		imap_parser_safe_write(pcontext, buff, string_length);
		return;
	}
	xarray_free(&xarray);
	if (TRUE == b_deleted) {
		imap_parser_touch_modify(pcontext,
			pcontext->username, prev_selected);
	}
}
