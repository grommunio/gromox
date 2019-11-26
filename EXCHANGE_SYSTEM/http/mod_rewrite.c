#include "mod_rewrite.h"
#include "double_list.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <regex.h>

#define MAX_LINE					16*1024

typedef struct _REWRITE_NODE {
	DOUBLE_LIST_NODE node;
	regex_t search_pattern;
	char *replace_string;
} REWRITE_NODE;

static char g_list_path[256];
static DOUBLE_LIST g_rewite_list;

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
		strncpy(buf, rp + 2, size);
		return TRUE;
	}
	strcpy(original_buf, buf);
	strcpy(original_rp, rp);
	for (i=0; i<10; i++) {
		rp_offsets[i] = -1;
	}
	for (pos=original_rp; '\0'!=*pos; pos++) {
		if ('\\' == *pos && *(pos + 1) > '0' && *(pos + 1) <= '9') {
			rp_offsets[*(pos + 1) - '0'] = pos + 2 - original_rp;
			*pos = '\0';
		}
	}
	last_pos = 0;
	for (i=1,offset=0; i<=10&&offset<size; i++) {
		if (pmatch[i].rm_so < 0 || pmatch[i].rm_eo < 0 || 10 == i) {
			len = strlen(original_buf + last_pos);
			if (offset + len >= size) {
				break;
			}
			strcpy(buf + offset, original_buf + last_pos);
			return TRUE;
		}
		if (-1 != rp_offsets[i]) {
			len = pmatch[i].rm_so - last_pos;
			if (offset + len >= size) {
				break;
			}
			memcpy(buf + offset, original_buf + last_pos, len);
			offset += len;
			len = strlen(original_rp + rp_offsets[i]);
			if (offset + len >= size) {
				break;
			}
			strcpy(buf + offset, original_rp + rp_offsets[i]);
		} else {
			len = pmatch[i].rm_eo - last_pos;
			if (offset + len >= size) {
				break;
			}
			memcpy(buf + offset, original_buf + last_pos, len);
		}
		offset += len;
		last_pos = pmatch[i].rm_eo;
	}
	return FALSE;
}

void mod_rewrite_init(const char *list_path)
{
	strcpy(g_list_path, list_path);
	double_list_init(&g_rewite_list);
}

int mod_rewrite_run()
{
	int tmp_len;
	int line_no;
	char *ptoken;
	int table_size;
	FILE *file_ptr;
	char line[MAX_LINE];
	REWRITE_NODE *prnode;
	
	line_no = 0;
	file_ptr = fopen(g_list_path, "r");
	while (NULL != fgets(line, MAX_LINE, file_ptr)) {
		line_no ++;
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			/* skip empty line or comments */
			continue;
		}
		/* prevent line exceed maximum length ---MAX_LEN */
		line[sizeof(line) - 1] = '\0';
		tmp_len = strlen(line);
		if ('\r' == line[tmp_len - 2] && '\n' == line[tmp_len - 1]) {
			line[tmp_len - 2] = '\0';
		} else if ('\n' == line[tmp_len - 1] || '\r' == line[tmp_len - 1]) {
			line[tmp_len - 1] = '\0';
		}
		ltrim_string(line);
		rtrim_string(line);
		ptoken = strstr(line, "=>");
		if (NULL == ptoken) {
			printf("[mod_rewrite]: invalid line %d, cannot "
						"find seperator \"=>\"\n", line_no);
			continue;
		}
		*ptoken = '\0';
		rtrim_string(line);
		ptoken += 2;
		ltrim_string(ptoken);
		if ('\\' != ptoken[0] || ptoken[1] < '0' || ptoken[1] > '9') {
			printf("[mod_rewrite]: invalid line %d, cannot"
				" find replace sequence number\n", line_no);
			continue;
		}
		prnode = malloc(sizeof(REWRITE_NODE));
		if (NULL == prnode) {
			printf("[mod_rewrite]: cannot load line"
					" %d, out of memory\n", line_no);
			continue;
		}
		prnode->node.pdata = prnode;
		prnode->replace_string = strdup(ptoken);
		if (NULL == prnode->replace_string) {
			free(prnode);
			printf("[mod_rewrite]: cannot load line"
					" %d, out of memory\n", line_no);
			continue;
		}
		if (0 != regcomp(&prnode->search_pattern, line, REG_ICASE)) {
			free(prnode->replace_string);
			free(prnode);
			printf("[mod_rewrite]: invalid line %d, search"
						" pattern regex error\n", line_no);
			continue;
		}
		double_list_append_as_tail(&g_rewite_list, &prnode->node);
	}
	fclose(file_ptr);
	return 0;
}

int mod_rewrite_stop()
{
	REWRITE_NODE *prnode;
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(&g_rewite_list)) {
		prnode = (REWRITE_NODE*)pnode->pdata;
		regfree(&prnode->search_pattern);
		free(prnode->replace_string);
		free(prnode);
	}
}

void mod_rewrite_free()
{
	double_list_free(&g_rewite_list);
}

BOOL mod_rewrite_process(const char *uri_buff,
	int uri_len, MEM_FILE *pf_request_uri)
{
	char tmp_buff[8192];
	REWRITE_NODE *prnode;
	DOUBLE_LIST_NODE *pnode;
	
	if (uri_len >= sizeof(tmp_buff)) {
		return FALSE;
	}
	for (pnode=double_list_get_head(&g_rewite_list); NULL!=pnode;
		pnode=double_list_get_after(&g_rewite_list, pnode)) {
		prnode = (REWRITE_NODE*)pnode->pdata;
		memcpy(tmp_buff, uri_buff, uri_len);
		tmp_buff[uri_len] = '\0';
		if (TRUE == mod_rewrite_rreplace(tmp_buff, sizeof(tmp_buff),
			&prnode->search_pattern, prnode->replace_string)) {
			mem_file_write(pf_request_uri, tmp_buff, strlen(tmp_buff));
			return TRUE;
		}
	}
	return FALSE;
}
