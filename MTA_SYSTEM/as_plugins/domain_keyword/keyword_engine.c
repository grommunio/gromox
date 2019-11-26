#include <libHX/defs.h>
#include "keyword_engine.h"
#include "single_list.h"
#include "list_file.h"
#include <stdio.h>
#include <iconv.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct _CHARSET_ITEM {
	SINGLE_LIST_NODE node;
	char charset[32];
	char **match_table;
} CHARSET_ITEM;

typedef struct _KEYWORD_NODE {
	SINGLE_LIST_NODE node;
	int length;
	char keyword[1024];
} KEYWORD_NODE;

KEYWORD_ENGINE* keyword_engine_init(char *charset_path, char *list_path)
{
	int i, j, k, temp_len;
	size_t in_len, out_len, conv_ret;
	int item_num1, item_num2;
	unsigned short temp_index[4];
	iconv_t conv_id;
	char *pin, *pout, *ptr;
	char temp_buff[1024];
	char *pitem1, *pitem2;
	CHARSET_ITEM *pcharset;
	LIST_FILE *pfile1, *pfile2;
	SINGLE_LIST **temp_table;
	SINGLE_LIST_NODE *pnode;
	KEYWORD_NODE *pkeyword;
	SINGLE_LIST *charset_list;
	
	charset_list = malloc(sizeof(SINGLE_LIST));
	if (NULL == charset_list) {
		printf("[keyword_engine]: fail to allocate memory for "
			"keyword engine\n");
		return NULL;
	}
	single_list_init(charset_list);
	pfile1 = list_file_init(charset_path, "%s:32");
	if (NULL == pfile1) {
		printf("[keyword_engine]: fail to init charset list file\n");
		free(charset_list);
		return NULL;
	}
	pfile2 = list_file_init(list_path, "%s:256");
	if (NULL == pfile2) {
		printf("[keyword_engine]: fail to init keyword list file\n");
		free(charset_list);
		list_file_free(pfile1);
		return NULL;
	}
	pitem1 = list_file_get_list(pfile1);
	item_num1 = list_file_get_item_num(pfile1);
	pitem2 = list_file_get_list(pfile2);
	item_num2 = list_file_get_item_num(pfile2);
	temp_table = (SINGLE_LIST**)malloc(256*256*sizeof(SINGLE_LIST*));
	if (NULL == temp_table) {
		printf("[keyword_engine]: fail to allocate memory for "
			"temporary index table\n");
		free(charset_list);
		list_file_free(pfile1);
		list_file_free(pfile2);
		return NULL;
	}
	memset(temp_table, 0, sizeof(SINGLE_LIST*)*256*256);
	for (i=0; i<item_num1; i++) {
		pcharset = (CHARSET_ITEM*)malloc(sizeof(CHARSET_ITEM));
		if (NULL == pcharset) {
			printf("[keyword_engine]: fail to allocate charset node for %s\n",
				pitem1 + 32*i);
			continue;
		}
		pcharset->node.pdata = pcharset;
		strcpy(pcharset->charset, pitem1 + 32*i);
		pcharset->match_table = malloc(256*256*sizeof(void*));
		if (NULL == pcharset->match_table) {
			printf("[keyword_engine]: fail to allocate match index table "
				"for %s", pcharset->charset);
			free(pcharset);
			continue;
		}
		memset(pcharset->match_table, 0, 256*256*sizeof(void*));
		if (0 != i) {
			conv_id = iconv_open(pitem1 + 32*i, pitem1);
			if ((iconv_t)-1 == conv_id) {
				free(pcharset->match_table);
				free(pcharset);
				continue;
			}
		}
		for (j=0; j<item_num2; j++) {
			if (0 == i) {
				strcpy(temp_buff, pitem2 + 256*j);
			} else {
				pin = pitem2 + 256*j;
				pout = temp_buff;
				in_len = strlen(pin) + 1;
				out_len = 1024;
				conv_ret = iconv(conv_id, &pin, &in_len, &pout, &out_len);
				if (-1 == conv_ret || 1024 - out_len <= 0 ||
					1024 - out_len > 1023) {
					continue;
				}
			}
			temp_len = strlen(temp_buff);
			if (temp_len < 2) {
				printf("[keyword_engine]: keyword %s is too short, will be "
					"ignored\n", temp_buff);
				continue;
			}
			if (0 != isalpha(temp_buff[0]) && 0 != isalpha(temp_buff[1])) {
				temp_buff[0] = tolower(temp_buff[0]);
				temp_buff[1] = tolower(temp_buff[1]);
				memcpy(&temp_index[0], temp_buff, sizeof(unsigned short));
				temp_buff[1] = toupper(temp_buff[1]);
				memcpy(&temp_index[1], temp_buff, sizeof(unsigned short));
				temp_buff[0] = toupper(temp_buff[0]);
				memcpy(&temp_index[2], temp_buff, sizeof(unsigned short));
				temp_buff[1] = tolower(temp_buff[1]);
				memcpy(&temp_index[3], temp_buff, sizeof(unsigned short));
			} else if (0 != isalpha(temp_buff[0])) {
				temp_buff[0] = tolower(temp_buff[0]);
				memcpy(&temp_index[0], temp_buff, sizeof(unsigned short));
				temp_buff[0] = toupper(temp_buff[0]);
				memcpy(&temp_index[1], temp_buff, sizeof(unsigned short));
				temp_index[2] = 0;
				temp_index[3] = 0;
			} else if (0 != isalpha(temp_buff[1])) {
				temp_index[0] = 0;
				temp_index[1] = 0;
				temp_buff[1] = tolower(temp_buff[1]);
				memcpy(&temp_index[2], temp_buff, sizeof(unsigned short));
				temp_buff[1] = toupper(temp_buff[1]);
				memcpy(&temp_index[3], temp_buff, sizeof(unsigned short));
			} else {
				memcpy(&temp_index[0], temp_buff, sizeof(unsigned short));
				temp_index[1] = 0;
				temp_index[2] = 0;
				temp_index[3] = 0;
			}
			for (k=0; k<4; k++) {
				if (0 == temp_index[k]) {
					continue;
				}
				if (NULL == temp_table[temp_index[k]]) {
					temp_table[temp_index[k]] = malloc(sizeof(SINGLE_LIST));
					if (NULL == temp_table[temp_index[k]]) {
						continue;
					}
					single_list_init(temp_table[temp_index[k]]);
				}
				pkeyword = (KEYWORD_NODE*)malloc(sizeof(KEYWORD_NODE));
				if (NULL == pkeyword) {
					continue;
				}
				pkeyword->node.pdata = pkeyword;
				pkeyword->length = temp_len - 1;
				memcpy(pkeyword->keyword, temp_buff + 2, temp_len - 1);
				single_list_append_as_tail(temp_table[temp_index[k]],
					&pkeyword->node);
			}
			
		}
		if (0 != i) {
			iconv_close(conv_id);
		}
		
		for (j=0; j<256*256; j++) {
			temp_len = 0;
			if (NULL != temp_table[j]) {
				for (pnode=single_list_get_head(temp_table[j]); pnode!=NULL;
					pnode=single_list_get_after(temp_table[j], pnode)) {
					pkeyword = (KEYWORD_NODE*)pnode->pdata;
					temp_len += pkeyword->length + sizeof(int) + 2;
				}
				pcharset->match_table[j] = malloc(temp_len + sizeof(int));
				if (NULL == pcharset->match_table[j]) {
					printf("[keyword_engine]: fail to allocate memory for "
						"match item in %s", pcharset->charset);
					continue;
				}
				ptr = pcharset->match_table[j];
				for (pnode=single_list_get_head(temp_table[j]); pnode!=NULL;
					pnode=single_list_get_after(temp_table[j], pnode)) {
					pkeyword = (KEYWORD_NODE*)pnode->pdata;
					*(int*)ptr = pkeyword->length;
					ptr += sizeof(int);
					memcpy(ptr, &j, 2);
					ptr += 2;
					memcpy(ptr, pkeyword->keyword, pkeyword->length);
					ptr += pkeyword->length;
				}
				*(int*)ptr = 0;
				while ((pnode = single_list_get_from_head(temp_table[j])) != NULL)
					free(pnode->pdata);
				single_list_free(temp_table[j]);
				free(temp_table[j]);
				temp_table[j] = NULL;
			}
		}
		single_list_append_as_tail(charset_list, &pcharset->node);
	}
	free(temp_table);
	list_file_free(pfile1);
	list_file_free(pfile2);
	return charset_list;
}

void keyword_engine_free(KEYWORD_ENGINE *pengine)
{
	int i;
	SINGLE_LIST_NODE *pnode;
	CHARSET_ITEM *pcharset;

	while ((pnode = single_list_get_from_head(pengine)) != NULL) {
		pcharset = (CHARSET_ITEM*)pnode->pdata;
		for (i=0; i<256*256; i++) {
			if (NULL != pcharset->match_table[i]) {
				free(pcharset->match_table[i]);
				pcharset->match_table[i] = 0;
			}
		}
		free(pcharset->match_table);
		free(pcharset);
	}
	single_list_free(pengine);
	free(pengine);
}

const char *keyword_engine_match(KEYWORD_ENGINE *pengine, const char *charset,
	const char *buff, int length)
{
	int i, offset;
	unsigned short temp_index;
	SINGLE_LIST_NODE *pnode;
	CHARSET_ITEM *pcharset;
	char **index_table;
	char *pkeywords_list;
	SINGLE_LIST *charset_list;
	
	charset_list = pengine;
	if (single_list_get_nodes_num(charset_list) == 0) {
		return NULL;
	}
	if (length < 2) {
		return NULL;
	}
	if (NULL == charset || '\0' == charset[0] ||
		0 == strcasecmp("default", charset)) {
		pnode = single_list_get_head(charset_list);
		pcharset = (CHARSET_ITEM*)pnode->pdata;
	} else {
		pcharset = NULL;
		for (pnode=single_list_get_head(charset_list); pnode!=NULL;
			pnode=single_list_get_after(charset_list, pnode)) {
			pcharset = (CHARSET_ITEM*)pnode->pdata;
			if (0 == strcasecmp(pcharset->charset, charset)) {
				break;
			}
			pcharset = NULL;
		}
		if (NULL == pcharset) {
			pnode = single_list_get_head(charset_list);
			pcharset = (CHARSET_ITEM*)pnode->pdata;
		}
	}
	index_table = pcharset->match_table;

	for (i=0; i<length-1; i++) {
		memcpy(&temp_index, buff + i, sizeof(unsigned short));
		pkeywords_list = index_table[temp_index];
		if (NULL == pkeywords_list) {
			continue;
		}
		while ((offset = *reinterpret_cast(const int *, pkeywords_list)) != 0) {
			if (0 == strncasecmp(pkeywords_list + sizeof(int) + 2,
				buff + i + 2, offset - 1)) {
				return pkeywords_list + sizeof(int);
			}
			pkeywords_list += sizeof(int) + offset + 2;
		}
	}
	return NULL;
}

