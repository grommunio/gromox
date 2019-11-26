#include <libHX/defs.h>
#include "anonymous_keyword.h"
#include "single_list.h"
#include "list_file.h"
#include <stdio.h>
#include <iconv.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

typedef struct _CHARSET_ITEM {
	SINGLE_LIST_NODE node;
	char charset[32];
	char **match_table;
} CHARSET_ITEM;

typedef struct _KEYWORD_NODE {
	SINGLE_LIST_NODE node;
	int length;
	int group_index;
	char keyword[1024];
} KEYWORD_NODE;

typedef struct _GROUP_ITEM {
	char name[32];
	int times;
} GROUP_ITEM;

static int g_group_num;
static GROUP_ITEM *g_group_array;
static char g_charset_path[256];
static char g_list_path[256];
static SINGLE_LIST *g_keyword_list;
static pthread_rwlock_t g_list_lock;

static void anonymous_keyword_destroy_engine(SINGLE_LIST *pengine);

void anonymous_keyword_init(const char *charset_path, const char *list_path)
{
	g_group_num = 0;
	g_group_array = NULL;
	g_keyword_list = NULL;
	strcpy(g_charset_path, charset_path);
	strcpy(g_list_path, list_path);
	pthread_rwlock_init(&g_list_lock, NULL);
}

int anonymous_keyword_run()
{
	if (FALSE == anonymous_keyword_refresh()) {
		return -1;
	}
	return 0;
}

int anonymous_keyword_stop()
{
	if (NULL != g_keyword_list) {
		anonymous_keyword_destroy_engine(g_keyword_list);
		g_keyword_list = NULL;
	}
	if (NULL != g_group_array) {
		free(g_group_array);
		g_group_array = NULL;
	}
	return 0;
}

void anonymous_keyword_free()
{
	g_group_num = 0;
	g_group_array = NULL;
	g_keyword_list = NULL;
	g_charset_path[0] = '\0';
	g_list_path[0] = '\0';
	pthread_rwlock_destroy(&g_list_lock);
}

BOOL anonymous_keyword_refresh()
{
	int conv_ret;
	int i, j, k, temp_len;
	size_t in_len, out_len;
	int item_num1, item_num2;
	int group_num, group_index;
	GROUP_ITEM *group_array;
	GROUP_ITEM *temp_group;
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
	SINGLE_LIST *charset_list, *temp_list;
	
	charset_list = malloc(sizeof(SINGLE_LIST));
	if (NULL == charset_list) {
		printf("[anonymous_keyword]: fail to allocate memory for "
			"keyword engine\n");
		return FALSE;
	}
	single_list_init(charset_list);
	pfile1 = list_file_init(g_charset_path, "%s:32");
	if (NULL == pfile1) {
		free(charset_list);
		printf("[anonymous_keyword]: fail to init charset list file\n");
		return FALSE;
	}
	pfile2 = list_file_init(g_list_path, "%s:256");
	if (NULL == pfile2) {
		printf("[anonymous_keyword]: fail to init keyword list file\n");
		free(charset_list);
		list_file_free(pfile1);
		return FALSE;
	}
	pitem1 = list_file_get_list(pfile1);
	item_num1 = list_file_get_item_num(pfile1);
	pitem2 = list_file_get_list(pfile2);
	item_num2 = list_file_get_item_num(pfile2);
	temp_table = (SINGLE_LIST**)malloc(256*256*sizeof(SINGLE_LIST*));
	if (NULL == temp_table) {
		printf("[anonymous_keyword]: fail to allocate memory for "
			"temporary index table\n");
		free(charset_list);
		list_file_free(pfile1);
		list_file_free(pfile2);
		return FALSE;
	}
	memset(temp_table, 0, sizeof(SINGLE_LIST*)*256*256);
	if (item_num2 != 0 &&
		0 != strncmp("--------", pitem2, 8)) {
		printf("[anonymous_keyword]: first line of %s should be group name\n",
			g_list_path);
		free(charset_list);
		list_file_free(pfile1);
		list_file_free(pfile2);
		free(temp_table);
		return FALSE;
	}
	for (group_num=0, i=0; i<item_num2; i++) {
		if (0 == strncmp("--------", pitem2 + 256*i, 8)) {
			group_num ++;
		}
	}
	group_array = malloc(group_num*sizeof(GROUP_ITEM));
	if (NULL == group_array) {
		printf("[anonymous_keyword]: fail to allocate memory for "
			"group array\n");
		free(charset_list);
		list_file_free(pfile1);
		list_file_free(pfile2);
		free(temp_table);
		return FALSE;	
	}
	for (i=0; i<group_num; i++) {
		sprintf(group_array[i].name, "group%d", i);
		group_array[i].times = 0;
	}
	for (group_index=0, i=0; i<item_num2; i++) {
		if (0 == strncmp("--------", pitem2 + 256*i, 8)) {
			if (strlen(pitem2 + 256*i) > 8 && strlen(pitem2 + 256*i) < 32) {
				strcpy(group_array[group_index].name, pitem2 + 256*i + 8);
			}
			group_index ++;
		}
	}
	
	for (i=0; i<item_num1; i++) {
		pcharset = (CHARSET_ITEM*)malloc(sizeof(CHARSET_ITEM));
		if (NULL == pcharset) {
			printf("[anonymous_keyword]: fail to allocate charset node for %s\n",
				pitem1 + 32*i);
			continue;
		}
		pcharset->node.pdata = pcharset;
		strcpy(pcharset->charset, pitem1 + 32*i);
		pcharset->match_table = malloc(256*256*sizeof(void*));
		if (NULL == pcharset->match_table) {
			printf("[anonymous_keyword]: fail to allocate match index table "
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
		for (group_index=-1, j=0; j<item_num2; j++) {
			if (0 == strncmp("--------", pitem2 + 256*j, 8)) {
				group_index ++;
				continue;
			}
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
					printf("[anonymous_keyword]: fail to convert %s from \"%s\" "
						"to \"%s\"!\n", pitem2 + 256*j, pitem1, pitem1 + 32*i);
				}
			}
			temp_len = strlen(temp_buff);
			if (temp_len < 2) {
				printf("[anonymous_keyword]: keyword %s is too short, will be "
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
				pkeyword->group_index = group_index;
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
					temp_len += pkeyword->length + 2*sizeof(int) + 2;
				}
				pcharset->match_table[j] = malloc(temp_len + sizeof(int));
				if (NULL == pcharset->match_table[j]) {
					printf("[anonymous_keyword]: fail to allocate memory for "
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
					*(int*)ptr = pkeyword->group_index;
					ptr += sizeof(int);
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
	if (NULL != g_keyword_list) {
		pthread_rwlock_wrlock(&g_list_lock);
		for (i=0; i<group_num; i++) {
			for (j=0; j<g_group_num; j++) {
				if (0 == strcasecmp(g_group_array[j].name,
					group_array[i].name)) {
					group_array[i].times = g_group_array[j].times;
					break;
				}
			}
		}
		temp_list = g_keyword_list;
		g_keyword_list = charset_list;
		temp_group = g_group_array;
		g_group_array = group_array;
		g_group_num = group_num;
		pthread_rwlock_unlock(&g_list_lock);
		free(temp_group);
		anonymous_keyword_destroy_engine(temp_list);
	} else {
		g_keyword_list = charset_list;
		g_group_array = group_array;
		g_group_num = group_num;
	}
	return TRUE;
}

static void anonymous_keyword_destroy_engine(SINGLE_LIST *pengine)
{
	int i;
	SINGLE_LIST_NODE *pnode;
	CHARSET_ITEM *pcharset;

	while ((pnode = single_list_get_from_head(pengine)) != NULL) {
		pcharset = (CHARSET_ITEM*)pnode->pdata;
		for (i=0; i<256*256; i++) {
			if (NULL != pcharset->match_table[i]) {
				free(pcharset->match_table[i]);
				pcharset->match_table[i] = NULL;
			}
		}
		free(pcharset->match_table);
		free(pcharset);
	}
	single_list_free(pengine);
	free(pengine);
}

BOOL anonymous_keyword_match(const char *charset, const char *buff,
	int length, char *keyword, char *group)
{
	int i, offset;
	unsigned short temp_index;
	SINGLE_LIST_NODE *pnode;
	CHARSET_ITEM *pcharset;
	char **index_table;
	char *pkeywords_list;
	
	if (length < 2) {
		return FALSE;
	}
	pthread_rwlock_rdlock(&g_list_lock);
	if (single_list_get_nodes_num(g_keyword_list) == 0) {
		pthread_rwlock_unlock(&g_list_lock);
		return FALSE;
	}
	
	if (NULL == charset || '\0' == charset[0] ||
		0 == strcasecmp("default", charset)) {
		pnode = single_list_get_head(g_keyword_list);
		pcharset = (CHARSET_ITEM*)pnode->pdata;
	} else {
		pcharset = NULL;
		for (pnode=single_list_get_head(g_keyword_list); pnode!=NULL;
			pnode=single_list_get_after(g_keyword_list, pnode)) {
			pcharset = (CHARSET_ITEM*)pnode->pdata;
			if (0 == strcasecmp(pcharset->charset, charset)) {
				break;
			}
			pcharset = NULL;
		}
		if (NULL == pcharset) {
			pthread_rwlock_unlock(&g_list_lock);
			return FALSE;
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
				g_group_array[*(int*)(pkeywords_list + sizeof(int) + 2 + 
					offset)].times ++;
				strcpy(keyword, pkeywords_list + sizeof(int));
				strcpy(group, g_group_array[*(int*)(pkeywords_list + 
					sizeof(int) + 2 + offset)].name);
				pthread_rwlock_unlock(&g_list_lock);
				return TRUE;
			}
			pkeywords_list += 2*sizeof(int) + offset + 2;
		}
	}
	pthread_rwlock_unlock(&g_list_lock);
	return FALSE;
}

void anonymous_keyword_enum_group(ENUM_GROUP enum_func)
{
	int i;
	
	pthread_rwlock_rdlock(&g_list_lock);
	for (i=0; i<g_group_num; i++) {
		enum_func(g_group_array[i].name, g_group_array[i].times);
	}
	pthread_rwlock_unlock(&g_list_lock);
}

void anonymous_keyword_clear_statistic()
{
	int i;

	pthread_rwlock_rdlock(&g_list_lock);
	for (i=0; i<g_group_num; i++) {
		g_group_array[i].times = 0;
	}
	pthread_rwlock_unlock(&g_list_lock);
}

