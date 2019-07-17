#include "codepage_lang.h"
#include "single_list.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


enum {
	RETRIEVE_NONE,
	RETRIEVE_TAG_FINDING,
	RETRIEVE_TAG_FOUND,
	RETRIEVE_TAG_END,
	RETRIEVE_VALUE_FINDING,
	RETRIEVE_VALUE_FOUND,
	RETRIEVE_VALUE_END,
	RETRIEVE_END
};

typedef struct _CODEPAGE_NODE {
	SINGLE_LIST_NODE node;
	uint32_t codepage;
	SINGLE_LIST lang_list;
} CODEPAGE_NODE;

typedef struct _LANG_NODE {
	SINGLE_LIST_NODE node;
	char *tag;
	char *value;
} LANG_NODE;


static char g_file_path[256];
static SINGLE_LIST g_cp_list;
static pthread_rwlock_t g_list_lock;


static void codepage_lang_unload_langlist(SINGLE_LIST *plist)
{
	LANG_NODE *plang;
	SINGLE_LIST_NODE *pnode;
	
	while (pnode=single_list_get_from_head(plist)) {
		plang = (LANG_NODE*)pnode->pdata;
		free(plang->tag);
		free(plang->value);
		free(plang);
	}
}

static BOOL codepage_lang_load_langlist(SINGLE_LIST *plist,
	char *digest_buff, int length)
{
	int val_len;
	int i, rstat;
	int last_pos;
	size_t temp_len;
	LANG_NODE *plang;
	char temp_tag[128];
	char temp_value[2048];
	char temp_value1[1024];
	
	
	last_pos = 0;
	rstat = RETRIEVE_NONE;
    for (i=0; i<length; i++) {
		switch (rstat) {
		case RETRIEVE_NONE:
			/* get the first "{" in the buffer */
			if ('{' == digest_buff[i]) {
				rstat = RETRIEVE_TAG_FINDING;
			} else if (' ' != digest_buff[i] && '\t' != digest_buff[i]) {
				return FALSE;
			}
			break;
		case RETRIEVE_TAG_FINDING:
			if ('"' == digest_buff[i]) {
				rstat = RETRIEVE_TAG_FOUND;
				last_pos = i + 1;
			} else if ('}' == digest_buff[i]) {
				rstat = RETRIEVE_END;
			} else if (' ' != digest_buff[i] && '\t' != digest_buff[i]) {
				return FALSE;
			}
			break;
		case RETRIEVE_TAG_FOUND:
			if ('"' == digest_buff[i] && '\\' != digest_buff[i - 1]) {
				if (i < last_pos || i - last_pos > 127) {
					return FALSE;
				}
				rstat = RETRIEVE_TAG_END;
				if (i - last_pos > sizeof(temp_tag)) {
					return FALSE;
				}
				memcpy(temp_tag, digest_buff + last_pos, i - last_pos);
				temp_tag[i - last_pos] = '\0';
			}
			break;
		case RETRIEVE_TAG_END:
			if (':' == digest_buff[i]) {
				rstat = RETRIEVE_VALUE_FINDING;
			} else if (' ' != digest_buff[i] && '\t' != digest_buff[i]) {
				return FALSE;
			}
			break;
		case RETRIEVE_VALUE_FINDING:
			if ('"' == digest_buff[i]) {
				rstat = RETRIEVE_VALUE_FOUND;
				last_pos = i + 1;
			} else if (' ' != digest_buff[i] && '\t' != digest_buff[i]) {
				return FALSE;
			}
			break;
		case RETRIEVE_VALUE_FOUND:
			if ('"' == digest_buff[i] && '\\' != digest_buff[i - 1]) {
				if (i < last_pos || i - last_pos >= sizeof(temp_value)) {
					return FALSE;
				}
				val_len = i - last_pos;
				memcpy(temp_value, digest_buff + last_pos, val_len);
				temp_value[val_len] = '\0';
				if (0 != decode64(temp_value, val_len,
					temp_value1, &temp_len)) {
					return FALSE;
				}
				plang = malloc(sizeof(LANG_NODE));
				if (NULL == plang) {
					return FALSE;
				}
				plang->node.pdata = plang;
				plang->tag = strdup(temp_tag);
				if (NULL == plang->tag) {
					free(plang);
					return FALSE;
				}
				plang->value = strdup(temp_value1);
				if (NULL == plang->value) {
					free(plang->tag);
					free(plang);
					return FALSE;
				}
				single_list_append_as_tail(plist, &plang->node);
				rstat = RETRIEVE_VALUE_END;
			}
			break;
		case RETRIEVE_VALUE_END:
			if (',' == digest_buff[i]) {
				rstat = RETRIEVE_TAG_FINDING;
			} else if ('}' == digest_buff[i]) {
				rstat = RETRIEVE_END;
			} else if (' ' != digest_buff[i] && '\t' != digest_buff[i]) {
				return FALSE;
			}
			break;
		case RETRIEVE_END:
			if (' ' != digest_buff[i] && '\t' != digest_buff[i] &&
				'\r' != digest_buff[i] && '\n' != digest_buff[i] &&
				'\0' != digest_buff[i]) {
				return FALSE;
			}
			break;
		}
	}
	
	if (RETRIEVE_END != rstat) {
		return FALSE;
	}
	
	return TRUE;
}

static BOOL codepage_lang_load_cplist(SINGLE_LIST *plist)
{
	int i;
	FILE *fp;
	char *ptr;
	size_t temp_len;
	char temp_buff[256];
	char temp_line[64*1024];
	CODEPAGE_NODE *pcodepage;
	
	
    fp = fopen(g_file_path, "r");
	if (NULL == fp) {
       return FALSE;
    }
	
    for (i=0; fgets(temp_line, sizeof(temp_line), fp); i++) {
		if ('\r' == temp_line[0] || '\n' == temp_line[0] ||
			'#' == temp_line[0]) {
		   /* skip empty line or comments */
		   continue;
		}

		ptr = strchr(temp_line, ':');
		if (NULL == ptr) {
			printf("[codepage_lang]: line %d format error in %s\n",
				i + 1, g_file_path);
			fclose(fp);
			return FALSE;
		}
		
		*ptr = '\0';
		ptr ++;
		temp_len = strlen(ptr);
		pcodepage = malloc(sizeof(CODEPAGE_NODE));
		if (NULL == pcodepage) {
			printf("[codepage_lang]: out of memory while loading file %s\n",
				g_file_path);
			fclose(fp);
			return FALSE;
		}
		
		pcodepage->node.pdata = pcodepage;
		pcodepage->codepage = atoi(temp_line);
		single_list_init(&pcodepage->lang_list);
		if (FALSE == codepage_lang_load_langlist(&pcodepage->lang_list,
			ptr, temp_len)) {
			codepage_lang_unload_langlist(&pcodepage->lang_list);
			single_list_free(&pcodepage->lang_list);
			free(pcodepage);
			fclose(fp);
			printf("[codepage_lang]: fail to parse line %d in %s\n",
				i  + 1, g_file_path);
			return FALSE;
		}
		single_list_append_as_tail(plist, &pcodepage->node);
	}
	fclose(fp);
	
	if (0 == single_list_get_nodes_num(plist)) {
		return FALSE;
	}
	return TRUE;
}

static void codepage_lang_unload_cplist(SINGLE_LIST *plist)
{
	SINGLE_LIST_NODE *pnode;
	CODEPAGE_NODE *pcodepage;
	
	while (pnode=single_list_get_from_head(plist)) {
		pcodepage = (CODEPAGE_NODE*)pnode->pdata;
		codepage_lang_unload_langlist(&pcodepage->lang_list);
		free(pcodepage);
	}
}

void codepage_lang_init(const char *path)
{
    strcpy(g_file_path, path);
	single_list_init(&g_cp_list);
	pthread_rwlock_init(&g_list_lock, NULL);
}

int codepage_lang_run()
{
    if (FALSE == codepage_lang_load_cplist(&g_cp_list)) {
		return -1;
	}
	return 0;
}

int codepage_lang_stop()
{
	codepage_lang_unload_cplist(&g_cp_list);
	return 0;
}

void codepage_lang_free()
{
	single_list_free(&g_cp_list);
	pthread_rwlock_destroy(&g_list_lock);
}

BOOL codepage_lang_get_lang(uint32_t codepage, const char *tag,
	char *value, int len)
{
	LANG_NODE *plang;
	SINGLE_LIST_NODE *pnode;
	CODEPAGE_NODE *pdefault;
	CODEPAGE_NODE *pcodepage;
	
	pdefault = NULL;
	pthread_rwlock_rdlock(&g_list_lock);
	for (pnode=single_list_get_head(&g_cp_list); NULL!=pnode;
		pnode=single_list_get_after(&g_cp_list, pnode)) {
		pcodepage = (CODEPAGE_NODE*)pnode->pdata;
		if (NULL == pdefault) {
			pdefault = pcodepage;
		}
		if (codepage == pcodepage->codepage) {
			break;
		}
	}
	if (NULL == pnode) {
		pcodepage = pdefault;
	}
	for (pnode=single_list_get_head(&pcodepage->lang_list); NULL!=pnode;
		pnode=single_list_get_after(&pcodepage->lang_list, pnode)) {
		plang = (LANG_NODE*)pnode->pdata;
		if (0 == strcasecmp(plang->tag, tag)) {
			strncpy(value, plang->value, len);
			pthread_rwlock_unlock(&g_list_lock);
			return TRUE;
		}
	}
	pthread_rwlock_unlock(&g_list_lock);
	return FALSE;
}

BOOL codepage_lang_reload()
{
	SINGLE_LIST cp_list;
	SINGLE_LIST temp_list;
	
	single_list_init(&cp_list);
	if (FALSE == codepage_lang_load_cplist(&cp_list)) {
		codepage_lang_unload_cplist(&cp_list);
		single_list_free(&cp_list);
		return FALSE;
	}
	pthread_rwlock_wrlock(&g_list_lock);
	temp_list = g_cp_list;
	g_cp_list = cp_list;
	pthread_rwlock_unlock(&g_list_lock);
	codepage_lang_unload_cplist(&temp_list);
	single_list_free(&temp_list);
	return TRUE;
}
