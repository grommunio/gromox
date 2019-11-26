#include <errno.h>
#include <libHX/string.h>
#include "lang_resource.h"
#include "list_file.h"
#include "util.h"
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#define DEFAULT_LANGUAGE		"en"

typedef struct _LANG_ACCEPT {
	DOUBLE_LIST_NODE node;
	char language[32];
	float weight;
} LANG_ACCEPT;

static const char* g_replace_table[] = {"zh-hans-cn", "zh-cn"};

static const char* lang_resource_replace(const char *language)
{
	int i;

	for (i=0; i<sizeof(g_replace_table)/sizeof(const char*); i+=2) {
		if (0 == strcasecmp(g_replace_table[i], language)) {
			return g_replace_table[i + 1];
		}
	}

	return language;
}

LANG_RESOURCE* lang_resource_init(const char *path)
{
	DIR *dirp;
	char *pitem;
	char *pvalue;
	int i, item_num;
	LIST_FILE *pfile;
	LANG_NODE *pnode;
	char temp_path[256];
	struct dirent *direntp;
	LANG_RESOURCE *presource;

	dirp = opendir(path);
	if (NULL == dirp){
		fprintf(stderr, "[lang_resource]: opendir %s: %s\n", path, strerror(errno));
		return NULL;
	}
	presource = (LANG_RESOURCE*)malloc(sizeof(LANG_RESOURCE));
	if (NULL == presource) {
		return NULL;
	}
	single_list_init(&presource->resource_list);
	presource->pdefault_lang = NULL;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (strlen(direntp->d_name) >= 32) {
			continue;
		}
		sprintf(temp_path, "%s/%s", path, direntp->d_name);
		pfile = list_file_init(temp_path, "%s:32%s:1024");
		if (NULL == pfile) {
			continue;
		}
		pnode = (LANG_NODE*)malloc(sizeof(LANG_NODE));
		if (NULL == pnode) {
			list_file_free(pfile);
			continue;
		}
		pnode->node.pdata = pnode;
		strcpy(pnode->language, direntp->d_name);
		pnode->parray = assoc_array_init(sizeof(char**));
		if (NULL == pnode->parray) {
			list_file_free(pfile);
			free(pnode);
			continue;
		}
		pitem = list_file_get_list(pfile);
		item_num = list_file_get_item_num(pfile);
		for (i=0; i<item_num; i++) {
			pvalue = strdup(pitem + (1024+32)*i + 32);
			if (FALSE == assoc_array_assign(pnode->parray,
				pitem + (1024+32)*i, &pvalue)) {
				free(pvalue);	
			}
		}
		list_file_free(pfile);
		
		single_list_append_as_tail(&presource->resource_list, &pnode->node);
		if (0 == strcasecmp(pnode->language, DEFAULT_LANGUAGE)) {
			presource->pdefault_lang = pnode;
		}
	}
	closedir(dirp);
	if (NULL == presource->pdefault_lang) {
		lang_resource_free(presource);
		return NULL;
	}
	return presource;
}

static void lang_resource_enum(const char *key, char **ppvalue)
{
	free(*ppvalue);
}

void lang_resource_free(LANG_RESOURCE *presource)
{
	LANG_NODE *plang;
	SINGLE_LIST_NODE *pnode;

	while ((pnode = single_list_get_from_head(&presource->resource_list)) != NULL) {
		plang = (LANG_NODE*)(pnode->pdata);
		if (NULL != plang->parray) {
			assoc_array_foreach(plang->parray,
				(ASSOC_ARRAY_ENUM)lang_resource_enum);
			assoc_array_free(plang->parray);
		}
		free(plang);
	}
	free(presource);
}


const char* lang_resource_get(LANG_RESOURCE *presource, const char *tag,
	const char *language)
{
	char *ptr;
	int i, j, len;
	char **ppvalue;
	BOOL found_lang;
	int temp_weight;
	LANG_NODE *plang;
	char temp_lang[32];
	const char *replang;
	LANG_ACCEPT *paccept;
	SINGLE_LIST_NODE *pnode;
	DOUBLE_LIST accept_list;
	DOUBLE_LIST_NODE *pdnode;
	static const char fake_string[] = "unknown resource item";

	found_lang = FALSE;
	double_list_init(&accept_list);
	len = strlen(language);
	temp_weight = 1;
	for (i=0,j=0; i<=len; i++) {
		if (',' == language[i] || '\0' == language[i]) {
			if (j < 31) {
				temp_lang[j] = '\0';
			} else {
				temp_lang[31] = '\0';
			}
			ptr = strchr(temp_lang, ';');
			if (NULL != ptr) {
				*ptr = '\0';
				ptr = strcasestr(ptr + 1, "q=");
				if (NULL != ptr) {
					temp_weight = strtof(ptr + 2, NULL);
				}
			}
			HX_strrtrim(temp_lang);
			HX_strltrim(temp_lang);
			replang = lang_resource_replace(temp_lang);
			paccept = malloc(sizeof(LANG_ACCEPT));
			if (NULL == paccept) {
				goto DEFAULT_FOUND;
			}
			paccept->node.pdata = paccept;
			strcpy(paccept->language, replang);
			paccept->weight = temp_weight;
			for (pdnode=double_list_get_head(&accept_list); NULL!=pdnode;
				pdnode=double_list_get_after(&accept_list, pdnode)) {
				if (((LANG_ACCEPT*)pdnode->pdata)->weight <
					paccept->weight) {
					break;
				}
			}
			if (NULL == pdnode) {
				double_list_append_as_tail(&accept_list, &paccept->node);
			} else {
				double_list_insert_before(&accept_list, pdnode,
					&paccept->node);
			}
			temp_weight = 1;
			j = 0;
		} else {
			if (j < 31) {
				temp_lang[j] = language[i];
			}
			j ++;
		}
	}


	for (pdnode=double_list_get_head(&accept_list); NULL!=pdnode;
		pdnode=double_list_get_after(&accept_list, pdnode)) {
		for (pnode=single_list_get_head(&presource->resource_list); NULL!=pnode;
			pnode=single_list_get_after(&presource->resource_list, pnode)) {
			plang = (LANG_NODE*)(pnode->pdata);
			if (0 == strcasecmp(plang->language,
				((LANG_ACCEPT*)pdnode->pdata)->language)) {
				found_lang = TRUE;
				break;
			}
		}
		if (TRUE == found_lang) {
			break;
		}
	}

DEFAULT_FOUND:
	while ((pdnode = double_list_get_from_head(&accept_list)) != NULL)
		free(pdnode->pdata);
	double_list_free(&accept_list);

	if (FALSE == found_lang) {
		plang = presource->pdefault_lang;
	}
	
	ppvalue = (char**)assoc_array_get_by_key(plang->parray, tag);
	if (NULL == ppvalue) {
		return fake_string;
	}
	return *ppvalue;
	
}

