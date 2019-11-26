#include "translator.h"
#include "single_list.h"
#include "double_list.h"
#include "list_file.h"
#include "util.h"
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

typedef struct _LANGUAGE_NODE {
	SINGLE_LIST_NODE node;
	LIST_FILE *pfile;
	char language[16];
	char *pitem;
	int item_num;
} LANGUAGE_NODE;

typedef struct _LANGUAGE_ACCEPT {
	DOUBLE_LIST_NODE node;
	char language[32];
	float weight;
} LANGUAGE_ACCEPT;



static char g_translator_path[256];
static SINGLE_LIST g_translator_list;

void translator_init(const char *path)
{
	single_list_init(&g_translator_list);
	strcpy(g_translator_path, path);
}

int translator_run()
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	LIST_FILE *pfile;
	LANGUAGE_NODE *pnode;

	dirp = opendir(g_translator_path);
	if (NULL == dirp){
		printf("[translator]: fail to open directory %s\n", g_translator_path);
		return -1;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (strlen(direntp->d_name) > 15) {
			continue;
		}
		sprintf(temp_path, "%s/%s", g_translator_path, direntp->d_name);
		pfile = list_file_init(temp_path, "%s:128");
		if (NULL == pfile) {
			continue;
		}
		pnode = (LANGUAGE_NODE*)malloc(sizeof(LANGUAGE_NODE));
		if (NULL == pnode) {
			list_file_free(pfile);
			continue;
		}
		pnode->node.pdata = pnode;
		strcpy(pnode->language, direntp->d_name);
		pnode->pfile = pfile;
		pnode->pitem = list_file_get_list(pfile);
		pnode->item_num = list_file_get_item_num(pfile);
		single_list_append_as_tail(&g_translator_list, &pnode->node);
	}
	closedir(dirp);
	return 0;
}

void translator_stop(void)
{
	SINGLE_LIST_NODE *pnode;
	LANGUAGE_NODE *plang;

	while ((pnode = single_list_get_from_head(&g_translator_list)) != NULL) {
		plang = (LANGUAGE_NODE*)(pnode->pdata);
		list_file_free(plang->pfile);
		free(plang);
	}
}

void translator_free()
{
	single_list_free(&g_translator_list);
	g_translator_path[0] = '\0';

}

void translator_do(STATISTIC_ITEM *psmtp_item, int smtp_num,
	STATISTIC_ITEM *pdelivery_item, int delivery_num, const char *language)
{
	char *ptr;
	BOOL found_lang;
	SINGLE_LIST_NODE *pnode;
	int i, j, len;
	int until_pos;
	int boundary_pos;
	LANGUAGE_NODE *plang;
	DOUBLE_LIST accept_list;
	DOUBLE_LIST_NODE *pdnode;
	LANGUAGE_ACCEPT *paccept;

	found_lang = FALSE;
	double_list_init(&accept_list);
	len = strlen(language);
	paccept = malloc(sizeof(LANGUAGE_ACCEPT));
	if (NULL == paccept) {
		goto DEFAULT_FOUND;
	}
	paccept->node.pdata = paccept;
	paccept->weight = 1;

	for (i=0,j=0; i<=len; i++) {
		if (',' == language[i] || '\0' == language[i]) {
			if (j < 31) {
				paccept->language[j] = '\0';
			} else {
				paccept->language[31] = '\0';
			}
			ptr = strchr(paccept->language, ';');
			if (NULL != ptr) {
				*ptr = '\0';
				ptr = strcasestr(ptr + 1, "q=");
				if (NULL != ptr) {
					paccept->weight = strtof(ptr + 2, NULL);
				}
			}
			ltrim_string(paccept->language);
			rtrim_string(paccept->language);
			for (pdnode=double_list_get_head(&accept_list); NULL!=pdnode;
				pdnode=double_list_get_after(&accept_list, pdnode)) {
				if (((LANGUAGE_ACCEPT*)pdnode->pdata)->weight <
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
			paccept = malloc(sizeof(LANGUAGE_ACCEPT));
			if (NULL == paccept) {
				goto DEFAULT_FOUND;
			}
			paccept->node.pdata = paccept;
			paccept->weight = 1;
			j = 0;
		} else {
			if (j < 31) {
				paccept->language[j] = language[i];
			}
			j ++;
		}
	}


	for (pdnode=double_list_get_head(&accept_list); NULL!=pdnode;
		pdnode=double_list_get_after(&accept_list, pdnode)) {
		for (pnode=single_list_get_head(&g_translator_list); NULL!=pnode;
			pnode=single_list_get_after(&g_translator_list, pnode)) {
			plang = (LANGUAGE_NODE*)(pnode->pdata);
			if (0 == strcasecmp(plang->language,
				((LANGUAGE_ACCEPT*)pdnode->pdata)->language)) {
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
		return;
	}
	boundary_pos = -1;
	for (i=0; i<plang->item_num; i++) {
		if (0 == strcmp(plang->pitem + 128*i, "--------")) {
			boundary_pos = i;
		}
	}
	if (-1 == boundary_pos) {
		return;
	}
	until_pos = smtp_num > boundary_pos ? boundary_pos : smtp_num;
	for (i=0; i<until_pos; i++) {
		strcpy(psmtp_item[i].tag, plang->pitem + 128*i);
	}
	until_pos = delivery_num > (plang->item_num - boundary_pos - 1) ?
		plang->item_num - boundary_pos - 1 : delivery_num;
	for (i=0; i<until_pos; i++) {
		strcpy(pdelivery_item[i].tag, plang->pitem + (boundary_pos+ 1+i)*128);
	}
}

