#include <errno.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include "msgchg_grouping.h"
#include "proptag_array.h"
#include "double_list.h"
#include "list_file.h"
#include "rop_util.h"
#include "guid.h"
#include "util.h"
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>


typedef struct _TAG_NODE {
	DOUBLE_LIST_NODE node;
	uint16_t propid;
	uint16_t type;
	PROPERTY_NAME *ppropname;
} TAG_NODE;

typedef struct _GROUP_NODE { 
	DOUBLE_LIST_NODE node;
	uint32_t index;
	DOUBLE_LIST tag_list;
} GROUP_NODE;

typedef struct _INFO_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t group_id;
	DOUBLE_LIST group_list;
} INFO_NODE;


static char g_folder_path[256];
static DOUBLE_LIST g_info_list;

void msgchg_grouping_init(const char *path)
{
	strcpy(g_folder_path, path);
	double_list_init(&g_info_list);
}

static GROUP_NODE* msgchg_grouping_create_group_node(uint32_t index)
{
	GROUP_NODE *pgp_node;
	
	pgp_node = malloc(sizeof(GROUP_NODE));
	if (NULL == pgp_node) {
		return NULL;
	}
	pgp_node->node.pdata = pgp_node;
	pgp_node->index = index;
	double_list_init(&pgp_node->tag_list);
	return pgp_node;
}

static void msgchg_grouping_free_group_node(GROUP_NODE *pgp_node)
{
	TAG_NODE *ptag_node;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_get_from_head(&pgp_node->tag_list)) != NULL) {
		ptag_node = (TAG_NODE*)pnode->pdata;
		if (0 == ptag_node->propid) {
			switch (ptag_node->ppropname->kind) {
			case KIND_LID:
				free(ptag_node->ppropname->plid);
				break;
			case KIND_NAME:
				free(ptag_node->ppropname->pname);
				break;
			}
			free(ptag_node->ppropname);
		}
		free(ptag_node);
	}
	double_list_free(&pgp_node->tag_list);
	free(pgp_node);
}

static INFO_NODE* msgchg_grouping_create_info_node(uint32_t group_id)
{
	INFO_NODE *pinfo_node;
	
	pinfo_node = malloc(sizeof(INFO_NODE));
	if (NULL == pinfo_node) {
		return NULL;
	}
	pinfo_node->node.pdata = pinfo_node;
	pinfo_node->group_id = group_id;
	double_list_init(&pinfo_node->group_list);
	return pinfo_node;
}

static void msgchg_grouping_free_info_node(INFO_NODE *pinfo_node)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_get_from_head(&pinfo_node->group_list)) != NULL)
		msgchg_grouping_free_group_node(pnode->pdata);
	double_list_free(&pinfo_node->group_list);
	free(pinfo_node);
}

static BOOL msgchg_grouping_append_group_list(
	INFO_NODE *pinfo_node, GROUP_NODE *pgp_node)
{
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&pinfo_node->group_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo_node->group_list, pnode)) {
		if (((GROUP_NODE*)pnode->pdata)->index == pgp_node->index) {
			return FALSE;
		} else if (pgp_node->index < ((GROUP_NODE*)pnode->pdata)->index) {
			double_list_insert_before(&pinfo_node->group_list,
									pnode, &pgp_node->node);
			return TRUE;
		}
	}
	double_list_append_as_tail(&pinfo_node->group_list, &pgp_node->node);
	return TRUE;
}

static BOOL msgchg_grouping_append_info_list(INFO_NODE *pinfo_node)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_info_list); NULL!=pnode;
		pnode=double_list_get_after(&g_info_list, pnode)) {
		if (((INFO_NODE*)pnode->pdata)->group_id == pinfo_node->group_id) {
			return FALSE;
		} else if (pinfo_node->group_id <
			((INFO_NODE*)pnode->pdata)->group_id) {
			double_list_insert_before(&g_info_list,
							pnode, &pinfo_node->node);
			return TRUE;
		}
	}
	double_list_append_as_tail(&g_info_list, &pinfo_node->node);
	return TRUE;
}

static BOOL msgchg_grouping_veryfy_group_list(INFO_NODE *pinfo_node)
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	
	for (i=0,pnode=double_list_get_head(&pinfo_node->group_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo_node->group_list, pnode),i++) {
		if (i != ((GROUP_NODE*)pnode->pdata)->index) {
			return FALSE;
		}
	}
	return TRUE;
}

static INFO_NODE* msgchg_grouping_load_gpinfo(char *file_name)
{
	int i;
	int index;
	char *pline;
	int line_num;
	char *ptoken;
	char *ptoken1;
	LIST_FILE *pfile;
	uint32_t proptag;
	uint32_t group_id;
	char file_path[256];
	TAG_NODE *ptag_node;
	GROUP_NODE *pgp_node;
	INFO_NODE *pinfo_node;
	
	strcpy(file_path, file_name + 2);
	ptoken = strchr(file_path, '.');
	if (NULL != ptoken) {
		*ptoken = '\0';
	}
	group_id = strtol(file_path, NULL, 16);
	if (0 == group_id || 0xFFFFFFFF == group_id) {
		printf("[[exchange_emsmdb]: file name"
			" %s format error\n", file_name);
		return NULL;
	}
	sprintf(file_path, "%s/%s", g_folder_path, file_name);
	pfile = list_file_init(file_path, "%s:256");
	if (NULL == pfile) {
		printf("[[exchange_emsmdb]: list_file_init %s: %s\n",
			file_path, strerror(errno));
		return NULL;
	}
	pinfo_node = msgchg_grouping_create_info_node(group_id);
	if (NULL == pinfo_node) {
		printf("[[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
		list_file_free(pfile);
		return NULL;
	}
	line_num = list_file_get_item_num(pfile);
	pline = list_file_get_list(pfile);
	index = -1;
	pgp_node = NULL;
	for (i=0; i<line_num; i++) {
		if (0 == strncasecmp(pline, "index:", 6)) {
			index = atoi(pline + 6);
			if (index < 0) {
				printf("[exchange_emsmdb]: index %d "
					"error in %s\n", index, file_path);
				list_file_free(pfile);
				return NULL;
			}
			pgp_node = msgchg_grouping_create_group_node(index);
			if (NULL == pgp_node) {
				printf("[[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
				list_file_free(pfile);
				return NULL;
			}
			if (FALSE == msgchg_grouping_append_group_list(
				pinfo_node, pgp_node)) {
				msgchg_grouping_free_group_node(pgp_node);
				printf("[[exchange_emsmdb]: index %d "
							"duplicated\n", index);
				list_file_free(pfile);
				return NULL;
			}
		} else if (0 == strncasecmp(pline, "0x", 2)) {
			if (-1 == index) {
				printf("[exchange_emsmdb]: file %s must "
					"begin with \"index:\"\n", file_path);
				list_file_free(pfile);
				return NULL;
			}
			proptag = strtol(pline + 2, NULL, 16);
			if ((proptag >> 16) == 0 || (proptag >> 16) >= 0x8000) {
				printf("[exchange_emsmdb]: fail to parse line"
					"\"%s\" in %s\n", pline, file_path);
				list_file_free(pfile);
				return NULL;
			}
			ptag_node = malloc(sizeof(TAG_NODE));
			if (NULL == ptag_node) {
				printf("[[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
				list_file_free(pfile);
				return NULL;
			}
			ptag_node->node.pdata = ptag_node;
			ptag_node->propid = proptag >> 16;
			ptag_node->type = proptag & 0xFFFF;
			ptag_node->ppropname = NULL;
			double_list_append_as_tail(
				&pgp_node->tag_list, &ptag_node->node);
		} else if (0 == strncasecmp(pline, "GUID=", 5)) {
			if (-1 == index) {
				printf("[exchange_emsmdb]: file %s must "
					"begin with \"index:\"\n", file_path);
				list_file_free(pfile);
				return NULL;
			}
			ptoken = strchr(pline + 5, ',');
			if (NULL == ptoken) {
				printf("[exchange_emsmdb]: line "
					"\"%s\" format error\n", pline);
				list_file_free(pfile);
				return NULL;
			}
			*ptoken = '\0';
			ptoken ++;
			ptoken1 = strchr(ptoken, ',');
			if (NULL == ptoken1) {
				printf("[exchange_emsmdb]: format"
					" error in \"%s\"\n", ptoken);
				list_file_free(pfile);
				return NULL;
			}
			*ptoken1 = '\0';
			ptoken1 ++;
			if (0 != strncasecmp(ptoken1, "TYPE=0x", 7)) {
				printf("[exchange_emsmdb]: format"
					" error in \"%s\"\n", ptoken1);
				list_file_free(pfile);
				return NULL;
			}
			ptag_node = malloc(sizeof(TAG_NODE));
			if (NULL == ptag_node) {
				printf("[[exchange_emsmdb]: out of memory "
					"when loading property group info\n");
				list_file_free(pfile);
				return NULL;
			}
			ptag_node->node.pdata = ptag_node;
			ptag_node->propid = 0;
			ptag_node->type = strtol(ptoken1 + 7, NULL, 16);
			if (0 == ptag_node->type) {
				printf("[exchange_emsmdb]: format"
					"error in \"%s\"\n", ptoken1);
				list_file_free(pfile);
				return NULL;
			}
			ptag_node->ppropname = malloc(sizeof(PROPERTY_NAME));
			if (NULL == ptag_node->ppropname) {
				free(ptag_node);
				printf("[[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
				list_file_free(pfile);
				return NULL;
			}
			if (FALSE == guid_from_string(
				&ptag_node->ppropname->guid, pline + 5)) {
				free(ptag_node->ppropname);
				free(ptag_node);
				printf("[exchange_emsmdb]: guid string"
					" \"%s\" format error\n", pline + 5);
				list_file_free(pfile);
				return NULL;
			}
			if (0 == strncasecmp(ptoken, "LID=", 4)) {
				ptag_node->ppropname->kind = KIND_LID;
				ptag_node->ppropname->plid = malloc(sizeof(uint32_t));
				if (NULL == ptag_node->ppropname->plid) {
					free(ptag_node->ppropname);
					free(ptag_node);
					printf("[[exchange_emsmdb]: out of memory "
						"when loading property group info\n");
					list_file_free(pfile);
					return NULL;
				}
				*ptag_node->ppropname->plid = atoi(ptoken + 4);
				if (0 == *ptag_node->ppropname->plid) {
					free(ptag_node->ppropname);
					free(ptag_node);
					printf("[exchange_emsmdb]: lid %u error "
						"with guid \"%s\"\n",
						*ptag_node->ppropname->plid, pline + 5);
					list_file_free(pfile);
					return NULL;
				}
				ptag_node->ppropname->pname = NULL;
				double_list_append_as_tail(
					&pgp_node->tag_list, &ptag_node->node);
			} else if (0 == strncasecmp(ptoken, "NAME=", 5)) {
				ptag_node->ppropname->kind = KIND_NAME;
				HX_strrtrim(ptoken + 5);
				HX_strltrim(ptoken + 5);
				if ('\0' == ptoken[5]) {
					free(ptag_node->ppropname);
					free(ptag_node);
					printf("[exchange_emsmdb]: name empty "
						"with guid \"%s\"\n", pline + 5);
					list_file_free(pfile);
					return NULL;
				}
				ptag_node->ppropname->pname = strdup(ptoken + 5);
				if (NULL == ptag_node->ppropname->pname) {
					free(ptag_node->ppropname);
					free(ptag_node);
					printf("[[exchange_emsmdb]: out of memory "
						"when loading property group info\n");
					list_file_free(pfile);
					return NULL;
				}
				ptag_node->ppropname->plid = NULL;
				double_list_append_as_tail(
					&pgp_node->tag_list, &ptag_node->node);
			} else {
				free(ptag_node->ppropname);
				free(ptag_node);
				printf("[exchange_emsmdb]: type %s unknown\n", ptoken);
				list_file_free(pfile);
				return NULL;
			}
		}
		pline += 256;
	}
	list_file_free(pfile);
	if (TRUE == msgchg_grouping_veryfy_group_list(pinfo_node)) {
		if (TRUE == msgchg_grouping_append_info_list(pinfo_node)) {
			return pinfo_node;
		} else {
			printf("[exchange_emsmdb]: duplicated "
				"group_id 0x%x\n", pinfo_node->group_id);
		}
	} else {
		printf("[exchange_emsmdb]: indexes shoud "
			"begin with 0 and be continuous\n");
	}
	return NULL;
}

int msgchg_grouping_run()
{
	DIR *dirp;
	struct dirent *direntp;
	
	dirp = opendir(g_folder_path);
	if (NULL == dirp) {
		printf("[exchange_emsmdb]: failed to open directory %s for "
			"loading \"property group info\": %s\n", g_folder_path, strerror(errno));
		return -1;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 != strncasecmp(direntp->d_name, "0x", 2)) {
			continue;	
		}
		if (FALSE == msgchg_grouping_load_gpinfo(direntp->d_name)) {
			printf("[exchange_emsmdb]: fail to load property group "
				"info definition file %s under directory %s\n",
				direntp->d_name, g_folder_path);
			closedir(dirp);
			return -2;
		}
	}
	closedir(dirp);
	if (0 == double_list_get_nodes_num(&g_info_list)) {
		printf("[exchange_emsmdb]: there's no \"property"
			" group info\" under directory %s\n", g_folder_path);
		return -3;
	}
	return 0;
}

uint32_t msgchg_grouping_get_last_group_id()
{
	DOUBLE_LIST_NODE *pnode;
	
	pnode = double_list_get_tail(&g_info_list);
	return ((INFO_NODE*)pnode->pdata)->group_id;
}

PROPERTY_GROUPINFO* msgchg_grouping_get_groupinfo(
	STORE_OBJECT *pstore, uint32_t group_id)
{
	uint16_t propid;
	uint32_t proptag;
	TAG_NODE *ptag_node;
	GROUP_NODE *pgp_node;
	INFO_NODE *pinfo_node;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	PROPTAG_ARRAY *pproptags;
	PROPERTY_GROUPINFO *pinfo;
	
	for (pnode=double_list_get_head(&g_info_list); NULL!=pnode;
		pnode=double_list_get_after(&g_info_list, pnode)) {
		pinfo_node = (INFO_NODE*)pnode->pdata;
		if (group_id == pinfo_node->group_id) {
			break;
		}
	}
	if (NULL == pnode) {
		return NULL;
	}
	pinfo = property_groupinfo_init(group_id);
	if (NULL == pinfo) {
		return NULL;
	}
	for (pnode=double_list_get_head(&pinfo_node->group_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo_node->group_list, pnode)) {
		pgp_node = (GROUP_NODE*)pnode->pdata;
		pproptags = proptag_array_init();
		for (pnode1=double_list_get_head(&pgp_node->tag_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pgp_node->tag_list, pnode1)) {
			ptag_node = (TAG_NODE*)pnode1->pdata;
			if (0 != ptag_node->propid) {
				proptag = ptag_node->propid;
			} else {
				if (FALSE == store_object_get_named_propid(pstore, TRUE,
					ptag_node->ppropname, &propid) || 0 == propid) {
					property_groupinfo_free(pinfo);
					proptag_array_free(pproptags);
					return NULL;
				}
				proptag = propid;
			}
			proptag <<= 16;
			proptag |= ptag_node->type;
			if (FALSE == proptag_array_append(pproptags, proptag)) {
				property_groupinfo_free(pinfo);
				proptag_array_free(pproptags);
				return NULL;
			}
		}
		if (FALSE == property_groupinfo_append_internal(
			pinfo, pproptags)) {
			property_groupinfo_free(pinfo);
			proptag_array_free(pproptags);
			return NULL;
		}
	}
	return pinfo;
}

int msgchg_grouping_stop()
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_get_from_head(&g_info_list)) != NULL)
		msgchg_grouping_free_info_node(pnode->pdata);
	return 0;
}

void msgchg_grouping_free()
{
	double_list_free(&g_info_list);
}
