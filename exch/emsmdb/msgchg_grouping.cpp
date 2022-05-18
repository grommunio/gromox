// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>
#include <libHX/string.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "msgchg_grouping.h"

using namespace std::string_literals;
using namespace gromox;

namespace {

struct TAG_NODE {
	DOUBLE_LIST_NODE node;
	uint16_t propid;
	uint16_t type;
	PROPERTY_NAME *ppropname;
};

struct msg_group_node {
	DOUBLE_LIST_NODE node;
	uint32_t index;
	DOUBLE_LIST tag_list;
};

struct INFO_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t group_id;
	DOUBLE_LIST group_list;
};

}

static std::string g_folder_path;
static DOUBLE_LIST g_info_list;

void msgchg_grouping_init(const char *sdlist)
{
	g_folder_path = sdlist;
	double_list_init(&g_info_list);
}

static msg_group_node *msgchg_grouping_create_group_node(uint32_t index)
{
	auto pgp_node = me_alloc<msg_group_node>();
	if (NULL == pgp_node) {
		return NULL;
	}
	pgp_node->node.pdata = pgp_node;
	pgp_node->index = index;
	double_list_init(&pgp_node->tag_list);
	return pgp_node;
}

static void msgchg_grouping_free_group_node(msg_group_node *pgp_node)
{
	TAG_NODE *ptag_node;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pgp_node->tag_list)) != nullptr) {
		ptag_node = (TAG_NODE*)pnode->pdata;
		if (0 == ptag_node->propid) {
			switch (ptag_node->ppropname->kind) {
			case MNID_STRING:
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
	auto pinfo_node = me_alloc<INFO_NODE>();
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
	
	while ((pnode = double_list_pop_front(&pinfo_node->group_list)) != nullptr)
		msgchg_grouping_free_group_node(static_cast<msg_group_node *>(pnode->pdata));
	double_list_free(&pinfo_node->group_list);
	free(pinfo_node);
}

static BOOL msgchg_grouping_append_group_list(INFO_NODE *pinfo_node, msg_group_node *pgp_node)
{
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&pinfo_node->group_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo_node->group_list, pnode)) {
		if (static_cast<msg_group_node *>(pnode->pdata)->index == pgp_node->index) {
			return FALSE;
		} else if (pgp_node->index < static_cast<msg_group_node *>(pnode->pdata)->index) {
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

static BOOL msgchg_grouping_verify_group_list(INFO_NODE *pinfo_node)
{
	size_t i;
	DOUBLE_LIST_NODE *pnode;
	
	for (i=0,pnode=double_list_get_head(&pinfo_node->group_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo_node->group_list, pnode),i++) {
		if (i != static_cast<msg_group_node *>(pnode->pdata)->index)
			return FALSE;
	}
	return TRUE;
}

static INFO_NODE *msgchg_grouping_load_gpinfo(const char *dir, const char *file_name)
{
	int index;
	char *ptoken;
	char *ptoken1;
	uint32_t proptag;
	TAG_NODE *ptag_node;
	INFO_NODE *pinfo_node;
	
	uint32_t group_id = strtoul(file_name + 2, nullptr, 16);
	if (0 == group_id || 0xFFFFFFFF == group_id) {
		printf("[exchange_emsmdb]: file name"
			" %s format error\n", file_name);
		return NULL;
	}
	std::string file_path;
	try {
		file_path = dir + "/"s + file_name;
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1493: ENOMEM\n");
		return nullptr;
	}
	auto pfile = list_file_initd(file_path.c_str(), nullptr, "%s:256");
	if (NULL == pfile) {
		printf("[exchange_emsmdb]: list_file_init %s: %s\n",
		       file_path.c_str(), strerror(errno));
		return NULL;
	}
	pinfo_node = msgchg_grouping_create_info_node(group_id);
	if (NULL == pinfo_node) {
		printf("[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
		return NULL;
	}
	auto line_num = pfile->get_size();
	auto pline = static_cast<char *>(pfile->get_list());
	index = -1;
	msg_group_node *pgp_node = nullptr;
	for (decltype(line_num) i = 0; i < line_num; ++i) {
		if (0 == strncasecmp(pline, "index:", 6)) {
			index = strtol(pline + 6, nullptr, 0);
			if (index < 0) {
				printf("[exchange_emsmdb]: index %d "
					"error in %s\n", index, file_path.c_str());
				return NULL;
			}
			pgp_node = msgchg_grouping_create_group_node(index);
			if (NULL == pgp_node) {
				printf("[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
				return NULL;
			}
			if (!msgchg_grouping_append_group_list(pinfo_node, pgp_node)) {
				msgchg_grouping_free_group_node(pgp_node);
				printf("[exchange_emsmdb]: index %d "
							"duplicated\n", index);
				return NULL;
			}
		} else if (0 == strncasecmp(pline, "0x", 2)) {
			if (-1 == index) {
				printf("[exchange_emsmdb]: file %s must "
					"begin with \"index:\"\n", file_path.c_str());
				return NULL;
			}
			proptag = strtol(pline + 2, NULL, 16);
			if (PROP_ID(proptag) == 0 || PROP_ID(proptag) >= 0x8000) {
				printf("[exchange_emsmdb]: fail to parse line"
					"\"%s\" in %s\n", pline, file_path.c_str());
				return NULL;
			}
			ptag_node = me_alloc<TAG_NODE>();
			if (NULL == ptag_node) {
				printf("[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
				return NULL;
			}
			ptag_node->node.pdata = ptag_node;
			ptag_node->propid = PROP_ID(proptag);
			ptag_node->type = PROP_TYPE(proptag);
			ptag_node->ppropname = NULL;
			double_list_append_as_tail(
				&pgp_node->tag_list, &ptag_node->node);
		} else if (0 == strncasecmp(pline, "GUID=", 5)) {
			if (-1 == index) {
				printf("[exchange_emsmdb]: file %s must "
					"begin with \"index:\"\n", file_path.c_str());
				return NULL;
			}
			ptoken = strchr(pline + 5, ',');
			if (NULL == ptoken) {
				printf("[exchange_emsmdb]: line "
					"\"%s\" format error\n", pline);
				return NULL;
			}
			*ptoken++ = '\0';
			ptoken1 = strchr(ptoken, ',');
			if (NULL == ptoken1) {
				printf("[exchange_emsmdb]: format"
					" error in \"%s\"\n", ptoken);
				return NULL;
			}
			*ptoken1++ = '\0';
			if (0 != strncasecmp(ptoken1, "TYPE=0x", 7)) {
				printf("[exchange_emsmdb]: format"
					" error in \"%s\"\n", ptoken1);
				return NULL;
			}
			ptag_node = me_alloc<TAG_NODE>();
			if (NULL == ptag_node) {
				printf("[exchange_emsmdb]: out of memory "
					"when loading property group info\n");
				return NULL;
			}
			ptag_node->node.pdata = ptag_node;
			ptag_node->propid = 0;
			ptag_node->type = strtol(ptoken1 + 7, NULL, 16);
			if (0 == ptag_node->type) {
				printf("[exchange_emsmdb]: format"
					"error in \"%s\"\n", ptoken1);
				return NULL;
			}
			ptag_node->ppropname = me_alloc<PROPERTY_NAME>();
			if (NULL == ptag_node->ppropname) {
				free(ptag_node);
				printf("[exchange_emsmdb]: out of memory when "
					"loading property group info\n");
				return NULL;
			}
			if (!ptag_node->ppropname->guid.from_str(pline + 5)) {
				free(ptag_node->ppropname);
				free(ptag_node);
				printf("[exchange_emsmdb]: guid string"
					" \"%s\" format error\n", pline + 5);
				return NULL;
			}
			if (0 == strncasecmp(ptoken, "LID=", 4)) {
				ptag_node->ppropname->kind = MNID_ID;
				ptag_node->ppropname->lid = strtol(ptoken + 4, nullptr, 0);
				if (ptag_node->ppropname->lid == 0) {
					printf("[exchange_emsmdb]: lid \"%s\"/%u error "
						"with guid \"%s\"\n", ptoken + 4,
						ptag_node->ppropname->lid, pline + 5);
					free(ptag_node->ppropname);
					free(ptag_node);
					return NULL;
				}
				ptag_node->ppropname->pname = NULL;
				double_list_append_as_tail(
					&pgp_node->tag_list, &ptag_node->node);
			} else if (0 == strncasecmp(ptoken, "NAME=", 5)) {
				ptag_node->ppropname->kind = MNID_STRING;
				HX_strrtrim(ptoken + 5);
				HX_strltrim(ptoken + 5);
				if ('\0' == ptoken[5]) {
					free(ptag_node->ppropname);
					free(ptag_node);
					printf("[exchange_emsmdb]: name empty "
						"with guid \"%s\"\n", pline + 5);
					return NULL;
				}
				ptag_node->ppropname->pname = strdup(ptoken + 5);
				if (NULL == ptag_node->ppropname->pname) {
					free(ptag_node->ppropname);
					free(ptag_node);
					printf("[exchange_emsmdb]: out of memory "
						"when loading property group info\n");
					return NULL;
				}
				ptag_node->ppropname->lid = 0;
				double_list_append_as_tail(
					&pgp_node->tag_list, &ptag_node->node);
			} else {
				free(ptag_node->ppropname);
				free(ptag_node);
				printf("[exchange_emsmdb]: type %s unknown\n", ptoken);
				return NULL;
			}
		}
		pline += 256;
	}
	if (!msgchg_grouping_verify_group_list(pinfo_node))
		printf("[exchange_emsmdb]: indexes should "
			"begin with 0 and be continuous\n");
	else if (msgchg_grouping_append_info_list(pinfo_node))
		return pinfo_node;
	else
		printf("[exchange_emsmdb]: duplicated "
			"group_id 0x%x\n", pinfo_node->group_id);
	return NULL;
}

int msgchg_grouping_run()
{
	struct dirent *direntp;
	auto dinfo = opendir_sd("msgchg_grouping", g_folder_path.c_str());
	if (dinfo.m_dir == nullptr) {
		printf("[exchange_emsmdb]: opendir \"%s\": %s\n",
		       dinfo.m_path.c_str(), strerror(errno));
		return -1;
	}
	while ((direntp = readdir(dinfo.m_dir.get())) != nullptr) {
		if (0 != strncasecmp(direntp->d_name, "0x", 2)) {
			continue;	
		}
		if (msgchg_grouping_load_gpinfo(dinfo.m_path.c_str(), direntp->d_name) == nullptr) {
			printf("[exchange_emsmdb]: Failed to load property group "
				"info definition file %s/%s: %s\n",
				dinfo.m_path.c_str(), direntp->d_name, strerror(errno));
			return -2;
		}
	}
	if (0 == double_list_get_nodes_num(&g_info_list)) {
		printf("[exchange_emsmdb]: no \"property"
			" group info\" found within directory \"%s\"\n",
			dinfo.m_path.c_str());
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

std::unique_ptr<property_groupinfo>
    msgchg_grouping_get_groupinfo(get_named_propid_t get_named_propid,
    void *stororlogin, uint32_t group_id) try
{
	uint16_t propid;
	uint32_t proptag;
	TAG_NODE *ptag_node;
	msg_group_node *pgp_node;
	INFO_NODE *pinfo_node;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	PROPTAG_ARRAY *pproptags;
	
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
	auto pinfo = std::make_unique<property_groupinfo>(group_id);
	if (NULL == pinfo) {
		return NULL;
	}
	for (pnode=double_list_get_head(&pinfo_node->group_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo_node->group_list, pnode)) {
		pgp_node = static_cast<msg_group_node *>(pnode->pdata);
		pproptags = proptag_array_init();
		for (pnode1=double_list_get_head(&pgp_node->tag_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pgp_node->tag_list, pnode1)) {
			ptag_node = (TAG_NODE*)pnode1->pdata;
			if (0 != ptag_node->propid) {
				proptag = PROP_TAG(ptag_node->type, ptag_node->propid);
			} else {
				if (!get_named_propid(stororlogin, TRUE,
				    ptag_node->ppropname, &propid) || propid == 0) {
					proptag_array_free(pproptags);
					return NULL;
				}
				proptag = PROP_TAG(ptag_node->type, propid);
			}
			if (!proptag_array_append(pproptags, proptag)) {
				proptag_array_free(pproptags);
				return NULL;
			}
		}
		if (!pinfo->append_internal(pproptags)) {
			proptag_array_free(pproptags);
			return NULL;
		}
	}
	return pinfo;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1632: ENOMEM\n");
	return nullptr;
}

void msgchg_grouping_stop()
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&g_info_list)) != nullptr)
		msgchg_grouping_free_info_node(static_cast<INFO_NODE *>(pnode->pdata));
}

void msgchg_grouping_free()
{
	double_list_free(&g_info_list);
}
