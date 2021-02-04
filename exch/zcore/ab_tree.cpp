// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <new>
#include <string>
#include <utility>
#include <vector>
#include <cstdint>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include "ab_tree.h"
#include <gromox/ext_buffer.hpp>
#include "common_util.h"
#include "zarafa_server.h"
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include "system_services.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <unistd.h>
#include <csignal>
#include <fcntl.h>
#include <pthread.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/md5.h>
#include "../mysql_adaptor/mysql_adaptor.h"

#define EPOCH_DIFF 							11644473600LL

#define DTE_FLAG_ACL_CAPABLE				0x40000000

#define ADDRESS_TYPE_NORMAL					0
#define ADDRESS_TYPE_ALIAS 1 /* historic; no longer used in db schema */
#define ADDRESS_TYPE_MLIST					2
/* composed value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_ROOM */
#define ADDRESS_TYPE_ROOM					4
/* composed value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_EQUIPMENT */
#define ADDRESS_TYPE_EQUIPMENT				5

#define BASE_STATUS_CONSTRUCTING			0
#define BASE_STATUS_LIVING					1
#define BASE_STATUS_DESTRUCTING				2

#define MLIST_TYPE_NORMAL 					0
#define MLIST_TYPE_GROUP					1
#define MLIST_TYPE_DOMAIN					2
#define MLIST_TYPE_CLASS					3

/* 0x00 ~ 0x10 minid reserved by nspi */
#define MINID_TYPE_RESERVED					7

#define HGROWING_SIZE						100

/* 
	PERSON: username, real_name, title, memo, cell, tel,
			nickname, homeaddress, create_day, maildir
	ROOM: title
	EQUIPMENT: title
	MLIST: listname, list_type(int), list_privilege(int)
	DOMAIN: domainname, title, address
	GROUP: groupname, title
	CLASS: classname
*/

struct AB_NODE {
	SIMPLE_TREE_NODE node;
	uint8_t node_type;
	uint32_t minid;
	void *d_info;
	int id;
};

struct GUID_ENUM {
	int item_id;
	int node_type;
	uint64_t dgt;
	AB_NODE *pabnode;
};

struct SORT_ITEM {
	SIMPLE_TREE_NODE *pnode;
	char *string;
};

static int g_base_size;
static int g_file_blocks;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static int g_cache_interval;
static char g_org_name[256];
static INT_HASH_TABLE *g_base_hash;
static pthread_mutex_t g_base_lock;
static LIB_BUFFER *g_file_allocator;
static const uint8_t g_guid_nspi[] = {0xDC, 0xA7, 0x40, 0xC8,
									   0xC0, 0x42, 0x10, 0x1A,
									   0xB4, 0xB9, 0x08, 0x00,
									   0x2B, 0x2F, 0xE1, 0x82};

static void* scan_work_func(void *param);

static void ab_tree_get_display_name(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, char *str_dname);
static void ab_tree_get_user_info(SIMPLE_TREE_NODE *pnode, int type, char *value, size_t vsize);

uint32_t ab_tree_make_minid(uint8_t type, int value)
{
	uint32_t minid;
	
	if (MINID_TYPE_ADDRESS == type && value <= 0x10) {
		type = MINID_TYPE_RESERVED;
	}
	minid = type;
	minid <<= 29;
	minid |= value;
	return minid;
}

uint8_t ab_tree_get_minid_type(uint32_t minid)
{
	uint8_t type;
	
	if (0 == (minid & 0x80000000)) {
		return MINID_TYPE_ADDRESS;
	}
	type = minid >> 29;
	if (MINID_TYPE_RESERVED == type) {
		return MINID_TYPE_ADDRESS;
	}
	return type;
}

int ab_tree_get_minid_value(uint32_t minid)
{
	if (0 == (minid & 0x80000000)) {
		return minid;
	}
	return minid & 0x1FFFFFFF;
}

uint32_t ab_tree_get_leaves_num(SIMPLE_TREE_NODE *pnode)
{
	uint32_t count;
	
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return 0;
	}
	count = 0;
	do {
		if (ab_tree_get_node_type(pnode) < 0x80) {
			count ++;
		}
	} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	return count;
}

static SINGLE_LIST_NODE* ab_tree_get_snode()
{
	return new(std::nothrow) SINGLE_LIST_NODE;
}

static void ab_tree_put_snode(SINGLE_LIST_NODE *psnode)
{
	delete psnode;
}

static AB_NODE* ab_tree_get_abnode()
{
	auto n = new(std::nothrow) AB_NODE;
	if (n == nullptr)
		return nullptr;
	n->d_info = nullptr;
	n->minid = 0;
	return n;
}

static void ab_tree_put_abnode(AB_NODE *pabnode)
{
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN:
		delete static_cast<sql_domain *>(pabnode->d_info);
		break;
	case NODE_TYPE_PERSON:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
	case NODE_TYPE_MLIST:
		delete static_cast<sql_user *>(pabnode->d_info);
		break;
	case NODE_TYPE_GROUP:
		delete static_cast<sql_group *>(pabnode->d_info);
		break;
	case NODE_TYPE_CLASS:
		delete static_cast<sql_class *>(pabnode->d_info);
		break;
	}
	delete pabnode;
}

SIMPLE_TREE_NODE* ab_tree_minid_to_node(AB_BASE *pbase, uint32_t minid)
{
	auto ppnode = static_cast<SIMPLE_TREE_NODE **>(int_hash_query(pbase->phash, minid));
	if (NULL != ppnode) {
		return *ppnode;
	}
	return NULL;
}

void ab_tree_init(const char *org_name, int base_size,
	int cache_interval, int file_blocks)
{
	HX_strlcpy(g_org_name, org_name, GX_ARRAY_SIZE(g_org_name));
	g_base_size = base_size;
	g_cache_interval = cache_interval;
	g_file_blocks = file_blocks;
	pthread_mutex_init(&g_base_lock, NULL);
	g_notify_stop = TRUE;
}

int ab_tree_run()
{
	int i;
	AB_NODE *pabnode;
	SINGLE_LIST_NODE *psnode;
	
	g_base_hash = int_hash_init(g_base_size, sizeof(AB_BASE *));
	if (NULL == g_base_hash) {
		printf("[exchange_nsp]: Failed to init base hash table\n");
		return -1;
	}
	g_file_allocator = lib_buffer_init(
		FILE_ALLOC_SIZE, g_file_blocks, TRUE);
	if (NULL == g_file_allocator) {
		printf("[exchange_nsp]: Failed to allocate file blocks\n");
		return -2;
	}
	g_notify_stop = FALSE;
	int ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
	if (ret != 0) {
		printf("[exchange_nsp]: failed to create scanning thread: %s\n", strerror(ret));
		g_notify_stop = TRUE;
		return -3;
	}
	pthread_setname_np(g_scan_id, "abtree/scan");
	for (i=0; i<2*g_file_blocks; i++) {
		psnode = ab_tree_get_snode();
		if (NULL != psnode) {
			ab_tree_put_snode(psnode);
		}
	}
	for (i=0; i<g_file_blocks; i++) {
		pabnode = ab_tree_get_abnode();
		if (NULL != pabnode) {
			ab_tree_put_abnode(pabnode);
		}
	}
	return 0;
}

static void ab_tree_destruct_tree(SIMPLE_TREE *ptree)
{
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(ptree);
	if (NULL != proot) {
		simple_tree_destroy_node(ptree, proot,
			(SIMPLE_TREE_DELETE)ab_tree_put_abnode);
	}
	simple_tree_free(ptree);
}

static void ab_tree_unload_base(AB_BASE *pbase)
{
	SINGLE_LIST_NODE *pnode;
	
	while ((pnode = single_list_pop_front(&pbase->list)) != nullptr) {
		ab_tree_destruct_tree(&((DOMAIN_NODE*)pnode->pdata)->tree);
		free(pnode->pdata);
	}
	single_list_free(&pbase->list);
	while ((pnode = single_list_pop_front(&pbase->gal_list)) != nullptr)
		ab_tree_put_snode(pnode);
	single_list_free(&pbase->gal_list);
	if (NULL != pbase->phash) {
		int_hash_free(pbase->phash);
		pbase->phash = NULL;
	}
}

int ab_tree_stop()
{
	AB_BASE **ppbase;
	INT_HASH_ITER *iter;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
	}
	if (NULL != g_base_hash) {
		iter = int_hash_iter_init(g_base_hash);
		for (int_hash_iter_begin(iter);
			FALSE == int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ppbase = static_cast<decltype(ppbase)>(int_hash_iter_get_value(iter, nullptr));
			ab_tree_unload_base(*ppbase);
			free(*ppbase);
		}
		int_hash_iter_free(iter);
		int_hash_free(g_base_hash);
		g_base_hash = NULL;
	}
	if (NULL != g_file_allocator) {
		lib_buffer_free(g_file_allocator);
		g_file_allocator = NULL;
	}
	return 0;
}

void ab_tree_free()
{
	pthread_mutex_destroy(&g_base_lock);
}

static BOOL ab_tree_cache_node(AB_BASE *pbase, AB_NODE *pabnode)
{
	int tmp_id;
	void *ptmp_value;
	INT_HASH_ITER *iter;
	
	if (NULL == pbase->phash) {
		pbase->phash = int_hash_init(HGROWING_SIZE, sizeof(AB_NODE *));
		if (NULL == pbase->phash) {
			return FALSE;
		}
	}
	if (1 != int_hash_add(pbase->phash, pabnode->minid, &pabnode)) {
		INT_HASH_TABLE *phash = int_hash_init(pbase->phash->capacity +
		                        HGROWING_SIZE, sizeof(AB_NODE *));
		if (NULL == phash) {
			return FALSE;
		}
		iter = int_hash_iter_init(pbase->phash);
		for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ptmp_value = int_hash_iter_get_value(iter, &tmp_id);
			int_hash_add(phash, tmp_id, ptmp_value);
		}
		int_hash_iter_free(iter);
		int_hash_free(pbase->phash);
		pbase->phash = phash;
		int_hash_add(pbase->phash, pabnode->minid, &pabnode);
	}
	return TRUE;
}

static BOOL ab_tree_load_user(AB_NODE *pabnode, sql_user &&usr, AB_BASE *pbase)
{
	switch (usr.addr_type) {
	case ADDRESS_TYPE_ROOM:
		pabnode->node_type = NODE_TYPE_ROOM;
		break;
	case ADDRESS_TYPE_EQUIPMENT:
		pabnode->node_type = NODE_TYPE_EQUIPMENT;
		break;
	default:
		pabnode->node_type = NODE_TYPE_PERSON;
		break;
	}
	pabnode->id = usr.id;
	pabnode->minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, usr.id);
	((SIMPLE_TREE_NODE*)pabnode)->pdata = int_hash_query(
							pbase->phash, pabnode->minid);
	if (NULL == ((SIMPLE_TREE_NODE*)pabnode)->pdata) {
		if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
			return FALSE;
		}
	}
	pabnode->d_info = new(std::nothrow) sql_user(std::move(usr));
	if (pabnode->d_info == nullptr)
		return false;
	return TRUE;
}

static BOOL ab_tree_load_mlist(AB_NODE *pabnode, sql_user &&usr, AB_BASE *pbase)
{
	pabnode->node_type = NODE_TYPE_MLIST;
	pabnode->id = usr.id;
	pabnode->minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, usr.id);
	((SIMPLE_TREE_NODE*)pabnode)->pdata = int_hash_query(
							pbase->phash, pabnode->minid);
	if (NULL == ((SIMPLE_TREE_NODE*)pabnode)->pdata) {
		if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
			return FALSE;
		}
	}
	pabnode->d_info = new(std::nothrow) sql_user(std::move(usr));
	if (pabnode->d_info == nullptr)
		return false;
	return TRUE;
}

static int ab_tree_cmpstring(const void *p1, const void *p2)
{
	return strcasecmp(((SORT_ITEM*)p1)->string, ((SORT_ITEM*)p2)->string);
}

static BOOL ab_tree_load_class(
	int class_id, SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, AB_BASE *pbase)
{
	int i;
	int rows;
	AB_NODE *pabnode;
	char temp_buff[1024];
	std::vector<sql_class> file_subclass;
	SIMPLE_TREE_NODE *pclass;
	
	if (!system_services_get_sub_classes(class_id, file_subclass))
		return FALSE;
	for (auto &&cls : file_subclass) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			return FALSE;
		}
		pabnode->node_type = NODE_TYPE_CLASS;
		pabnode->id = cls.child_id;
		pabnode->minid = ab_tree_make_minid(MINID_TYPE_CLASS, cls.child_id);
		if (NULL == int_hash_query(pbase->phash, pabnode->minid)) {
			if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
				return FALSE;
			}
		}
		pabnode->d_info = new(std::nothrow) sql_class(std::move(cls));
		if (pabnode->d_info == nullptr)
			return false;
		pclass = (SIMPLE_TREE_NODE*)pabnode;
		simple_tree_add_child(ptree, pnode,
			pclass, SIMPLE_TREE_ADD_LAST);
		if (!ab_tree_load_class(cls.child_id, ptree, pclass, pbase))
			return FALSE;
	}

	std::vector<sql_user> file_user;
	rows = system_services_get_class_users(class_id, file_user);
	if (-1 == rows) {
		return FALSE;
	} else if (0 == rows) {
		return TRUE;
	}
	auto parray = me_alloc<SORT_ITEM>(rows);
	if (NULL == parray) {
		return FALSE;
	}
	i = 0;
	for (auto &&usr : file_user) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			goto LOAD_FAIL;
		}
		if (usr.addr_type == ADDRESS_TYPE_MLIST) {
			if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		} else {
			if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		}
		parray[i].pnode = (SIMPLE_TREE_NODE*)pabnode;
		ab_tree_get_display_name(parray[i].pnode, 1252, temp_buff);
		parray[i].string = strdup(temp_buff);
		if (NULL == parray[i].string) {
			ab_tree_put_abnode(pabnode);
			goto LOAD_FAIL;
		}
		i ++;
	}

	qsort(parray, rows, sizeof(SORT_ITEM), ab_tree_cmpstring);
	for (i=0; i<rows; i++) {
		simple_tree_add_child(ptree, pnode,
			parray[i].pnode, SIMPLE_TREE_ADD_LAST);
		free(parray[i].string);
	}
	free(parray);
	return TRUE;
LOAD_FAIL:
	for (i-=1; i>=0; i--) {
		free(parray[i].string);
		ab_tree_put_abnode((AB_NODE*)parray[i].pnode);
	}
	free(parray);
	return FALSE;
}

static BOOL ab_tree_load_tree(int domain_id,
	SIMPLE_TREE *ptree, AB_BASE *pbase)
{
	int i;
	int rows;
	AB_NODE *pabnode;
	SORT_ITEM *parray;
	sql_domain dinfo;
	SIMPLE_TREE_NODE *pgroup;
	SIMPLE_TREE_NODE *pclass;
	SIMPLE_TREE_NODE *pdomain;
	
    {
	if (!system_services_get_domain_info(domain_id, dinfo))
		return FALSE;
	pabnode = ab_tree_get_abnode();
	if (NULL == pabnode) {
		return FALSE;
	}
	pabnode->node_type = NODE_TYPE_DOMAIN;
	pabnode->id = domain_id;
	pabnode->minid = ab_tree_make_minid(MINID_TYPE_DOMAIN, domain_id);
	if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
		return FALSE;
	}
	if (!utf8_check(dinfo.name.c_str()))
		utf8_filter(dinfo.name.data());
	if (!utf8_check(dinfo.title.c_str()))
		utf8_filter(dinfo.title.data());
	if (!utf8_check(dinfo.address.c_str()))
		utf8_filter(dinfo.address.data());
	pabnode->d_info = new(std::nothrow) sql_domain(std::move(dinfo));
	if (pabnode->d_info == nullptr)
		return false;
	pdomain = (SIMPLE_TREE_NODE*)pabnode;
	simple_tree_set_root(ptree, pdomain);

	std::vector<sql_group> file_group;
	if (!system_services_get_domain_groups(domain_id, file_group))
		return FALSE;
	for (auto &&grp : file_group) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			return FALSE;
		}
		pabnode->node_type = NODE_TYPE_GROUP;
		pabnode->id = grp.id;
		pabnode->minid = ab_tree_make_minid(MINID_TYPE_GROUP, grp.id);
		if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
			return FALSE;
		}
		auto grp_id = grp.id;
		pabnode->d_info = new(std::nothrow) sql_group(std::move(grp));
		if (pabnode->d_info == nullptr)
			return false;
		pgroup = (SIMPLE_TREE_NODE*)pabnode;
		simple_tree_add_child(ptree, pdomain, pgroup, SIMPLE_TREE_ADD_LAST);
		
		std::vector<sql_class> file_class;
		if (!system_services_get_group_classes(grp_id, file_class))
			return FALSE;
		for (auto &&cls : file_class) {
			pabnode = ab_tree_get_abnode();
			if (NULL == pabnode) {
				return FALSE;
			}
			pabnode->node_type = NODE_TYPE_CLASS;
			pabnode->id = cls.child_id;
			pabnode->minid = ab_tree_make_minid(MINID_TYPE_CLASS, cls.child_id);
			if (NULL == int_hash_query(pbase->phash, pabnode->minid)) {
				if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
					ab_tree_put_abnode(pabnode);
					return FALSE;
				}
			}
			pabnode->d_info = new(std::nothrow) sql_class(std::move(cls));
			if (pabnode->d_info == nullptr)
				return false;
			pclass = (SIMPLE_TREE_NODE*)pabnode;
			simple_tree_add_child(ptree, pgroup,
				pclass, SIMPLE_TREE_ADD_LAST);
			if (!ab_tree_load_class(cls.child_id, ptree, pclass, pbase))
				return FALSE;
		}
		
		std::vector<sql_user> file_user;
		rows = system_services_get_group_users(grp_id, file_user);
		if (-1 == rows) {
			return FALSE;
		} else if (0 == rows) {
			continue;
		}
		parray = me_alloc<SORT_ITEM>(rows);
		if (NULL == parray) {
			return FALSE;
		}
		i = 0;
		for (auto &&usr : file_user) {
			pabnode = ab_tree_get_abnode();
			if (NULL == pabnode) {
				goto LOAD_FAIL;
			}
			if (usr.addr_type == ADDRESS_TYPE_MLIST) {
				if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
					ab_tree_put_abnode(pabnode);
					goto LOAD_FAIL;
				}
			} else {
				if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
					ab_tree_put_abnode(pabnode);
					goto LOAD_FAIL;
				}
			}
			parray[i].pnode = (SIMPLE_TREE_NODE*)pabnode;
			char temp_buff[1024];
			ab_tree_get_display_name(parray[i].pnode, 1252, temp_buff);
			parray[i].string = strdup(temp_buff);
			if (NULL == parray[i].string) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
			i ++;
		}
		
		qsort(parray, rows, sizeof(SORT_ITEM), ab_tree_cmpstring);
		for (i=0; i<rows; i++) {
			simple_tree_add_child(ptree, pgroup,
				parray[i].pnode, SIMPLE_TREE_ADD_LAST);
			free(parray[i].string);
		}
		free(parray);
	}

	std::vector<sql_user> file_user;
	rows = system_services_get_domain_users(domain_id, file_user);
	if (-1 == rows) {
		return FALSE;
	} else if (0 == rows) {
		return TRUE;
	}
	parray = me_alloc<SORT_ITEM>(rows);
	if (NULL == parray) {
		return FALSE;	
	}
	i = 0;
	for (auto &&usr : file_user) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			goto LOAD_FAIL;
		}
		if (usr.addr_type == ADDRESS_TYPE_MLIST) {
			if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		} else {
			if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		}
		parray[i].pnode = (SIMPLE_TREE_NODE*)pabnode;
		char temp_buff[1024];
		ab_tree_get_display_name(parray[i].pnode, 1252, temp_buff);
		parray[i].string = strdup(temp_buff);
		if (NULL == parray[i].string) {
			ab_tree_put_abnode(pabnode);
			goto LOAD_FAIL;
		}
		i ++;
	}
	
	qsort(parray, rows, sizeof(SORT_ITEM), ab_tree_cmpstring);
	for (i=0; i<rows; i++) {
		simple_tree_add_child(ptree, pdomain,
			parray[i].pnode, SIMPLE_TREE_ADD_LAST);
		free(parray[i].string);
	}
	free(parray);
	return TRUE;
    }
LOAD_FAIL:
	for (i-=1; i>=0; i--) {
		free(parray[i].string);
		ab_tree_put_abnode((AB_NODE*)parray[i].pnode);
	}
	free(parray);
	return FALSE;
}

static void ab_tree_enum_nodes(SIMPLE_TREE_NODE *pnode, void *pparam)
{
	uint8_t node_type;
	SINGLE_LIST_NODE *psnode;
	
	node_type = ab_tree_get_node_type(pnode);
	if (node_type > 0x80) {
		return;
	}
	if (NULL != pnode->pdata) {
		return;	
	}
	psnode = ab_tree_get_snode();
	if (NULL == psnode) {
		return;
	}
	psnode->pdata = pnode;
	single_list_append_as_tail((SINGLE_LIST*)pparam, psnode);
}

static BOOL ab_tree_load_base(AB_BASE *pbase)
{
	int i, num;
	int domain_id;
	SORT_ITEM *parray;
	DOMAIN_NODE *pdomain;
	char temp_buff[1024];
	SIMPLE_TREE_NODE *proot;
	SINGLE_LIST_NODE *pnode;
	
	if (pbase->base_id > 0) {
		std::vector<int> temp_file;
		if (!system_services_get_org_domains(pbase->base_id, temp_file))
			return FALSE;
		for (auto domain_id : temp_file) {
			pdomain = me_alloc<DOMAIN_NODE>();
			if (NULL == pdomain) {
				ab_tree_unload_base(pbase);
				return FALSE;
			}
			pdomain->node.pdata = pdomain;
			pdomain->domain_id = domain_id;
			simple_tree_init(&pdomain->tree);
			if (FALSE == ab_tree_load_tree(
				domain_id, &pdomain->tree, pbase)) {
				ab_tree_destruct_tree(&pdomain->tree);
				free(pdomain);
				ab_tree_unload_base(pbase);
				return FALSE;
			}
			single_list_append_as_tail(&pbase->list, &pdomain->node);
		}
	} else {
		pdomain = me_alloc<DOMAIN_NODE>();
		if (NULL == pdomain) {
			return FALSE;
		}
		pdomain->node.pdata = pdomain;
		domain_id = pbase->base_id * (-1);
		pdomain->domain_id = domain_id;
		simple_tree_init(&pdomain->tree);
		if (FALSE == ab_tree_load_tree(
			domain_id, &pdomain->tree, pbase)) {
			ab_tree_destruct_tree(&pdomain->tree);
			free(pdomain);
			ab_tree_unload_base(pbase);
			return FALSE;
		}
		single_list_append_as_tail(&pbase->list, &pdomain->node);
	}
	for (pnode=single_list_get_head(&pbase->list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->list, pnode)) {
		pdomain = (DOMAIN_NODE*)pnode->pdata;
		proot = simple_tree_get_root(&pdomain->tree);
		if (NULL == proot) {
			continue;
		}
		simple_tree_enum_from_node(proot,
			ab_tree_enum_nodes, &pbase->gal_list);
	}
	num = single_list_get_nodes_num(&pbase->gal_list);
	if (num <= 1) {
		return TRUE;
	}
	parray = me_alloc<SORT_ITEM>(num);
	if (NULL == parray) {
		return TRUE;
	}
	i = 0;
	for (pnode=single_list_get_head(&pbase->gal_list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->gal_list, pnode)) {
		ab_tree_get_display_name(static_cast<SIMPLE_TREE_NODE *>(pnode->pdata), 1252, temp_buff);
		parray[i].pnode = static_cast<SIMPLE_TREE_NODE *>(pnode->pdata);
		parray[i].string = strdup(temp_buff);
		if (NULL == parray[i].string) {
			for (i-=1; i>=0; i--) {
				free(parray[i].string);
			}
			free(parray);
			return TRUE;
		}
		i ++;
	}
	qsort(parray, num, sizeof(SORT_ITEM), ab_tree_cmpstring);
	i = 0;
	for (pnode=single_list_get_head(&pbase->gal_list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->gal_list, pnode)) {
		pnode->pdata = parray[i].pnode;
		free(parray[i].string);
		i ++;
	}
	free(parray);
	return TRUE;
}

AB_BASE* ab_tree_get_base(int base_id)
{
	int count;
	AB_BASE *pbase;
	AB_BASE **ppbase;
	
	count = 0;
RETRY_LOAD_BASE:
	pthread_mutex_lock(&g_base_lock);
	ppbase = static_cast<decltype(ppbase)>(int_hash_query(g_base_hash, base_id));
	if (NULL == ppbase) {
		pbase = me_alloc<AB_BASE>();
		if (NULL == pbase) {
			pthread_mutex_unlock(&g_base_lock);
			return NULL;
		}
		if (1 != int_hash_add(g_base_hash, base_id, &pbase)) {
			pthread_mutex_unlock(&g_base_lock);
			free(pbase);
			return NULL;
		}
		pbase->base_id = base_id;
		pbase->load_time = 0;
		pbase->reference = 0;
		pbase->status = BASE_STATUS_CONSTRUCTING;
		single_list_init(&pbase->list);
		single_list_init(&pbase->gal_list);
		pbase->phash = NULL;
		pthread_mutex_unlock(&g_base_lock);
		if (FALSE == ab_tree_load_base(pbase)) {
			pthread_mutex_lock(&g_base_lock);
			int_hash_remove(g_base_hash, base_id);
			pthread_mutex_unlock(&g_base_lock);
			free(pbase);
			return NULL;
		}
		time(&pbase->load_time);
		pthread_mutex_lock(&g_base_lock);
		pbase->status = BASE_STATUS_LIVING;
	} else {
		if (BASE_STATUS_LIVING != (*ppbase)->status) {
			pthread_mutex_unlock(&g_base_lock);
			count ++;
			if (count > 60) {
				return NULL;
			}
			sleep(1);
			goto RETRY_LOAD_BASE;
		}
		pbase = *ppbase;
	}
	pbase->reference ++;
	pthread_mutex_unlock(&g_base_lock);
	return pbase;
}

void ab_tree_put_base(AB_BASE *pbase)
{
	pthread_mutex_lock(&g_base_lock);
	pbase->reference --;
	pthread_mutex_unlock(&g_base_lock);
}

static void *scan_work_func(void *param)
{
	AB_BASE *pbase;
	AB_BASE **ppbase;
	INT_HASH_ITER *iter;
	SINGLE_LIST_NODE *pnode;
	
	while (FALSE == g_notify_stop) {
		pbase = NULL;
		pthread_mutex_lock(&g_base_lock);
		iter = int_hash_iter_init(g_base_hash);
		for (int_hash_iter_begin(iter);
			FALSE == int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ppbase = static_cast<decltype(ppbase)>(int_hash_iter_get_value(iter, nullptr));
			if (BASE_STATUS_LIVING != (*ppbase)->status ||
				0 != (*ppbase)->reference || time(NULL) -
				(*ppbase)->load_time < g_cache_interval) {
				continue;
			}
			pbase = *ppbase;
			pbase->status = BASE_STATUS_CONSTRUCTING;
			break;
		}
		int_hash_iter_free(iter);
		pthread_mutex_unlock(&g_base_lock);
		if (NULL == pbase) {
			sleep(1);
			continue;
		}
		while ((pnode = single_list_pop_front(&pbase->list)) != nullptr) {
			ab_tree_destruct_tree(&((DOMAIN_NODE*)pnode->pdata)->tree);
			free(pnode->pdata);
		}
		while ((pnode = single_list_pop_front(&pbase->gal_list)) != nullptr)
			ab_tree_put_snode(pnode);
		if (NULL != pbase->phash) {
			int_hash_free(pbase->phash);
			pbase->phash = NULL;
		}
		if (FALSE == ab_tree_load_base(pbase)) {
			pthread_mutex_lock(&g_base_lock);
			int_hash_remove(g_base_hash, pbase->base_id);
			pthread_mutex_unlock(&g_base_lock);
			free(pbase);
		} else {
			pthread_mutex_lock(&g_base_lock);
			time(&pbase->load_time);
			pbase->status = BASE_STATUS_LIVING;
			pthread_mutex_unlock(&g_base_lock);
		}
	}
	return NULL;
}

static int ab_tree_node_to_rpath(SIMPLE_TREE_NODE *pnode,
	char *pbuff, int length)
{
	int len;
	AB_NODE *pabnode;
	char temp_buff[1024];
	
	pabnode = (AB_NODE*)pnode;
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN:
		len = sprintf(temp_buff, "d%d", pabnode->id);
		break;
	case NODE_TYPE_GROUP:
		len = sprintf(temp_buff, "g%d", pabnode->id);
		break;
	case NODE_TYPE_CLASS:
		len = sprintf(temp_buff, "c%d", pabnode->id);
		break;
	case NODE_TYPE_PERSON:
		len = sprintf(temp_buff, "p%d", pabnode->id);
		break;
	case NODE_TYPE_MLIST:
		len = sprintf(temp_buff, "l%d", pabnode->id);
		break;
	case NODE_TYPE_ROOM:
		len = sprintf(temp_buff, "r%d", pabnode->id);
		break;
	case NODE_TYPE_EQUIPMENT:
		len = sprintf(temp_buff, "e%d", pabnode->id);
		break;
	default:
		return 0;
	}
	if (len >= length) {
		return 0;
	}
	memcpy(pbuff, temp_buff, len + 1);
	return len;
}

static BOOL ab_tree_node_to_path(SIMPLE_TREE_NODE *pnode,
	char *pbuff, int length)
{
	int len;
	int offset;
	BOOL b_remote;
	AB_BASE *pbase;
	SIMPLE_TREE_NODE **ppnode;
	
	
	b_remote = FALSE;
	if (NODE_TYPE_REMOTE == ((AB_NODE*)pnode)->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*((AB_NODE*)pnode)->id);
		if (NULL == pbase) {
			return FALSE;
		}
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash,
		         reinterpret_cast<AB_NODE *>(pnode)->minid));
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			return FALSE;
		}
		pnode = *ppnode;
	}
	
	offset = 0;
	do {
		len = ab_tree_node_to_rpath(pnode,
			pbuff + offset, length - offset);
		if (0 == len) {
			return FALSE;
		}
		offset += len;
	} while ((pnode = simple_tree_node_get_parent(pnode)) != NULL);
	
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
	return TRUE;
}


static void ab_tree_md5_path(const char *path, uint64_t *pdgt)
{
	int i;
	uint64_t b;
	MD5_CTX ctx;
	uint8_t dgt_buff[MD5_DIGEST_LENGTH];
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, path, strlen(path));
	MD5_Final(dgt_buff, &ctx);
	*pdgt = 0;
	for (i=0; i<16; i+=2) {
		b = dgt_buff[i];
		*pdgt |= (b << 4*i);
	}
}

static void ab_tree_enum_guid(SIMPLE_TREE_NODE *pnode, void *pparam)
{
	uint64_t dgt;
	AB_NODE *pabnode;
	GUID_ENUM *penum;
	char temp_path[512];
	
	pabnode = (AB_NODE*)pnode;
	penum = (GUID_ENUM*)pparam;
	if (NULL != penum->pabnode) {
		return;
	}
	if (pabnode->node_type != penum->node_type) {
		return;
	}
	if (pabnode->id != penum->item_id) {
		return;
	}
	ab_tree_node_to_path(pnode, temp_path, sizeof(temp_path));
	ab_tree_md5_path(temp_path, &dgt);
	if (dgt == penum->dgt) {
		penum->pabnode = pabnode;
	}
}

SIMPLE_TREE_NODE* ab_tree_guid_to_node(
	AB_BASE *pbase, GUID guid)
{
	int domain_id;
	GUID_ENUM tmp_enum;
	DOMAIN_NODE *pdomain;
	SIMPLE_TREE_NODE *ptnode;
	SINGLE_LIST_NODE *psnode;
	
	domain_id = guid.time_low & 0xFFFFFF;
	for (psnode=single_list_get_head(&pbase->list); NULL!=psnode;
		psnode=single_list_get_after(&pbase->list, psnode)) {
		pdomain = (DOMAIN_NODE*)psnode->pdata;
		if (pdomain->domain_id == domain_id) {
			break;
		}
	}
	if (NULL == psnode) {
		return NULL;
	}
	tmp_enum.node_type = (guid.time_low & 0xFF000000) >> 24;
	tmp_enum.item_id = (((int)guid.time_hi_and_version) << 16)
											| guid.time_mid;
	tmp_enum.dgt = guid.node[0] |
		(((uint64_t)guid.node[1]) << 8) |
		(((uint64_t)guid.node[2]) << 16) |
		(((uint64_t)guid.node[3]) << 24) |
		(((uint64_t)guid.node[4]) << 32) |
		(((uint64_t)guid.node[5]) << 40) |
		(((uint64_t)guid.clock_seq[0]) << 48) |
		(((uint64_t)guid.clock_seq[1]) << 56);
	
	tmp_enum.pabnode = NULL;
	ptnode = simple_tree_get_root(&pdomain->tree);
	if (NULL == ptnode) {
		return NULL;
	}
	simple_tree_enum_from_node(ptnode, ab_tree_enum_guid, &tmp_enum);
	return (SIMPLE_TREE_NODE*)tmp_enum.pabnode;
}

static void ab_tree_node_to_guid(SIMPLE_TREE_NODE *pnode, GUID *pguid)
{
	uint64_t dgt;
	uint32_t tmp_id;
	AB_NODE *pabnode;
	char temp_path[512];
	SIMPLE_TREE_NODE *proot;
	SIMPLE_TREE_NODE *pnode1;
	
	pabnode = (AB_NODE*)pnode;
	if (pabnode->node_type < 0x80 && NULL != pnode->pdata) {
		return ab_tree_node_to_guid(static_cast<SIMPLE_TREE_NODE *>(pnode->pdata), pguid);
	}
	memset(pguid, 0, sizeof(GUID));
	pguid->time_low = pabnode->node_type << 24;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		pguid->time_low |= pabnode->id;
		tmp_id = ab_tree_get_minid_value(pabnode->minid);
		pguid->time_hi_and_version = (tmp_id & 0xFFFF0000) >> 16;
		pguid->time_mid = tmp_id & 0xFFFF;
	} else {
		proot = pnode;
		while ((pnode1 = simple_tree_node_get_parent(proot)) != NULL)
			proot = pnode1;
		pguid->time_low |= ((AB_NODE*)proot)->id;
		pguid->time_hi_and_version = (pabnode->id & 0xFFFF0000) >> 16;
		pguid->time_mid = pabnode->id & 0xFFFF;
	}
	memset(temp_path, 0, sizeof(temp_path));
	ab_tree_node_to_path((SIMPLE_TREE_NODE*)
		pabnode, temp_path, sizeof(temp_path));
	ab_tree_md5_path(temp_path, &dgt);
	pguid->node[0] = dgt & 0xFF;
	pguid->node[1] = (dgt & 0xFF00) >> 8;
	pguid->node[2] = (dgt & 0xFF0000) >> 16;
	pguid->node[3] = (dgt & 0xFF000000) >> 24;
	pguid->node[4] = (dgt & 0xFF00000000ULL) >> 32;
	pguid->node[5] = (dgt & 0xFF0000000000ULL) >> 40;
	pguid->clock_seq[0] = (dgt & 0xFF000000000000ULL) >> 48;
	pguid->clock_seq[1] = (dgt & 0xFF00000000000000ULL) >> 56;
}

BOOL ab_tree_node_to_dn(SIMPLE_TREE_NODE *pnode, char *pbuff, int length)
{
	int id;
	GUID guid;
	char *ptoken;
	int domain_id;
	BOOL b_remote;
	AB_BASE *pbase;
	AB_NODE *pabnode;
	char username[324];
	char hex_string[32];
	char hex_string1[32];
	SIMPLE_TREE_NODE **ppnode;
	
	b_remote = FALSE;
	pabnode = (AB_NODE*)pnode;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*pabnode->id);
		if (NULL == pbase) {
			return FALSE;
		}
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash, pabnode->minid));
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			return FALSE;
		}
		pabnode = (AB_NODE*)*ppnode;
		pnode = *ppnode;
	}
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN:
	case NODE_TYPE_GROUP:
	case NODE_TYPE_CLASS:
		ab_tree_node_to_guid(pnode, &guid);
		snprintf(pbuff, 128,
			"/guid=%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
			guid.time_low, guid.time_mid,
			guid.time_hi_and_version,
			guid.clock_seq[0],
			guid.clock_seq[1],
			guid.node[0], guid.node[1],
			guid.node[2], guid.node[3],
			guid.node[4], guid.node[5]);
		break;
	case NODE_TYPE_PERSON:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		id = pabnode->id;
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, username, GX_ARRAY_SIZE(username));
		ptoken = strchr(username, '@');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		while ((pnode = simple_tree_node_get_parent(pnode)) != NULL)
			pabnode = (AB_NODE*)pnode;
		if (pabnode->node_type != NODE_TYPE_DOMAIN) {
			if (TRUE == b_remote) {
				ab_tree_put_base(pbase);
			}
			return FALSE;
		}
		domain_id = pabnode->id;
		encode_hex_int(id, hex_string);
		encode_hex_int(domain_id, hex_string1);
		sprintf(pbuff, "/o=%s/ou=Exchange Administrative Group"
				" (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
				g_org_name, hex_string1, hex_string, username);
		HX_strupper(pbuff);
		break;
	case NODE_TYPE_MLIST: try {
		id = pabnode->id;
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		std::string username = obj->username;
		auto pos = username.find('@');
		if (pos != username.npos)
			username.erase(pos);
		while ((pnode = simple_tree_node_get_parent(pnode)) != NULL)
			pabnode = (AB_NODE*)pnode;
		if (pabnode->node_type != NODE_TYPE_DOMAIN) {
			if (TRUE == b_remote) {
				ab_tree_put_base(pbase);
			}
			return FALSE;
		}
		domain_id = pabnode->id;
		encode_hex_int(id, hex_string);
		encode_hex_int(domain_id, hex_string1);
		sprintf(pbuff, "/o=%s/ou=Exchange Administrative Group"
				" (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
				g_org_name, hex_string1, hex_string, username.c_str());
		HX_strupper(pbuff);
		break;
	} catch (...) {
		if (b_remote)
			ab_tree_put_base(pbase);
		return false;
	}
	default:
		if (TRUE == b_remote) {
			ab_tree_put_base(pbase);
		}
		return FALSE;
	}
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
	return TRUE;	
}

uint32_t ab_tree_get_node_minid(SIMPLE_TREE_NODE *pnode)
{
	return ((AB_NODE*)pnode)->minid;
}

uint8_t ab_tree_get_node_type(SIMPLE_TREE_NODE *pnode)
{
	AB_BASE *pbase;
	AB_NODE *pabnode;
	uint8_t node_type;
	SIMPLE_TREE_NODE **ppnode;
	
	pabnode = (AB_NODE*)pnode;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		pbase = ab_tree_get_base((-1)*pabnode->id);
		if (NULL == pbase) {
			return NODE_TYPE_REMOTE;
		}
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash, pabnode->minid));
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			return NODE_TYPE_REMOTE;
		}
		node_type = ((AB_NODE*)*ppnode)->node_type;
		ab_tree_put_base(pbase);
		return node_type;
	}
	return pabnode->node_type;
}

static void ab_tree_get_display_name(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, char *str_dname)
{
	char *ptoken;
	AB_NODE *pabnode;
	char lang_string[256];
	
	pabnode = (AB_NODE*)pnode;
	str_dname[0] = '\0';
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN: {
		auto obj = static_cast<sql_domain *>(pabnode->d_info);
		strcpy(str_dname, obj->title.c_str());
		break;
	}
	case NODE_TYPE_GROUP: {
		auto obj = static_cast<sql_group *>(pabnode->d_info);
		strcpy(str_dname, obj->title.c_str());
		break;
	}
	case NODE_TYPE_CLASS: {
		auto obj = static_cast<sql_class *>(pabnode->d_info);
		strcpy(str_dname, obj->name.c_str());
		break;
	}
	case NODE_TYPE_PERSON:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT: {
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		auto it = obj->propvals.find(PROP_TAG_DISPLAYNAME);
		if (it != obj->propvals.cend()) {
			strcpy(str_dname, it->second.c_str());
		} else {
			strcpy(str_dname, obj->username.c_str());
			ptoken = strchr(str_dname, '@');
			if (NULL != ptoken) {
				*ptoken = '\0';
			}
		}
		break;
	}
	case NODE_TYPE_MLIST: {
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		auto it = obj->propvals.find(PROP_TAG_DISPLAYNAME);
		switch (obj->list_type) {
		case MLIST_TYPE_NORMAL:
			if (FALSE == system_services_get_lang(codepage, "mlist0", str_dname, 256)) {
				strcpy(str_dname, "custom address list");
			}
			snprintf(str_dname, 256, "%s(%s)", obj->username.c_str(), lang_string);
			break;
		case MLIST_TYPE_GROUP:
			if (FALSE == system_services_get_lang(codepage, "mlist1", lang_string, 256)) {
				strcpy(lang_string, "all users in department of %s");
			}
			snprintf(str_dname, 256, lang_string, it != obj->propvals.cend() ? it->second.c_str() : "");
			break;
		case MLIST_TYPE_DOMAIN:
			if (FALSE == system_services_get_lang(codepage, "mlist2", str_dname, 256)) {
				strcpy(str_dname, "all users in domain");
			}
			break;
		case MLIST_TYPE_CLASS:
			if (FALSE == system_services_get_lang(codepage, "mlist3", lang_string, 256)) {
				strcpy(lang_string, "all users in group of %s");
			}
			snprintf(str_dname, 256, lang_string, it != obj->propvals.cend() ? it->second.c_str() : "");
			break;
		default:
			snprintf(str_dname, 256, "unknown address list type %u", obj->list_type);
		}
		break;
	}
	}
}

static std::vector<std::string> ab_tree_get_object_aliases(SIMPLE_TREE_NODE *pnode, unsigned int type)
{
	std::vector<std::string> alist;
	auto pabnode = reinterpret_cast<AB_NODE *>(pnode);
	for (const auto &a : static_cast<sql_user *>(pabnode->d_info)->aliases)
		alist.push_back(a);
	return alist;
}

static void ab_tree_get_user_info(SIMPLE_TREE_NODE *pnode, int type,
    char *value, size_t vsize)
{
	AB_NODE *pabnode;
	
	value[0] = '\0';
	pabnode = (AB_NODE*)pnode;
	if (pabnode->node_type != NODE_TYPE_PERSON &&
		pabnode->node_type != NODE_TYPE_ROOM &&
		pabnode->node_type != NODE_TYPE_EQUIPMENT &&
		pabnode->node_type != NODE_TYPE_REMOTE) {
		return;
	}
	auto u = static_cast<sql_user *>(pabnode->d_info);
	unsigned int tag = 0;
	switch (type) {
	case USER_MAIL_ADDRESS: HX_strlcpy(value, u->username.c_str(), vsize); return;
	case USER_REAL_NAME: tag = PROP_TAG_DISPLAYNAME; break;
	case USER_JOB_TITLE: tag = PROP_TAG_TITLE; break;
	case USER_COMMENT: tag = PROP_TAG_COMMENT; break;
	case USER_MOBILE_TEL: tag = PROP_TAG_MOBILETELEPHONENUMBER; break;
	case USER_BUSINESS_TEL: tag = PROP_TAG_PRIMARYTELEPHONENUMBER; break;
	case USER_NICK_NAME: tag = PROP_TAG_NICKNAME; break;
	case USER_HOME_ADDRESS: tag = PROP_TAG_HOMEADDRESSSTREET; break;
	case USER_CREATE_DAY: *value = '\0'; return;
	case USER_STORE_PATH: HX_strlcpy(value, u->maildir.c_str(), vsize); return;
	}
	if (tag == 0)
		return;
	auto it = u->propvals.find(tag);
	if (it != u->propvals.cend())
		HX_strlcpy(value, it->second.c_str(), vsize);
}

static void ab_tree_get_mlist_info(SIMPLE_TREE_NODE *pnode,
	char *mail_address, char *create_day, int *plist_privilege)
{
	AB_NODE *pabnode;
	
	pabnode = (AB_NODE*)pnode;
	if (pabnode->node_type != NODE_TYPE_MLIST &&
		pabnode->node_type != NODE_TYPE_REMOTE) {
		mail_address[0] = '\0';
		*plist_privilege = 0;
		return;
	}
	auto obj = static_cast<sql_user *>(pabnode->d_info);
	if (mail_address != nullptr)
		strcpy(mail_address, obj->username.c_str());
	if (create_day != nullptr)
		*create_day = '\0';
	if (plist_privilege != nullptr)
		*plist_privilege = obj->list_priv;
}

static void ab_tree_get_mlist_title(uint32_t codepage, char *str_title)
{
	if (FALSE == system_services_get_lang(codepage, "mlist", str_title, 256)) {
		strcpy(str_title, "Address List");
	}
}

static void ab_tree_get_server_dn(
	SIMPLE_TREE_NODE *pnode, char *dn, int length)
{
	char *ptoken;
	char username[324];
	char hex_string[32];
	
	if (((AB_NODE*)pnode)->node_type < 0x80) {
		memset(username, 0, sizeof(username));
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, username, GX_ARRAY_SIZE(username));
		ptoken = strchr(username, '@');
		HX_strlower(username);
		if (NULL != ptoken) {
			ptoken ++;
		} else {
			ptoken = username;
		}
		if (NODE_TYPE_REMOTE == ((AB_NODE*)pnode)->node_type) {
			encode_hex_int(ab_tree_get_minid_value(
				((AB_NODE*)pnode)->minid), hex_string);
		} else {
			encode_hex_int(((AB_NODE*)pnode)->id, hex_string);
		}
		snprintf(dn, length, "/o=%s/ou=Exchange Administrative "
			"Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers"
			"/cn=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
			"-%02x%02x%s@%s", g_org_name, username[0], username[1],
			username[2], username[3], username[4], username[5],
			username[6], username[7], username[8], username[9],
			username[10], username[11], hex_string, ptoken);
		HX_strupper(dn);
	}
}

static void ab_tree_get_company_info(SIMPLE_TREE_NODE *pnode,
	char *str_name, char *str_address)
{
	BOOL b_remote;
	AB_BASE *pbase;
	AB_NODE *pabnode;
	SIMPLE_TREE_NODE **ppnode;
	
	b_remote = FALSE;
	pabnode = (AB_NODE*)pnode;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*pabnode->id);
		if (NULL == pbase) {
			str_name[0] = '\0';
			str_address[0] = '\0';
			return;
		}
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash, pabnode->minid));
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			str_name[0] = '\0';
			str_address[0] = '\0';
			return;
		}
		pnode = *ppnode;
		pabnode = (AB_NODE*)*ppnode;
	}
	while ((pnode = simple_tree_node_get_parent(pnode)) != NULL)
		pabnode = (AB_NODE*)pnode;
	auto obj = static_cast<sql_domain *>(pabnode->d_info);
	if (str_name != nullptr)
		strcpy(str_name, obj->title.c_str());
	if (str_address != nullptr)
		strcpy(str_address, obj->address.c_str());
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
}

static void ab_tree_get_department_name(SIMPLE_TREE_NODE *pnode, char *str_name)
{
	BOOL b_remote;
	AB_BASE *pbase;
	AB_NODE *pabnode;
	SIMPLE_TREE_NODE **ppnode;
	
	b_remote = FALSE;
	if (NODE_TYPE_REMOTE == ((AB_NODE*)pnode)->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*((AB_NODE*)pnode)->id);
		if (NULL == pbase) {
			str_name[0] = '\0';
			return;
		}
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash,
		         reinterpret_cast<AB_NODE *>(pnode)->minid));
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			str_name[0] = '\0';
			return;
		}
		pnode = *ppnode;
	}
	do {
		pabnode = (AB_NODE*)pnode;
		if (NODE_TYPE_GROUP == pabnode->node_type) {
			break;
		}
	} while ((pnode = simple_tree_node_get_parent(pnode)) != NULL);
	if (NULL == pnode) {
		str_name[0] = '\0';
		return;
	}
	auto obj = static_cast<sql_group *>(pabnode->d_info);
	strcpy(str_name, obj->title.c_str());
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
}

BOOL ab_tree_has_child(SIMPLE_TREE_NODE *pnode)
{
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return FALSE;
	}
	do {
		if (ab_tree_get_node_type(pnode) > 0x80) {
			return TRUE;
		}
	} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	return FALSE;
}

static int ab_tree_fetchprop(SIMPLE_TREE_NODE *node,
    unsigned int proptag, void **prop)
{
	auto node_type = ab_tree_get_node_type(node);
	if (node_type != NODE_TYPE_PERSON && node_type != NODE_TYPE_ROOM &&
	    node_type != NODE_TYPE_EQUIPMENT && node_type != NODE_TYPE_MLIST)
		return ecNotFound;
	const auto &obj = *static_cast<sql_user *>(reinterpret_cast<AB_NODE *>(node)->d_info);
	auto it = obj.propvals.find(proptag);
	if (it == obj.propvals.cend())
		return ecNotFound;

	switch (PROP_TYPE(proptag)) {
	case PT_BOOLEAN:
		*prop = cu_alloc<int16_t>();
		*static_cast<int16_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0) != 0;
		return ecSuccess;
	case PT_SHORT:
		*prop = cu_alloc<int16_t>();
		*static_cast<int16_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_LONG:
		*prop = cu_alloc<int32_t>();
		*static_cast<int16_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_I8:
	case PT_SYSTIME:
		*prop = cu_alloc<int64_t>();
		*static_cast<int16_t *>(*prop) = strtoll(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_STRING8:
	case PT_UNICODE:
		*prop = common_util_alloc(strlen(it->second.c_str()) + 1);
		if (*prop == nullptr)
			return ecMAPIOOM;
		strcpy(static_cast<char *>(*prop), it->second.c_str());
		return ecSuccess;
	case PT_BINARY: {
		*prop = cu_alloc<BINARY>();
		if (*prop == nullptr)
			return ecMAPIOOM;
		auto bv = static_cast<BINARY *>(*prop);
		bv->cb = it->second.size();
		bv->pv = common_util_alloc(it->second.size());
		if (bv->pv == nullptr)
			return ecMAPIOOM;
		memcpy(bv->pv, it->second.data(), bv->cb);
		return ecSuccess;
	}
	case PT_MV_UNICODE: {
		*prop = cu_alloc<STRING_ARRAY>();
		if (*prop == nullptr)
			return ecMAPIOOM;
		auto sa = static_cast<STRING_ARRAY *>(*prop);
		sa->count = 1;
		sa->ppstr = cu_alloc<char *>();
		if (sa->ppstr == nullptr)
			return ecMAPIOOM;
		sa->ppstr[0] = cu_alloc<char>(it->second.size() + 1);
		if (sa->ppstr[0] == nullptr)
			return ecMAPIOOM;
		strcpy(sa->ppstr[0], it->second.c_str());
		return ecSuccess;
	}
	}
	return ecNotFound;
}

/* Returns: TRUE (success or notfound), FALSE (fatal error/enomem/etc.) */
BOOL ab_tree_fetch_node_property(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, uint32_t proptag, void **ppvalue)
{
	int minid;
	void *pvalue;
	char dn[1280]{};
	GUID temp_guid;
	time_t tmp_time;
	struct tm tmp_tm;
	uint8_t node_type;
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	*ppvalue = nullptr;
	node_type = ab_tree_get_node_type(pnode);
	/* Properties that need to be force-generated */
	switch (proptag) {
	case PROP_TAG_ABPROVIDERID:
		*ppvalue = cu_alloc<BINARY>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((BINARY*)*ppvalue)->cb = 16;
		static_cast<BINARY *>(*ppvalue)->pb = deconst(common_util_get_muidecsab());
		return TRUE;
	case PROP_TAG_CONTAINERFLAGS:
		if (node_type < 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == ab_tree_has_child(pnode)) {
			*(uint32_t*)pvalue = AB_RECIPIENTS | AB_UNMODIFIABLE;
		} else {
			*(uint32_t*)pvalue = AB_RECIPIENTS |
				AB_SUBCONTAINERS | AB_UNMODIFIABLE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPTH:
		if (node_type < 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = simple_tree_node_get_depth(pnode) + 1;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKISMASTER:
		if (node_type < 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<uint8_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint8_t*)pvalue = 0;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE:
		if (node_type > 0x80) {
			return TRUE;
		}
		ab_tree_get_server_dn(pnode, dn, sizeof(dn));
		strcat(dn, "/cn=Microsoft Private MDB");
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKOBJECTGUID:
		ab_tree_node_to_guid(pnode, &temp_guid);
		pvalue = common_util_guid_to_binary(temp_guid);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKCONTAINERID:
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		if (node_type > 0x80) {
			*(uint32_t*)pvalue = ab_tree_get_node_minid(pnode);
		} else {
			pnode = simple_tree_node_get_parent(pnode);
			if (NULL == pnode) {
				*(uint32_t*)pvalue = 0;
			} else {
				*(uint32_t*)pvalue = ab_tree_get_node_minid(pnode);
			}
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSTYPE:
		if (node_type > 0x80) {
			return TRUE;
		}
		*ppvalue = deconst("EX");
		return TRUE;
	case PROP_TAG_EMAILADDRESS:
		if (node_type > 0x80) {
			return TRUE;
		}
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return FALSE;
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_OBJECTTYPE:
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		if (node_type > 0x80) {
			*(uint32_t*)pvalue = OBJECT_ABCONTAINER;
		} else if (NODE_TYPE_MLIST == node_type) {
			*(uint32_t*)pvalue = OBJECT_DLIST;
		} else if (NODE_TYPE_FOLDER == node_type) {
			*(uint32_t*)pvalue = OBJECT_FOLDER;
		} else {
			*(uint32_t*)pvalue = OBJECT_USER;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DISPLAYTYPE:
		if (node_type > 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		if (NODE_TYPE_MLIST == node_type) {
			*(uint32_t*)pvalue = DISPLAY_TYPE_DISTLIST;
		} else {
			*(uint32_t*)pvalue = DISPLAY_TYPE_MAILUSER;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DISPLAYTYPEEX:
		if (node_type > 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		if (NODE_TYPE_ROOM == node_type) {
			*(uint32_t*)pvalue = DISPLAY_TYPE_ROOM;
		} else if (NODE_TYPE_EQUIPMENT == node_type) {
			*(uint32_t*)pvalue = DISPLAY_TYPE_EQUIPMENT;
		} else {
			*(uint32_t*)pvalue = DISPLAY_TYPE_MAILUSER
								| DTE_FLAG_ACL_CAPABLE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_MAPPINGSIGNATURE:
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		((BINARY*)pvalue)->cb = 16;
		static_cast<BINARY *>(pvalue)->pb = deconst(g_guid_nspi);
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_PARENTENTRYID:
		pnode = simple_tree_node_get_parent(pnode);
		if (NULL == pnode) {
			return TRUE;
		}
		return ab_tree_fetch_node_property(
			pnode, codepage, proptag, ppvalue);
	case PROP_TAG_ENTRYID:
	case PROP_TAG_RECORDKEY:
	case PROP_TAG_TEMPLATEID:
	case PROP_TAG_ORIGINALENTRYID: {
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(pvalue);
		ab_entryid.flags = 0;
		rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
									ab_entryid.provider_uid);
		ab_entryid.version = 1;
		if (node_type > 0x80) {
			ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_CONTAINER;
		} else if (NODE_TYPE_MLIST == node_type) {
			ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_DLIST;
		} else {
			ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER;
		}
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return FALSE;
		ab_entryid.px500dn = dn;
		bv->pv = common_util_alloc(1280);
		if (bv->pv == nullptr)
			return FALSE;
		ext_buffer_push_init(&ext_push, bv->pv, 1280, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
			&ext_push, &ab_entryid)) {
			return FALSE;
		}
		bv->cb = ext_push.offset;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PROP_TAG_SEARCHKEY: {
		if (node_type > 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(pvalue);
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return FALSE;
		bv->cb = strlen(dn) + 4;
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr)
			return FALSE;
		sprintf(bv->pc, "EX:%s", dn);
		HX_strupper(bv->pc);
		*ppvalue = pvalue;
		return TRUE;
	}
	case PROP_TAG_INSTANCEKEY: {
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(pvalue);
		bv->cb = 4;
		bv->pv = common_util_alloc(4);
		if (bv->pv == nullptr)
			return FALSE;
		minid = ab_tree_get_node_minid(pnode);
		bv->pb[0] = minid & 0xFF;
		bv->pb[1] = (minid >> 8) & 0xFF;
		bv->pb[2] = (minid >> 16) & 0xFF;
		bv->pb[3] = (minid >> 24) & 0xFF;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
		if (node_type > 0x80) {
			return TRUE;
		}
		[[fallthrough]];
	case PROP_TAG_DISPLAYNAME:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
		ab_tree_get_display_name(pnode, codepage, dn);
		if ('\0' == dn[0]) {
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_COMPANYNAME:
		if (node_type > 0x80) {
			return TRUE;
		}
		ab_tree_get_company_info(pnode, dn, NULL);
		if ('\0' == dn[0]) {
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPARTMENTNAME:
		if (node_type > 0x80) {
			return TRUE;
		}
		ab_tree_get_department_name(pnode, dn);
		if ('\0' == dn[0]) {
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ACCOUNT:
	case PROP_TAG_SMTPADDRESS:
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (node_type == NODE_TYPE_PERSON ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		} else {
			return TRUE;
		}
		if ('\0' == dn[0]) {
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKPROXYADDRESSES: {
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (node_type == NODE_TYPE_PERSON ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		} else {
			return TRUE;
		}
		if ('\0' == dn[0]) {
			return TRUE;
		}
		std::vector<std::string> alias_list;
		try {
			alias_list = ab_tree_get_object_aliases(pnode, node_type);
		} catch (...) {
		}
		auto sa = cu_alloc<STRING_ARRAY>();
		if (sa == nullptr)
			return FALSE;
		sa->count = 1 + alias_list.size();
		sa->ppstr = cu_alloc<char *>(sa->count);
		if (sa->ppstr == nullptr)
			return FALSE;
		sa->ppstr[0] = cu_alloc<char>(strlen(dn) + 6);
		if (sa->ppstr[0] == nullptr)
			return FALSE;
		sprintf(sa->ppstr[0], "SMTP:%s", dn);
		size_t i = 1;
		for (const auto &a : alias_list) {
			sa->ppstr[i] = cu_alloc<char>(a.size() + 6);
			if (sa->ppstr[i] == nullptr)
				return false;
			strcpy(sa->ppstr[i], "SMTP:");
			strcat(sa->ppstr[i++], a.c_str());
		}
		*ppvalue = sa;
		return TRUE;
	}
	case PROP_TAG_THUMBNAILPHOTO:
		if (node_type != NODE_TYPE_PERSON) {
			return TRUE;
		}
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		ab_tree_get_user_info(pnode, USER_STORE_PATH, dn, GX_ARRAY_SIZE(dn));
		strcat(dn, "/config/portrait.jpg");
		if (!common_util_load_file(dn, static_cast<BINARY *>(pvalue))) {
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	}
	/* User-defined props */
	if (node_type == NODE_TYPE_PERSON || node_type == NODE_TYPE_ROOM ||
	    node_type == NODE_TYPE_EQUIPMENT || node_type == NODE_TYPE_MLIST) {
		auto ret = ab_tree_fetchprop(pnode, proptag, ppvalue);
		if (ret == ecSuccess)
			return TRUE;
		if (ret != ecNotFound)
			return false;
	}
	/*
	 * Fallback defaults in case ab_tree does not contain a prop
	 * (in case e.g. a user has not explicitly set SENDRICHINFO=0)
	 */
	switch (proptag) {
	case PROP_TAG_SENDRICHINFO:
		if (node_type > 0x80) {
			return TRUE;
		}
		pvalue = cu_alloc<uint8_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint8_t*)pvalue = 1;
		*ppvalue = pvalue;
		return TRUE;
	}
	return TRUE;
}

BOOL ab_tree_fetch_node_properties(SIMPLE_TREE_NODE *pnode,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	USER_INFO *pinfo;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (FALSE == ab_tree_fetch_node_property(pnode,
			pinfo->cpid, pproptags->pproptag[i], &pvalue)) {
			return FALSE;	
		}
		if (NULL == pvalue) {
			continue;
		}
		ppropvals->ppropval[ppropvals->count].proptag =
									pproptags->pproptag[i];
		ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
		ppropvals->count ++;
	}
	return TRUE;
}

static BOOL ab_tree_resolve_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	if (TRUE == ab_tree_node_to_dn(pnode, dn, sizeof(dn))
		&& 0 == strcasecmp(dn, pstr)) {
		return TRUE;
	}
	ab_tree_get_department_name(pnode, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	switch(ab_tree_get_node_type(pnode)) {
	case NODE_TYPE_PERSON:
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	case NODE_TYPE_MLIST:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	}
	return FALSE;
}

BOOL ab_tree_resolvename(AB_BASE *pbase, uint32_t codepage,
	char *pstr, SINGLE_LIST *presult_list)
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *prnode;
	SINGLE_LIST_NODE *psnode;
	
	plist = &pbase->gal_list;
	single_list_init(presult_list);
	for (psnode=single_list_get_head(plist); NULL!=psnode;
		psnode=single_list_get_after(plist, psnode)) {
		if (!ab_tree_resolve_node(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata),
		    codepage, pstr))
			continue;
		prnode = cu_alloc<SINGLE_LIST_NODE>();
		if (NULL == prnode) {
			return FALSE;
		}
		prnode->pdata = psnode->pdata;
		single_list_append_as_tail(presult_list, prnode);
	}
	return TRUE;
}

static BOOL ab_tree_match_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const RESTRICTION *pfilter)
{
	int len;
	char *ptoken;
	void *pvalue;
	uint8_t node_type;
	
	switch (pfilter->rt) {
	case RES_AND:
		for (unsigned int i = 0; i < pfilter->andor->count; ++i)
			if (!ab_tree_match_node(pnode, codepage, &pfilter->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (unsigned int i = 0; i < pfilter->andor->count; ++i)
			if (ab_tree_match_node(pnode, codepage, &pfilter->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_NOT:
		if (ab_tree_match_node(pnode, codepage, &pfilter->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pfilter->cont;
		if (PROP_TYPE(rcon->proptag) != PT_STRING8 &&
		    PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		if (!ab_tree_fetch_node_property(pnode, codepage,
		    rcon->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;	
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strcmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			} else {
				if (strstr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		case FL_PREFIX:
			len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			} else {
				if (strncmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue), len) == 0)
					return TRUE;
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pfilter->prop;
		if (rprop->proptag == PROP_TAG_ANR) {
			if (TRUE == ab_tree_fetch_node_property(pnode,
				codepage, PROP_TAG_ACCOUNT, &pvalue) &&
				NULL != pvalue) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
					return TRUE;
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(static_cast<char *>(rprop->propval.pvalue), ':');
			if (ptoken != nullptr && pvalue != nullptr)
				if (strcasestr(static_cast<char *>(pvalue), ptoken + 1) != nullptr)
					return TRUE;
			if (TRUE == ab_tree_fetch_node_property(pnode,
				codepage, PROP_TAG_DISPLAYNAME, &pvalue) &&
				NULL != pvalue) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		}
		if (!ab_tree_fetch_node_property(pnode, codepage,
		    rprop->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_BITMASK: {
		auto rbm = pfilter->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		if (!ab_tree_fetch_node_property(pnode, codepage,
		    rbm->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if ((*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0)
				return TRUE;
			break;
		case BMR_NEZ:
			if (*static_cast<uint32_t *>(pvalue) & rbm->mask)
				return TRUE;
			break;
		}
		return FALSE;
	}
	case RES_EXIST:
		node_type = ab_tree_get_node_type(pnode);
		if (node_type > 0x80) {
			return FALSE;
		}
		if (ab_tree_fetch_node_property(pnode, codepage,
		    pfilter->exist->proptag, &pvalue) && pvalue != nullptr)
			return TRUE;	
		return FALSE;
	default:
		return FALSE;
	}
	return false;
}

BOOL ab_tree_match_minids(AB_BASE *pbase, uint32_t container_id,
	uint32_t codepage, const RESTRICTION *pfilter, LONG_ARRAY *pminids)
{
	int count;
	SINGLE_LIST temp_list;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	SINGLE_LIST_NODE *psnode1;
	
	single_list_init(&temp_list);
	if (0xFFFFFFFF == container_id) {
		pgal_list = &pbase->gal_list;
		for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
			psnode=single_list_get_after(pgal_list, psnode)) {
			if (ab_tree_match_node(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata), codepage, pfilter)) {
				psnode1 = cu_alloc<SINGLE_LIST_NODE>();
				if (NULL == psnode1) {
					return FALSE;
				}
				psnode1->pdata = psnode->pdata;
				single_list_append_as_tail(&temp_list, psnode1);
			}
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, container_id);
		if (NULL == pnode || NULL == (pnode =
			simple_tree_node_get_child(pnode))) {
			pminids->count = 0;
			pminids->pl = NULL;
			return TRUE;
		}
		do {
			if (ab_tree_get_node_type(pnode) > 0x80) {
				continue;
			}
			if (TRUE == ab_tree_match_node(pnode, codepage, pfilter)) {
				psnode1 = cu_alloc<SINGLE_LIST_NODE>();
				if (NULL == psnode1) {
					return FALSE;
				}
				psnode1->pdata = pnode;
				single_list_append_as_tail(&temp_list, psnode1);
			}
		} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	}
	pminids->count = single_list_get_nodes_num(&temp_list);
	if (0 == pminids->count) {
		pminids->pl = NULL;
	} else {
		pminids->pl = cu_alloc<uint32_t>(pminids->count);
		if (NULL == pminids->pl) {
			return FALSE;
		}
	}
	count = 0;
	for (psnode=single_list_get_head(&temp_list); NULL!=psnode;
		psnode=single_list_get_after(&temp_list, psnode),count++) {
		pminids->pl[count] = ab_tree_get_node_minid(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata));
	}
	return TRUE;
}
