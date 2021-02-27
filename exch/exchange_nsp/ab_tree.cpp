// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
#include <new>
#include <string>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proptags.hpp>
#include "ab_tree.h"
#include <gromox/ndr_stack.hpp>
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
#include "common_util.h"
#include "nsp_types.h"
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

#define MINID_TYPE_ADDRESS					0x0
#define MINID_TYPE_DOMAIN					0x4
#define MINID_TYPE_GROUP					0x5
#define MINID_TYPE_CLASS					0x6

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

struct ab_sort_item {
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
static pthread_mutex_t g_remote_lock;

static decltype(mysql_adaptor_get_org_domains) *get_org_domains;
static decltype(mysql_adaptor_get_domain_info) *get_domain_info;
static decltype(mysql_adaptor_get_domain_groups) *get_domain_groups;
static decltype(mysql_adaptor_get_group_classes) *get_group_classes;
static decltype(mysql_adaptor_get_sub_classes) *get_sub_classes;
static decltype(mysql_adaptor_get_class_users) *get_class_users;
static decltype(mysql_adaptor_get_group_users) *get_group_users;
static decltype(mysql_adaptor_get_domain_users) *get_domain_users;
static decltype(mysql_adaptor_get_mlist_ids) *get_mlist_ids;

static BOOL (*get_lang)(uint32_t codepage,
	const char *tag, char *value, int len);

static void* scan_work_func(void *param);

static uint32_t ab_tree_make_minid(uint8_t type, int value)
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

static int ab_tree_get_minid_value(uint32_t minid)
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
	SINGLE_LIST_NODE *psnode;
	auto ppnode = static_cast<SIMPLE_TREE_NODE **>(int_hash_query(pbase->phash, minid));
	if (NULL != ppnode) {
		return *ppnode;
	}
	pthread_mutex_lock(&g_remote_lock);
	for (psnode=single_list_get_head(&pbase->remote_list); NULL!=psnode;
		psnode=single_list_get_after(&pbase->remote_list, psnode)) {
		if (minid == ((AB_NODE*)psnode->pdata)->minid) {
			pthread_mutex_unlock(&g_remote_lock);
			return static_cast<SIMPLE_TREE_NODE *>(psnode->pdata);
		}
	}
	pthread_mutex_unlock(&g_remote_lock);
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
	pthread_mutex_init(&g_remote_lock, NULL);
	g_notify_stop = TRUE;
}

int ab_tree_run()
{
#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "exchange_nsp", (s)); \
		return -1; \
	} \
} while (false)

	E(get_org_domains, "get_org_domains");
	E(get_domain_info, "get_domain_info");
	E(get_domain_groups, "get_domain_groups");
	E(get_group_classes, "get_group_classes");
	E(get_sub_classes, "get_sub_classes");
	E(get_class_users, "get_class_users");
	E(get_group_users, "get_group_users");
	E(get_domain_users, "get_domain_users");
	E(get_mlist_ids, "get_mlist_ids");
	E(get_lang, "get_lang");
#undef E
	g_base_hash = int_hash_init(g_base_size, sizeof(AB_BASE *));
	if (NULL == g_base_hash) {
		printf("[exchange_nsp]: Failed to init base hash table\n");
		return -2;
	}
	g_file_allocator = lib_buffer_init(
		FILE_ALLOC_SIZE, g_file_blocks, TRUE);
	if (NULL == g_file_allocator) {
		printf("[exchange_nsp]: Failed to allocate file blocks\n");
		return -3;
	}
	g_notify_stop = FALSE;
	int ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
	if (ret != 0) {
		printf("[exchange_nsp]: failed to create scanning thread: %s\n", strerror(ret));
		g_notify_stop = TRUE;
		return -4;
	}
	pthread_setname_np(g_scan_id, "nsp_abtree_scan");
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
	while ((pnode = single_list_pop_front(&pbase->remote_list)) != nullptr) {
		ab_tree_put_abnode(static_cast<AB_NODE *>(pnode->pdata));
		ab_tree_put_snode(pnode);
	}
	single_list_free(&pbase->remote_list);
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
	pthread_mutex_destroy(&g_remote_lock);
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

static BOOL ab_tree_load_user(AB_NODE *pabnode,
    sql_user &&usr, AB_BASE *pbase)
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

static BOOL ab_tree_load_mlist(AB_NODE *pabnode,
    sql_user &&usr, AB_BASE *pbase)
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
	return strcasecmp(static_cast<const ab_sort_item *>(p1)->string,
	       static_cast<const ab_sort_item *>(p2)->string);
}

static BOOL ab_tree_load_class(
	int class_id, SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, AB_BASE *pbase)
{
	int i;
	int rows;
	AB_NODE *pabnode;
	char temp_buff[1024];
	SIMPLE_TREE_NODE *pclass;
	
	std::vector<sql_class> file_subclass;
	if (!get_sub_classes(class_id, file_subclass))
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
		auto child_id = cls.child_id;
		pabnode->d_info = new(std::nothrow) sql_class(std::move(cls));
		if (pabnode->d_info == nullptr)
			return false;
		pclass = (SIMPLE_TREE_NODE*)pabnode;
		simple_tree_add_child(ptree, pnode,
			pclass, SIMPLE_TREE_ADD_LAST);
		if (!ab_tree_load_class(child_id, ptree, pclass, pbase))
			return FALSE;
	}

	std::vector<sql_user> file_user;
	rows = get_class_users(class_id, file_user);
	if (-1 == rows) {
		return FALSE;
	} else if (0 == rows) {
		return TRUE;
	}
	auto parray = static_cast<ab_sort_item *>(malloc(sizeof(ab_sort_item) * rows));
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

	qsort(parray, rows, sizeof(*parray), ab_tree_cmpstring);
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
	ab_sort_item *parray = nullptr;
	sql_domain dinfo;
	SIMPLE_TREE_NODE *pgroup;
	SIMPLE_TREE_NODE *pclass;
	SIMPLE_TREE_NODE *pdomain;
	
    {
	if (!get_domain_info(domain_id, dinfo))
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
	if (!get_domain_groups(domain_id, file_group))
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
		if (!get_group_classes(grp_id, file_class))
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
		rows = get_group_users(grp_id, file_user);
		if (-1 == rows) {
			return FALSE;
		} else if (0 == rows) {
			continue;
		}
		parray = static_cast<ab_sort_item *>(malloc(sizeof(ab_sort_item) * rows));
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
		
		qsort(parray, rows, sizeof(ab_sort_item), ab_tree_cmpstring);
		for (i=0; i<rows; i++) {
			simple_tree_add_child(ptree, pgroup,
				parray[i].pnode, SIMPLE_TREE_ADD_LAST);
			free(parray[i].string);
		}
		free(parray);
	}
	
	std::vector<sql_user> file_user;
	rows = get_domain_users(domain_id, file_user);
	if (-1 == rows) {
		return FALSE;
	} else if (0 == rows) {
		return TRUE;
	}
	parray = static_cast<ab_sort_item *>(malloc(sizeof(ab_sort_item) * rows));
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
	
	qsort(parray, rows, sizeof(*parray), ab_tree_cmpstring);
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
	DOMAIN_NODE *pdomain;
	char temp_buff[1024];
	SIMPLE_TREE_NODE *proot;
	SINGLE_LIST_NODE *pnode;
	
	if (pbase->base_id > 0) {
		std::vector<int> temp_file;
		if (!get_org_domains(pbase->base_id, temp_file))
			return FALSE;
		for (auto domain_id : temp_file) {
			pdomain = (DOMAIN_NODE*)malloc(sizeof(DOMAIN_NODE));
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
		pdomain = (DOMAIN_NODE*)malloc(sizeof(DOMAIN_NODE));
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
	auto parray = static_cast<ab_sort_item *>(malloc(sizeof(ab_sort_item) * num));
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
	qsort(parray, num, sizeof(ab_sort_item), ab_tree_cmpstring);
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
		pbase = (AB_BASE*)malloc(sizeof(AB_BASE));
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
		pbase->guid = guid_random_new();
		memcpy(pbase->guid.node, &base_id, sizeof(int));
		single_list_init(&pbase->list);
		single_list_init(&pbase->gal_list);
		single_list_init(&pbase->remote_list);
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
		while ((pnode = single_list_pop_front(&pbase->remote_list)) != nullptr) {
			ab_tree_put_abnode(static_cast<AB_NODE *>(pnode->pdata));
			ab_tree_put_snode(pnode);
		}
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
			if (TRUE == b_remote) {
				ab_tree_put_base(pbase);
			}
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

void ab_tree_node_to_guid(SIMPLE_TREE_NODE *pnode, GUID *pguid)
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
	pguid->time_low = static_cast<unsigned int>(pabnode->node_type) << 24;
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

SIMPLE_TREE_NODE* ab_tree_dn_to_node(AB_BASE *pbase, const char *pdn)
{
	int id;
	int temp_len;
	int domain_id;
	uint32_t minid;
	AB_BASE *pbase1;
	AB_NODE *pabnode;
	SINGLE_LIST_NODE *psnode;
	char prefix_string[1024];
	SIMPLE_TREE_NODE **ppnode;
	
	temp_len = gx_snprintf(prefix_string, GX_ARRAY_SIZE(prefix_string), "/o=%s/ou=Exchange "
			"Administrative Group (FYDIBOHF23SPDLT)", g_org_name);
	if (0 != strncasecmp(pdn, prefix_string, temp_len)) {
		return NULL;
	}
	if (strncasecmp(pdn + temp_len, "/cn=Configuration/cn=Servers/cn=", 32) == 0 &&
	    strlen(pdn) >= temp_len + 60) {
		/* Reason for 60: see DN format in ab_tree_get_server_dn */
		id = decode_hex_int(pdn + temp_len + 60);
		minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, id);
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash, minid));
		if (NULL != ppnode) {
			return *ppnode;
		} else {
			return NULL;
		}
	}
	if (0 != strncasecmp(pdn + temp_len, "/cn=Recipients/cn=", 18)) {
		return NULL;
	}
	domain_id = decode_hex_int(pdn + temp_len + 18);
	id = decode_hex_int(pdn + temp_len + 26);
	minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, id);
	ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash, minid));
	if (NULL != ppnode) {
		return *ppnode;
	}
	pthread_mutex_lock(&g_remote_lock);
	for (psnode=single_list_get_head(&pbase->remote_list); NULL!=psnode;
		psnode=single_list_get_after(&pbase->remote_list, psnode)) {
		if (minid == ((AB_NODE*)psnode->pdata)->minid) {
			pthread_mutex_unlock(&g_remote_lock);
			return static_cast<SIMPLE_TREE_NODE *>(psnode->pdata);
		}
	}
	pthread_mutex_unlock(&g_remote_lock);
	for (psnode=single_list_get_head(&pbase->list); NULL!=psnode;
		psnode=single_list_get_after(&pbase->list, psnode)) {
		if (((DOMAIN_NODE*)psnode->pdata)->domain_id == domain_id) {
			return NULL;
		}
	}
	pbase1 = ab_tree_get_base((-1)*domain_id);
	if (NULL == pbase1) {
		return NULL;
	}
	ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase1->phash, minid));
	if (NULL == ppnode) {
		ab_tree_put_base(pbase1);
		return NULL;
	}
	psnode = ab_tree_get_snode();
	if (NULL == psnode) {
		ab_tree_put_base(pbase1);
		return NULL;
	}
	pabnode = ab_tree_get_abnode();
	if (NULL == pabnode) {
		ab_tree_put_base(pbase1);
		ab_tree_put_snode(psnode);
		return NULL;
	}
	psnode->pdata = pabnode;
	((SIMPLE_TREE_NODE*)pabnode)->pdata = NULL;
	pabnode->node_type = NODE_TYPE_REMOTE;
	pabnode->minid = ((AB_NODE*)*ppnode)->minid;
	pabnode->id = domain_id;
	pabnode->d_info = new(std::nothrow) sql_domain(*static_cast<sql_domain *>(reinterpret_cast<AB_NODE *>(*ppnode)->d_info));
	if (pabnode->d_info == nullptr) {
		ab_tree_put_abnode(pabnode);
		ab_tree_put_base(pbase1);
		ab_tree_put_snode(psnode);
		return nullptr;
	}
	ab_tree_put_base(pbase1);
	pthread_mutex_lock(&g_remote_lock);
	single_list_append_as_tail(&pbase->remote_list, psnode);
	pthread_mutex_unlock(&g_remote_lock);
	return (SIMPLE_TREE_NODE*)pabnode;
}

SIMPLE_TREE_NODE* ab_tree_uid_to_node(AB_BASE *pbase, int user_id)
{
	uint32_t minid;
	
	minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, user_id);
	auto ppnode = static_cast<SIMPLE_TREE_NODE **>(int_hash_query(pbase->phash, minid));
	if (NULL == ppnode) {
		return NULL;
	}
	return *ppnode;
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

void ab_tree_get_display_name(SIMPLE_TREE_NODE *pnode,
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
			if (FALSE == get_lang(codepage, "mlist0", lang_string, 256)) {
				strcpy(lang_string, "custom address list");
			}
			snprintf(str_dname, 256, "%s(%s)", obj->username.c_str(), lang_string);
			break;
		case MLIST_TYPE_GROUP:
			if (FALSE == get_lang(codepage, "mlist1", lang_string, 256)) {
				strcpy(lang_string, "all users in department of %s");
			}
			snprintf(str_dname, 256, lang_string, it != obj->propvals.cend() ? it->second.c_str() : "");
			break;
		case MLIST_TYPE_DOMAIN:
			if (FALSE == get_lang(codepage, "mlist2", str_dname, 256)) {
				strcpy(str_dname, "all users in domain");
			}
			break;
		case MLIST_TYPE_CLASS:
			if (FALSE == get_lang(codepage, "mlist3", lang_string, 256)) {
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

std::vector<std::string> ab_tree_get_object_aliases(SIMPLE_TREE_NODE *pnode, unsigned int type)
{
	std::vector<std::string> alist;
	auto pabnode = reinterpret_cast<AB_NODE *>(pnode);
	for (const auto &a : static_cast<sql_user *>(pabnode->d_info)->aliases)
		alist.push_back(a);
	return alist;
}

void ab_tree_get_user_info(SIMPLE_TREE_NODE *pnode, int type, char *value, size_t vsize)
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
	case USER_STORE_PATH: strcpy(value, u->maildir.c_str()); return;
	}
	if (tag == 0)
		return;
	auto it = u->propvals.find(tag);
	if (it != u->propvals.cend())
		HX_strlcpy(value, it->second.c_str(), vsize);
}

void ab_tree_get_mlist_info(SIMPLE_TREE_NODE *pnode,
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

void ab_tree_get_mlist_title(uint32_t codepage, char *str_title)
{
	if (FALSE == get_lang(codepage, "mlist", str_title, 256)) {
		strcpy(str_title, "Address List");
	}
}

void ab_tree_get_server_dn(SIMPLE_TREE_NODE *pnode, char *dn, int length)
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

void ab_tree_get_company_info(SIMPLE_TREE_NODE *pnode,
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

void ab_tree_get_department_name(SIMPLE_TREE_NODE *pnode, char *str_name)
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
		ppnode = static_cast<decltype(ppnode)>(int_hash_query(pbase->phash, reinterpret_cast<AB_NODE *>(pnode)->minid));
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
		if (TRUE == b_remote) {
			ab_tree_put_base(pbase);
		}
		return;
	}
	auto obj = static_cast<sql_group *>(pabnode->d_info);
	strcpy(str_name, obj->title.c_str());
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
}

int ab_tree_get_guid_base_id(GUID guid)
{
	int base_id;
	
	memcpy(&base_id, guid.node, sizeof(int));
	pthread_mutex_lock(&g_base_lock);
	if (NULL == int_hash_query(g_base_hash, base_id)) {
		base_id = 0;
	}
	pthread_mutex_unlock(&g_base_lock);
	return base_id;
}

int ab_tree_fetchprop(SIMPLE_TREE_NODE *node, unsigned int codepage,
    unsigned int proptag, PROPERTY_VALUE *prop)
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
		prop->value.b = strtol(it->second.c_str(), nullptr, 0) != 0;
		return ecSuccess;
	case PT_SHORT:
		prop->value.s = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_LONG:
		prop->value.l = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_I8:
		prop->value.l = strtoll(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_SYSTIME:
		common_util_day_to_filetime(it->second.c_str(), &prop->value.ftime);
		return ecSuccess;
	case PT_STRING8: {
		auto tg = ndr_stack_anew<char>(NDR_STACK_OUT, it->second.size() + 1);
		if (tg == nullptr)
			return ecMAPIOOM;
		auto ret = common_util_from_utf8(codepage, it->second.c_str(), tg, it->second.size());
		if (ret < 0)
			return ecError;
		tg[ret] = '\0';
		prop->value.pstr = tg;
		return ecSuccess;
	}
	case PT_UNICODE: {
		auto tg = ndr_stack_anew<char>(NDR_STACK_OUT, it->second.size() + 1);
		if (tg == nullptr)
			return ecMAPIOOM;
		strcpy(tg, it->second.c_str());
		prop->value.pstr = tg;
		return ecSuccess;
	}
	case PT_BINARY: {
		prop->value.bin.cb = it->second.size();
		prop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, it->second.size());
		if (prop->value.bin.pv == nullptr)
			return ecMAPIOOM;
		memcpy(prop->value.bin.pv, it->second.data(), prop->value.bin.cb);
		return ecSuccess;
	}
	case PT_MV_UNICODE: {
		auto &x = prop->value.string_array;
		x.cvalues = 1;
		x.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT);
		if (x.ppstr == nullptr)
			return ecMAPIOOM;
		auto tg = ndr_stack_anew<char>(NDR_STACK_OUT, it->second.size() + 1);
		if (tg == nullptr)
			return ecMAPIOOM;
		strcpy(tg, it->second.c_str());
		x.ppstr[0] = tg;
		return ecSuccess;
	}
	}
	return ecNotFound;
}
