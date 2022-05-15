// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <new>
#include <pthread.h> 
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/ab_tree.hpp>
#include <gromox/atomic.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "ab_tree.h"
#include "common_util.h"
#include "container_object.h"
#include "system_services.h"
#include "zarafa_server.h"
#include "../mysql_adaptor/mysql_adaptor.h"

#define EPOCH_DIFF 							11644473600LL

#define BASE_STATUS_CONSTRUCTING			0
#define BASE_STATUS_LIVING					1
#define BASE_STATUS_DESTRUCTING				2

#undef containerof
#define containerof(var, T, member) reinterpret_cast<std::conditional<std::is_const<std::remove_pointer<decltype(var)>::type>::value, std::add_const<T>::type, T>::type *>(reinterpret_cast<std::conditional<std::is_const<std::remove_pointer<decltype(var)>::type>::value, const char, char>::type *>(var) - offsetof(T, member))

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

using namespace gromox;

struct ZAB_NODE {
	SIMPLE_TREE_NODE stree;
	int id = 0;
	uint32_t minid = 0;
	void *d_info = nullptr;
	abnode_type node_type = abnode_type::remote;
};
using AB_NODE = ZAB_NODE;

namespace {

struct GUID_ENUM {
	int item_id;
	abnode_type node_type;
	uint64_t dgt;
	const AB_NODE *pabnode;
};

struct sort_item {
	SIMPLE_TREE_NODE *pnode = nullptr;
	std::string str;
	inline bool operator<(const sort_item &o) const { return strcasecmp(str.c_str(), o.str.c_str()) < 0; }
};

}

static size_t g_base_size;
static int g_ab_cache_interval;
static gromox::atomic_bool g_notify_stop;
static pthread_t g_scan_id;
static char g_zcab_org_name[256];
static std::unordered_map<int, AB_BASE> g_base_hash;
static std::mutex g_base_lock;

static void *zcoreab_scanwork(void *);
static void ab_tree_get_display_name(const SIMPLE_TREE_NODE *, uint32_t codepage, char *str_dname, size_t dn_size);
static void ab_tree_get_user_info(const SIMPLE_TREE_NODE *pnode, int type, char *value, size_t vsize);

uint32_t ab_tree_make_minid(minid_type type, uint32_t value)
{
	if (type == minid_type::address && value <= 0x10)
		type = minid_type::reserved;
	auto minid = static_cast<uint32_t>(type);
	minid <<= 29;
	minid |= value;
	return minid;
}

minid_type ab_tree_get_minid_type(uint32_t minid)
{
	if (0 == (minid & 0x80000000)) {
		return minid_type::address;
	}
	auto type = static_cast<minid_type>(minid >> 29);
	return type == minid_type::reserved ? minid_type::address : type;
}

uint32_t ab_tree_get_minid_value(uint32_t minid)
{
	if (0 == (minid & 0x80000000)) {
		return minid;
	}
	return minid & 0x1FFFFFFF;
}

static AB_NODE* ab_tree_get_abnode()
{
	return new(std::nothrow) AB_NODE;
}

static void ab_tree_put_abnode(AB_NODE *pabnode)
{
	switch (pabnode->node_type) {
	case abnode_type::domain:
		delete static_cast<sql_domain *>(pabnode->d_info);
		break;
	case abnode_type::person:
	case abnode_type::room:
	case abnode_type::equipment:
	case abnode_type::mlist:
		delete static_cast<sql_user *>(pabnode->d_info);
		break;
	case abnode_type::group:
		delete static_cast<sql_group *>(pabnode->d_info);
		break;
	case abnode_type::abclass:
		delete static_cast<sql_class *>(pabnode->d_info);
		break;
	default:
		break;
	}
	delete pabnode;
}

const SIMPLE_TREE_NODE *
ab_tree_minid_to_node(const AB_BASE *pbase, uint32_t minid)
{
	auto iter = pbase->phash.find(minid);
	return iter != pbase->phash.end() ? &iter->second->stree : nullptr;
}

void ab_tree_init(const char *org_name, int base_size, int cache_interval)
{
	gx_strlcpy(g_zcab_org_name, org_name, arsizeof(g_zcab_org_name));
	g_base_size = base_size;
	g_ab_cache_interval = cache_interval;
	g_notify_stop = true;
}

int ab_tree_run()
{
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, zcoreab_scanwork, nullptr);
	if (ret != 0) {
		printf("[exchange_nsp]: failed to create scanning thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return -3;
	}
	pthread_setname_np(g_scan_id, "abtree/scan");
	return 0;
}

static void ab_tree_destruct_tree(SIMPLE_TREE *ptree)
{
	auto proot = ptree->get_root();
	if (NULL != proot) {
		ptree->destroy_node(proot, [](SIMPLE_TREE_NODE *nd) {
			ab_tree_put_abnode(containerof(nd, AB_NODE, stree));
		});
	}
	ptree->clear();
}

void AB_BASE::unload()
{
	auto pbase = this;
	
	gal_list.clear();
	domain_list.clear();
	pbase->phash.clear();
}

domain_node::domain_node(int id) : domain_id(id)
{
	simple_tree_init(&tree);
}

domain_node::domain_node(domain_node &&o) noexcept :
	domain_id(o.domain_id), tree(std::move(o.tree))
{
	o.tree = {};
}

domain_node::~domain_node()
{
	ab_tree_destruct_tree(&tree);
}

void ab_tree_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_scan_id, {})) {
			pthread_kill(g_scan_id, SIGALRM);
			pthread_join(g_scan_id, NULL);
		}
	}
	g_base_hash.clear();
}

static BOOL ab_tree_cache_node(AB_BASE *pbase, AB_NODE *pabnode) try
{
	return pbase->phash.emplace(pabnode->minid, pabnode).second ? TRUE : false;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1550: ENOMEM\n");
	return false;
}

static BOOL ab_tree_load_user(AB_NODE *pabnode, sql_user &&usr, AB_BASE *pbase)
{
	switch (usr.dtypx) {
	case DT_ROOM:
		pabnode->node_type = abnode_type::room;
		break;
	case DT_EQUIPMENT:
		pabnode->node_type = abnode_type::equipment;
		break;
	default:
		pabnode->node_type = abnode_type::person;
		break;
	}
	pabnode->id = usr.id;
	pabnode->minid = ab_tree_make_minid(minid_type::address, usr.id);
	auto iter = pbase->phash.find(pabnode->minid);
	pabnode->stree.pdata = iter != pbase->phash.end() ? iter->second : nullptr;
	if (pabnode->stree.pdata == nullptr && !ab_tree_cache_node(pbase, pabnode))
		return FALSE;
	pabnode->d_info = new(std::nothrow) sql_user(std::move(usr));
	return pabnode->d_info != nullptr ? TRUE : false;
}

static BOOL ab_tree_load_mlist(AB_NODE *pabnode, sql_user &&usr, AB_BASE *pbase)
{
	pabnode->node_type = abnode_type::mlist;
	pabnode->id = usr.id;
	pabnode->minid = ab_tree_make_minid(minid_type::address, usr.id);
	auto iter = pbase->phash.find(pabnode->minid);
	pabnode->stree.pdata = iter != pbase->phash.end() ? iter->second : nullptr;
	if (pabnode->stree.pdata == nullptr && !ab_tree_cache_node(pbase, pabnode))
		return FALSE;
	pabnode->d_info = new(std::nothrow) sql_user(std::move(usr));
	return pabnode->d_info != nullptr ? TRUE : false;
}

static BOOL ab_tree_load_class(
	int class_id, SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, AB_BASE *pbase)
{
	int rows;
	AB_NODE *pabnode;
	char temp_buff[1024];
	std::vector<sql_class> file_subclass;
	
	if (!system_services_get_sub_classes(class_id, file_subclass))
		return FALSE;
	for (auto &&cls : file_subclass) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			return FALSE;
		}
		pabnode->node_type = abnode_type::abclass;
		pabnode->id = cls.child_id;
		pabnode->minid = ab_tree_make_minid(minid_type::abclass, cls.child_id);
		if (pbase->phash.find(pabnode->minid) == pbase->phash.end() &&
		    !ab_tree_cache_node(pbase, pabnode))
			return FALSE;
		auto child_id = cls.child_id;
		pabnode->d_info = new(std::nothrow) sql_class(std::move(cls));
		if (pabnode->d_info == nullptr)
			return false;
		auto pclass = &pabnode->stree;
		ptree->add_child(pnode, pclass, SIMPLE_TREE_ADD_LAST);
		if (!ab_tree_load_class(child_id, ptree, pclass, pbase))
			return FALSE;
	}

	std::vector<sql_user> file_user;
	rows = system_services_get_class_users(class_id, file_user);
	if (-1 == rows) {
		return FALSE;
	} else if (0 == rows) {
		return TRUE;
	}
	std::vector<sort_item> parray;
	auto cl_array = make_scope_exit([&parray]() {
		for (const auto &e : parray)
			ab_tree_put_abnode(containerof(e.pnode, AB_NODE, stree));
	});
	for (auto &&usr : file_user) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			return false;
		}
		if (usr.dtypx == DT_DISTLIST) {
			if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				return false;
			}
		} else {
			if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				return false;
			}
		}
		ab_tree_get_display_name(&pabnode->stree, 1252, temp_buff, arsizeof(temp_buff));
		try {
			parray.push_back(sort_item{&pabnode->stree, temp_buff});
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1670: ENOMEM\n");
			ab_tree_put_abnode(pabnode);
			return false;
		}
	}
	std::sort(parray.begin(), parray.end());
	for (int i = 0; i < rows; ++i)
		ptree->add_child(pnode, parray[i].pnode, SIMPLE_TREE_ADD_LAST);
	cl_array.release();
	return TRUE;
}

static BOOL ab_tree_load_tree(int domain_id,
	SIMPLE_TREE *ptree, AB_BASE *pbase)
{
	int rows;
	AB_NODE *pabnode;
	sql_domain dinfo;
	
	if (!system_services_get_domain_info(domain_id, dinfo))
		return FALSE;
	pabnode = ab_tree_get_abnode();
	if (NULL == pabnode) {
		return FALSE;
	}
	pabnode->node_type = abnode_type::domain;
	pabnode->id = domain_id;
	pabnode->minid = ab_tree_make_minid(minid_type::domain, domain_id);
	if (!ab_tree_cache_node(pbase, pabnode))
		return FALSE;
	if (!utf8_check(dinfo.name.c_str()))
		utf8_filter(dinfo.name.data());
	if (!utf8_check(dinfo.title.c_str()))
		utf8_filter(dinfo.title.data());
	if (!utf8_check(dinfo.address.c_str()))
		utf8_filter(dinfo.address.data());
	pabnode->d_info = new(std::nothrow) sql_domain(std::move(dinfo));
	if (pabnode->d_info == nullptr)
		return false;
	auto pdomain = &pabnode->stree;
	ptree->set_root(pdomain);

	std::vector<sql_group> file_group;
	if (!system_services_get_domain_groups(domain_id, file_group))
		return FALSE;
	for (auto &&grp : file_group) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			return FALSE;
		}
		pabnode->node_type = abnode_type::group;
		pabnode->id = grp.id;
		pabnode->minid = ab_tree_make_minid(minid_type::group, grp.id);
		if (!ab_tree_cache_node(pbase, pabnode))
			return FALSE;
		auto grp_id = grp.id;
		pabnode->d_info = new(std::nothrow) sql_group(std::move(grp));
		if (pabnode->d_info == nullptr)
			return false;
		auto pgroup = &pabnode->stree;
		ptree->add_child(pdomain, pgroup, SIMPLE_TREE_ADD_LAST);
		
		std::vector<sql_class> file_class;
		if (!system_services_get_group_classes(grp_id, file_class))
			return FALSE;
		for (auto &&cls : file_class) {
			pabnode = ab_tree_get_abnode();
			if (NULL == pabnode) {
				return FALSE;
			}
			pabnode->node_type = abnode_type::abclass;
			pabnode->id = cls.child_id;
			pabnode->minid = ab_tree_make_minid(minid_type::abclass, cls.child_id);
			if (pbase->phash.find(pabnode->minid) == pbase->phash.end() &&
			    !ab_tree_cache_node(pbase, pabnode)) {
				ab_tree_put_abnode(pabnode);
				return FALSE;
			}
			auto child_id = cls.child_id;
			pabnode->d_info = new(std::nothrow) sql_class(std::move(cls));
			if (pabnode->d_info == nullptr)
				return false;
			auto pclass = &pabnode->stree;
			ptree->add_child(pgroup, pclass, SIMPLE_TREE_ADD_LAST);
			if (!ab_tree_load_class(child_id, ptree, pclass, pbase))
				return FALSE;
		}
		
		std::vector<sql_user> file_user;
		rows = system_services_get_group_users(grp_id, file_user);
		if (-1 == rows) {
			return FALSE;
		} else if (0 == rows) {
			continue;
		}
		std::vector<sort_item> parray;
		auto cl_array = make_scope_exit([&parray]() {
			for (const auto &e : parray)
				ab_tree_put_abnode(containerof(e.pnode, AB_NODE, stree));
		});
		for (auto &&usr : file_user) {
			pabnode = ab_tree_get_abnode();
			if (NULL == pabnode) {
				return false;
			}
			if (usr.dtypx == DT_DISTLIST) {
				if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
					ab_tree_put_abnode(pabnode);
					return false;
				}
			} else {
				if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
					ab_tree_put_abnode(pabnode);
					return false;
				}
			}
			char temp_buff[1024];
			ab_tree_get_display_name(&pabnode->stree, 1252, temp_buff, arsizeof(temp_buff));
			try {
				parray.push_back(sort_item{&pabnode->stree, temp_buff});
			} catch (const std::bad_alloc &) {
				fprintf(stderr, "E-1671: ENOMEM\n");
				ab_tree_put_abnode(pabnode);
				return false;
			}
		}
		std::sort(parray.begin(), parray.end());
		for (int i = 0; i < rows; ++i)
			ptree->add_child(pgroup, parray[i].pnode, SIMPLE_TREE_ADD_LAST);
		cl_array.release();
	}

	std::vector<sql_user> file_user;
	rows = system_services_get_domain_users(domain_id, file_user);
	if (-1 == rows) {
		return FALSE;
	} else if (0 == rows) {
		return TRUE;
	}
	std::vector<sort_item> parray;
	auto cl_array = make_scope_exit([&parray]() {
		for (const auto &e : parray)
			ab_tree_put_abnode(containerof(e.pnode, AB_NODE, stree));
	});
	for (auto &&usr : file_user) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			return false;
		}
		if (usr.dtypx == DT_DISTLIST) {
			if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				return false;
			}
		} else {
			if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
				ab_tree_put_abnode(pabnode);
				return false;
			}
		}
		char temp_buff[1024];
		ab_tree_get_display_name(&pabnode->stree, 1252, temp_buff, arsizeof(temp_buff));
		try {
			parray.push_back(sort_item{&pabnode->stree, temp_buff});
		} catch (const std::bad_alloc &) {
			fprintf(stderr, "E-1672: ENOMEM\n");
			ab_tree_put_abnode(pabnode);
			return false;
		}
	}
	std::sort(parray.begin(), parray.end());
	for (int i = 0; i < rows; ++i)
		ptree->add_child(pdomain, parray[i].pnode, SIMPLE_TREE_ADD_LAST);
	cl_array.release();
	return TRUE;
}

static BOOL ab_tree_load_base(AB_BASE *pbase) try
{
	char temp_buff[1024];
	
	if (pbase->base_id > 0) {
		std::vector<int> temp_file;
		if (!system_services_get_org_domains(pbase->base_id, temp_file))
			return FALSE;
		for (auto domain_id : temp_file) {
			domain_node dnode(domain_id);
			if (!ab_tree_load_tree(domain_id, &dnode.tree, pbase))
				return FALSE;
			pbase->domain_list.push_back(std::move(dnode));
		}
	} else {
		domain_node dnode(-pbase->base_id);
		if (!ab_tree_load_tree(dnode.domain_id, &dnode.tree, pbase))
			return FALSE;
		pbase->domain_list.push_back(std::move(dnode));
	}
	for (auto &domain : pbase->domain_list) {
		auto pdomain = &domain;
		auto proot = pdomain->tree.get_root();
		if (NULL == proot) {
			continue;
		}
		simple_tree_enum_from_node(proot, [&pbase](SIMPLE_TREE_NODE *nd) {
			auto node_type = ab_tree_get_node_type(nd);
			if (node_type >= abnode_type::containers || nd->pdata != nullptr)
				return;
			pbase->gal_list.push_back(nd);
		});
	}
	if (pbase->gal_list.size() <= 1)
		return TRUE;
	std::vector<sort_item> parray;
	for (auto ptr : pbase->gal_list) {
		ab_tree_get_display_name(ptr, 1252, temp_buff, arsizeof(temp_buff));
		parray.push_back(sort_item{ptr, temp_buff});
	}
	std::sort(parray.begin(), parray.end());
	size_t i = 0;
	for (auto &ptr : pbase->gal_list)
		ptr = parray[i++].pnode;
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1673: ENOMEM\n");
	return TRUE;
}

AB_BASE_REF ab_tree_get_base(int base_id)
{
	int count;
	AB_BASE *pbase;
	
	count = 0;
 RETRY_LOAD_BASE:
	std::unique_lock bl_hold(g_base_lock);
	auto it = g_base_hash.find(base_id);
	if (it == g_base_hash.cend()) {
		if (g_base_hash.size() >= g_base_size) {
			printf("[exchange_nsp]: W-1290: AB base hash is full\n");
			return nullptr;
		}
		try {
			auto xp = g_base_hash.try_emplace(base_id);
			if (!xp.second)
				return nullptr;
			it = xp.first;
			pbase = &it->second;
		} catch (const std::bad_alloc &) {
			return nullptr;
		}
		pbase->base_id = base_id;
		pbase->status = BASE_STATUS_CONSTRUCTING;
		bl_hold.unlock();
		if (!ab_tree_load_base(pbase)) {
			pbase->unload();
			bl_hold.lock();
			g_base_hash.erase(it);
			return nullptr;
		}
		time(&pbase->load_time);
		bl_hold.lock();
		pbase->status = BASE_STATUS_LIVING;
	} else {
		pbase = &it->second;
		if (pbase->status != BASE_STATUS_LIVING) {
			bl_hold.unlock();
			count ++;
			if (count > 60) {
				return nullptr;
			}
			sleep(1);
			goto RETRY_LOAD_BASE;
		}
	}
	pbase->reference ++;
	return AB_BASE_REF(pbase);
}

void ab_tree_del::operator()(AB_BASE *pbase)
{
	std::unique_lock bl_hold(g_base_lock);
	pbase->reference --;
}

static void *zcoreab_scanwork(void *param)
{
	while (!g_notify_stop) {
		AB_BASE *pbase = nullptr;
		auto now = time(nullptr);
		std::unique_lock bl_hold(g_base_lock);
		for (auto &pair : g_base_hash) {
			if (pair.second.status != BASE_STATUS_LIVING ||
			    pair.second.reference != 0 ||
			    now - pair.second.load_time < g_ab_cache_interval)
				continue;
			pbase = &pair.second;
			pbase->status = BASE_STATUS_CONSTRUCTING;
			break;
		}
		bl_hold.unlock();
		if (NULL == pbase) {
			sleep(1);
			continue;
		}
		pbase->gal_list.clear();
		pbase->domain_list.clear();
		pbase->phash.clear();
		if (!ab_tree_load_base(pbase)) {
			pbase->unload();
			bl_hold.lock();
			g_base_hash.erase(pbase->base_id);
			bl_hold.unlock();
		} else {
			bl_hold.lock();
			time(&pbase->load_time);
			pbase->status = BASE_STATUS_LIVING;
			bl_hold.unlock();
		}
	}
	return NULL;
}

static int ab_tree_node_to_rpath(const SIMPLE_TREE_NODE *pnode,
	char *pbuff, int length)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	char k;
	
	switch (pabnode->node_type) {
	case abnode_type::domain: k = 'd'; break;
	case abnode_type::group: k = 'g'; break;
	case abnode_type::abclass: k = 'c'; break;
	case abnode_type::person: k = 'p'; break;
	case abnode_type::mlist: k = 'l'; break;
	case abnode_type::room: k = 'r'; break;
	case abnode_type::equipment: k = 'e'; break;
	default: return 0;
	}
	char temp_buff[HXSIZEOF_Z32+2];
	auto len = sprintf(temp_buff, "%c%d", k, pabnode->id);
	if (len >= length) {
		return 0;
	}
	memcpy(pbuff, temp_buff, len + 1);
	return len;
}

static BOOL ab_tree_node_to_path(const SIMPLE_TREE_NODE *pnode,
	char *pbuff, int length)
{
	int len;
	int offset;
	AB_BASE_REF pbase;
	auto xab = containerof(pnode, AB_NODE, stree);
	
	if (xab->node_type == abnode_type::remote) {
		pbase = ab_tree_get_base(-xab->id);
		if (pbase == nullptr)
			return FALSE;
		auto iter = pbase->phash.find(xab->minid);
		if (iter == pbase->phash.end())
			return FALSE;
		xab = iter->second;
		pnode = &xab->stree;
	}
	
	offset = 0;
	do {
		len = ab_tree_node_to_rpath(pnode,
			pbuff + offset, length - offset);
		if (0 == len) {
			return FALSE;
		}
		offset += len;
	} while ((pnode = pnode->get_parent()) != nullptr);
	return TRUE;
}

static bool ab_tree_md5_path(const char *path, uint64_t *pdgt) __attribute__((warn_unused_result));
static bool ab_tree_md5_path(const char *path, uint64_t *pdgt)
{
	int i;
	uint64_t b;
	uint8_t dgt_buff[MD5_DIGEST_LENGTH];
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), path, strlen(path)) <= 0 ||
	    EVP_DigestFinal(ctx.get(), dgt_buff, nullptr) <= 0)
		return false;
	*pdgt = 0;
	for (i=0; i<16; i+=2) {
		b = dgt_buff[i];
		*pdgt |= (b << 4*i);
	}
	return true;
}

const SIMPLE_TREE_NODE *ab_tree_guid_to_node(AB_BASE *pbase, GUID guid)
{
	int domain_id;
	GUID_ENUM tmp_enum;
	
	domain_id = guid.time_low & 0xFFFFFF;
	auto pdomain = std::find_if(pbase->domain_list.begin(), pbase->domain_list.end(),
	               [&](const domain_node &dnode) { return dnode.domain_id == domain_id; });
	if (pdomain == pbase->domain_list.end())
		return NULL;
	tmp_enum.node_type = static_cast<abnode_type>((guid.time_low >> 24) & 0xff);
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
	const SIMPLE_TREE_NODE *ptnode = pdomain->tree.get_root();
	if (NULL == ptnode) {
		return NULL;
	}
	simple_tree_enum_from_node(ptnode, [&tmp_enum](const SIMPLE_TREE_NODE *pnode) {
		char temp_path[512];
		auto abn = containerof(pnode, AB_NODE, stree);
		if (tmp_enum.pabnode != nullptr ||
		    abn->node_type != tmp_enum.node_type ||
		    abn->id != tmp_enum.item_id)
			return;
		ab_tree_node_to_path(pnode, temp_path, arsizeof(temp_path));
		uint64_t dgt;
		if (ab_tree_md5_path(temp_path, &dgt) && dgt == tmp_enum.dgt)
			tmp_enum.pabnode = abn;
	});
	return &tmp_enum.pabnode->stree;
}

static bool ab_tree_node_to_guid(const SIMPLE_TREE_NODE *pnode, GUID *pguid) __attribute__((warn_unused_result));
static bool ab_tree_node_to_guid(const SIMPLE_TREE_NODE *pnode, GUID *pguid)
{
	uint64_t dgt;
	uint32_t tmp_id;
	char temp_path[512];
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (pabnode->node_type < abnode_type::containers &&
	    pnode->pdata != nullptr)
		return ab_tree_node_to_guid(static_cast<const SIMPLE_TREE_NODE *>(pnode->pdata), pguid);
	memset(pguid, 0, sizeof(GUID));
	pguid->time_low = static_cast<uint32_t>(pabnode->node_type) << 24;
	if (pabnode->node_type == abnode_type::remote) {
		pguid->time_low |= pabnode->id;
		tmp_id = ab_tree_get_minid_value(pabnode->minid);
		pguid->time_hi_and_version = (tmp_id >> 16) & 0xffff;
		pguid->time_mid = tmp_id & 0xFFFF;
	} else {
		auto proot = pnode;
		const SIMPLE_TREE_NODE *pnode1;
		while ((pnode1 = proot->get_parent()) != nullptr)
			proot = pnode1;
		auto abroot = containerof(proot, AB_NODE, stree);
		pguid->time_low |= abroot->id;
		pguid->time_hi_and_version = (pabnode->id >> 16) & 0xffff;
		pguid->time_mid = pabnode->id & 0xFFFF;
	}
	memset(temp_path, 0, sizeof(temp_path));
	ab_tree_node_to_path(&pabnode->stree, temp_path, arsizeof(temp_path));
	if (!ab_tree_md5_path(temp_path, &dgt))
		return false;
	pguid->node[0] = dgt & 0xFF;
	pguid->node[1] = (dgt >> 8) & 0xff;
	pguid->node[2] = (dgt >> 16) & 0xff;
	pguid->node[3] = (dgt >> 24) & 0xff;
	pguid->node[4] = (dgt >> 32) & 0xff;
	pguid->node[5] = (dgt >> 40) & 0xff;
	pguid->clock_seq[0] = (dgt >> 48) & 0xff;
	pguid->clock_seq[1] = (dgt >> 56) & 0xff;
	return true;
}

static BOOL ab_tree_node_to_dn(const SIMPLE_TREE_NODE *pnode,
    char *pbuff, int length)
{
	int id;
	GUID guid;
	char *ptoken;
	int domain_id;
	AB_BASE_REF pbase;
	char username[UADDR_SIZE];
	char hex_string[32];
	char hex_string1[32];
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (pabnode->node_type == abnode_type::remote) {
		pbase = ab_tree_get_base(-pabnode->id);
		if (pbase == nullptr)
			return FALSE;
		auto iter = pbase->phash.find(pabnode->minid);
		if (iter == pbase->phash.end())
			return FALSE;
		pabnode = iter->second;
		pnode = &pabnode->stree;
	}
	switch (pabnode->node_type) {
	case abnode_type::domain:
	case abnode_type::group:
	case abnode_type::abclass:
		if (!ab_tree_node_to_guid(pnode, &guid))
			return false;
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
	case abnode_type::person:
	case abnode_type::room:
	case abnode_type::equipment:
		id = pabnode->id;
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, username, GX_ARRAY_SIZE(username));
		ptoken = strchr(username, '@');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		while ((pnode = pnode->get_parent()) != nullptr)
			pabnode = containerof(pnode, AB_NODE, stree);
		if (pabnode->node_type != abnode_type::domain)
			return FALSE;
		domain_id = pabnode->id;
		encode_hex_int(id, hex_string);
		encode_hex_int(domain_id, hex_string1);
		sprintf(pbuff, "/o=%s/ou=Exchange Administrative Group"
				" (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
			g_zcab_org_name, hex_string1, hex_string, username);
		HX_strupper(pbuff);
		break;
	case abnode_type::mlist: try {
		id = pabnode->id;
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		std::string ustr = obj->username;
		auto pos = ustr.find('@');
		if (pos != ustr.npos)
			ustr.erase(pos);
		while ((pnode = pnode->get_parent()) != nullptr)
			pabnode = containerof(pnode, AB_NODE, stree);
		if (pabnode->node_type != abnode_type::domain)
			return FALSE;
		domain_id = pabnode->id;
		encode_hex_int(id, hex_string);
		encode_hex_int(domain_id, hex_string1);
		sprintf(pbuff, "/o=%s/ou=Exchange Administrative Group"
				" (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
			g_zcab_org_name, hex_string1, hex_string, ustr.c_str());
		HX_strupper(pbuff);
		break;
	} catch (...) {
		return false;
	}
	default:
		return FALSE;
	}
	return TRUE;	
}

uint32_t ab_tree_get_node_minid(const SIMPLE_TREE_NODE *pnode)
{
	auto xab = containerof(pnode, AB_NODE, stree);
	return xab->minid;
}

abnode_type ab_tree_get_node_type(const SIMPLE_TREE_NODE *pnode)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	if (pabnode->node_type != abnode_type::remote)
		return pabnode->node_type;
	auto pbase = ab_tree_get_base(-pabnode->id);
	if (pbase == nullptr)
		return abnode_type::remote;
	auto iter = pbase->phash.find(pabnode->minid);
	if (iter == pbase->phash.end())
		return abnode_type::remote;
	return iter->second->node_type;
}

static void ab_tree_get_display_name(const SIMPLE_TREE_NODE *pnode,
    uint32_t codepage, char *str_dname, size_t dn_size)
{
	char *ptoken;
	char lang_string[256];
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (dn_size > 0)
		str_dname[0] = '\0';
	switch (pabnode->node_type) {
	case abnode_type::domain: {
		auto obj = static_cast<sql_domain *>(pabnode->d_info);
		gx_strlcpy(str_dname, obj->title.c_str(), dn_size);
		break;
	}
	case abnode_type::group: {
		auto obj = static_cast<sql_group *>(pabnode->d_info);
		gx_strlcpy(str_dname, obj->title.c_str(), dn_size);
		break;
	}
	case abnode_type::abclass: {
		auto obj = static_cast<sql_class *>(pabnode->d_info);
		gx_strlcpy(str_dname, obj->name.c_str(), dn_size);
		break;
	}
	case abnode_type::person:
	case abnode_type::room:
	case abnode_type::equipment: {
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		auto it = obj->propvals.find(PR_DISPLAY_NAME);
		if (it != obj->propvals.cend()) {
			gx_strlcpy(str_dname, it->second.c_str(), dn_size);
			break;
		}
		gx_strlcpy(str_dname, obj->username.c_str(), dn_size);
		ptoken = strchr(str_dname, '@');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		break;
	}
	case abnode_type::mlist: {
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		auto it = obj->propvals.find(PR_DISPLAY_NAME);
		switch (obj->list_type) {
		case MLIST_TYPE_NORMAL:
			if (!system_services_get_lang(codepage, "mlist0", lang_string, GX_ARRAY_SIZE(lang_string)))
				strcpy(lang_string, "custom address list");
			snprintf(str_dname, dn_size, "%s(%s)", obj->username.c_str(), lang_string);
			break;
		case MLIST_TYPE_GROUP:
			if (!system_services_get_lang(codepage, "mlist1",
			    lang_string, arsizeof(lang_string)))
				strcpy(lang_string, "all users in department of %s");
			snprintf(str_dname, dn_size, lang_string, it != obj->propvals.cend() ? it->second.c_str() : "");
			break;
		case MLIST_TYPE_DOMAIN:
			if (!system_services_get_lang(codepage, "mlist2", str_dname, dn_size))
				gx_strlcpy(str_dname, "all users in domain", dn_size);
			break;
		case MLIST_TYPE_CLASS:
			if (!system_services_get_lang(codepage, "mlist3",
			    lang_string, arsizeof(lang_string)))
				strcpy(lang_string, "all users in group of %s");
			snprintf(str_dname, dn_size, lang_string, it != obj->propvals.cend() ? it->second.c_str() : "");
			break;
		default:
			snprintf(str_dname, dn_size, "unknown address list type %u", obj->list_type);
		}
		break;
	}
	default:
		break;
	}
}

static std::vector<std::string>
ab_tree_get_object_aliases(const SIMPLE_TREE_NODE *pnode, abnode_type type)
{
	std::vector<std::string> alist;
	auto pabnode = containerof(pnode, AB_NODE, stree);
	for (const auto &a : static_cast<sql_user *>(pabnode->d_info)->aliases)
		alist.push_back(a);
	return alist;
}

static void ab_tree_get_user_info(const SIMPLE_TREE_NODE *pnode, int type,
    char *value, size_t vsize)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	value[0] = '\0';
	if (pabnode->node_type != abnode_type::person &&
	    pabnode->node_type != abnode_type::room &&
	    pabnode->node_type != abnode_type::equipment &&
	    pabnode->node_type != abnode_type::remote)
		return;
	auto u = static_cast<sql_user *>(pabnode->d_info);
	unsigned int tag = 0;
	switch (type) {
	case USER_MAIL_ADDRESS: gx_strlcpy(value, u->username.c_str(), vsize); return;
	case USER_REAL_NAME: tag = PR_DISPLAY_NAME; break;
	case USER_JOB_TITLE: tag = PR_TITLE; break;
	case USER_COMMENT: tag = PR_COMMENT; break;
	case USER_MOBILE_TEL: tag = PR_MOBILE_TELEPHONE_NUMBER; break;
	case USER_BUSINESS_TEL: tag = PR_PRIMARY_TELEPHONE_NUMBER; break;
	case USER_NICK_NAME: tag = PR_NICKNAME; break;
	case USER_HOME_ADDRESS: tag = PR_HOME_ADDRESS_STREET; break;
	case USER_CREATE_DAY: *value = '\0'; return;
	case USER_STORE_PATH: gx_strlcpy(value, u->maildir.c_str(), vsize); return;
	}
	if (tag == 0)
		return;
	auto it = u->propvals.find(tag);
	if (it != u->propvals.cend())
		gx_strlcpy(value, it->second.c_str(), vsize);
}

static void ab_tree_get_mlist_info(const SIMPLE_TREE_NODE *pnode,
	char *mail_address, char *create_day, int *plist_privilege)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	if (pabnode->node_type != abnode_type::mlist &&
	    pabnode->node_type != abnode_type::remote) {
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

static void ab_tree_get_server_dn(const SIMPLE_TREE_NODE *pnode,
    char *dn, int length)
{
	char *ptoken;
	char username[UADDR_SIZE];
	char hex_string[32];
	auto xab = containerof(pnode, AB_NODE, stree);
	
	if (xab->node_type >= abnode_type::containers)
		return;
	memset(username, 0, sizeof(username));
	ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, username, GX_ARRAY_SIZE(username));
	ptoken = strchr(username, '@');
	HX_strlower(username);
	if (NULL != ptoken) {
		ptoken++;
	} else {
		ptoken = username;
	}
	if (xab->node_type == abnode_type::remote)
		encode_hex_int(ab_tree_get_minid_value(xab->minid), hex_string);
	else
		encode_hex_int(xab->id, hex_string);
	snprintf(dn, length, "/o=%s/ou=Exchange Administrative "
	         "Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers"
	         "/cn=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
	         "-%02x%02x%s@%s", g_zcab_org_name, username[0], username[1],
	         username[2], username[3], username[4], username[5],
	         username[6], username[7], username[8], username[9],
	         username[10], username[11], hex_string, ptoken);
	HX_strupper(dn);
}

static void ab_tree_get_company_info(const SIMPLE_TREE_NODE *pnode,
	char *str_name, char *str_address)
{
	AB_BASE_REF pbase;
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (pabnode->node_type == abnode_type::remote) {
		pbase = ab_tree_get_base(-pabnode->id);
		if (pbase == nullptr) {
			str_name[0] = '\0';
			str_address[0] = '\0';
			return;
		}
		auto iter = pbase->phash.find(pabnode->minid);
		if (iter == pbase->phash.end()) {
			str_name[0] = '\0';
			str_address[0] = '\0';
			return;
		}
		pabnode = iter->second;
		pnode = &pabnode->stree;
	}
	while ((pnode = pnode->get_parent()) != nullptr)
		pabnode = containerof(pnode, AB_NODE, stree);
	auto obj = static_cast<sql_domain *>(pabnode->d_info);
	if (str_name != nullptr)
		strcpy(str_name, obj->title.c_str());
	if (str_address != nullptr)
		strcpy(str_address, obj->address.c_str());
}

static void
ab_tree_get_department_name(const SIMPLE_TREE_NODE *pnode, char *str_name)
{
	AB_BASE_REF pbase;
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (pabnode->node_type == abnode_type::remote) {
		pbase = ab_tree_get_base(-pabnode->id);
		if (pbase == nullptr) {
			str_name[0] = '\0';
			return;
		}
		auto iter = pbase->phash.find(pabnode->minid);
		if (iter == pbase->phash.end()) {
			str_name[0] = '\0';
			return;
		}
		pabnode = iter->second;
		pnode = &pabnode->stree;
	}
	do {
		pabnode = containerof(pnode, AB_NODE, stree);
		if (pabnode->node_type == abnode_type::group)
			break;
	} while ((pnode = pnode->get_parent()) != nullptr);
	if (NULL == pnode) {
		str_name[0] = '\0';
		return;
	}
	auto obj = static_cast<sql_group *>(pabnode->d_info);
	strcpy(str_name, obj->title.c_str());
}

BOOL ab_tree_has_child(const SIMPLE_TREE_NODE *pnode)
{
	pnode = pnode->get_child();
	if (NULL == pnode) {
		return FALSE;
	}
	do {
		if (ab_tree_get_node_type(pnode) >= abnode_type::containers)
			return TRUE;
	} while ((pnode = pnode->get_sibling()) != nullptr);
	return FALSE;
}

static ec_error_t ab_tree_fetchprop(const SIMPLE_TREE_NODE *node,
    unsigned int proptag, void **prop)
{
	auto node_type = ab_tree_get_node_type(node);
	if (node_type != abnode_type::person && node_type != abnode_type::room &&
	    node_type != abnode_type::equipment && node_type != abnode_type::mlist)
		return ecNotFound;
	auto xab = containerof(node, AB_NODE, stree);
	const auto &obj = *static_cast<sql_user *>(xab->d_info);
	auto it = obj.propvals.find(proptag);
	if (it == obj.propvals.cend())
		return ecNotFound;

	switch (PROP_TYPE(proptag)) {
	case PT_BOOLEAN:
		*prop = cu_alloc<int8_t>();
		*static_cast<int8_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0) != 0;
		return ecSuccess;
	case PT_SHORT:
		*prop = cu_alloc<int16_t>();
		*static_cast<int16_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_LONG:
		*prop = cu_alloc<int32_t>();
		*static_cast<int32_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_I8:
	case PT_SYSTIME:
		*prop = cu_alloc<int64_t>();
		*static_cast<int64_t *>(*prop) = strtoll(it->second.c_str(), nullptr, 0);
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
static BOOL ab_tree_fetch_node_property(const SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, uint32_t proptag, void **ppvalue)
{
	int minid;
	void *pvalue;
	char dn[1280]{};
	GUID temp_guid;
	EXT_PUSH ext_push;
	EMSAB_ENTRYID ab_entryid;
	
	*ppvalue = nullptr;
	auto node_type = ab_tree_get_node_type(pnode);
	/* Properties that need to be force-generated */
	switch (proptag) {
	case PROP_TAG_ABPROVIDERID: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return FALSE;
		*ppvalue = bv;
		bv->cb = sizeof(muidECSAB);
		bv->pv = deconst(&muidECSAB);
		return TRUE;
	}
	case PROP_TAG_CONTAINERFLAGS:
		if (node_type < abnode_type::containers)
			return TRUE;
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*static_cast<uint32_t *>(pvalue) = !ab_tree_has_child(pnode) ?
			AB_RECIPIENTS | AB_UNMODIFIABLE :
			AB_RECIPIENTS | AB_SUBCONTAINERS | AB_UNMODIFIABLE;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPTH: {
		if (node_type < abnode_type::containers)
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = pnode->get_depth() + 1;
		*ppvalue = v;
		return TRUE;
	}
	case PR_EMS_AB_IS_MASTER:
		if (node_type < abnode_type::containers)
			return TRUE;
		pvalue = cu_alloc<uint8_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint8_t*)pvalue = 0;
		*ppvalue = pvalue;
		return TRUE;
	case PR_EMS_AB_HOME_MDB:
		if (node_type >= abnode_type::containers)
			return TRUE;
		ab_tree_get_server_dn(pnode, dn, sizeof(dn));
		strcat(dn, "/cn=Microsoft Private MDB");
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PR_EMS_AB_OBJECT_GUID:
		if (!ab_tree_node_to_guid(pnode, &temp_guid))
			return false;
		pvalue = common_util_guid_to_binary(temp_guid);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PR_EMS_AB_CONTAINERID:
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		if (node_type >= abnode_type::containers) {
			*(uint32_t*)pvalue = ab_tree_get_node_minid(pnode);
		} else {
			pnode = pnode->get_parent();
			if (NULL == pnode) {
				*(uint32_t*)pvalue = 0;
			} else {
				*(uint32_t*)pvalue = ab_tree_get_node_minid(pnode);
			}
		}
		*ppvalue = pvalue;
		return TRUE;
	case PR_ADDRTYPE:
		if (node_type >= abnode_type::containers)
			return TRUE;
		*ppvalue = deconst("EX");
		return TRUE;
	case PR_EMAIL_ADDRESS:
		if (node_type >= abnode_type::containers)
			return TRUE;
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return FALSE;
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = node_type >= abnode_type::containers ? MAPI_ABCONT :
		     node_type == abnode_type::mlist ? MAPI_DISTLIST :
		     node_type == abnode_type::folder ? MAPI_FOLDER : MAPI_MAILUSER;
		*ppvalue = v;
		return TRUE;
	}
	case PR_DISPLAY_TYPE: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = node_type == abnode_type::mlist ? DT_DISTLIST : DT_MAILUSER;
		*ppvalue = v;
		return TRUE;
	}
	case PR_DISPLAY_TYPE_EX: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = node_type == abnode_type::room ? DT_ROOM :
		     node_type == abnode_type::equipment ? DT_EQUIPMENT :
			DT_MAILUSER | DTE_FLAG_ACL_CAPABLE;
		*ppvalue = v;
		return TRUE;
	}
	case PR_MAPPING_SIGNATURE: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return FALSE;
		*ppvalue = bv;
		bv->cb = sizeof(muidEMSAB);
		bv->pv = deconst(&muidEMSAB);
		return TRUE;
	}
	case PR_PARENT_ENTRYID:
		pnode = pnode->get_parent();
		if (NULL == pnode) {
			return TRUE;
		}
		return ab_tree_fetch_node_property(
			pnode, codepage, proptag, ppvalue);
	case PR_ENTRYID:
	case PR_RECORD_KEY:
	case PR_TEMPLATEID:
	case PR_ORIGINAL_ENTRYID: {
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(pvalue);
		ab_entryid.flags = 0;
		ab_entryid.version = 1;
		if (node_type >= abnode_type::containers)
			ab_entryid.type = DT_CONTAINER;
		else if (node_type == abnode_type::mlist)
			ab_entryid.type = DT_DISTLIST;
		else
			ab_entryid.type = DT_MAILUSER;
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return FALSE;
		ab_entryid.px500dn = dn;
		bv->pv = common_util_alloc(1280);
		if (bv->pv == nullptr || !ext_push.init(bv->pv, 1280, 0) ||
		    ext_push.p_abk_eid(ab_entryid) != EXT_ERR_SUCCESS)
			return FALSE;
		bv->cb = ext_push.m_offset;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_SEARCH_KEY: {
		if (node_type >= abnode_type::containers)
			return TRUE;
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
	case PR_INSTANCE_KEY: {
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
	case PR_TRANSMITABLE_DISPLAY_NAME:
		if (node_type >= abnode_type::containers)
			return TRUE;
		[[fallthrough]];
	case PR_DISPLAY_NAME:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
		ab_tree_get_display_name(pnode, codepage, dn, arsizeof(dn));
		if ('\0' == dn[0]) {
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PR_COMPANY_NAME:
		if (node_type >= abnode_type::containers)
			return TRUE;
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
	case PR_DEPARTMENT_NAME:
		if (node_type >= abnode_type::containers)
			return TRUE;
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
	case PR_ACCOUNT:
	case PR_SMTP_ADDRESS:
		if (node_type == abnode_type::mlist)
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		else if (node_type == abnode_type::person ||
		    node_type == abnode_type::equipment ||
		    node_type == abnode_type::room)
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		else
			return TRUE;
		if ('\0' == dn[0]) {
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PR_EMS_AB_PROXY_ADDRESSES: {
		if (node_type == abnode_type::mlist)
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		else if (node_type == abnode_type::person ||
		    node_type == abnode_type::equipment ||
		    node_type == abnode_type::room)
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		else
			return TRUE;
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
		if (sa->ppstr == nullptr) {
			return FALSE;
		}
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
	case PR_EMS_AB_THUMBNAIL_PHOTO:
		if (node_type != abnode_type::person)
			return TRUE;
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
	if (node_type == abnode_type::person || node_type == abnode_type::room ||
	    node_type == abnode_type::equipment || node_type == abnode_type::mlist) {
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
	case PR_SEND_RICH_INFO:
		if (node_type >= abnode_type::containers)
			return TRUE;
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

BOOL ab_tree_fetch_node_properties(const SIMPLE_TREE_NODE *pnode,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	auto pinfo = zarafa_server_get_info();
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (!ab_tree_fetch_node_property(pnode,
		    pinfo->cpid, pproptags->pproptag[i], &pvalue))
			return FALSE;	
		if (NULL == pvalue) {
			continue;
		}
		ppropvals->ppropval[ppropvals->count].proptag =
									pproptags->pproptag[i];
		ppropvals->ppropval[ppropvals->count++].pvalue = pvalue;
	}
	return TRUE;
}

static BOOL ab_tree_resolve_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn, arsizeof(dn));
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	if (ab_tree_node_to_dn(pnode, dn, sizeof(dn)) && strcasecmp(dn, pstr) == 0)
		return TRUE;
	ab_tree_get_department_name(pnode, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	switch(ab_tree_get_node_type(pnode)) {
	case abnode_type::person:
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
	case abnode_type::mlist:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	default:
		break;
	}
	return FALSE;
}

bool ab_tree_resolvename(AB_BASE *pbase, uint32_t codepage, char *pstr,
    stn_list_t &result_list) try
{
	result_list.clear();
	for (auto ptr : pbase->gal_list) {
		if (!ab_tree_resolve_node(ptr, codepage, pstr))
			continue;
		result_list.push_back(ptr);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1678: ENOMEM\n");
	return false;
}

static bool ab_tree_match_node(const SIMPLE_TREE_NODE *pnode, uint32_t codepage,
    const RESTRICTION *pfilter)
{
	int len;
	char *ptoken;
	void *pvalue;
	
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
		if (rprop->proptag == PR_ANR) {
			if (ab_tree_fetch_node_property(pnode, codepage,
			    PR_ACCOUNT, &pvalue) && pvalue != nullptr &&
			    strcasestr(static_cast<char *>(pvalue),
			    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
				return TRUE;
			/* =SMTP:user@company.com */
			ptoken = strchr(static_cast<char *>(rprop->propval.pvalue), ':');
			if (ptoken != nullptr && pvalue != nullptr &&
			    strcasestr(static_cast<char *>(pvalue), ptoken + 1) != nullptr)
				return TRUE;
			if (ab_tree_fetch_node_property(pnode, codepage,
			    PR_DISPLAY_NAME, &pvalue) && pvalue != nullptr &&
			    strcasestr(static_cast<char *>(pvalue),
			    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
				return TRUE;
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
	case RES_EXIST: {
		auto node_type = ab_tree_get_node_type(pnode);
		if (node_type >= abnode_type::containers)
			return FALSE;
		if (ab_tree_fetch_node_property(pnode, codepage,
		    pfilter->exist->proptag, &pvalue) && pvalue != nullptr)
			return TRUE;	
		return FALSE;
	}
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
	SINGLE_LIST_NODE *psnode1;
	
	single_list_init(&temp_list);
	if (container_id == SPECIAL_CONTAINER_GAL) {
		for (auto ptr : pbase->gal_list) {
			if (!ab_tree_match_node(ptr, codepage, pfilter))
				continue;
			psnode1 = cu_alloc<SINGLE_LIST_NODE>();
			if (NULL == psnode1) {
				return FALSE;
			}
			psnode1->pdata = ptr;
			single_list_append_as_tail(&temp_list, psnode1);
		}
	} else {
		auto pnode = ab_tree_minid_to_node(pbase, container_id);
		if (pnode == nullptr ||
		    (pnode = pnode->get_child()) == nullptr) {
			pminids->count = 0;
			pminids->pl = NULL;
			return TRUE;
		}
		do {
			if (ab_tree_get_node_type(pnode) >= abnode_type::containers)
				continue;
			if (!ab_tree_match_node(pnode, codepage, pfilter))
				continue;
			psnode1 = cu_alloc<SINGLE_LIST_NODE>();
			if (NULL == psnode1) {
				return FALSE;
			}
			psnode1->pdata = const_cast<SIMPLE_TREE_NODE *>(pnode);
			single_list_append_as_tail(&temp_list, psnode1);
		} while ((pnode = pnode->get_sibling()) != nullptr);
	}
	pminids->count = single_list_get_nodes_num(&temp_list);
	if (0 == pminids->count) {
		pminids->pl = NULL;
	} else {
		pminids->pl = cu_alloc<uint32_t>(pminids->count);
		if (NULL == pminids->pl) {
			pminids->count = 0;
			return FALSE;
		}
	}
	count = 0;
	for (auto psnode = single_list_get_head(&temp_list); psnode != nullptr;
		psnode=single_list_get_after(&temp_list, psnode),count++) {
		pminids->pl[count] = ab_tree_get_node_minid(static_cast<const SIMPLE_TREE_NODE *>(psnode->pdata));
	}
	return TRUE;
}

void ab_tree_invalidate_cache()
{
	printf("[zcore]: Invalidating AB caches\n");
	std::unique_lock bl_hold(g_base_lock);
	for (auto &kvpair : g_base_hash)
		kvpair.second.load_time = 0;
}
