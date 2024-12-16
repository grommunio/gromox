// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
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
#include <optional>
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
#include <gromox/clock.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/gab.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/process.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "ab_tree.hpp"
#include "common_util.hpp"
#include "objects.hpp"
#include "system_services.hpp"
#include "zserver.hpp"

#define EPOCH_DIFF 							11644473600LL

#define BASE_STATUS_CONSTRUCTING			0
#define BASE_STATUS_LIVING					1
#define BASE_STATUS_DESTRUCTING				2

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

/* See NSAB_NODE for commentary. */
struct ZAB_NODE {
	ZAB_NODE() = default;
	~ZAB_NODE();
	NOMOVE(ZAB_NODE);

	SIMPLE_TREE_NODE stree{};
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
static gromox::time_duration g_ab_cache_interval;
static gromox::atomic_bool g_notify_stop;
static pthread_t g_scan_id;
static char g_zcab_org_name[256];
static std::unordered_map<int, AB_BASE> g_base_hash;
static std::mutex g_base_lock;

static void *zcoreab_scanwork(void *);
static void ab_tree_get_display_name(const SIMPLE_TREE_NODE *, cpid_t codepage, char *str_dname, size_t dn_size);
static const char *ab_tree_get_user_info(const tree_node *, unsigned int type);

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
	if (!(minid & 0x80000000))
		return minid_type::address;
	auto type = static_cast<minid_type>(minid >> 29);
	return type == minid_type::reserved ? minid_type::address : type;
}

uint32_t ab_tree_get_minid_value(uint32_t minid)
{
	if (!(minid & 0x80000000))
		return minid;
	return minid & 0x1FFFFFFF;
}

static AB_NODE* ab_tree_get_abnode()
{
	return new(std::nothrow) AB_NODE;
}

ZAB_NODE::~ZAB_NODE()
{
	auto pabnode = this;
	switch (pabnode->node_type) {
	case abnode_type::domain:
		delete static_cast<sql_domain *>(pabnode->d_info);
		break;
	case abnode_type::user:
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
}

const SIMPLE_TREE_NODE *
ab_tree_minid_to_node(const AB_BASE *pbase, uint32_t minid)
{
	auto iter = pbase->phash.find(minid);
	return iter != pbase->phash.end() ? &iter->second->stree : nullptr;
}

void ab_tree_init(const char *org_name, int base_size, int cache_interval)
{
	gx_strlcpy(g_zcab_org_name, org_name, std::size(g_zcab_org_name));
	g_base_size = base_size;
	g_ab_cache_interval = std::chrono::seconds(cache_interval);
	g_notify_stop = true;
}

int ab_tree_run()
{
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, zcoreab_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "zcore: failed to create scanning thread: %s", strerror(ret));
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
			delete containerof(nd, AB_NODE, stree);
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

static bool ab_tree_cache_node(AB_BASE *pbase, AB_NODE *pabnode) try
{
	pbase->phash.emplace(pabnode->minid, pabnode);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1550: ENOMEM");
	return false;
}

static BOOL ab_tree_load_user(AB_NODE *pabnode, sql_user &&usr, AB_BASE *pbase)
{
	pabnode->node_type = abnode_type::user;
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

static BOOL ab_tree_load_tree(int domain_id,
	SIMPLE_TREE *ptree, AB_BASE *pbase)
{
	int rows;
	AB_NODE *pabnode;
	sql_domain dinfo;
	
	if (!mysql_adaptor_get_domain_info(domain_id, dinfo))
		return FALSE;
	pabnode = ab_tree_get_abnode();
	if (pabnode == nullptr)
		return FALSE;
	pabnode->node_type = abnode_type::domain;
	pabnode->id = domain_id;
	pabnode->minid = ab_tree_make_minid(minid_type::domain, domain_id);
	utf8_filter(dinfo.name.data());
	utf8_filter(dinfo.title.data());
	utf8_filter(dinfo.address.data());
	pabnode->d_info = new(std::nothrow) sql_domain(std::move(dinfo));
	if (pabnode->d_info == nullptr) {
		delete pabnode;
		return false;
	}
	auto pdomain = &pabnode->stree;
	ptree->set_root(pdomain);
	if (!ab_tree_cache_node(pbase, pabnode))
		return false;

	std::vector<sql_group> file_group;
	if (!mysql_adaptor_get_domain_groups(domain_id, file_group))
		return FALSE;
	for (auto &&grp : file_group) {
		pabnode = ab_tree_get_abnode();
		if (pabnode == nullptr)
			return FALSE;
		pabnode->node_type = abnode_type::group;
		pabnode->id = grp.id;
		pabnode->minid = ab_tree_make_minid(minid_type::group, grp.id);
		auto grp_id = grp.id;
		pabnode->d_info = new(std::nothrow) sql_group(std::move(grp));
		if (pabnode->d_info == nullptr) {
			delete pabnode;
			return false;
		}
		auto pgroup = &pabnode->stree;
		ptree->add_child(pdomain, pgroup, SIMPLE_TREE_ADD_LAST);
		if (!ab_tree_cache_node(pbase, pabnode))
			return false;
		
		std::vector<sql_user> file_user;
		rows = mysql_adaptor_get_group_users(grp_id, file_user);
		if (rows == -1)
			return FALSE;
		else if (rows == 0)
			continue;
		std::vector<sort_item> parray;
		auto cl_array = make_scope_exit([&parray]() {
			for (const auto &e : parray)
				delete containerof(e.pnode, AB_NODE, stree);
		});
		for (auto &&usr : file_user) {
			pabnode = ab_tree_get_abnode();
			if (pabnode == nullptr)
				return false;
			if (usr.dtypx == DT_DISTLIST) {
				if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
					delete pabnode;
					return false;
				}
			} else {
				if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
					delete pabnode;
					return false;
				}
			}
			char temp_buff[1024];
			ab_tree_get_display_name(&pabnode->stree, CP_UTF8,
				temp_buff, std::size(temp_buff));
			try {
				parray.push_back(sort_item{&pabnode->stree, temp_buff});
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1671: ENOMEM");
				delete pabnode;
				return false;
			}
		}
		std::sort(parray.begin(), parray.end());
		for (int i = 0; i < rows; ++i)
			ptree->add_child(pgroup, parray[i].pnode, SIMPLE_TREE_ADD_LAST);
		cl_array.release();
	}

	std::vector<sql_user> file_user;
	rows = mysql_adaptor_get_domain_users(domain_id, file_user);
	if (rows == -1)
		return FALSE;
	else if (rows == 0)
		return TRUE;
	std::vector<sort_item> parray;
	auto cl_array = make_scope_exit([&parray]() {
		for (const auto &e : parray)
			delete containerof(e.pnode, AB_NODE, stree);
	});
	for (auto &&usr : file_user) {
		pabnode = ab_tree_get_abnode();
		if (pabnode == nullptr)
			return false;
		if (usr.dtypx == DT_DISTLIST) {
			if (!ab_tree_load_mlist(pabnode, std::move(usr), pbase)) {
				delete pabnode;
				return false;
			}
		} else {
			if (!ab_tree_load_user(pabnode, std::move(usr), pbase)) {
				delete pabnode;
				return false;
			}
		}
		char temp_buff[1024];
		ab_tree_get_display_name(&pabnode->stree, CP_UTF8,
			temp_buff, std::size(temp_buff));
		try {
			parray.push_back(sort_item{&pabnode->stree, temp_buff});
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1672: ENOMEM");
			delete pabnode;
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
		std::vector<unsigned int> temp_file;
		if (!mysql_adaptor_get_org_domains(pbase->base_id, temp_file))
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
	pbase->gal_hidden_count = 0;
	for (auto &domain : pbase->domain_list) {
		auto pdomain = &domain;
		auto proot = pdomain->tree.get_root();
		if (proot == nullptr)
			continue;
		simple_tree_enum_from_node(proot, [&pbase](tree_node *nd, unsigned int) {
			auto node_type = ab_tree_get_node_type(nd);
			if (node_type >= abnode_type::containers || nd->pdata != nullptr)
				return;
			if (ab_tree_hidden(nd) & AB_HIDE_FROM_GAL)
				++pbase->gal_hidden_count;
			pbase->gal_list.push_back(nd);
		});
	}
	if (pbase->gal_list.size() <= 1)
		return TRUE;
	std::vector<sort_item> parray;
	for (auto ptr : pbase->gal_list) {
		ab_tree_get_display_name(ptr, CP_UTF8, temp_buff, std::size(temp_buff));
		parray.push_back(sort_item{ptr, temp_buff});
	}
	std::sort(parray.begin(), parray.end());
	size_t i = 0;
	for (auto &ptr : pbase->gal_list)
		ptr = parray[i++].pnode;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1673: ENOMEM");
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
			mlog(LV_ERR, "E-1290: AB base hash is full");
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
		pbase->load_time = tp_now();
		bl_hold.lock();
		pbase->status = BASE_STATUS_LIVING;
	} else {
		pbase = &it->second;
		if (pbase->status != BASE_STATUS_LIVING) {
			bl_hold.unlock();
			count ++;
			if (count > 60)
				return nullptr;
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
		auto now = tp_now();
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
			pbase->load_time = tp_now();
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
	case abnode_type::mlist: k = 'l'; break;
	case abnode_type::user:
		switch (static_cast<const sql_user *>(pabnode->d_info)->dtypx) {
		case DT_ROOM: k = 'r'; break;
		case DT_EQUIPMENT: k = 'e'; break;
		default: k = 'p'; break;
		}
		break;
	default: return 0;
	}
	char temp_buff[HXSIZEOF_Z32+2];
	auto len = sprintf(temp_buff, "%c%d", k, pabnode->id);
	if (len >= length)
		return 0;
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
		if (len == 0)
			return FALSE;
		offset += len;
	} while ((pnode = pnode->get_parent()) != nullptr);
	return TRUE;
}

static bool ab_tree_md5_path(const char *path, uint64_t *pdgt) __attribute__((warn_unused_result));
static bool ab_tree_md5_path(const char *path, uint64_t *pdgt)
{
	uint8_t dgt_buff[MD5_DIGEST_LENGTH];
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr ||
	    EVP_DigestInit(ctx.get(), EVP_md5()) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), path, strlen(path)) <= 0 ||
	    EVP_DigestFinal(ctx.get(), dgt_buff, nullptr) <= 0)
		return false;
	memcpy(pdgt, dgt_buff, 8);
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
	tmp_enum.item_id = (((int)guid.time_hi_and_version) << 16) | guid.time_mid;
	memcpy(&tmp_enum.dgt, reinterpret_cast<char *>(&guid) + 8, 8);
	tmp_enum.pabnode = NULL;
	const SIMPLE_TREE_NODE *ptnode = pdomain->tree.get_root();
	if (NULL == ptnode) {
		return NULL;
	}
	simple_tree_enum_from_node(ptnode, [&tmp_enum](const tree_node *pnode, unsigned int) {
		char temp_path[512];
		auto abn = containerof(pnode, AB_NODE, stree);
		if (tmp_enum.pabnode != nullptr ||
		    abn->node_type != tmp_enum.node_type ||
		    abn->id != tmp_enum.item_id)
			return;
		ab_tree_node_to_path(pnode, temp_path, std::size(temp_path));
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
	    pnode->pdata != nullptr) {
		if (pnode == pnode->pdata) {
			mlog(LV_WARN, "W-1197: Self-referencing ZAB_NODE");
			return false;
		}
		return ab_tree_node_to_guid(static_cast<const SIMPLE_TREE_NODE *>(pnode->pdata), pguid);
	}
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
	ab_tree_node_to_path(&pabnode->stree, temp_path, std::size(temp_path));
	if (!ab_tree_md5_path(temp_path, &dgt))
		return false;
	memcpy(reinterpret_cast<char *>(pguid) + 8, &dgt, 8);
	return true;
}

static BOOL ab_tree_node_to_dn(const SIMPLE_TREE_NODE *pnode,
    char *pbuff, int length) try
{
	int id;
	GUID guid;
	AB_BASE_REF pbase;
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
		memcpy(pbuff, "/guid=", 6);
		guid.to_str(&pbuff[6], 32);
		pbuff[38] = '\0';
		break;
	case abnode_type::user: {
		id = pabnode->id;
		auto username = znul(ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS));
		while ((pnode = pnode->get_parent()) != nullptr)
			pabnode = containerof(pnode, AB_NODE, stree);
		if (pabnode->node_type != abnode_type::domain)
			return FALSE;
		std::string essdn;
		if (cvt_username_to_essdn(username, g_zcab_org_name, id,
		    pabnode->id, essdn) != ecSuccess)
			return false;
		gx_strlcpy(pbuff, essdn.c_str(), length);
		break;
	}
	case abnode_type::mlist: {
		id = pabnode->id;
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		while ((pnode = pnode->get_parent()) != nullptr)
			pabnode = containerof(pnode, AB_NODE, stree);
		if (pabnode->node_type != abnode_type::domain)
			return FALSE;
		std::string essdn;
		if (cvt_username_to_essdn(obj->username.c_str(), g_zcab_org_name, id,
		    pabnode->id, essdn) != ecSuccess)
			return false;
		gx_strlcpy(pbuff, essdn.c_str(), length);
		break;
	}
	default:
		return FALSE;
	}
	return TRUE;	
} catch (const std::bad_alloc &) {
	return false;
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
    cpid_t codepage, char *str_dname, size_t dn_size)
{
	char *ptoken;
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
	case abnode_type::user:
	case abnode_type::mlist: {
		auto obj = static_cast<sql_user *>(pabnode->d_info);
		auto it = obj->propvals.find(PR_DISPLAY_NAME);
		if (it != obj->propvals.cend()) {
			gx_strlcpy(str_dname, it->second.c_str(), dn_size);
			break;
		}
		gx_strlcpy(str_dname, obj->username.c_str(), dn_size);
		ptoken = strchr(str_dname, '@');
		if (ptoken != nullptr)
			*ptoken = '\0';
		break;
	}
	default:
		break;
	}
}

static const std::vector<std::string> &
ab_tree_get_object_aliases(const tree_node *pnode)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	return static_cast<const sql_user *>(pabnode->d_info)->aliases;
}

static const char *ab_tree_get_user_info(const tree_node *pnode, unsigned int type)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (pabnode->node_type != abnode_type::user &&
	    pabnode->node_type != abnode_type::remote &&
	    pabnode->node_type != abnode_type::mlist)
		return nullptr;
	auto u = static_cast<const sql_user *>(pabnode->d_info);
	unsigned int tag = 0;
	switch (type) {
	case USER_MAIL_ADDRESS:
		if ((u->dtypx & DTE_MASK_LOCAL) == DT_REMOTE_MAILUSER) {
			tag = PR_SMTP_ADDRESS;
			break;
		}
		return u->username.c_str();
	case USER_REAL_NAME: tag = PR_DISPLAY_NAME; break;
	case USER_JOB_TITLE: tag = PR_TITLE; break;
	case USER_COMMENT: tag = PR_COMMENT; break;
	case USER_MOBILE_TEL: tag = PR_MOBILE_TELEPHONE_NUMBER; break;
	case USER_BUSINESS_TEL: tag = PR_PRIMARY_TELEPHONE_NUMBER; break;
	case USER_NICK_NAME: tag = PR_NICKNAME; break;
	case USER_HOME_ADDRESS: tag = PR_HOME_ADDRESS_STREET; break;
	case USER_STORE_PATH: return u->maildir.c_str();
	}
	if (tag == 0)
		return nullptr;
	auto it = u->propvals.find(tag);
	return it != u->propvals.cend() ? it->second.c_str() : "";
}

static void ab_tree_get_mlist_info(const SIMPLE_TREE_NODE *pnode,
	char *mail_address, char *create_day, int *plist_privilege)
{
	auto pabnode = containerof(pnode, AB_NODE, stree);
	if (pabnode->node_type != abnode_type::mlist &&
	    pabnode->node_type != abnode_type::remote) {
		if (mail_address != nullptr)
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

static void ab_tree_get_company_info(const SIMPLE_TREE_NODE *pnode,
	char *str_name, char *str_address)
{
	AB_BASE_REF pbase;
	auto pabnode = containerof(pnode, AB_NODE, stree);
	
	if (pabnode->node_type == abnode_type::remote) {
		pbase = ab_tree_get_base(-pabnode->id);
		if (pbase == nullptr) {
			if (str_name != nullptr)
				str_name[0] = '\0';
			if (str_address != nullptr)
				str_address[0] = '\0';
			return;
		}
		auto iter = pbase->phash.find(pabnode->minid);
		if (iter == pbase->phash.end()) {
			if (str_name != nullptr)
				str_name[0] = '\0';
			if (str_address != nullptr)
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
	if (pnode == nullptr)
		return FALSE;
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
	if (node_type != abnode_type::user && node_type != abnode_type::mlist)
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
			return ecServerOOM;
		strcpy(static_cast<char *>(*prop), it->second.c_str());
		return ecSuccess;
	case PT_BINARY: {
		*prop = cu_alloc<BINARY>();
		if (*prop == nullptr)
			return ecServerOOM;
		auto bv = static_cast<BINARY *>(*prop);
		bv->cb = it->second.size();
		bv->pv = common_util_alloc(it->second.size());
		if (bv->pv == nullptr)
			return ecServerOOM;
		memcpy(bv->pv, it->second.data(), bv->cb);
		return ecSuccess;
	}
	case PT_MV_UNICODE: {
		*prop = cu_alloc<STRING_ARRAY>();
		if (*prop == nullptr)
			return ecServerOOM;
		auto sa = static_cast<STRING_ARRAY *>(*prop);
		sa->count = 1;
		sa->ppstr = cu_alloc<char *>();
		if (sa->ppstr == nullptr)
			return ecServerOOM;
		sa->ppstr[0] = cu_alloc<char>(it->second.size() + 1);
		if (sa->ppstr[0] == nullptr)
			return ecServerOOM;
		strcpy(sa->ppstr[0], it->second.c_str());
		return ecSuccess;
	}
	}
	return ecNotFound;
}

static uint32_t ab_tree_get_dtyp(const tree_node *n)
{
	auto &a = *containerof(n, AB_NODE, stree);
	if (a.node_type >= abnode_type::containers)
		return DT_CONTAINER;
	else if (a.node_type == abnode_type::mlist)
		return DT_DISTLIST;
	else if (a.node_type == abnode_type::folder)
		return DT_FORUM;
	else if (a.node_type != abnode_type::user)
		return DT_MAILUSER;
	auto &obj = *static_cast<const sql_user *>(a.d_info);
	if (obj.dtypx == DT_REMOTE_MAILUSER)
		return DT_REMOTE_MAILUSER;
	return DT_MAILUSER;
}

static uint32_t ab_tree_get_etyp(const tree_node *n)
{
	/* cloned from/to nsp/ab_tree.cpp */
	auto &a = *containerof(n, AB_NODE, stree);
	if (a.node_type >= abnode_type::containers)
		return DT_CONTAINER;
	else if (a.node_type == abnode_type::mlist)
		return DT_DISTLIST;
	else if (a.node_type != abnode_type::user)
		return DT_MAILUSER;
	return dtypx_to_etyp(static_cast<const sql_user *>(a.d_info)->dtypx);
}

static std::optional<uint32_t> ab_tree_get_dtypx(const tree_node *n)
{
	auto &a = *containerof(n, AB_NODE, stree);
	if (a.node_type >= abnode_type::containers ||
	    a.node_type == abnode_type::folder)
		return {};
	else if (a.node_type == abnode_type::mlist)
		return {DT_DISTLIST | DTE_FLAG_ACL_CAPABLE};
	else if (a.node_type != abnode_type::user)
		return {DT_MAILUSER};
	auto &obj = *static_cast<const sql_user *>(a.d_info);
	if (obj.dtypx == DT_REMOTE_MAILUSER)
		return {DT_REMOTE_MAILUSER};
	/*
	 * In Gromox, (almost) everything with a username is capable of being
	 * used in an ACL (and usernames are mandatory currently).
	 */
	return {(obj.dtypx & DTE_MASK_LOCAL) | DTE_FLAG_ACL_CAPABLE};
}

/* Returns: TRUE (success or notfound), FALSE (fatal error/enomem/etc.) */
static BOOL ab_tree_fetch_node_property(const SIMPLE_TREE_NODE *pnode,
    cpid_t codepage, uint32_t proptag, void **ppvalue)
{
	int minid;
	char dn[1280]{};
	GUID temp_guid;
	EXT_PUSH ext_push;
	EMSAB_ENTRYID ab_entryid;
	
	*ppvalue = nullptr;
	auto node_type = ab_tree_get_node_type(pnode);
	/* Properties that need to be force-generated */
	switch (proptag) {
	case PR_AB_PROVIDER_ID: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return FALSE;
		*ppvalue = bv;
		bv->cb = sizeof(muidECSAB);
		bv->pv = deconst(&muidECSAB);
		return TRUE;
	}
	case PR_CONTAINER_FLAGS: {
		if (node_type < abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<uint32_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(pvalue) = !ab_tree_has_child(pnode) ?
			AB_RECIPIENTS | AB_UNMODIFIABLE :
			AB_RECIPIENTS | AB_SUBCONTAINERS | AB_UNMODIFIABLE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_DEPTH: {
		if (node_type < abnode_type::containers)
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = pnode->get_depth() + 1;
		*ppvalue = v;
		return TRUE;
	}
	case PR_EMS_AB_IS_MASTER: {
		if (node_type < abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<uint8_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint8_t *>(pvalue) = 0;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_HOME_MDB: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		auto xab = containerof(pnode, AB_NODE, stree);
		if (xab->node_type >= abnode_type::containers)
			return ecNotFound;
		auto username = znul(ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS));
		auto id = xab->node_type == abnode_type::remote ?
		          ab_tree_get_minid_value(xab->minid) : xab->id;
		std::string mdbdn;
		auto err = cvt_username_to_mdbdn(username, g_zcab_org_name, id, mdbdn);
		if (err != ecSuccess)
			return false;
		auto pvalue = common_util_dup(mdbdn.c_str());
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_OBJECT_GUID: {
		if (!ab_tree_node_to_guid(pnode, &temp_guid))
			return false;
		auto pvalue = common_util_guid_to_binary(temp_guid);
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_CONTAINERID: {
		auto pvalue = cu_alloc<uint32_t>();
		if (pvalue == nullptr)
			return FALSE;
		if (node_type >= abnode_type::containers) {
			*static_cast<uint32_t *>(pvalue) = ab_tree_get_node_minid(pnode);
		} else {
			pnode = pnode->get_parent();
			*static_cast<uint32_t *>(pvalue) = pnode == nullptr ? 0 :
				ab_tree_get_node_minid(pnode);
		}
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_ADDRTYPE:
		if (node_type >= abnode_type::containers)
			return TRUE;
		*ppvalue = deconst("EX");
		return TRUE;
	case PR_EMAIL_ADDRESS: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
			return FALSE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		auto t = node_type >= abnode_type::containers ? MAPI_ABCONT :
		         node_type == abnode_type::mlist ? MAPI_DISTLIST :
		         node_type == abnode_type::folder ? MAPI_FOLDER : MAPI_MAILUSER;
		*v = static_cast<uint32_t>(t);
		*ppvalue = v;
		return TRUE;
	}
	case PR_DISPLAY_TYPE: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = ab_tree_get_dtyp(pnode);
		*ppvalue = v;
		return TRUE;
	}
	case PR_DISPLAY_TYPE_EX: {
		auto dtypx = ab_tree_get_dtypx(pnode);
		if (!dtypx.has_value())
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = *dtypx;
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
		if (pnode == nullptr)
			return TRUE;
		return ab_tree_fetch_node_property(
			pnode, codepage, proptag, ppvalue);
	case PR_ENTRYID:
	case PR_RECORD_KEY:
	case PR_TEMPLATEID:
	case PR_ORIGINAL_ENTRYID: {
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		ab_entryid.flags = 0;
		ab_entryid.type = ab_tree_get_etyp(pnode);
		if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
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
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
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
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		bv->cb = 4;
		bv->pv = common_util_alloc(4);
		if (bv->pv == nullptr)
			return FALSE;
		minid = ab_tree_get_node_minid(pnode);
		cpu_to_le32p(bv->pb, minid);
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_TRANSMITABLE_DISPLAY_NAME:
		if (node_type >= abnode_type::containers)
			return TRUE;
		[[fallthrough]];
	case PR_DISPLAY_NAME:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE: {
		ab_tree_get_display_name(pnode, codepage, dn, std::size(dn));
		if (*dn == '\0')
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_COMPANY_NAME: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		ab_tree_get_company_info(pnode, dn, NULL);
		if (*dn == '\0')
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_DEPARTMENT_NAME: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		ab_tree_get_department_name(pnode, dn);
		if (*dn == '\0')
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_ACCOUNT:
	case PR_SMTP_ADDRESS: {
		if (node_type == abnode_type::mlist)
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		else if (node_type == abnode_type::user)
			gx_strlcpy(dn, znul(ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS)), sizeof(dn));
		else
			return TRUE;
		if (*dn == '\0')
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_PROXY_ADDRESSES: {
		if (node_type == abnode_type::mlist)
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		else if (node_type == abnode_type::user)
			gx_strlcpy(dn, znul(ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS)), sizeof(dn));
		else
			return TRUE;
		if (*dn == '\0')
			return TRUE;
		auto alias_list = ab_tree_get_object_aliases(pnode);
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
	case PR_EMS_AB_THUMBNAIL_PHOTO: {
		auto path = ab_tree_get_user_info(pnode, USER_STORE_PATH);
		if (path == nullptr)
			return TRUE;
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(cu_read_storenamedprop(path,
		          PSETID_Gromox, "photo", PT_BINARY));
		if (bv != nullptr) {
			*ppvalue = bv;
			return TRUE;
		}
		gx_strlcpy(dn, path, sizeof(dn));
		HX_strlcat(dn, "/config/portrait.jpg", std::size(dn));
		if (!common_util_load_file(dn, pvalue))
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	}
	/* User-defined props */
	if (node_type == abnode_type::user || node_type == abnode_type::mlist) {
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
	case PR_SEND_RICH_INFO: {
		if (node_type >= abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<uint8_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint8_t *>(pvalue) = 1;
		*ppvalue = pvalue;
		return TRUE;
	}
	}
	return TRUE;
}

BOOL ab_tree_fetch_node_properties(const SIMPLE_TREE_NODE *pnode,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	auto pinfo = zs_get_info();
	ppropvals->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (!ab_tree_fetch_node_property(pnode,
		    pinfo->cpid, tag, &pvalue))
			return FALSE;	
		if (pvalue == nullptr)
			continue;
		ppropvals->emplace_back(tag, pvalue);
	}
	return TRUE;
}

static BOOL ab_tree_resolve_node(SIMPLE_TREE_NODE *pnode,
    cpid_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn, std::size(dn));
	if (strcasestr(dn, pstr) != nullptr)
		return TRUE;
	if (ab_tree_node_to_dn(pnode, dn, sizeof(dn)) && strcasecmp(dn, pstr) == 0)
		return TRUE;
	ab_tree_get_department_name(pnode, dn);
	if (strcasestr(dn, pstr) != nullptr)
		return TRUE;
	switch(ab_tree_get_node_type(pnode)) {
	case abnode_type::user: {
		auto s = ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		for (const auto &a : ab_tree_get_object_aliases(pnode))
			if (strcasestr(a.c_str(), pstr) != nullptr)
				return TRUE;
		s = ab_tree_get_user_info(pnode, USER_NICK_NAME);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_JOB_TITLE);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_COMMENT);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_MOBILE_TEL);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_BUSINESS_TEL);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_HOME_ADDRESS);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		break;
	}
	case abnode_type::mlist:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (strcasestr(dn, pstr) != nullptr)
			return TRUE;
		break;
	default:
		break;
	}
	return FALSE;
}

bool ab_tree_resolvename(AB_BASE *pbase, cpid_t codepage, const char *pstr,
    stn_list_t &result_list) try
{
	result_list.clear();
	for (auto ptr : pbase->gal_list) {
		if ((ab_tree_hidden(ptr) & AB_HIDE_RESOLVE) ||
		    !ab_tree_resolve_node(ptr, codepage, pstr))
			continue;
		result_list.push_back(ptr);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1678: ENOMEM");
	return false;
}

static bool ab_tree_match_node(const SIMPLE_TREE_NODE *pnode, cpid_t codepage,
    const RESTRICTION *pfilter)
{
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
		if (!rcon->comparable())
			return FALSE;
		if (!ab_tree_fetch_node_property(pnode, codepage,
		    rcon->proptag, &pvalue))
			return FALSE;	
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pfilter->prop;
		if (!rprop->comparable())
			return false;
		if (rprop->proptag != PR_ANR) {
			if (!ab_tree_fetch_node_property(pnode, codepage,
			    rprop->proptag, &pvalue))
				return false;
			return rprop->eval(pvalue);
		}
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
	case RES_BITMASK: {
		auto rbm = pfilter->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!ab_tree_fetch_node_property(pnode, codepage,
		    rbm->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return rbm->eval(pvalue);
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

uint32_t ab_tree_hidden(const tree_node *node)
{
	auto node_type = ab_tree_get_node_type(node);
	if (node_type != abnode_type::user && node_type != abnode_type::mlist)
		return 0;
	auto xab = containerof(node, AB_NODE, stree);
	return static_cast<const sql_user *>(xab->d_info)->hidden;
}

BOOL ab_tree_match_minids(AB_BASE *pbase, uint32_t container_id,
    cpid_t codepage, const RESTRICTION *pfilter, LONG_ARRAY *pminids) try
{
	std::vector<const tree_node *> tlist;
	
	if (container_id == SPECIAL_CONTAINER_GAL) {
		for (auto ptr : pbase->gal_list) {
			if ((ab_tree_hidden(ptr) & AB_HIDE_FROM_GAL) ||
			    !ab_tree_match_node(ptr, codepage, pfilter))
				continue;
			tlist.push_back(ptr);
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
			if (ab_tree_get_node_type(pnode) >= abnode_type::containers ||
			    (ab_tree_hidden(pnode) & AB_HIDE_FROM_AL))
				continue;
			if (!ab_tree_match_node(pnode, codepage, pfilter))
				continue;
			tlist.push_back(pnode);
		} while ((pnode = pnode->get_sibling()) != nullptr);
	}
	pminids->count = tlist.size();
	if (0 == pminids->count) {
		pminids->pl = NULL;
	} else {
		pminids->pl = cu_alloc<uint32_t>(pminids->count);
		if (NULL == pminids->pl) {
			pminids->count = 0;
			return FALSE;
		}
		size_t count = 0;
		for (auto ptr : tlist)
			pminids->pl[count++] = ab_tree_get_node_minid(ptr);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1247: ENOMEM");
	return false;
}

void ab_tree_invalidate_cache()
{
	mlog(LV_NOTICE, "zcore: Invalidating AB caches");
	std::unique_lock bl_hold(g_base_lock);
	for (auto &kvpair : g_base_hash)
		kvpair.second.load_time = {};
}
