// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <unistd.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/clock.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "object_tree.h"
#include "objects.hpp"
#include "store_object.h"
#include "system_services.hpp"
#include "table_object.h"
#include "zserver.hpp"

enum {
	PROP_TAG_PROFILESCLSID = PROP_TAG(PT_CLSID, 0x0048),
};

using namespace gromox;

namespace {

struct root_object {
	~root_object();
	BOOL b_touched = false;
	char *maildir = nullptr;
	TPROPVAL_ARRAY *pprivate_proplist = nullptr;
	TARRAY_SET *pprof_set = nullptr;
};

}

unsigned int zcore_max_obh_per_session = 500;

root_object::~root_object()
{
	free(maildir);
	if (pprivate_proplist != nullptr)
		tpropval_array_free(pprivate_proplist);
	if (pprof_set != nullptr)
		tarray_set_free(pprof_set);
}

static errno_t object_tree_deserialize(root_object &root,
    const void *buf, size_t size)
{
	EXT_PULL ep;
	TPROPVAL_ARRAY propvals;

	ep.init(buf, size, common_util_alloc, EXT_FLAG_WCOUNT);
	if (ep.g_tpropval_a(&propvals) != pack_result::success)
		return EINVAL;
	root.pprivate_proplist = propvals.dup();
	if (root.pprivate_proplist == nullptr)
		return ENOMEM;

	TARRAY_SET prof_set;
	if (ep.g_tarray_set(&prof_set) != pack_result::success)
		return EINVAL;
	root.pprof_set = prof_set.dup();
	if (root.pprof_set == nullptr)
		return ENOMEM;
	return 0;
}

static std::unique_ptr<root_object>
object_tree_init_root(const char *maildir) try
{
	auto prootobj = std::make_unique<root_object>();
	prootobj->maildir = strdup(maildir);
	if (prootobj->maildir == nullptr)
		return NULL;
	prootobj->b_touched = FALSE;
	auto bv = cu_read_storenamedprop(maildir, PSETID_GROMOX,
	          "zcore_profsect", PT_BINARY);
	if (bv != nullptr && object_tree_deserialize(*prootobj, bv->pb, bv->cb) == 0)
		return prootobj;

	char tmp_path[256];
	struct stat node_stat;

	snprintf(tmp_path, std::size(tmp_path), "%s/config/zarafa.dat", maildir);
	wrapfd fd = open(tmp_path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0) {
		prootobj->pprivate_proplist = tpropval_array_init();
		if (prootobj->pprivate_proplist == nullptr)
			return NULL;
		prootobj->pprof_set = tarray_set_init();
		if (prootobj->pprof_set == nullptr)
			return NULL;
		return prootobj;
	}
	auto pbuff = std::make_unique<char[]>(node_stat.st_size);
	if (pbuff == nullptr)
		return NULL;
	if (read(fd.get(), pbuff.get(), node_stat.st_size) != node_stat.st_size)
		return NULL;
	if (object_tree_deserialize(*prootobj, pbuff.get(), node_stat.st_size) != 0)
		return NULL;
	return prootobj;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1099: ENOMEM");
	return nullptr;
}

static void object_tree_write_root(root_object *prootobj)
{
	EXT_PUSH ext_push;
	
	if (!prootobj->b_touched ||
	    !ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT) ||
	    ext_push.p_tpropval_a(*prootobj->pprivate_proplist) != EXT_ERR_SUCCESS ||
	    ext_push.p_tarray_set(*prootobj->pprof_set) != EXT_ERR_SUCCESS)
		return;
	cu_write_storenamedprop(prootobj->maildir, PSETID_GROMOX,
		"zcore_profsect", PT_BINARY, ext_push.m_udata, ext_push.m_offset);
}

static void object_tree_free_root(root_object *prootobj)
{
	object_tree_write_root(prootobj);
	delete prootobj;
}

object_node::object_node(object_node &&o) noexcept :
	handle(o.handle), type(o.type), pobject(o.pobject)
{
	o.handle = INVALID_HANDLE;
	o.type = zs_objtype::invalid;
	o.pobject = nullptr;
}

object_node::~object_node()
{
	switch (type) {
	case zs_objtype::root:
		object_tree_free_root(static_cast<root_object *>(pobject));
		break;
	case zs_objtype::table:
		delete static_cast<table_object *>(pobject);
		break;
	case zs_objtype::message:
		delete static_cast<message_object *>(pobject);
		break;
	case zs_objtype::attach:
		delete static_cast<attachment_object *>(pobject);
		break;
	case zs_objtype::abcont:
		delete static_cast<container_object *>(pobject);
		break;
	case zs_objtype::folder:
		delete static_cast<folder_object *>(pobject);
		break;
	case zs_objtype::store:
		delete static_cast<store_object *>(pobject);
		break;
	case zs_objtype::mailuser:
	case zs_objtype::distlist:
		delete static_cast<user_object *>(pobject);
		break;
	case zs_objtype::oneoff:
		delete static_cast<oneoff_object *>(pobject);
		break;
	case zs_objtype::profproperty:
		/* do not free TPROPVAL_ARRAY,
		it's an element of pprof_set */
		break;
	case zs_objtype::icsdownctx:
		delete static_cast<icsdownctx_object *>(pobject);
		break;
	case zs_objtype::icsupctx:
		delete static_cast<icsupctx_object *>(pobject);
		break;
	default:
		break;
	}
}

static void object_tree_release_objnode(
	OBJECT_TREE *pobjtree, OBJECT_NODE *pobjnode)
{	
	simple_tree_enum_from_node(&pobjnode->node, [&](const tree_node *n, unsigned int) {
		pobjtree->m_hash.erase(static_cast<const OBJECT_NODE *>(n->pdata)->handle);
	});
	pobjtree->tree.destroy_node(&pobjnode->node, [](SIMPLE_TREE_NODE *n) {
		delete static_cast<OBJECT_NODE *>(n->pdata);
	});
}

OBJECT_TREE::~OBJECT_TREE()
{
	auto pobjtree = this;
	auto proot = tree.get_root();
	if (proot != nullptr)
		object_tree_release_objnode(pobjtree, static_cast<OBJECT_NODE *>(proot->pdata));
	pobjtree->tree.clear();
}

uint32_t OBJECT_TREE::add_object_handle(int parent_handle, object_node &&obnode)
{
	auto pobjtree = this;
	OBJECT_NODE *parent_ptr = nullptr;
	
	if (zcore_max_obh_per_session &&
	    pobjtree->tree.get_nodes_num() > zcore_max_obh_per_session)
		return ecZOutOfHandles;
	if (parent_handle < 0) {
		if (pobjtree->tree.get_root() != nullptr)
			return ecZNullObject;
		parent_ptr = nullptr;
	} else {
		auto i = pobjtree->m_hash.find(parent_handle);
		if (i == pobjtree->m_hash.end())
			return ecZNullObject;
		parent_ptr = i->second;
	}
	OBJECT_NODE *pobjnode;
	try {
		pobjnode = new object_node(std::move(obnode));
	} catch (const std::bad_alloc &) {
		return ecMAPIOOM;
	}
	if (parent_handle < 0) {
		pobjnode->handle = ROOT_HANDLE;
	} else {
		if (pobjtree->last_handle >= INT32_MAX)
			pobjtree->last_handle = 0;
		pobjtree->last_handle ++;
		pobjnode->handle = pobjtree->last_handle;
	}
	pobjnode->node.pdata = pobjnode;
	try {
		pobjtree->m_hash.try_emplace(pobjnode->handle, pobjnode);
	} catch (const std::bad_alloc &) {
		delete pobjnode;
		return ecMAPIOOM;
	}
	if (parent_ptr == nullptr)
		pobjtree->tree.set_root(&pobjnode->node);
	else
		pobjtree->tree.add_child(&parent_ptr->node,
			&pobjnode->node, SIMPLE_TREE_ADD_LAST);
	return pobjnode->handle;
}

std::unique_ptr<OBJECT_TREE> object_tree_create(const char *maildir)
{
	std::unique_ptr<OBJECT_TREE> pobjtree;
	try {
		pobjtree = std::make_unique<OBJECT_TREE>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pobjtree->last_handle = 0;
	auto prootobj = object_tree_init_root(maildir);
	if (prootobj == nullptr)
		return NULL;
	auto handle = pobjtree->add_object_handle(-1, {zs_objtype::root, std::move(prootobj)});
	if (zh_error(handle))
		return nullptr;
	return pobjtree;
}

void *OBJECT_TREE::get_object1(uint32_t obj_handle, zs_objtype *ptype)
{
	if (obj_handle > INT32_MAX)
		return NULL;
	auto pobjtree = this;
	auto iter = pobjtree->m_hash.find(obj_handle);
	if (iter == pobjtree->m_hash.end())
		return NULL;
	*ptype = iter->second->type;
	return iter->second->pobject;
}

void OBJECT_TREE::release_object_handle(uint32_t obj_handle)
{
	if (obj_handle == ROOT_HANDLE || obj_handle > INT32_MAX)
		return;
	auto pobjtree = this;
	auto iter = pobjtree->m_hash.find(obj_handle);
	/* do not release store object until
	the whole object tree is unloaded */
	if (iter == pobjtree->m_hash.end() || iter->second->type == zs_objtype::store)
		return;
	object_tree_release_objnode(pobjtree, iter->second);
}

void *OBJECT_TREE::get_zstore_propval(uint32_t proptag)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (proot == nullptr)
		return NULL;
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	return prootobj->pprivate_proplist->getval(proptag);
}

BOOL OBJECT_TREE::set_zstore_propval(const TAGGED_PROPVAL *ppropval)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (proot == nullptr)
		return FALSE;
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	auto ret = prootobj->pprivate_proplist->set(*ppropval);
	if (ret != 0)
		return false;
	/*
	 * g-web touches PR_EC_WEBACCESS_SETTINGS_JSON every now and then even
	 * if just browsing one's store/settings panel. Occurrence seems still
	 * acceptable that we may not need to add an age check.
	 */
	object_tree_write_root(prootobj);
	return TRUE;
}

void OBJECT_TREE::remove_zstore_propval(uint32_t proptag)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (proot == nullptr)
		return;
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	prootobj->pprivate_proplist->erase(proptag);
	object_tree_write_root(prootobj);
}

TPROPVAL_ARRAY *OBJECT_TREE::get_profile_sec(GUID sec_guid)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (proot == nullptr)
		return NULL;
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	for (size_t i = 0; i < prootobj->pprof_set->count; ++i) {
		auto pguid = prootobj->pprof_set->pparray[i]->get<GUID>(PROP_TAG_PROFILESCLSID);
		if (pguid == nullptr)
			continue;
		if (*pguid == sec_guid)
			return prootobj->pprof_set->pparray[i];
	}
	tpropval_array_ptr pproplist(tpropval_array_init());
	if (pproplist == nullptr)
		return NULL;
	if (pproplist->set(PROP_TAG_PROFILESCLSID, &sec_guid) != 0 ||
	    prootobj->pprof_set->append_move(std::move(pproplist)) != 0)
		return NULL;
	return prootobj->pprof_set->back();
}

void OBJECT_TREE::touch_profile_sec()
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (proot == nullptr)
		return;
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	object_tree_write_root(prootobj);
}

uint32_t OBJECT_TREE::get_store_handle(BOOL b_private, int account_id)
{
	auto pobjtree = this;
	char dir[256];
	char account[UADDR_SIZE];
	
	auto pnode = pobjtree->tree.get_root();
	if (pnode == nullptr)
		return ecZNullObject;
	pnode = pnode->get_child();
	if (NULL != pnode) {
		do {
			auto pobjnode = static_cast<OBJECT_NODE *>(pnode->pdata);
			if (pobjnode->type != zs_objtype::store)
				continue;
			auto store = static_cast<store_object *>(pobjnode->pobject);
			if (store->b_private == b_private &&
			    store->account_id == account_id)
				return pobjnode->handle;	
		} while ((pnode = pnode->get_sibling()) != nullptr);
	}
	auto pinfo = zs_get_info();
	if (b_private) {
		if (account_id == pinfo->user_id) {
			gx_strlcpy(dir, pinfo->get_maildir(), std::size(dir));
			gx_strlcpy(account, pinfo->get_username(), std::size(account));
		} else {
			if (!system_services_get_username_from_id(account_id,
			    account, std::size(account)) ||
			    !system_services_get_maildir(account, dir, std::size(dir)))
				return ecZNullObject;
		}
	} else {
		if (account_id != pinfo->domain_id)
			return ecZNullObject;
		gx_strlcpy(dir, pinfo->get_homedir(), std::size(dir));
		auto pdomain = strchr(pinfo->get_username(), '@');
		if (pdomain == nullptr)
			return ecZNullObject;
		pdomain ++;
		gx_strlcpy(account, pdomain, std::size(account));
	}
	auto pstore = store_object::create(b_private, account_id, account, dir);
	if (pstore == nullptr)
		return ecMAPIOOM;
	return add_object_handle(ROOT_HANDLE, {zs_objtype::store, std::move(pstore)});
}
