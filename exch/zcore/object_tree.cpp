// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/clock.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/guid.hpp>
#include <gromox/mapidefs.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "container_object.h"
#include "folder_object.h"
#include "icsdownctx_object.h"
#include "icsupctx_object.h"
#include "message_object.h"
#include "object_tree.h"
#include "store_object.h"
#include "system_services.h"
#include "table_object.h"
#include "user_object.h"
#include "zarafa_server.h"
#define HGROWING_SIZE					250

/* maximum handle number per session */
#define MAX_HANDLE_NUM					500

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
	std::mutex writeout_mtx;
};

}

root_object::~root_object()
{
	free(maildir);
	if (pprivate_proplist != nullptr)
		tpropval_array_free(pprivate_proplist);
	if (pprof_set != nullptr)
		tarray_set_free(pprof_set);
}

static std::unique_ptr<root_object>
object_tree_init_root(const char *maildir) try
{
	EXT_PULL ext_pull;
	char tmp_path[256];
	TARRAY_SET prof_set;
	struct stat node_stat;
	TPROPVAL_ARRAY propvals;
	
	auto prootobj = std::make_unique<root_object>();
	prootobj->maildir = strdup(maildir);
	if (NULL == prootobj->maildir) {
		return NULL;
	}
	prootobj->b_touched = FALSE;
	snprintf(tmp_path, arsizeof(tmp_path), "%s/config/zarafa.dat", maildir);
	wrapfd fd = open(tmp_path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0) {
		prootobj->pprivate_proplist = tpropval_array_init();
		if (NULL == prootobj->pprivate_proplist) {
			return NULL;
		}
		prootobj->pprof_set = tarray_set_init();
		if (NULL == prootobj->pprof_set) {
			return NULL;
		}
		return prootobj;
	}
	auto pbuff = std::make_unique<char[]>(node_stat.st_size);
	if (NULL == pbuff) {
		return NULL;
	}
	if (read(fd.get(), pbuff.get(), node_stat.st_size) != node_stat.st_size) {
		return NULL;
	}
	ext_pull.init(pbuff.get(), node_stat.st_size, common_util_alloc, EXT_FLAG_WCOUNT);
	if (ext_pull.g_tpropval_a(&propvals) != EXT_ERR_SUCCESS) {
		return NULL;
	}
	prootobj->pprivate_proplist = propvals.dup();
	if (NULL == prootobj->pprivate_proplist) {
		return NULL;
	}
	if (ext_pull.g_tarray_set(&prof_set) != EXT_ERR_SUCCESS) {
		return NULL;
	}
	pbuff.reset();
	prootobj->pprof_set = prof_set.dup();
	if (NULL == prootobj->pprof_set) {
		return NULL;
	}
	return prootobj;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1099: ENOMEM\n");
	return nullptr;
}

static void object_tree_write_root(root_object *prootobj)
{
	int fd;
	EXT_PUSH ext_push;
	char tmp_path[256];
	
	if (!prootobj->b_touched ||
	    !ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT) ||
	    ext_push.p_tpropval_a(*prootobj->pprivate_proplist) != EXT_ERR_SUCCESS ||
	    ext_push.p_tarray_set(*prootobj->pprof_set) != EXT_ERR_SUCCESS)
		return;
	snprintf(tmp_path, arsizeof(tmp_path), "%s/config/zarafa.dat",
		prootobj->maildir);
	std::lock_guard lk(prootobj->writeout_mtx);
	fd = open(tmp_path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
	if (fd < 0)
		return;
	write(fd, ext_push.m_udata, ext_push.m_offset);
	close(fd);
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
	o.type = ZMG_INVALID;
	o.pobject = nullptr;
}

object_node::~object_node()
{
	switch (type) {
	case ZMG_ROOT:
		object_tree_free_root(static_cast<root_object *>(pobject));
		break;
	case ZMG_TABLE:
		delete static_cast<table_object *>(pobject);
		break;
	case ZMG_MESSAGE:
		delete static_cast<message_object *>(pobject);
		break;
	case ZMG_ATTACH:
		delete static_cast<attachment_object *>(pobject);
		break;
	case ZMG_ABCONT:
		delete static_cast<container_object *>(pobject);
		break;
	case ZMG_FOLDER:
		delete static_cast<folder_object *>(pobject);
		break;
	case ZMG_STORE:
		delete static_cast<store_object *>(pobject);
		break;
	case ZMG_MAILUSER:
	case ZMG_DISTLIST:
		delete static_cast<user_object *>(pobject);
		break;
	case ZMG_PROFPROPERTY:
		/* do not free TPROPVAL_ARRAY,
		it's an element of pprof_set */
		break;
	case ZMG_ICSDOWNCTX:
		delete static_cast<icsdownctx_object *>(pobject);
		break;
	case ZMG_ICSUPCTX:
		delete static_cast<icsupctx_object *>(pobject);
		break;
	}
}

static void object_tree_release_objnode(
	OBJECT_TREE *pobjtree, OBJECT_NODE *pobjnode)
{	
	simple_tree_enum_from_node(&pobjnode->node, [&](const SIMPLE_TREE_NODE *n) {
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
	if (NULL != proot) {
		object_tree_release_objnode(pobjtree, static_cast<OBJECT_NODE *>(proot->pdata));
	}
	pobjtree->tree.clear();
}

uint32_t OBJECT_TREE::add_object_handle(int parent_handle, object_node &&obnode)
{
	auto pobjtree = this;
	OBJECT_NODE *parent_ptr = nullptr;
	
	if (pobjtree->tree.get_nodes_num() > MAX_HANDLE_NUM)
		return INVALID_HANDLE;
	if (parent_handle < 0) {
		if (pobjtree->tree.get_root() != nullptr)
			return INVALID_HANDLE;
		parent_ptr = nullptr;
	} else {
		auto i = pobjtree->m_hash.find(parent_handle);
		if (i == pobjtree->m_hash.end())
			return INVALID_HANDLE;
		parent_ptr = i->second;
	}
	OBJECT_NODE *pobjnode;
	try {
		pobjnode = new object_node(std::move(obnode));
	} catch (const std::bad_alloc &) {
		return INVALID_HANDLE;
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
		return INVALID_HANDLE;
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
	if (NULL == prootobj) {
		return NULL;
	}
	simple_tree_init(&pobjtree->tree);
	auto handle = pobjtree->add_object_handle(-1, {ZMG_ROOT, std::move(prootobj)});
	if (handle == INVALID_HANDLE)
		return nullptr;
	return pobjtree;
}

void *OBJECT_TREE::get_object1(uint32_t obj_handle, uint8_t *ptype)
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
	/* do not relase store object until
	the whole object tree is unloaded */
	if (iter == pobjtree->m_hash.end() || iter->second->type == ZMG_STORE)
		return;
	object_tree_release_objnode(pobjtree, iter->second);
}

void *OBJECT_TREE::get_zstore_propval(uint32_t proptag)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (NULL == proot) {
		return NULL;
	}
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	return prootobj->pprivate_proplist->getval(proptag);
}

BOOL OBJECT_TREE::set_zstore_propval(const TAGGED_PROPVAL *ppropval)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (NULL == proot) {
		return FALSE;
	}
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	auto ret = prootobj->pprivate_proplist->set(*ppropval);
	if (ret != 0)
		return false;
	/*
	 * g-web touches PR_EC_WEBACCESS_SETTINGS_JSON every now and then even
	 * if just browing one's store/settings panel. Occurrence seems still
	 * acceptable that we may not need to add an age check.
	 */
	object_tree_write_root(prootobj);
	return TRUE;
}

void OBJECT_TREE::remove_zstore_propval(uint32_t proptag)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (NULL == proot) {
		return;
	}
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	prootobj->pprivate_proplist->erase(proptag);
	object_tree_write_root(prootobj);
}

TPROPVAL_ARRAY *OBJECT_TREE::get_profile_sec(GUID sec_guid)
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (NULL == proot) {
		return NULL;
	}
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	for (size_t i = 0; i < prootobj->pprof_set->count; ++i) {
		auto pguid = prootobj->pprof_set->pparray[i]->get<GUID>(PROP_TAG_PROFILESCLSID);
		if (NULL == pguid) {
			continue;
		}
		if (*pguid == sec_guid)
			return prootobj->pprof_set->pparray[i];
	}
	auto pproplist = tpropval_array_init();
	if (NULL == pproplist) {
		return NULL;
	}
	if (pproplist->set(PROP_TAG_PROFILESCLSID, &sec_guid) != 0 ||
	    prootobj->pprof_set->append_move(pproplist) != 0) {
		tpropval_array_free(pproplist);
		return NULL;
	}
	return pproplist;
}

void OBJECT_TREE::touch_profile_sec()
{
	auto pobjtree = this;
	auto proot = pobjtree->tree.get_root();
	if (NULL == proot) {
		return;
	}
	auto prootobj = static_cast<root_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	object_tree_write_root(prootobj);
}

uint32_t OBJECT_TREE::get_store_handle(BOOL b_private, int account_id)
{
	auto pobjtree = this;
	char dir[256];
	char account[UADDR_SIZE];
	OBJECT_NODE *pobjnode;
	
	auto pnode = pobjtree->tree.get_root();
	if (NULL == pnode) {
		return INVALID_HANDLE;
	}
	pnode = pnode->get_child();
	if (NULL != pnode) {
		do {
			pobjnode = (OBJECT_NODE*)pnode->pdata;
			if (pobjnode->type == ZMG_STORE &&
			    static_cast<store_object *>(pobjnode->pobject)->b_private == b_private &&
			    static_cast<store_object *>(pobjnode->pobject)->account_id == account_id)
				return pobjnode->handle;	
		} while ((pnode = pnode->get_sibling()) != nullptr);
	}
	auto pinfo = zarafa_server_get_info();
	if (b_private) {
		if (account_id == pinfo->user_id) {
			gx_strlcpy(dir, pinfo->get_maildir(), arsizeof(dir));
			gx_strlcpy(account, pinfo->get_username(), arsizeof(account));
		} else {
			if (!system_services_get_username_from_id(account_id,
			    account, GX_ARRAY_SIZE(account)) ||
			    !system_services_get_maildir(account, dir, arsizeof(dir)))
				return INVALID_HANDLE;	
		}
	} else {
		if (account_id != pinfo->domain_id) {
			return INVALID_HANDLE;
		}
		gx_strlcpy(dir, pinfo->get_homedir(), arsizeof(dir));
		auto pdomain = strchr(pinfo->get_username(), '@');
		if (NULL == pdomain) {
			return INVALID_HANDLE;
		}
		pdomain ++;
		gx_strlcpy(account, pdomain, GX_ARRAY_SIZE(account));
	}
	auto pstore = store_object::create(b_private, account_id, account, dir);
	if (NULL == pstore) {
		return INVALID_HANDLE;
	}
	return add_object_handle(ROOT_HANDLE, {ZMG_STORE, std::move(pstore)});
}
