// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include <gromox/scope.hpp>
#include <gromox/tarray_set.hpp>
#include <gromox/ext_buffer.hpp>
#include "common_util.h"
#include "object_tree.h"
#include "user_object.h"
#include "store_object.h"
#include "table_object.h"
#include "folder_object.h"
#include "zarafa_server.h"
#include "message_object.h"
#include "system_services.h"
#include "icsupctx_object.h"
#include "container_object.h"
#include "icsdownctx_object.h"
#include "attachment_object.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#define HGROWING_SIZE					250

/* maximum handle number per session */
#define MAX_HANDLE_NUM					500

#define PROP_TAG_PROPFILESECLSID		0x00480048

using namespace gromox;

namespace {

struct ROOT_OBJECT {
	BOOL b_touched;
	char *maildir;
	TPROPVAL_ARRAY *pprivate_proplist;
	TARRAY_SET *pprof_set;
};

struct OBJECT_NODE {
	SIMPLE_TREE_NODE node;
	uint32_t handle;
	uint8_t type;
	void *pobject;
};

}

static ROOT_OBJECT* object_tree_init_root(const char *maildir)
{
	EXT_PULL ext_pull;
	char tmp_path[256];
	TARRAY_SET prof_set;
	struct stat node_stat;
	TPROPVAL_ARRAY propvals;
	
	auto prootobj = me_alloc<ROOT_OBJECT>();
	if (NULL == prootobj) {
		return NULL;
	}
	prootobj->maildir = strdup(maildir);
	if (NULL == prootobj->maildir) {
		free(prootobj);
		return NULL;
	}
	prootobj->b_touched = FALSE;
	sprintf(tmp_path, "%s/config/zarafa.dat", maildir);
	wrapfd fd = open(tmp_path, O_RDONLY);
	if (fd.get() < 0 || fstat(fd.get(), &node_stat) != 0) {
		prootobj->pprivate_proplist = tpropval_array_init();
		if (NULL == prootobj->pprivate_proplist) {
			free(prootobj->maildir);
			free(prootobj);
			return NULL;
		}
		prootobj->pprof_set = tarray_set_init();
		if (NULL == prootobj->pprof_set) {
			tpropval_array_free(prootobj->pprivate_proplist);
			free(prootobj->maildir);
			free(prootobj);
			return NULL;
		}
		return prootobj;
	}
	auto pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		free(prootobj->maildir);
		free(prootobj);
		return NULL;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size) {
		free(pbuff);
		free(prootobj->maildir);
		free(prootobj);
		return NULL;
	}
	ext_buffer_pull_init(
		&ext_pull, pbuff, node_stat.st_size,
		common_util_alloc, EXT_FLAG_WCOUNT);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tpropval_array(
		&ext_pull, &propvals)) {
		free(pbuff);
		free(prootobj->maildir);
		free(prootobj);
		return NULL;
	}
	prootobj->pprivate_proplist = tpropval_array_dup(&propvals);
	if (NULL == prootobj->pprivate_proplist) {
		free(pbuff);
		free(prootobj->maildir);
		free(prootobj);
		return NULL;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tarray_set(
		&ext_pull, &prof_set)) {
		tpropval_array_free(prootobj->pprivate_proplist);
		free(pbuff);
		free(prootobj->maildir);
		free(prootobj);
		return NULL;
	}
	free(pbuff);
	prootobj->pprof_set = tarray_set_dup(&prof_set);
	if (NULL == prootobj->pprof_set) {
		tpropval_array_free(prootobj->pprivate_proplist);
		free(prootobj->maildir);
		free(prootobj);
		return NULL;
	}
	return prootobj;
}

static void object_tree_free_root(ROOT_OBJECT *prootobj)
{
	int fd;
	EXT_PUSH ext_push;
	char tmp_path[256];
	
	if (prootobj->b_touched &&
	    ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT) &&
	    ext_push.p_tpropval_a(prootobj->pprivate_proplist) == EXT_ERR_SUCCESS &&
	    ext_push.p_tarray_set(prootobj->pprof_set) == EXT_ERR_SUCCESS) {
		sprintf(tmp_path, "%s/config/zarafa.dat",
			prootobj->maildir);
		fd = open(tmp_path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
		if (-1 != fd) {
			write(fd, ext_push.data, ext_push.offset);
			close(fd);
		}
	}
	tarray_set_free(prootobj->pprof_set);
	tpropval_array_free(prootobj->pprivate_proplist);
	free(prootobj->maildir);
	free(prootobj);
}

static void object_tree_enum_objnode(
	SIMPLE_TREE_NODE *pnode, void *pparam)
{
	OBJECT_TREE *pobjtree;
	OBJECT_NODE *pobjnode;
	
	pobjtree = (OBJECT_TREE*)pparam;
	pobjnode = (OBJECT_NODE*)pnode->pdata;
	int_hash_remove(pobjtree->phash, pobjnode->handle);
}

static void object_tree_free_object(void *pobject, uint8_t type)
{
	switch (type) {
	case ZMG_ROOT:
		object_tree_free_root(static_cast<ROOT_OBJECT *>(pobject));
		break;
	case ZMG_TABLE:
		delete static_cast<TABLE_OBJECT *>(pobject);
		break;
	case ZMG_MESSAGE:
		delete static_cast<MESSAGE_OBJECT *>(pobject);
		break;
	case ZMG_ATTACH:
		delete static_cast<ATTACHMENT_OBJECT *>(pobject);
		break;
	case ZMG_ABCONT:
		delete static_cast<CONTAINER_OBJECT *>(pobject);
		break;
	case ZMG_FOLDER:
		delete static_cast<FOLDER_OBJECT *>(pobject);
		break;
	case ZMG_STORE:
		delete static_cast<STORE_OBJECT *>(pobject);
		break;
	case ZMG_MAILUSER:
	case ZMG_DISTLIST:
		delete static_cast<USER_OBJECT *>(pobject);
		break;
	case ZMG_PROFPROPERTY:
		/* do not free TPROPVAL_ARRAY,
		it's an element of pprof_set */
		break;
	case ZMG_ICSDOWNCTX:
		delete static_cast<ICSDOWNCTX_OBJECT *>(pobject);
		break;
	case ZMG_ICSUPCTX:
		delete static_cast<ICSUPCTX_OBJECT *>(pobject);
		break;
	}
}

static void object_tree_free_objnode(SIMPLE_TREE_NODE *pnode)
{
	OBJECT_NODE *pobjnode;
	
	pobjnode = (OBJECT_NODE*)pnode->pdata;
	object_tree_free_object(pobjnode->pobject, pobjnode->type);
	free(pobjnode);
}

static void object_tree_release_objnode(
	OBJECT_TREE *pobjtree, OBJECT_NODE *pobjnode)
{	
	simple_tree_enum_from_node(&pobjnode->node,
		object_tree_enum_objnode, pobjtree);
	simple_tree_destroy_node(&pobjtree->tree,
		&pobjnode->node, object_tree_free_objnode);
}

OBJECT_TREE::~OBJECT_TREE()
{
	auto pobjtree = this;
	auto proot = simple_tree_get_root(&tree);
	if (NULL != proot) {
		object_tree_release_objnode(pobjtree, static_cast<OBJECT_NODE *>(proot->pdata));
	}
	int_hash_free(pobjtree->phash);
	simple_tree_free(&pobjtree->tree);
}

uint32_t OBJECT_TREE::add_object_handle(int parent_handle, int type, void *pobject)
{
	auto pobjtree = this;
	int tmp_handle;
	INT_HASH_ITER *iter;
	OBJECT_NODE *ptmphanle;
	OBJECT_NODE **ppparent;
	
	if (simple_tree_get_nodes_num(&pobjtree->tree) > MAX_HANDLE_NUM) {
		return INVALID_HANDLE;
	}
	if (parent_handle < 0) {
		if (NULL != simple_tree_get_root(&pobjtree->tree)) {
			return INVALID_HANDLE;
		}
		ppparent = NULL;
	} else {
		ppparent = static_cast<OBJECT_NODE **>(int_hash_query(pobjtree->phash, parent_handle));
		if (NULL == ppparent) {
			return INVALID_HANDLE;
		}
	}
	auto pobjnode = me_alloc<OBJECT_NODE>();
	if (NULL == pobjnode) {
		return INVALID_HANDLE;
	}
	if (parent_handle < 0) {
		pobjnode->handle = ROOT_HANDLE;
	} else {
		if (pobjtree->last_handle >= 0x7FFFFFFF) {
			pobjtree->last_handle = 0;
		}
		pobjtree->last_handle ++;
		pobjnode->handle = pobjtree->last_handle;
	}
	pobjnode->node.pdata = pobjnode;
	pobjnode->type = type;
	pobjnode->pobject = pobject;
	if (1 != int_hash_add(pobjtree->phash,
		pobjnode->handle, &pobjnode)) {
		INT_HASH_TABLE *phash = int_hash_init(pobjtree->phash->capacity +
		                        HGROWING_SIZE, sizeof(OBJECT_NODE *));
		if (NULL == phash) {
			free(pobjnode);
			return INVALID_HANDLE;
		}
		iter = int_hash_iter_init(pobjtree->phash);
		for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ptmphanle = static_cast<OBJECT_NODE *>(int_hash_iter_get_value(iter, &tmp_handle));
			int_hash_add(phash, tmp_handle, ptmphanle);
		}
		int_hash_iter_free(iter);
		int_hash_free(pobjtree->phash);
		pobjtree->phash = phash;
		int_hash_add(pobjtree->phash, pobjnode->handle, &pobjnode);
	}
	if (NULL == ppparent) {
		simple_tree_set_root(&pobjtree->tree, &pobjnode->node);
	} else {
		simple_tree_add_child(&pobjtree->tree, &(*ppparent)->node,
			&pobjnode->node, SIMPLE_TREE_ADD_LAST);
	}
	return pobjnode->handle;
}

std::unique_ptr<OBJECT_TREE> object_tree_create(const char *maildir)
{
	ROOT_OBJECT *prootobj;
	std::unique_ptr<OBJECT_TREE> pobjtree;
	try {
		pobjtree = std::make_unique<OBJECT_TREE>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pobjtree->last_handle = 0;
	pobjtree->phash = int_hash_init(HGROWING_SIZE, sizeof(OBJECT_NODE *));
	if (NULL == pobjtree->phash) {
		return NULL;
	}
	prootobj = object_tree_init_root(maildir);
	if (NULL == prootobj) {
		return NULL;
	}
	simple_tree_init(&pobjtree->tree);
	auto handle = pobjtree->add_object_handle(-1, ZMG_ROOT, prootobj);
	if (handle == INVALID_HANDLE)
		return nullptr;
	return pobjtree;
}

void *OBJECT_TREE::get_object1(uint32_t obj_handle, uint8_t *ptype)
{
	OBJECT_NODE **ppobjnode;
	
	if (obj_handle > 0x7FFFFFFF) {
		return NULL;
	}
	auto pobjtree = this;
	ppobjnode = static_cast<OBJECT_NODE **>(int_hash_query(pobjtree->phash, obj_handle));
	if (NULL == ppobjnode) {
		return NULL;
	}
	*ptype = (*ppobjnode)->type;
	return (*ppobjnode)->pobject;
}

void OBJECT_TREE::release_object_handle(uint32_t obj_handle)
{
	OBJECT_NODE **ppobjnode;
	
	if (ROOT_HANDLE == obj_handle || obj_handle > 0x7FFFFFFF) {
		return;
	}
	auto pobjtree = this;
	ppobjnode = static_cast<OBJECT_NODE **>(int_hash_query(pobjtree->phash, obj_handle));
	/* do not relase store object until
	the whole object tree is unloaded */
	if (ppobjnode == nullptr || (*ppobjnode)->type == ZMG_STORE)
		return;
	object_tree_release_objnode(pobjtree, *ppobjnode);
}

void *OBJECT_TREE::get_zstore_propval(uint32_t proptag)
{
	auto pobjtree = this;
	ROOT_OBJECT *prootobj;
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(&pobjtree->tree);
	if (NULL == proot) {
		return NULL;
	}
	prootobj = static_cast<ROOT_OBJECT *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	return tpropval_array_get_propval(
		prootobj->pprivate_proplist, proptag);
}

BOOL OBJECT_TREE::set_zstore_propval(const TAGGED_PROPVAL *ppropval)
{
	auto pobjtree = this;
	ROOT_OBJECT *prootobj;
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(&pobjtree->tree);
	if (NULL == proot) {
		return FALSE;
	}
	prootobj = static_cast<ROOT_OBJECT *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	return tpropval_array_set_propval(prootobj->pprivate_proplist, ppropval) ?
	       TRUE : false;
}

void OBJECT_TREE::remove_zstore_propval(uint32_t proptag)
{
	auto pobjtree = this;
	ROOT_OBJECT *prootobj;
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(&pobjtree->tree);
	if (NULL == proot) {
		return;
	}
	prootobj = static_cast<ROOT_OBJECT *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
	tpropval_array_remove_propval(
		prootobj->pprivate_proplist, proptag);
}

TPROPVAL_ARRAY *OBJECT_TREE::get_profile_sec(GUID sec_guid)
{
	auto pobjtree = this;
	GUID *pguid;
	ROOT_OBJECT *prootobj;
	TAGGED_PROPVAL propval;
	SIMPLE_TREE_NODE *proot;
	TPROPVAL_ARRAY *pproplist;
	
	proot = simple_tree_get_root(&pobjtree->tree);
	if (NULL == proot) {
		return NULL;
	}
	prootobj = static_cast<ROOT_OBJECT *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	for (size_t i = 0; i < prootobj->pprof_set->count; ++i) {
		pguid = static_cast<GUID *>(tpropval_array_get_propval(
			prootobj->pprof_set->pparray[i],
			PROP_TAG_PROPFILESECLSID));
		if (NULL == pguid) {
			continue;
		}
		if (0 == guid_compare(pguid, &sec_guid)) {
			return prootobj->pprof_set->pparray[i];
		}
	}
	pproplist = tpropval_array_init();
	if (NULL == pproplist) {
		return NULL;
	}
	propval.proptag = PROP_TAG_PROPFILESECLSID;
	propval.pvalue = &sec_guid;
	if (!tpropval_array_set_propval(pproplist, &propval) || 
	    !tarray_set_append_internal(prootobj->pprof_set, pproplist)) {
		tpropval_array_free(pproplist);
		return NULL;
	}
	return pproplist;
}

void OBJECT_TREE::touch_profile_sec()
{
	auto pobjtree = this;
	ROOT_OBJECT *prootobj;
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(&pobjtree->tree);
	if (NULL == proot) {
		return;
	}
	prootobj = static_cast<ROOT_OBJECT *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
	prootobj->b_touched = TRUE;
}

uint32_t OBJECT_TREE::get_store_handle(BOOL b_private, int account_id)
{
	auto pobjtree = this;
	char dir[256];
	char account[UADDR_SIZE];
	OBJECT_NODE *pobjnode;
	SIMPLE_TREE_NODE *pnode;
	
	pnode = simple_tree_get_root(&pobjtree->tree);
	if (NULL == pnode) {
		return INVALID_HANDLE;
	}
	pnode = simple_tree_node_get_child(pnode);
	if (NULL != pnode) {
		do {
			pobjnode = (OBJECT_NODE*)pnode->pdata;
			if (pobjnode->type == ZMG_STORE &&
			    static_cast<STORE_OBJECT *>(pobjnode->pobject)->b_private == b_private &&
			    static_cast<STORE_OBJECT *>(pobjnode->pobject)->account_id == account_id)
				return pobjnode->handle;	
		} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	}
	auto pinfo = zarafa_server_get_info();
	if (TRUE == b_private) {
		if (account_id == pinfo->user_id) {
			gx_strlcpy(dir, pinfo->get_maildir(), arsizeof(dir));
			gx_strlcpy(account, pinfo->get_username(), arsizeof(account));
		} else {
			if (!system_services_get_username_from_id(account_id,
			    account, GX_ARRAY_SIZE(account)) ||
				FALSE == system_services_get_maildir(
				account, dir)) {
				return INVALID_HANDLE;	
			}
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
	auto pstore = store_object_create(b_private, account_id, account, dir);
	if (NULL == pstore) {
		return INVALID_HANDLE;
	}
	auto handle = add_object_handle(ROOT_HANDLE, ZMG_STORE, pstore.get());
	if (handle != INVALID_HANDLE)
		pstore.release();
	return handle;
}
