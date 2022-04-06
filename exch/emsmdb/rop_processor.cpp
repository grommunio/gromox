// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cassert>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <unistd.h>
#include <utility>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/int_hash.hpp>
#include <gromox/proc_common.h>
#include <gromox/simple_tree.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/util.hpp>
#include "attachment_object.h"
#include "aux_types.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "fastdownctx_object.h"
#include "fastupctx_object.h"
#include "folder_object.h"
#include "icsdownctx_object.h"
#include "icsupctx_object.h"
#include "message_object.h"
#include "notify_response.h"
#include "processor_types.h"
#include "rop_dispatch.h"
#include "rop_ext.h"
#include "rop_ids.h"
#include "rop_processor.h"
#include "stream_object.h"
#include "subscription_object.h"
#include "table_object.h"
#define RPCEXT2_FLAG_NOCOMPRESSION		0x00000001
#define RPCEXT2_FLAG_NOXORMAGIC			0x00000002
#define RPCEXT2_FLAG_CHAIN				0x00000004

#define MAX_ROP_PAYLOADS				96

#define HGROWING_SIZE					250

namespace {

struct LOGON_ITEM {
	std::unique_ptr<INT_HASH_TABLE> phash;
	SIMPLE_TREE tree;
};

}

struct LOGMAP {
	LOGON_ITEM *p[256];
};

static int g_scan_interval;
static pthread_t g_scan_id;
static int g_average_handles;
static gromox::atomic_bool g_notify_stop{true};
static std::mutex g_hash_lock;
static std::unique_ptr<STR_HASH_TABLE> g_logon_hash;
static LIB_BUFFER g_logmap_allocator, g_handle_allocator, g_logitem_allocator;

unsigned int emsmdb_max_obh_per_session = 500;
unsigned int emsmdb_max_cxh_per_user = 100;
unsigned int emsmdb_max_hoc = 10;

LOGMAP *rop_processor_create_logmap()
{
	auto plogmap = g_logmap_allocator->get<LOGMAP>();
	if (NULL != plogmap) {
		memset(plogmap, 0, sizeof(LOGMAP));
	}
	return plogmap;
}

object_node::object_node(object_node &&o) noexcept :
	node(std::move(o.node)), handle(std::move(o.handle)),
	type(std::move(o.type)), pobject(std::move(o.pobject))
{
	o.node = {};
	o.handle = 0;
	o.type = OBJECT_TYPE_NONE;
	o.pobject = nullptr;
}

void object_node::clear() noexcept
{
	switch (type) {
	case OBJECT_TYPE_LOGON:
		delete static_cast<logon_object *>(pobject);
		break;
	case OBJECT_TYPE_FOLDER:
		delete static_cast<folder_object *>(pobject);
		break;
	case OBJECT_TYPE_MESSAGE:
		delete static_cast<message_object *>(pobject);
		break;
	case OBJECT_TYPE_ATTACHMENT:
		delete static_cast<attachment_object *>(pobject);
		break;
	case OBJECT_TYPE_TABLE:
		delete static_cast<table_object *>(pobject);
		break;
	case OBJECT_TYPE_STREAM:
		delete static_cast<stream_object *>(pobject);
		break;
	case OBJECT_TYPE_FASTDOWNCTX:
		delete static_cast<fastdownctx_object *>(pobject);
		break;
	case OBJECT_TYPE_FASTUPCTX:
		delete static_cast<fastupctx_object *>(pobject);
		break;
	case OBJECT_TYPE_ICSDOWNCTX:
		delete static_cast<icsdownctx_object *>(pobject);
		break;
	case OBJECT_TYPE_ICSUPCTX:
		delete static_cast<icsupctx_object *>(pobject);
		break;
	case OBJECT_TYPE_SUBSCRIPTION:
		delete static_cast<subscription_object *>(pobject);
		break;
	}
	type = OBJECT_TYPE_NONE;
	pobject = nullptr;
}

void object_node::operator=(object_node &&o) noexcept
{
	clear();
	type = std::move(o.type);
	pobject = std::move(o.pobject);
	o.type = OBJECT_TYPE_NONE;
	o.pobject = nullptr;
}

static void rop_processor_free_objnode(SIMPLE_TREE_NODE *pnode)
{
	OBJECT_NODE *pobjnode;

	pobjnode = (OBJECT_NODE*)pnode->pdata;
	g_handle_allocator->put(pobjnode);
}

static bool rop_processor_release_objnode(
	LOGON_ITEM *plogitem, OBJECT_NODE *pobjnode)
{
	BOOL b_root;
	
	/* root is the logon object, free logon object
		will cause the logon item to be released
	*/
	if (plogitem->tree.get_root() == &pobjnode->node) {
		auto proot = plogitem->tree.get_root();
		auto pobject = static_cast<const logon_object *>(static_cast<const OBJECT_NODE *>(proot->pdata)->pobject);
		std::lock_guard hl_hold(g_hash_lock);
		auto pref = g_logon_hash->query<uint32_t>(pobject->get_dir());
		if (pref != nullptr) {
			(*pref) --;
			if (0 == *pref) {
				g_logon_hash->remove(pobject->get_dir());
			}
		}
		b_root = TRUE;
	} else {
		b_root = FALSE;
	}
	simple_tree_enum_from_node(&pobjnode->node, [&](const SIMPLE_TREE_NODE *pnode) {
		plogitem->phash->remove(static_cast<const OBJECT_NODE *>(pnode->pdata)->handle);
	});
	plogitem->tree.destroy_node(&pobjnode->node, rop_processor_free_objnode);
	if (b_root) {
		plogitem->tree.clear();
		plogitem->phash.reset();
		g_logitem_allocator->put(plogitem);
	}
	return b_root;
}

static void rop_processor_release_logon_item(LOGON_ITEM *plogitem)
{
	auto proot = plogitem->tree.get_root();
	if (NULL == proot) {
		debug_info("[exchange_emsmdb]: fatal error in"
				" rop_processor_release_logon_item\n");
	} else {
		rop_processor_release_objnode(plogitem, static_cast<OBJECT_NODE *>(proot->pdata));
	}
}

void rop_processor_release_logmap(LOGMAP *plogmap)
{
	int i;
	
	for (i=0; i<256; i++) {
		if (plogmap->p[i] != nullptr) {
			rop_processor_release_logon_item(plogmap->p[i]);
			plogmap->p[i] = nullptr;
		}
	}
	g_logmap_allocator->put(plogmap);
}

int rop_processor_create_logon_item(LOGMAP *plogmap,
    uint8_t logon_id, std::unique_ptr<logon_object> &&plogon)
{
	uint32_t tmp_ref;
	auto plogitem = plogmap->p[logon_id];
	/* MS-OXCROPS 3.1.4.2 */
	if (NULL != plogitem) {
		rop_processor_release_logon_item(plogitem);
		plogmap->p[logon_id] = nullptr;
	}
	plogitem = g_logitem_allocator->get<LOGON_ITEM>();
	if (NULL == plogitem) {
		return -1;
	}
	plogitem->phash = INT_HASH_TABLE::create(HGROWING_SIZE, sizeof(OBJECT_NODE *));
	if (NULL == plogitem->phash) {
		g_logitem_allocator->put(plogitem);
		return -2;
	}
	simple_tree_init(&plogitem->tree);
	plogmap->p[logon_id] = plogitem;
	auto rlogon = plogon.get();
	auto handle = rop_processor_add_object_handle(plogmap,
				logon_id, -1, {OBJECT_TYPE_LOGON, std::move(plogon)});
	if (handle < 0) {
		g_logitem_allocator->put(plogitem);
		return -3;
	}
	std::lock_guard hl_hold(g_hash_lock);
	auto pref = g_logon_hash->query<uint32_t>(rlogon->get_dir());
	if (NULL == pref) {
		tmp_ref = 1;
		g_logon_hash->add(rlogon->get_dir(), &tmp_ref);
	} else {
		(*pref) ++;
	}
	return handle;
}

int rop_processor_add_object_handle(LOGMAP *plogmap, uint8_t logon_id,
	int parent_handle, object_node &&in_object)
{
	int tmp_handle;
	OBJECT_NODE *ptmphanle;
	OBJECT_NODE **ppparent;
	EMSMDB_INFO *pemsmdb_info;
	
	auto plogitem = plogmap->p[logon_id];
	if (NULL == plogitem) {
		return -1;
	}
	if (plogitem->tree.get_nodes_num() > emsmdb_max_obh_per_session)
		return -3;
	if (parent_handle < 0) {
		if (plogitem->tree.get_root() != nullptr)
			return -4;
		ppparent = NULL;
	} else if (parent_handle >= 0 && parent_handle < INT32_MAX) {
		ppparent = plogitem->phash->query<OBJECT_NODE *>(parent_handle);
		if (NULL == ppparent) {
			return -5;
		}
	} else {
		return -6;
	}
	auto pobjnode = g_handle_allocator->get<OBJECT_NODE>();
	if (NULL == pobjnode) {
		return -7;
	}
	if (!emsmdb_interface_alloc_handle_number(&pobjnode->handle)) {
		g_handle_allocator->put(pobjnode);
		return -8;
	}
	*pobjnode = std::move(in_object);
	if (plogitem->phash->add(pobjnode->handle, &pobjnode) != 1) {
		auto phash = INT_HASH_TABLE::create(plogitem->phash->capacity +
		                        HGROWING_SIZE, sizeof(OBJECT_NODE *));
		if (NULL == phash) {
			g_handle_allocator->put(pobjnode);
			return -8;
		}
		auto iter = plogitem->phash->make_iter();
		for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ptmphanle = static_cast<OBJECT_NODE *>(int_hash_iter_get_value(iter, &tmp_handle));
			phash->add(tmp_handle, ptmphanle);
		}
		int_hash_iter_free(iter);
		plogitem->phash = std::move(phash);
		plogitem->phash->add(pobjnode->handle, &pobjnode);
	}
	if (NULL == ppparent) {
		plogitem->tree.set_root(&pobjnode->node);
	} else {
		plogitem->tree.add_child(&(*ppparent)->node,
			&pobjnode->node, SIMPLE_TREE_ADD_LAST);
	}
	if (pobjnode->type == OBJECT_TYPE_ICSUPCTX) {
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref ++;
	}
	return pobjnode->handle;
}

void *rop_processor_get_object(LOGMAP *plogmap,
	uint8_t logon_id, uint32_t obj_handle, int *ptype)
{
	if (obj_handle >= INT32_MAX)
		return NULL;
	auto plogitem = plogmap->p[logon_id];
	if (NULL == plogitem) {
		return NULL;
	}
	auto ppobjnode = plogitem->phash->query<OBJECT_NODE *>(obj_handle);
	if (NULL == ppobjnode) {
		return NULL;
	}
	*ptype = (*ppobjnode)->type;
	return (*ppobjnode)->pobject;
}

void rop_processor_release_object_handle(LOGMAP *plogmap,
	uint8_t logon_id, uint32_t obj_handle)
{
	EMSMDB_INFO *pemsmdb_info;
	
	if (obj_handle >= INT32_MAX)
		return;
	auto plogitem = plogmap->p[logon_id];
	if (NULL == plogitem) {
		return;
	}
	auto ppobjnode = plogitem->phash->query<OBJECT_NODE *>(obj_handle);
	if (NULL == ppobjnode) {
		return;
	}
	if (OBJECT_TYPE_ICSUPCTX == (*ppobjnode)->type) {
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref --;
	}
	if (rop_processor_release_objnode(plogitem, *ppobjnode))
		plogmap->p[logon_id] = nullptr;
}

logon_object *rop_processor_get_logon_object(LOGMAP *plogmap, uint8_t logon_id)
{
	auto plogitem = plogmap->p[logon_id];
	if (NULL == plogitem) {
		return nullptr;
	}
	auto proot = plogitem->tree.get_root();
	if (NULL == proot) {
		return nullptr;
	}
	return static_cast<logon_object *>(static_cast<OBJECT_NODE *>(proot->pdata)->pobject);
}

static void *emsrop_scanwork(void *param)
{
	int count;
	char tmp_dir[256];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&temp_list);
	count = 0;
	while (!g_notify_stop) {
		sleep(1);
		count ++;
		if (count < g_scan_interval) {
			count ++;
			continue;
		} else {
			count = 0;
		}
		std::unique_lock hl_hold(g_hash_lock);
		auto iter = g_logon_hash->make_iter();
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			str_hash_iter_get_value(iter, tmp_dir);
			pnode = gromox::me_alloc<DOUBLE_LIST_NODE>();
			if (NULL == pnode) {
				continue;
			}
			pnode->pdata = strdup(tmp_dir);
			if (NULL == pnode->pdata) {
				free(pnode);
				continue;
			}
			double_list_append_as_tail(&temp_list, pnode);
		}
		str_hash_iter_free(iter);
		hl_hold.unlock();
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			exmdb_client_ping_store(static_cast<char *>(pnode->pdata));
			free(pnode->pdata);
			free(pnode);
		}
	}
	double_list_free(&temp_list);
	return nullptr;
}

void rop_processor_init(int average_handles, int scan_interval)
{
	g_average_handles = average_handles;
	g_scan_interval = scan_interval;
}

int rop_processor_run()
{
	int context_num;
	
	context_num = get_context_num();
	g_logmap_allocator = LIB_BUFFER(256 * sizeof(LOGON_ITEM *),
	                     context_num * emsmdb_max_hoc);
	g_logitem_allocator = LIB_BUFFER(sizeof(LOGON_ITEM), 256 * context_num);
	g_handle_allocator = LIB_BUFFER(sizeof(OBJECT_NODE),
	                     g_average_handles * context_num);
	g_logon_hash = STR_HASH_TABLE::create(get_context_num() * 256, sizeof(uint32_t), nullptr);
	if (NULL == g_logon_hash) {
		printf("[exchange_emsmdb]: Failed to init logon hash\n");
		return -4;
	}
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, emsrop_scanwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		printf("[exchange_emsmdb]: failed to create scanning thread "
		       "for logon hash table: %s\n", strerror(ret));
		return -5;
	}
	pthread_setname_np(g_scan_id, "rop_scan");
	return 0;
}

void rop_processor_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_scan_id, {})) {
			pthread_kill(g_scan_id, SIGALRM);
			pthread_join(g_scan_id, NULL);
		}
	}
	g_logon_hash.reset();
}

static int rop_processor_execute_and_push(uint8_t *pbuff,
	uint32_t *pbuff_len, ROP_BUFFER *prop_buff,
	BOOL b_notify, DOUBLE_LIST *presponse_list)
{
	int type;
	int status;
	int rop_num;
	BOOL b_icsup;
	BINARY tmp_bin;
	uint32_t result;
	uint32_t tmp_len;
	EXT_PUSH ext_push;
	EXT_PUSH ext_push1;
	PROPERTY_ROW tmp_row;
	char ext_buff[0x8000];
	char ext_buff1[0x8000];
	TPROPVAL_ARRAY propvals;
	DOUBLE_LIST_NODE *pnode;
	EMSMDB_INFO *pemsmdb_info;
	DOUBLE_LIST *pnotify_list;
	PENDING_RESPONSE tmp_pending;
	
	/* ms-oxcrpc 3.1.4.2.1.2 */
	if (*pbuff_len > 0x8000) {
		*pbuff_len = 0x8000;
	}
	tmp_len = *pbuff_len - 5*sizeof(uint16_t)
			- sizeof(uint32_t)*prop_buff->hnum;
	if (!ext_push.init(ext_buff, tmp_len, EXT_FLAG_UTF16))
		return ecMAPIOOM;
	rop_num = double_list_get_nodes_num(&prop_buff->rop_list);
	emsmdb_interface_set_rop_num(rop_num);
	b_icsup = FALSE;
	pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	for (pnode=double_list_get_head(&prop_buff->rop_list); NULL!=pnode;
		pnode=double_list_get_after(&prop_buff->rop_list, pnode)) {
		auto pnode1 = cu_alloc<DOUBLE_LIST_NODE>();
		if (NULL == pnode1) {
			return ecMAPIOOM;
		}
		emsmdb_interface_set_rop_left(tmp_len - ext_push.m_offset);
		auto req = static_cast<ROP_REQUEST *>(pnode->pdata);
		result = rop_dispatch(req, reinterpret_cast<ROP_RESPONSE **>(&pnode1->pdata),
				prop_buff->phandles, prop_buff->hnum);
		auto rsp = static_cast<ROP_RESPONSE *>(pnode1->pdata);
		bool dbg = g_rop_debug >= 2;
		if (g_rop_debug >= 1 && result != 0)
			dbg = true;
		if (g_rop_debug >= 1 && rsp != nullptr && rsp->result != 0)
			dbg = true;
		if (dbg) {
			if (rsp != nullptr)
				fprintf(stderr, "rop_dispatch(%s) EC=%xh RS=%xh\n",
					rop_idtoname(req->rop_id), result, rsp->result);
			else
				fprintf(stderr, "rop_dispatch(%s) EC=%xh RS=none\n",
					rop_idtoname(req->rop_id), result);
		}
		switch (result) {
		case ecSuccess:
			/* disable compression when RopReadStream
				RopFastTransferSourceGetBuffer success.
				in many cases, lzxpress will make buffer inflate! */
			if (req->rop_id == ropReadStream ||
			    req->rop_id == ropFastTransferSourceGetBuffer)
				prop_buff->rhe_flags &= ~RHE_FLAG_COMPRESSED;
			break;
		case ecBufferTooSmall: {
			rsp->rop_id = ropBufferTooSmall;
			rsp->ppayload = cu_alloc<BUFFERTOOSMALL_RESPONSE>();
			if (rsp->ppayload == nullptr)
				return ecMAPIOOM;
			auto bts = static_cast<BUFFERTOOSMALL_RESPONSE *>(rsp->ppayload);
			bts->size_needed = 0x8000;
			bts->buffer = req->bookmark;
			if (rop_ext_push_rop_response(&ext_push, req->logon_id, rsp) != EXT_ERR_SUCCESS)
				return ecBufferTooSmall;
			goto MAKE_RPC_EXT;
		}
		default:
			return result;
		}
		if (0 != pemsmdb_info->upctx_ref) {
			b_icsup = TRUE;	
		}
		/* some ROPs do not have response, for example ropRelease */
		if (NULL == pnode1->pdata) {
			continue;
		}
		uint32_t last_offset = ext_push.m_offset;
		status = rop_ext_push_rop_response(&ext_push,
				((ROP_REQUEST*)pnode->pdata)->logon_id,
		         static_cast<ROP_RESPONSE *>(pnode1->pdata));
		switch (status) {
		case EXT_ERR_SUCCESS:
			double_list_append_as_tail(presponse_list, pnode1);
			break;
		case EXT_ERR_BUFSIZE:
			if (static_cast<ROP_REQUEST *>(pnode->pdata)->rop_id == ropGetPropertiesAll) {
				/* MS-OXCPRPT 3.2.5.2, fail to whole RPC */
				if (pnode == double_list_get_head(&prop_buff->rop_list)) {
					return ecServerOOM;
				}
			}
			static_cast<ROP_RESPONSE *>(pnode1->pdata)->rop_id = ropBufferTooSmall;
			static_cast<ROP_RESPONSE *>(pnode1->pdata)->ppayload = cu_alloc<BUFFERTOOSMALL_RESPONSE>();
			if (NULL == ((ROP_RESPONSE*)pnode1->pdata)->ppayload) {
				return ecMAPIOOM;
			}
			((BUFFERTOOSMALL_RESPONSE*)((ROP_RESPONSE*)
				pnode1->pdata)->ppayload)->size_needed = 0x8000;
			((BUFFERTOOSMALL_RESPONSE*)((ROP_RESPONSE*)
				pnode1->pdata)->ppayload)->buffer =
					((ROP_REQUEST*)pnode->pdata)->bookmark;
			ext_push.m_offset = last_offset;
			if (rop_ext_push_rop_response(&ext_push,
			    static_cast<ROP_REQUEST *>(pnode->pdata)->logon_id,
			    static_cast<ROP_RESPONSE *>(pnode1->pdata)) != EXT_ERR_SUCCESS)
				return ecBufferTooSmall;
			goto MAKE_RPC_EXT;
		case EXT_ERR_ALLOC:
			return ecMAPIOOM;
		default:
			return ecRpcFailed;
		}
	}
	
	if (!b_notify || b_icsup)
		goto MAKE_RPC_EXT;
	while (true) {
		pnotify_list = emsmdb_interface_get_notify_list();
		if (NULL == pnotify_list) {
			return ecRpcFailed;
		}
		pnode = double_list_pop_front(pnotify_list);
		emsmdb_interface_put_notify_list();
		if (NULL == pnode) {
			break;
		}
		uint32_t last_offset = ext_push.m_offset;
		auto pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		auto pobject = rop_processor_get_object(pemsmdb_info->plogmap, pnotify->logon_id, pnotify->handle, &type);
		if (NULL != pobject) {
			if (OBJECT_TYPE_TABLE == type &&
				NULL != pnotify->notification_data.ptable_event &&
				(TABLE_EVENT_ROW_ADDED ==
				*pnotify->notification_data.ptable_event ||
				TABLE_EVENT_ROW_MODIFIED ==
				*pnotify->notification_data.ptable_event)) {
				auto tbl = static_cast<table_object *>(pobject);
				auto pcolumns = tbl->get_columns();
				if (!ext_push1.init(ext_buff1, sizeof(ext_buff1), EXT_FLAG_UTF16))
					goto NEXT_NOTIFY;
				if (pnotify->notification_data.notification_flags
					&NOTIFICATION_FLAG_MOST_MESSAGE) {
					if (!tbl->read_row(*pnotify->notification_data.prow_message_id,
					    *pnotify->notification_data.prow_instance,
					    &propvals) || propvals.count == 0)
						goto NEXT_NOTIFY;
					
				} else {
					if (!tbl->read_row(*pnotify->notification_data.prow_folder_id,
					    0, &propvals) || propvals.count == 0)
						goto NEXT_NOTIFY;
				}
				if (!common_util_propvals_to_row(&propvals, pcolumns, &tmp_row) ||
				    ext_push1.p_proprow(*pcolumns, tmp_row) != EXT_ERR_SUCCESS)
					goto NEXT_NOTIFY;
				tmp_bin.cb = ext_push1.m_offset;
				tmp_bin.pb = ext_push1.m_udata;
				pnotify->notification_data.prow_data = &tmp_bin;
			}
			if (EXT_ERR_SUCCESS != rop_ext_push_notify_response(
				&ext_push, pnotify)) {
				ext_push.m_offset = last_offset;
				double_list_insert_as_head(pnotify_list, pnode);
				emsmdb_interface_get_cxr(&tmp_pending.session_index);
				status = rop_ext_push_pending_response(
								&ext_push, &tmp_pending);
				if (EXT_ERR_SUCCESS != status) {
					ext_push.m_offset = last_offset;
				}
				break;
			}
		}
 NEXT_NOTIFY:
		notify_response_free(static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload));
		free(pnode->pdata);
		free(pnode);
	}
	
 MAKE_RPC_EXT:
	if (rop_ext_make_rpc_ext(ext_buff, ext_push.m_offset, prop_buff,
	    pbuff, pbuff_len) != EXT_ERR_SUCCESS)
		return ecError;
	return ecSuccess;
}

uint32_t rop_processor_proc(uint32_t flags, const uint8_t *pin,
	uint32_t cb_in, uint8_t *pout, uint32_t *pcb_out)
{
	int count;
	uint32_t result;
	uint32_t tmp_cb;
	uint32_t offset;
	EXT_PULL ext_pull;
	ROP_BUFFER rop_buff;
	uint32_t last_offset;
	ROP_REQUEST *prequest;
	ROP_RESPONSE *presponse;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST response_list;
	
	ext_pull.init(pin, cb_in, common_util_alloc, EXT_FLAG_UTF16);
	switch(rop_ext_pull_rop_buffer(&ext_pull, &rop_buff)) {
	case EXT_ERR_SUCCESS:
		break;
	case EXT_ERR_ALLOC:
		return ecMAPIOOM;
	default:
		return ecRpcFormat;
	}
	rop_buff.rhe_flags = 0;
	if (0 == (flags & RPCEXT2_FLAG_NOXORMAGIC)) {
		rop_buff.rhe_flags |= RHE_FLAG_XORMAGIC;
	}
	if (0 == (flags & RPCEXT2_FLAG_NOCOMPRESSION)) {
		rop_buff.rhe_flags |= RHE_FLAG_COMPRESSED;
	}
	double_list_init(&response_list);
	tmp_cb = *pcb_out;
	result = rop_processor_execute_and_push(pout,
		&tmp_cb, &rop_buff, TRUE, &response_list);
	if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
		fprintf(stderr, "rop_proc_ex+push() EC = %xh\n", result);
	if (result != ecSuccess)
		return result;
	offset = tmp_cb;
	last_offset = 0;
	count = double_list_get_nodes_num(&response_list);
	pnode = double_list_get_tail(&rop_buff.rop_list);
	pnode1 = double_list_get_tail(&response_list);
	if (NULL == pnode || NULL == pnode1) {
		goto PROC_SUCCESS;
	}
	prequest = (ROP_REQUEST*)pnode->pdata;
	presponse = (ROP_RESPONSE*)pnode1->pdata;
	if (prequest->rop_id != presponse->rop_id) {
		goto PROC_SUCCESS;
	}
	double_list_free(&rop_buff.rop_list);
	double_list_init(&rop_buff.rop_list);
	double_list_append_as_tail(&rop_buff.rop_list, pnode);
	double_list_free(&response_list);
	double_list_init(&response_list);
	
	if (presponse->rop_id == ropQueryRows) {
		auto req = static_cast<QUERYROWS_REQUEST *>(prequest->ppayload);
		auto rsp = static_cast<QUERYROWS_RESPONSE *>(presponse->ppayload);
		if (req->flags == QUERY_ROWS_FLAGS_ENABLEPACKEDBUFFERS)
			goto PROC_SUCCESS;
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (presponse->result == ecSuccess &&
			*pcb_out - offset >= 0x8000 && count < MAX_ROP_PAYLOADS) {
			if (req->forward_read != 0) {
				if (rsp->seek_pos == BOOKMARK_END)
					break;
			} else {
				if (rsp->seek_pos == BOOKMARK_BEGINNING)
					break;
			}
			req->row_count -= rsp->count;
			if (req->row_count == 0)
				break;
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (result != ecSuccess)
				break;
			pnode1 = double_list_pop_front(&response_list);
			if (NULL == pnode1) {
				break;
			}
			presponse = (ROP_RESPONSE*)pnode1->pdata;
			if (presponse->rop_id != ropQueryRows ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (presponse->rop_id == ropReadStream) {
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (presponse->result == ecSuccess &&
			*pcb_out - offset >= 0x2000 && count < MAX_ROP_PAYLOADS) {
			if (0 == ((READSTREAM_RESPONSE*)
				presponse->ppayload)->data.cb) {
				break;
			}
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (result != ecSuccess)
				break;
			pnode1 = double_list_pop_front(&response_list);
			if (NULL == pnode1) {
				break;
			}
			presponse = (ROP_RESPONSE*)pnode1->pdata;
			if (presponse->rop_id != ropReadStream ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (presponse->rop_id == ropFastTransferSourceGetBuffer) {
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (presponse->result == ecSuccess &&
			*pcb_out - offset >= 0x2000 && count < MAX_ROP_PAYLOADS) {
			if (TRANSFER_STATUS_ERROR == 
				((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)
				presponse->ppayload)->transfer_status ||
				TRANSFER_STATUS_DONE == 
				((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)
				presponse->ppayload)->transfer_status) {
				break;
			}
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (result != ecSuccess)
				break;
			pnode1 = double_list_pop_front(&response_list);
			if (NULL == pnode1) {
				break;
			}
			presponse = (ROP_RESPONSE*)pnode1->pdata;
			if (presponse->rop_id != ropFastTransferSourceGetBuffer ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	}
	
 PROC_SUCCESS:
	rop_ext_set_rhe_flag_last(pout, last_offset);
	*pcb_out = offset;
	return ecSuccess;
}
