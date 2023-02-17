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
#include <unordered_map>
#include <utility>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/int_hash.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "attachment_object.h"
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
#include "rop_ids.hpp"
#include "rop_processor.h"
#include "stream_object.h"
#include "subscription_object.h"
#include "table_object.h"

using namespace gromox;

static int g_scan_interval;
static pthread_t g_scan_id;
static int g_average_handles;
static gromox::atomic_bool g_notify_stop{true};
static std::mutex g_hash_lock;
static std::unordered_map<std::string, uint32_t> g_logon_hash;
static unsigned int g_emsmdb_full_parenting;
static unsigned int g_max_rop_payloads = 96;

unsigned int emsmdb_max_obh_per_session = 500;
unsigned int emsmdb_max_cxh_per_user = 100;
unsigned int emsmdb_max_hoc = 10;
unsigned int emsmdb_pvt_folder_softdel, emsmdb_rop_chaining;

std::unique_ptr<LOGMAP> rop_processor_create_logmap() try
{
	return std::make_unique<LOGMAP>();
} catch (const std::bad_alloc &) {
	return nullptr;
}

object_node::object_node(object_node &&o) noexcept :
	handle(std::move(o.handle)),
	type(std::move(o.type)), pobject(std::move(o.pobject))
{
	o.handle = 0;
	o.type = ems_objtype::none;
	o.pobject = nullptr;
}

void object_node::clear() noexcept
{
	switch (type) {
	case ems_objtype::logon: {
		auto logon = static_cast<logon_object *>(pobject);
		{
			/* Remove from pinger list */
			std::lock_guard hl_hold(g_hash_lock);
			auto ref = g_logon_hash.find(logon->get_dir());
			if (ref != g_logon_hash.end() && --ref->second == 0)
				g_logon_hash.erase(ref);
		}
		delete logon;
		break;
	}
	case ems_objtype::folder:
		delete static_cast<folder_object *>(pobject);
		break;
	case ems_objtype::message:
		delete static_cast<message_object *>(pobject);
		break;
	case ems_objtype::attach:
		delete static_cast<attachment_object *>(pobject);
		break;
	case ems_objtype::table:
		delete static_cast<table_object *>(pobject);
		break;
	case ems_objtype::stream:
		delete static_cast<stream_object *>(pobject);
		break;
	case ems_objtype::fastdownctx:
		delete static_cast<fastdownctx_object *>(pobject);
		break;
	case ems_objtype::fastupctx:
		delete static_cast<fastupctx_object *>(pobject);
		break;
	case ems_objtype::icsdownctx:
		delete static_cast<icsdownctx_object *>(pobject);
		break;
	case ems_objtype::icsupctx:
		delete static_cast<icsupctx_object *>(pobject);
		break;
	case ems_objtype::subscription:
		delete static_cast<subscription_object *>(pobject);
		break;
	default:
		break;
	}
	type = ems_objtype::none;
	pobject = nullptr;
}

void object_node::operator=(object_node &&o) noexcept
{
	clear();
	type = std::move(o.type);
	pobject = std::move(o.pobject);
	o.type = ems_objtype::none;
	o.pobject = nullptr;
}

int32_t rop_processor_create_logon_item(LOGMAP *plogmap,
    uint8_t logon_id, std::unique_ptr<logon_object> &&plogon) try
{
	/* MS-OXCROPS 3.1.4.2 */
	plogmap->p[logon_id] = std::make_unique<LOGON_ITEM>();
	auto rlogon = plogon.get();
	auto handle = rop_processor_add_object_handle(plogmap, logon_id, -1,
	              {ems_objtype::logon, std::move(plogon)});
	if (handle < 0)
		return -3;
	std::lock_guard hl_hold(g_hash_lock);
	auto pref = g_logon_hash.find(rlogon->get_dir());
	if (pref != g_logon_hash.end())
		++pref->second;
	else
		g_logon_hash.emplace(rlogon->get_dir(), 1);
	return handle;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1974: ENOMEM");
	return -1;
}

static bool object_dep(ems_objtype p, ems_objtype c)
{
	if (p == ems_objtype::logon)
		/* emsmdb special */
		return c == ems_objtype::fastdownctx || c == ems_objtype::fastupctx ||
		       c == ems_objtype::folder || c == ems_objtype::message ||
		       c == ems_objtype::icsdownctx || c == ems_objtype::icsupctx ||
		       c == ems_objtype::subscription || c == ems_objtype::table;

	if (p == ems_objtype::attach)
		return c == ems_objtype::stream || c == ems_objtype::message ||
		       c == ems_objtype::fastdownctx ||
		       c == ems_objtype::fastupctx;
	if (p == ems_objtype::message)
		return c == ems_objtype::attach || c == ems_objtype::stream ||
		       c == ems_objtype::table ||
		       c == ems_objtype::fastdownctx ||
		       c == ems_objtype::fastupctx ||
		       /* emsmdb special */
		       c == ems_objtype::logon;

	if (p != ems_objtype::folder)
		return false;
	return c == ems_objtype::stream || c == ems_objtype::table ||
	       c == ems_objtype::fastdownctx || c == ems_objtype::fastupctx ||
	       c == ems_objtype::icsdownctx || c == ems_objtype::icsupctx ||
	       /* emsmdb special */
	       c == ems_objtype::logon;
}

int32_t rop_processor_add_object_handle(LOGMAP *plogmap, uint8_t logon_id,
    int32_t parent_handle, object_node &&in_object) try
{
	EMSMDB_INFO *pemsmdb_info;
	
	auto plogitem = plogmap->p[logon_id].get();
	if (plogitem == nullptr)
		return -1;
	if (plogitem->phash.size() >= emsmdb_max_obh_per_session)
		return -3;

	std::shared_ptr<object_node> parent;
	if (parent_handle < 0) {
		if (plogitem->root != nullptr)
			return -4;
	} else if (parent_handle >= 0 && parent_handle < INT32_MAX) {
		auto i = plogitem->phash.find(parent_handle);
		if (i == plogitem->phash.end())
			return -5;
		parent = i->second;
	} else {
		return -6;
	}
	auto pobjnode = std::make_shared<object_node>(std::move(in_object));
	if (!emsmdb_interface_alloc_handle_number(&pobjnode->handle))
		return -8;
	auto xp = plogitem->phash.emplace(pobjnode->handle, pobjnode);
	if (!xp.second)
		return -8;
	if (parent == nullptr)
		plogitem->root = pobjnode;
	else if (g_emsmdb_full_parenting || object_dep(parent->type, pobjnode->type))
		pobjnode->parent = parent;
	if (pobjnode->type == ems_objtype::icsupctx) {
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref ++;
	}
	return pobjnode->handle;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1975: ENOMEM");
	return -1;
}

void *rop_processor_get_object(LOGMAP *plogmap, uint8_t logon_id,
    uint32_t obj_handle, ems_objtype *ptype)
{
	if (obj_handle >= INT32_MAX)
		return NULL;
	auto &plogitem = plogmap->p[logon_id];
	if (plogitem == nullptr)
		return NULL;
	auto i = plogitem->phash.find(obj_handle);
	if (i == plogitem->phash.end())
		return NULL;
	*ptype = i->second->type;
	return i->second->pobject;
}

void rop_processor_release_object_handle(LOGMAP *plogmap,
	uint8_t logon_id, uint32_t obj_handle)
{
	EMSMDB_INFO *pemsmdb_info;
	
	if (obj_handle >= INT32_MAX)
		return;
	auto &plogitem = plogmap->p[logon_id];
	if (plogitem == nullptr)
		return;
	auto i = plogitem->phash.find(obj_handle);
	if (i == plogitem->phash.end())
		return;
	auto objnode = i->second;
	if (objnode->type == ems_objtype::icsupctx) {
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref --;
	}
	plogitem->phash.erase(objnode->handle);
}

logon_object *rop_processor_get_logon_object(LOGMAP *plogmap, uint8_t logon_id)
{
	auto &plogitem = plogmap->p[logon_id];
	if (plogitem == nullptr)
		return nullptr;
	auto proot = plogitem->root;
	if (proot == nullptr)
		return nullptr;
	return static_cast<logon_object *>(proot->pobject);
}

static void *emsrop_scanwork(void *param)
{
	int count;
	
	count = 0;
	while (!g_notify_stop) try {
		sleep(1);
		count ++;
		if (count < g_scan_interval) {
			count ++;
			continue;
		}
		count = 0;
		std::unique_lock hl_hold(g_hash_lock);
		std::vector<std::string> dirs;
		for (const auto &pair : g_logon_hash)
			dirs.push_back(pair.first);
		hl_hold.unlock();
		while (dirs.size() > 0) {
			exmdb_client::ping_store(dirs.back().c_str());
			dirs.pop_back();
		}
	} catch (const std::bad_alloc &) {
		sleep(1);
	}
	return nullptr;
}

void rop_processor_init(int average_handles, int scan_interval)
{
	g_average_handles = average_handles;
	g_scan_interval = scan_interval;
}

int rop_processor_run()
{
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, emsrop_scanwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		mlog(LV_ERR, "emsmdb: failed to create scanning thread "
		       "for logon hash table: %s", strerror(ret));
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
	g_logon_hash.clear();
}

static uint32_t rpcext_cutoff = 32U << 10; /* OXCRPC v23 3.1.4.2.1.2.2 */

static ec_error_t rop_processor_execute_and_push(uint8_t *pbuff,
    uint32_t *pbuff_len, ROP_BUFFER *prop_buff, BOOL b_notify,
    DOUBLE_LIST *presponse_list) try
{
	int rop_num;
	BOOL b_icsup;
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	EXT_PUSH ext_push1;
	PROPERTY_ROW tmp_row;
	static constexpr size_t ext_buff_size = 0x8000;
	auto ext_buff = std::make_unique<uint8_t[]>(ext_buff_size);
	auto ext_buff1 = std::make_unique<uint8_t[]>(ext_buff_size);
	TPROPVAL_ARRAY propvals;
	DOUBLE_LIST_NODE *pnode;
	EMSMDB_INFO *pemsmdb_info;
	DOUBLE_LIST *pnotify_list;
	PENDING_RESPONSE tmp_pending;
	
	/* ms-oxcrpc 3.1.4.2.1.2 */
	if (*pbuff_len > rpcext_cutoff)
		*pbuff_len = rpcext_cutoff;
	auto endroom_needed = 5 * sizeof(uint16_t) + prop_buff->hnum * sizeof(uint32_t);
	auto tmp_len = *pbuff_len;
	if (tmp_len >= endroom_needed)
		tmp_len -= endroom_needed;
	else
		tmp_len = 0;
	if (tmp_len > ext_buff_size)
		tmp_len = ext_buff_size;
	if (!ext_push.init(ext_buff.get(), tmp_len, EXT_FLAG_UTF16))
		return ecServerOOM;
	rop_num = double_list_get_nodes_num(&prop_buff->rop_list);
	emsmdb_interface_set_rop_num(rop_num);
	b_icsup = FALSE;
	pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	size_t rop_count = double_list_get_nodes_num(&prop_buff->rop_list), rop_idx = 0;
	for (pnode=double_list_get_head(&prop_buff->rop_list); NULL!=pnode;
		pnode=double_list_get_after(&prop_buff->rop_list, pnode)) {
		auto pnode1 = cu_alloc<DOUBLE_LIST_NODE>();
		if (pnode1 == nullptr)
			return ecServerOOM;
		emsmdb_interface_set_rop_left(tmp_len - ext_push.m_offset);
		auto req = static_cast<ROP_REQUEST *>(pnode->pdata);
		auto result = rop_dispatch(req, reinterpret_cast<ROP_RESPONSE **>(&pnode1->pdata),
		              prop_buff->phandles, prop_buff->hnum);
		auto rsp = static_cast<ROP_RESPONSE *>(pnode1->pdata);
		bool dbg = g_rop_debug >= 2;
		if (g_rop_debug >= 1 && result != 0)
			dbg = true;
		if (g_rop_debug >= 1 && rsp != nullptr && rsp->result != 0)
			dbg = true;
		if (dbg) {
			char e1[32], e2[32];
			if (rsp != nullptr)
				mlog(LV_DEBUG, "[%zu/%zu] rop_dispatch(%s) EC=%s RS=%s",
					++rop_idx, rop_count,
					rop_idtoname(req->rop_id),
					mapi_errname_r(result, e1, std::size(e1)),
					mapi_errname_r(rsp->result, e2, std::size(e2)));
			else
				mlog(LV_DEBUG, "[%zu/%zu] rop_dispatch(%s) EC=%s RS=none",
					++rop_idx, rop_count,
					rop_idtoname(req->rop_id),
					mapi_errname_r(result, e1, std::size(e1)));
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
				return ecServerOOM;
			auto bts = static_cast<BUFFERTOOSMALL_RESPONSE *>(rsp->ppayload);
			bts->size_needed = rpcext_cutoff;
			bts->buffer = req->bookmark;
			if (rop_ext_push(&ext_push, req->logon_id, rsp) != pack_result::success)
				return ecBufferTooSmall;
			goto MAKE_RPC_EXT;
		}
		default:
			return result;
		}
		if (pemsmdb_info->upctx_ref != 0)
			b_icsup = TRUE;	
		/* some ROPs do not have response, for example ropRelease */
		if (rsp == nullptr)
			continue;
		uint32_t last_offset = ext_push.m_offset;
		auto status = rop_ext_push(&ext_push, req->logon_id, rsp);
		switch (status) {
		case EXT_ERR_SUCCESS:
			double_list_append_as_tail(presponse_list, pnode1);
			break;
		case EXT_ERR_BUFSIZE: {
			/* MS-OXCPRPT 3.2.5.2, fail the whole RPC */
			if (req->rop_id == ropGetPropertiesAll &&
			    pnode == double_list_get_head(&prop_buff->rop_list))
				return ecServerOOM;
			rsp->rop_id = ropBufferTooSmall;
			auto bts = cu_alloc<BUFFERTOOSMALL_RESPONSE>();
			rsp->ppayload = bts;
			if (rsp->ppayload == nullptr)
				return ecServerOOM;
			bts->size_needed = 0x8000;
			bts->buffer = req->bookmark;
			ext_push.m_offset = last_offset;
			if (rop_ext_push(&ext_push, req->logon_id, rsp) != pack_result::success)
				return ecBufferTooSmall;
			goto MAKE_RPC_EXT;
		}
		case EXT_ERR_ALLOC:
			return ecServerOOM;
		default:
			return ecRpcFailed;
		}
	}
	
	if (!b_notify || b_icsup)
		goto MAKE_RPC_EXT;
	while (true) {
		pnotify_list = emsmdb_interface_get_notify_list();
		if (pnotify_list == nullptr)
			return ecRpcFailed;
		pnode = double_list_pop_front(pnotify_list);
		emsmdb_interface_put_notify_list();
		if (pnode == nullptr)
			break;
		uint32_t last_offset = ext_push.m_offset;
		auto pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		ems_objtype type;
		auto pobject = rop_processor_get_object(pemsmdb_info->plogmap.get(), pnotify->logon_id, pnotify->handle, &type);
		if (NULL != pobject) {
			if (type == ems_objtype::table &&
				NULL != pnotify->notification_data.ptable_event &&
				(TABLE_EVENT_ROW_ADDED ==
				*pnotify->notification_data.ptable_event ||
				TABLE_EVENT_ROW_MODIFIED ==
				*pnotify->notification_data.ptable_event)) {
				auto tbl = static_cast<table_object *>(pobject);
				auto pcolumns = tbl->get_columns();
				if (!ext_push1.init(ext_buff1.get(), ext_buff_size, EXT_FLAG_UTF16))
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
			if (rop_ext_push(&ext_push, pnotify) != pack_result::success) {
				ext_push.m_offset = last_offset;
				double_list_insert_as_head(pnotify_list, pnode);
				emsmdb_interface_get_cxr(&tmp_pending.session_index);
				auto status = rop_ext_push(&ext_push, &tmp_pending);
				if (status != EXT_ERR_SUCCESS)
					ext_push.m_offset = last_offset;
				break;
			}
		}
 NEXT_NOTIFY:
		notify_response_free(static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload));
		free(pnode->pdata);
		free(pnode);
	}
	
 MAKE_RPC_EXT:
	if (rop_ext_make_rpc_ext(ext_buff.get(), ext_push.m_offset, prop_buff,
	    pbuff, pbuff_len) != EXT_ERR_SUCCESS)
		return ecError;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1173: ENOMEM");
	return ecServerOOM;
}

ec_error_t rop_processor_proc(uint32_t flags, const uint8_t *pin,
	uint32_t cb_in, uint8_t *pout, uint32_t *pcb_out)
{
	uint32_t tmp_cb;
	uint32_t offset;
	EXT_PULL ext_pull;
	ROP_BUFFER rop_buff;
	uint32_t last_offset;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST response_list;
	
	ext_pull.init(pin, cb_in, common_util_alloc, EXT_FLAG_UTF16);
	switch (rop_ext_pull(&ext_pull, &rop_buff)) {
	case EXT_ERR_SUCCESS:
		break;
	case EXT_ERR_ALLOC:
		return ecServerOOM;
	default:
		return ecRpcFormat;
	}
	rop_buff.rhe_flags = 0;
	if (!(flags & RPCEXT2_FLAG_NOXORMAGIC))
		rop_buff.rhe_flags |= RHE_FLAG_XORMAGIC;
	if (!(flags & RPCEXT2_FLAG_NOCOMPRESSION))
		rop_buff.rhe_flags |= RHE_FLAG_COMPRESSED;
	double_list_init(&response_list);
	tmp_cb = *pcb_out;
	auto result = rop_processor_execute_and_push(pout, &tmp_cb, &rop_buff,
	              TRUE, &response_list);
	if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
		mlog(LV_DEBUG, "rop_proc_ex+push() EC = %xh", static_cast<unsigned int>(result));
	if (result != ecSuccess)
		return result;
	offset = tmp_cb;
	last_offset = 0;
	auto count = double_list_get_nodes_num(&response_list);
	if (!(flags & RPCEXT2_FLAG_CHAIN)) {
		rop_ext_set_rhe_flag_last(pout, last_offset);
		*pcb_out = offset;
		return ecSuccess;
	}
	pnode = double_list_get_tail(&rop_buff.rop_list);
	pnode1 = double_list_get_tail(&response_list);
	if (pnode == nullptr || pnode1 == nullptr) {
		rop_ext_set_rhe_flag_last(pout, last_offset);
		*pcb_out = offset;
		return ecSuccess;
	}
	auto prequest = static_cast<const ROP_REQUEST *>(pnode->pdata);
	auto presponse = static_cast<ROP_RESPONSE *>(pnode1->pdata);
	if (prequest->rop_id != presponse->rop_id) {
		rop_ext_set_rhe_flag_last(pout, last_offset);
		*pcb_out = offset;
		return ecSuccess;
	}
	double_list_free(&rop_buff.rop_list);
	double_list_init(&rop_buff.rop_list);
	double_list_append_as_tail(&rop_buff.rop_list, pnode);
	double_list_free(&response_list);
	double_list_init(&response_list);
	
	if (presponse->rop_id == ropQueryRows) {
		auto req = static_cast<QUERYROWS_REQUEST *>(prequest->ppayload);
		auto rsp = static_cast<QUERYROWS_RESPONSE *>(presponse->ppayload);
		if (req->flags == QUERY_ROWS_FLAGS_ENABLEPACKEDBUFFERS) {
			rop_ext_set_rhe_flag_last(pout, last_offset);
			*pcb_out = offset;
			return ecSuccess;
		}
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (presponse->result == ecSuccess &&
		       *pcb_out - offset >= 0x8000 && count < g_max_rop_payloads) {
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
			if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
				mlog(LV_DEBUG, "rop_proc_ex+chain() EC = %xh", result);
			if (result != ecSuccess)
				break;
			pnode1 = double_list_pop_front(&response_list);
			if (pnode1 == nullptr)
				break;
			presponse = static_cast<ROP_RESPONSE *>(pnode1->pdata);
			if (presponse->rop_id != ropQueryRows ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (presponse->rop_id == ropReadStream &&
	    !(flags & GROMOX_READSTREAM_NOCHAIN)) {
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (presponse->result == ecSuccess &&
		       *pcb_out - offset >= 0x2000 && count < g_max_rop_payloads) {
			if (static_cast<READSTREAM_RESPONSE *>(presponse->ppayload)->data.cb == 0)
				break;
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
				mlog(LV_DEBUG, "rop_proc_ex+chain() EC = %xh", result);
			if (result != ecSuccess)
				break;
			pnode1 = double_list_pop_front(&response_list);
			if (pnode1 == nullptr)
				break;
			presponse = static_cast<ROP_RESPONSE *>(pnode1->pdata);
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
		       *pcb_out - offset >= 0x2000 && count < g_max_rop_payloads) {
			auto sgb = static_cast<const FASTTRANSFERSOURCEGETBUFFER_RESPONSE *>(presponse->ppayload);
			if (sgb->transfer_status == TRANSFER_STATUS_DONE ||
			    sgb->transfer_status == TRANSFER_STATUS_ERROR)
				break;
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
				mlog(LV_DEBUG, "rop_proc_ex+chain() EC = %xh", result);
			if (result != ecSuccess)
				break;
			pnode1 = double_list_pop_front(&response_list);
			if (pnode1 == nullptr)
				break;
			presponse = static_cast<ROP_RESPONSE *>(pnode1->pdata);
			if (presponse->rop_id != ropFastTransferSourceGetBuffer ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	}
	
	rop_ext_set_rhe_flag_last(pout, last_offset);
	*pcb_out = offset;
	return ecSuccess;
}
