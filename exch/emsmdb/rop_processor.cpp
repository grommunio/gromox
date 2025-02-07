// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
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
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "attachment_object.hpp"
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "fastdownctx_object.hpp"
#include "fastupctx_object.hpp"
#include "folder_object.hpp"
#include "icsdownctx_object.hpp"
#include "message_object.hpp"
#include "notify_response.hpp"
#include "processor_types.hpp"
#include "rop_dispatch.hpp"
#include "rop_ext.hpp"
#include "rop_ids.hpp"
#include "rop_processor.hpp"
#include "stream_object.hpp"
#include "table_object.hpp"

using namespace gromox;

static int g_scan_interval;
static pthread_t g_scan_id;
static gromox::atomic_bool g_notify_stop{true};
static std::mutex g_hash_lock;
static std::unordered_map<std::string, uint32_t> g_logon_hash;
static unsigned int g_emsmdb_full_parenting;
static unsigned int g_max_rop_payloads = 96;

unsigned int emsmdb_max_obh_per_session = 500;
unsigned int emsmdb_max_cxh_per_user = 100;
unsigned int emsmdb_pvt_folder_softdel, emsmdb_rop_chaining;
uint16_t server_normal_version[4];

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
		return handle;
	std::lock_guard hl_hold(g_hash_lock);
	auto pref = g_logon_hash.find(rlogon->get_dir());
	if (pref != g_logon_hash.end())
		++pref->second;
	else
		g_logon_hash.emplace(rlogon->get_dir(), 1);
	return handle;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1974: ENOMEM");
	return -ENOMEM;
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

ec_error_t aoh_to_error(int x)
{
	switch (x) {
	case -EEXIST:
	case -ESRCH:
	case -EINVAL: return ecRpcInvalidHandle;
	case -ENOMEM: return ecServerOOM;
	default: return ecRpcFailed;
	}
}

int32_t rop_processor_add_object_handle(LOGMAP *plogmap, uint8_t logon_id,
    int32_t parent_handle, object_node &&in_object) try
{
	auto eiuser = znul(emsmdb_interface_get_username());
	auto plogitem = plogmap->p[logon_id].get();
	if (plogitem == nullptr)
		return -EINVAL;
	auto root = plogitem->root.get();
	const char *target = "";
	if (root != nullptr && root->type == ems_objtype::logon) {
		auto lo = static_cast<logon_object *>(root->pobject);
		if (lo != nullptr)
			target = lo->account;
	}
	if (emsmdb_max_obh_per_session > 0 &&
	    plogitem->phash.size() >= emsmdb_max_obh_per_session) {
		mlog(LV_NOTICE, "W-2357: \"%s\" accessing \"%s\": limit exchange_emsmdb.cfg:emsmdb_max_obh_per_session (%u) reached",
			eiuser, target, emsmdb_max_obh_per_session);
		return -EMFILE;
	}

	std::shared_ptr<object_node> parent;
	if (parent_handle < 0) {
		if (plogitem->root != nullptr) {
			mlog(LV_ERR, "E-2356: \"%s\" on \"%s\": duplicate root object", eiuser, target);
			return -EEXIST;
		}
	} else if (parent_handle >= 0 && parent_handle < INT32_MAX) {
		auto i = plogitem->phash.find(parent_handle);
		if (i == plogitem->phash.end()) {
			mlog(LV_NOTICE, "E-2355: \"%s\" on \"%s\": invalid child object assignment", eiuser, target);
			return -ESRCH;
		}
		parent = i->second;
	} else {
		mlog(LV_NOTICE, "E-2354: \"%s\" on \"%s\": use of invalid parent object", eiuser, target);
		return -EINVAL;
	}
	auto pobjnode = std::make_shared<object_node>(std::move(in_object));
	if (!emsmdb_interface_alloc_handle_number(&pobjnode->handle))
		return -ENOMEM;
	auto xp = plogitem->phash.emplace(pobjnode->handle, pobjnode);
	if (!xp.second)
		return -ENOMEM;
	if (parent == nullptr)
		plogitem->root = pobjnode;
	else if (g_emsmdb_full_parenting || object_dep(parent->type, pobjnode->type))
		pobjnode->parent = std::move(parent);
	if (pobjnode->type == ems_objtype::icsupctx) {
		auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref ++;
	}
	return pobjnode->handle;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1975: ENOMEM");
	return -ENOMEM;
}

void *rop_processor_get_object(LOGMAP *plogmap, uint8_t logon_id,
    uint32_t obj_handle, ems_objtype *ptype)
{
	if (obj_handle >= INT32_MAX)
		return NULL;
	auto &plogitem = plogmap->p[logon_id];
	if (plogitem == nullptr)
		return NULL;
	if (g_rop_debug >= 1 && plogitem->root != nullptr) {
		auto lo = static_cast<logon_object *>(plogitem->root->pobject);
		if (lo != nullptr)
			g_last_rop_dir = lo->get_dir();
	}
	auto i = plogitem->phash.find(obj_handle);
	if (i == plogitem->phash.end())
		return NULL;
	*ptype = i->second->type;
	return i->second->pobject;
}

void rop_processor_release_object_handle(LOGMAP *plogmap,
	uint8_t logon_id, uint32_t obj_handle)
{
	if (obj_handle >= INT32_MAX)
		return;
	auto &plogitem = plogmap->p[logon_id];
	if (plogitem == nullptr)
		return;
	if (g_rop_debug > 0) {
		auto root = plogitem->root;
		if (root != nullptr) {
			auto obj = static_cast<logon_object *>(root->pobject);
			/* obj->dir may go away with .erase */
			static char lastdir[256];
			gx_strlcpy(lastdir, obj->dir, std::size(lastdir));
			g_last_rop_dir = lastdir;
		}
	}
	auto i = plogitem->phash.find(obj_handle);
	if (i == plogitem->phash.end())
		return;
	auto objnode = i->second;
	if (objnode->type == ems_objtype::icsupctx) {
		auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
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
	auto obj = static_cast<logon_object *>(proot->pobject);
	g_last_rop_dir = obj->get_dir();
	return obj;
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
			exmdb_client->ping_store(dirs.back().c_str());
			dirs.pop_back();
		}
	} catch (const std::bad_alloc &) {
		sleep(1);
	}
	return nullptr;
}

void rop_processor_init(int scan_interval)
{
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
	{ /* silence cov-scan, take locks even in single-thread scenarios */
		std::lock_guard lk(g_hash_lock);
		g_logon_hash.clear();
	}
}

static uint32_t rpcext_cutoff = 32U << 10; /* OXCRPC v23 3.1.4.2.1.2.2 */

thread_local const char *g_last_rop_dir;

static ec_error_t rop_processor_execute_and_push(uint8_t *pbuff,
    uint32_t *pbuff_len, ROP_BUFFER *prop_buff, BOOL b_notify,
    std::vector<std::unique_ptr<rop_response>> &response_list) try
{
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
	const auto rop_num = prop_buff->rop_list.size();
	size_t rop_idx = 0;
	emsmdb_interface_set_rop_num(rop_num);
	b_icsup = FALSE;
	auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	for (auto req_iter = prop_buff->rop_list.cbegin();
	     req_iter != prop_buff->rop_list.cend(); ++req_iter) {
		emsmdb_interface_set_rop_left(tmp_len - ext_push.m_offset);
		const rop_request *req = req_iter->get();
		/*
		 * One RPC may contain multiple ROPs and if one ROP fails,
		 * subsequent ROPs may still be invoked, albeit with
		 * INVALID_HANDLEs, thus also failing, though with
		 * ecNullObject. This is normal even if it generated worrying
		 * output with rop_debug=1.
		 *
		 * Think of it as close(open("nonexisting",O_RDONLY));
		 */
		std::unique_ptr<rop_response> rsp;
		g_last_rop_dir = nullptr;
		auto result = rop_dispatch(*req, rsp, prop_buff->phandles, prop_buff->hnum);
		bool dbg = g_rop_debug >= 2;
		if (g_rop_debug >= 1 && result != 0)
			dbg = true;
		if (g_rop_debug >= 1 && rsp != nullptr && rsp->result != 0)
			dbg = true;
		if (dbg) {
			char e1[32], e2[32];
			auto rpd = g_last_rop_dir != nullptr ? g_last_rop_dir : ".";
			if (rsp != nullptr)
				mlog(LV_DEBUG, "[%zu/%zu] %s %s EC=%s RS=%s",
					++rop_idx, rop_num, rpd,
					rop_idtoname(req->rop_id),
					mapi_errname_r(result, e1, std::size(e1)),
					mapi_errname_r(rsp->result, e2, std::size(e2)));
			else
				mlog(LV_DEBUG, "[%zu/%zu] %s %s EC=%s RS=none",
					++rop_idx, rop_num, rpd,
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
			BUFFERTOOSMALL_RESPONSE bts{};
			bts.rop_id = ropBufferTooSmall;
			bts.size_needed = rpcext_cutoff;
			bts.buffer = req->rq_bookmark;
			if (rop_ext_push(ext_push, req->logon_id, bts) != pack_result::success)
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
		auto status = rop_ext_push(ext_push, req->logon_id, *rsp);
		switch (status) {
		case EXT_ERR_SUCCESS:
			try {
				response_list.push_back(std::move(rsp));
			} catch (const std::bad_alloc &) {
				return ecServerOOM;
			}
			break;
		case EXT_ERR_BUFSIZE: {
			/* MS-OXCPRPT 3.2.5.2, fail the whole RPC */
			if (req->rop_id == ropGetPropertiesAll &&
			    req_iter == prop_buff->rop_list.begin())
				return ecServerOOM;
			BUFFERTOOSMALL_RESPONSE bts{};
			bts.rop_id = ropBufferTooSmall;
			bts.size_needed = 0x8000;
			bts.buffer = req->rq_bookmark;
			ext_push.m_offset = last_offset;
			if (rop_ext_push(ext_push, req->logon_id, bts) != pack_result::success)
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
		auto pnotify = static_cast<notify_response *>(pnode->pdata);
		ems_objtype type;
		auto pobject = rop_processor_get_object(&pemsmdb_info->logmap, pnotify->logon_id, pnotify->handle, &type);
		if (NULL != pobject) {
			if (type == ems_objtype::table &&
			    pnotify->nflags & NF_TABLE_MODIFIED &&
			    (pnotify->table_event == TABLE_EVENT_ROW_ADDED ||
			    pnotify->table_event == TABLE_EVENT_ROW_MODIFIED)) {
				auto tbl = static_cast<table_object *>(pobject);
				auto pcolumns = tbl->get_columns();
				if (!ext_push1.init(ext_buff1.get(), ext_buff_size, EXT_FLAG_UTF16))
					goto NEXT_NOTIFY;
				if (pnotify->nflags & NF_BY_MESSAGE) {
					if (!tbl->read_row(pnotify->row_message_id,
					    pnotify->row_instance,
					    &propvals) || propvals.count == 0)
						goto NEXT_NOTIFY;
					
				} else {
					if (!tbl->read_row(pnotify->row_folder_id,
					    0, &propvals) || propvals.count == 0)
						goto NEXT_NOTIFY;
				}
				if (!common_util_propvals_to_row(&propvals, pcolumns, &tmp_row) ||
				    ext_push1.p_proprow(*pcolumns, tmp_row) != EXT_ERR_SUCCESS)
					goto NEXT_NOTIFY;
				tmp_bin.cb = ext_push1.m_offset;
				tmp_bin.pb = ext_push1.m_udata;
				pnotify->row_data = &tmp_bin;
			}
			if (rop_ext_push(ext_push, *pnotify) != pack_result::success) {
				ext_push.m_offset = last_offset;
				double_list_insert_as_head(pnotify_list, pnode);
				emsmdb_interface_get_cxr(&tmp_pending.session_index);
				auto status = rop_ext_push(ext_push, tmp_pending);
				if (status != EXT_ERR_SUCCESS)
					ext_push.m_offset = last_offset;
				break;
			}
		}
 NEXT_NOTIFY:
		delete static_cast<notify_response *>(pnode->pdata);
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
	/*
	 * (response_list.)GETPROPERTIESSPECIFIC_RESPONSE::pproptags can link
	 * to (rop_buff.)GETPROPERTIESSPECIFIC_REQUEST::pproptags, so watch
	 * lifetime and destruction order.
	 */
	std::vector<std::unique_ptr<rop_response>> response_list;
	
	ext_pull.init(pin, cb_in, common_util_alloc, EXT_FLAG_UTF16);
	switch (rop_ext_pull(ext_pull, rop_buff)) {
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
	tmp_cb = *pcb_out;
	auto result = rop_processor_execute_and_push(pout, &tmp_cb, &rop_buff,
	              TRUE, response_list);
	if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
		mlog(LV_DEBUG, "rop_proc_ex+push() EC = %xh", static_cast<unsigned int>(result));
	if (result != ecSuccess)
		return result;
	offset = tmp_cb;
	last_offset = 0;
	auto count = response_list.size();
	if (!(flags & RPCEXT2_FLAG_CHAIN)) {
		rop_ext_set_rhe_flag_last(pout, last_offset);
		*pcb_out = offset;
		return ecSuccess;
	}

	/*
	 * Repeat execution of the last ROP (if it is a chainable ROP) to
	 * produce more responses pursuant to MS-OXCRPC v24 §3.1.4.2.1.2.2.
	 */
	if (rop_buff.rop_list.empty() || response_list.empty()) {
		rop_ext_set_rhe_flag_last(pout, last_offset);
		*pcb_out = offset;
		return ecSuccess;
	}
	auto prequest_mutable = static_cast<rop_request *>(rop_buff.rop_list.back().get());
	auto prequest = static_cast<const rop_request *>(prequest_mutable);
	auto presponse = static_cast<const rop_response *>(response_list.back().get());
	auto tail_response_ropid = presponse->rop_id;

	if (prequest->rop_id != presponse->rop_id) {
		rop_ext_set_rhe_flag_last(pout, last_offset);
		*pcb_out = offset;
		return ecSuccess;
	}
	rop_buff.rop_list[0] = std::move(rop_buff.rop_list.back());
	rop_buff.rop_list.erase(rop_buff.rop_list.begin() + 1, rop_buff.rop_list.end());
	auto holder_rsp = std::move(response_list.back()); // presponse stays valid
	response_list.clear();
	
	if (tail_response_ropid == ropQueryRows) {
		auto req = static_cast<QUERYROWS_REQUEST *>(prequest_mutable);
		auto rsp = static_cast<const QUERYROWS_RESPONSE *>(presponse);
		if (req->flags == QUERY_ROWS_FLAGS_ENABLEPACKEDBUFFERS) {
			rop_ext_set_rhe_flag_last(pout, last_offset);
			*pcb_out = offset;
			return ecSuccess;
		}
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
			         &tmp_cb, &rop_buff, false, response_list);
			if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
				mlog(LV_DEBUG, "rop_proc_ex+chain() EC = %xh", result);
			if (result != ecSuccess)
				break;
			if (response_list.empty())
				break;
			holder_rsp = std::move(response_list.front());
			response_list.erase(response_list.begin());
			presponse = holder_rsp.get();
			if (presponse->rop_id != ropQueryRows ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (tail_response_ropid == ropReadStream &&
	    !(flags & GROMOX_READSTREAM_NOCHAIN)) {
		while (presponse->result == ecSuccess &&
		       *pcb_out - offset >= 0x2000 && count < g_max_rop_payloads) {
			if (static_cast<const READSTREAM_RESPONSE *>(presponse)->data.cb == 0)
				break;
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
			         &tmp_cb, &rop_buff, false, response_list);
			if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
				mlog(LV_DEBUG, "rop_proc_ex+chain() EC = %xh", result);
			if (result != ecSuccess)
				break;
			if (response_list.empty())
				break;
			holder_rsp = std::move(response_list.front());
			response_list.erase(response_list.begin());
			presponse = holder_rsp.get();
			if (presponse->rop_id != ropReadStream ||
			    presponse->result != ecSuccess)
				break;
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (tail_response_ropid == ropFastTransferSourceGetBuffer) {
		while (presponse->result == ecSuccess &&
		       *pcb_out - offset >= 0x2000 && count < g_max_rop_payloads) {
			auto sgb = static_cast<const FASTTRANSFERSOURCEGETBUFFER_RESPONSE *>(presponse);
			if (sgb->transfer_status == TRANSFER_STATUS_DONE ||
			    sgb->transfer_status == TRANSFER_STATUS_ERROR)
				break;
			tmp_cb = *pcb_out - offset;
			result = rop_processor_execute_and_push(pout + offset,
			         &tmp_cb, &rop_buff, false, response_list);
			if (g_rop_debug >= 2 || (g_rop_debug >= 1 && result != 0))
				mlog(LV_DEBUG, "rop_proc_ex+chain() EC = %xh", result);
			if (result != ecSuccess)
				break;
			if (response_list.empty())
				break;
			holder_rsp = std::move(response_list.front());
			response_list.erase(response_list.begin());
			presponse = holder_rsp.get();
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
