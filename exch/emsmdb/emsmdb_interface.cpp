// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cassert>
#include <algorithm>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "asyncemsmdb_interface.h"
#include "aux_types.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "notify_response.h"
#include "processor_types.h"
#include "rop_ids.hpp"
#include "rop_processor.h"
#define	EMSMDB_PCMSPOLLMAX				60000
#define	EMSMDB_PCRETRY					6
#define	EMSMDB_PCRETRYDELAY				10000

#define HANDLE_EXCHANGE_EMSMDB			2

#define HANDLE_EXCHANGE_ASYNCEMSMDB		3
#define MAX_CONTENT_ROW_DELETED			6

#define FLAG_PRIVILEGE_ADMIN			0x00000001

using namespace gromox;

template<> struct std::hash<GUID> {
	std::size_t operator()(const GUID &g) const
	{
		uint64_t x[2];
		memcpy(x, &g, sizeof(x));
		auto c = reinterpret_cast<const char *>(x);
		return std::hash<uint64_t>()(*reinterpret_cast<const uint64_t *>(c)) ^
		       std::hash<uint64_t>()(*reinterpret_cast<const uint64_t *>(c + 8));
	}
};

namespace {

struct HANDLE_DATA {
	HANDLE_DATA();
	HANDLE_DATA(HANDLE_DATA &&) noexcept;
	~HANDLE_DATA();
	void operator=(HANDLE_DATA &&) noexcept = delete;

	GUID guid{};
	char username[UADDR_SIZE]{};
	BOOL b_processing = false; /* if the handle is processing rops */
	BOOL b_occupied = false; /* if the notify list is locked */
	time_point last_time;
	uint32_t last_handle = 0;
	int rop_num = 0;
	uint16_t rop_left = 0; /* size left in rop response buffer */
	uint16_t cxr = 0;
	emsmdb_info info;
	DOUBLE_LIST notify_list{};
};

struct NOTIFY_ITEM {
	uint32_t handle = 0;
	uint8_t logon_id = 0;
	GUID guid{};
};

}

static constexpr auto HANDLE_VALID_INTERVAL = std::chrono::seconds(2000);
static constexpr size_t TAG_SIZE = 256;
static time_point g_start_time;
static pthread_t g_scan_id;
static std::mutex g_lock, g_notify_lock;
static gromox::atomic_bool g_notify_stop{true};
static thread_local HANDLE_DATA *g_handle_key;
static std::unordered_map<GUID, HANDLE_DATA> g_handle_hash;
static std::unordered_map<std::string, std::vector<HANDLE_DATA *>> g_user_hash;
static std::unordered_map<std::string, NOTIFY_ITEM> g_notify_hash;
size_t ems_max_active_sessions, ems_max_active_users, ems_max_active_notifh;
size_t ems_max_pending_sesnotif;
static size_t ems_high_active_sessions, ems_high_active_users;
static size_t ems_high_active_notifh, ems_high_pending_sesnotif;

static void *emsi_scanwork(void *);

void emsmdb_report()
{
	size_t sessions = 0, logons = 0, pend_notif = 0;
	std::unique_lock gl_hold(g_lock);
	mlog(LV_INFO, "EMSMDB Sessions:");
	mlog(LV_INFO, "%-32s  %-32s  CXR CPID LCID #NF", "GUID", "USERNAME");
	mlog(LV_INFO, "LOGON  %-32s  MBOXUSER", "MBOXGUID");
	mlog(LV_INFO, "--------------------------------------------------------------------------------");
	/* Sort display by user, then CXR. */
	for (const auto &e1 : g_user_hash) {
	for (const auto hp : e1.second) {
		auto &h = *hp;
		auto &ei = h.info;
		auto pn = double_list_get_nodes_num(&h.notify_list);
		mlog(LV_INFO, "%-32s  %-32s  /%-2u %-4u %-4u %3zu",
			bin2hex(&h.guid, sizeof(GUID)).c_str(), h.username, h.cxr,
			ei.cpid, ei.lcid_string, pn);
		++sessions;
		pend_notif += pn;
		for (unsigned int i = 0; i < std::size(ei.plogmap->p); ++i) {
			auto li = ei.plogmap->p[i].get();
			if (li == nullptr)
				continue;
			auto root = li->root.get();
			if (root == nullptr || root->type != ems_objtype::logon) {
				mlog(LV_INFO, "%5u  null", i);
				continue;
			}
			++logons;
			auto lo = static_cast<logon_object *>(root->pobject);
			mlog(LV_INFO, "%5u  %-32s  %s(%u)", i,
			        bin2hex(&lo->mailbox_guid, sizeof(lo->mailbox_guid)).c_str(),
			        lo->account, lo->account_id);
		}
	}
	}
	mlog(LV_INFO, "Mailboxes %zu/%zu, EMSMDB ses %zu/%zu/%zu, ROPLogons %zu",
		g_user_hash.size(), ems_high_active_users,
		sessions, g_handle_hash.size(), ems_high_active_sessions,
		logons);
	gl_hold.unlock();
	std::lock_guard gl2(g_notify_lock);
	mlog(LV_INFO, "NotifyHandles %zu/%zu, NotifyPending %zu/%zu",
		g_notify_hash.size(), ems_high_active_notifh,
		pend_notif, ems_high_pending_sesnotif);
}

emsmdb_info::emsmdb_info(emsmdb_info &&o) noexcept :
	cpid(o.cpid), lcid_string(o.lcid_string), lcid_sort(o.lcid_sort),
	client_mode(o.client_mode), plogmap(std::move(o.plogmap)),
	upctx_ref(o.upctx_ref.load())
{
	memcpy(client_version, o.client_version, sizeof(client_version));
	o.upctx_ref = 0;
}

static uint32_t emsmdb_interface_get_timestamp()
{
	auto d = decltype(g_start_time)::clock::now() - g_start_time;
	return std::chrono::duration_cast<std::chrono::seconds>(d).count() + 1230336000;
}

BOOL emsmdb_interface_check_acxh(ACXH *pacxh,
	char *username, uint16_t *pcxr, BOOL b_touch)
{
	if (pacxh->handle_type != HANDLE_EXCHANGE_ASYNCEMSMDB)
		return FALSE;
	std::lock_guard gl_hold(g_lock);
	auto iter = g_handle_hash.find(pacxh->guid);
	if (iter == g_handle_hash.end())
		return false;
	auto phandle = &iter->second;
	if (b_touch)
		phandle->last_time = tp_now();
	strcpy(username, phandle->username);
	*pcxr = phandle->cxr;
	return TRUE;
}

BOOL emsmdb_interface_check_notify(ACXH *pacxh)
{
	if (pacxh->handle_type != HANDLE_EXCHANGE_ASYNCEMSMDB)
		return FALSE;
	std::lock_guard gl_hold(g_lock);
	auto iter = g_handle_hash.find(pacxh->guid);
	if (iter == g_handle_hash.end())
		return false;
	auto phandle = &iter->second;
	return double_list_get_nodes_num(&phandle->notify_list) > 0 ? TRUE : false;
}

/* called by moh_emsmdb module */
void emsmdb_interface_touch_handle(const CXH &cxh)
{
	auto pcxh = &cxh;
	if (pcxh->handle_type != HANDLE_EXCHANGE_EMSMDB)
		return;
	std::lock_guard gl_hold(g_lock);
	auto iter = g_handle_hash.find(pcxh->guid);
	if (iter != g_handle_hash.end())
		iter->second.last_time = tp_now();
}

static HANDLE_DATA* emsmdb_interface_get_handle_data(CXH *pcxh)
{
	if (pcxh->handle_type != HANDLE_EXCHANGE_EMSMDB)
		return NULL;
	while (true) {
		std::unique_lock gl_hold(g_lock);
		auto iter = g_handle_hash.find(pcxh->guid);
		if (iter == g_handle_hash.end())
			return NULL;
		auto phandle = &iter->second;
		if (phandle->b_processing) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			phandle->b_processing = TRUE;
			return phandle;
		}
	}
}

static void emsmdb_interface_put_handle_data(HANDLE_DATA *phandle)
{
	std::lock_guard gl_hold(g_lock);
	phandle->b_processing = FALSE;
}

static HANDLE_DATA* emsmdb_interface_get_handle_notify_list(CXH *pcxh)
{
	if (pcxh->handle_type != HANDLE_EXCHANGE_EMSMDB)
		return NULL;
	while (true) {
		std::unique_lock gl_hold(g_lock);
		auto iter = g_handle_hash.find(pcxh->guid);
		if (iter == g_handle_hash.end())
			return NULL;
		auto phandle = &iter->second;
		if (phandle->b_occupied) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			phandle->b_occupied = TRUE;
			return phandle;
		}
	}
}

static void emsmdb_interface_put_handle_notify_list(HANDLE_DATA *phandle)
{
	std::lock_guard gl_hold(g_lock);
	phandle->b_occupied = FALSE;
}

static BOOL emsmdb_interface_alloc_cxr(std::vector<HANDLE_DATA *> &plist,
	HANDLE_DATA *phandle)
{
	int i = 1;
	
	for (auto ha_iter = plist.begin(); ha_iter != plist.end() && i <= 0xFFFF;
	     ++ha_iter, ++i) {
		if (i < (*ha_iter)->cxr) {
			phandle->cxr = i;
			plist.insert(ha_iter, phandle);
			return TRUE;
		}
	}
	if (i > 0xFFFF)
		return FALSE;
	phandle->cxr = i;
	plist.push_back(phandle);
	return TRUE;
}

HANDLE_DATA::HANDLE_DATA() :
	guid(GUID::random_new()), last_time(tp_now())
{
	double_list_init(&notify_list);
}

HANDLE_DATA::HANDLE_DATA(HANDLE_DATA &&o) noexcept :
	guid(o.guid), b_processing(o.b_processing), b_occupied(o.b_occupied),
	last_time(o.last_time), last_handle(o.last_handle), rop_num(o.rop_num),
	rop_left(o.rop_left), cxr(o.cxr), info(std::move(o.info)),
	notify_list(std::move(o.notify_list))
{
	strcpy(username, o.username);
	o.notify_list = {};
}

HANDLE_DATA::~HANDLE_DATA()
{
	double_list_free(&notify_list);
}

static BOOL emsmdb_interface_create_handle(const char *username,
    uint16_t client_version[4], uint16_t client_mode, cpid_t cpid,
	uint32_t lcid_string, uint32_t lcid_sort, uint16_t *pcxr, CXH *pcxh)
{
	HANDLE_DATA temp_handle;
	
	if (!verify_cpid(cpid))
		return FALSE;
	temp_handle.info.cpid = cpid;
	temp_handle.info.lcid_string = lcid_string;
	temp_handle.info.lcid_sort = lcid_sort;
	memcpy(temp_handle.info.client_version, client_version, sizeof(temp_handle.info.client_version));
	temp_handle.info.client_mode = client_mode;
	gx_strlcpy(temp_handle.username, username, std::size(temp_handle.username));
	HX_strlower(temp_handle.username);
	std::unique_lock gl_hold(g_lock);
	if (ems_max_active_sessions > 0 &&
	    g_handle_hash.size() >= ems_max_active_sessions) {
		mlog(LV_WARN, "W-2300: g_handle_hash full (%zu handles)",
			ems_max_active_sessions);
		return FALSE;
	}
	temp_handle.info.plogmap = rop_processor_create_logmap();
	if (temp_handle.info.plogmap == nullptr)
		return false;

	HANDLE_DATA *phandle;

	try {
		auto xp = g_handle_hash.emplace(temp_handle.guid, std::move(temp_handle));
		ems_high_active_sessions = std::max(ems_high_active_sessions, g_handle_hash.size());
		phandle = &xp.first->second;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1578: ENOMEM");
		return false;
	}
	auto uh_iter = g_user_hash.find(phandle->username);
	if (uh_iter == g_user_hash.end()) {
		if (ems_max_active_users > 0 &&
		    g_user_hash.size() >= ems_max_active_users) {
			mlog(LV_WARN, "W-2301: g_user_hash full (%zu handles)",
				ems_max_active_users);
			g_handle_hash.erase(phandle->guid);
			gl_hold.unlock();
			return FALSE;
		}
		try {
			auto xp = g_user_hash.emplace(phandle->username, std::vector<HANDLE_DATA *>{});
			ems_high_active_users = std::max(ems_high_active_users, g_user_hash.size());
			uh_iter = xp.first;
		} catch (const std::bad_alloc &) {
			g_handle_hash.erase(phandle->guid);
			gl_hold.unlock();
			mlog(LV_ERR, "E-1579: ENOMEM");
			return FALSE;
		}
	} else {
		if (uh_iter->second.size() >= emsmdb_max_cxh_per_user) {
			mlog(LV_WARN, "W-1580: user %s reached maximum CXH (%u)",
			        phandle->username, emsmdb_max_cxh_per_user);
			g_handle_hash.erase(phandle->guid);
			gl_hold.unlock();
			return FALSE;
		}
	}
	if (!emsmdb_interface_alloc_cxr(uh_iter->second, phandle)) {
		if (uh_iter->second.empty())
			g_user_hash.erase(phandle->username);
		g_handle_hash.erase(phandle->guid);
		gl_hold.unlock();
		return FALSE;
	}
	*pcxr = phandle->cxr;
	gl_hold.unlock();
	pcxh->handle_type = HANDLE_EXCHANGE_EMSMDB;
	pcxh->guid = phandle->guid;
	return TRUE;
}

static void emsmdb_interface_remove_handle(const CXH &cxh)
{
	auto pcxh = &cxh;
	HANDLE_DATA *phandle;
	DOUBLE_LIST_NODE *pnode;
	
	if (pcxh->handle_type != HANDLE_EXCHANGE_EMSMDB)
		return;
	std::unique_lock gl_hold(g_lock);
	while (true) {
		auto iter = g_handle_hash.find(pcxh->guid);
		if (iter == g_handle_hash.end())
			return;
		phandle = &iter->second;
		if (phandle->b_processing)
			/* this means handle is being processed
			   in emsmdb_interface_rpc_ext2 by another
			   rpc connection, can not be released! */
			return;
		if (!phandle->b_occupied)
			break;
		gl_hold.unlock();
		usleep(100000);
	}
	auto uh_iter = g_user_hash.find(phandle->username);
	if (uh_iter != g_user_hash.end()) {
		auto &uhv = uh_iter->second;
		gromox::erase_first(uhv, phandle);
		if (uhv.empty())
			g_user_hash.erase(phandle->username);
	}
	while ((pnode = double_list_pop_front(&phandle->notify_list)) != nullptr) {
		notify_response_free(static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload));
		free(pnode->pdata);
		free(pnode);
	}
	auto plogmap = std::move(phandle->info.plogmap);
	g_handle_hash.erase(pcxh->guid);
	gl_hold.unlock();
}

void emsmdb_interface_init()
{
	g_start_time = decltype(g_start_time)::clock::now();
}

int emsmdb_interface_run()
{
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, emsi_scanwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		mlog(LV_ERR, "E-1447: pthread_create: %s", strerror(ret));
		return -4;
	}
	pthread_setname_np(g_scan_id, "emsmdb/scan");
	return 0;
}

void emsmdb_interface_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (!pthread_equal(g_scan_id, {})) {
			pthread_kill(g_scan_id, SIGALRM);
			pthread_join(g_scan_id, NULL);
		}
	}
	g_notify_hash.clear();
	g_user_hash.clear();
	g_handle_hash.clear();
}

int emsmdb_interface_disconnect(CXH &cxh)
{
	emsmdb_interface_remove_handle(cxh);
	memset(&cxh, 0, sizeof(CXH));
	return ecSuccess;
}

int emsmdb_interface_register_push_notification(CXH *pcxh, uint32_t rpc,
	uint8_t *pctx, uint16_t cb_ctx, uint32_t advise_bits, uint8_t *paddr,
	uint16_t cb_addr, uint32_t *phnotification)
{
	return ecNotSupported;
}

int emsmdb_interface_dummy_rpc(uint64_t hrpc)
{
	return ecSuccess;
}

static BOOL emsmdb_interface_decode_version(const uint16_t pvers[3],
	uint16_t pnormal_vers[4])
{
	if (pvers[1] & 0x8000) {
		pnormal_vers[0] = (pvers[0] & 0xFF00) >> 8;
		pnormal_vers[1] = pvers[0] & 0xFF;
		pnormal_vers[2] = pvers[1] & 0x7FFF;
		pnormal_vers[3] = pvers[2];
		return TRUE;
	} else {
		pnormal_vers[0] = pvers[0];
		pnormal_vers[1] = 0;
		pnormal_vers[2] = pvers[1];
		pnormal_vers[3] = pvers[2];
		return FALSE;
	}
}

static void emsmdb_interface_encode_version(BOOL high_bit,
	const uint16_t pnormal_vers[4], uint16_t pvers[3])
{
	if (high_bit) {
		pvers[0] = (pnormal_vers[0] << 8) | pnormal_vers[1];
		pvers[1] = pnormal_vers[2] | 0x8000;
		pvers[2] = pnormal_vers[3];
	} else {
		pvers[0] = pnormal_vers[0];
		pvers[1] = pnormal_vers[2];
		pvers[2] = pnormal_vers[3];
	}
}

/**
 * @flags:	this is related to PR_PROFILE_CONNECT_FLAGS.
 * 		OXCRPC only specifies a handful,
 * 		CONNECT_USE_ADMIN_PRIVILEGE = 0x1U,
 * 		CONNECT_IGNORE_NO_PF = 0x8000U,
 */
int emsmdb_interface_connect_ex(uint64_t hrpc, CXH *pcxh, const char *puser_dn,
    uint32_t flags, uint32_t con_mode, uint32_t limit, cpid_t cpid,
    uint32_t lcid_string, uint32_t lcid_sort, uint32_t cxr_link, uint16_t cnvt_cps,
	uint32_t *pmax_polls, uint32_t *pmax_retry, uint32_t *pretry_delay,
	uint16_t *pcxr, char *pdn_prefix, char *pdisplayname,
	const uint16_t pclient_vers[3], uint16_t pserver_vers[3],
	uint16_t pbest_vers[3], uint32_t *ptimestamp, const uint8_t *pauxin,
	uint32_t cb_auxin, uint8_t *pauxout, uint32_t *pcb_auxout)
{
	AUX_INFO aux_out;
	EXT_PUSH ext_push;
	char username[UADDR_SIZE];
	char temp_buff[1024];
	uint16_t client_mode;
	uint16_t client_version[4];
	AUX_CLIENT_CONTROL aux_control;
	uint16_t server_normal_version[4] = {15, 0, 847, 4040};
	bool is_success = false;

	auto cl_0 = make_scope_exit([&]() {
		if (is_success)
			return;
		memset(pcxh, 0, sizeof(CXH));
		*pmax_polls = 0;
		*pmax_retry = 0;
		*pretry_delay = 0;
		*pcxr = 0;
		pdisplayname[0] = '\0';
		memset(pserver_vers, 0, 3 * sizeof(*pserver_vers));
		memset(pbest_vers, 0, 3 * sizeof(*pbest_vers));
		*ptimestamp = 0;
	});
	
	aux_out.rhe_version = 0;
	aux_out.rhe_flags = RHE_FLAG_LAST;

	AUX_HEADER aux_header;
	aux_header.version = AUX_VERSION_1;
	aux_header.type = AUX_TYPE_EXORGINFO;
	aux_header.immed = PUBLIC_FOLDERS_ENABLED | USE_AUTODISCOVER_FOR_PUBLIC_FOLDER_CONFIGURATION;
	aux_out.aux_list.emplace_back(std::move(aux_header));
	
	aux_control.enable_flags = ENABLE_COMPRESSION | ENABLE_HTTP_TUNNELING;
	aux_control.expiry_time = 604800000;
	aux_header.version = AUX_VERSION_1;
	aux_header.type = AUX_TYPE_CLIENT_CONTROL;
	aux_header.ppayload = &aux_control;
	aux_out.aux_list.emplace_back(std::move(aux_header));
	
	aux_header.version = AUX_VERSION_1;
	aux_header.type = AUX_TYPE_ENDPOINT_CAPABILITIES;
	aux_header.immed = ENDPOINT_CAPABILITIES_SINGLE_ENDPOINT;
	aux_out.aux_list.emplace_back(std::move(aux_header));

	DCERPC_INFO rpc_info;
	if (!ext_push.init(pauxout, 0x1008, EXT_FLAG_UTF16))
		return ecServerOOM;
	*pcb_auxout = aux_ext_push_aux_info(&ext_push, aux_out) != EXT_ERR_SUCCESS ?
	              0 : ext_push.m_offset;
	aux_out.aux_list.clear();
	
	pdn_prefix[0] = '\0';
	rpc_info = get_rpc_info();
	if (flags & FLAG_PRIVILEGE_ADMIN)
		return ecLoginPerm;
	
	*pmax_polls = EMSMDB_PCMSPOLLMAX;
	*pmax_retry = EMSMDB_PCRETRY;
	*pretry_delay = EMSMDB_PCRETRYDELAY;
	
	if (*puser_dn == '\0')
		return ecAccessDenied;
	if (!common_util_essdn_to_username(puser_dn,
	    username, std::size(username)))
		return ecRpcFailed;
	if (*username == '\0')
		return ecUnknownUser;
	if (strcasecmp(username, rpc_info.username) != 0)
		return ecAccessDenied;
	if (!common_util_get_user_displayname(username, temp_buff, std::size(temp_buff)) ||
	    common_util_mb_from_utf8(cpid, temp_buff, pdisplayname, 1024) < 0)
		return ecRpcFailed;
	if (*pdisplayname == '\0')
		strcpy(pdisplayname, rpc_info.username);
	
	emsmdb_interface_decode_version(pclient_vers, client_version);
	emsmdb_interface_encode_version(TRUE, server_normal_version, pserver_vers);
	pbest_vers[0] = pclient_vers[0];
	pbest_vers[1] = pclient_vers[1];
	pbest_vers[2] = pclient_vers[2];
	
	if (cb_auxin > 0 && cb_auxin < 0x8)
		return ecRpcFailed;
	else if (cb_auxin > 0x1008)
		return RPC_X_BAD_STUB_DATA;
	
	client_mode = CLIENT_MODE_UNKNOWN;
	/* auxin parsing in commit history */
	/* just like EXCHANGE 2010 or later, we do
		not support session context linking */
	if (cxr_link == UINT32_MAX)
		*ptimestamp = emsmdb_interface_get_timestamp();
	if (!emsmdb_interface_create_handle(rpc_info.username, client_version,
	    client_mode, cpid, lcid_string, lcid_sort, pcxr, pcxh))
		return ecLoginFailure;
	is_success = true;
	return ecSuccess;
}

static bool enable_rop_chaining(uint16_t v[4])
{
	if (emsmdb_rop_chaining == 0)
		return false;
	return emsmdb_rop_chaining >= 2 || v[0] <= 14 || v[0] > 16 ||
	       (v[0] == 16 && v[2] >= 10000);
}

int emsmdb_interface_rpc_ext2(CXH &cxh, uint32_t *pflags,
	const uint8_t *pin, uint32_t cb_in, uint8_t *pout, uint32_t *pcb_out,
	const uint8_t *pauxin, uint32_t cb_auxin, uint8_t *pauxout,
	uint32_t *pcb_auxout, uint32_t *ptrans_time)
{
	auto pcxh = &cxh;
	int result;
	uint16_t cxr;
	char username[UADDR_SIZE];
	HANDLE_DATA *phandle;
	auto input_flags = *pflags;
	*pflags = 0;
	*pcb_auxout = 0;
	*ptrans_time = 0;
	
	/* ms-oxcrpc 3.1.4.2 */
	if (cb_in < 8 || *pcb_out < 8) {
		*pcb_out = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecRpcFailed;
	}
	if (cb_in > 0x40000)
		return RPC_X_BAD_STUB_DATA;
	/*
	 * OXCRPC says to check *pcb_out for 0x40000 and *pcb_auxout for
	 * 0x1008, but this only applies to RPCH where those are INOUT
	 * parameters (cf. emsmdb_ndr_pull_ecdorpcext2). In our MH, *pcb_out is
	 * the buffer size MH is offering us (auxout is unused).
	 */
	if (cb_auxin > 0x1008) {
		*pcb_out = 0;
		memset(pcxh, 0, sizeof(CXH));
		return RPC_X_BAD_STUB_DATA;
	}
	auto first_time = tp_now();
	phandle = emsmdb_interface_get_handle_data(pcxh);
	if (NULL == phandle) {
		*pcb_out = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecError;
	}
	auto rpc_info = get_rpc_info();
	if (0 != strcasecmp(phandle->username, rpc_info.username)) {
		emsmdb_interface_put_handle_data(phandle);
		*pcb_out = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecAccessDenied;
	}
	if (first_time - phandle->last_time > HANDLE_VALID_INTERVAL) {
		emsmdb_interface_put_handle_data(phandle);
		emsmdb_interface_remove_handle(cxh);
		*pcb_out = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecError;
	}
	phandle->last_time = tp_now();
	g_handle_key = phandle;
	/* auxin parsing in commit history */
	if (enable_rop_chaining(phandle->info.client_version))
		input_flags &= ~GROMOX_READSTREAM_NOCHAIN;
	else
		input_flags |= GROMOX_READSTREAM_NOCHAIN;
	result = rop_processor_proc(input_flags, pin, cb_in, pout, pcb_out);
	gx_strlcpy(username, phandle->username, std::size(username));
	cxr = phandle->cxr;
	BOOL b_wakeup = double_list_get_nodes_num(&phandle->notify_list) == 0 ? false : TRUE;
	emsmdb_interface_put_handle_data(phandle);
	if (b_wakeup)
		asyncemsmdb_interface_wakeup(username, cxr);
	g_handle_key = nullptr;
	if (result != ecSuccess) {
		*pcb_out = 0;
		return result;
	}
	*ptrans_time = std::chrono::duration_cast<std::chrono::milliseconds>(tp_now() - first_time).count();
	return ecSuccess;
}
	
int emsmdb_interface_async_connect_ex(CXH cxh, ACXH *pacxh)
{
	pacxh->handle_type = HANDLE_EXCHANGE_ASYNCEMSMDB;
	pacxh->guid = cxh.guid;
	return ecSuccess;
}

void emsmdb_interface_unbind_rpc_handle(uint64_t hrpc)
{
	/* do nothing */
}

const char *emsmdb_interface_get_username()
{
	auto h = g_handle_key;
	return h != nullptr ? h->username : nullptr;
}

const GUID* emsmdb_interface_get_handle()
{
	auto phandle = g_handle_key;
	return phandle != nullptr ? &phandle->guid : nullptr;
}

EMSMDB_INFO* emsmdb_interface_get_emsmdb_info()
{
	auto phandle = g_handle_key;
	return phandle != nullptr ? &phandle->info : nullptr;
}

DOUBLE_LIST* emsmdb_interface_get_notify_list()
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return NULL;
	while (true) {
		std::unique_lock gl_hold(g_lock);
		if (phandle->b_occupied) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			phandle->b_occupied = TRUE;
			return &phandle->notify_list;
		}
	}
}

void emsmdb_interface_put_notify_list()
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return;
	emsmdb_interface_put_handle_notify_list(phandle);
}

BOOL emsmdb_interface_get_cxr(uint16_t *pcxr)
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return FALSE;
	*pcxr = phandle->cxr;
	return TRUE;
}

BOOL emsmdb_interface_alloc_handle_number(uint32_t *pnum)
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return FALSE;
	if (phandle->last_handle >= INT32_MAX) {
		mlog(LV_ERR, "E-2304: Very long lived connection, awkward situation - I am not implemented!");
		return false;
	}
	*pnum = phandle->last_handle++;
	return TRUE;
}

BOOL emsmdb_interface_get_cxh(CXH *pcxh)
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return FALSE;
	pcxh->handle_type = HANDLE_EXCHANGE_EMSMDB;
	pcxh->guid = phandle->guid;
	return TRUE;
}

BOOL emsmdb_interface_get_rop_left(uint16_t *psize)
{
	auto phandle = g_handle_key;
	*psize = phandle != nullptr ? phandle->rop_left : 0;
	return phandle != nullptr;
}

BOOL emsmdb_interface_set_rop_left(uint16_t size)
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return FALSE;
	phandle->rop_left = size;
	return TRUE;
}

BOOL emsmdb_interface_get_rop_num(int *pnum)
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return FALSE;
	*pnum = phandle->rop_num;
	return TRUE;
}

BOOL emsmdb_interface_set_rop_num(int num)
{
	auto phandle = g_handle_key;
	if (phandle == nullptr)
		return FALSE;
	phandle->rop_num = num;
	return TRUE;
}

void emsmdb_interface_add_table_notify(const char *dir,
    uint32_t table_id, uint32_t handle, uint8_t logon_id, GUID *pguid) try
{
	char tag_buff[TAG_SIZE];
	NOTIFY_ITEM tmp_notify;
	
	tmp_notify.handle = handle;
	tmp_notify.logon_id = logon_id;
	tmp_notify.guid = *pguid;
	snprintf(tag_buff, std::size(tag_buff), "%u:%s", table_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	if (ems_max_active_notifh > 0 &&
	    g_notify_hash.size() >= ems_max_active_notifh) {
		mlog(LV_WARN, "W-2302: g_notify_hash full (%zu handles)",
			ems_max_active_notifh);
		return;
	}
	g_notify_hash.emplace(tag_buff, std::move(tmp_notify));
	ems_high_active_notifh = std::max(ems_high_active_notifh, g_notify_hash.size());
} catch (const std::bad_alloc &) {
	mlog(LV_WARN, "W-1541: ENOMEM");
}

static BOOL emsmdb_interface_get_table_notify(const char *dir,
	uint32_t table_id, uint32_t *phandle, uint8_t *plogon_id, GUID *pguid)
{
	char tag_buff[TAG_SIZE];
	snprintf(tag_buff, std::size(tag_buff), "%u:%s", table_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	const auto &nh = g_notify_hash;
	auto iter = nh.find(tag_buff);
	if (iter == nh.cend())
		return FALSE;
	auto pnotify = &iter->second;
	*phandle = pnotify->handle;
	*plogon_id = pnotify->logon_id;
	*pguid = pnotify->guid;
	return TRUE;
}

void emsmdb_interface_remove_table_notify(
	const char *dir, uint32_t table_id)
{
	char tag_buff[TAG_SIZE];
	
	snprintf(tag_buff, std::size(tag_buff), "%u:%s", table_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	g_notify_hash.erase(tag_buff);
}

void emsmdb_interface_add_subscription_notify(const char *dir,
    uint32_t sub_id, uint32_t handle, uint8_t logon_id, GUID *pguid) try
{
	char tag_buff[TAG_SIZE];
	NOTIFY_ITEM tmp_notify;
	
	
	tmp_notify.handle = handle;
	tmp_notify.logon_id = logon_id;
	tmp_notify.guid = *pguid;
	
	snprintf(tag_buff, std::size(tag_buff), "%u|%s", sub_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	if (ems_max_active_notifh > 0 &&
	    g_notify_hash.size() >= ems_max_active_notifh) {
		mlog(LV_WARN, "W-2303: g_notify_hash full (%zu handles)",
			ems_max_active_notifh);
		return;
	}
	g_notify_hash.emplace(tag_buff, std::move(tmp_notify));
	ems_high_active_notifh = std::max(ems_high_active_notifh, g_notify_hash.size());
} catch (const std::bad_alloc &) {
	mlog(LV_WARN, "W-1542: ENOMEM");
}

static BOOL emsmdb_interface_get_subscription_notify(
	const char *dir, uint32_t sub_id, uint32_t *phandle,
	uint8_t *plogon_id, GUID *pguid)
{
	char tag_buff[TAG_SIZE];
	snprintf(tag_buff, std::size(tag_buff), "%u|%s", sub_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	const auto &nh = g_notify_hash;
	auto iter = nh.find(tag_buff);
	if (iter == nh.cend())
		return FALSE;
	auto pnotify = &iter->second;
	*phandle = pnotify->handle;
	*plogon_id = pnotify->logon_id;
	*pguid = pnotify->guid;
	return TRUE;
}

void emsmdb_interface_remove_subscription_notify(
	const char *dir, uint32_t sub_id)
{
	char tag_buff[TAG_SIZE];
	
	snprintf(tag_buff, std::size(tag_buff), "%u|%s", sub_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	g_notify_hash.erase(tag_buff);
}

static BOOL emsmdb_interface_merge_content_row_deleted(
	uint32_t obj_handle, uint8_t logon_id, DOUBLE_LIST *pnotify_list)
{
	int count;
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	
	count = 1;
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle || pnotify->logon_id != logon_id)
			continue;
		if (pnotification_data->ptable_event == nullptr)
			continue;
		if (TABLE_EVENT_ROW_DELETED ==
			*pnotification_data->ptable_event) {
			count ++;
			if (MAX_CONTENT_ROW_DELETED == count) {
				notify_response_content_table_row_event_to_change(pnotify);
				return TRUE;
			}
		} else if (TABLE_EVENT_TABLE_CHANGED ==
			*pnotification_data->ptable_event) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL emsmdb_interface_merge_hierarchy_row_modified(
	const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *pmodified_row,
	uint32_t obj_handle, uint8_t logon_id, DOUBLE_LIST *pnotify_list)
{
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	auto row_folder_id = rop_util_nfid_to_eid(pmodified_row->row_folder_id);
	
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle || pnotify->logon_id != logon_id)
			continue;
		if (pnotification_data->ptable_event == nullptr)
			continue;
		if (TABLE_EVENT_ROW_MODIFIED ==
			*pnotification_data->ptable_event &&
			*pnotification_data->prow_folder_id
			== row_folder_id) {
			double_list_remove(pnotify_list, pnode);
			double_list_append_as_tail(pnotify_list, pnode);
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL emsmdb_interface_merge_message_modified(
	const DB_NOTIFY_MESSAGE_MODIFIED *pmodified_message,
	uint32_t obj_handle, uint8_t logon_id,
	DOUBLE_LIST *pnotify_list)
{
	uint64_t folder_id;
	uint64_t message_id;
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	
	folder_id = rop_util_make_eid_ex(
		1, pmodified_message->folder_id);
	message_id = rop_util_make_eid_ex(
		1, pmodified_message->message_id);
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle || pnotify->logon_id != logon_id)
			continue;
		if (pnotification_data->notification_flags ==
		    (NOTIFICATION_FLAG_OBJECTMODIFIED | NOTIFICATION_FLAG_MOST_MESSAGE) &&
		    *pnotification_data->pfolder_id == folder_id &&
		    *pnotification_data->pmessage_id == message_id &&
		    pnotification_data->pproptags->count == 0)
			return TRUE;
	}
	return FALSE;
}

static BOOL emsmdb_interface_merge_folder_modified(
	const DB_NOTIFY_FOLDER_MODIFIED *pmodified_folder,
	uint32_t obj_handle, uint8_t logon_id,
	DOUBLE_LIST *pnotify_list)
{
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	auto folder_id = rop_util_nfid_to_eid(pmodified_folder->folder_id);
	
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle || pnotify->logon_id != logon_id)
			continue;
		if (pnotification_data->notification_flags == NOTIFICATION_FLAG_OBJECTMODIFIED &&
		    *pnotification_data->pfolder_id == folder_id &&
		    pnotification_data->pproptags->count == 0)
			return TRUE;
	}
	return FALSE;
}

void emsmdb_interface_event_proc(const char *dir, BOOL b_table,
	uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	CXH cxh;
	uint16_t cxr;
	uint8_t logon_id;
	BOOL b_processing;
	char username[UADDR_SIZE];
	uint32_t obj_handle;
	HANDLE_DATA *phandle;
	DOUBLE_LIST_NODE *pnode;
	
	cxh.handle_type = HANDLE_EXCHANGE_EMSMDB;
	if (!b_table) {
		if (!emsmdb_interface_get_subscription_notify(dir,
		    notify_id, &obj_handle, &logon_id, &cxh.guid))
			return;
	} else {
		if (!emsmdb_interface_get_table_notify(dir,
		    notify_id, &obj_handle, &logon_id, &cxh.guid))
			return;
	}
	phandle = emsmdb_interface_get_handle_notify_list(&cxh);
	if (phandle == nullptr)
		return;
	switch (pdb_notify->type) {
	case db_notify_type::content_table_row_deleted:
		if (!emsmdb_interface_merge_content_row_deleted(obj_handle, logon_id, &phandle->notify_list))
			break;
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	case db_notify_type::hierarchy_table_row_modified:
		if (!emsmdb_interface_merge_hierarchy_row_modified(
		    static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *>(pdb_notify->pdata),
		    obj_handle, logon_id, &phandle->notify_list))
			break;
		b_processing = phandle->b_processing;
		if (!b_processing) {
			cxr = phandle->cxr;
			gx_strlcpy(username, phandle->username, std::size(username));
		}
		emsmdb_interface_put_handle_notify_list(phandle);
		if (!b_processing)
			asyncemsmdb_interface_wakeup(username, cxr);
		return;
	case db_notify_type::message_modified:
		if (!emsmdb_interface_merge_message_modified(
		    static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata),
		    obj_handle, logon_id, &phandle->notify_list))
			break;
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	case db_notify_type::folder_modified:
		if (!emsmdb_interface_merge_folder_modified(
		    static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata),
		    obj_handle, logon_id, &phandle->notify_list))
			break;
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	default:
		break;
	}
	auto notifnum = double_list_get_nodes_num(&phandle->notify_list);
	if (notifnum >= ems_max_pending_sesnotif) {
		mlog(LV_WARN, "W-2305: EMS session %s reached maximum of %zu pending notifications",
			bin2hex(phandle->guid).c_str(), ems_max_pending_sesnotif);
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	}
	ems_high_pending_sesnotif = std::max(ems_high_pending_sesnotif, notifnum);
	cxr = phandle->cxr;
	gx_strlcpy(username, phandle->username, std::size(username));
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	}
	pnode->pdata = me_alloc<ROP_RESPONSE>();
	if (NULL == pnode->pdata) {
		emsmdb_interface_put_handle_notify_list(phandle);
		free(pnode);
		return;
	}
	auto rsp = static_cast<ROP_RESPONSE *>(pnode->pdata);
	rsp->rop_id = ropRegisterNotify;
	rsp->hindex = 0; /* ignore by system */
	rsp->result = 0; /* ignore by system */
	auto nfr = notify_response_init(obj_handle, logon_id);
	rsp->ppayload = nfr;
	if (rsp->ppayload == nullptr) {
		emsmdb_interface_put_handle_notify_list(phandle);
		free(pnode->pdata);
		free(pnode);
		return;
	}
	BOOL b_cache = phandle->info.client_mode == CLIENT_MODE_CACHED ? TRUE : false;
	if (notify_response_retrieve(nfr, b_cache, pdb_notify)) {
		double_list_append_as_tail(&phandle->notify_list, pnode);
		b_processing = phandle->b_processing;
		emsmdb_interface_put_handle_notify_list(phandle);
	} else {
		b_processing = phandle->b_processing;
		emsmdb_interface_put_handle_notify_list(phandle);
		notify_response_free(nfr);
		free(pnode->pdata);
		free(pnode);
	}
	if (!b_processing)
		asyncemsmdb_interface_wakeup(username, cxr);
}

static void *emsi_scanwork(void *pparam)
{
	while (!g_notify_stop) {
		std::vector<GUID> temp_list;
		auto cur_time = tp_now();
		std::unique_lock gl_hold(g_lock);
		for (const auto &[guid, handle] : g_handle_hash) {
			auto phandle = &handle;
			if (phandle->b_processing || phandle->b_occupied)
				continue;
			if (cur_time - phandle->last_time > HANDLE_VALID_INTERVAL) try {
				temp_list.push_back(guid);
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1624: ENOMEM");
				continue;
			}
		}
		gl_hold.unlock();
		for (auto &&guid : temp_list)
			emsmdb_interface_remove_handle({HANDLE_EXCHANGE_EMSMDB, std::move(guid)});
		sleep(3);
	}
	return nullptr;
}
