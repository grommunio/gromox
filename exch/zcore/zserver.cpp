// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2022 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <gromox/ab_tree.hpp>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/int_hash.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/safeint.hpp>
#include <gromox/scope.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include <gromox/zcore_rpc.hpp>
#include "ab_tree.h"
#include "common_util.h"
#include "exmdb_client.h"
#include "ics_state.h"
#include "object_tree.h"
#include "objects.hpp"
#include "rpc_ext.h"
#include "rpc_parser.hpp"
#include "store_object.h"
#include "system_services.hpp"
#include "table_object.h"
#include "zserver.hpp"

using namespace std::string_literals;
using namespace gromox;
using LLU = unsigned long long;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

namespace {

struct NOTIFY_ITEM {
	NOTIFY_ITEM(const GUID &session, uint32_t store);
	~NOTIFY_ITEM();
	NOMOVE(NOTIFY_ITEM);

	DOUBLE_LIST notify_list{};
	GUID hsession{};
	uint32_t hstore = 0;
	time_t last_time = 0;
};

struct user_info_del {
	void operator()(USER_INFO *x);
};

}

using USER_INFO_REF = std::unique_ptr<USER_INFO, user_info_del>;

static size_t g_table_size;
static gromox::atomic_bool g_notify_stop;
static int g_ping_interval;
static pthread_t g_scan_id;
static int g_cache_interval;
static thread_local USER_INFO *g_info_key;
static std::mutex g_table_lock, g_notify_lock;
static std::unordered_map<std::string, int> g_user_table;
static std::unordered_map<std::string, NOTIFY_ITEM> g_notify_table;
static std::unordered_map<int, USER_INFO> g_session_table;

sink_node::~sink_node()
{
	if (clifd >= 0)
		close(clifd);
	free(sink.padvise);
}

USER_INFO::USER_INFO(USER_INFO &&o) noexcept :
	hsession(o.hsession), user_id(o.user_id), domain_id(o.domain_id),
	org_id(o.org_id), username(std::move(o.username)),
	lang(std::move(o.lang)), maildir(std::move(o.maildir)),
	homedir(std::move(o.homedir)), cpid(o.cpid), flags(o.flags),
	last_time(o.last_time), reload_time(o.reload_time),
	ptree(std::move(o.ptree)), sink_list(std::move(o.sink_list))
{}

USER_INFO::~USER_INFO()
{
	auto pinfo = this;
	sink_list.clear();
	if (pinfo->ptree != nullptr) {
		common_util_build_environment();
		pinfo->ptree.reset();
		common_util_free_environment();
	}
}

static int zs_get_user_id(GUID hsession)
{
	int32_t user_id;
	
	memcpy(&user_id, hsession.node, sizeof(int32_t));
	return user_id;
}

static USER_INFO_REF zs_query_session(GUID hsession)
{
	auto user_id = zs_get_user_id(hsession);
	std::unique_lock tl_hold(g_table_lock);
	auto iter = g_session_table.find(user_id);
	if (iter == g_session_table.end())
		return nullptr;
	auto pinfo = &iter->second;
	if (hsession != pinfo->hsession)
		return nullptr;
	pinfo->reference ++;
	time(&pinfo->last_time);
	tl_hold.unlock();
	g_info_key = pinfo;
	pinfo->lock.lock();
	return USER_INFO_REF(pinfo);
}

USER_INFO *zs_get_info()
{
	return g_info_key;
}

void user_info_del::operator()(USER_INFO *pinfo)
{
	pinfo->lock.unlock();
	std::unique_lock tl_hold(g_table_lock);
	pinfo->reference --;
	tl_hold.unlock();
	g_info_key = nullptr;
}

NOTIFY_ITEM::NOTIFY_ITEM(const GUID &ses, uint32_t store) :
	hsession(ses), hstore(store)
{
	double_list_init(&notify_list);
	time(&last_time);
}

NOTIFY_ITEM::~NOTIFY_ITEM()
{
	DOUBLE_LIST_NODE *pnode;
	while ((pnode = double_list_pop_front(&notify_list)) != nullptr) {
		common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
		free(pnode);
	}
	double_list_free(&notify_list);
}

static void *zcorezs_scanwork(void *param)
{
	int count;
	int tv_msec;
	BINARY tmp_bin;
	time_t cur_time;
	uint8_t tmp_byte;
	struct pollfd fdpoll;
	
	count = 0;
	const zcresp_notifdequeue response = {zcresp{zcore_callid::notifdequeue, ecSuccess}};
	while (!g_notify_stop) {
		sleep(1);
		count ++;
		if (count >= g_ping_interval)
			count = 0;
		std::vector<std::string> maildir_list;
		std::list<sink_node> expired_list;
		std::unique_lock tl_hold(g_table_lock);
		time(&cur_time);
		for (auto iter = g_session_table.begin(); iter != g_session_table.end(); ) {
			auto pinfo = &iter->second;
			if (0 != pinfo->reference) {
				++iter;
				continue;
			}
			auto ptail = pinfo->sink_list.size() > 0 ? &pinfo->sink_list.back() : nullptr;
			while (pinfo->sink_list.size() > 0) {
				auto psink_node = &pinfo->sink_list.front();
				if (cur_time >= psink_node->until_time)
					expired_list.splice(expired_list.end(), pinfo->sink_list, pinfo->sink_list.begin());
				else
					pinfo->sink_list.splice(pinfo->sink_list.end(), pinfo->sink_list, pinfo->sink_list.begin());
				if (psink_node == ptail)
					break;
			}
			if (cur_time - pinfo->reload_time >= g_cache_interval) {
				common_util_build_environment();
				auto ptree = object_tree_create(pinfo->get_maildir());
				if (NULL != ptree) {
					pinfo->ptree = std::move(ptree);
					pinfo->reload_time = cur_time;
				}
				common_util_free_environment();
				++iter;
				continue;
			}
			if (cur_time - pinfo->last_time < g_cache_interval) {
				if (0 != count) {
					++iter;
					continue;
				}
				try {
					maildir_list.push_back(pinfo->get_maildir());
				} catch (const std::bad_alloc &) {
					mlog(LV_ERR, "E-2178: ENOMEM");
					++iter;
					continue;
				}
				++iter;
			} else {
				if (pinfo->sink_list.size() != 0) {
					++iter;
					continue;
				}
				common_util_build_environment();
				pinfo->ptree.reset();
				common_util_free_environment();
				pinfo->sink_list.clear();
				g_user_table.erase(pinfo->username);
				iter = g_session_table.erase(iter);
			}
		}
		tl_hold.unlock();
		for (const auto &dir : maildir_list) {
			common_util_build_environment();
			exmdb_client::ping_store(dir.c_str());
			common_util_free_environment();
		}
		maildir_list.clear();
		while (expired_list.size() > 0) {
			std::list<sink_node> holder;
			holder.splice(holder.end(), expired_list, expired_list.begin());
			auto psink_node = &holder.front();
			/* implied ~sink_node at end of scope */
			if (!rpc_ext_push_response(&response, &tmp_bin))
				continue;
			tv_msec = SOCKET_TIMEOUT * 1000;
			fdpoll.fd = psink_node->clifd;
			fdpoll.events = POLLOUT|POLLWRBAND;
			if (tmp_bin.pb != nullptr && poll(&fdpoll, 1, tv_msec) == 1)
				write(psink_node->clifd, tmp_bin.pb, tmp_bin.cb);
			free(tmp_bin.pb);
			tmp_bin.pb = nullptr;
			shutdown(psink_node->clifd, SHUT_WR);
			if (read(psink_node->clifd, &tmp_byte, 1))
				/* ignore */;
		}
		if (count != 0)
			continue;
		time(&cur_time);
		std::unique_lock nl_hold(g_notify_lock);
#if __cplusplus >= 202000L
		std::erase_if(g_notify_table, [=](const auto &it) {
			return cur_time - it.second.last_time >= g_cache_interval;
		});
#else
		for (auto iter1 = g_notify_table.begin(); iter1 != g_notify_table.end(); ) {
			auto pnitem = &iter1->second;
			if (cur_time - pnitem->last_time >= g_cache_interval)
				iter1 = g_notify_table.erase(iter1);
			else
				++iter1;
		}
#endif
	}
	return NULL;
}

static void zs_notification_proc(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	int i;
	int tv_msec;
	GUID hsession;
	BINARY tmp_bin;
	uint32_t hstore;
	uint64_t old_eid;
	zs_objtype mapi_type;
	char tmp_buff[256];
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t message_id;
	struct pollfd fdpoll;
	uint64_t old_parentid;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	DOUBLE_LIST_NODE *pnode;
	uint32_t proptag_buff[2];
	ZNOTIFICATION *pnotification;
	NEWMAIL_ZNOTIFICATION *pnew_mail;
	OBJECT_ZNOTIFICATION *pobj_notify;
	
	if (b_table)
		return;
	snprintf(tmp_buff, arsizeof(tmp_buff), "%u|%s", notify_id, dir);
	std::unique_lock nl_hold(g_notify_lock);
	auto iter = g_notify_table.find(tmp_buff);
	if (iter == g_notify_table.end())
		return;
	auto pitem = &iter->second;
	hsession = pitem->hsession;
	hstore = pitem->hstore;
	nl_hold.unlock();
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr || mapi_type != zs_objtype::store ||
	    strcmp(dir, pstore->get_dir()) != 0)
		return;
	pnotification = cu_alloc<ZNOTIFICATION>();
	if (pnotification == nullptr)
		return;
	switch (pdb_notify->type) {
	case DB_NOTIFY_TYPE_NEW_MAIL: {
		pnotification->event_type = EVENT_TYPE_NEWMAIL;
		pnew_mail = cu_alloc<NEWMAIL_ZNOTIFICATION>();
		if (pnew_mail == nullptr)
			return;
		pnotification->pnotification_data = pnew_mail;
		auto nt = static_cast<const DB_NOTIFY_NEW_MAIL *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		auto pbin = cu_mid_to_entryid(pstore, folder_id, message_id);
		if (pbin == nullptr)
			return;
		pnew_mail->entryid = *pbin;
		pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pnew_mail->parentid = *pbin;
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = PR_MESSAGE_CLASS;
		proptag_buff[1] = PR_MESSAGE_FLAGS;
		if (!exmdb_client::get_message_properties(dir, nullptr, 0,
		    message_id, &proptags, &propvals))
			return;
		auto str = propvals.get<char>(PR_MESSAGE_CLASS);
		if (str == nullptr)
			return;
		pnew_mail->message_class = str;
		auto num = propvals.get<const uint32_t>(PR_MESSAGE_FLAGS);
		if (num == nullptr)
			return;
		pnew_mail->message_flags = *num;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_CREATED: {
		pnotification->event_type = EVENT_TYPE_OBJECTCREATED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_FOLDER_CREATED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		parent_id = rop_util_nfid_to_eid(nt->parent_id);
		pobj_notify->object_type = MAPI_FOLDER;
		auto pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, parent_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_CREATED: {
		pnotification->event_type = EVENT_TYPE_OBJECTCREATED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = MAPI_MESSAGE;
		auto pbin = cu_mid_to_entryid(pstore, folder_id, message_id);
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_DELETED: {
		pnotification->event_type = EVENT_TYPE_OBJECTDELETED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_FOLDER_DELETED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		parent_id = rop_util_nfid_to_eid(nt->parent_id);
		pobj_notify->object_type = MAPI_FOLDER;
		auto pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, parent_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_DELETED: {
		pnotification->event_type = EVENT_TYPE_OBJECTDELETED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = MAPI_MESSAGE;
		auto pbin = cu_mid_to_entryid(pstore, folder_id, message_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED: {
		pnotification->event_type = EVENT_TYPE_OBJECTMODIFIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		pobj_notify->object_type = MAPI_FOLDER;
		auto pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED: {
		pnotification->event_type = EVENT_TYPE_OBJECTMODIFIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = MAPI_MESSAGE;
		auto pbin = cu_mid_to_entryid(pstore, folder_id, message_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED: {
		pnotification->event_type = pdb_notify->type == DB_NOTIFY_TYPE_FOLDER_MOVED ?
		                            EVENT_TYPE_OBJECTMOVED : EVENT_TYPE_OBJECTCOPIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		parent_id = rop_util_nfid_to_eid(nt->parent_id);
		old_eid = rop_util_nfid_to_eid(nt->old_folder_id);
		old_parentid = rop_util_nfid_to_eid(nt->old_parent_id);
		pobj_notify->object_type = MAPI_FOLDER;
		auto pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, parent_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		pbin = cu_fid_to_entryid(pstore, old_eid);
		if (pbin == nullptr)
			return;
		pobj_notify->pold_entryid = pbin;
		pbin = cu_fid_to_entryid(pstore, old_parentid);
		if (pbin == nullptr)
			return;
		pobj_notify->pold_parentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED: {
		pnotification->event_type = pdb_notify->type == DB_NOTIFY_TYPE_MESSAGE_MOVED ?
		                            EVENT_TYPE_OBJECTMOVED : EVENT_TYPE_OBJECTCOPIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		old_parentid = rop_util_nfid_to_eid(nt->old_folder_id);
		old_eid = rop_util_make_eid_ex(1, nt->old_message_id);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = MAPI_MESSAGE;
		auto pbin = cu_mid_to_entryid(pstore, folder_id, message_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pparentid = pbin;
		pbin = cu_mid_to_entryid(pstore, old_parentid, old_eid);
		if (pbin == nullptr)
			return;
		pobj_notify->pold_entryid = pbin;
		pbin = cu_fid_to_entryid(pstore, old_parentid);
		if (pbin == nullptr)
			return;
		pobj_notify->pold_parentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED: {
		pnotification->event_type = EVENT_TYPE_SEARCHCOMPLETE;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (pobj_notify == nullptr)
			return;
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<const DB_NOTIFY_SEARCH_COMPLETED *>(pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		pobj_notify->object_type = MAPI_FOLDER;
		auto pbin = cu_fid_to_entryid(pstore, folder_id);
		if (pbin == nullptr)
			return;
		pobj_notify->pentryid = pbin;
		break;
	}
	default:
		return;
	}
	for (auto psink_node = pinfo->sink_list.begin();
	     psink_node != pinfo->sink_list.end(); ++psink_node) {
		for (i=0; i<psink_node->sink.count; i++) {
			if (psink_node->sink.padvise[i].sub_id != notify_id ||
			    hstore != psink_node->sink.padvise[i].hstore)
				continue;
			std::list<sink_node> holder;
			holder.splice(holder.end(), pinfo->sink_list, psink_node);
			const zcresp_notifdequeue response = {zcresp{zcore_callid::notifdequeue, ecSuccess}, {1, &pnotification}};
			tv_msec = SOCKET_TIMEOUT * 1000;
			fdpoll.fd = psink_node->clifd;
			fdpoll.events = POLLOUT | POLLWRBAND;
			if (!rpc_ext_push_response(&response, &tmp_bin)) {
				auto tmp_byte = zcore_response::push_error;
				if (poll(&fdpoll, 1, tv_msec) == 1)
					write(psink_node->clifd, &tmp_byte, 1);
			} else {
				if (poll(&fdpoll, 1, tv_msec) == 1)
					write(psink_node->clifd, tmp_bin.pb, tmp_bin.cb);
				free(tmp_bin.pb);
			}
			/* implied ~sink_node */
			return;
		}
	}
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (pnode == nullptr)
		return;
	pnode->pdata = common_util_dup_znotification(pnotification, FALSE);
	if (NULL == pnode->pdata) {
		free(pnode);
		return;
	}
	nl_hold.lock();
	iter = g_notify_table.find(tmp_buff);
	pitem = iter != g_notify_table.end() ? &iter->second : nullptr;
	if (pitem != nullptr)
		double_list_append_as_tail(&pitem->notify_list, pnode);
	nl_hold.unlock();
	if (NULL == pitem) {
		common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
		free(pnode);
	}
}

void zserver_init(size_t table_size, int cache_interval, int ping_interval)
{
	g_table_size = table_size;
	g_cache_interval = cache_interval;
	g_ping_interval = ping_interval;
}

int zserver_run()
{
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, zcorezs_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "E-1443: pthread_create: %s", strerror(ret));
		return -4;
	}
	pthread_setname_np(g_scan_id, "zarafa");
	exmdb_client_register_proc(reinterpret_cast<void *>(zs_notification_proc));
	return 0;
}

void zserver_stop()
{
	g_notify_stop = true;
	if (!pthread_equal(g_scan_id, {})) {
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, NULL);
	}
	g_session_table.clear();
	g_user_table.clear();
	g_notify_table.clear();
}

ec_error_t zs_logon(const char *username,
	const char *password, uint32_t flags, GUID *phsession)
{
	int org_id;
	int user_id;
	int domain_id;
	char lang[32];
	char reason[256];
	char homedir[256];
	char maildir[256];
	char tmp_name[UADDR_SIZE];
	
	auto pdomain = strchr(username, '@');
	if (pdomain == nullptr)
		return ecUnknownUser;
	pdomain ++;
	if (!system_services_auth_login(username, znul(password), maildir,
	    sizeof(maildir), lang, sizeof(lang), reason, sizeof(reason),
	    USER_PRIVILEGE_EXCH)) {
		mlog(LV_ERR, "Auth rejected for \"%s\": %s", username, reason);
		return ecLoginFailure;
	}
	gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
	HX_strlower(tmp_name);
	std::unique_lock tl_hold(g_table_lock);
	auto iter = g_user_table.find(tmp_name);
	if (iter != g_user_table.end()) {
		user_id = iter->second;
		auto st_iter = g_session_table.find(user_id);
		if (st_iter != g_session_table.end()) {
			auto pinfo = &st_iter->second;
			time(&pinfo->last_time);
			*phsession = pinfo->hsession;
			return ecSuccess;
		}
		g_user_table.erase(iter);
	}
	tl_hold.unlock();
	if (!system_services_get_id_from_username(username, &user_id) ||
	    !system_services_get_homedir(pdomain, homedir, arsizeof(homedir)) ||
	    !system_services_get_domain_ids(pdomain, &domain_id, &org_id))
		return ecError;
	if (password == nullptr &&
	    (!system_services_get_maildir(username, maildir, arsizeof(maildir)) ||
	    !system_services_get_user_lang(username, lang, arsizeof(lang))))
		return ecError;

	USER_INFO tmp_info;
	tmp_info.hsession = GUID::random_new();
	memcpy(tmp_info.hsession.node, &user_id, sizeof(int32_t));
	tmp_info.user_id = user_id;
	tmp_info.domain_id = domain_id;
	tmp_info.org_id = org_id;
	try {
		tmp_info.username = username;
		HX_strlower(tmp_info.username.data());
		tmp_info.lang = lang;
		tmp_info.maildir = maildir;
		tmp_info.homedir = homedir;
	} catch (const std::bad_alloc &) {
		return ecServerOOM;
	}
	auto c = lang_to_charset(lang);
	tmp_info.cpid = c != nullptr ? cset_to_cpid(c) : CP_UTF8;
	tmp_info.flags = flags;
	time(&tmp_info.last_time);
	tmp_info.reload_time = tmp_info.last_time;
	tmp_info.ptree = object_tree_create(maildir);
	if (tmp_info.ptree == nullptr)
		return ecError;
	tl_hold.lock();
	auto st_iter = g_session_table.find(user_id);
	if (st_iter != g_session_table.end()) {
		auto pinfo = &st_iter->second;
		*phsession = pinfo->hsession;
		return ecSuccess;
	}
	if (g_session_table.size() >= g_table_size)
		return ecError;
	try {
		st_iter = g_session_table.try_emplace(user_id, std::move(tmp_info)).first;
	} catch (const std::bad_alloc &) {
		return ecError;
	}
	if (g_user_table.size() >= g_table_size) {
		g_session_table.erase(user_id);
		return ecError;
	}
	try {
		g_user_table.try_emplace(tmp_name, user_id);
	} catch (const std::bad_alloc &) {
		g_session_table.erase(user_id);
		return ecError;
	}
	*phsession = st_iter->second.hsession;
	return ecSuccess;
}

ec_error_t zs_checksession(GUID hsession)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_uinfo(const char *username, BINARY *pentryid,
	char **ppdisplay_name, char **ppx500dn, uint32_t *pprivilege_bits)
{
	char x500dn[1024];
	EXT_PUSH ext_push;
	char display_name[1024];
	EMSAB_ENTRYID tmp_entryid;
	
	if (!system_services_get_user_displayname(username,
	    display_name, arsizeof(display_name)) ||
	    !system_services_get_user_privilege_bits(username, pprivilege_bits) ||
	    !common_util_username_to_essdn(username, x500dn, arsizeof(x500dn)))
		return ecNotFound;
	tmp_entryid.flags = 0;
	tmp_entryid.version = 1;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = x500dn;
	pentryid->pv = common_util_alloc(1280);
	if (pentryid->pv == nullptr ||
	    !ext_push.init(pentryid->pb, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != EXT_ERR_SUCCESS)
		return ecError;
	pentryid->cb = ext_push.m_offset;
	*ppdisplay_name = common_util_dup(display_name);
	*ppx500dn = common_util_dup(x500dn);
	return *ppdisplay_name == nullptr || *ppx500dn == nullptr ?
	       ecError : ecSuccess;
}

ec_error_t zs_unloadobject(GUID hsession, uint32_t hobject)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pinfo->ptree->release_object_handle(hobject);
	return ecSuccess;
}

static ec_error_t zs_openentry_emsab(GUID, BINARY, uint32_t, const char *, uint32_t, zs_objtype *, uint32_t *);
static ec_error_t zs_openentry_zcsab(GUID, BINARY, uint32_t, zs_objtype *, uint32_t *);

ec_error_t zs_openentry(GUID hsession, BINARY entryid,
    uint32_t flags, zs_objtype *pmapi_type, uint32_t *phobject)
{
	BOOL b_private;
	int account_id;
	char essdn[1024];
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t address_type;
	uint16_t type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	if (strncmp(entryid.pc, "/exmdb=", 7) == 0) {
		/* Stupid GUID-less entryid from submit.php */
		gx_strlcpy(essdn, entryid.pc, sizeof(essdn));
		return zs_openentry_emsab(hsession, entryid, flags, essdn,
		       DT_REMOTE_MAILUSER, pmapi_type, phobject);
	} else if (common_util_parse_addressbook_entryid(entryid, &address_type,
	    essdn, arsizeof(essdn))) {
		return zs_openentry_emsab(hsession, entryid, flags, essdn,
		       address_type, pmapi_type, phobject);
	} else if (entryid.cb >= 20 && *reinterpret_cast<const FLATUID *>(&entryid.pb[4]) == muidZCSAB) {
		return zs_openentry_zcsab(hsession, entryid, flags,
		       pmapi_type, phobject);
	}

	/* Arbitrary GUID, it's probably a FOLDER_ENTRYID/MESSAGE_ENTRYID. */
	type = common_util_get_messaging_entryid_type(entryid);
	switch (type) {
	case EITLT_PRIVATE_FOLDER:
	case EITLT_PUBLIC_FOLDER: {
		if (!cu_entryid_to_fid(entryid,
		    &b_private, &account_id, &folder_id))
			break;
		auto handle = pinfo->ptree->get_store_handle(b_private, account_id);
		if (handle == INVALID_HANDLE)
			return ecNullObject;
		pinfo.reset();
		return zs_openstoreentry(hsession,
			handle, entryid, flags, pmapi_type, phobject);
	}
	case EITLT_PRIVATE_MESSAGE:
	case EITLT_PUBLIC_MESSAGE: {
		if (!cu_entryid_to_mid(entryid,
		    &b_private, &account_id, &folder_id, &message_id))
			break;
		auto handle = pinfo->ptree->get_store_handle(b_private, account_id);
		if (handle == INVALID_HANDLE)
			return ecNullObject;
		pinfo.reset();
		return zs_openstoreentry(hsession,
			handle, entryid, flags, pmapi_type, phobject);
	}
	}
	return ecInvalidParam;
}

static ec_error_t zs_openentry_emsab(GUID hsession, BINARY entryid,
    uint32_t flags, const char *essdn, uint32_t address_type,
    zs_objtype *pmapi_type, uint32_t *phobject)
{
	/*
	 * EMSAB entryids with a X500DN of the /exmdb=t:u:i form specify some
	 * folder/message in some private/public store. Everything else (e.g.
	 * GAL root or GAL entries) have no message to open.
	 */
	if (strncmp(essdn, "/exmdb=", 7) != 0 ||
	    address_type != DT_REMOTE_MAILUSER)
		return ecInvalidParam;

	BOOL b_private;
	int user_id;
	uint64_t eid;
	uint8_t loc_type;
	if (!common_util_exmdb_locinfo_from_string(essdn + 7,
	    &loc_type, &user_id, &eid))
		return ecNotFound;
	switch (loc_type) {
	case LOC_TYPE_PRIVATE_FOLDER:
	case LOC_TYPE_PRIVATE_MESSAGE:
		b_private = TRUE;
		break;
	case LOC_TYPE_PUBLIC_FOLDER:
	case LOC_TYPE_PUBLIC_MESSAGE:
		b_private = FALSE;
		break;
	default:
		return ecNotFound;
	}
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecInvalidParam;
	auto handle = pinfo->ptree->get_store_handle(b_private, user_id);
	pinfo.reset();
	return zs_openstoreentry(hsession,
		handle, entryid, flags, pmapi_type, phobject);
}

static ec_error_t zs_openentry_zcsab(GUID ses, BINARY entryid, uint32_t flags,
    zs_objtype *mapi_type, uint32_t *objh)
{
	if (entryid.cb < 28)
		return ecInvalidParam;
	BINARY lower_eid = {entryid.cb - 28, {entryid.pb + 28}};
	return zs_openentry(ses, lower_eid, flags, mapi_type, objh);
}

ec_error_t zs_openstoreentry(GUID hsession, uint32_t hobject, BINARY entryid,
    uint32_t flags, zs_objtype *pmapi_type, uint32_t *phobject)
{
	BOOL b_del;
	BOOL b_exist;
	void *pvalue;
	uint64_t eid;
	uint16_t type;
	BOOL b_private;
	int account_id;
	char essdn[1024];
	uint64_t fid_val;
	uint8_t loc_type;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t tag_access;
	uint32_t permission;
	uint32_t address_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hobject, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	if (0 == entryid.cb) {
		folder_id = rop_util_make_eid_ex(1, pstore->b_private ?
		            PRIVATE_FID_ROOT : PUBLIC_FID_ROOT);
		message_id = 0;
	} else {
		type = common_util_get_messaging_entryid_type(entryid);
		switch (type) {
		case EITLT_PRIVATE_FOLDER:
		case EITLT_PUBLIC_FOLDER:
			if (cu_entryid_to_fid(entryid,
			    &b_private, &account_id, &folder_id)) {
				message_id = 0;
				goto CHECK_LOC;
			}
			break;
		case EITLT_PRIVATE_MESSAGE:
		case EITLT_PUBLIC_MESSAGE:
			if (cu_entryid_to_mid(entryid,
			    &b_private, &account_id, &folder_id, &message_id))
				goto CHECK_LOC;
			break;
		}
		if (strncmp(entryid.pc, "/exmdb=", 7) == 0) {
			gx_strlcpy(essdn, entryid.pc, sizeof(essdn));
		} else if (common_util_parse_addressbook_entryid(entryid,
		     &address_type, essdn, GX_ARRAY_SIZE(essdn)) &&
		     strncmp(essdn, "/exmdb=", 7) == 0 &&
		     address_type == DT_REMOTE_MAILUSER) {
			/* do nothing */	
		} else {
			return ecInvalidParam;
		}
		if (!common_util_exmdb_locinfo_from_string(essdn + 7,
		    &loc_type, &account_id, &eid))
			return ecNotFound;
		switch (loc_type) {
		case LOC_TYPE_PRIVATE_FOLDER:
			b_private = TRUE;
			folder_id = eid;
			message_id = 0;
			break;
		case LOC_TYPE_PRIVATE_MESSAGE:
			b_private = TRUE;
			message_id = eid;
			break;
		case LOC_TYPE_PUBLIC_FOLDER:
			b_private = FALSE;
			folder_id = eid;
			message_id = 0;
			break;
		case LOC_TYPE_PUBLIC_MESSAGE:
			b_private = FALSE;
			message_id = eid;
			break;
		default:
			return ecNotFound;
		}
		if (LOC_TYPE_PRIVATE_MESSAGE == loc_type ||
			LOC_TYPE_PUBLIC_MESSAGE == loc_type) {
			if (!exmdb_client_get_message_property(pstore->get_dir(),
			    nullptr, 0, message_id, PidTagParentFolderId,
			    &pvalue) || pvalue == nullptr)
				return ecError;
			folder_id = *static_cast<uint64_t *>(pvalue);
		}
 CHECK_LOC:
		if (b_private != pstore->b_private ||
		    account_id != pstore->account_id)
			return ecInvalidParam;
	}
	if (0 != message_id) {
		if (!exmdb_client::check_message_deleted(pstore->get_dir(),
		    message_id, &b_del))
			return ecError;
		if (b_del && !(flags & FLAG_SOFT_DELETE))
			return ecNotFound;
		auto ret = cu_calc_msg_access(pstore, pinfo->get_username(),
		           folder_id, message_id, tag_access);
		if (ret != ecSuccess)
			return ret;
		bool b_writable = tag_access & MAPI_ACCESS_MODIFY;
		auto pmessage = message_object::create(pstore, false,
		                pinfo->cpid, message_id, &folder_id, tag_access,
		                b_writable ? TRUE : false, nullptr);
		if (pmessage == nullptr)
			return ecError;
		*phobject = pinfo->ptree->add_object_handle(hobject, {zs_objtype::message, std::move(pmessage)});
		if (*phobject == INVALID_HANDLE)
			return ecError;
		*pmapi_type = zs_objtype::message;
	} else {
		if (!exmdb_client::check_folder_id(pstore->get_dir(),
		    folder_id, &b_exist))
			return ecError;
		if (!b_exist)
			return ecNotFound;
		if (!pstore->b_private) {
			if (!exmdb_client::check_folder_deleted(pstore->get_dir(),
			    folder_id, &b_del))
				return ecError;
			if (b_del && !(flags & FLAG_SOFT_DELETE))
				return ecNotFound;
		}
		if (!exmdb_client_get_folder_property(pstore->get_dir(), 0,
		    folder_id, PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
			return ecError;
		auto folder_type = *static_cast<uint32_t *>(pvalue);
		if (pstore->owner_mode()) {
			tag_access = MAPI_ACCESS_AllSix;
		} else {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (permission == rightsNone) {
				fid_val = rop_util_get_gc_value(folder_id);
				if (pstore->b_private) {
					if (fid_val == PRIVATE_FID_ROOT ||
					    fid_val == PRIVATE_FID_IPMSUBTREE)
						permission = frightsVisible;
				} else {
					if (fid_val == PUBLIC_FID_ROOT)
						permission = frightsVisible;
				}
			}
			if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
				return ecNotFound;
			if (permission & frightsOwner) {
				tag_access = MAPI_ACCESS_AllSix;
			} else {
				tag_access = MAPI_ACCESS_READ;
				if (permission & frightsCreate)
					tag_access |= MAPI_ACCESS_CREATE_CONTENTS | MAPI_ACCESS_CREATE_ASSOCIATED;
				if (permission & frightsCreateSubfolder)
					tag_access |= MAPI_ACCESS_CREATE_HIERARCHY;
			}
		}
		auto pfolder = folder_object::create(pstore, folder_id,
		               folder_type, tag_access);
		if (pfolder == nullptr)
			return ecError;
		*phobject = pinfo->ptree->add_object_handle(hobject, {zs_objtype::folder, std::move(pfolder)});
		if (*phobject == INVALID_HANDLE)
			return ecError;
		*pmapi_type = zs_objtype::folder;
	}
	return ecSuccess;
}

static ec_error_t zs_openab_emsab(USER_INFO_REF &&, BINARY, int, zs_objtype *, uint32_t *);
static ec_error_t zs_openab_zcsab(USER_INFO_REF &&, BINARY, int, zs_objtype *, uint32_t *);

static ec_error_t zs_openab_oop(USER_INFO_REF &&info, BINARY bin,
    zs_objtype *zmg_type, uint32_t *objh)
{
	ONEOFF_ENTRYID eid;
	EXT_PULL ep;
	ep.init(bin.pv, bin.cb, common_util_alloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	if (ep.g_oneoff_eid(&eid) != EXT_ERR_SUCCESS)
		return ecInvalidParam;
	auto u = oneoff_object::create(eid);
	if (u == nullptr)
		return ecServerOOM;
	*zmg_type = zs_objtype::oneoff;
	*objh = info->ptree->add_object_handle(ROOT_HANDLE, {*zmg_type, std::move(u)});
	return *objh != INVALID_HANDLE ? ecSuccess : ecError;
}

ec_error_t zs_openabentry(GUID hsession,
    BINARY entryid, zs_objtype *pmapi_type, uint32_t *phobject)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	int base_id = pinfo->org_id == 0 ? -pinfo->domain_id : pinfo->org_id;
	if (0 == entryid.cb) {
		CONTAINER_ID container_id;
		container_id.abtree_id.base_id = base_id;
		container_id.abtree_id.minid = SPECIAL_CONTAINER_ROOT;
		auto contobj = container_object::create(CONTAINER_TYPE_ABTREE, container_id);
		if (contobj == nullptr)
			return ecError;
		*pmapi_type = zs_objtype::abcont;
		*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {*pmapi_type, std::move(contobj)});
		if (*phobject == INVALID_HANDLE)
			return ecError;
		return ecSuccess;
	}
	if (entryid.cb < 20)
		return ecInvalidParam;
	const auto &prov = *reinterpret_cast<const FLATUID *>(&entryid.pb[4]);
	if (prov == muidEMSAB)
		return zs_openab_emsab(std::move(pinfo), entryid, base_id, pmapi_type, phobject);
	else if (prov == muidZCSAB)
		return zs_openab_zcsab(std::move(pinfo), entryid, base_id, pmapi_type, phobject);
	else if (prov == muidOOP)
		return zs_openab_oop(std::move(pinfo), entryid, pmapi_type, phobject);
	return ecInvalidParam;
}

static ec_error_t zs_openab_emsab(USER_INFO_REF &&pinfo, BINARY entryid,
    int base_id, zs_objtype *pmapi_type, uint32_t *phobject)
{
	int user_id, domain_id;
	char essdn[1024];
	uint32_t address_type;

	if (!common_util_parse_addressbook_entryid(entryid, &address_type,
	    essdn, std::size(essdn)))
		return ecInvalidParam;

	if (address_type == DT_CONTAINER) {
		CONTAINER_ID container_id;
		uint8_t type;

		HX_strlower(essdn);
		if (strcmp(essdn, "/") == 0) {
			type = CONTAINER_TYPE_ABTREE;
			container_id.abtree_id.base_id = base_id;
			container_id.abtree_id.minid = SPECIAL_CONTAINER_GAL;
		} else if (strcmp(essdn, "/exmdb") == 0) {
			type = CONTAINER_TYPE_ABTREE;
			container_id.abtree_id.base_id = base_id;
			container_id.abtree_id.minid = SPECIAL_CONTAINER_EMPTY;
		} else {
			if (strncmp(essdn, "/guid=", 6) != 0 || strlen(essdn) != 38)
				return ecNotFound;
			char tmp_buff[16];
			GUID guid;
			memcpy(tmp_buff, essdn + 6, 8);
			tmp_buff[8] = '\0';
			guid.time_low = strtoll(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 14, 4);
			tmp_buff[4] = '\0';
			guid.time_mid = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 18, 4);
			tmp_buff[4] = '\0';
			guid.time_hi_and_version = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 22, 2);
			tmp_buff[2] = '\0';
			guid.clock_seq[0] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 24, 2);
			tmp_buff[2] = '\0';
			guid.clock_seq[1] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 26, 2);
			tmp_buff[2] = '\0';
			guid.node[0] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 28, 2);
			tmp_buff[2] = '\0';
			guid.node[1] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 30, 2);
			tmp_buff[2] = '\0';
			guid.node[2] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 32, 2);
			tmp_buff[2] = '\0';
			guid.node[3] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 34, 2);
			tmp_buff[2] = '\0';
			guid.node[4] = strtol(tmp_buff, NULL, 16);
			memcpy(tmp_buff, essdn + 36, 2);
			tmp_buff[2] = '\0';
			guid.node[5] = strtol(tmp_buff, NULL, 16);
			auto pbase = ab_tree_get_base(base_id);
			if (pbase == nullptr)
				return ecError;
			auto pnode = ab_tree_guid_to_node(pbase.get(), guid);
			if (pnode == nullptr)
				return ecNotFound;
			auto minid = ab_tree_get_node_minid(pnode);
			type = CONTAINER_TYPE_ABTREE;
			container_id.abtree_id.base_id = base_id;
			container_id.abtree_id.minid = minid;
		}
		auto contobj = container_object::create(type, container_id);
		if (contobj == nullptr)
			return ecError;
		*pmapi_type = zs_objtype::abcont;
		*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {*pmapi_type, std::move(contobj)});
	} else if (address_type == DT_DISTLIST || address_type == DT_MAILUSER) {
		if (!common_util_essdn_to_ids(essdn, &domain_id, &user_id))
			return ecNotFound;
		if (domain_id != pinfo->domain_id &&
		    !system_services_check_same_org(domain_id, pinfo->domain_id))
			base_id = -domain_id;
		auto minid = ab_tree_make_minid(minid_type::address, user_id);
		auto userobj = user_object::create(base_id, minid);
		if (userobj == nullptr)
			return ecError;
		if (!userobj->valid())
			return ecNotFound;
		*pmapi_type = address_type == DT_DISTLIST ?
			      zs_objtype::distlist : zs_objtype::mailuser;
		*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {*pmapi_type, std::move(userobj)});
	} else {
		return ecInvalidParam;
	}
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

static ec_error_t zs_openab_zcsab(USER_INFO_REF &&info, BINARY entryid,
    int base_id, zs_objtype *zmg_type, uint32_t *objh)
{
	EXT_PULL ep;
	FOLDER_ENTRYID fe;
	uint32_t mapi_type = 0;
	ep.init(entryid.pb, entryid.cb, common_util_alloc, EXT_FLAG_UTF16);
	ep.m_offset += 20;
	if (ep.g_uint32(&mapi_type) != EXT_ERR_SUCCESS ||
	    static_cast<mapi_object_type>(mapi_type) != MAPI_ABCONT ||
	    ep.advance(4) != EXT_ERR_SUCCESS ||
	    ep.g_folder_eid(&fe) != EXT_ERR_SUCCESS ||
	    fe.folder_type != EITLT_PRIVATE_FOLDER)
		return ecInvalidParam;

	CONTAINER_ID ctid;
	ctid.exmdb_id.b_private = TRUE;
	ctid.exmdb_id.folder_id = rop_util_make_eid(1, fe.global_counter);
	auto contobj = container_object::create(CONTAINER_TYPE_FOLDER, ctid);
	if (contobj == nullptr)
		return ecError;
	*zmg_type = zs_objtype::abcont;
	*objh = info->ptree->add_object_handle(ROOT_HANDLE, {*zmg_type, std::move(contobj)});
	return *objh != INVALID_HANDLE ? ecSuccess : ecError;
}

ec_error_t zs_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set)
{
	PROPTAG_ARRAY proptags;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	int base_id = pinfo->org_id == 0 ? -pinfo->domain_id : pinfo->org_id;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr)
		return ecError;
	stn_list_t result_list;
	for (size_t i = 0; i < pcond_set->count; ++i) {
		auto pstring = pcond_set->pparray[i]->get<char>(PR_DISPLAY_NAME);
		if (NULL == pstring) {
			presult_set->count = 0;
			presult_set->pparray = NULL;
			return ecSuccess;
		}
		stn_list_t temp_list;
		if (!ab_tree_resolvename(pbase.get(), pinfo->cpid, pstring, temp_list))
			return ecError;
		switch (temp_list.size()) {
		case 0:
			return ecNotFound;
		case 1:
			break;
		default:
			return ecAmbiguousRecip;
		}
		try {
			result_list.insert(result_list.end(),
				std::make_move_iterator(temp_list.begin()),
				std::make_move_iterator(temp_list.end()));
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1679: ENOMEM");
			return ecServerOOM;
		}
	}
	presult_set->count = 0;
	if (result_list.size() == 0) {
		presult_set->pparray = NULL;
		return ecNotFound;
	}
	presult_set->pparray = cu_alloc<TPROPVAL_ARRAY *>(result_list.size());
	if (presult_set->pparray == nullptr)
		return ecError;
	container_object_get_user_table_all_proptags(&proptags);
	for (auto ptr : result_list) {
		presult_set->pparray[presult_set->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == presult_set->pparray[presult_set->count] ||
		    !ab_tree_fetch_node_properties(ptr,
		    &proptags, presult_set->pparray[presult_set->count]))
			return ecError;
		presult_set->count ++;
	}
	return ecSuccess;
}

ec_error_t zs_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hobject, &mapi_type);
	if (NULL == pobject) {
		pperm_set->count = 0;
		return ecNullObject;
	}
	switch (mapi_type) {
	case zs_objtype::store:
		if (!static_cast<store_object *>(pobject)->get_permissions(pperm_set))
			return ecError;
		break;
	case zs_objtype::folder:
		if (!static_cast<folder_object *>(pobject)->get_permissions(pperm_set))
			return ecError;
		break;
	default:
		return ecNotSupported;
	}
	return ecSuccess;
}

ec_error_t zs_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset)
{
	zs_objtype mapi_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	return pfolder->set_permissions(pset) ? ecSuccess : ecError;
}

ec_error_t zs_modifyrules(GUID hsession,
	uint32_t hfolder, uint32_t flags, const RULE_LIST *plist)
{
	zs_objtype mapi_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	if (flags & MODIFY_RULES_FLAG_REPLACE)
		for (size_t i = 0; i < plist->count; ++i)
			if (plist->prule[i].flags != ROW_ADD)
				return ecInvalidParam;
	return pfolder->updaterules(flags, plist) ? ecSuccess : ecError;
}

ec_error_t zs_getabgal(GUID hsession, BINARY *pentryid)
{
	void *pvalue;
	
	if (!container_object_fetch_special_property(SPECIAL_CONTAINER_GAL,
	    PR_ENTRYID, &pvalue))
		return ecError;
	if (pvalue == nullptr)
		return ecNotFound;
	*pentryid = *static_cast<BINARY *>(pvalue);
	return ecSuccess;
}

ec_error_t zs_loadstoretable(GUID hsession, uint32_t *phobject)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = table_object::create(nullptr, nullptr, zcore_tbltype::store, 0);
	if (ptable == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {zs_objtype::table, std::move(ptable)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_openstore(GUID hsession, BINARY entryid, uint32_t *phobject)
{
	int user_id;
	char dir[256];
	EXT_PULL ext_pull;
	char username[UADDR_SIZE];
	STORE_ENTRYID store_entryid = {};
	
	ext_pull.init(entryid.pb, entryid.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_store_eid(&store_entryid) != EXT_ERR_SUCCESS)
		return ecError;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	if (store_entryid.wrapped_provider_uid == g_muidStorePublic) {
		*phobject = pinfo->ptree->get_store_handle(false, pinfo->domain_id);
		return *phobject != INVALID_HANDLE ? ecSuccess : ecError;
	}
	if (!common_util_essdn_to_uid(store_entryid.pmailbox_dn, &user_id))
		return ecNotFound;
	if (pinfo->user_id == user_id) {
		*phobject = pinfo->ptree->get_store_handle(TRUE, user_id);
		return *phobject != INVALID_HANDLE ? ecSuccess : ecError;
	}
	if (!system_services_get_username_from_id(user_id,
	    username, GX_ARRAY_SIZE(username)) ||
	    !system_services_get_maildir(username, dir, arsizeof(dir)))
		return ecError;
	uint32_t permission = rightsNone;
	if (!exmdb_client::get_mbox_perm(dir,
	    pinfo->get_username(), &permission))
		return ecError;
	if (permission == rightsNone) {
		if (g_zrpc_debug >= 1)
			mlog(LV_ERR, "openstore: \"%s\" has no rights to access \"%s\"\n",
				pinfo->get_username(), username);
		return ecLoginPerm;
	} else if (g_zrpc_debug >= 2) {
		mlog(LV_DEBUG, "openstore: \"%s\" granted access to \"%s\"\n",
			pinfo->get_username(), username);
	}
	if (permission & frightsGromoxStoreOwner) try {
		std::lock_guard lk(pinfo->eowner_lock);
		pinfo->extra_owner.insert_or_assign(user_id, time(nullptr));
	} catch (const std::bad_alloc &) {
	}
	*phobject = pinfo->ptree->get_store_handle(TRUE, user_id);
	return *phobject != INVALID_HANDLE ? ecSuccess : ecError;
}

ec_error_t zs_openprofilesec(GUID hsession,
	const FLATUID *puid, uint32_t *phobject)
{
	GUID guid;
	BINARY bin;
	
	bin.cb = 16;
	bin.pv = deconst(puid);
	guid = rop_util_binary_to_guid(&bin);
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ppropvals = pinfo->ptree->get_profile_sec(guid);
	if (ppropvals == nullptr)
		return ecNotFound;
	*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {zs_objtype::profproperty, ppropvals});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	zs_objtype mapi_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hfolder, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;

	store_object *pstore = nullptr;
	std::unique_ptr<table_object> ptable;
	switch (mapi_type) {
	case zs_objtype::folder:
		pstore = static_cast<folder_object *>(pobject)->pstore;
		ptable = table_object::create(pstore, pobject, zcore_tbltype::hierarchy, flags);
		break;
	case zs_objtype::abcont:
		ptable = table_object::create(nullptr, pobject, zcore_tbltype::container, flags);
		break;
	default:
		return ecNotSupported;
	}
	if (ptable == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hfolder, {zs_objtype::table, std::move(ptable)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	zs_objtype mapi_type;
	uint32_t permission;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hfolder, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;

	store_object *pstore;
	std::unique_ptr<table_object> ptable;
	switch (mapi_type) {
	case zs_objtype::folder: {
		auto folder = static_cast<folder_object *>(pobject);
		pstore = folder->pstore;
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    folder->folder_id, pinfo->get_username(), &permission))
				return ecNotFound;
			if (!(permission & (frightsReadAny | frightsOwner)))
				return ecNotFound;
		}
		ptable = table_object::create(folder->pstore, pobject, zcore_tbltype::content, flags);
		break;
	}
	case zs_objtype::distlist:
		ptable = table_object::create(nullptr, pobject, zcore_tbltype::distlist, 0);
		break;
	case zs_objtype::abcont:
		ptable = table_object::create(nullptr, pobject, zcore_tbltype::abcontusr, 0);
		break;
	default:
		return ecNotSupported;
	}
	if (ptable == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hfolder, {zs_objtype::table, std::move(ptable)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	zs_objtype mapi_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto ptable = table_object::create(pmessage->get_store(), pmessage, zcore_tbltype::recipient, 0);
	if (ptable == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hmessage, {zs_objtype::table, std::move(ptable)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_loadruletable(GUID hsession, uint32_t hfolder, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto folder_id = pfolder->folder_id;
	auto ptable = table_object::create(pfolder->pstore, &folder_id, zcore_tbltype::rule, 0);
	if (ptable == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hfolder, {zs_objtype::table, std::move(ptable)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_createmessage(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	zs_objtype mapi_type;
	uint32_t tag_access;
	uint32_t permission;
	uint64_t message_id;
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto folder_id = pfolder->folder_id;
	auto pstore = pfolder->pstore;
	auto hstore = pinfo->ptree->get_store_handle(pstore->b_private, pstore->account_id);
	if (hstore == INVALID_HANDLE)
		return ecNullObject;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreate)))
			return ecNotFound;
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ;
		if (permission & (frightsDeleteOwned | frightsDeleteAny))
			tag_access |= MAPI_ACCESS_DELETE;
	} else {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
	}
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MESSAGE_SIZE_EXTENDED;
	proptag_buff[1] = PR_STORAGE_QUOTA_LIMIT;
	proptag_buff[2] = PR_ASSOC_CONTENT_COUNT;
	proptag_buff[3] = PR_CONTENT_COUNT;
	if (!pstore->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;
	auto num = tmp_propvals.get<const uint32_t>(PR_STORAGE_QUOTA_LIMIT);
	int64_t max_quota = num == nullptr ? -1 : static_cast<int64_t>(*num) * 1024;
	auto lnum = tmp_propvals.get<const uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	uint64_t total_size = lnum != nullptr ? *lnum : 0;
	if (max_quota > 0 && total_size > static_cast<uint64_t>(max_quota))
		return ecQuotaExceeded;
	num = tmp_propvals.get<uint32_t>(PR_ASSOC_CONTENT_COUNT);
	uint32_t total_mail = num != nullptr ? *num : 0;
	num = tmp_propvals.get<uint32_t>(PR_CONTENT_COUNT);
	if (num != nullptr)
		total_mail += *num;
	if (total_mail > g_max_message)
		return ecQuotaExceeded;
	if (!exmdb_client::allocate_message_id(pstore->get_dir(),
	    folder_id, &message_id))
		return ecError;
	auto pmessage = message_object::create(pstore, TRUE,
			pinfo->cpid, message_id, &folder_id,
			tag_access, TRUE, NULL);
	if (pmessage == nullptr)
		return ecError;
	BOOL b_fai = (flags & FLAG_ASSOCIATED) ? TRUE : false;
	if (pmessage->init_message(b_fai, pinfo->cpid) != 0)
		return ecError;
	/* add the store handle as the parent object handle
		because the caller normally will not keep the
		handle of folder */
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::message, std::move(pmessage)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_deletemessages(GUID hsession, uint32_t hfolder,
    const BINARY_ARRAY *pentryids, uint32_t flags)
{
	BOOL b_owner;
	EID_ARRAY ids;
	EID_ARRAY ids1;
	int account_id;
	BOOL b_private;
	BOOL b_partial;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	uint64_t message_id;
	MESSAGE_CONTENT *pbrief;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	bool notify_non_read = flags & ZC_DELMSG_NOTIFY_UNREAD;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (permission & (frightsDeleteAny | frightsOwner))
			username = NULL;
		else if (permission & frightsDeleteOwned)
			username = pinfo->get_username();
		else
			return ecNotFound;
	}
	ids.count = 0;
	ids.pids = cu_alloc<uint64_t>(pentryids->count);
	if (ids.pids == nullptr)
		return ecError;
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (!cu_entryid_to_mid(pentryids->pbin[i],
		    &b_private, &account_id, &folder_id, &message_id))
			return ecError;
		if (b_private != pstore->b_private ||
		    account_id != pstore->account_id ||
		    folder_id != pfolder->folder_id)
			continue;
		ids.pids[ids.count++] = message_id;
	}
	BOOL b_hard = (flags & FLAG_HARD_DELETE) ? false : TRUE; /* XXX */
	if (!notify_non_read) {
		if (!exmdb_client::delete_messages(pstore->get_dir(),
		    pstore->account_id, pinfo->cpid, username,
		    pfolder->folder_id, &ids, b_hard, &b_partial))
			return ecError;
		return ecSuccess;
	}
	ids1.count = 0;
	ids1.pids  = cu_alloc<uint64_t>(ids.count);
	if (ids1.pids == nullptr)
		return ecError;
	for (size_t i = 0; i < ids.count; ++i) {
		if (NULL != username) {
			if (!exmdb_client_check_message_owner(pstore->get_dir(),
			    ids.pids[i], username, &b_owner))
				return ecError;
			if (!b_owner)
				continue;
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
		proptag_buff[1] = PR_READ;
		if (!exmdb_client::get_message_properties(pstore->get_dir(),
		    nullptr, 0, ids.pids[i], &tmp_proptags, &tmp_propvals))
			return ecError;
		pbrief = NULL;
		auto flag = tmp_propvals.get<const uint8_t>(PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
		if (flag != nullptr && *flag != 0) {
			flag = tmp_propvals.get<uint8_t>(PR_READ);
			if ((flag == nullptr || *flag == 0) &&
			    !exmdb_client::get_message_brief(pstore->get_dir(),
			    pinfo->cpid, ids.pids[i], &pbrief))
				return ecError;
		}
		ids1.pids[ids1.count++] = ids.pids[i];
		if (pbrief != nullptr)
			common_util_notify_receipt(pstore->get_account(),
				NOTIFY_RECEIPT_NON_READ, pbrief);
	}
	return exmdb_client::delete_messages(pstore->get_dir(),
	       pstore->account_id, pinfo->cpid, username,
	       pfolder->folder_id, &ids1, b_hard, &b_partial) ?
	       ecSuccess : ecError;
}

ec_error_t zs_copymessages(GUID hsession, uint32_t hsrcfolder,
    uint32_t hdstfolder, const BINARY_ARRAY *pentryids, uint32_t flags)
{
	BOOL b_done, b_guest = TRUE, b_owner;
	EID_ARRAY ids;
	BOOL b_partial;
	BOOL b_private;
	int account_id;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission;
	
	if (pentryids->count == 0)
		return ecSuccess;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto psrc_folder = pinfo->ptree->get_object<folder_object>(hsrcfolder, &mapi_type);
	if (psrc_folder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = psrc_folder->pstore;
	auto pdst_folder = pinfo->ptree->get_object<folder_object>(hdstfolder, &mapi_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder || pdst_folder->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto pstore1 = pdst_folder->pstore;
	BOOL b_copy = (flags & FLAG_MOVE) ? false : TRUE;
	if (pstore != pstore1) {
		if (!b_copy) {
			b_guest = FALSE;
			if (!pstore->owner_mode()) {
				if (!exmdb_client::get_folder_perm(pstore->get_dir(),
				    psrc_folder->folder_id, pinfo->get_username(), &permission))
					return ecError;
				if (permission & frightsDeleteAny)
					/* permission to delete any message */;
				else if (permission & frightsDeleteOwned)
					b_guest = TRUE;
				else
					return ecAccessDenied;
			}
		}
		if (!pstore1->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore1->get_dir(),
			    pdst_folder->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsCreate))
				return ecAccessDenied;
		}
		for (size_t i = 0; i < pentryids->count; ++i) {
			if (!cu_entryid_to_mid(pentryids->pbin[i],
			    &b_private, &account_id, &folder_id, &message_id))
				return ecError;
			if (b_private != pstore->b_private ||
			    account_id != pstore->account_id ||
			    folder_id != psrc_folder->folder_id)
				continue;
			auto ret = cu_remote_copy_message(pstore, message_id,
			           pstore1, pdst_folder->folder_id);
			if (ret != ecSuccess)
				return ret;
			if (!b_copy) {
				if (b_guest) {
					if (!exmdb_client_check_message_owner(pstore->get_dir(),
					    message_id, pinfo->get_username(), &b_owner))
						return ecError;
					if (!b_owner)
						continue;
				}
				if (!exmdb_client_delete_message(pstore->get_dir(),
				    pstore->account_id, pinfo->cpid,
				    psrc_folder->folder_id, message_id, false, &b_done))
					return ecError;
			}
		}
		return ecSuccess;
	}
	ids.count = 0;
	ids.pids = cu_alloc<uint64_t>(pentryids->count);
	if (ids.pids == nullptr)
		return ecError;
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (!cu_entryid_to_mid(pentryids->pbin[i],
		    &b_private, &account_id, &folder_id, &message_id))
			return ecError;
		if (b_private != pstore->b_private ||
		    account_id != pstore->account_id ||
		    folder_id != psrc_folder->folder_id)
			continue;
		ids.pids[ids.count++] = message_id;
	}
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pdst_folder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	return exmdb_client::movecopy_messages(pstore->get_dir(),
	       pstore->account_id, pinfo->cpid, b_guest,
	       pinfo->get_username(), psrc_folder->folder_id,
	       pdst_folder->folder_id, b_copy, &ids, &b_partial) ?
	       ecSuccess : ecError;
}

ec_error_t zs_setreadflags(GUID hsession, uint32_t hfolder,
    const BINARY_ARRAY *pentryids, uint32_t flags)
{
	void *pvalue;
	BOOL b_private;
	BOOL b_changed;
	int account_id;
	uint64_t read_cn;
	uint8_t tmp_byte;
	uint32_t table_id;
	zs_objtype mapi_type;
	uint32_t row_count;
	uint64_t folder_id;
	TARRAY_SET tmp_set;
	uint64_t message_id;
	uint32_t tmp_proptag;
	BOOL b_notify = TRUE; /* TODO: Read from config or USER_INFO. */
	BINARY_ARRAY tmp_bins;
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
	MESSAGE_CONTENT *pbrief;
	TPROPVAL_ARRAY propvals;
	RESTRICTION restriction;
	RESTRICTION_PROPERTY res_prop;
	static constexpr uint8_t fake_false = false;
	TAGGED_PROPVAL propval_buff[2];
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	auto username = pstore->owner_mode() ? nullptr : pinfo->get_username();
	if (0 == pentryids->count) {
		restriction.rt = RES_PROPERTY;
		restriction.pres = &res_prop;
		res_prop.relop = flags == FLAG_CLEAR_READ ? RELOP_NE : RELOP_EQ;
		res_prop.proptag = PR_READ;
		res_prop.propval.proptag = PR_READ;
		res_prop.propval.pvalue = deconst(&fake_false);
		if (!exmdb_client::load_content_table(pstore->get_dir(), 0,
		    pfolder->folder_id, username, TABLE_FLAG_NONOTIFICATIONS,
		    &restriction, nullptr, &table_id, &row_count))
			return ecError;
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PR_ENTRYID;
		if (!exmdb_client::query_table(pstore->get_dir(), username,
		    0, table_id, &proptags, 0, row_count, &tmp_set)) {
			exmdb_client::unload_table(pstore->get_dir(), table_id);
			return ecError;
		}
		exmdb_client::unload_table(pstore->get_dir(), table_id);
		if (tmp_set.count > 0) {
			tmp_bins.count = 0;
			tmp_bins.pbin = cu_alloc<BINARY>(tmp_set.count);
			if (tmp_bins.pbin == nullptr)
				return ecError;
			for (size_t i = 0; i < tmp_set.count; ++i) {
				if (tmp_set.pparray[i]->count != 1)
					continue;
				tmp_bins.pbin[tmp_bins.count++] = *static_cast<BINARY *>(tmp_set.pparray[i]->ppropval[0].pvalue);
			}
			pentryids = &tmp_bins;
		}
	}
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (!cu_entryid_to_mid(pentryids->pbin[i],
		    &b_private, &account_id, &folder_id, &message_id))
			return ecError;
		if (b_private != pstore->b_private ||
		    account_id != pstore->account_id ||
		    folder_id != pfolder->folder_id)
			continue;
		b_notify = FALSE;
		b_changed = FALSE;
		if (FLAG_CLEAR_READ == flags) {
			if (!exmdb_client_get_message_property(pstore->get_dir(),
			    username, 0, message_id, PR_READ, &pvalue))
				return ecError;
			if (pvb_enabled(pvalue)) {
				tmp_byte = 0;
				b_changed = TRUE;
			}
		} else {
			if (!exmdb_client_get_message_property(pstore->get_dir(),
			    username, 0, message_id, PR_READ, &pvalue))
				return ecError;
			if (pvb_disabled(pvalue)) {
				tmp_byte = 1;
				b_changed = TRUE;
				if (!exmdb_client_get_message_property(pstore->get_dir(),
				    username, 0, message_id,
				    PR_READ_RECEIPT_REQUESTED, &pvalue))
					return ecError;
				if (pvb_enabled(pvalue))
					b_notify = TRUE;
			}
		}
		if (b_changed && !exmdb_client::set_message_read_state(pstore->get_dir(),
		    username, message_id, tmp_byte, &read_cn))
			return ecError;
		if (b_notify) {
			if (!exmdb_client::get_message_brief(pstore->get_dir(),
			    pinfo->cpid, message_id, &pbrief))
				return ecError;
			if (pbrief != nullptr)
				common_util_notify_receipt(pstore->get_account(),
					NOTIFY_RECEIPT_READ, pbrief);
			propvals.count = 2;
			propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PR_READ_RECEIPT_REQUESTED;
			propval_buff[0].pvalue = deconst(&fake_false);
			propval_buff[1].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
			propval_buff[1].pvalue = deconst(&fake_false);
			exmdb_client::set_message_properties(pstore->get_dir(), username,
				0, message_id, &propvals, &problems);
		}
	}
	return ecSuccess;
}

ec_error_t zs_createfolder(GUID hsession, uint32_t hparent_folder,
    uint32_t folder_type, const char *folder_name, const char *folder_comment,
    uint32_t flags, uint32_t *phobject)
{
	void *pvalue;
	uint64_t tmp_id;
	uint32_t tmp_type;
	zs_objtype mapi_type;
	uint64_t last_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	uint32_t permission;
	TPROPVAL_ARRAY tmp_propvals;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	if (folder_type != FOLDER_SEARCH && folder_type != FOLDER_GENERIC)
		return ecNotSupported;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pparent = pinfo->ptree->get_object<folder_object>(hparent_folder, &mapi_type);
	if (pparent == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	if (rop_util_get_replid(pparent->folder_id) != 1 ||
	    pparent->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto pstore = pparent->pstore;
	if (!pstore->b_private && folder_type == FOLDER_SEARCH)
		return ecNotSupported;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pparent->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
	}
	if (!exmdb_client::get_folder_by_name(pstore->get_dir(),
	    pparent->folder_id, folder_name, &folder_id))
		return ecError;
	if (0 != folder_id) {
		if (!exmdb_client_get_folder_property(pstore->get_dir(), 0,
		    folder_id, PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
			return ecError;
		if (!(flags & FLAG_OPEN_IF_EXISTS) ||
		    folder_type != *static_cast<uint32_t *>(pvalue))
			return ecDuplicateName;
	} else {
		parent_id = pparent->folder_id;
		if (!exmdb_client::allocate_cn(pstore->get_dir(), &change_num))
			return ecError;
		tmp_type = folder_type;
		last_time = rop_util_current_nttime();
		tmp_propvals.count = 9;
		tmp_propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PidTagParentFolderId;
		propval_buff[0].pvalue = &parent_id;
		propval_buff[1].proptag = PR_FOLDER_TYPE;
		propval_buff[1].pvalue = &tmp_type;
		propval_buff[2].proptag = PR_DISPLAY_NAME;
		propval_buff[2].pvalue = deconst(folder_name);
		propval_buff[3].proptag = PR_COMMENT;
		propval_buff[3].pvalue = deconst(folder_comment);
		propval_buff[4].proptag = PR_CREATION_TIME;
		propval_buff[4].pvalue = &last_time;
		propval_buff[5].proptag = PR_LAST_MODIFICATION_TIME;
		propval_buff[5].pvalue = &last_time;
		propval_buff[6].proptag = PidTagChangeNumber;
		propval_buff[6].pvalue = &change_num;
		propval_buff[7].proptag = PR_CHANGE_KEY;
		propval_buff[7].pvalue = cu_xid_to_bin({pstore->guid(), change_num});
		if (propval_buff[7].pvalue == nullptr)
			return ecError;
		propval_buff[8].proptag = PR_PREDECESSOR_CHANGE_LIST;
		propval_buff[8].pvalue = common_util_pcl_append(nullptr, static_cast<BINARY *>(propval_buff[7].pvalue));
		if (propval_buff[8].pvalue == nullptr)
			return ecError;
		if (!exmdb_client::create_folder_by_properties(pstore->get_dir(),
		    pinfo->cpid, &tmp_propvals, &folder_id) || folder_id == 0)
			return ecError;
		if (!pstore->owner_mode()) {
			auto pentryid = common_util_username_to_addressbook_entryid(pinfo->get_username());
			if (pentryid == nullptr)
				return ecError;
			tmp_id = 1;
			permission = rightsGromox7;
			permission_row.flags = ROW_ADD;
			permission_row.propvals.count = 3;
			permission_row.propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PR_ENTRYID;
			propval_buff[0].pvalue = pentryid;
			propval_buff[1].proptag = PR_MEMBER_ID;
			propval_buff[1].pvalue = &tmp_id;
			propval_buff[2].proptag = PR_MEMBER_RIGHTS;
			propval_buff[2].pvalue = &permission;
			if (!exmdb_client::update_folder_permission(pstore->get_dir(),
			    folder_id, false, 1, &permission_row))
				return ecError;
		}
	}
	uint32_t tag_access = MAPI_ACCESS_AllSix;
	auto pfolder = folder_object::create(pstore, folder_id,
	               folder_type, tag_access);
	if (pfolder == nullptr)
		return ecError;
	if (folder_type == FOLDER_SEARCH) {
		/* add the store handle as the parent object handle
			because the caller normally will not keep the
			handle of parent folder */
		auto hstore = pinfo->ptree->get_store_handle(TRUE, pstore->account_id);
		if (hstore == INVALID_HANDLE)
			return ecError;
		*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::folder, std::move(pfolder)});
	} else {
		*phobject = pinfo->ptree->add_object_handle(hparent_folder, {zs_objtype::folder, std::move(pfolder)});
	}
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_deletefolder(GUID hsession,
	uint32_t hparent_folder, BINARY entryid, uint32_t flags)
{
	BOOL b_done;
	void *pvalue;
	BOOL b_exist;
	BOOL b_partial;
	BOOL b_private;
	int account_id;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hparent_folder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	if (!cu_entryid_to_fid(entryid,
	    &b_private, &account_id, &folder_id))
		return ecError;
	if (b_private != pstore->b_private || account_id != pstore->account_id)
		return ecInvalidParam;
	if (pstore->b_private) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return ecAccessDenied;
		}
	} else {
		if (1 == rop_util_get_replid(folder_id) &&
			rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			return ecAccessDenied;
		}
	}
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
		username = pinfo->get_username();
	}
	if (!exmdb_client::check_folder_id(pstore->get_dir(),
	    pfolder->folder_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecSuccess;
	BOOL b_normal = (flags & DEL_MESSAGES) ? TRUE : false;
	BOOL b_fai = b_normal;
	BOOL b_sub = (flags & DEL_FOLDERS) ? TRUE : false;
	BOOL b_hard = (flags & DELETE_HARD_DELETE) ? TRUE : false;
	if (pstore->b_private) {
		if (!exmdb_client_get_folder_property(pstore->get_dir(), 0,
		    folder_id, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (pvalue == nullptr)
			return ecSuccess;
		if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
			goto DELETE_FOLDER;
	}
	if (b_sub || b_normal || b_fai) {
		if (!exmdb_client::empty_folder(pstore->get_dir(), pinfo->cpid,
		    username, folder_id, b_hard, b_normal, b_fai, b_sub, &b_partial))
			return ecError;
		if (b_partial)
			/* failure occurs, stop deleting folder */
			return ecSuccess;
	}
 DELETE_FOLDER:
	return exmdb_client::delete_folder(pstore->get_dir(),
	       pinfo->cpid, folder_id, b_hard, &b_done) ? ecSuccess : ecError;
}

ec_error_t zs_emptyfolder(GUID hsession, uint32_t hfolder, uint32_t flags)
{
	BOOL b_partial;
	zs_objtype mapi_type;
	uint32_t permission;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	if (!pstore->b_private)
		return ecNotSupported;
	auto fid_val = rop_util_get_gc_value(pfolder->folder_id);
	if (fid_val == PRIVATE_FID_ROOT || fid_val == PRIVATE_FID_IPMSUBTREE)
		return ecAccessDenied;
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsDeleteAny | frightsDeleteOwned)))
			return ecAccessDenied;
		username = pinfo->get_username();
	}
	BOOL b_fai = (flags & FLAG_DEL_ASSOCIATED) ? TRUE : false;
	BOOL b_hard = (flags & FLAG_HARD_DELETE) ? TRUE : false;
	return exmdb_client::empty_folder(pstore->get_dir(),
	       pinfo->cpid, username, pfolder->folder_id,
	       b_hard, TRUE, b_fai, TRUE, &b_partial) ? ecSuccess : ecError;
}

ec_error_t zs_copyfolder(GUID hsession, uint32_t hsrc_folder, BINARY entryid,
    uint32_t hdst_folder, const char *new_name, uint32_t flags)
{
	BOOL b_done;
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_private;
	BOOL b_partial;
	int account_id;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto psrc_parent = pinfo->ptree->get_object<folder_object>(hsrc_folder, &mapi_type);
	if (psrc_parent == nullptr)
		return ecNullObject;
	BOOL b_copy = (flags & FLAG_MOVE) ? false : TRUE;
	if (psrc_parent->type == FOLDER_SEARCH && !b_copy)
		return ecNotSupported;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = psrc_parent->pstore;
	if (!cu_entryid_to_fid(entryid,
	    &b_private, &account_id, &folder_id))
		return ecError;
	if (b_private != pstore->b_private || account_id != pstore->account_id)
		return ecInvalidParam;
	auto pdst_folder = pinfo->ptree->get_object<folder_object>(hdst_folder, &mapi_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore1 = pdst_folder->pstore;
	auto fidtest = pstore->b_private ? PRIVATE_FID_ROOT : PUBLIC_FID_ROOT;
	if (rop_util_get_gc_value(folder_id) == fidtest)
		return ecAccessDenied;
	BOOL b_guest = false;
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsReadAny))
			return ecAccessDenied;
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pdst_folder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
		username = pinfo->get_username();
		b_guest = TRUE;
	}
	if (pstore != pstore1) {
		if (!b_copy && !pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    psrc_parent->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		auto ret = cu_remote_copy_folder(pstore, folder_id, pstore1,
		           pdst_folder->folder_id, new_name);
		if (ret != ecSuccess)
			return ret;
		if (!b_copy) {
			if (!exmdb_client::empty_folder(pstore->get_dir(),
			    pinfo->cpid, username, folder_id, false, TRUE,
			    TRUE, TRUE, &b_partial))
				return ecError;
			if (b_partial)
				/* failure occurs, stop deleting folder */
				return ecSuccess;
			if (!exmdb_client::delete_folder(pstore->get_dir(),
			    pinfo->cpid, folder_id, false, &b_done))
				return ecError;
		}
		return ecSuccess;
	}
	if (!exmdb_client::check_folder_cycle(pstore->get_dir(), folder_id,
	    pdst_folder->folder_id, &b_cycle))
		return ecError;
	if (b_cycle)
		return ecRootFolder;
	if (!exmdb_client::movecopy_folder(pstore->get_dir(),
	    pstore->account_id, pinfo->cpid, b_guest, pinfo->get_username(),
	    psrc_parent->folder_id, folder_id, pdst_folder->folder_id,
	    new_name, b_copy, &b_exist, &b_partial))
		return ecError;
	return b_exist ? ecDuplicateName : ecSuccess;
}

ec_error_t zs_getstoreentryid(const char *mailbox_dn, BINARY *pentryid)
{
	EXT_PUSH ext_push;
	char username[UADDR_SIZE];
	char tmp_buff[1024];
	STORE_ENTRYID store_entryid = {};
	
	if (0 == strncasecmp(mailbox_dn, "/o=", 3)) {
		if (!common_util_essdn_to_username(mailbox_dn,
		    username, GX_ARRAY_SIZE(username)))
			return ecNotFound;
	} else {
		gx_strlcpy(username, mailbox_dn, GX_ARRAY_SIZE(username));
		if (!common_util_username_to_essdn(username,
		    tmp_buff, GX_ARRAY_SIZE(tmp_buff)))
			return ecNotFound;
		mailbox_dn = tmp_buff;
	}
	store_entryid.flags = 0;
	store_entryid.version = 0;
	store_entryid.flag = 0;
	store_entryid.wrapped_flags = 0;
	store_entryid.wrapped_provider_uid = g_muidStorePrivate;
	store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
	store_entryid.pserver_name = username;
	store_entryid.pmailbox_dn = deconst(mailbox_dn);
	pentryid->pv = common_util_alloc(1024);
	if (pentryid->pv == nullptr ||
	    !ext_push.init(pentryid->pb, 1024, EXT_FLAG_UTF16) ||
	    ext_push.p_store_eid(store_entryid) != EXT_ERR_SUCCESS)
		return ecError;
	pentryid->cb = ext_push.m_offset;
	return ecSuccess;
}

ec_error_t zs_entryidfromsourcekey(GUID hsession, uint32_t hstore,
    BINARY folder_key, const BINARY *pmessage_key, BINARY *pentryid)
{
	XID tmp_xid;
	BOOL b_found;
	BINARY *pbin;
	uint16_t replid;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	
	if (folder_key.cb != 22 || (pmessage_key != nullptr && pmessage_key->cb != 22))
		return ecInvalidParam;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	if (!common_util_binary_to_xid(&folder_key, &tmp_xid))
		return ecNotSupported;
	if (pstore->b_private) {
		auto tmp_guid = rop_util_make_user_guid(pstore->account_id);
		if (tmp_guid != tmp_xid.guid)
			return ecInvalidParam;
		folder_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
	} else {
		auto domain_id = rop_util_get_domain_id(tmp_xid.guid);
		if (domain_id == -1)
			return ecInvalidParam;
		if (domain_id == pstore->account_id) {
			replid = 1;
		} else {
			if (pmessage_key != nullptr)
				return ecInvalidParam;
			if (!system_services_check_same_org(domain_id, pstore->account_id))
				return ecInvalidParam;
			if (!exmdb_client::get_mapping_replid(pstore->get_dir(),
			    tmp_xid.guid, &b_found, &replid))
				return ecError;
			if (!b_found)
				return ecNotFound;
		}
		folder_id = rop_util_make_eid(replid, tmp_xid.local_to_gc());
	}
	if (NULL != pmessage_key) {
		if (!common_util_binary_to_xid(pmessage_key, &tmp_xid))
			return ecNotSupported;
		if (pstore->b_private) {
			auto tmp_guid = rop_util_make_user_guid(pstore->account_id);
			if (tmp_guid != tmp_xid.guid)
				return ecInvalidParam;
			message_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		} else {
			auto domain_id = rop_util_get_domain_id(tmp_xid.guid);
			if (domain_id == -1)
				return ecInvalidParam;
			if (domain_id != pstore->account_id)
				return ecInvalidParam;
			message_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		}
		pbin = cu_mid_to_entryid(pstore, folder_id, message_id);
	} else {
		pbin = cu_fid_to_entryid(pstore, folder_id);
	}
	if (pbin == nullptr)
		return ecError;
	*pentryid = *pbin;
	return ecSuccess;
}

ec_error_t zs_storeadvise(GUID hsession, uint32_t hstore,
    const BINARY *pentryid, uint32_t event_mask, uint32_t *psub_id)
{
	char dir[256];
	uint16_t type;
	BOOL b_private;
	int account_id;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	folder_id = 0;
	message_id = 0;
	if (NULL != pentryid) {
		type = common_util_get_messaging_entryid_type(*pentryid);
		switch (type) {
		case EITLT_PRIVATE_FOLDER:
		case EITLT_PUBLIC_FOLDER:
			if (!cu_entryid_to_fid(*pentryid,
			    &b_private, &account_id, &folder_id))
				return ecError;
			break;
		case EITLT_PRIVATE_MESSAGE:
		case EITLT_PUBLIC_MESSAGE:
			if (!cu_entryid_to_mid(*pentryid,
			    &b_private, &account_id, &folder_id, &message_id))
				return ecError;
			break;
		default:
			return ecNotFound;
		}
		if (b_private != pstore->b_private || account_id != pstore->account_id)
			return ecInvalidParam;
	}
	if (!exmdb_client::subscribe_notification(pstore->get_dir(),
	    event_mask, TRUE, folder_id, message_id, psub_id))
		return ecError;
	gx_strlcpy(dir, pstore->get_dir(), arsizeof(dir));
	pinfo.reset();
	std::unique_lock nl_hold(g_notify_lock);
	if (g_notify_table.size() == g_table_size) {
		nl_hold.unlock();
		exmdb_client::unsubscribe_notification(dir, *psub_id);
		return ecError;
	}
	try {
		auto tmp_buf = std::to_string(*psub_id) + "|" + dir;
		g_notify_table.try_emplace(std::move(tmp_buf), hsession, hstore);
	} catch (const std::bad_alloc &) {
		nl_hold.unlock();
		exmdb_client::unsubscribe_notification(dir, *psub_id);
		return ecError;
	}
	return ecSuccess;
}

ec_error_t zs_unadvise(GUID hsession, uint32_t hstore,
     uint32_t sub_id) try
{	
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	std::string dir = pstore->get_dir();
	pinfo.reset();
	exmdb_client::unsubscribe_notification(dir.c_str(), sub_id);
	auto tmp_buf = std::to_string(sub_id) + "|"s + std::move(dir);
	std::unique_lock nl_hold(g_notify_lock);
	g_notify_table.erase(std::move(tmp_buf));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1498: ENOMEM");
	return ecServerOOM;
}

ec_error_t zs_notifdequeue(const NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications)
{
	int i;
	int count;
	zs_objtype mapi_type;
	DOUBLE_LIST_NODE *pnode;
	ZNOTIFICATION* ppnotifications[1024];
	
	auto pinfo = zs_query_session(psink->hsession);
	if (pinfo == nullptr)
		return ecError;
	count = 0;
	for (i=0; i<psink->count; i++) {
		auto pstore = pinfo->ptree->get_object<store_object>(psink->padvise[i].hstore, &mapi_type);
		if (pstore == nullptr || mapi_type != zs_objtype::store)
			continue;
		std::string tmp_buf;
		try {
			tmp_buf = std::to_string(psink->padvise[i].sub_id) +
			          "|" + pstore->get_dir();
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1496: ENOMEM");
			continue;
		}
		std::unique_lock nl_hold(g_notify_lock);
		auto iter = g_notify_table.find(std::move(tmp_buf));
		if (iter == g_notify_table.end())
			continue;
		auto pnitem = &iter->second;
		time(&pnitem->last_time);
		while ((pnode = double_list_pop_front(&pnitem->notify_list)) != nullptr) {
			ppnotifications[count] = common_util_dup_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata), true);
			common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
			free(pnode);
			if (ppnotifications[count] != nullptr)
				count ++;
			if (count == 1024)
				break;
		}
		nl_hold.unlock();
		if (count == 1024)
			break;
	}
	if (count > 0) {
		pinfo.reset();
		pnotifications->count = count;
		pnotifications->ppnotification = cu_alloc<ZNOTIFICATION *>(count);
		if (pnotifications->ppnotification == nullptr)
			return ecError;
		memcpy(pnotifications->ppnotification,
			ppnotifications, sizeof(void*)*count);
		return ecSuccess;
	}
	std::list<sink_node> holder;
	try {
		holder.emplace_back();
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-2179: ENOMEM");
		return ecServerOOM;
	}
	auto psink_node = &holder.front();
	psink_node->clifd = common_util_get_clifd();
	time(&psink_node->until_time);
	psink_node->until_time += timeval;
	psink_node->sink.hsession = psink->hsession;
	psink_node->sink.count = psink->count;
	psink_node->sink.padvise = me_alloc<ADVISE_INFO>(psink->count);
	if (psink_node->sink.padvise == nullptr)
		return ecError;
	memcpy(psink_node->sink.padvise, psink->padvise,
				psink->count*sizeof(ADVISE_INFO));
	pinfo->sink_list.splice(pinfo->sink_list.end(), holder, holder.begin());
	return ecNotFound;
}

ec_error_t zs_queryrows(GUID hsession, uint32_t htable, uint32_t start,
	uint32_t count, const RESTRICTION *prestriction,
	const PROPTAG_ARRAY *pproptags, TARRAY_SET *prowset)
{
	uint32_t row_num;
	int32_t position;
	zs_objtype mapi_type;
	TARRAY_SET tmp_set;
	uint32_t *pobject_type = nullptr;
	TAGGED_PROPVAL *ppropvals;
	
	if (count > INT32_MAX)
		count = INT32_MAX;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	auto table_type = ptable->table_type;
	if (start != UINT32_MAX)
		ptable->set_position(start);
	if (NULL != prestriction) {
		switch (ptable->table_type) {
		case zcore_tbltype::hierarchy:
		case zcore_tbltype::content:
		case zcore_tbltype::rule:
			row_num = ptable->get_total();
			if (row_num > count)
				row_num = count;
			prowset->count = 0;
			prowset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_num);
			if (prowset->pparray == nullptr)
				return ecError;
			while (true) {
				if (!ptable->match_row(TRUE, prestriction, &position))
					return ecError;
				if (position < 0)
					break;
				ptable->set_position(position);
				if (!ptable->query_rows(pproptags, 1, &tmp_set))
					return ecError;
				if (tmp_set.count != 1)
					break;
				ptable->seek_current(TRUE, 1);
				prowset->pparray[prowset->count++] = tmp_set.pparray[0];
				if (count == prowset->count)
					break;
			}
			break;
		case zcore_tbltype::attachment:
		case zcore_tbltype::recipient:
		case zcore_tbltype::store:
		case zcore_tbltype::abcontusr:
			if (!ptable->filter_rows(count, prestriction, pproptags, prowset))
				return ecError;
			break;
		default:
			return ecNotSupported;
		}
	} else {
		if (!ptable->query_rows(pproptags, count, prowset))
			return ecError;
		ptable->seek_current(TRUE, prowset->count);
	}
	pinfo.reset();
	if ((table_type != zcore_tbltype::store &&
	     table_type != zcore_tbltype::hierarchy &&
	     table_type != zcore_tbltype::content &&
	     table_type != zcore_tbltype::attachment) ||
	    (pproptags != nullptr && !pproptags->has(PR_OBJECT_TYPE)))
		return ecSuccess;
	static constexpr auto object_type_store      = static_cast<uint32_t>(MAPI_STORE);
	static constexpr auto object_type_folder     = static_cast<uint32_t>(MAPI_FOLDER);
	static constexpr auto object_type_message    = static_cast<uint32_t>(MAPI_MESSAGE);
	static constexpr auto object_type_attachment = static_cast<uint32_t>(MAPI_ATTACH);
	switch (table_type) {
	case zcore_tbltype::store:
		pobject_type = deconst(&object_type_store);
		break;
	case zcore_tbltype::hierarchy:
		pobject_type = deconst(&object_type_folder);
		break;
	case zcore_tbltype::content:
		pobject_type = deconst(&object_type_message);
		break;
	case zcore_tbltype::attachment:
		pobject_type = deconst(&object_type_attachment);
		break;
	default:
		break;
	}
	for (size_t i = 0; i < prowset->count; ++i) {
		ppropvals = cu_alloc<TAGGED_PROPVAL>(prowset->pparray[i]->count + 1);
		if (ppropvals == nullptr)
			return ecError;
		memcpy(ppropvals, prowset->pparray[i]->ppropval,
			sizeof(TAGGED_PROPVAL)*prowset->pparray[i]->count);
		ppropvals[prowset->pparray[i]->count].proptag = PR_OBJECT_TYPE;
		ppropvals[prowset->pparray[i]->count++].pvalue = pobject_type;
		prowset->pparray[i]->ppropval = ppropvals;
	}
	return ecSuccess;
}
	
ec_error_t zs_setcolumns(GUID hsession, uint32_t htable,
	const PROPTAG_ARRAY *pproptags, uint32_t flags)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	return ptable->set_columns(pproptags) ? ecSuccess : ecError;
}

ec_error_t zs_seekrow(GUID hsession, uint32_t htable, uint32_t bookmark,
    int32_t seek_rows, int32_t *psought_rows)
{
	BOOL b_exist;
	zs_objtype mapi_type;
	uint32_t original_position;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	switch (bookmark) {
	case BOOKMARK_BEGINNING:
		if (seek_rows < 0)
			return ecInvalidParam;
		original_position = 0;
		ptable->set_position(seek_rows);
		break;
	case BOOKMARK_END:
		if (seek_rows > 0)
			return ecInvalidParam;
		original_position = ptable->get_total();
		ptable->set_position(safe_add_s(original_position, seek_rows));
		break;
	case BOOKMARK_CURRENT:
		original_position = ptable->get_position();
		ptable->set_position(safe_add_s(original_position, seek_rows));
		break;
	default: {
		original_position = ptable->get_position();
		if (!ptable->retrieve_bookmark(bookmark, &b_exist))
			return ecError;
		if (!b_exist)
			return ecNotFound;
		auto original_position1 = ptable->get_position();
		ptable->set_position(safe_add_s(original_position1, seek_rows));
		break;
	}
	}
	*psought_rows = ptable->get_position() - original_position;
	return ecSuccess;
}

static bool table_acceptable_type(uint16_t type)
{
	switch (type) {
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_CURRENCY:
	case PT_APPTIME:
	case PT_BOOLEAN:
	case PT_OBJECT:
	case PT_I8:
	case PT_STRING8:
	case PT_UNICODE:
	case PT_SYSTIME:
	case PT_CLSID:
	case PT_SVREID:
	case PT_SRESTRICTION:
	case PT_ACTIONS:
	case PT_BINARY:
	case PT_MV_SHORT:
	case PT_MV_LONG:
	case PT_MV_FLOAT:
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
	case PT_MV_SYSTIME:
	case PT_MV_CLSID:
	case PT_MV_BINARY:
		return true;
	case PT_UNSPECIFIED:
	case PT_ERROR:
	default:
		return false;
	}
}

ec_error_t zs_sorttable(GUID hsession,
	uint32_t htable, const SORTORDER_SET *psortset)
{
	BOOL b_max;
	uint16_t type;
	zs_objtype mapi_type;
	BOOL b_multi_inst;
	uint32_t tmp_proptag;
	
	if (psortset->count > MAXIMUM_SORT_COUNT)
		return ecTooComplex;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	if (ptable->table_type != zcore_tbltype::content)
		return ecSuccess;
	b_max = FALSE;
	b_multi_inst = FALSE;
	for (unsigned int i = 0; i < psortset->count; ++i) {
		tmp_proptag = PROP_TAG(psortset->psort[i].type, psortset->psort[i].propid);
		if (tmp_proptag == PR_DEPTH || tmp_proptag == PidTagInstID ||
		    tmp_proptag == PidTagInstanceNum ||
		    tmp_proptag == PR_CONTENT_COUNT ||
		    tmp_proptag == PR_CONTENT_UNREAD)
			return ecInvalidParam;
		switch (psortset->psort[i].table_sort) {
		case TABLE_SORT_ASCEND:
		case TABLE_SORT_DESCEND:
			break;
		case TABLE_SORT_MAXIMUM_CATEGORY:
		case TABLE_SORT_MINIMUM_CATEGORY:
			if (psortset->ccategories == 0 ||
			    psortset->ccategories != i)
				return ecInvalidParam;
			break;
		default:
			return ecInvalidParam;
		}
		type = psortset->psort[i].type;
		if (type & MV_FLAG) {
			/* we do not support multivalue property
				without multivalue instances */
			if (!(type & MV_INSTANCE))
				return ecNotSupported;
			type &= ~MV_INSTANCE;
			/* MUST NOT contain more than one multivalue property! */
			if (b_multi_inst)
				return ecInvalidParam;
			b_multi_inst = TRUE;
		}
		if (!table_acceptable_type(type))
			return ecInvalidParam;
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psortset->psort[i].table_sort ||
			TABLE_SORT_MINIMUM_CATEGORY ==
			psortset->psort[i].table_sort) {
			if (b_max || i != psortset->ccategories)
				return ecInvalidParam;
			b_max = TRUE;
		}
	}
	auto pcolumns = ptable->get_columns();
	if (b_multi_inst && pcolumns != nullptr &&
	    !common_util_verify_columns_and_sorts(pcolumns, psortset))
		return ecNotSupported;
	if (!ptable->set_sorts(psortset))
		return ecError;
	ptable->unload();
	ptable->clear_bookmarks();
	ptable->clear_position();
	return ecSuccess;
}

ec_error_t zs_getrowcount(GUID hsession, uint32_t htable, uint32_t *pcount)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	*pcount = ptable->get_total();
	return ecSuccess;
}

ec_error_t zs_restricttable(GUID hsession, uint32_t htable,
	const RESTRICTION *prestriction, uint32_t flags)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	switch (ptable->table_type) {
	case zcore_tbltype::hierarchy:
	case zcore_tbltype::content:
	case zcore_tbltype::rule:
	case zcore_tbltype::store:
	case zcore_tbltype::abcontusr:
		break;
	default:
		return ecNotSupported;
	}
	if (!ptable->set_restriction(prestriction))
		return ecError;
	ptable->unload();
	ptable->clear_bookmarks();
	ptable->clear_position();
	return ecSuccess;
}

ec_error_t zs_findrow(GUID hsession, uint32_t htable, uint32_t bookmark,
    const RESTRICTION *prestriction, uint32_t flags, uint32_t *prow_idx)
{
	BOOL b_exist;
	int32_t position;
	zs_objtype mapi_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	switch (ptable->table_type) {
	case zcore_tbltype::hierarchy:
	case zcore_tbltype::content:
	case zcore_tbltype::rule:
		break;
	default:
		return ecNotSupported;
	}
	if (!ptable->load())
		return ecError;
	switch (bookmark) {
	case BOOKMARK_BEGINNING:
		ptable->set_position(0);
		break;
	case BOOKMARK_END:
		ptable->set_position(ptable->get_total());
		break;
	case BOOKMARK_CURRENT:
		break;
	default:
		if (ptable->table_type == zcore_tbltype::rule)
			return ecNotSupported;
		if (!ptable->retrieve_bookmark(bookmark, &b_exist))
			return ecInvalidBookmark;
		break;
	}
	if (ptable->match_row(TRUE, prestriction, &position))
		return ecError;
	if (position < 0)
		return ecNotFound;
	ptable->set_position(position);
	*prow_idx = position;
	return ecSuccess;
}

ec_error_t zs_createbookmark(GUID hsession, uint32_t htable, uint32_t *pbookmark)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	switch (ptable->table_type) {
	case zcore_tbltype::hierarchy:
	case zcore_tbltype::content:
		break;
	default:
		return ecNotSupported;
	}
	if (!ptable->load())
		return ecError;
	return ptable->create_bookmark(pbookmark) ? ecSuccess : ecError;
}

ec_error_t zs_freebookmark(GUID hsession, uint32_t htable, uint32_t bookmark)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto ptable = pinfo->ptree->get_object<table_object>(htable, &mapi_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::table)
		return ecNotSupported;
	switch (ptable->table_type) {
	case zcore_tbltype::hierarchy:
	case zcore_tbltype::content:
		break;
	default:
		return ecNotSupported;
	}
	ptable->remove_bookmark(bookmark);
	return ecSuccess;
}

ec_error_t zs_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid)
{
	BINARY *pbin;
	zs_objtype mapi_type;
	uint64_t folder_id;
	char *temp_class = nullptr;
	
	if (pstrclass == nullptr)
		pstrclass = "";
	if (!cu_validate_msgclass(pstrclass))
		return ecInvalidParam;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	if (!pstore->b_private)
		return ecNotSupported;
	if (!exmdb_client::get_folder_by_class(pstore->get_dir(), pstrclass,
	    &folder_id, &temp_class))
		return ecError;
	pbin = cu_fid_to_entryid(pstore, folder_id);
	if (pbin == nullptr)
		return ecError;
	*pentryid = *pbin;
	return ecSuccess;
}

ec_error_t zs_modifyrecipients(GUID hsession,
	uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list)
{
	static constexpr uint8_t persist_true = true, persist_false = false;
	BOOL b_found;
	zs_objtype mapi_type;
	EXT_PULL ext_pull;
	uint32_t tmp_flags;
	char tmp_buff[256];
	uint32_t last_rowid;
	TPROPVAL_ARRAY *prcpt;
	FLATUID provider_uid;
	TAGGED_PROPVAL *ppropval;
	TAGGED_PROPVAL tmp_propval;
	ONEOFF_ENTRYID oneoff_entry;
	EMSAB_ENTRYID ab_entryid;
	
	if (prcpt_list->count >= 0x7fef || (flags != MODRECIP_ADD &&
	    flags != MODRECIP_MODIFY && flags != MODRECIP_REMOVE))
		return ecInvalidParam;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	if (MODRECIP_MODIFY == flags) {
		pmessage->empty_rcpts();
	} else if (MODRECIP_REMOVE == flags) {
		for (size_t i = 0; i < prcpt_list->count; ++i) {
			prcpt = prcpt_list->pparray[i];
			b_found = FALSE;
			for (size_t j = 0; j < prcpt->count; ++j) {
				if (prcpt->ppropval[j].proptag == PR_ROWID) {
					prcpt->count = 1;
					prcpt->ppropval = prcpt->ppropval + j;
					b_found = TRUE;
					break;
				}
			}
			if (!b_found)
				return ecInvalidParam;
		}
		if (!pmessage->set_rcpts(prcpt_list))
			return ecError;
		return ecSuccess;
	}
	if (!pmessage->get_rowid_begin(&last_rowid))
		return ecError;
	for (size_t i = 0; i < prcpt_list->count; ++i, ++last_rowid) {
		if (!prcpt_list->pparray[i]->has(PR_ENTRYID) &&
		    !prcpt_list->pparray[i]->has(PR_EMAIL_ADDRESS) &&
		    !prcpt_list->pparray[i]->has(PR_SMTP_ADDRESS))
			return ecInvalidParam;
		auto prowid = prcpt_list->pparray[i]->get<uint32_t>(PR_ROWID);
		if (NULL != prowid) {
			if (*prowid < last_rowid)
				*prowid = last_rowid;
			else
				last_rowid = *prowid;
		} else {
			prcpt = prcpt_list->pparray[i];
			ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 1);
			if (ppropval == nullptr)
				return ecError;
			memcpy(ppropval, prcpt->ppropval,
				sizeof(TAGGED_PROPVAL)*prcpt->count);
			ppropval[prcpt->count].proptag = PR_ROWID;
			ppropval[prcpt->count].pvalue = cu_alloc<uint32_t>();
			if (ppropval[prcpt->count].pvalue == nullptr)
				return ecError;
			*static_cast<uint32_t *>(ppropval[prcpt->count++].pvalue) = last_rowid;
			prcpt->ppropval = ppropval;
			auto pbin = prcpt->get<BINARY>(PR_ENTRYID);
			if (pbin == nullptr ||
			    (prcpt->has(PR_EMAIL_ADDRESS) &&
			    prcpt->has(PR_ADDRTYPE) && prcpt->has(PR_DISPLAY_NAME)))
				continue;
			ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
			if (ext_pull.g_uint32(&tmp_flags) != EXT_ERR_SUCCESS ||
			    tmp_flags != 0)
				continue;
			if (ext_pull.g_guid(&provider_uid) != EXT_ERR_SUCCESS)
				continue;
			if (provider_uid == muidEMSAB) {
				ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
				if (ext_pull.g_abk_eid(&ab_entryid) != EXT_ERR_SUCCESS ||
				    ab_entryid.type != DT_MAILUSER)
					continue;
				ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 4);
				if (ppropval == nullptr)
					return ecError;
				memcpy(ppropval, prcpt->ppropval,
					prcpt->count*sizeof(TAGGED_PROPVAL));
				prcpt->ppropval = ppropval;
				tmp_propval.proptag = PR_ADDRTYPE;
				tmp_propval.pvalue  = deconst("EX");
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PR_EMAIL_ADDRESS;
				tmp_propval.pvalue = common_util_dup(ab_entryid.px500dn);
				if (tmp_propval.pvalue == nullptr)
					return ecError;
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PR_SMTP_ADDRESS;
				if (!common_util_essdn_to_username(ab_entryid.px500dn,
				    tmp_buff, GX_ARRAY_SIZE(tmp_buff)))
					continue;
				tmp_propval.pvalue = common_util_dup(tmp_buff);
				if (tmp_propval.pvalue == nullptr)
					return ecError;
				common_util_set_propvals(prcpt, &tmp_propval);
				if (!system_services_get_user_displayname(tmp_buff,
				    tmp_buff, arsizeof(tmp_buff)))
					continue;	
				tmp_propval.proptag = PR_DISPLAY_NAME;
				tmp_propval.pvalue = common_util_dup(tmp_buff);
				if (tmp_propval.pvalue == nullptr)
					return ecError;
				common_util_set_propvals(prcpt, &tmp_propval);
				continue;
			}
			if (provider_uid == muidOOP) {
				ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
				if (ext_pull.g_oneoff_eid(&oneoff_entry) != EXT_ERR_SUCCESS ||
				    strcasecmp(oneoff_entry.paddress_type, "SMTP") != 0)
					continue;
				ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 5);
				if (ppropval == nullptr)
					return ecError;
				memcpy(ppropval, prcpt->ppropval,
					prcpt->count*sizeof(TAGGED_PROPVAL));
				prcpt->ppropval = ppropval;
				tmp_propval.proptag = PR_ADDRTYPE;
				tmp_propval.pvalue  = deconst("SMTP");
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PR_EMAIL_ADDRESS;
				tmp_propval.pvalue = common_util_dup(
						oneoff_entry.pmail_address);
				if (tmp_propval.pvalue == nullptr)
					return ecError;
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PR_SMTP_ADDRESS;
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PR_DISPLAY_NAME;
				tmp_propval.pvalue = common_util_dup(
						oneoff_entry.pdisplay_name);
				if (tmp_propval.pvalue == nullptr)
					return ecError;
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PR_SEND_RICH_INFO;
				tmp_propval.pvalue = deconst((oneoff_entry.ctrl_flags & MAPI_ONE_OFF_NO_RICH_INFO) ? &persist_false : &persist_true);
				common_util_set_propvals(prcpt, &tmp_propval);
			}
		}
	}
	return pmessage->set_rcpts(prcpt_list) ? ecSuccess : ecError;
}

/**
 * @send_as:	mangle message for Send-As (true) or just
 * 		Send-On-Behalf/No-Change (false)
 */
static ec_error_t rectify_message(message_object *pmessage,
    const char *representing_username, bool send_as)
{
	auto account = pmessage->pstore->get_account();
	uint8_t tmp_byte = 1;
	auto nt_time = rop_util_current_nttime();
	int32_t tmp_level = -1;
	char essdn[1024], essdn1[1024];
	if (!common_util_username_to_essdn(account, essdn, arsizeof(essdn)))
		return ecError;
	char dispname[256], dispname1[256], search_buff[1024], search_buff1[1024];
	if (!system_services_get_user_displayname(account,
	    dispname, arsizeof(dispname)))
		return ecError;
	auto entryid = common_util_username_to_addressbook_entryid(account);
	if (entryid == nullptr)
		return ecError;
	auto entryid1 = entryid;
	BINARY search_bin, search_bin1;
	search_bin.cb = gx_snprintf(search_buff, arsizeof(search_buff), "EX:%s", essdn) + 1;
	search_bin.pv = search_buff;
	if (0 != strcasecmp(account, representing_username)) {
		if (!common_util_username_to_essdn(representing_username,
		    essdn1, arsizeof(essdn1)))
			return ecError;
		if (!system_services_get_user_displayname(representing_username,
		    dispname1, arsizeof(dispname1)))
			return ecError;
		entryid1 = common_util_username_to_addressbook_entryid(representing_username);
		if (entryid1 == nullptr)
			return ecError;
	} else {
		strcpy(essdn1, essdn);
		strcpy(dispname1, dispname);
	}
	search_bin1.cb = gx_snprintf(search_buff1, arsizeof(search_buff1), "EX:%s", essdn1) + 1;
	search_bin1.pv = search_buff1;
	char msgid[UADDR_SIZE+2];
	make_inet_msgid(msgid, arsizeof(msgid), 0x5a53);
	TAGGED_PROPVAL pv[] = {
		{PR_READ, &tmp_byte},
		{PR_CLIENT_SUBMIT_TIME, &nt_time},
		{PR_MESSAGE_DELIVERY_TIME, &nt_time},
		{PR_CONTENT_FILTER_SCL, &tmp_level},
		{PR_SENDER_SMTP_ADDRESS, deconst(send_as ? representing_username : account)},
		{PR_SENDER_ADDRTYPE, deconst("EX")},
		{PR_SENDER_EMAIL_ADDRESS, send_as ? essdn1 : essdn},
		{PR_SENDER_NAME, send_as ? dispname1 : dispname},
		{PR_SENDER_ENTRYID, send_as ? entryid1 : entryid},
		{PR_SENDER_SEARCH_KEY, send_as ? &search_bin1 : &search_bin},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, deconst(representing_username)},
		{PR_SENT_REPRESENTING_ADDRTYPE, deconst("EX")},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, essdn1},
		{PR_SENT_REPRESENTING_NAME, dispname1},
		{PR_SENT_REPRESENTING_ENTRYID, entryid1},
		{PR_SENT_REPRESENTING_SEARCH_KEY, &search_bin1},
		{PR_INTERNET_MESSAGE_ID, msgid},
	};
	TPROPVAL_ARRAY tmp_propvals = {arsizeof(pv), pv};
	if (!pmessage->set_properties(&tmp_propvals))
		return ecError;
	return pmessage->save();
}

ec_error_t zs_submitmessage(GUID hsession, uint32_t hmessage)
{
	int timer_id;
	BOOL b_marked;
	zs_objtype mapi_type;
	uint16_t rcpt_num;
	char username[UADDR_SIZE];
	char command_buff[1024];
	uint32_t proptag_buff[6];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto pstore = pmessage->get_store();
	if (!pstore->b_private)
		return ecNotSupported;
	if (!pstore->owner_mode()) {
		uint32_t permission = 0;
		if (!exmdb_client::get_mbox_perm(pstore->get_dir(),
		    pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsGromoxSendAs))
			return ecAccessDenied;
	}
	if (pmessage->get_id() == 0)
		return ecNotSupported;
	if (pmessage->importing() || !pmessage->writable())
		return ecAccessDenied;
	if (pmessage->get_recipient_num(&rcpt_num) == 0)
		return MAPI_E_NO_RECIPIENTS;
	if (rcpt_num > g_max_rcpt)
		return ecTooManyRecips;

	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_ASSOCIATED;
	if (!pmessage->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;
	auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
	/* FAI message cannot be sent */
	if (flag != nullptr && *flag != 0)
		return ecAccessDenied;
	if (!cu_extract_delegate(pmessage, username, std::size(username)))
		return ecSendAsDenied;
	auto account = pstore->get_account();
	repr_grant repr_grant;
	if ('\0' == username[0]) {
		gx_strlcpy(username, account, GX_ARRAY_SIZE(username));
		repr_grant = repr_grant::send_as;
	} else {
		repr_grant = cu_get_delegate_perm_AA(account, username);
	}
	if (repr_grant < repr_grant::send_on_behalf) {
		mlog(LV_INFO, "I-1334: uid %s tried to send with from=<%s>, but no impersonation permission given.",
		        account, username);
		return ecAccessDenied;
	}
	auto err = rectify_message(pmessage, username,
	           repr_grant >= repr_grant::send_as);
	if (err != ecSuccess)
		return err;
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MAX_SUBMIT_MESSAGE_SIZE;
	proptag_buff[1] = PR_PROHIBIT_SEND_QUOTA;
	proptag_buff[2] = PR_MESSAGE_SIZE_EXTENDED;
	if (!pstore->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;

	auto sendquota = tmp_propvals.get<uint32_t>(PR_PROHIBIT_SEND_QUOTA);
	auto storesize = tmp_propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	/* Sendquota is in KiB, storesize in bytes */
	if (sendquota != nullptr && storesize != nullptr &&
	    static_cast<uint64_t>(*sendquota) * 1024 <= *storesize)
		return ecQuotaExceeded;

	auto num = tmp_propvals.get<const uint32_t>(PR_MAX_SUBMIT_MESSAGE_SIZE);
	ssize_t max_length = -1;
	if (num != nullptr)
		max_length = *num;
	tmp_proptags.count = 6;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MESSAGE_SIZE;
	proptag_buff[1] = PR_MESSAGE_FLAGS;
	proptag_buff[2] = PR_DEFERRED_SEND_TIME;
	proptag_buff[3] = PR_DEFERRED_SEND_NUMBER;
	proptag_buff[4] = PR_DEFERRED_SEND_UNITS;
	proptag_buff[5] = PR_DELETE_AFTER_SUBMIT;
	if (!pmessage->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;
	num = tmp_propvals.get<uint32_t>(PR_MESSAGE_SIZE);
	if (num == nullptr)
		return ecError;
	auto mail_length = *num;
	if (max_length > 0 && mail_length > static_cast<size_t>(max_length))
		return EC_EXCEEDED_SIZE;
	num = tmp_propvals.get<uint32_t>(PR_MESSAGE_FLAGS);
	if (num == nullptr)
		return ecError;
	auto message_flags = *num;
	/* here we handle the submit request
		differently from exchange_emsmdb.
		we always allow a submitted message
		to be resubmitted */
	BOOL b_unsent = (message_flags & MSGFLAG_UNSENT) ? TRUE : false;
	flag = tmp_propvals.get<const uint8_t>(PR_DELETE_AFTER_SUBMIT);
	BOOL b_delete = flag != nullptr && *flag != 0 ? TRUE : false;
	if (!(message_flags & MSGFLAG_SUBMITTED)) {
		if (!exmdb_client::try_mark_submit(pstore->get_dir(),
		    pmessage->get_id(), &b_marked))
			return ecError;
		if (!b_marked)
			return ecAccessDenied;
		auto deferred_time = props_to_defer_interval(tmp_propvals);
		if (deferred_time > 0) {
			snprintf(command_buff, 1024, "%s %s %llu",
				common_util_get_submit_command(),
			         pstore->get_account(),
			         LLU{rop_util_get_gc_value(pmessage->get_id())});
			timer_id = system_services_add_timer(
					command_buff, deferred_time);
			if (0 == timer_id) {
				exmdb_client::clear_submit(pstore->get_dir(),
					pmessage->get_id(), b_unsent);
				return ecError;
			}
			exmdb_client::set_message_timer(pstore->get_dir(),
				pmessage->get_id(), timer_id);
			pmessage->reload();
			return ecSuccess;
		}
	}
	if (!common_util_send_message(pstore, pmessage->get_id(), TRUE)) {
		exmdb_client::clear_submit(pstore->get_dir(),
			pmessage->get_id(), b_unsent);
		return ecRpcFailed;
	}
	if (!b_delete)
		pmessage->reload();
	else
		pmessage->clear_unsent();
	return ecSuccess;
}

ec_error_t zs_loadattachmenttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto pstore = pmessage->get_store();
	auto ptable = table_object::create(pstore, pmessage, zcore_tbltype::attachment, 0);
	if (ptable == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hmessage, {zs_objtype::table, std::move(ptable)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_openattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto pattachment = attachment_object::create(pmessage, attach_id);
	if (pattachment == nullptr)
		return ecError;
	if (pattachment->get_instance_id() == 0)
		return ecNotFound;
	*phobject = pinfo->ptree->add_object_handle(hmessage, {zs_objtype::attach, std::move(pattachment)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_createattachment(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	if (!pmessage->writable())
		return ecAccessDenied;
	auto pattachment = attachment_object::create(pmessage, ATTACHMENT_NUM_INVALID);
	if (pattachment == nullptr)
		return ecError;
	if (pattachment->get_attachment_num() == ATTACHMENT_NUM_INVALID)
		return ecMaxAttachmentExceeded;
	if (!pattachment->init_attachment())
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hmessage, {zs_objtype::attach, std::move(pattachment)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_deleteattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	if (!pmessage->writable())
		return ecAccessDenied;
	return pmessage->delete_attachment(attach_id) ? ecSuccess : ecError;
}

ec_error_t zs_setpropvals(GUID hsession, uint32_t hobject,
    TPROPVAL_ARRAY *ppropvals)
{
	zs_objtype mapi_type;
	uint32_t permission;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hobject, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (mapi_type) {
	case zs_objtype::profproperty:
		for (size_t i = 0; i < ppropvals->count; ++i)
			if (static_cast<TPROPVAL_ARRAY *>(pobject)->set(ppropvals->ppropval[i]) != 0)
				return ecError;
		pinfo->ptree->touch_profile_sec();
		return ecSuccess;
	case zs_objtype::store: {
		auto store = static_cast<store_object *>(pobject);
		if (!store->owner_mode())
			return ecAccessDenied;
		if (!store->set_properties(ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::folder: {
		auto folder = static_cast<folder_object *>(pobject);
		auto pstore = folder->pstore;
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    folder->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		if (!folder->set_properties(ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		if (!msg->writable())
			return ecAccessDenied;
		if (!msg->set_properties(ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		if (!atx->writable())
			return ecAccessDenied;
		if (!atx->set_properties(ppropvals))
			return ecError;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t zs_getpropvals(GUID hsession, uint32_t hobject,
    const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	zs_objtype mapi_type;
	PROPTAG_ARRAY proptags;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hobject, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (mapi_type) {
	case zs_objtype::profproperty:
		if (NULL == pproptags) {
			*ppropvals = *static_cast<TPROPVAL_ARRAY *>(pobject);
			return ecSuccess;
		}
		ppropvals->count = 0;
		ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
		if (ppropvals->ppropval == nullptr)
			return ecError;
		for (i = 0; i < pproptags->count; i++) {
			ppropvals->ppropval[ppropvals->count].proptag =
				pproptags->pproptag[i];
			ppropvals->ppropval[ppropvals->count].pvalue = static_cast<TPROPVAL_ARRAY *>(pobject)->getval(pproptags->pproptag[i]);
			if (ppropvals->ppropval[ppropvals->count].pvalue != nullptr)
				ppropvals->count++;
		}
		return ecSuccess;
	case zs_objtype::store: {
		auto store = static_cast<store_object *>(pobject);
		if (NULL == pproptags) {
			if (!store->get_all_proptags(&proptags))
				return ecError;
			pproptags = &proptags;
		}
		if (!store->get_properties(pproptags, ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::folder: {
		auto folder = static_cast<folder_object *>(pobject);
		if (NULL == pproptags) {
			if (!folder->get_all_proptags(&proptags))
				return ecError;
			pproptags = &proptags;
		}
		if (!folder->get_properties(pproptags, ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		if (NULL == pproptags) {
			if (!msg->get_all_proptags(&proptags))
				return ecError;
			pproptags = &proptags;
		}
		if (!msg->get_properties(pproptags, ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		if (NULL == pproptags) {
			if (!atx->get_all_proptags(&proptags))
				return ecError;
			pproptags = &proptags;
		}
		if (!atx->get_properties(pproptags, ppropvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::abcont:
		if (NULL == pproptags) {
			container_object_get_container_table_all_proptags(
				&proptags);
			pproptags = &proptags;
		}
		if (!static_cast<container_object *>(pobject)->get_properties(pproptags, ppropvals))
			return ecError;
		return ecSuccess;
	case zs_objtype::mailuser:
	case zs_objtype::distlist:
		if (NULL == pproptags) {
			container_object_get_user_table_all_proptags(&proptags);
			pproptags = &proptags;
		}
		if (!static_cast<user_object *>(pobject)->get_properties(pproptags, ppropvals))
			return ecError;
		return ecSuccess;
	case zs_objtype::oneoff:
		if (pproptags == nullptr)
			pproptags = &oneoff_object::all_tags;
		return static_cast<oneoff_object *>(pobject)->get_props(pproptags, ppropvals);
	default:
		return ecNotSupported;
	}
}

ec_error_t zs_deletepropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags)
{
	zs_objtype mapi_type;
	uint32_t permission;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hobject, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;
	switch (mapi_type) {
	case zs_objtype::profproperty:
		for (size_t i = 0; i < pproptags->count; ++i)
			static_cast<TPROPVAL_ARRAY *>(pobject)->erase(pproptags->pproptag[i]);
		pinfo->ptree->touch_profile_sec();
		return ecSuccess;
	case zs_objtype::store: {
		auto store = static_cast<store_object *>(pobject);
		if (!store->owner_mode())
			return ecAccessDenied;
		if (!store->remove_properties(pproptags))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::folder: {
		auto folder = static_cast<folder_object *>(pobject);
		auto pstore = folder->pstore;
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    folder->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		if (!folder->remove_properties(pproptags))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::message: {
		auto msg = static_cast<message_object *>(pobject);
		if (!msg->writable())
			return ecAccessDenied;
		if (!msg->remove_properties(pproptags))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::attach: {
		auto atx = static_cast<attachment_object *>(pobject);
		if (!atx->writable())
			return ecAccessDenied;
		if (!atx->remove_properties(pproptags))
			return ecError;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t zs_setmessagereadflag(GUID hsession, uint32_t hmessage,
    uint32_t flags)
{
	BOOL b_changed;
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	return pmessage->set_readflag(flags, &b_changed) ? ecSuccess : ecError;
}

ec_error_t zs_openembedded(GUID hsession,
	uint32_t hattachment, uint32_t flags, uint32_t *phobject)
{
	zs_objtype mapi_type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pattachment = pinfo->ptree->get_object<attachment_object>(hattachment, &mapi_type);
	if (pattachment == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::attach)
		return ecNotSupported;
	auto pstore = pattachment->get_store();
	auto hstore = pinfo->ptree->get_store_handle(pstore->b_private, pstore->account_id);
	if (hstore == INVALID_HANDLE)
		return ecNullObject;
	auto b_writable = pattachment->writable();
	auto tag_access = pattachment->get_tag_access();
	if ((flags & FLAG_CREATE) && !b_writable)
		return ecAccessDenied;
	auto pmessage = message_object::create(pstore, false, pinfo->cpid, 0,
	                pattachment, tag_access, b_writable ? TRUE : false, nullptr);
	if (pmessage == nullptr)
		return ecError;
	if (pmessage->get_instance_id() == 0) {
		if (!(flags & FLAG_CREATE))
			return ecNotFound;
		if (!b_writable)
			return ecAccessDenied;
		pmessage = message_object::create(pstore, TRUE, pinfo->cpid, 0,
		           pattachment, tag_access, TRUE, nullptr);
		if (pmessage == nullptr)
			return ecError;
		if (pmessage->init_message(false, pinfo->cpid) != 0)
			return ecError;
	}
	/* add the store handle as the parent object handle
		because the caller normally will not keep the
		handle of attachment */
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::message, std::move(pmessage)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	return pstore->get_named_propids(TRUE, ppropnames, ppropids) ?
	       ecSuccess : ecError;
}

ec_error_t zs_getpropnames(GUID hsession, uint32_t hstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pstore = pinfo->ptree->get_object<store_object>(hstore, &mapi_type);
	if (pstore == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::store)
		return ecNotSupported;
	return pstore->get_named_propnames(ppropids, ppropnames) ?
	       ecSuccess : ecError;
}

ec_error_t zs_copyto(GUID hsession, uint32_t hsrcobject,
    const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject, uint32_t flags)
{
	int i;
	BOOL b_cycle;
	BOOL b_collid;
	BOOL b_partial;
	zs_objtype mapi_type, dst_type;
	uint32_t permission;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY tmp_proptags;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hsrcobject, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;
	auto pobject_dst = pinfo->ptree->get_object<void>(hdstobject, &dst_type);
	if (pobject_dst == nullptr)
		return ecNullObject;
	if (mapi_type != dst_type)
		return ecNotSupported;

	BOOL b_force = (flags & MAPI_NOREPLACE) ? false : TRUE;
	switch (mapi_type) {
	case zs_objtype::folder: {
		auto folder = static_cast<folder_object *>(pobject);
		auto fdst = static_cast<folder_object *>(pobject_dst);
		auto pstore = folder->pstore;
		if (pstore != fdst->pstore)
			return ecNotSupported;
		/* MS-OXCPRPT 3.2.5.8, public folder not supported */
		if (!pstore->b_private)
			return ecNotSupported;
		const char *username = nullptr;
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    folder->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (permission & frightsOwner) {
				username = NULL;
			} else {
				if (!(permission & frightsReadAny))
					return ecAccessDenied;
				username = pinfo->get_username();
			}
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    fdst->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		BOOL b_sub;
		if (!pexclude_proptags->has(PR_CONTAINER_HIERARCHY)) {
			if (!exmdb_client::check_folder_cycle(pstore->get_dir(),
			    folder->folder_id, fdst->folder_id, &b_cycle))
				return ecError;
			if (b_cycle)
				return ecRootFolder;
			b_sub = TRUE;
		} else {
			b_sub = FALSE;
		}
		BOOL b_normal = !pexclude_proptags->has(PR_CONTAINER_CONTENTS) ? TRUE : false;
		BOOL b_fai    = !pexclude_proptags->has(PR_FOLDER_ASSOCIATED_CONTENTS) ? TRUE : false;
		if (!static_cast<folder_object *>(pobject)->get_all_proptags(&proptags))
			return ecError;
		common_util_reduce_proptags(&proptags, pexclude_proptags);
		tmp_proptags.count = 0;
		tmp_proptags.pproptag = cu_alloc<uint32_t>(proptags.count);
		if (tmp_proptags.pproptag == nullptr)
			return ecError;
		if (!b_force && !fdst->get_all_proptags(&proptags1))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (fdst->is_readonly_prop(proptags.pproptag[i]))
				continue;
			if (!b_force && proptags1.has(proptags.pproptag[i]))
				continue;
			tmp_proptags.pproptag[tmp_proptags.count++] = proptags.pproptag[i];
		}
		if (!folder->get_properties(&tmp_proptags, &propvals))
			return ecError;
		if (b_sub || b_normal || b_fai) {
			BOOL b_guest = username == nullptr ? false : TRUE;
			if (!exmdb_client::copy_folder_internal(pstore->get_dir(),
			    pstore->account_id, pinfo->cpid, b_guest,
			    pinfo->get_username(), folder->folder_id,
			    b_normal, b_fai, b_sub, fdst->folder_id,
			    &b_collid, &b_partial))
				return ecError;
			if (b_collid)
				return ecDuplicateName;
			if (!fdst->set_properties(&propvals))
				return ecError;
			return ecSuccess;
		}
		if (!fdst->set_properties(&propvals))
			return ecError;
		return ecSuccess;
	}
	case zs_objtype::message: {
		auto mdst = static_cast<message_object *>(pobject_dst);
		if (!mdst->writable())
			return ecAccessDenied;
		if (!mdst->copy_to(static_cast<message_object *>(pobject),
		    pexclude_proptags, b_force, &b_cycle))
			return ecError;
		return b_cycle ? ecMsgCycle : ecSuccess;
	}
	case zs_objtype::attach: {
		auto adst = static_cast<attachment_object *>(pobject_dst);
		if (!adst->writable())
			return ecAccessDenied;
		if (!adst->copy_properties(static_cast<attachment_object *>(pobject),
		    pexclude_proptags, b_force, &b_cycle))
			return ecError;
		return b_cycle ? ecMsgCycle : ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

ec_error_t zs_savechanges(GUID hsession, uint32_t hobject)
{
	BOOL b_touched;
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pobject = pinfo->ptree->get_object<void>(hobject, &mapi_type);
	if (pobject == nullptr)
		return ecNullObject;
	if (mapi_type == zs_objtype::message) {
		auto msg = static_cast<message_object *>(pobject);
		if (!msg->writable())
			return ecAccessDenied;
		if (!msg->check_original_touched(&b_touched))
			return ecError;
		if (b_touched)
			return ecObjectModified;
		return msg->save();
	} else if (mapi_type == zs_objtype::attach) {
		auto atx = static_cast<attachment_object *>(pobject);
		if (!atx->writable())
			return ecAccessDenied;
		return atx->save();
	} else {
		return ecNotSupported;
	}
}

ec_error_t zs_hierarchysync(GUID hsession, uint32_t hfolder, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	auto hstore = pinfo->ptree->get_store_handle(pstore->b_private, pstore->account_id);
	if (hstore == INVALID_HANDLE)
		return ecNullObject;
	auto pctx = icsdownctx_object::create(pfolder, SYNC_TYPE_HIERARCHY);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsdownctx, std::move(pctx)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_contentsync(GUID hsession, uint32_t hfolder, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	auto hstore = pinfo->ptree->get_store_handle(pstore->b_private, pstore->account_id);
	if (hstore == INVALID_HANDLE)
		return ecNullObject;
	auto pctx = icsdownctx_object::create(pfolder, SYNC_TYPE_CONTENTS);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsdownctx, std::move(pctx)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_configsync(GUID hsession, uint32_t hctx, uint32_t flags,
    const BINARY *pstate, const RESTRICTION *prestriction, uint8_t *pb_changed,
    uint32_t *pcount)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsdownctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsdownctx)
		return ecNotSupported;
	BOOL b_changed = false;
	if (pctx->get_type() == SYNC_TYPE_CONTENTS) {
		if (!pctx->make_content(pstate, prestriction, flags, &b_changed, pcount))
			return ecError;
	} else {
		if (!pctx->make_hierarchy(pstate, flags, &b_changed, pcount))
			return ecError;
	}
	*pb_changed = !!b_changed;
	return ecSuccess;
}

ec_error_t zs_statesync(GUID hsession, uint32_t hctx, BINARY *pstate)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsdownctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsdownctx)
		return ecNotSupported;
	auto pbin = pctx->get_state();
	if (pbin == nullptr)
		return ecError;
	*pstate = *pbin;
	return ecSuccess;
}

ec_error_t zs_syncmessagechange(GUID hsession, uint32_t hctx,
    uint8_t *pb_new, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_found;
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsdownctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsdownctx || pctx->get_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	BOOL b_new = false;
	if (!pctx->sync_message_change(&b_found, &b_new, pproplist))
		return ecError;
	*pb_new = !!b_new;
	return b_found ? ecSuccess : ecNotFound;
}

ec_error_t zs_syncfolderchange(GUID hsession,
	uint32_t hctx, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_found;
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsdownctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsdownctx || pctx->get_type() != SYNC_TYPE_HIERARCHY)
		return ecNotSupported;
	if (!pctx->sync_folder_change(&b_found, pproplist))
		return ecError;
	return b_found ? ecSuccess : ecNotFound;
}

ec_error_t zs_syncreadstatechanges(GUID hsession, uint32_t hctx,
    STATE_ARRAY *pstates)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsdownctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsdownctx || pctx->get_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	return pctx->sync_readstates(pstates) ? ecSuccess : ecError;
}

ec_error_t zs_syncdeletions(GUID hsession,
	uint32_t hctx, uint32_t flags, BINARY_ARRAY *pbins)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsdownctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsdownctx)
		return ecNotSupported;
	return pctx->sync_deletions(flags, pbins) ? ecSuccess : ecError;
}

ec_error_t zs_hierarchyimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder || pfolder->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	auto hstore = pinfo->ptree->get_store_handle(pstore->b_private, pstore->account_id);
	if (hstore == INVALID_HANDLE)
		return ecNullObject;
	auto pctx = icsupctx_object::create(pfolder, SYNC_TYPE_HIERARCHY);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsupctx, std::move(pctx)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_contentimport(GUID hsession, uint32_t hfolder, uint32_t *phobject)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	auto hstore = pinfo->ptree->get_store_handle(pstore->b_private, pstore->account_id);
	if (hstore == INVALID_HANDLE)
		return ecNullObject;
	auto pctx = icsupctx_object::create(pfolder, SYNC_TYPE_CONTENTS);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsupctx, std::move(pctx)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_configimport(GUID hsession,
	uint32_t hctx, uint8_t sync_type, const BINARY *pstate)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsupctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsupctx)
		return ecNotSupported;
	return pctx->upload_state(pstate) ? ecSuccess : ecError;
}

ec_error_t zs_stateimport(GUID hsession, uint32_t hctx, BINARY *pstate)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsupctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsupctx)
		return ecNotSupported;
	auto pbin = pctx->get_state();
	if (pbin == nullptr)
		return ecError;
	*pstate = *pbin;
	return ecSuccess;
}

ec_error_t zs_importmessage(GUID hsession, uint32_t hctx,
	uint32_t flags, const TPROPVAL_ARRAY *pproplist, uint32_t *phobject)
{
	BOOL b_fai;
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_owner;
	zs_objtype mapi_type;
	uint64_t message_id;
	uint32_t permission = rightsNone, tag_access = 0;
	
	auto pbool = pproplist->get<const uint8_t>(PR_ASSOCIATED);
	if (pbool != nullptr) {
		b_fai = *pbool != 0 ? TRUE : false;
	} else {
		auto num = pproplist->get<const uint32_t>(PR_MESSAGE_FLAGS);
		b_fai = (num != nullptr && *num & MSGFLAG_ASSOCIATED) ? TRUE : false;
	}
	/*
	 * If there is no sourcekey, it is a new message. That is how
	 * grommunio-sync creates new items coming from mobile devices.
	 */
	auto pbin = pproplist->get<BINARY>(PR_SOURCE_KEY);
	if (pbin == nullptr)
		flags |= SYNC_NEW_MESSAGE;
	BOOL b_new = (flags & SYNC_NEW_MESSAGE) ? TRUE : false;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsupctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsupctx)
		return ecNotSupported;
	auto pstore = pctx->get_store();
	if (pctx->get_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	auto folder_id = pctx->get_parent_folder_id();
	if (!b_new) {
		pbin = pproplist->get<BINARY>(PR_SOURCE_KEY);
		if (pbin == nullptr || pbin->cb != 22)
			return ecInvalidParam;
		if (!common_util_binary_to_xid(pbin, &tmp_xid))
			return ecError;
		auto tmp_guid = pstore->guid();
		if (tmp_guid != tmp_xid.guid)
			return ecInvalidParam;
		message_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		if (!exmdb_client::check_message(pstore->get_dir(), folder_id,
		    message_id, &b_exist))
			return ecError;
		if (!b_exist)
			return ecNotFound;
	}
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (b_new) {
			if (!(permission & frightsCreate))
				return ecAccessDenied;
			tag_access = MAPI_ACCESS_READ;
			if (permission & (frightsEditAny | frightsEditOwned))
				tag_access |= MAPI_ACCESS_MODIFY;
			if (permission & (frightsDeleteAny | frightsDeleteOwned))
				tag_access |= MAPI_ACCESS_DELETE;
		} else if (permission & frightsOwner) {
			tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		} else {
			if (!exmdb_client_check_message_owner(pstore->get_dir(),
			    message_id, pinfo->get_username(), &b_owner))
				return ecError;
			if (b_owner || (permission & frightsReadAny))
				tag_access |= MAPI_ACCESS_READ;
			if ((permission & frightsEditAny) ||
			    (b_owner && (permission & frightsEditOwned)))
				tag_access |= MAPI_ACCESS_MODIFY;
			if ((permission & frightsDeleteAny) ||
			    (b_owner && (permission & frightsDeleteOwned)))
				tag_access |= MAPI_ACCESS_DELETE;
		}
	} else {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
	}
	if (!b_new) {
		void *pvalue = nullptr;
		if (!exmdb_client_get_message_property(pstore->get_dir(),
		    nullptr, 0, message_id, PR_ASSOCIATED, &pvalue))
			return ecError;
		bool orig_is_fai = pvb_enabled(pvalue);
		if (b_fai != orig_is_fai)
			return ecInvalidParam;
	} else {
		if (!exmdb_client::allocate_message_id(pstore->get_dir(),
		    folder_id, &message_id))
			return ecError;
	}
	auto pmessage = message_object::create(pstore, b_new, pinfo->cpid,
	                message_id, &folder_id, tag_access,
	                OPEN_MODE_FLAG_READWRITE, pctx->pstate);
	if (pmessage == nullptr)
		return ecError;
	if (b_new && pmessage->init_message(b_fai, pinfo->cpid) != 0)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hctx, {zs_objtype::message, std::move(pmessage)});
	if (*phobject == INVALID_HANDLE)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_importfolder(GUID hsession,
	uint32_t hctx, const TPROPVAL_ARRAY *ppropvals)
{
	XID tmp_xid;
	BOOL b_exist;
	BINARY *pbin;
	BOOL b_guest;
	BOOL b_found;
	void *pvalue;
	BOOL b_partial;
	uint64_t nttime;
	uint16_t replid;
	uint64_t tmp_fid;
	zs_objtype mapi_type;
	uint32_t tmp_type;
	uint64_t folder_id;
	uint64_t parent_id1;
	uint64_t change_num;
	uint32_t permission;
	TPROPVAL_ARRAY *pproplist;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[4];
	TPROPVAL_ARRAY hierarchy_propvals;
	
	pproplist = &hierarchy_propvals;
	hierarchy_propvals.count = 4;
	hierarchy_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PR_PARENT_SOURCE_KEY;
	propval_buff[0].pvalue = ppropvals->getval(PR_PARENT_SOURCE_KEY);
	if (propval_buff[0].pvalue == nullptr)
		return ecInvalidParam;
	propval_buff[1].proptag = PR_SOURCE_KEY;
	propval_buff[1].pvalue = ppropvals->getval(PR_SOURCE_KEY);
	if (propval_buff[1].pvalue == nullptr)
		return ecInvalidParam;
	propval_buff[2].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[2].pvalue = ppropvals->getval(PR_LAST_MODIFICATION_TIME);
	if (NULL == propval_buff[2].pvalue) {
		propval_buff[2].pvalue = &nttime;
		nttime = rop_util_current_nttime();
	}
	propval_buff[3].proptag = PR_DISPLAY_NAME;
	propval_buff[3].pvalue = ppropvals->getval(PR_DISPLAY_NAME);
	if (propval_buff[3].pvalue == nullptr)
		return ecInvalidParam;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsupctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsupctx)
		return ecNotSupported;
	auto pstore = pctx->get_store();
	if (pctx->get_type() != SYNC_TYPE_HIERARCHY)
		return ecNotSupported;
	if (static_cast<BINARY *>(pproplist->ppropval[0].pvalue)->cb == 0) {
		parent_id1 = pctx->get_parent_folder_id();
		if (!exmdb_client::check_folder_id(pstore->get_dir(),
		    parent_id1, &b_exist))
			return ecError;
		if (!b_exist)
			return SYNC_E_NO_PARENT;
	} else {
		pbin = static_cast<BINARY *>(pproplist->ppropval[0].pvalue);
		if (pbin == nullptr || pbin->cb != 22)
			return ecInvalidParam;
		if (!common_util_binary_to_xid(pbin, &tmp_xid))
			return ecError;
		if (pstore->b_private) {
			auto tmp_guid = rop_util_make_user_guid(pstore->account_id);
			if (tmp_guid != tmp_xid.guid)
				return ecInvalidParam;
		} else {
			auto tmp_guid = rop_util_make_domain_guid(pstore->account_id);
			if (tmp_guid != tmp_xid.guid)
				return ecAccessDenied;
		}
		parent_id1 = rop_util_make_eid(1, tmp_xid.local_to_gc());
		if (!exmdb_client_get_folder_property(pstore->get_dir(), 0,
		    parent_id1, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (pvalue == nullptr)
			return SYNC_E_NO_PARENT;
	}
	pbin = static_cast<BINARY *>(pproplist->ppropval[1].pvalue);
	if (pbin == nullptr || pbin->cb != 22)
		return ecInvalidParam;
	if (!common_util_binary_to_xid(pbin, &tmp_xid))
		return ecError;
	if (pstore->b_private) {
		auto tmp_guid = rop_util_make_user_guid(pstore->account_id);
		if (tmp_guid != tmp_xid.guid)
			return ecInvalidParam;
		folder_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
	} else {
		auto tmp_guid = rop_util_make_domain_guid(pstore->account_id);
		if (tmp_guid != tmp_xid.guid) {
			auto domain_id = rop_util_get_domain_id(tmp_xid.guid);
			if (domain_id == -1)
				return ecInvalidParam;
			if (!system_services_check_same_org(domain_id, pstore->account_id))
				return ecInvalidParam;
			if (!exmdb_client::get_mapping_replid(pstore->get_dir(),
			    tmp_xid.guid, &b_found, &replid))
				return ecError;
			if (!b_found)
				return ecInvalidParam;
			folder_id = rop_util_make_eid(replid, tmp_xid.local_to_gc());
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		}
	}
	if (!exmdb_client::check_folder_id(pstore->get_dir(), folder_id, &b_exist))
		return ecError;
	if (!b_exist) {
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    parent_id1, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsCreateSubfolder))
				return ecAccessDenied;
		}
		if (!exmdb_client::get_folder_by_name(pstore->get_dir(),
		    parent_id1, static_cast<char *>(pproplist->ppropval[3].pvalue),
		    &tmp_fid))
			return ecError;
		if (tmp_fid != 0)
			return ecDuplicateName;
		if (!exmdb_client::allocate_cn(pstore->get_dir(), &change_num))
			return ecError;
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8 + ppropvals->count);
		if (tmp_propvals.ppropval == nullptr)
			return ecError;
		tmp_propvals.ppropval[0].proptag = PidTagFolderId;
		tmp_propvals.ppropval[0].pvalue = &folder_id;
		tmp_propvals.ppropval[1].proptag = PidTagParentFolderId;
		tmp_propvals.ppropval[1].pvalue = &parent_id1;
		tmp_propvals.ppropval[2].proptag = PR_LAST_MODIFICATION_TIME;
		tmp_propvals.ppropval[2].pvalue = pproplist->ppropval[2].pvalue;
		tmp_propvals.ppropval[3].proptag = PR_DISPLAY_NAME;
		tmp_propvals.ppropval[3].pvalue = pproplist->ppropval[3].pvalue;
		tmp_propvals.ppropval[4].proptag = PidTagChangeNumber;
		tmp_propvals.ppropval[4].pvalue = &change_num;
		tmp_propvals.count = 5;
		for (size_t i = 0; i < ppropvals->count; ++i)
			tmp_propvals.ppropval[tmp_propvals.count++] = ppropvals->ppropval[i];
		if (!tmp_propvals.has(PR_FOLDER_TYPE)) {
			tmp_type = FOLDER_GENERIC;
			tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_FOLDER_TYPE;
			tmp_propvals.ppropval[tmp_propvals.count++].pvalue = &tmp_type;
		}
		if (!exmdb_client::create_folder_by_properties(pstore->get_dir(),
		    pinfo->cpid, &tmp_propvals, &tmp_fid) || folder_id != tmp_fid)
			return ecError;
		pctx->pstate->pseen->append(change_num);
		return ecSuccess;
	}
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (!exmdb_client_get_folder_property(pstore->get_dir(), 0, folder_id,
	    PidTagParentFolderId, &pvalue) || pvalue == nullptr)
		return ecError;
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (!pstore->b_private)
			return ecNotSupported;
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM)
			return ecAccessDenied;
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    parent_id1, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsCreateSubfolder))
				return ecAccessDenied;
			b_guest = TRUE;
		} else {
			b_guest = FALSE;
		}
		if (!exmdb_client::movecopy_folder(pstore->get_dir(),
		    pstore->account_id, pinfo->cpid, b_guest,
		    pinfo->get_username(), parent_id, folder_id, parent_id1,
		    static_cast<char *>(pproplist->ppropval[3].pvalue), false,
		    &b_exist, &b_partial))
			return ecError;
		if (b_exist)
			return ecDuplicateName;
		if (b_partial)
			return ecError;
	}
	if (!exmdb_client::allocate_cn(pstore->get_dir(), &change_num))
		return ecError;
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5 + ppropvals->count);
	if (tmp_propvals.ppropval == nullptr)
		return ecError;
	tmp_propvals.ppropval[0].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[0].pvalue = pproplist->ppropval[2].pvalue;
	tmp_propvals.ppropval[1].proptag = PR_DISPLAY_NAME;
	tmp_propvals.ppropval[1].pvalue = pproplist->ppropval[3].pvalue;
	tmp_propvals.ppropval[2].proptag = PidTagChangeNumber;
	tmp_propvals.ppropval[2].pvalue = &change_num;
	tmp_propvals.count = 3;
	for (size_t i = 0; i < ppropvals->count; ++i)
		tmp_propvals.ppropval[tmp_propvals.count++] = ppropvals->ppropval[i];
	if (!exmdb_client::set_folder_properties(pstore->get_dir(),
	    pinfo->cpid, folder_id, &tmp_propvals, &tmp_problems))
		return ecError;
	pctx->pstate->pseen->append(change_num);
	return ecSuccess;
}

ec_error_t zs_importdeletion(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins)
{
	XID tmp_xid;
	void *pvalue;
	BOOL b_exist;
	BOOL b_found;
	uint64_t eid;
	BOOL b_owner;
	BOOL b_result;
	BOOL b_partial;
	uint16_t replid;
	zs_objtype mapi_type;
	uint32_t permission;
	EID_ARRAY message_ids;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsupctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsupctx)
		return ecNotSupported;
	auto pstore = pctx->get_store();
	auto sync_type = pctx->get_type();
	BOOL b_hard = (flags & SYNC_DELETES_FLAG_HARDDELETE) ? TRUE : false;
	if (flags & SYNC_DELETES_FLAG_HIERARCHY &&
	    sync_type == SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	auto folder_id = pctx->get_parent_folder_id();
	auto username = pinfo->get_username();
	if (pstore->owner_mode()) {
		username = NULL;
	} else if (sync_type == SYNC_TYPE_CONTENTS &&
	    !exmdb_client::get_folder_perm(pstore->get_dir(),
	    folder_id, pinfo->get_username(), &permission)) {
		if (permission & (frightsOwner | frightsDeleteAny))
			username = NULL;
		else if (!(permission & frightsDeleteOwned))
			return ecAccessDenied;
	}
	if (SYNC_TYPE_CONTENTS == sync_type) {
		message_ids.count = 0;
		message_ids.pids = cu_alloc<uint64_t>(pbins->count);
		if (message_ids.pids == nullptr)
			return ecError;
	}
	for (size_t i = 0; i < pbins->count; ++i) {
		if (pbins->pbin[i].cb != 22)
			return ecInvalidParam;
		if (!common_util_binary_to_xid(&pbins->pbin[i], &tmp_xid))
			return ecError;
		if (pstore->b_private) {
			auto tmp_guid = rop_util_make_user_guid(pstore->account_id);
			if (tmp_guid != tmp_xid.guid)
				return ecInvalidParam;
			eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
		} else if (sync_type == SYNC_TYPE_CONTENTS) {
			auto tmp_guid = rop_util_make_domain_guid(pstore->account_id);
			if (tmp_guid != tmp_xid.guid)
				return ecInvalidParam;
			eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
		} else {
			auto tmp_guid = rop_util_make_domain_guid(pstore->account_id);
			if (tmp_guid != tmp_xid.guid) {
				auto domain_id = rop_util_get_domain_id(tmp_xid.guid);
				if (domain_id == -1)
					return ecInvalidParam;
				if (!system_services_check_same_org(domain_id,
				    pstore->account_id))
					return ecInvalidParam;
				if (!exmdb_client::get_mapping_replid(pstore->get_dir(),
				    tmp_xid.guid, &b_found, &replid))
					return ecError;
				if (!b_found)
					return ecInvalidParam;
				eid = rop_util_make_eid(replid, tmp_xid.local_to_gc());
			} else {
				eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (!exmdb_client::check_message(pstore->get_dir(),
			    folder_id, eid, &b_exist))
				return ecError;
		} else {
			if (!exmdb_client::check_folder_id(pstore->get_dir(),
			    eid, &b_exist))
				return ecError;
		}
		if (!b_exist)
			continue;
		if (NULL != username) {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				if (!exmdb_client_check_message_owner(pstore->get_dir(),
				    eid, username, &b_owner))
					return ecError;
				if (!b_owner)
					return ecAccessDenied;
			} else if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    eid, username, &permission) && !(permission & frightsOwner)) {
				return ecAccessDenied;
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			message_ids.pids[message_ids.count++] = eid;
		} else {
			if (pstore->b_private) {
				if (!exmdb_client_get_folder_property(pstore->get_dir(),
				    0, eid, PR_FOLDER_TYPE, &pvalue))
					return ecError;
				if (pvalue == nullptr)
					return ecSuccess;
				if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
					goto DELETE_FOLDER;
			}
			if (!exmdb_client::empty_folder(pstore->get_dir(),
			    pinfo->cpid, username, eid, b_hard, TRUE, TRUE, TRUE,
			    &b_partial) || b_partial)
				return ecError;
 DELETE_FOLDER:
			if (!exmdb_client::delete_folder(pstore->get_dir(),
			    pinfo->cpid, eid, b_hard, &b_result) || !b_result)
				return ecError;
		}
	}
	if (sync_type == SYNC_TYPE_CONTENTS && message_ids.count > 0 &&
	    (!exmdb_client::delete_messages(pstore->get_dir(),
	    pstore->account_id, pinfo->cpid, nullptr,
	    folder_id, &message_ids, b_hard, &b_partial) || b_partial))
		return ecError;
	return ecSuccess;
}

ec_error_t zs_importreadstates(GUID hsession,
	uint32_t hctx, const STATE_ARRAY *pstates)
{
	XID tmp_xid;
	BOOL b_owner;
	uint64_t read_cn;
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pctx = pinfo->ptree->get_object<icsupctx_object>(hctx, &mapi_type);
	if (pctx == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::icsupctx)
		return ecNotSupported;
	auto pstore = pctx->get_store();
	if (pctx->get_type() != SYNC_TYPE_CONTENTS)
		return ecNotSupported;
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		folder_id = pctx->get_parent_folder_id();
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsReadAny))
			username = pinfo->get_username();
	}
	for (size_t i = 0; i < pstates->count; ++i) {
		if (!common_util_binary_to_xid(
		    &pstates->pstate[i].source_key, &tmp_xid))
			return ecNotSupported;
		auto tmp_guid = pstore->guid();
		if (tmp_guid != tmp_xid.guid)
			continue;
		auto message_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		bool mark_as_read = pstates->pstate[i].message_flags & MSGFLAG_READ;
		if (NULL != username) {
			if (!exmdb_client_check_message_owner(pstore->get_dir(),
			    message_id, username, &b_owner))
				return ecError;
			if (!b_owner)
				continue;
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PR_ASSOCIATED;
		proptag_buff[1] = PR_READ;
		if (!exmdb_client::get_message_properties(pstore->get_dir(),
		    nullptr, 0, message_id, &tmp_proptags, &tmp_propvals))
			return ecError;
		auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
		if (flag != nullptr && *flag != 0)
			continue;
		flag = tmp_propvals.get<uint8_t>(PR_READ);
		if ((flag != nullptr && *flag != 0) == mark_as_read)
			/* Already set to the value we want it to be */
			continue;
		if (!exmdb_client::set_message_read_state(pstore->get_dir(),
		    pstore->b_private ? nullptr : pinfo->get_username(),
		    message_id, mark_as_read, &read_cn))
			return ecError;
		pctx->pstate->pread->append(read_cn);
	}
	return ecSuccess;
}

ec_error_t zs_getsearchcriteria(GUID hsession,
	uint32_t hfolder, BINARY_ARRAY *pfolder_array,
	RESTRICTION **pprestriction, uint32_t *psearch_stat)
{
	zs_objtype mapi_type;
	LONGLONG_ARRAY folder_ids;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	if (pfolder->type != FOLDER_SEARCH)
		return ecNotSearchFolder;
	if (!exmdb_client::get_search_criteria(pstore->get_dir(),
	    pfolder->folder_id, psearch_stat, pprestriction, &folder_ids))
		return ecError;
	pfolder_array->count = folder_ids.count;
	if (0 == folder_ids.count) {
		pfolder_array->pbin = NULL;
		return ecSuccess;
	}
	pfolder_array->pbin = cu_alloc<BINARY>(folder_ids.count);
	if (pfolder_array->pbin == nullptr)
		return ecError;
	for (size_t i = 0; i < folder_ids.count; ++i) {
		auto pbin = cu_fid_to_entryid(pstore, folder_ids.pll[i]);
		if (pbin == nullptr)
			return ecError;
		pfolder_array->pbin[i] = *pbin;
	}
	return ecSuccess;
}

ec_error_t zs_setsearchcriteria(GUID hsession, uint32_t hfolder, uint32_t flags,
    const BINARY_ARRAY *pfolder_array, const RESTRICTION *prestriction)
{
	int db_id;
	BOOL b_result;
	BOOL b_private;
	zs_objtype mapi_type;
	uint32_t permission;
	uint32_t search_status;
	LONGLONG_ARRAY folder_ids;
	
	if (!(flags & (RESTART_SEARCH | STOP_SEARCH)))
		/* make the default search_flags */
		flags |= RESTART_SEARCH;
	if (!(flags & (RECURSIVE_SEARCH | SHALLOW_SEARCH)))
		/* make the default search_flags */
		flags |= SHALLOW_SEARCH;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pfolder = pinfo->ptree->get_object<folder_object>(hfolder, &mapi_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto pstore = pfolder->pstore;
	if (!pstore->b_private)
		return ecNotSupported;
	if (!pstore->owner_mode()) {
		if (!exmdb_client::get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (NULL == prestriction || 0 == pfolder_array->count) {
		if (!exmdb_client::get_search_criteria(pstore->get_dir(),
		    pfolder->folder_id, &search_status, nullptr, nullptr))
			return ecError;
		if (search_status == SEARCH_STATUS_NOT_INITIALIZED)
			return ecNotInitialized;
		if (!(flags & RESTART_SEARCH) && prestriction == nullptr &&
		    pfolder_array->count == 0)
			return ecSuccess;
	}
	folder_ids.count = pfolder_array->count;
	folder_ids.pll   = cu_alloc<uint64_t>(folder_ids.count);
	if (folder_ids.pll == nullptr)
		return ecError;
	for (size_t i = 0; i < pfolder_array->count; ++i) {
		if (!cu_entryid_to_fid(pfolder_array->pbin[i],
		    &b_private, &db_id, &folder_ids.pll[i]))
			return ecError;
		if (!b_private || db_id != pstore->account_id)
			return ecSearchFolderScopeViolation;
		if (!pstore->owner_mode()) {
			if (!exmdb_client::get_folder_perm(pstore->get_dir(),
			    folder_ids.pll[i], pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & (frightsOwner | frightsReadAny)))
				return ecAccessDenied;
		}
	}
	if (!exmdb_client::set_search_criteria(pstore->get_dir(), pinfo->cpid,
	    pfolder->folder_id, flags, prestriction, &folder_ids, &b_result))
		return ecError;
	return b_result ? ecSuccess : ecSearchFolderScopeViolation;
}

ec_error_t zs_messagetorfc822(GUID hsession, uint32_t hmessage, BINARY *peml_bin)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	return common_util_message_to_rfc822(pmessage->get_store(),
	       pmessage->get_id(), peml_bin) ? ecSuccess : ecError;
}

ec_error_t zs_rfc822tomessage(GUID hsession, uint32_t hmessage,
    uint32_t mxf_flags, /* effective-moved-from */ BINARY *peml_bin)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto pmsgctnt = cu_rfc822_to_message(pmessage->get_store(), mxf_flags, peml_bin);
	if (pmsgctnt == nullptr)
		return ecError;
	return pmessage->write_message(pmsgctnt) ? ecSuccess : ecError;
}

ec_error_t zs_messagetoical(GUID hsession, uint32_t hmessage, BINARY *pical_bin)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	return common_util_message_to_ical(pmessage->get_store(),
	       pmessage->get_id(), pical_bin) ? ecSuccess : ecError;
}

ec_error_t zs_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto pmsgctnt = cu_ical_to_message(pmessage->get_store(), pical_bin);
	if (pmsgctnt == nullptr)
		return ecError;
	return pmessage->write_message(pmsgctnt.get()) ? ecSuccess : ecError;
}

ec_error_t zs_imtomessage2(GUID session, uint32_t fld_handle,
    uint32_t data_type, char *im_data, LONG_ARRAY *outhandles)
{
	auto info = zs_query_session(session);
	if (info == nullptr)
		return ecError;
	zs_objtype mapi_type;
	auto fld = info->ptree->get_object<folder_object>(fld_handle, &mapi_type);
	if (fld == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	std::vector<message_ptr> msgvec;
	ec_error_t ret = ecInvalidParam;
	if (data_type == IMTOMESSAGE_ICAL)
		ret = cu_ical_to_message2(fld->pstore, im_data, msgvec);
	else if (data_type == IMTOMESSAGE_VCARD)
		ret = cu_vcf_to_message2(fld->pstore, im_data, msgvec);
	if (ret != ecSuccess)
		return ret;

	outhandles->count = 0;
	outhandles->pl = cu_alloc<uint32_t>(msgvec.size());
	if (outhandles->pl == nullptr)
		return ecServerOOM;
	auto cl_0 = make_scope_exit([&]() {
		for (size_t i = 0; i < outhandles->count; ++i)
			zs_unloadobject(session, outhandles->pl[i]);
	});
	for (auto &&msgctnt : msgvec) {
		uint32_t msg_handle = 0;
		auto rt2 = zs_createmessage(session, fld_handle,
		           0, &msg_handle);
		if (rt2 != ecSuccess)
			return rt2;
		auto zmo = info->ptree->get_object<message_object>(msg_handle, &mapi_type);
		if (zmo == nullptr || mapi_type != zs_objtype::message ||
		    !zmo->write_message(msgctnt.get()))
			return ecError;
		outhandles->pl[outhandles->count++] = msg_handle;
	}
	cl_0.release();
	return ecSuccess;
}

ec_error_t zs_messagetovcf(GUID hsession, uint32_t hmessage, BINARY *pvcf_bin)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	return common_util_message_to_vcf(pmessage, pvcf_bin) ? ecSuccess : ecError;
}

ec_error_t zs_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto pmessage = pinfo->ptree->get_object<message_object>(hmessage, &mapi_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::message)
		return ecNotSupported;
	auto pmsgctnt = common_util_vcf_to_message(pmessage->get_store(), pvcf_bin);
	if (pmsgctnt == nullptr)
		return ecError;
	return pmessage->write_message(pmsgctnt) ? ecSuccess : ecError;
}

ec_error_t zs_getuseravailability(GUID hsession, BINARY entryid,
    uint64_t starttime, uint64_t endtime, char **ppresult_string)
{
	pid_t pid;
	int status;
	int offset;
	int tmp_len;
	char *ptoken;
	char* argv[3];
	char maildir[256];
	char username[UADDR_SIZE];
	char tool_path[256];
	char cookie_buff[1024];
	int pipes_in[2] = {-1, -1};
	int pipes_out[2] = {-1, -1};
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	if (!common_util_addressbook_entryid_to_username(entryid,
	    username, GX_ARRAY_SIZE(username)) ||
	    !system_services_get_maildir(username, maildir, arsizeof(maildir))) {
		*ppresult_string = NULL;
		return ecSuccess;
	}
	if (strcasecmp(pinfo->get_username(), username) == 0)
		tmp_len = gx_snprintf(cookie_buff, GX_ARRAY_SIZE(cookie_buff),
		          "starttime=%llu;endtime=%llu;dirs=1;dir0=%s",
		          LLU{starttime}, LLU{endtime}, maildir);
	else
		tmp_len = gx_snprintf(cookie_buff, GX_ARRAY_SIZE(cookie_buff),
		          "username=%s;starttime=%llu;endtime=%llu;dirs=1;dir0=%s",
		          pinfo->get_username(),
		          LLU{starttime}, LLU{endtime}, maildir);
	pinfo.reset();
	if (pipe(pipes_in) < 0)
		return ecError;
	if (-1 == pipe(pipes_out)) {
		close(pipes_in[0]);
		close(pipes_in[1]);
		return ecError;
	}
	pid = fork();
	if (0 == pid) {
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(0);
		close(1);
		dup2(pipes_in[0], 0);
		dup2(pipes_out[1], 1);
		close(pipes_in[0]);
		close(pipes_out[1]);
		strcpy(tool_path, common_util_get_freebusy_path());
		ptoken = strrchr(tool_path, '/');
		if (ptoken != nullptr)
			++ptoken;
		argv[0] = ptoken;
		argv[1] = NULL;
		execve(tool_path, argv, NULL);
		_exit(-1);
	} else if (pid < 0) {
		close(pipes_in[0]);
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(pipes_out[1]);
		return ecError;
	}
	close(pipes_in[0]);
	close(pipes_out[1]);
	write(pipes_in[1], cookie_buff, tmp_len);
	close(pipes_in[1]);
	*ppresult_string = cu_alloc<char>(1024 * 1024);
	if (NULL == *ppresult_string) {
		waitpid(pid, &status, 0);
		return ecError;
	}
	offset = 0;
	while ((tmp_len = read(pipes_out[0], *ppresult_string
		+ offset, 1024*1024 - offset)) > 0) {
		offset += tmp_len;
		if (offset >= 1024*1024) {
			waitpid(pid, &status, 0);
			close(pipes_out[0]);
			return ecError;
		}
	}
	(*ppresult_string)[offset] = '\0';
	close(pipes_out[0]);
	waitpid(pid, &status, 0);
	return status == 0 ? ecSuccess : ecError;
}

ec_error_t zs_setpasswd(const char *username,
	const char *passwd, const char *new_passwd)
{
	return system_services_setpasswd(username, passwd, new_passwd) ?
	       ecSuccess : ecAccessDenied;
}

ec_error_t zs_linkmessage(GUID hsession,
	BINARY search_entryid, BINARY message_entryid)
{
	uint32_t cpid;
	BOOL b_result;
	BOOL b_private;
	BOOL b_private1;
	char maildir[256];
	zs_objtype mapi_type;
	uint64_t folder_id;
	uint64_t folder_id1;
	uint64_t message_id;
	uint32_t account_id;
	uint32_t account_id1;
	
	if (common_util_get_messaging_entryid_type(search_entryid) != EITLT_PRIVATE_FOLDER ||
	    !cu_entryid_to_fid(search_entryid, &b_private,
	    reinterpret_cast<int *>(&account_id), &folder_id) ||
	    b_private != TRUE)
		return ecInvalidParam;
	if (common_util_get_messaging_entryid_type(message_entryid) != EITLT_PRIVATE_MESSAGE ||
	    !cu_entryid_to_mid(message_entryid, &b_private1,
	    reinterpret_cast<int *>(&account_id1), &folder_id1, &message_id) ||
	    b_private1 != TRUE || account_id != account_id1)
		return ecInvalidParam;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto handle = pinfo->ptree->get_store_handle(b_private, account_id);
	if (handle == INVALID_HANDLE)
		return ecNullObject;
	if (pinfo->user_id < 0)
		return ecAccessDenied;
	auto pstore = pinfo->ptree->get_object<store_object>(handle, &mapi_type);
	if (pstore == nullptr || mapi_type != zs_objtype::store)
		return ecError;
	if (!pstore->owner_mode()) {
		uint32_t permission = rightsNone;
		if (!exmdb_client::get_folder_perm(pstore->get_dir(), folder_id,
		    pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
	}
	gx_strlcpy(maildir, pstore->get_dir(), arsizeof(maildir));
	cpid = pinfo->cpid;
	pinfo.reset();
	return exmdb_client::link_message(maildir, cpid, folder_id, message_id,
	       &b_result) && b_result ? ecSuccess : ecError;
}
