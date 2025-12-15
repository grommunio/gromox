// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
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
#include <libHX/io.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <gromox/ab_tree.hpp>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/freebusy.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/notify_types.hpp>
#include <gromox/process.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/safeint.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include <gromox/zcore_rpc.hpp>
#include <gromox/zcore_types.hpp>
#include "ab_tree.hpp"
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "ics_state.hpp"
#include "object_tree.hpp"
#include "objects.hpp"
#include "rpc_ext.hpp"
#include "rpc_parser.hpp"
#include "store_object.hpp"
#include "system_services.hpp"
#include "table_object.hpp"
#include "zserver.hpp"

using namespace std::string_literals;
using namespace gromox;
using LLU = unsigned long long;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

namespace {

struct NOTIFY_ITEM {
	NOTIFY_ITEM(const GUID &ses, uint32_t store) :
		hsession(ses), hstore(store), last_time(time(nullptr))
	{}

	std::vector<ZNOTIFICATION> notify_list;
	GUID hsession{};
	uint32_t hstore = 0;
	time_t last_time = 0;
};

}

static size_t g_table_size;
static gromox::atomic_bool g_zserver_stop;
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
	org_id(o.org_id), privbits(o.privbits),
	username(std::move(o.username)),
	lang(std::move(o.lang)), maildir(std::move(o.maildir)),
	homedir(std::move(o.homedir)), cpid(o.cpid),
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

USER_INFO_REF zs_query_session(GUID hsession)
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
	pinfo->last_time = time(nullptr);
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

static void *zcorezs_scanwork(void *param)
{
	int count;
	BINARY tmp_bin;
	uint8_t tmp_byte;
	struct pollfd fdpoll;
	
	count = 0;
	zcresp_notifdequeue response{};
	response.call_id = zcore_callid::notifdequeue;
	response.result = ecSuccess;
	while (!g_zserver_stop) {
		sleep(1);
		count ++;
		if (count >= g_ping_interval)
			count = 0;
		std::vector<std::string> maildir_list;
		std::list<sink_node> expired_list;
		std::unique_lock tl_hold(g_table_lock);
		auto cur_time = time(nullptr);
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
			exmdb_client->ping_store(dir.c_str());
			common_util_free_environment();
		}
		maildir_list.clear();
		while (expired_list.size() > 0) {
			std::list<sink_node> holder;
			holder.splice(holder.end(), expired_list, expired_list.begin());
			auto psink_node = &holder.front();
			/* implied ~sink_node at end of scope */
			if (rpc_ext_push_response(&response, &tmp_bin) != pack_result::ok)
				continue;
			fdpoll.fd = psink_node->clifd;
			fdpoll.events = POLLOUT|POLLWRBAND;
			if (tmp_bin.pb != nullptr &&
			    poll(&fdpoll, 1, SOCKET_TIMEOUT * 1000) == 1 &&
			    write(psink_node->clifd, tmp_bin.pb, tmp_bin.cb) < 0)
				/* ignore */;
			free(tmp_bin.pb);
			tmp_bin.pb = nullptr;
			shutdown(psink_node->clifd, SHUT_WR);
			if (read(psink_node->clifd, &tmp_byte, 1))
				/* ignore */;
		}
		if (count != 0)
			continue;
		cur_time = time(nullptr);
		std::unique_lock nl_hold(g_notify_lock);
		std::erase_if(g_notify_table, [=](const auto &it) {
			return cur_time - it.second.last_time >= g_cache_interval;
		});
	}
	return NULL;
}

void zs_notification_proc(const char *dir, BOOL b_table, uint32_t notify_id,
    const DB_NOTIFY *pdb_notify) try
{
	int i;
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
	TPROPVAL_ARRAY propvals;
	
	if (b_table)
		return;
	snprintf(tmp_buff, std::size(tmp_buff), "%u|%s", notify_id, dir);
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

	ZNOTIFICATION zn, *pnotification = &zn, *pnew_mail = &zn, *oz = &zn;
	switch (pdb_notify->type) {
	case db_notify_type::new_mail: {
		pnotification->event_type = fnevNewMail;
		auto nt = std::any_cast<const DB_NOTIFY_NEW_MAIL>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pnew_mail->pentryid = cu_mid_to_entryid_s(*pstore, folder_id, message_id);
		if (pnew_mail->pentryid->empty())
			return;
		pnew_mail->pparentid = cu_fid_to_entryid_s(*pstore, folder_id);
		if (pnew_mail->pparentid->empty())
			return;
		static constexpr proptag_t proptag_buff[] = {PR_MESSAGE_CLASS, PR_MESSAGE_FLAGS};
		static constexpr PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
		if (!exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
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
	case db_notify_type::folder_created: {
		pnotification->event_type = fnevObjectCreated;
		auto nt = std::any_cast<const DB_NOTIFY_FOLDER_CREATED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		parent_id = rop_util_nfid_to_eid(nt->parent_id);
		oz->object_type = MAPI_FOLDER;
		oz->pentryid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, parent_id));
		if (oz->pparentid->empty())
			return;
		break;
	}
	case db_notify_type::message_created: {
		pnotification->event_type = fnevObjectCreated;
		auto nt = std::any_cast<const DB_NOTIFY_MESSAGE_CREATED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		oz->object_type = MAPI_MESSAGE;
		oz->pentryid.emplace(cu_mid_to_entryid_s(*pstore, folder_id, message_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pparentid->empty())
			return;
		break;
	}
	case db_notify_type::folder_deleted: {
		pnotification->event_type = fnevObjectDeleted;
		auto nt = std::any_cast<const DB_NOTIFY_FOLDER_DELETED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		parent_id = rop_util_nfid_to_eid(nt->parent_id);
		oz->object_type = MAPI_FOLDER;
		oz->pentryid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, parent_id));
		if (oz->pparentid->empty())
			return;
		break;
	}
	case db_notify_type::message_deleted: {
		pnotification->event_type = fnevObjectDeleted;
		auto nt = std::any_cast<const DB_NOTIFY_MESSAGE_DELETED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		oz->object_type = MAPI_MESSAGE;
		oz->pentryid.emplace(cu_mid_to_entryid_s(*pstore, folder_id, message_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pparentid->empty())
			return;
		break;
	}
	case db_notify_type::folder_modified: {
		pnotification->event_type = fnevObjectModified;
		auto nt = std::any_cast<const DB_NOTIFY_FOLDER_MODIFIED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		oz->object_type = MAPI_FOLDER;
		oz->pentryid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pentryid->empty())
			return;
		break;
	}
	case db_notify_type::message_modified: {
		pnotification->event_type = fnevObjectModified;
		auto nt = std::any_cast<const DB_NOTIFY_MESSAGE_MODIFIED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		oz->object_type = MAPI_MESSAGE;
		oz->pentryid.emplace(cu_mid_to_entryid_s(*pstore, folder_id, message_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pparentid->empty())
			return;
		break;
	}
	case db_notify_type::folder_moved:
	case db_notify_type::folder_copied: {
		pnotification->event_type = pdb_notify->type == db_notify_type::folder_moved ?
		                            fnevObjectMoved : fnevObjectCopied;
		auto nt = std::any_cast<const DB_NOTIFY_FOLDER_MVCP>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		parent_id = rop_util_nfid_to_eid(nt->parent_id);
		old_eid = rop_util_nfid_to_eid(nt->old_folder_id);
		old_parentid = rop_util_nfid_to_eid(nt->old_parent_id);
		oz->object_type = MAPI_FOLDER;
		oz->pentryid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, parent_id));
		if (oz->pparentid->empty())
			return;
		oz->pold_entryid.emplace(cu_fid_to_entryid_s(*pstore, old_eid));
		if (oz->pold_entryid->empty())
			return;
		oz->pold_parentid.emplace(cu_fid_to_entryid_s(*pstore, old_parentid));
		if (oz->pold_parentid->empty())
			return;
		break;
	}
	case db_notify_type::message_moved:
	case db_notify_type::message_copied: {
		pnotification->event_type = pdb_notify->type == db_notify_type::message_moved ?
		                            fnevObjectMoved : fnevObjectCopied;
		auto nt = std::any_cast<const DB_NOTIFY_MESSAGE_MVCP>(&pdb_notify->pdata);
		old_parentid = rop_util_nfid_to_eid(nt->old_folder_id);
		old_eid = rop_util_make_eid_ex(1, nt->old_message_id);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		oz->object_type = MAPI_MESSAGE;
		oz->pentryid.emplace(cu_mid_to_entryid_s(*pstore, folder_id, message_id));
		if (oz->pentryid->empty())
			return;
		oz->pparentid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pparentid->empty())
			return;
		oz->pold_entryid.emplace(cu_mid_to_entryid_s(*pstore, old_parentid, old_eid));
		if (oz->pold_entryid->empty())
			return;
		oz->pold_parentid.emplace(cu_fid_to_entryid_s(*pstore, old_parentid));
		if (oz->pold_parentid->empty())
			return;
		break;
	}
	case db_notify_type::search_completed: {
		pnotification->event_type = fnevSearchComplete;
		auto nt = std::any_cast<const DB_NOTIFY_SEARCH_COMPLETED>(&pdb_notify->pdata);
		folder_id = rop_util_nfid_to_eid(nt->folder_id);
		oz->object_type = MAPI_FOLDER;
		oz->pentryid.emplace(cu_fid_to_entryid_s(*pstore, folder_id));
		if (oz->pentryid->empty())
			return;
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
			zcresp_notifdequeue response{};
			response.call_id = zcore_callid::notifdequeue;
			response.result  = ecSuccess;
			response.notifications.emplace_back(std::move(zn));

			fdpoll.fd = psink_node->clifd;
			fdpoll.events = POLLOUT | POLLWRBAND;
			if (rpc_ext_push_response(&response, &tmp_bin) != pack_result::ok) {
				auto tmp_byte = zcore_response::push_error;
				if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1 &&
				    HXio_fullwrite(psink_node->clifd, &tmp_byte, 1) != 1)
					/* ignore */;
			} else {
				if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1) {
					auto ret = HXio_fullwrite(psink_node->clifd, tmp_bin.pb, tmp_bin.cb);
					if (ret < 0 || static_cast<size_t>(ret) != tmp_bin.cb)
						/* ignore */;
				}
				free(tmp_bin.pb);
			}
			/* implied ~sink_node */
			return;
		}
	}
	nl_hold.lock();
	iter = g_notify_table.find(tmp_buff);
	if (iter != g_notify_table.end())
		iter->second.notify_list.push_back(std::move(zn));
} catch (const std::bad_alloc &) {
}

void zserver_init(size_t table_size, int cache_interval, int ping_interval)
{
	g_table_size = table_size;
	g_cache_interval = cache_interval;
	g_ping_interval = ping_interval;
}

int zserver_run()
{
	g_zserver_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, zcorezs_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "E-1443: pthread_create: %s", strerror(ret));
		return -4;
	}
	pthread_setname_np(g_scan_id, "zarafa");
	return 0;
}

void zserver_stop()
{
	g_zserver_stop = true;
	if (!pthread_equal(g_scan_id, {})) {
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, NULL);
	}
	{ /* silence cov-scan, take locks even in single-thread scenarios */
		std::lock_guard lk(g_table_lock);
		g_session_table.clear();
		g_user_table.clear();
	}
	{
		std::lock_guard lk(g_notify_lock);
		g_notify_table.clear();
	}
}

static ec_error_t zs_logon_phase2(sql_meta_result &&mres, GUID *phsession)
{
	char homedir[256];
	char tmp_name[UADDR_SIZE];
	auto username = mres.username.c_str();
	auto pdomain = strchr(username, '@');
	if (pdomain == nullptr)
		return ecUnknownUser;
	pdomain ++;
	gx_strlcpy(tmp_name, username, std::size(tmp_name));
	HX_strlower(tmp_name);
	std::unique_lock tl_hold(g_table_lock);
	unsigned int user_id = 0, domain_id = 0, org_id = 0;
	auto iter = g_user_table.find(tmp_name);
	if (iter != g_user_table.end()) {
		user_id = iter->second;
		auto st_iter = g_session_table.find(user_id);
		if (st_iter != g_session_table.end()) {
			auto pinfo = &st_iter->second;
			pinfo->last_time = time(nullptr);
			*phsession = pinfo->hsession;
			return ecSuccess;
		}
		g_user_table.erase(iter);
	}
	tl_hold.unlock();
	if (!mysql_adaptor_get_user_ids(username, &user_id, nullptr, nullptr) ||
	    !mysql_adaptor_get_homedir(pdomain, homedir, std::size(homedir)) ||
	    !mysql_adaptor_get_domain_ids(pdomain, &domain_id, &org_id))
		return ecError;
	assert(!mres.maildir.empty());

	USER_INFO tmp_info;
	tmp_info.hsession = GUID::random_new();
	memcpy(tmp_info.hsession.node, &user_id, sizeof(int32_t));
	tmp_info.user_id = user_id;
	tmp_info.domain_id = domain_id;
	tmp_info.org_id = org_id;
	tmp_info.privbits = mres.privbits;
	try {
		tmp_info.username = username;
		HX_strlower(tmp_info.username.data());
		tmp_info.lang = mres.lang;
		tmp_info.maildir = mres.maildir;
		tmp_info.homedir = homedir;
	} catch (const std::bad_alloc &) {
		return ecServerOOM;
	}
	auto c = lang_to_charset(tmp_info.lang.c_str());
	tmp_info.cpid = c != nullptr ? cset_to_cpid(c) : CP_UTF8;
	tmp_info.last_time = time(nullptr);
	tmp_info.reload_time = tmp_info.last_time;
	tmp_info.ptree = object_tree_create(tmp_info.maildir.c_str());
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

ec_error_t zs_logon(const char *username, const char *password,
    const char *rhost, uint32_t flags, GUID *phsession)
{
	sql_meta_result mres{};
	if (!system_services_auth_login(username, znul(password),
	    WANTPRIV_BASIC, mres)) {
		mlog(LV_WARN, "rhost=[%s]:0 user=%s zs_logon rejected: %s",
			znul(rhost), username, mres.errstr.c_str());
		return ecLoginFailure;
	}
	return zs_logon_phase2(std::move(mres), phsession);
}

ec_error_t zs_logon_np(const char *username, const char *password,
    const char *rhost, uint32_t flags, GUID *phsession)
{
	sql_meta_result mres{};
	auto ret = mysql_adaptor_meta(username, WANTPRIV_METAONLY, mres);
	if (ret != 0) {
		mlog(LV_WARN, "rhost=[%s]:0 user=%s zs_logon_np rejected: %s",
			znul(rhost), username, mres.errstr.c_str());
		return ecLoginFailure;
	}
	return zs_logon_phase2(std::move(mres), phsession);
}

ec_error_t zs_logon_token(const char *token, const char *rhost, GUID *phsession)
{
	sql_meta_result mres{};
	if (!system_services_auth_login_token(token, WANTPRIV_BASIC, mres)) {
		mlog(LV_WARN, "rhost=[%s] user=%s zs_logon_token rejected: %s",
			znul(rhost), mres.username.c_str(), mres.errstr.c_str());
		return ecLoginFailure;
	}
	return zs_logon_phase2(std::move(mres), phsession);
}

ec_error_t zs_checksession(GUID hsession)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	return ecSuccess;
}

ec_error_t zs_uinfo(const char *username, BINARY *pentryid,
    std::string *dispname, std::string *essdn, uint32_t *pprivilege_bits) try
{
	EXT_PUSH ext_push;
	EMSAB_ENTRYID_view tmp_entryid;
	
	if (!mysql_adaptor_get_user_displayname(username, *dispname) ||
	    !mysql_adaptor_get_user_privilege_bits(username, pprivilege_bits))
		return ecNotFound;
	auto err = cvt_username_to_essdn(username, g_org_name,
	           mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	           *essdn);
	if (err != ecSuccess)
		return err;
	tmp_entryid.flags = 0;
	tmp_entryid.type = DT_MAILUSER;
	tmp_entryid.px500dn = essdn->c_str();
	pentryid->pv = common_util_alloc(1280);
	if (pentryid->pv == nullptr ||
	    !ext_push.init(pentryid->pb, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_abk_eid(tmp_entryid) != pack_result::ok)
		return ecError;
	pentryid->cb = ext_push.m_offset;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
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
	std::string essdn;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t address_type;
	uint16_t type;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	if (strncmp(entryid.pc, "/exmdb=", 7) == 0) {
		/* Stupid GUID-less entryid from submit.php */
		return zs_openentry_emsab(hsession, entryid, flags, entryid.pc,
		       DT_REMOTE_MAILUSER, pmapi_type, phobject);
	} else if (cu_parse_abkeid(entryid, &address_type, essdn)) {
		return zs_openentry_emsab(hsession, entryid, flags, essdn.c_str(),
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
		if (zh_is_error(handle))
			return zh_error(handle);
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
		if (zh_is_error(handle))
			return zh_error(handle);
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
		std::string essdn_s;
		const char *essdn = essdn_s.c_str();

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
			essdn = entryid.pc;
		} else if (cu_parse_abkeid(entryid, &address_type, essdn_s) &&
		     strncmp(essdn_s.c_str(), "/exmdb=", 7) == 0 &&
		     address_type == DT_REMOTE_MAILUSER) {
			essdn = essdn_s.c_str();
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
			    nullptr, CP_ACP, message_id, PidTagParentFolderId,
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
		if (!exmdb_client->is_msg_deleted(pstore->get_dir(),
		    message_id, &b_del))
			return ecError;
		if (b_del && !(flags & SHOW_SOFT_DELETES))
			return ecNotFound;
		auto ret = cu_calc_msg_access(*pstore, pinfo->get_username(),
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
		if (zh_is_error(*phobject))
			return zh_error(*phobject);
		*pmapi_type = zs_objtype::message;
	} else {
		if (!exmdb_client->is_folder_present(pstore->get_dir(),
		    folder_id, &b_exist))
			return ecError;
		if (!b_exist)
			return ecNotFound;
		if (!pstore->b_private) {
			if (!exmdb_client->is_folder_deleted(pstore->get_dir(),
			    folder_id, &b_del))
				return ecError;
			if (b_del && !(flags & SHOW_SOFT_DELETES))
				return ecNotFound;
		}
		if (!exmdb_client_get_folder_property(pstore->get_dir(), CP_ACP,
		    folder_id, PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
			return ecError;
		auto folder_type = *static_cast<uint32_t *>(pvalue);
		if (pstore->owner_mode()) {
			tag_access = MAPI_ACCESS_AllSix;
		} else {
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
		if (zh_is_error(*phobject))
			return zh_error(*phobject);
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
	if (ep.g_oneoff_eid(&eid) != pack_result::ok)
		return ecInvalidParam;
	auto u = oneoff_object::create(std::move(eid));
	if (u == nullptr)
		return ecServerOOM;
	*zmg_type = zs_objtype::oneoff;
	*objh = info->ptree->add_object_handle(ROOT_HANDLE, {*zmg_type, std::move(u)});
	return zh_error(*objh);
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
		container_id.abtree_id.minid = ab_tree::minid::SC_ROOT;
		auto contobj = container_object::create(CONTAINER_TYPE_ABTREE, container_id);
		if (contobj == nullptr)
			return ecError;
		*pmapi_type = zs_objtype::abcont;
		*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {*pmapi_type, std::move(contobj)});
		if (zh_is_error(*phobject))
			return zh_error(*phobject);
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
	std::string essdn_s;
	uint32_t address_type;

	if (!cu_parse_abkeid(entryid, &address_type, essdn_s))
		return ecInvalidParam;

	auto essdn = essdn_s.data();
	if (address_type == DT_CONTAINER) {
		CONTAINER_ID container_id;
		uint8_t type;

		HX_strlower(essdn);
		if (strcmp(essdn, "/") == 0) {
			type = CONTAINER_TYPE_ABTREE;
			container_id.abtree_id.base_id = base_id;
			container_id.abtree_id.minid = ab_tree::minid::SC_GAL;
		} else if (strcmp(essdn, "/exmdb") == 0) {
			type = CONTAINER_TYPE_ABTREE;
			container_id.abtree_id.base_id = base_id;
			container_id.abtree_id.minid = ab_tree::minid::SC_EMPTY;
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
			auto pbase = ab_tree::AB.get(base_id);
			if (!pbase)
				return ecError;
			ab_tree::ab_node node(pbase, ab_tree::minid(guid));
			if (!node.exists())
				return ecNotFound;
			type = CONTAINER_TYPE_ABTREE;
			container_id.abtree_id.base_id = base_id;
			container_id.abtree_id.minid = node.mid;
		}
		auto contobj = container_object::create(type, container_id);
		if (contobj == nullptr)
			return ecError;
		*pmapi_type = zs_objtype::abcont;
		*phobject = pinfo->ptree->add_object_handle(ROOT_HANDLE, {*pmapi_type, std::move(contobj)});
	} else if (address_type == DT_DISTLIST || address_type == DT_MAILUSER || address_type == DT_REMOTE_MAILUSER) {
		if (!common_util_essdn_to_ids(essdn, &domain_id, &user_id))
			return ecNotFound;
		if (domain_id != pinfo->domain_id &&
		    !mysql_adaptor_check_same_org(domain_id, pinfo->domain_id))
			base_id = -domain_id;
		auto minid = ab_tree::minid(ab_tree::minid::address, user_id);
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
	if (zh_is_error(*phobject))
		return zh_error(*phobject);
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
	if (ep.g_uint32(&mapi_type) != pack_result::ok ||
	    static_cast<mapi_object_type>(mapi_type) != MAPI_ABCONT ||
	    ep.advance(4) != pack_result::ok ||
	    ep.g_folder_eid(&fe) != pack_result::ok ||
	    fe.eid_type != EITLT_PRIVATE_FOLDER)
		return ecInvalidParam;

	CONTAINER_ID ctid;
	ctid.exmdb_id.b_private = TRUE;
	ctid.exmdb_id.folder_id = rop_util_make_eid(1, fe.folder_gc);
	auto contobj = container_object::create(CONTAINER_TYPE_FOLDER, ctid);
	if (contobj == nullptr)
		return ecError;
	*zmg_type = zs_objtype::abcont;
	*objh = info->ptree->add_object_handle(ROOT_HANDLE, {*zmg_type, std::move(contobj)});
	return zh_error(*objh);
}

ec_error_t zs_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set)
{
	PROPTAG_ARRAY proptags;
	
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	int base_id = pinfo->org_id == 0 ? -pinfo->domain_id : pinfo->org_id;
	auto pbase = ab_tree::AB.get(base_id);
	if (!pbase)
		return ecError;
	std::vector<ab_tree::minid> result_list;
	for (size_t i = 0; i < pcond_set->count; ++i) {
		auto pstring = pcond_set->pparray[i]->get<const char>(PR_DISPLAY_NAME);
		if (NULL == pstring) {
			presult_set->count = 0;
			presult_set->pparray = NULL;
			return ecSuccess;
		}
		std::string idn_deco = gx_utf8_to_punycode(pstring);
		pstring = idn_deco.c_str();
		std::vector<ab_tree::minid> temp_list;
		if (!ab_tree_resolvename(pbase.get(), pstring, temp_list))
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
		return ecServerOOM;
	container_object_get_user_table_all_proptags(&proptags);
	for (auto mid : result_list) {
		presult_set->pparray[presult_set->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (presult_set->pparray[presult_set->count] == nullptr)
			return ecServerOOM;
		if (!ab_tree_fetch_node_properties({pbase, mid},
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
	if (!pfolder->pstore->owner_mode()) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(pfolder->pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	return pfolder->set_permissions(pset) ? ecSuccess : ecError;
}

ec_error_t zs_modifyrules(GUID hsession, uint32_t hfolder, uint32_t flags,
    RULE_LIST *plist)
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
		for (const auto &rule : *plist)
			if (rule.flags != ROW_ADD)
				return ecInvalidParam;
	if (!pfolder->pstore->owner_mode()) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(pfolder->pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	return pfolder->updaterules(flags, plist) ? ecSuccess : ecError;
}

ec_error_t zs_getabgal(GUID hsession, BINARY *pentryid)
{
	void *pvalue;
	
	if (!container_object_fetch_special_property(ab_tree::minid::SC_GAL,
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
	return zh_error(*phobject);
}

ec_error_t zs_openstore(GUID hsession, BINARY entryid, uint32_t *phobject)
{
	int user_id;
	EXT_PULL ext_pull;
	STORE_ENTRYID store_entryid = {};
	
	ext_pull.init(entryid.pb, entryid.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_store_eid(&store_entryid) != pack_result::ok)
		return ecError;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	if (store_entryid.wrapped_provider_uid == g_muidStorePublic) {
		/* pserver_name or ESSDN is ignored; can only ever open PF of own domain */
		*phobject = pinfo->ptree->get_store_handle(false, pinfo->domain_id);
		return zh_error(*phobject);
	}
	if (!common_util_essdn_to_uid(store_entryid.pmailbox_dn, &user_id))
		return ecNotFound;
	if (pinfo->user_id == user_id) {
		*phobject = pinfo->ptree->get_store_handle(TRUE, user_id);
		return zh_error(*phobject);
	}
	std::string username;
	auto ret = mysql_adaptor_userid_to_name(user_id, username);
	if (ret != ecSuccess)
		return ret;
	sql_meta_result mres;
	if (mysql_adaptor_meta(username.c_str(), WANTPRIV_METAONLY, mres) != 0)
		return ecError;
	uint32_t permission = rightsNone;
	if (!exmdb_client->get_mbox_perm(mres.maildir.c_str(),
	    pinfo->get_username(), &permission))
		return ecError;
	if (permission == rightsNone) {
		if (g_zrpc_debug >= 1)
			mlog(LV_ERR, "openstore: \"%s\" has no rights to access \"%s\"",
				pinfo->get_username(), username.c_str());
		return ecLoginPerm;
	} else if (g_zrpc_debug >= 2) {
		mlog(LV_DEBUG, "openstore: \"%s\" granted access to \"%s\"",
			pinfo->get_username(), username.c_str());
	}
	if (permission & frightsGromoxStoreOwner) try {
		std::lock_guard lk(pinfo->eowner_lock);
		pinfo->extra_owner.insert_or_assign(user_id, time(nullptr));
	} catch (const std::bad_alloc &) {
	}
	*phobject = pinfo->ptree->get_store_handle(TRUE, user_id);
	return zh_error(*phobject);
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
	return zh_error(*phobject);
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
	return zh_error(*phobject);
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
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
	return zh_error(*phobject);
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
	return zh_error(*phobject);
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
	return zh_error(*phobject);
}

ec_error_t zs_createmessage(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	zs_objtype mapi_type;
	uint32_t tag_access;
	uint32_t permission;
	uint64_t message_id;
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
	if (zh_is_error(hstore))
		return zh_error(hstore);
	if (!pstore->owner_mode()) {
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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

	static constexpr proptag_t proptag_buff[] =
		{PR_MESSAGE_SIZE_EXTENDED, PR_STORAGE_QUOTA_LIMIT,
		PR_ASSOC_CONTENT_COUNT, PR_CONTENT_COUNT};
	static constexpr PROPTAG_ARRAY tmp_proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	if (!pstore->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;
	auto num = tmp_propvals.get<const uint32_t>(PR_STORAGE_QUOTA_LIMIT);
	int64_t max_quota = num == nullptr ? -1 : static_cast<int64_t>(*num) * 1024;
	auto lnum = tmp_propvals.get<const uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	uint64_t total_size = lnum != nullptr ? *lnum : 0;
	if (max_quota > 0 && total_size > static_cast<uint64_t>(max_quota))
		return ecQuotaExceeded;
	if (!exmdb_client->allocate_message_id(pstore->get_dir(),
	    folder_id, &message_id))
		return ecError;
	auto pmessage = message_object::create(pstore, TRUE,
			pinfo->cpid, message_id, &folder_id,
			tag_access, TRUE, NULL);
	if (pmessage == nullptr)
		return ecError;
	BOOL b_fai = (flags & MAPI_ASSOCIATED) ? TRUE : false;
	if (pmessage->init_message(b_fai, pinfo->cpid) != 0)
		return ecError;
	/* add the store handle as the parent object handle
		because the caller normally will not keep the
		handle of folder */
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::message, std::move(pmessage)});
	return zh_error(*phobject);
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
	TPROPVAL_ARRAY tmp_propvals;
	bool notify_non_read = flags & GX_DELMSG_NOTIFY_UNREAD;
	
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
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
		return ecServerOOM;
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
	BOOL b_hard = (flags & DELETE_HARD_DELETE) ? TRUE : false;
	if (!notify_non_read) {
		if (!exmdb_client->delete_messages(pstore->get_dir(),
		    pinfo->cpid, username, pfolder->folder_id, &ids, b_hard,
		    &b_partial))
			return ecError;
		return ecSuccess;
	}
	ids1.count = 0;
	ids1.pids  = cu_alloc<uint64_t>(ids.count);
	if (ids1.pids == nullptr)
		return ecServerOOM;
	for (auto i_eid : ids) {
		if (username != STORE_OWNER_GRANTED) {
			if (!exmdb_client_check_message_owner(pstore->get_dir(),
			    i_eid, username, &b_owner))
				return ecError;
			if (!b_owner)
				continue;
		}
		static constexpr proptag_t proptag_buff[] =
			{PR_NON_RECEIPT_NOTIFICATION_REQUESTED, PR_READ};
		static constexpr PROPTAG_ARRAY tmp_proptags =
			{std::size(proptag_buff), deconst(proptag_buff)};
		if (!exmdb_client->get_message_properties(pstore->get_dir(),
		    nullptr, CP_ACP, i_eid, &tmp_proptags, &tmp_propvals))
			return ecError;
		pbrief = NULL;
		auto flag = tmp_propvals.get<const uint8_t>(PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
		if (flag != nullptr && *flag != 0) {
			flag = tmp_propvals.get<uint8_t>(PR_READ);
			if ((flag == nullptr || *flag == 0) &&
			    !exmdb_client->get_message_brief(pstore->get_dir(),
			    pinfo->cpid, i_eid, &pbrief))
				return ecError;
		}
		ids1.pids[ids1.count++] = i_eid;
		if (pbrief != nullptr)
			common_util_notify_receipt(pstore->get_account(),
				NOTIFY_RECEIPT_NON_READ, pbrief);
	}
	return exmdb_client->delete_messages(pstore->get_dir(), pinfo->cpid,
	       username, pfolder->folder_id, &ids1, b_hard, &b_partial) ?
	       ecSuccess : ecError;
}

ec_error_t zs_copymessages(GUID hsession, uint32_t hsrcfolder,
    uint32_t hdstfolder, const BINARY_ARRAY *pentryids, uint32_t flags)
{
	BOOL b_guest = TRUE, b_owner;
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
	auto src_store = psrc_folder->pstore;
	auto pdst_folder = pinfo->ptree->get_object<folder_object>(hdstfolder, &mapi_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder || pdst_folder->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto dst_store = pdst_folder->pstore;
	BOOL b_copy = (flags & MAPI_MOVE) ? false : TRUE;
	if (src_store != dst_store) {
		if (!b_copy) {
			b_guest = FALSE;
			if (!src_store->owner_mode()) {
				if (!exmdb_client->get_folder_perm(src_store->get_dir(),
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
		if (!dst_store->owner_mode()) {
			if (!exmdb_client->get_folder_perm(dst_store->get_dir(),
			    pdst_folder->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsCreate))
				return ecAccessDenied;
		}
		for (size_t i = 0; i < pentryids->count; ++i) {
			if (!cu_entryid_to_mid(pentryids->pbin[i],
			    &b_private, &account_id, &folder_id, &message_id))
				return ecError;
			if (b_private != src_store->b_private ||
			    account_id != src_store->account_id ||
			    folder_id != psrc_folder->folder_id)
				continue;
			auto ret = cu_remote_copy_message(src_store, message_id,
			           dst_store, pdst_folder->folder_id);
			if (ret != ecSuccess)
				return ret;
			if (!b_copy) {
				if (b_guest) {
					if (!exmdb_client_check_message_owner(src_store->get_dir(),
					    message_id, pinfo->get_username(), &b_owner))
						return ecError;
					if (!b_owner)
						continue;
				}
				BOOL b_partial = false;
				const EID_ARRAY ids = {1, &message_id};
				if (!exmdb_client->delete_messages(src_store->get_dir(),
				    pinfo->cpid, nullptr, psrc_folder->folder_id,
				    &ids, false, &b_partial))
					return ecError;
			}
		}
		return ecSuccess;
	}

	EID_ARRAY ids;
	ids.count = 0;
	ids.pids = cu_alloc<uint64_t>(pentryids->count);
	if (ids.pids == nullptr)
		return ecServerOOM;
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (!cu_entryid_to_mid(pentryids->pbin[i],
		    &b_private, &account_id, &folder_id, &message_id))
			return ecError;
		if (b_private != src_store->b_private ||
		    account_id != src_store->account_id ||
		    folder_id != psrc_folder->folder_id)
			continue;
		ids.pids[ids.count++] = message_id;
	}
	if (!src_store->owner_mode()) {
		if (!exmdb_client->get_folder_perm(src_store->get_dir(),
		    pdst_folder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	return exmdb_client->movecopy_messages(src_store->get_dir(),
	       pinfo->cpid, b_guest, pinfo->get_username(),
	       psrc_folder->folder_id, pdst_folder->folder_id, b_copy, &ids,
	       &b_partial) ? ecSuccess : ecError;
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
	BOOL b_notify = TRUE; /* TODO: Read from config or USER_INFO. */
	BINARY_ARRAY tmp_bins;
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
		res_prop.relop = flags & rfClearReadFlag ? RELOP_NE : RELOP_EQ;
		res_prop.proptag = PR_READ;
		res_prop.propval.proptag = PR_READ;
		res_prop.propval.pvalue = deconst(&fake_false);
		if (!exmdb_client->load_content_table(pstore->get_dir(), CP_ACP,
		    pfolder->folder_id, username, TABLE_FLAG_NONOTIFICATIONS,
		    &restriction, nullptr, &table_id, &row_count))
			return ecError;

		static constexpr proptag_t tmp_proptag[] = {PR_ENTRYID};
		static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
		if (!exmdb_client->query_table(pstore->get_dir(), username,
		    CP_ACP, table_id, &proptags, 0, row_count, &tmp_set)) {
			exmdb_client->unload_table(pstore->get_dir(), table_id);
			return ecError;
		}
		exmdb_client->unload_table(pstore->get_dir(), table_id);
		if (tmp_set.count > 0) {
			tmp_bins.count = 0;
			tmp_bins.pbin = cu_alloc<BINARY>(tmp_set.count);
			if (tmp_bins.pbin == nullptr)
				return ecServerOOM;
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
		if (flags & rfClearReadFlag) {
			if (!exmdb_client_get_message_property(pstore->get_dir(),
			    username, CP_ACP, message_id, PR_READ, &pvalue))
				return ecError;
			if (pvb_enabled(pvalue)) {
				tmp_byte = 0;
				b_changed = TRUE;
			}
		} else {
			if (!exmdb_client_get_message_property(pstore->get_dir(),
			    username, CP_ACP, message_id, PR_READ, &pvalue))
				return ecError;
			if (pvb_disabled(pvalue)) {
				tmp_byte = 1;
				b_changed = TRUE;
				if (!exmdb_client_get_message_property(pstore->get_dir(),
				    username, CP_ACP, message_id,
				    PR_READ_RECEIPT_REQUESTED, &pvalue))
					return ecError;
				if (pvb_enabled(pvalue))
					b_notify = TRUE;
			}
		}
		if (b_changed && !exmdb_client->set_message_read_state(pstore->get_dir(),
		    username, message_id, tmp_byte, &read_cn))
			return ecError;
		if (!b_notify)
			continue;
		if (!exmdb_client->get_message_brief(pstore->get_dir(),
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
		exmdb_client->set_message_properties(pstore->get_dir(), username,
			CP_ACP, message_id, &propvals, &problems);
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
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
		    pparent->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
	}
	if (!exmdb_client->get_folder_by_name(pstore->get_dir(),
	    pparent->folder_id, folder_name, &folder_id))
		return ecError;
	if (0 != folder_id) {
		if (!exmdb_client_get_folder_property(pstore->get_dir(), CP_ACP,
		    folder_id, PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
			return ecError;
		if (!(flags & OPEN_IF_EXISTS) ||
		    folder_type != *static_cast<uint32_t *>(pvalue))
			return ecDuplicateName;
	} else {
		parent_id = pparent->folder_id;
		if (!exmdb_client->allocate_cn(pstore->get_dir(), &change_num))
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
		ec_error_t err = ecSuccess;
		if (!exmdb_client->create_folder(pstore->get_dir(), pinfo->cpid,
		    &tmp_propvals, &folder_id, &err))
			return ecError;
		if (err != ecSuccess)
			return err;
		if (folder_id == 0)
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
			if (!exmdb_client->update_folder_permission(pstore->get_dir(),
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
		if (zh_is_error(hstore))
			return zh_error(hstore);
		*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::folder, std::move(pfolder)});
	} else {
		*phobject = pinfo->ptree->add_object_handle(hparent_folder, {zs_objtype::folder, std::move(pfolder)});
	}
	return zh_error(*phobject);
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
		if (rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
			return ecAccessDenied;
	} else {
		if (1 == rop_util_get_replid(folder_id) &&
		    rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
			return ecAccessDenied;
	}
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
		username = pinfo->get_username();
	}
	if (!exmdb_client->is_folder_present(pstore->get_dir(),
	    pfolder->folder_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecSuccess;
	if (flags & DEL_MESSAGES)
		/*
		 * MAPI has the %DEL_ASSOCIATED associated flag, but its use is
		 * not specified for IMAPIFolder::DeleteFolder.
		 * Deletion of FAI is implicit in the specs' wording though.
		 */
		flags |= DEL_ASSOCIATED;
	if (pstore->b_private) {
		if (!exmdb_client_get_folder_property(pstore->get_dir(), CP_ACP,
		    folder_id, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (pvalue == nullptr)
			return ecSuccess;
		if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
			goto DELETE_FOLDER;
	}
	if (flags & (DEL_FOLDERS | DEL_MESSAGES | DEL_ASSOCIATED)) {
		if (!exmdb_client->empty_folder(pstore->get_dir(), pinfo->cpid,
		    username, folder_id, flags, &b_partial))
			return ecError;
		if (b_partial)
			/* failure occurs, stop deleting folder */
			return ecSuccess;
	}
 DELETE_FOLDER:
	return exmdb_client->delete_folder(pstore->get_dir(), pinfo->cpid,
	       folder_id, (flags & DELETE_HARD_DELETE) ? TRUE : false, &b_done) ?
	       ecSuccess : ecError;
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
	auto fid_val = rop_util_get_gc_value(pfolder->folder_id);
	if (pstore->b_private) {
		if (fid_val == PRIVATE_FID_ROOT || fid_val == PRIVATE_FID_IPMSUBTREE)
			return ecAccessDenied;
	} else {
		if (fid_val == PUBLIC_FID_ROOT || fid_val == PUBLIC_FID_IPMSUBTREE)
			return ecAccessDenied;
	}
	const char *username = nullptr;
	if (!pstore->owner_mode()) {
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsDeleteAny | frightsDeleteOwned)))
			return ecAccessDenied;
		username = pinfo->get_username();
	}
	return exmdb_client->empty_folder(pstore->get_dir(),
	       pinfo->cpid, username, pfolder->folder_id,
	       flags | DEL_MESSAGES | DEL_FOLDERS, &b_partial) ? ecSuccess : ecError;
}

ec_error_t zs_copyfolder(GUID hsession, uint32_t hsrc_folder, BINARY entryid,
    uint32_t hdst_folder, const char *new_name, uint32_t flags)
{
	BOOL b_done;
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
	BOOL b_copy = (flags & MAPI_MOVE) ? false : TRUE;
	if (psrc_parent->type == FOLDER_SEARCH && !b_copy)
		return ecNotSupported;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto src_store = psrc_parent->pstore;
	if (!cu_entryid_to_fid(entryid,
	    &b_private, &account_id, &folder_id))
		return ecError;
	if (b_private != src_store->b_private ||
	    account_id != src_store->account_id)
		return ecInvalidParam;
	auto pdst_folder = pinfo->ptree->get_object<folder_object>(hdst_folder, &mapi_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (mapi_type != zs_objtype::folder)
		return ecNotSupported;
	auto dst_store = pdst_folder->pstore;
	auto fidtest = src_store->b_private ? PRIVATE_FID_ROOT : PUBLIC_FID_ROOT;
	if (rop_util_get_gc_value(folder_id) == fidtest)
		return ecAccessDenied;
	BOOL b_guest = false;
	const char *username = nullptr;
	if (!src_store->owner_mode()) {
		if (!exmdb_client->get_folder_perm(src_store->get_dir(),
		    folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsReadAny))
			return ecAccessDenied;
		if (!exmdb_client->get_folder_perm(src_store->get_dir(),
		    pdst_folder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
		username = pinfo->get_username();
		b_guest = TRUE;
	}
	if (src_store != dst_store) {
		if (!b_copy && !src_store->owner_mode()) {
			if (!exmdb_client->get_folder_perm(src_store->get_dir(),
			    psrc_parent->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		auto ret = cu_remote_copy_folder(src_store, folder_id, dst_store,
		           pdst_folder->folder_id, new_name);
		if (ret != ecSuccess)
			return ret;
		if (!b_copy) {
			if (!exmdb_client->empty_folder(src_store->get_dir(),
			    pinfo->cpid, username, folder_id,
			    DEL_MESSAGES | DEL_ASSOCIATED | DEL_FOLDERS, &b_partial))
				return ecError;
			if (b_partial)
				/* failure occurs, stop deleting folder */
				return ecSuccess;
			if (!exmdb_client->delete_folder(src_store->get_dir(),
			    pinfo->cpid, folder_id, false, &b_done))
				return ecError;
		}
		return ecSuccess;
	}
	if (!exmdb_client->is_descendant_folder(src_store->get_dir(), folder_id,
	    pdst_folder->folder_id, &b_cycle))
		return ecError;
	if (b_cycle)
		return ecRootFolder;
	ec_error_t err = ecSuccess;
	if (!exmdb_client->movecopy_folder(src_store->get_dir(), pinfo->cpid,
	    b_guest, pinfo->get_username(), psrc_parent->folder_id, folder_id,
	    pdst_folder->folder_id, new_name, b_copy, &err))
		return ecError;
	return err;
}

ec_error_t zs_getstoreentryid(const char *mailbox_dn, BINARY *pentryid)
{
	EXT_PUSH ext_push;
	std::string username, essdn;
	STORE_ENTRYID store_entryid = {};
	
	if (0 == strncasecmp(mailbox_dn, "/o=", 3)) {
		auto ret = cvt_essdn_to_username(mailbox_dn, g_org_name,
		           mysql_adaptor_userid_to_name, username);
		if (ret == ecUnknownUser)
			return ecNotFound;
		else if (ret != ecSuccess)
			return ret;
	} else {
		username = mailbox_dn;
		auto err = cvt_username_to_essdn(mailbox_dn, g_org_name,
		           mysql_adaptor_get_user_ids,
		           mysql_adaptor_get_domain_ids, essdn);
		if (err != ecSuccess)
			return err;
		mailbox_dn = essdn.c_str();
	}
	store_entryid.wrapped_provider_uid = g_muidStorePrivate;
	store_entryid.wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
	store_entryid.pserver_name = deconst(username.c_str());
	store_entryid.pmailbox_dn = deconst(mailbox_dn);
	pentryid->pv = common_util_alloc(1024);
	if (pentryid->pv == nullptr ||
	    !ext_push.init(pentryid->pb, 1024, EXT_FLAG_UTF16) ||
	    ext_push.p_store_eid(store_entryid) != pack_result::ok)
		return ecError;
	pentryid->cb = ext_push.m_offset;
	return ecSuccess;
}

ec_error_t zs_entryidfromsourcekey(GUID hsession, uint32_t hstore,
    BINARY folder_key, const BINARY *pmessage_key, BINARY *pentryid)
{
	XID tmp_xid;
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
			if (!mysql_adaptor_check_same_org(domain_id, pstore->account_id))
				return ecInvalidParam;
			ec_error_t ret = ecSuccess;
			if (!exmdb_client->get_mapping_replid(pstore->get_dir(),
			    tmp_xid.guid, &replid, &ret))
				return ecError;
			if (ret != ecSuccess)
				return ret;
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
		pbin = cu_mid_to_entryid(*pstore, folder_id, message_id);
	} else {
		pbin = cu_fid_to_entryid(*pstore, folder_id);
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
	if (!exmdb_client->subscribe_notification(pstore->get_dir(),
	    event_mask, TRUE, folder_id, message_id, psub_id))
		return ecError;
	gx_strlcpy(dir, pstore->get_dir(), std::size(dir));
	pinfo.reset();
	std::unique_lock nl_hold(g_notify_lock);
	if (g_notify_table.size() == g_table_size) {
		nl_hold.unlock();
		exmdb_client->unsubscribe_notification(dir, *psub_id);
		return ecError;
	}
	try {
		auto tmp_buf = std::to_string(*psub_id) + "|" + dir;
		g_notify_table.try_emplace(std::move(tmp_buf), hsession, hstore);
	} catch (const std::bad_alloc &) {
		nl_hold.unlock();
		exmdb_client->unsubscribe_notification(dir, *psub_id);
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
	exmdb_client->unsubscribe_notification(dir.c_str(), sub_id);
	auto tmp_buf = std::to_string(sub_id) + "|"s + std::move(dir);
	std::unique_lock nl_hold(g_notify_lock);
	g_notify_table.erase(std::move(tmp_buf));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

ec_error_t zs_notifdequeue(const NOTIF_SINK *psink, uint32_t timeval,
    std::vector<ZNOTIFICATION> *pnotifications)
{
	int i;
	zs_objtype mapi_type;
	std::vector<ZNOTIFICATION> ppnotifications;
	
	auto pinfo = zs_query_session(psink->hsession);
	if (pinfo == nullptr)
		return ecError;
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
		pnitem->last_time = time(nullptr);

		size_t limit = 1024 - std::min(ppnotifications.size(), static_cast<size_t>(1024));
		limit = std::min(limit, pnitem->notify_list.size());
		ppnotifications.insert(ppnotifications.end(),
			std::make_move_iterator(pnitem->notify_list.begin()),
			std::make_move_iterator(pnitem->notify_list.end()));
		pnitem->notify_list.erase(pnitem->notify_list.begin(), pnitem->notify_list.begin() + limit);
		nl_hold.unlock();
		if (ppnotifications.size() >= 1024)
			break;
	}
	if (ppnotifications.size() > 0) {
		pinfo.reset();
		*pnotifications = std::move(ppnotifications);
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
	psink_node->until_time = time(nullptr);
	psink_node->until_time += timeval;
	psink_node->sink.hsession = psink->hsession;
	psink_node->sink.count = psink->count;
	psink_node->sink.padvise = me_alloc<ADVISE_INFO>(psink->count);
	if (psink_node->sink.padvise == nullptr)
		return ecServerOOM;
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
				return ecServerOOM;
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
			if (!ptable->filter_rows(count, prestriction, prowset))
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
			return ecServerOOM;
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

static bool table_acceptable_type(proptype_t type)
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
	zs_objtype mapi_type;
	BOOL b_multi_inst;
	
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
		auto tmp_proptag = PROP_TAG(psortset->psort[i].type, psortset->psort[i].propid);
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
		auto type = psortset->psort[i].type;
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

/*
 * Seeing [ZRPC 80040102h getreceivefolder] is legit; public stores
 * just do not implement this function.
 */
ec_error_t zs_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid)
{
	BINARY *pbin;
	zs_objtype mapi_type;
	uint64_t folder_id;
	
	if (pstrclass == nullptr)
		pstrclass = "";
	auto ret = cu_validate_msgclass(pstrclass);
	if (ret != ecSuccess)
		return ret;
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
	std::string temp_class;
	if (!exmdb_client->get_folder_by_class(pstore->get_dir(), pstrclass,
	    &folder_id, &temp_class))
		return ecError;
	pbin = cu_fid_to_entryid(*pstore, folder_id);
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
			continue;
		}
		prcpt = prcpt_list->pparray[i];
		ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 1);
		if (ppropval == nullptr)
			return ecServerOOM;
		memcpy(ppropval, prcpt->ppropval,
			sizeof(TAGGED_PROPVAL)*prcpt->count);
		ppropval[prcpt->count].proptag = PR_ROWID;
		ppropval[prcpt->count].pvalue = cu_alloc<uint32_t>();
		if (ppropval[prcpt->count].pvalue == nullptr)
			return ecServerOOM;
		*static_cast<uint32_t *>(ppropval[prcpt->count++].pvalue) = last_rowid;
		prcpt->ppropval = ppropval;
		auto pbin = prcpt->get<BINARY>(PR_ENTRYID);
		if (pbin == nullptr ||
		    (prcpt->has(PR_EMAIL_ADDRESS) &&
		    prcpt->has(PR_ADDRTYPE) && prcpt->has(PR_DISPLAY_NAME)))
			continue;
		ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
		if (ext_pull.g_uint32(&tmp_flags) != pack_result::ok ||
		    tmp_flags != 0)
			continue;
		if (ext_pull.g_guid(&provider_uid) != pack_result::ok)
			continue;
		if (provider_uid == muidEMSAB) {
			EMSAB_ENTRYID ab_entryid;
			EXT_PULL ext_pull;

			ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
			if (ext_pull.g_abk_eid(&ab_entryid) != pack_result::ok ||
			    ab_entryid.type != DT_MAILUSER)
				continue;
			ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 4);
			if (ppropval == nullptr)
				return ecServerOOM;
			memcpy(ppropval, prcpt->ppropval,
				prcpt->count*sizeof(TAGGED_PROPVAL));
			prcpt->ppropval = ppropval;
			auto err = cu_set_propval(prcpt, PR_ADDRTYPE, "EX");
			if (err != ecSuccess)
				return err;
			auto dupval = common_util_dup(ab_entryid.x500dn.c_str());
			if (dupval == nullptr)
				return ecServerOOM;
			cu_set_propval(prcpt, PR_EMAIL_ADDRESS, dupval);
			std::string es_result;
			auto ret = cvt_essdn_to_username(ab_entryid.x500dn.c_str(),
				   g_org_name, mysql_adaptor_userid_to_name, es_result);
			if (ret != ecSuccess)
				continue;
			dupval = common_util_dup(es_result);
			if (dupval == nullptr)
				return ecServerOOM;
			es_result.clear();
			cu_set_propval(prcpt, PR_SMTP_ADDRESS, dupval);
			if (!mysql_adaptor_get_user_displayname(tmp_buff, es_result))
				continue;
			dupval = common_util_dup(es_result);
			if (dupval == nullptr)
				return ecServerOOM;
			cu_set_propval(prcpt, PR_DISPLAY_NAME, dupval);
		} else if (provider_uid == muidOOP) {
			ONEOFF_ENTRYID oneoff_entry;
			EXT_PULL ext_pull;

			ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
			if (ext_pull.g_oneoff_eid(&oneoff_entry) != pack_result::ok ||
			    strcasecmp(oneoff_entry.paddress_type.c_str(), "SMTP") != 0)
				continue;
			ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 5);
			if (ppropval == nullptr)
				return ecServerOOM;
			memcpy(ppropval, prcpt->ppropval,
				prcpt->count*sizeof(TAGGED_PROPVAL));
			prcpt->ppropval = ppropval;
			cu_set_propval(prcpt, PR_ADDRTYPE, "SMTP");
			auto dupval = common_util_dup(oneoff_entry.pmail_address);
			if (dupval == nullptr)
				return ecServerOOM;
			cu_set_propval(prcpt, PR_EMAIL_ADDRESS, dupval);
			cu_set_propval(prcpt, PR_SMTP_ADDRESS, dupval);
			dupval = common_util_dup(oneoff_entry.pdisplay_name);
			if (dupval == nullptr)
				return ecServerOOM;
			cu_set_propval(prcpt, PR_DISPLAY_NAME, dupval);
			cu_set_propval(prcpt, PR_SEND_RICH_INFO,
				oneoff_entry.ctrl_flags & MAPI_ONE_OFF_NO_RICH_INFO ?
				&persist_false : &persist_true);
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
	std::string sender_essdn, repr_essdn, sender_dispname, repr_dispname;
	sender_dispname.resize(256);
	repr_dispname.resize(256);
	auto err = cvt_username_to_essdn(account, g_org_name,
	           mysql_adaptor_get_user_ids,
	           mysql_adaptor_get_domain_ids, sender_essdn);
	if (err != ecSuccess)
		return err;
	if (!mysql_adaptor_get_user_displayname(account, sender_dispname))
		return ecError;
	auto sender_eid = common_util_username_to_addressbook_entryid(account);
	if (sender_eid == nullptr)
		return ecError;
	auto repr_eid = sender_eid;
	const std::string sender_skb = "EX:" + sender_essdn;
	BINARY sender_srch, repr_srch;
	sender_srch.cb = sender_skb.size() + 1;
	sender_srch.pv = deconst(sender_skb.c_str());
	if (0 != strcasecmp(account, representing_username)) {
		err = cvt_username_to_essdn(representing_username,
		      g_org_name, mysql_adaptor_get_user_ids,
		      mysql_adaptor_get_domain_ids, repr_essdn);
		if (err != ecSuccess)
			return err;
		if (!mysql_adaptor_get_user_displayname(representing_username, repr_dispname))
			return ecError;
		repr_eid = common_util_username_to_addressbook_entryid(representing_username);
		if (repr_eid == nullptr)
			return ecError;
	} else {
		repr_essdn = sender_essdn;
		repr_dispname = sender_dispname;
	}
	const std::string repr_skb = "EX:" + repr_essdn;
	repr_srch.cb = repr_skb.size() + 1;
	repr_srch.pv = deconst(repr_skb.c_str());
	char msgid[UADDR_SIZE+2];
	make_inet_msgid(msgid, std::size(msgid), 0x5a53);
	TAGGED_PROPVAL pv[] = {
		{PR_READ, &tmp_byte},
		{PR_CLIENT_SUBMIT_TIME, &nt_time},
		{PR_MESSAGE_DELIVERY_TIME, &nt_time},
		{PR_CONTENT_FILTER_SCL, &tmp_level},
		{PR_SENDER_SMTP_ADDRESS, deconst(send_as ? representing_username : account)},
		{PR_SENDER_ADDRTYPE, deconst("EX")},
		{PR_SENDER_EMAIL_ADDRESS, deconst(send_as ? repr_essdn.c_str() : sender_essdn.c_str())},
		{PR_SENDER_NAME, deconst(send_as ? repr_dispname.c_str() : sender_dispname.c_str())},
		{PR_SENDER_ENTRYID, send_as ? repr_eid : sender_eid},
		{PR_SENDER_SEARCH_KEY, send_as ? &repr_srch : &sender_srch},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, deconst(representing_username)},
		{PR_SENT_REPRESENTING_ADDRTYPE, deconst("EX")},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, deconst(repr_essdn.c_str())},
		{PR_SENT_REPRESENTING_NAME, deconst(repr_dispname.c_str())},
		{PR_SENT_REPRESENTING_ENTRYID, repr_eid},
		{PR_SENT_REPRESENTING_SEARCH_KEY, &repr_srch},
		{PR_INTERNET_MESSAGE_ID, msgid},
	};
	TPROPVAL_ARRAY tmp_propvals = {std::size(pv), pv};
	if (!pmessage->set_properties(&tmp_propvals))
		return ecError;
	return pmessage->save();
}

ec_error_t zs_submitmessage(GUID hsession, uint32_t hmessage) try
{
	int timer_id;
	BOOL b_marked;
	zs_objtype mapi_type;
	uint16_t rcpt_num;
	char command_buff[1024];
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
		if (!exmdb_client->get_mbox_perm(pstore->get_dir(),
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

	static constexpr proptag_t proptag_buff1[] = {PR_ASSOCIATED};
	static constexpr PROPTAG_ARRAY tmp_proptags1 = {std::size(proptag_buff1), deconst(proptag_buff1)};
	if (!pmessage->get_properties(&tmp_proptags1, &tmp_propvals))
		return ecError;
	auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
	/* FAI message cannot be sent */
	if (flag != nullptr && *flag != 0)
		return ecAccessDenied;
	std::string delegator;
	if (!cu_extract_delegator(pmessage, delegator))
		return ecSendAsDenied;
	auto actor = pstore->get_account();
	repr_grant repr_grant;
	if (delegator.empty()) {
		delegator = actor;
		repr_grant = repr_grant::send_as;
	} else {
		repr_grant = cu_get_delegate_perm_AA(actor, delegator.c_str());
	}
	if (repr_grant < repr_grant::send_on_behalf) {
		mlog(LV_INFO, "I-1334: uid %s tried to submit %s:%llxh with from=<%s>, but no impersonation permission given.",
		        actor, pstore->dir, LLU{pmessage->get_id()}, delegator.c_str());
		return ecAccessDenied;
	}
	auto err = rectify_message(pmessage, delegator.c_str(),
	           repr_grant >= repr_grant::send_as);
	if (err != ecSuccess)
		return err;
	static constexpr proptag_t proptag_buff2[] =
		{PR_MAX_SUBMIT_MESSAGE_SIZE, PR_PROHIBIT_SEND_QUOTA, PR_MESSAGE_SIZE_EXTENDED};
	static const PROPTAG_ARRAY tmp_proptags2 =
		{std::size(proptag_buff2), deconst(proptag_buff2)};
	if (!pstore->get_properties(&tmp_proptags2, &tmp_propvals))
		return ecError;

	auto sendquota = tmp_propvals.get<uint32_t>(PR_PROHIBIT_SEND_QUOTA);
	auto storesize = tmp_propvals.get<uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	/* Sendquota is in KiB, storesize in bytes */
	if (sendquota != nullptr && storesize != nullptr &&
	    static_cast<uint64_t>(*sendquota) * 1024 <= *storesize)
		return ecQuotaExceeded;

	auto num = tmp_propvals.get<const uint32_t>(PR_MAX_SUBMIT_MESSAGE_SIZE);
	uint64_t max_length = UINT64_MAX;
	if (num != nullptr)
		max_length = static_cast<uint64_t>(*num) << 10;

	static constexpr proptag_t proptag_buff3[] =
		{PR_MESSAGE_SIZE, PR_MESSAGE_FLAGS, PR_DEFERRED_SEND_TIME,
		PR_DEFERRED_SEND_NUMBER, PR_DEFERRED_SEND_UNITS,
		PR_DELETE_AFTER_SUBMIT};
	static constexpr PROPTAG_ARRAY tmp_proptags3 =
		{std::size(proptag_buff3), deconst(proptag_buff3)};
	if (!pmessage->get_properties(&tmp_proptags3, &tmp_propvals))
		return ecError;
	num = tmp_propvals.get<uint32_t>(PR_MESSAGE_SIZE);
	if (num == nullptr)
		return ecError;
	auto mail_length = *num;
	if (max_length != UINT64_MAX && mail_length > max_length)
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
		if (!exmdb_client->try_mark_submit(pstore->get_dir(),
		    pmessage->get_id(), &b_marked))
			return ecError;
		if (!b_marked)
			return ecAccessDenied;
		auto deferred_time = props_to_defer_interval(tmp_propvals);
		if (deferred_time > 0) {
			snprintf(command_buff, 1024, "%s %s %llu",
			         common_util_get_submit_command(), actor,
			         LLU{rop_util_get_gc_value(pmessage->get_id())});
			timer_id = system_services_add_timer(
					command_buff, deferred_time);
			if (0 == timer_id) {
				exmdb_client->clear_submit(pstore->get_dir(),
					pmessage->get_id(), b_unsent);
				return ecError;
			}
			exmdb_client->set_message_timer(pstore->get_dir(),
				pmessage->get_id(), timer_id);
			pmessage->reload();
			return ecSuccess;
		}
	}
	auto ev_from = repr_grant >= repr_grant::send_as ? delegator.c_str() : actor;
	auto ret = cu_send_message(pstore, pmessage, ev_from);
	if (ret != ecSuccess) {
		exmdb_client->clear_submit(pstore->get_dir(),
			pmessage->get_id(), b_unsent);
		return ret;
	}
	if (!b_delete)
		pmessage->reload();
	else
		pmessage->clear_unsent();
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
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
	return zh_error(*phobject);
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
	return zh_error(*phobject);
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
	return zh_error(*phobject);
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
		for (size_t i = 0; i < ppropvals->count; ++i) {
			auto err = static_cast<TPROPVAL_ARRAY *>(pobject)->set(ppropvals->ppropval[i]);
			if (err != ecSuccess)
				return err;
		}
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
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
			return ecServerOOM;
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			const auto tag = pproptags->pproptag[i];
			auto v = static_cast<TPROPVAL_ARRAY *>(pobject)->getval(tag);
			if (v != nullptr)
				ppropvals->emplace_back(tag, v);
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
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
	if (zh_is_error(hstore))
		return zh_error(hstore);
	auto b_writable = pattachment->writable();
	auto tag_access = pattachment->get_tag_access();
	if (!b_writable && (flags & MAPI_CREATE)) {
		/*
		 * MAPI_BEST_ACCESS is supposed to imply a fallback to readonly,
		 * so downgrade MAPI_BEST_ACCESS to read-only when lacking
		 * write permissions instead of returning ecAccessDenied.
		 */
		if ((flags & MAPI_BEST_ACCESS) != MAPI_BEST_ACCESS)
			return ecAccessDenied;
		flags &= ~MAPI_BEST_ACCESS;
	}
	auto pmessage = message_object::create(pstore, false, pinfo->cpid, 0,
	                pattachment, tag_access, b_writable ? TRUE : false, nullptr);
	if (pmessage == nullptr)
		return ecError;
	if (pmessage->get_instance_id() == 0) {
		if (!(flags & MAPI_CREATE))
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
	return zh_error(*phobject);
}

ec_error_t zs_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto obj = pinfo->ptree->get_object<void>(hstore, &mapi_type);
	if (obj == nullptr)
		return ecNullObject;
	store_object *pstore = nullptr;
	switch (mapi_type) {
	using enum zs_objtype;
	case store:   pstore = static_cast<store_object *>(obj); break;
	case folder:  pstore = static_cast<folder_object *>(obj)->pstore; break;
	case message: pstore = static_cast<message_object *>(obj)->get_store(); break;
	case attach:  pstore = static_cast<attachment_object *>(obj)->get_store(); break;
	default: break;
	}
	if (pstore == nullptr)
		return ecNotSupported;
	return pstore->get_named_propids(TRUE, ppropnames, ppropids) ?
	       ecSuccess : ecError;
}

ec_error_t zs_getpropnames(GUID hsession, uint32_t hstore,
    const PROPID_ARRAY &ppropids, PROPNAME_ARRAY *ppropnames)
{
	zs_objtype mapi_type;
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	auto obj = pinfo->ptree->get_object<void>(hstore, &mapi_type);
	if (obj == nullptr)
		return ecNullObject;
	store_object *pstore = nullptr;
	switch (mapi_type) {
	using enum zs_objtype;
	case store:   pstore = static_cast<store_object *>(obj); break;
	case folder:  pstore = static_cast<folder_object *>(obj)->pstore; break;
	case message: pstore = static_cast<message_object *>(obj)->get_store(); break;
	case attach:  pstore = static_cast<attachment_object *>(obj)->get_store(); break;
	default: break;
	}
	if (pstore == nullptr)
		return ecNotSupported;
	return pstore->get_named_propnames(ppropids, ppropnames) ?
	       ecSuccess : ecError;
}

ec_error_t zs_copyto(GUID hsession, uint32_t hsrcobject,
    const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject, uint32_t flags)
{
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
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
			    folder->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (permission & frightsOwner) {
				username = NULL;
			} else {
				if (!(permission & frightsReadAny))
					return ecAccessDenied;
				username = pinfo->get_username();
			}
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
			    fdst->folder_id, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsOwner))
				return ecAccessDenied;
		}
		BOOL b_sub;
		if (!pexclude_proptags->has(PR_CONTAINER_HIERARCHY)) {
			if (!exmdb_client->is_descendant_folder(pstore->get_dir(),
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
		tmp_proptags.pproptag = cu_alloc<proptag_t>(proptags.count);
		if (tmp_proptags.pproptag == nullptr)
			return ecServerOOM;
		if (!b_force && !fdst->get_all_proptags(&proptags1))
			return ecError;
		for (unsigned int i = 0; i < proptags.count; ++i) {
			const auto tag = proptags.pproptag[i];
			if (fdst->is_readonly_prop(tag))
				continue;
			if (!b_force && proptags1.has(tag))
				continue;
			tmp_proptags.emplace_back(tag);
		}
		if (!folder->get_properties(&tmp_proptags, &propvals))
			return ecError;
		if (b_sub || b_normal || b_fai) {
			BOOL b_guest = username == STORE_OWNER_GRANTED ? false : TRUE;
			if (!exmdb_client->copy_folder_internal(pstore->get_dir(),
			    pinfo->cpid, b_guest, pinfo->get_username(),
			    folder->folder_id, b_normal, b_fai, b_sub,
			    fdst->folder_id, &b_collid, &b_partial))
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
	if (zh_is_error(hstore))
		return zh_error(hstore);
	auto pctx = icsdownctx_object::create(pfolder, SYNC_TYPE_HIERARCHY);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsdownctx, std::move(pctx)});
	return zh_error(*phobject);
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
	if (zh_is_error(hstore))
		return zh_error(hstore);
	auto pctx = icsdownctx_object::create(pfolder, SYNC_TYPE_CONTENTS);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsdownctx, std::move(pctx)});
	return zh_error(*phobject);
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
		if (!pctx->make_content(*pstate, prestriction, flags, &b_changed, pcount))
			return ecError;
	} else {
		if (!pctx->make_hierarchy(*pstate, flags, &b_changed, pcount))
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
	if (zh_is_error(hstore))
		return zh_error(hstore);
	auto pctx = icsupctx_object::create(pfolder, SYNC_TYPE_HIERARCHY);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsupctx, std::move(pctx)});
	return zh_error(*phobject);
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
	if (zh_is_error(hstore))
		return zh_error(hstore);
	auto pctx = icsupctx_object::create(pfolder, SYNC_TYPE_CONTENTS);
	if (pctx == nullptr)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hstore, {zs_objtype::icsupctx, std::move(pctx)});
	return zh_error(*phobject);
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
	return pctx->upload_state(*pstate) ? ecSuccess : ecError;
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
		if (!exmdb_client->is_msg_present(pstore->get_dir(), folder_id,
		    message_id, &b_exist))
			return ecError;
		if (!b_exist)
			return ecNotFound;
	}
	if (!pstore->owner_mode()) {
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
		    nullptr, CP_ACP, message_id, PR_ASSOCIATED, &pvalue))
			return ecError;
		bool orig_is_fai = pvb_enabled(pvalue);
		if (b_fai != orig_is_fai)
			return ecInvalidParam;
	} else {
		if (!exmdb_client->allocate_message_id(pstore->get_dir(),
		    folder_id, &message_id))
			return ecError;
	}
	auto pmessage = message_object::create(pstore, b_new, pinfo->cpid,
	                message_id, &folder_id, tag_access,
	                MAPI_MODIFY, pctx->pstate);
	if (pmessage == nullptr)
		return ecError;
	if (b_new && pmessage->init_message(b_fai, pinfo->cpid) != 0)
		return ecError;
	*phobject = pinfo->ptree->add_object_handle(hctx, {zs_objtype::message, std::move(pmessage)});
	return zh_error(*phobject);
}

ec_error_t zs_importfolder(GUID hsession,
	uint32_t hctx, const TPROPVAL_ARRAY *ppropvals)
{
	XID tmp_xid;
	BOOL b_exist;
	BINARY *pbin;
	BOOL b_guest;
	void *pvalue;
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
	propval_buff[0].pvalue = deconst(ppropvals->getval(PR_PARENT_SOURCE_KEY));
	if (propval_buff[0].pvalue == nullptr)
		return ecInvalidParam;
	propval_buff[1].proptag = PR_SOURCE_KEY;
	propval_buff[1].pvalue = deconst(ppropvals->getval(PR_SOURCE_KEY));
	if (propval_buff[1].pvalue == nullptr)
		return ecInvalidParam;
	propval_buff[2].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[2].pvalue = deconst(ppropvals->getval(PR_LAST_MODIFICATION_TIME));
	if (NULL == propval_buff[2].pvalue) {
		propval_buff[2].pvalue = &nttime;
		nttime = rop_util_current_nttime();
	}
	propval_buff[3].proptag = PR_DISPLAY_NAME;
	propval_buff[3].pvalue = deconst(ppropvals->getval(PR_DISPLAY_NAME));
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
		if (!exmdb_client->is_folder_present(pstore->get_dir(),
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
		if (!exmdb_client_get_folder_property(pstore->get_dir(), CP_ACP,
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
			if (!mysql_adaptor_check_same_org(domain_id, pstore->account_id))
				return ecInvalidParam;
			ec_error_t ret = ecSuccess;
			if (!exmdb_client->get_mapping_replid(pstore->get_dir(),
			    tmp_xid.guid, &replid, &ret))
				return ecError;
			if (ret != ecSuccess)
				return ret;
			folder_id = rop_util_make_eid(replid, tmp_xid.local_to_gc());
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_to_gc());
		}
	}
	if (!exmdb_client->is_folder_present(pstore->get_dir(), folder_id, &b_exist))
		return ecError;
	if (!b_exist) {
		if (!pstore->owner_mode()) {
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
			    parent_id1, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsCreateSubfolder))
				return ecAccessDenied;
		}
		if (!exmdb_client->get_folder_by_name(pstore->get_dir(),
		    parent_id1, static_cast<char *>(pproplist->ppropval[3].pvalue),
		    &tmp_fid))
			return ecError;
		if (tmp_fid != 0)
			return ecDuplicateName;
		if (!exmdb_client->allocate_cn(pstore->get_dir(), &change_num))
			return ecError;
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8 + ppropvals->count);
		if (tmp_propvals.ppropval == nullptr)
			return ecServerOOM;
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
		ec_error_t err = ecSuccess;
		if (!exmdb_client->create_folder(pstore->get_dir(), pinfo->cpid,
		    &tmp_propvals, &tmp_fid, &err))
			return ecError;
		if (err != ecSuccess)
			return err;
		if (folder_id != tmp_fid)
			return ecError;
		pctx->pstate->pseen->append(change_num);
		return ecSuccess;
	}
	if (!pstore->owner_mode()) {
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
		    folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (!exmdb_client_get_folder_property(pstore->get_dir(), CP_ACP,
	    folder_id, PidTagParentFolderId, &pvalue) || pvalue == nullptr)
		return ecError;
	auto parent_id = *static_cast<uint64_t *>(pvalue);
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (!pstore->b_private)
			return ecNotSupported;
		if (rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
			return ecAccessDenied;
		if (!pstore->owner_mode()) {
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
			    parent_id1, pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & frightsCreateSubfolder))
				return ecAccessDenied;
			b_guest = TRUE;
		} else {
			b_guest = FALSE;
		}
		ec_error_t err = ecSuccess;
		if (!exmdb_client->movecopy_folder(pstore->get_dir(),
		    pinfo->cpid, b_guest, pinfo->get_username(), parent_id,
		    folder_id, parent_id1,
		    static_cast<char *>(pproplist->ppropval[3].pvalue), false,
		    &err))
			return ecError;
		if (err != ecSuccess)
			return err;
	}
	if (!exmdb_client->allocate_cn(pstore->get_dir(), &change_num))
		return ecError;
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5 + ppropvals->count);
	if (tmp_propvals.ppropval == nullptr)
		return ecServerOOM;
	tmp_propvals.ppropval[0].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[0].pvalue = pproplist->ppropval[2].pvalue;
	tmp_propvals.ppropval[1].proptag = PR_DISPLAY_NAME;
	tmp_propvals.ppropval[1].pvalue = pproplist->ppropval[3].pvalue;
	tmp_propvals.ppropval[2].proptag = PidTagChangeNumber;
	tmp_propvals.ppropval[2].pvalue = &change_num;
	tmp_propvals.count = 3;
	for (size_t i = 0; i < ppropvals->count; ++i)
		tmp_propvals.ppropval[tmp_propvals.count++] = ppropvals->ppropval[i];
	if (!exmdb_client->set_folder_properties(pstore->get_dir(),
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
	    !exmdb_client->get_folder_perm(pstore->get_dir(),
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
			return ecServerOOM;
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
				if (!mysql_adaptor_check_same_org(domain_id,
				    pstore->account_id))
					return ecInvalidParam;
				ec_error_t ret = ecSuccess;
				if (!exmdb_client->get_mapping_replid(pstore->get_dir(),
				    tmp_xid.guid, &replid, &ret))
					return ecError;
				if (ret != ecSuccess)
					return ret;
				eid = rop_util_make_eid(replid, tmp_xid.local_to_gc());
			} else {
				eid = rop_util_make_eid(1, tmp_xid.local_to_gc());
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (!exmdb_client->is_msg_present(pstore->get_dir(),
			    folder_id, eid, &b_exist))
				return ecError;
		} else {
			if (!exmdb_client->is_folder_present(pstore->get_dir(),
			    eid, &b_exist))
				return ecError;
		}
		if (!b_exist)
			continue;
		if (username != STORE_OWNER_GRANTED) {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				if (!exmdb_client_check_message_owner(pstore->get_dir(),
				    eid, username, &b_owner))
					return ecError;
				if (!b_owner)
					return ecAccessDenied;
			} else if (!exmdb_client->get_folder_perm(pstore->get_dir(),
			    eid, username, &permission) && !(permission & frightsOwner)) {
				return ecAccessDenied;
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			message_ids.pids[message_ids.count++] = eid;
		} else {
			if (pstore->b_private) {
				if (!exmdb_client_get_folder_property(pstore->get_dir(),
				    CP_ACP, eid, PR_FOLDER_TYPE, &pvalue))
					return ecError;
				if (pvalue == nullptr)
					return ecSuccess;
				if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
					goto DELETE_FOLDER;
			}
			{
			unsigned int f = b_hard ? DELETE_HARD_DELETE : 0;
			f |= DEL_MESSAGES | DEL_ASSOCIATED | DEL_FOLDERS;
			if (!exmdb_client->empty_folder(pstore->get_dir(),
			    pinfo->cpid, username, eid, f, &b_partial) ||
			    b_partial)
				return ecError;
			}
 DELETE_FOLDER:
			if (!exmdb_client->delete_folder(pstore->get_dir(),
			    pinfo->cpid, eid, b_hard, &b_result) || !b_result)
				return ecError;
		}
	}
	if (sync_type == SYNC_TYPE_CONTENTS && message_ids.count > 0 &&
	    (!exmdb_client->delete_messages(pstore->get_dir(), pinfo->cpid,
	    nullptr, folder_id, &message_ids, b_hard, &b_partial) || b_partial))
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
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
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
		if (username != STORE_OWNER_GRANTED) {
			if (!exmdb_client_check_message_owner(pstore->get_dir(),
			    message_id, username, &b_owner))
				return ecError;
			if (!b_owner)
				continue;
		}
		static constexpr proptag_t proptag_buff[] = {PR_ASSOCIATED, PR_READ};
		static constexpr PROPTAG_ARRAY tmp_proptags = {std::size(proptag_buff), deconst(proptag_buff)};
		if (!exmdb_client->get_message_properties(pstore->get_dir(),
		    nullptr, CP_ACP, message_id, &tmp_proptags, &tmp_propvals))
			return ecError;
		auto flag = tmp_propvals.get<const uint8_t>(PR_ASSOCIATED);
		if (flag != nullptr && *flag != 0)
			continue;
		flag = tmp_propvals.get<uint8_t>(PR_READ);
		if ((flag != nullptr && *flag != 0) == mark_as_read)
			/* Already set to the value we want it to be */
			continue;
		if (!exmdb_client->set_message_read_state(pstore->get_dir(),
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
	EID_ARRAY folder_ids;
	
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
	if (!exmdb_client->get_search_criteria(pstore->get_dir(),
	    pfolder->folder_id, psearch_stat, pprestriction, &folder_ids))
		return ecError;
	pfolder_array->count = folder_ids.count;
	if (0 == folder_ids.count) {
		pfolder_array->pbin = NULL;
		return ecSuccess;
	}
	pfolder_array->pbin = cu_alloc<BINARY>(folder_ids.count);
	if (pfolder_array->pbin == nullptr)
		return ecServerOOM;
	for (size_t i = 0; i < folder_ids.count; ++i) {
		auto pbin = cu_fid_to_entryid(*pstore, folder_ids.pids[i]);
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
	EID_ARRAY folder_ids;
	
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
		if (!exmdb_client->get_folder_perm(pstore->get_dir(),
		    pfolder->folder_id, pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (NULL == prestriction || 0 == pfolder_array->count) {
		if (!exmdb_client->get_search_criteria(pstore->get_dir(),
		    pfolder->folder_id, &search_status, nullptr, nullptr))
			return ecError;
		if (search_status == SEARCH_STATUS_NOT_INITIALIZED)
			return ecNotInitialized;
		if (!(flags & RESTART_SEARCH) && prestriction == nullptr &&
		    pfolder_array->count == 0)
			return ecSuccess;
	}
	folder_ids.count = pfolder_array->count;
	folder_ids.pids  = cu_alloc<uint64_t>(folder_ids.count);
	if (folder_ids.pids == nullptr)
		return ecServerOOM;
	for (size_t i = 0; i < pfolder_array->count; ++i) {
		if (!cu_entryid_to_fid(pfolder_array->pbin[i],
		    &b_private, &db_id, &folder_ids.pids[i]))
			return ecError;
		if (!b_private || db_id != pstore->account_id)
			return ecSearchFolderScopeViolation;
		if (!pstore->owner_mode()) {
			if (!exmdb_client->get_folder_perm(pstore->get_dir(),
			    folder_ids.pids[i], pinfo->get_username(), &permission))
				return ecError;
			if (!(permission & (frightsOwner | frightsReadAny)))
				return ecAccessDenied;
		}
	}
	if (!exmdb_client->set_search_criteria(pstore->get_dir(), pinfo->cpid,
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
	       pmessage->instance_id, peml_bin) ? ecSuccess : ecError;
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
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> pmsgctnt(cu_rfc822_to_message(pmessage->get_store(), mxf_flags, peml_bin));
	if (pmsgctnt == nullptr)
		return ecError;
	return pmessage->write_message(pmsgctnt.get()) ? ecSuccess : ecError;
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
	auto cl_0 = HX::make_scope_exit([&]() {
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

ec_error_t zs_getuserfreebusy(GUID hsession, BINARY entryid,
    time_t starttime, time_t endtime, std::vector<freebusy_event> *fb_data)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	std::string username;
	sql_meta_result mres;
	if (cvt_entryid_to_smtpaddr(&entryid, g_org_name,
	    mysql_adaptor_userid_to_name, username) != ecSuccess ||
	    mysql_adaptor_meta(username.c_str(), WANTPRIV_METAONLY, mres) != 0)
		return ecSuccess;
	auto actor = pinfo->get_username();
	if (strcmp(actor, mres.username.c_str()) == 0)
		actor = nullptr;
	return get_freebusy(actor, mres.maildir.c_str(),
	       starttime, endtime, *fb_data);
}

ec_error_t zs_getuserfreebusyical(GUID hsession, BINARY entryid,
    time_t starttime, time_t endtime, BINARY *bin)
{
	auto pinfo = zs_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	std::string username;
	sql_meta_result mres;
	if (cvt_entryid_to_smtpaddr(&entryid, g_org_name,
	    mysql_adaptor_userid_to_name, username) != ecSuccess ||
	    mysql_adaptor_meta(username.c_str(), WANTPRIV_METAONLY, mres) != 0)
		return ecSuccess;
	std::vector<freebusy_event> fb_data;
	auto err = get_freebusy(pinfo->get_username(), mres.maildir.c_str(),
	           starttime, endtime, fb_data);
	if (err != ecSuccess)
		return err;
	return cu_fbdata_to_ical(pinfo->get_username(), username.c_str(),
	       starttime, endtime, fb_data, bin);
}

ec_error_t zs_setpasswd(const char *username,
	const char *passwd, const char *new_passwd)
{
	return mysql_adaptor_setpasswd(username, passwd, new_passwd) ?
	       ecSuccess : ecAccessDenied;
}

ec_error_t zs_linkmessage(GUID hsession,
	BINARY search_entryid, BINARY message_entryid)
{
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
	if (zh_is_error(handle))
		return zh_error(handle);
	if (pinfo->user_id < 0)
		return ecAccessDenied;
	auto pstore = pinfo->ptree->get_object<store_object>(handle, &mapi_type);
	if (pstore == nullptr || mapi_type != zs_objtype::store)
		return ecError;
	if (!pstore->owner_mode()) {
		uint32_t permission = rightsNone;
		if (!exmdb_client->get_folder_perm(pstore->get_dir(), folder_id,
		    pinfo->get_username(), &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
	}
	gx_strlcpy(maildir, pstore->get_dir(), std::size(maildir));
	auto cpid = pinfo->cpid;
	pinfo.reset();
	return exmdb_client->link_message(maildir, cpid, folder_id, message_id,
	       &b_result) && b_result ? ecSuccess : ecError;
}

ec_error_t zs_essdn_to_username(const char *essdn, char **username)
{
	std::string es_result;
	auto ret = cvt_essdn_to_username(essdn, g_org_name, mysql_adaptor_userid_to_name, es_result);
	if (ret != ecSuccess)
		return ret;
	*username = common_util_dup(es_result);
	return *username != nullptr ? ecSuccess : ecServerOOM;
}
