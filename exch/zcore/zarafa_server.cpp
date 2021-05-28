// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <sys/wait.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/zcore_rpc.hpp>
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include "rpc_ext.h"
#include "ab_tree.h"
#include <gromox/rop_util.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/ext_buffer.hpp>
#include "user_object.h"
#include "common_util.h"
#include "table_object.h"
#include "zarafa_server.h"
#include "folder_object.h"
#include "message_object.h"
#include "system_services.h"
#include "icsupctx_object.h"
#include "container_object.h"
#include "icsdownctx_object.h"
#include "attachment_object.h"
#include "exmdb_client.h"
#include <gromox/idset.hpp>
#include <sys/socket.h>
#include <cstdio>
#include <poll.h>

namespace {

struct NOTIFY_ITEM {
	DOUBLE_LIST notify_list;
	GUID hsession;
	uint32_t hstore;
	time_t last_time;
};

struct SINK_NODE {
	DOUBLE_LIST_NODE node;
	int clifd;
	time_t until_time;
	NOTIF_SINK sink;
};

struct user_info_del {
	void operator()(USER_INFO *x);
};

}

using USER_INFO_REF = std::unique_ptr<USER_INFO, user_info_del>;

static int g_table_size;
static std::atomic<bool> g_notify_stop{false};
static int g_ping_interval;
static pthread_t g_scan_id;
static int g_cache_interval;
static pthread_key_t g_info_key;
static std::mutex g_table_lock, g_notify_lock;
static STR_HASH_TABLE *g_user_table;
static STR_HASH_TABLE *g_notify_table;
static INT_HASH_TABLE *g_session_table;

static int zarafa_server_get_user_id(GUID hsession)
{
	int user_id;
	
	memcpy(&user_id, hsession.node, sizeof(int));
	return user_id;
}

static USER_INFO_REF zarafa_server_query_session(GUID hsession)
{
	int user_id;
	
	user_id = zarafa_server_get_user_id(hsession);
	std::unique_lock tl_hold(g_table_lock);
	auto pinfo = static_cast<USER_INFO *>(int_hash_query(g_session_table, user_id));
	if (pinfo == nullptr || guid_compare(&hsession, &pinfo->hsession) != 0)
		return nullptr;
	pinfo->reference ++;
	time(&pinfo->last_time);
	tl_hold.unlock();
	pthread_mutex_lock(&pinfo->lock);
	pthread_setspecific(g_info_key, pinfo);
	return USER_INFO_REF(pinfo);
}

USER_INFO *zarafa_server_get_info()
{
	return static_cast<USER_INFO *>(pthread_getspecific(g_info_key));
}

void user_info_del::operator()(USER_INFO *pinfo)
{
	pthread_mutex_unlock(&pinfo->lock);
	std::unique_lock tl_hold(g_table_lock);
	pinfo->reference --;
	tl_hold.unlock();
	pthread_setspecific(g_info_key, NULL);
}

static void *zcorezs_scanwork(void *param)
{
	int count;
	int tv_msec;
	BINARY tmp_bin;
	time_t cur_time;
	uint8_t tmp_byte;
	OBJECT_TREE *ptree;
	NOTIFY_ITEM *pnitem;
	INT_HASH_ITER *iter;
	STR_HASH_ITER *iter1;
	struct pollfd fdpoll;
	ZCORE_RPC_RESPONSE response;
	SINK_NODE *psink_node;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST temp_list1;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	
	count = 0;
	double_list_init(&temp_list);
	double_list_init(&temp_list1);
	response.call_id = zcore_callid::NOTIFDEQUEUE;
	response.result = ecSuccess;
	response.payload.notifdequeue.notifications.count = 0;
	response.payload.notifdequeue.notifications.ppnotification = NULL;
	while (!g_notify_stop) {
		sleep(1);
		count ++;
		if (count >= g_ping_interval) {
			count = 0;
		}
		std::unique_lock tl_hold(g_table_lock);
		time(&cur_time);
		iter = int_hash_iter_init(g_session_table);
		for (int_hash_iter_begin(iter);
			FALSE == int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			auto pinfo = static_cast<USER_INFO *>(int_hash_iter_get_value(iter, nullptr));
			if (0 != pinfo->reference) {
				continue;
			}
			ptail = double_list_get_tail(&pinfo->sink_list);
			while ((pnode = double_list_pop_front(&pinfo->sink_list)) != nullptr) {
				psink_node = (SINK_NODE*)pnode->pdata;
				if (cur_time >= psink_node->until_time) {
					double_list_append_as_tail(&temp_list1, pnode);
				} else {
					double_list_append_as_tail(
						&pinfo->sink_list, pnode);
				}
				if (pnode == ptail) {
					break;
				}
			}
			if (cur_time - pinfo->reload_time >= g_cache_interval) {
				common_util_build_environment();
				ptree = object_tree_create(pinfo->maildir);
				if (NULL != ptree) {
					object_tree_free(pinfo->ptree);
					pinfo->ptree = ptree;
					pinfo->reload_time = cur_time;
				}
				common_util_free_environment();
				continue;
			}
			if (cur_time - pinfo->last_time < g_cache_interval) {
				if (0 != count) {
					continue;
				}
				pnode = me_alloc<DOUBLE_LIST_NODE>();
				if (NULL == pnode) {
					continue;
				}
				pnode->pdata = strdup(pinfo->maildir);
				if (NULL == pnode->pdata) {
					free(pnode);
					continue;
				}
				double_list_append_as_tail(&temp_list, pnode);
			} else {
				if (0 != double_list_get_nodes_num(&pinfo->sink_list)) {
					continue;
				}
				common_util_build_environment();
				object_tree_free(pinfo->ptree);
				common_util_free_environment();
				double_list_free(&pinfo->sink_list);
				pthread_mutex_destroy(&pinfo->lock);
				str_hash_remove(g_user_table, pinfo->username);
				int_hash_iter_remove(iter);
			}
		}
		int_hash_iter_free(iter);
		tl_hold.unlock();
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			common_util_build_environment();
			exmdb_client::ping_store(static_cast<char *>(pnode->pdata));
			common_util_free_environment();
			free(pnode->pdata);
			free(pnode);
		}
		while ((pnode = double_list_pop_front(&temp_list1)) != nullptr) {
			psink_node = (SINK_NODE*)pnode->pdata;
			if (TRUE == rpc_ext_push_response(
				&response, &tmp_bin)) {
				tv_msec = SOCKET_TIMEOUT * 1000;
				fdpoll.fd = psink_node->clifd;
				fdpoll.events = POLLOUT|POLLWRBAND;
				if (1 == poll(&fdpoll, 1, tv_msec)) {
					write(psink_node->clifd, tmp_bin.pb, tmp_bin.cb);
				}
				free(tmp_bin.pb);
				shutdown(psink_node->clifd, SHUT_WR);
				if (read(psink_node->clifd, &tmp_byte, 1))
					/* ignore */;
			}
			close(psink_node->clifd);
			free(psink_node->sink.padvise);
			free(psink_node);
		}
		if (0 != count) {
			continue;
		}
		time(&cur_time);
		std::unique_lock nl_hold(g_notify_lock);
		iter1 = str_hash_iter_init(g_notify_table);
		for (str_hash_iter_begin(iter1);
			FALSE == str_hash_iter_done(iter1);
			str_hash_iter_forward(iter1)) {
			pnitem = static_cast<NOTIFY_ITEM *>(str_hash_iter_get_value(iter1, nullptr));
			if (cur_time - pnitem->last_time >= g_cache_interval) {
				while ((pnode = double_list_pop_front(&pnitem->notify_list)) != nullptr) {
					common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
					free(pnode);
				}
				double_list_free(&pnitem->notify_list);
				str_hash_iter_remove(iter1);
			}
		}
	}
	return NULL;
}

static void zarafa_server_notification_proc(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	int i;
	int tv_msec;
	void *pvalue;
	BINARY *pbin;
	GUID hsession;
	BINARY tmp_bin;
	uint32_t hstore;
	uint8_t tmp_byte;
	uint64_t old_eid;
	uint8_t mapi_type;
	char tmp_buff[256];
	NOTIFY_ITEM *pitem;
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t message_id;
	struct pollfd fdpoll;
	STORE_OBJECT *pstore;
	ZCORE_RPC_RESPONSE response;
	SINK_NODE *psink_node;
	uint64_t old_parentid;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	DOUBLE_LIST_NODE *pnode;
	uint32_t proptag_buff[2];
	ZNOTIFICATION *pnotification;
	NEWMAIL_ZNOTIFICATION *pnew_mail;
	OBJECT_ZNOTIFICATION *pobj_notify;
	
	if (TRUE == b_table) {
		return;
	}
	sprintf(tmp_buff, "%u|%s", notify_id, dir);
	std::unique_lock nl_hold(g_notify_lock);
	pitem = static_cast<NOTIFY_ITEM *>(str_hash_query(g_notify_table, tmp_buff));
	if (NULL == pitem) {
		return;
	}
	hsession = pitem->hsession;
	hstore = pitem->hstore;
	nl_hold.unlock();
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore || MAPI_STORE != mapi_type ||
		0 != strcmp(dir, store_object_get_dir(pstore))) {
		return;
	}
	pnotification = cu_alloc<ZNOTIFICATION>();
	if (NULL == pnotification) {
		return;
	}
	switch (pdb_notify->type) {
	case DB_NOTIFY_TYPE_NEW_MAIL: {
		pnotification->event_type = EVENT_TYPE_NEWMAIL;
		pnew_mail = cu_alloc<NEWMAIL_ZNOTIFICATION>();
		if (NULL == pnew_mail) {
			return;
		}
		pnotification->pnotification_data = pnew_mail;
		auto nt = static_cast<DB_NOTIFY_NEW_MAIL *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			return;
		}
		pnew_mail->entryid = *pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pnew_mail->parentid = *pbin;
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_MESSAGECLASS;
		proptag_buff[1] = PROP_TAG_MESSAGEFLAGS;
		if (!exmdb_client::get_message_properties(dir,
			NULL, 0, message_id, &proptags, &propvals)) {
			return;
		}
		pvalue = common_util_get_propvals(
			&propvals, PROP_TAG_MESSAGECLASS);
		if (NULL == pvalue) {
			return;
		}
		pnew_mail->message_class = static_cast<char *>(pvalue);
		pvalue = common_util_get_propvals(
			&propvals, PROP_TAG_MESSAGEFLAGS);
		if (NULL == pvalue) {
			return;
		}
		pnew_mail->message_flags = *(uint32_t*)pvalue;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_CREATED: {
		pnotification->event_type = EVENT_TYPE_OBJECTCREATED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_FOLDER_CREATED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		parent_id = common_util_convert_notification_folder_id(nt->parent_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, parent_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_CREATED: {
		pnotification->event_type = EVENT_TYPE_OBJECTCREATED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_MESSAGE_CREATED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_DELETED: {
		pnotification->event_type = EVENT_TYPE_OBJECTDELETED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_FOLDER_DELETED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		parent_id = common_util_convert_notification_folder_id(nt->parent_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, parent_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_DELETED: {
		pnotification->event_type = EVENT_TYPE_OBJECTDELETED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_MESSAGE_DELETED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED: {
		pnotification->event_type = EVENT_TYPE_OBJECTMODIFIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED: {
		pnotification->event_type = EVENT_TYPE_OBJECTMODIFIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED: {
		pnotification->event_type = pdb_notify->type == DB_NOTIFY_TYPE_FOLDER_MOVED ?
		                            EVENT_TYPE_OBJECTMOVED : EVENT_TYPE_OBJECTCOPIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		parent_id = common_util_convert_notification_folder_id(nt->parent_id);
		old_eid = common_util_convert_notification_folder_id(nt->old_folder_id);
		old_parentid = common_util_convert_notification_folder_id(nt->old_parent_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, parent_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		pbin = common_util_to_folder_entryid(pstore, old_eid);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pold_entryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, old_parentid);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pold_parentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED: {
		pnotification->event_type = pdb_notify->type == DB_NOTIFY_TYPE_MESSAGE_MOVED ?
		                            EVENT_TYPE_OBJECTMOVED : EVENT_TYPE_OBJECTCOPIED;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		old_parentid = common_util_convert_notification_folder_id(nt->old_folder_id);
		old_eid = rop_util_make_eid_ex(1, nt->old_message_id);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		message_id = rop_util_make_eid_ex(1, nt->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(
							pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pparentid = pbin;
		pbin = common_util_to_message_entryid(
				pstore, old_parentid, old_eid);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pold_entryid = pbin;
		pbin = common_util_to_folder_entryid(
						pstore, old_parentid);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pold_parentid = pbin;
		break;
	}
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED: {
		pnotification->event_type = EVENT_TYPE_SEARCHCOMPLETE;
		pobj_notify = cu_alloc<OBJECT_ZNOTIFICATION>();
		if (NULL == pobj_notify) {
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		auto nt = static_cast<DB_NOTIFY_SEARCH_COMPLETED *>(pdb_notify->pdata);
		folder_id = common_util_convert_notification_folder_id(nt->folder_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			return;
		}
		pobj_notify->pentryid = pbin;
		break;
	}
	default:
		return;
	}
	for (pnode=double_list_get_head(&pinfo->sink_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo->sink_list, pnode)) {
		psink_node = (SINK_NODE*)pnode->pdata;
		for (i=0; i<psink_node->sink.count; i++) {
			if (psink_node->sink.padvise[i].sub_id != notify_id ||
			    hstore != psink_node->sink.padvise[i].hstore)
				continue;
			double_list_remove(&pinfo->sink_list, pnode);
			response.call_id = zcore_callid::NOTIFDEQUEUE;
			response.result = ecSuccess;
			response.payload.notifdequeue.notifications.count = 1;
			response.payload.notifdequeue.notifications.ppnotification =
				&pnotification;
			tv_msec = SOCKET_TIMEOUT * 1000;
			fdpoll.fd = psink_node->clifd;
			fdpoll.events = POLLOUT | POLLWRBAND;
			if (FALSE == rpc_ext_push_response(
				&response, &tmp_bin)) {
				tmp_byte = zcore_response::PUSH_ERROR;
				if (1 == poll(&fdpoll, 1, tv_msec)) {
					write(psink_node->clifd, &tmp_byte, 1);
				}
			} else {
				if (1 == poll(&fdpoll, 1, tv_msec)) {
					write(psink_node->clifd, tmp_bin.pb, tmp_bin.cb);
				}
				free(tmp_bin.pb);
			}
			close(psink_node->clifd);
			free(psink_node->sink.padvise);
			free(psink_node);
			return;
		}
	}
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		return;
	}
	pnode->pdata = common_util_dup_znotification(pnotification, FALSE);
	if (NULL == pnode->pdata) {
		free(pnode);
		return;
	}
	nl_hold.lock();
	pitem = static_cast<NOTIFY_ITEM *>(str_hash_query(g_notify_table, tmp_buff));
	if (NULL != pitem) {
		double_list_append_as_tail(&pitem->notify_list, pnode);
	}
	nl_hold.unlock();
	if (NULL == pitem) {
		common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
		free(pnode);
	}
}

void zarafa_server_init(int table_size,
	int cache_interval, int ping_interval)
{
	g_table_size = table_size;
	g_cache_interval = cache_interval;
	g_ping_interval = ping_interval;
	pthread_key_create(&g_info_key, NULL);
}

int zarafa_server_run()
{
	g_session_table = int_hash_init(g_table_size, sizeof(USER_INFO));
	if (NULL == g_session_table) {
		printf("[zarafa_server]: fail to "
			"create session hash table\n");
		return -1;
	}
	g_user_table = str_hash_init(
		g_table_size, sizeof(int), NULL);
	if (NULL == g_user_table) {
		int_hash_free(g_session_table);
		printf("[zarafa_server]: fail to"
			" create user hash table\n");
		return -2;
	}
	g_notify_table = str_hash_init(
		g_table_size, sizeof(NOTIFY_ITEM), NULL);
	if (NULL == g_notify_table) {
		int_hash_free(g_session_table);
		printf("[zarafa_server]: fail to "
			"create notify hash table\n");
		return -3;
	}
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, zcorezs_scanwork, nullptr);
	if (ret != 0) {
		printf("[zarafa_server]: E-1443: pthread_create: %s\n", strerror(ret));
		str_hash_free(g_user_table);
		int_hash_free(g_session_table);
		return -4;
	}
	pthread_setname_np(g_scan_id, "zarafa");
	exmdb_client_register_proc(reinterpret_cast<void *>(zarafa_server_notification_proc));
	return 0;
}

int zarafa_server_stop()
{
	INT_HASH_ITER *iter;
	SINK_NODE *psink_node;
	DOUBLE_LIST_NODE *pnode;
	
	g_notify_stop = true;
	pthread_kill(g_scan_id, SIGALRM);
	pthread_join(g_scan_id, NULL);
	iter = int_hash_iter_init(g_session_table);
	for (int_hash_iter_begin(iter);
		FALSE == int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		auto pinfo = static_cast<USER_INFO *>(int_hash_iter_get_value(iter, nullptr));
		while ((pnode = double_list_pop_front(&pinfo->sink_list)) != nullptr) {
			psink_node = (SINK_NODE*)pnode->pdata;
			close(psink_node->clifd);
			free(psink_node->sink.padvise);
			free(psink_node);
		}
		double_list_free(&pinfo->sink_list);
		common_util_build_environment();
		object_tree_free(pinfo->ptree);
		common_util_free_environment();
	}
	int_hash_iter_free(iter);
	int_hash_free(g_session_table);
	str_hash_free(g_user_table);
	str_hash_free(g_notify_table);
	return 0;
}

void zarafa_server_free()
{
	pthread_key_delete(g_info_key);
}

int zarafa_server_get_param(int param)
{
	switch (param) {
	case USER_TABLE_SIZE:
		return g_table_size;
	case USER_TABLE_USED:
		return g_user_table->item_num;
	default:
		return -1;
	}
}

uint32_t zarafa_server_logon(const char *username,
	const char *password, uint32_t flags, GUID *phsession)
{
	int org_id;
	int user_id;
	int *puser_id;
	int domain_id;
	char lang[32];
	char charset[64];
	char reason[256];
	char homedir[256];
	char maildir[256];
	char tmp_name[UADDR_SIZE];
	USER_INFO tmp_info;
	
	auto pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		return ecUnknownUser;
	}
	pdomain ++;
	if (NULL != password) {
		if (FALSE == system_services_auth_login(
			username, password, maildir, lang,
			reason, 256)) {
			return ecLoginFailure;
		}
	}
	gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
	HX_strlower(tmp_name);
	std::unique_lock tl_hold(g_table_lock);
	puser_id = static_cast<int *>(str_hash_query(g_user_table, tmp_name));
	if (NULL != puser_id) {
		user_id = *puser_id;
		auto pinfo = static_cast<USER_INFO *>(int_hash_query(g_session_table, user_id));
		if (NULL != pinfo) {
			time(&pinfo->last_time);
			*phsession = pinfo->hsession;
			return ecSuccess;
		}
		str_hash_remove(g_user_table, tmp_name);
	}
	tl_hold.unlock();
	if (FALSE == system_services_get_id_from_username(
		username, &user_id) ||
		FALSE == system_services_get_homedir(
		pdomain, homedir) ||
		FALSE == system_services_get_domain_ids(
		pdomain, &domain_id, &org_id)) {
		return ecError;
	}
	if (NULL == password) {
		if (FALSE == system_services_get_maildir(
			username, maildir) ||
			FALSE == system_services_get_user_lang(
			username, lang)) {
			return ecError;
		}
	}
	tmp_info.reference = 0;
	tmp_info.hsession = guid_random_new();
	memcpy(tmp_info.hsession.node, &user_id, sizeof(int));
	tmp_info.user_id = user_id;
	tmp_info.domain_id = domain_id;
	tmp_info.org_id = org_id;
	gx_strlcpy(tmp_info.username, username, GX_ARRAY_SIZE(tmp_info.username));
	HX_strlower(tmp_info.username);
	strcpy(tmp_info.lang, lang);
	tmp_info.cpid = !system_services_lang_to_charset(lang, charset) ? 1252 :
	                system_services_charset_to_cpid(charset);
	strcpy(tmp_info.maildir, maildir);
	strcpy(tmp_info.homedir, homedir);
	tmp_info.flags = flags;
	time(&tmp_info.last_time);
	tmp_info.reload_time = tmp_info.last_time;
	double_list_init(&tmp_info.sink_list);
	tmp_info.ptree = object_tree_create(maildir);
	if (NULL == tmp_info.ptree) {
		return ecError;
	}
	tl_hold.lock();
	auto pinfo = static_cast<USER_INFO *>(int_hash_query(g_session_table, user_id));
	if (NULL != pinfo) {
		*phsession = pinfo->hsession;
		tl_hold.unlock();
		object_tree_free(tmp_info.ptree);
		return ecSuccess;
	}
	if (1 != int_hash_add(g_session_table, user_id, &tmp_info)) {
		tl_hold.unlock();
		object_tree_free(tmp_info.ptree);
		return ecError;
	}
	if (1 != str_hash_add(g_user_table, tmp_name, &user_id)) {
		int_hash_remove(g_session_table, user_id);
		tl_hold.unlock();
		object_tree_free(tmp_info.ptree);
		return ecError;
	}
	pinfo = static_cast<USER_INFO *>(int_hash_query(g_session_table, user_id));
	pthread_mutex_init(&pinfo->lock, NULL);
	*phsession = tmp_info.hsession;
	return ecSuccess;
}

uint32_t zarafa_server_checksession(GUID hsession)
{
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	return ecSuccess;
}

uint32_t zarafa_server_uinfo(const char *username, BINARY *pentryid,
	char **ppdisplay_name, char **ppx500dn, uint32_t *pprivilege_bits)
{
	char x500dn[1024];
	EXT_PUSH ext_push;
	char display_name[1024];
	ADDRESSBOOK_ENTRYID tmp_entryid;
	
	if (FALSE == system_services_get_user_displayname(
		username, display_name) ||
		FALSE == system_services_get_user_privilege_bits(
		username, pprivilege_bits) || FALSE ==
	    common_util_username_to_essdn(username, x500dn, GX_ARRAY_SIZE(x500dn)))
		return ecNotFound;
	tmp_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
							tmp_entryid.provider_uid);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER;
	tmp_entryid.px500dn = x500dn;
	pentryid->pv = common_util_alloc(1280);
	if (pentryid->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pentryid->pb, 1280, EXT_FLAG_UTF16))
		return ecError;
	if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
		&ext_push, &tmp_entryid)) {
		return ecError;
	}
	pentryid->cb = ext_push.offset;
	*ppdisplay_name = common_util_dup(display_name);
	*ppx500dn = common_util_dup(x500dn);
	if (NULL == *ppdisplay_name || NULL == *ppx500dn) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_unloadobject(GUID hsession, uint32_t hobject)
{
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	object_tree_release_object_handle(pinfo->ptree, hobject);
	return ecSuccess;
}


uint32_t zarafa_server_openentry(GUID hsession, BINARY entryid,
	uint32_t flags, uint8_t *pmapi_type, uint32_t *phobject)
{
	int user_id;
	uint64_t eid;
	uint16_t type;
	BOOL b_private;
	int account_id;
	uint32_t handle;
	char essdn[1024];
	uint8_t loc_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t address_type;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	type = common_util_get_messaging_entryid_type(entryid);
	switch (type) {
	case EITLT_PRIVATE_FOLDER:
	case EITLT_PUBLIC_FOLDER:
		if (FALSE == common_util_from_folder_entryid(
			entryid, &b_private, &account_id, &folder_id)) {
			break;
		}
		handle = object_tree_get_store_handle(
			pinfo->ptree, b_private, account_id);
		pinfo.reset();
		if (INVALID_HANDLE == handle) {
			return ecNullObject;
		}
		return zarafa_server_openstoreentry(hsession,
			handle, entryid, flags, pmapi_type, phobject);
	case EITLT_PRIVATE_MESSAGE:
	case EITLT_PUBLIC_MESSAGE:
		if (FALSE == common_util_from_message_entryid(
			entryid, &b_private, &account_id, &folder_id,
			&message_id)) {
			break;
		}
		handle = object_tree_get_store_handle(
			pinfo->ptree, b_private, account_id);
		pinfo.reset();
		if (INVALID_HANDLE == handle) {
			return ecNullObject;
		}
		return zarafa_server_openstoreentry(hsession,
			handle, entryid, flags, pmapi_type, phobject);
	}
	if (strncmp(entryid.pc, "/exmdb=", 7) == 0) {
		gx_strlcpy(essdn, entryid.pc, sizeof(essdn));
	} else if (common_util_parse_addressbook_entryid(entryid, &address_type,
	    essdn, GX_ARRAY_SIZE(essdn)) && strncmp(essdn, "/exmdb=", 7) == 0 &&
	    ADDRESSBOOK_ENTRYID_TYPE_REMOTE_USER == address_type) {
		/* do nothing */	
	} else {
		return ecInvalidParam;
	}
	if (FALSE == common_util_exmdb_locinfo_from_string(
		essdn + 7, &loc_type, &user_id, &eid)) {
		return ecNotFound;
	}
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
	
	handle = object_tree_get_store_handle(
		pinfo->ptree, b_private, user_id);
	pinfo.reset();
	return zarafa_server_openstoreentry(hsession,
		handle, entryid, flags, pmapi_type, phobject);
}

uint32_t zarafa_server_openstoreentry(GUID hsession,
	uint32_t hobject, BINARY entryid, uint32_t flags,
	uint8_t *pmapi_type, uint32_t *phobject)
{
	BOOL b_del;
	BOOL b_owner;
	BOOL b_exist;
	void *pvalue;
	uint64_t eid;
	uint16_t type;
	BOOL b_private;
	int account_id;
	char essdn[1024];
	uint64_t fid_val;
	uint8_t loc_type;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t tag_access;
	uint32_t permission;
	uint32_t folder_type;
	STORE_OBJECT *pstore;
	uint32_t address_type;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hobject, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	if (0 == entryid.cb) {
		folder_id = rop_util_make_eid_ex(1, store_object_check_private(pstore) ?
		            PRIVATE_FID_ROOT : PUBLIC_FID_ROOT);
		message_id = 0;
	} else {
		type = common_util_get_messaging_entryid_type(entryid);
		switch (type) {
		case EITLT_PRIVATE_FOLDER:
		case EITLT_PUBLIC_FOLDER:
			if (TRUE == common_util_from_folder_entryid(
				entryid, &b_private, &account_id, &folder_id)) {
				message_id = 0;
				goto CHECK_LOC;
			}
			break;
		case EITLT_PRIVATE_MESSAGE:
		case EITLT_PUBLIC_MESSAGE:
			if (TRUE == common_util_from_message_entryid(
				entryid, &b_private, &account_id, &folder_id,
				&message_id)) {
				goto CHECK_LOC;
			}
			break;
		}
		if (strncmp(entryid.pc, "/exmdb=", 7) == 0) {
			gx_strlcpy(essdn, entryid.pc, sizeof(essdn));
		} else if (common_util_parse_addressbook_entryid(entryid,
		     &address_type, essdn, GX_ARRAY_SIZE(essdn)) &&
		     strncmp(essdn, "/exmdb=", 7) == 0 &&
		     ADDRESSBOOK_ENTRYID_TYPE_REMOTE_USER == address_type) {
			/* do nothing */	
		} else {
			return ecInvalidParam;
		}
		if (FALSE == common_util_exmdb_locinfo_from_string(
			essdn + 7, &loc_type, &account_id, &eid)) {
			return ecNotFound;
		}
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
			if (FALSE == exmdb_client_get_message_property(
				store_object_get_dir(pstore), NULL, 0,
				message_id, PROP_TAG_PARENTFOLDERID,
				&pvalue) || NULL == pvalue) {
				return ecError;
			}
			folder_id = *(uint64_t*)pvalue;
		}
 CHECK_LOC:
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore)) {
			return ecInvalidParam;
		}
	}
	if (0 != message_id) {
		if (!exmdb_client::check_message_deleted(
			store_object_get_dir(pstore), message_id, &b_del)) {
			return ecError;
		}
		if (TRUE == b_del && 0 == (flags & FLAG_SOFT_DELETE)) {
			return ecNotFound;
		}
		tag_access = 0;
		if (TRUE == store_object_check_owner_mode(pstore)) {
			tag_access = TAG_ACCESS_MODIFY|
				TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			goto PERMISSION_CHECK;
		}
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			return ecError;
		}
		if (!(permission & (PERMISSION_READANY |
		    PERMISSION_FOLDERVISIBLE | PERMISSION_FOLDEROWNER)))
			return ecAccessDenied;
		if (permission & PERMISSION_FOLDEROWNER) {
			tag_access = TAG_ACCESS_MODIFY|
				TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			goto PERMISSION_CHECK;
		}
		if (FALSE == exmdb_client_check_message_owner(
			store_object_get_dir(pstore), message_id,
			pinfo->username, &b_owner)) {
			return ecError;
		}
		if (TRUE == b_owner || (permission & PERMISSION_READANY)) {
			tag_access |= TAG_ACCESS_READ;
		}
		if ((permission & PERMISSION_EDITANY)
			|| (TRUE == b_owner &&
			(permission & PERMISSION_EDITOWNED))) {
			tag_access |= TAG_ACCESS_MODIFY;	
		}
		if ((permission & PERMISSION_DELETEANY)
			|| (TRUE == b_owner &&
			(permission & PERMISSION_DELETEOWNED))) {
			tag_access |= TAG_ACCESS_DELETE;	
		}
 PERMISSION_CHECK:
		if (0 == (TAG_ACCESS_READ & tag_access)) {
			return ecAccessDenied;
		}
		BOOL b_writable = !(tag_access & TAG_ACCESS_MODIFY) ? false : TRUE;
		auto pmessage = message_object_create(pstore, false,
		                pinfo->cpid, message_id, &folder_id, tag_access,
		                b_writable, nullptr);
		if (NULL == pmessage) {
			return ecError;
		}
		*phobject = object_tree_add_object_handle(pinfo->ptree,
		            hobject, MAPI_MESSAGE, pmessage.get());
		if (INVALID_HANDLE == *phobject) {
			return ecError;
		}
		pmessage.release();
		*pmapi_type = MAPI_MESSAGE;
	} else {
		if (!exmdb_client::check_folder_id(
			store_object_get_dir(pstore), folder_id,
			&b_exist)) {
			return ecError;
		}
		if (FALSE == b_exist) {
			return ecNotFound;
		}
		if (FALSE == store_object_check_private(pstore)) {
			if (!exmdb_client::check_folder_deleted(
				store_object_get_dir(pstore), folder_id, &b_del)) {
				return ecError;
			}
			if (TRUE == b_del && 0 == (flags & FLAG_SOFT_DELETE)) {
				return ecNotFound;
			}
		}
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue) || NULL == pvalue) {
			return ecError;
		}
		folder_type = *(uint32_t*)pvalue;
		if (TRUE == store_object_check_owner_mode(pstore)) {
			tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
					TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
					TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
		} else {
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pstore), folder_id,
				pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == permission) {
				fid_val = rop_util_get_gc_value(folder_id);
				if (TRUE == store_object_check_private(pstore)) {
					if (PRIVATE_FID_ROOT == fid_val ||
						PRIVATE_FID_IPMSUBTREE == fid_val) {
						permission = PERMISSION_FOLDERVISIBLE;
					}
				} else {
					if (PUBLIC_FID_ROOT == fid_val) {
						permission = PERMISSION_FOLDERVISIBLE;
					}
				}
			}
			if (!(permission & (PERMISSION_READANY |
			    PERMISSION_FOLDERVISIBLE | PERMISSION_FOLDEROWNER)))
				return ecNotFound;
			if (permission & PERMISSION_FOLDEROWNER) {
				tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
					TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
					TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
			} else {
				tag_access = TAG_ACCESS_READ;
				if (permission & PERMISSION_CREATE) {
					tag_access |= TAG_ACCESS_CONTENTS |
								TAG_ACCESS_FAI_CONTENTS;
				}
				if (permission & PERMISSION_CREATESUBFOLDER) {
					tag_access |= TAG_ACCESS_HIERARCHY;
				}
			}
		}
		auto pfolder = folder_object_create(pstore,
			folder_id, folder_type, tag_access);
		if (NULL == pfolder) {
			return ecError;
		}
		*phobject = object_tree_add_object_handle(pinfo->ptree,
		            hobject, MAPI_FOLDER, pfolder.get());
		if (INVALID_HANDLE == *phobject) {
			return ecError;
		}
		pfolder.release();
		*pmapi_type = MAPI_FOLDER;
	}
	return ecSuccess;
}

uint32_t zarafa_server_openabentry(GUID hsession,
	BINARY entryid, uint8_t *pmapi_type, uint32_t *phobject)
{
	GUID guid;
	int user_id;
	uint8_t type;
	void *pobject;
	int domain_id;
	uint32_t minid;
	uint8_t loc_type;
	char essdn[1024];
	char tmp_buff[16];
	uint32_t address_type;
	SIMPLE_TREE_NODE *pnode;
	CONTAINER_ID container_id;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	int base_id = pinfo->org_id == 0 ? -pinfo->domain_id : pinfo->org_id;
	if (0 == entryid.cb) {
		container_id.abtree_id.base_id = base_id;
		container_id.abtree_id.minid = 0xFFFFFFFF;
		pobject = container_object_create(
			CONTAINER_TYPE_ABTREE, container_id);
		if (NULL == pobject) {
			return ecError;
		}
		*pmapi_type = MAPI_ABCONT;
		*phobject = object_tree_add_object_handle(
			pinfo->ptree, ROOT_HANDLE, *pmapi_type, pobject);
		if (INVALID_HANDLE == *phobject) {
			container_object_free(static_cast<CONTAINER_OBJECT *>(pobject));
			return ecError;
		}
		return ecSuccess;
	}
	if (common_util_parse_addressbook_entryid(entryid, &address_type,
	    essdn, GX_ARRAY_SIZE(essdn))) {
		if (ADDRESSBOOK_ENTRYID_TYPE_CONTAINER == address_type) {
			HX_strlower(essdn);
			if ('\0' == essdn[0]) {
				type = CONTAINER_TYPE_ABTREE;
				container_id.abtree_id.base_id = base_id;
				container_id.abtree_id.minid = 0xFFFFFFFF;;
			} else if (0 == strcmp(essdn, "/")) {
				type = CONTAINER_TYPE_ABTREE;
				container_id.abtree_id.base_id = base_id;
				container_id.abtree_id.minid = 0;
			} else {
				if (0 == strncmp(essdn, "/exmdb=", 7)) {
					if (FALSE == common_util_exmdb_locinfo_from_string(
						essdn + 7, &loc_type, &user_id,
						&container_id.exmdb_id.folder_id) ||
						LOC_TYPE_PRIVATE_FOLDER != loc_type) {
						return ecNotFound;
					}
					container_id.exmdb_id.b_private = TRUE;
					type = CONTAINER_TYPE_FOLDER;
				} else {
					if (0 != strncmp(essdn, "/guid=", 6) || 38 != strlen(essdn)) {
						return ecNotFound;
					}
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
					pnode = ab_tree_guid_to_node(pbase.get(), guid);
					if (NULL == pnode) {
						return ecNotFound;
					}
					minid = ab_tree_get_node_minid(pnode);
					type = CONTAINER_TYPE_ABTREE;
					container_id.abtree_id.base_id = base_id;
					container_id.abtree_id.minid = minid;
				}
			}
			pobject = container_object_create(type, container_id);
			if (NULL == pobject) {
				return ecError;
			}
			*pmapi_type = MAPI_ABCONT;
		} else if (ADDRESSBOOK_ENTRYID_TYPE_DLIST == address_type ||
			ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER == address_type) {
			if (FALSE == common_util_essdn_to_ids(
				essdn, &domain_id, &user_id)) {
				return ecNotFound;
			}
			if (domain_id != pinfo->domain_id && FALSE ==
				system_services_check_same_org(domain_id,
				pinfo->domain_id)) {
				base_id = -domain_id;
			}
			minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, user_id);
			pobject = user_object_create(base_id, minid);
			if (NULL == pobject) {
				return ecError;
			}
			if (!user_object_check_valid(static_cast<USER_OBJECT *>(pobject))) {
				pinfo.reset();
				user_object_free(static_cast<USER_OBJECT *>(pobject));
				return ecNotFound;
			}
			*pmapi_type = address_type == ADDRESSBOOK_ENTRYID_TYPE_DLIST ?
			              MAPI_DISTLIST : MAPI_MAILUSER;
		} else {
			return ecInvalidParam;
		}
	} else {
		return ecInvalidParam;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree,
						ROOT_HANDLE, *pmapi_type, pobject);
	pinfo.reset();
	if (INVALID_HANDLE == *phobject) {
		switch (*pmapi_type) {
		case MAPI_ABCONT:
			container_object_free(static_cast<CONTAINER_OBJECT *>(pobject));
			break;
		case MAPI_MAILUSER:
			user_object_free(static_cast<USER_OBJECT *>(pobject));
			break;
		}
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set)
{
	char *pstring;
	SINGLE_LIST temp_list;
	PROPTAG_ARRAY proptags;
	SINGLE_LIST result_list;
	SINGLE_LIST_NODE *pnode;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	int base_id = pinfo->org_id == 0 ? -pinfo->domain_id : pinfo->org_id;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr)
		return ecError;
	single_list_init(&result_list);
	for (size_t i = 0; i < pcond_set->count; ++i) {
		pstring = static_cast<char *>(common_util_get_propvals(
		          pcond_set->pparray[i], PROP_TAG_DISPLAYNAME));
		if (NULL == pstring) {
			presult_set->count = 0;
			presult_set->pparray = NULL;
			return ecSuccess;
		}
		if (!ab_tree_resolvename(pbase.get(), pinfo->cpid, pstring, &temp_list))
			return ecError;
		switch (single_list_get_nodes_num(&temp_list)) {
		case 0:
			return ecNotFound;
		case 1:
			break;
		default:
			return ecAmbiguousRecip;
		}
		while ((pnode = single_list_pop_front(&temp_list)) != nullptr)
			single_list_append_as_tail(&result_list, pnode);
	}
	presult_set->count = 0;
	if (0 == single_list_get_nodes_num(&result_list)) {
		presult_set->pparray = NULL;
		return ecNotFound;
	}
	presult_set->pparray = cu_alloc<TPROPVAL_ARRAY *>(single_list_get_nodes_num(&result_list));
	if (NULL == presult_set->pparray) {
		return ecError;
	}
	container_object_get_user_table_all_proptags(&proptags);
	for (pnode=single_list_get_head(&result_list); NULL!=pnode;
		pnode=single_list_get_after(&result_list, pnode)) {
		presult_set->pparray[presult_set->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == presult_set->pparray[presult_set->count] ||
		    !ab_tree_fetch_node_properties(static_cast<SIMPLE_TREE_NODE *>(pnode->pdata),
		    &proptags, presult_set->pparray[presult_set->count])) {
			return ecError;
		}
		presult_set->count ++;
	}
	return ecSuccess;
}

uint32_t zarafa_server_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set)
{
	void *pobject;
	uint8_t mapi_type;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		pperm_set->count = 0;
		return ecNullObject;
	}
	switch (mapi_type) {
	case MAPI_STORE:
		if (!store_object_get_permissions(static_cast<STORE_OBJECT *>(pobject), pperm_set)) {
			return ecError;
		}
		break;
	case MAPI_FOLDER:
		if (!folder_object_get_permissions(static_cast<FOLDER_OBJECT *>(pobject), pperm_set)) {
			return ecError;
		}
		break;
	default:
		return ecNotSupported;
	}
	return ecSuccess;
}

uint32_t zarafa_server_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset)
{
	uint8_t mapi_type;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == folder_object_set_permissions(pfolder, pset)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_modifyrules(GUID hsession,
	uint32_t hfolder, uint32_t flags, const RULE_LIST *plist)
{
	int i;
	uint8_t mapi_type;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	if (MODIFY_RULES_FLAG_REPLACE & flags) {
		for (i=0; i<plist->count; i++) {
			if (plist->prule[i].flags != RULE_DATA_FLAG_ADD_ROW) {
				return ecInvalidParam;
			}
		}
	}
	if (FALSE == folder_object_updaterules(pfolder, flags, plist)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_getabgal(GUID hsession, BINARY *pentryid)
{
	void *pvalue;
	
	if (FALSE == container_object_fetch_special_property(
		SPECIAL_CONTAINER_GAL, PROP_TAG_ENTRYID, &pvalue)) {
		return ecError;
	}
	if (NULL == pvalue) {
		return ecNotFound;
	}
	pentryid->cb = ((BINARY*)pvalue)->cb;
	pentryid->pb = ((BINARY*)pvalue)->pb;
	return ecSuccess;
}

uint32_t zarafa_server_loadstoretable(
	GUID hsession, uint32_t *phobject)
{
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = table_object_create(NULL, NULL, STORE_TABLE, 0);
	if (NULL == ptable) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, ROOT_HANDLE, MAPI_TABLE,
		ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_openstore(GUID hsession,
	BINARY entryid, uint32_t *phobject)
{
	int user_id;
	char dir[256];
	EXT_PULL ext_pull;
	char username[UADDR_SIZE];
	uint32_t permission;
	uint8_t provider_uid[16];
	STORE_ENTRYID store_entryid = {};
	
	ext_buffer_pull_init(&ext_pull, entryid.pb,
		entryid.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_store_entryid(
		&ext_pull, &store_entryid)) {
		return ecError;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	rop_util_get_provider_uid(
		PROVIDER_UID_WRAPPED_PUBLIC, provider_uid);
	if (0 == memcmp(store_entryid.wrapped_provider_uid,
		provider_uid, 16)) {
		*phobject = object_tree_get_store_handle(
			pinfo->ptree, FALSE, pinfo->domain_id);
	} else {
		if (FALSE == common_util_essdn_to_uid(
			store_entryid.pmailbox_dn, &user_id)) {
			return ecNotFound;
		}
		if (pinfo->user_id != user_id) {
			if (!system_services_get_username_from_id(user_id,
			    username, GX_ARRAY_SIZE(username)) ||
				FALSE == system_services_get_maildir(
				username, dir)) {
				return ecError;
			}
			if (!exmdb_client::check_mailbox_permission(
				dir, pinfo->username, &permission)) {
				return ecError;
			}
			if (PERMISSION_NONE == permission) {
				return ecLoginPerm;
			}
		}
		*phobject = object_tree_get_store_handle(
					pinfo->ptree, TRUE, user_id);
	}
	if (INVALID_HANDLE == *phobject) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_openpropfilesec(GUID hsession,
	const FLATUID *puid, uint32_t *phobject)
{
	GUID guid;
	BINARY bin;
	TPROPVAL_ARRAY *ppropvals;
	
	bin.cb = 16;
	bin.pv = deconst(puid);
	guid = rop_util_binary_to_guid(&bin);
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ppropvals = object_tree_get_profile_sec(pinfo->ptree, guid);
	if (NULL == ppropvals) {
		return ecNotFound;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree,
				ROOT_HANDLE, MAPI_PROFPROPERTY, ppropvals);
	return ecSuccess;
}

uint32_t zarafa_server_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	void *pobject;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (mapi_type) {
	case MAPI_FOLDER:
		pstore = folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject));
		ptable = table_object_create(pstore,
			pobject, HIERARCHY_TABLE, flags);
		break;
	case MAPI_ABCONT:
		ptable = table_object_create(NULL,
			pobject, CONTAINER_TABLE, flags);
		break;
	default:
		return ecNotSupported;
	}
	if (NULL == ptable) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hfolder, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	void *pobject;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (mapi_type) {
	case MAPI_FOLDER:
		pstore = folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject));
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (!exmdb_client::check_folder_permission(store_object_get_dir(pstore),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
			    pinfo->username, &permission)) {
				return ecNotFound;
			}
			if (!(permission & (PERMISSION_READANY | PERMISSION_FOLDEROWNER)))
				return ecNotFound;
		}
		ptable = table_object_create(
		         folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject)),
			pobject, CONTENT_TABLE, flags);
		break;
	case MAPI_ABCONT:
		ptable = table_object_create(NULL,
				pobject, USER_TABLE, 0);
		break;
	default:
		return ecNotSupported;
	}
	if (NULL == ptable) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hfolder, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	ptable = table_object_create(
		message_object_get_store(pmessage),
		pmessage, RECIPIENT_TABLE, 0);
	if (NULL == ptable) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hmessage, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_loadruletable(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint8_t mapi_type;
	uint64_t folder_id;
	TABLE_OBJECT *ptable;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	folder_id = folder_object_get_id(pfolder);
	ptable = table_object_create(
		folder_object_get_store(pfolder),
		&folder_id, RULE_TABLE, 0);
	if (NULL == ptable) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hfolder, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_createmessage(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	void *pvalue;
	uint32_t hstore;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t tag_access;
	uint32_t permission;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	folder_id = folder_object_get_id(pfolder);
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		return ecNullObject;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (!(permission & (PERMISSION_FOLDEROWNER | PERMISSION_CREATE)))
			return ecNotFound;
		tag_access = TAG_ACCESS_MODIFY|TAG_ACCESS_READ;
		if (permission & (PERMISSION_DELETEOWNED | PERMISSION_DELETEANY))
			tag_access |= TAG_ACCESS_DELETE;
	} else {
		tag_access = TAG_ACCESS_MODIFY|
			TAG_ACCESS_READ|TAG_ACCESS_DELETE;
	}
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MESSAGESIZEEXTENDED;
	proptag_buff[1] = PROP_TAG_STORAGEQUOTALIMIT;
	proptag_buff[2] = PROP_TAG_ASSOCIATEDCONTENTCOUNT;
	proptag_buff[3] = PROP_TAG_CONTENTCOUNT;
	if (FALSE == store_object_get_properties(
		pstore, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}
	pvalue = common_util_get_propvals(&tmp_propvals, PROP_TAG_STORAGEQUOTALIMIT);
	int64_t max_quota = pvalue == nullptr ? -1 : static_cast<int64_t>(*static_cast<uint32_t *>(pvalue)) * 1024;
	pvalue = common_util_get_propvals(&tmp_propvals,
					PROP_TAG_MESSAGESIZEEXTENDED);
	uint64_t total_size = pvalue == nullptr ? 0 : *static_cast<uint64_t *>(pvalue);
	if (max_quota > 0 && total_size > static_cast<uint64_t>(max_quota)) {
		return ecQuotaExceeded;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
					PROP_TAG_ASSOCIATEDCONTENTCOUNT);
	uint32_t total_mail = pvalue != nullptr ? *static_cast<uint32_t *>(pvalue) : 0;
	pvalue = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_CONTENTCOUNT);
	if (NULL != pvalue) {
		total_mail += *(uint32_t*)pvalue;
	}
	if (total_mail > common_util_get_param(
		COMMON_UTIL_MAX_MESSAGE)) {
		return ecQuotaExceeded;
	}
	if (!exmdb_client::allocate_message_id(
		store_object_get_dir(pstore), folder_id,
		&message_id)) {
		return ecError;
	}
	auto pmessage = message_object_create(pstore, TRUE,
			pinfo->cpid, message_id, &folder_id,
			tag_access, TRUE, NULL);
	if (NULL == pmessage) {
		return ecError;
	}
	BOOL b_fai = (flags & FLAG_ASSOCIATED) ? TRUE : false;
	if (!message_object_init_message(pmessage.get(), b_fai, pinfo->cpid)) {
		return ecError;
	}
	/* add the store handle as the parent object handle
		because the caller normaly will not keep the
		handle of folder */
	*phobject = object_tree_add_object_handle(pinfo->ptree, hstore,
	            MAPI_MESSAGE, pmessage.get());
	if (INVALID_HANDLE == *phobject) {
		return ecError;
	}
	pmessage.release();
	return ecSuccess;
}

uint32_t zarafa_server_deletemessages(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags)
{
	BOOL b_owner;
	void *pvalue;
	EID_ARRAY ids;
	EID_ARRAY ids1;
	int account_id;
	BOOL b_private;
	BOOL b_partial;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	const char *username;
	FOLDER_OBJECT *pfolder;
	MESSAGE_CONTENT *pbrief;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	BOOL notify_non_read = FALSE; /* TODO: Read from config or USER_INFO. */
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return FALSE;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (permission & (PERMISSION_DELETEANY | PERMISSION_FOLDEROWNER)) {
			username = NULL;
		} else if (permission & PERMISSION_DELETEOWNED) {
			username = pinfo->username;
		} else {
			return ecNotFound;
		}
	} else {
		username = NULL;
	}
	ids.count = 0;
	ids.pids = cu_alloc<uint64_t>(pentryids->count);
	if (NULL == ids.pids) {
		return ecError;
	}
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (FALSE == common_util_from_message_entryid(
			pentryids->pbin[i], &b_private, &account_id,
			&folder_id, &message_id)) {
			return ecError;
		}
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore)
			|| folder_id != folder_object_get_id(pfolder)) {
			continue;
		}
		ids.pids[ids.count] = message_id;
		ids.count ++;
	}
	BOOL b_hard = (flags & FLAG_HARD_DELETE) ? false : TRUE; /* XXX */
	if (FALSE == notify_non_read) {
		if (!exmdb_client::delete_messages(
			store_object_get_dir(pstore),
			store_object_get_account_id(
			pstore), pinfo->cpid, username,
			folder_object_get_id(pfolder),
			&ids, b_hard, &b_partial)) {
			return ecError;
		}
		return ecSuccess;
	}
	ids1.count = 0;
	ids1.pids  = cu_alloc<uint64_t>(ids.count);
	if (NULL == ids1.pids) {
		return ecError;
	}
	for (size_t i = 0; i < ids.count; ++i) {
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				store_object_get_dir(pstore), ids.pids[i],
				username, &b_owner)) {
				return ecError;
			}
			if (FALSE == b_owner) {
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
		proptag_buff[1] = PROP_TAG_READ;
		if (!exmdb_client::get_message_properties(
			store_object_get_dir(pstore), NULL, 0,
			ids.pids[i], &tmp_proptags, &tmp_propvals)) {
			return ecError;
		}
		pbrief = NULL;
		pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			pvalue = common_util_get_propvals(
				&tmp_propvals, PROP_TAG_READ);
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				if (!exmdb_client::get_message_brief(
					store_object_get_dir(pstore), pinfo->cpid,
					ids.pids[i], &pbrief)) {
					return ecError;
				}
			}
		}
		ids1.pids[ids1.count] = ids.pids[i];
		ids1.count ++;
		if (NULL != pbrief) {
			common_util_notify_receipt(
				store_object_get_account(pstore),
				NOTIFY_RECEIPT_NON_READ, pbrief);
		}
	}
	if (!exmdb_client::delete_messages(
		store_object_get_dir(pstore),
		store_object_get_account_id(
		pstore), pinfo->cpid, username,
		folder_object_get_id(pfolder),
		&ids1, b_hard, &b_partial)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_copymessages(GUID hsession,
	uint32_t hsrcfolder, uint32_t hdstfolder,
	const BINARY_ARRAY *pentryids, uint32_t flags)
{
	BOOL b_done, b_guest = TRUE, b_owner;
	EID_ARRAY ids;
	BOOL b_partial;
	BOOL b_private;
	int account_id;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission;
	STORE_OBJECT *pstore;
	STORE_OBJECT *pstore1;
	FOLDER_OBJECT *psrc_folder;
	FOLDER_OBJECT *pdst_folder;
	
	if (0 == pentryids->count) {
		return ecSuccess;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	psrc_folder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	              pinfo->ptree, hsrcfolder, &mapi_type));
	if (NULL == psrc_folder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(psrc_folder);
	pdst_folder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	              pinfo->ptree, hdstfolder, &mapi_type));
	if (NULL == pdst_folder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type || FOLDER_TYPE_SEARCH
		== folder_object_get_type(pdst_folder)) {
		return ecNotSupported;
	}
	pstore1 = folder_object_get_store(pdst_folder);
	BOOL b_copy = (flags & FLAG_MOVE) ? false : TRUE;
	if (pstore != pstore1) {
		if (FALSE == b_copy) {
			b_guest = FALSE;
			if (FALSE == store_object_check_owner_mode(pstore)) {
				if (!exmdb_client::check_folder_permission(
					store_object_get_dir(pstore),
					folder_object_get_id(psrc_folder),
					pinfo->username, &permission)) {
					return ecError;
				}
				if (permission & PERMISSION_DELETEANY) {
					/* permission to delete any message */
				} else if (permission & PERMISSION_DELETEOWNED) {
					b_guest = TRUE;
				} else {
					return ecAccessDenied;
				}
			}
		}
		if (FALSE == store_object_check_owner_mode(pstore1)) {
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pstore1),
				folder_object_get_id(pdst_folder),
				pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_CREATE)) {
				return ecAccessDenied;
			}
		}
		for (size_t i = 0; i < pentryids->count; ++i) {
			if (FALSE == common_util_from_message_entryid(
				pentryids->pbin[i], &b_private, &account_id,
				&folder_id, &message_id)) {
				return ecError;
			}
			if (b_private != store_object_check_private(pstore) ||
				account_id != store_object_get_account_id(pstore) ||
				folder_id != folder_object_get_id(psrc_folder)) {
				continue;
			}
			gxerr_t err = common_util_remote_copy_message(pstore,
			              message_id, pstore1,
			              folder_object_get_id(pdst_folder));
			if (err != GXERR_SUCCESS) {
				return gxerr_to_hresult(err);
			}
			if (FALSE == b_copy) {
				if (TRUE == b_guest) {
					if (FALSE == exmdb_client_check_message_owner(
						store_object_get_dir(pstore), message_id,
						pinfo->username, &b_owner)) {
						return ecError;
					}
					if (FALSE == b_owner) {
						continue;
					}
				}
				if (FALSE == exmdb_client_delete_message(
					store_object_get_dir(pstore),
					store_object_get_account_id(pstore),
					pinfo->cpid, folder_object_get_id(
				    psrc_folder), message_id, false,
					&b_done)) {
					return ecError;
				}
			}
		}
		return ecSuccess;
	}
	ids.count = 0;
	ids.pids = cu_alloc<uint64_t>(pentryids->count);
	if (NULL == ids.pids) {
		return ecError;
	}
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (FALSE == common_util_from_message_entryid(
			pentryids->pbin[i], &b_private, &account_id,
			&folder_id, &message_id)) {
			return ecError;
		}
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore) ||
			folder_id != folder_object_get_id(psrc_folder)) {
			continue;
		}
		ids.pids[ids.count] = message_id;
		ids.count ++;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pdst_folder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_CREATE)) {
			return ecAccessDenied;
		}
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	if (!exmdb_client::movecopy_messages(
		store_object_get_dir(pstore),
		store_object_get_account_id(pstore),
		pinfo->cpid, b_guest, pinfo->username,
		folder_object_get_id(psrc_folder),
		folder_object_get_id(pdst_folder),
		b_copy, &ids, &b_partial)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_setreadflags(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags)
{
	void *pvalue;
	BOOL b_private;
	BOOL b_changed;
	int account_id;
	uint64_t read_cn;
	uint8_t tmp_byte;
	uint32_t table_id;
	uint8_t mapi_type;
	uint32_t row_count;
	uint64_t folder_id;
	TARRAY_SET tmp_set;
	uint64_t message_id;
	uint32_t tmp_proptag;
	STORE_OBJECT *pstore;
	BOOL b_notify = TRUE; /* TODO: Read from config or USER_INFO. */
	BINARY_ARRAY tmp_bins;
	PROPTAG_ARRAY proptags;
	FOLDER_OBJECT *pfolder;
	PROBLEM_ARRAY problems;
	MESSAGE_CONTENT *pbrief;
	TPROPVAL_ARRAY propvals;
	RESTRICTION restriction;
	RESTRICTION_PROPERTY res_prop;
	static constexpr uint8_t fake_false = false;
	TAGGED_PROPVAL propval_buff[2];
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	auto username = store_object_check_owner_mode(pstore) ? nullptr : pinfo->username;
	if (0 == pentryids->count) {
		restriction.rt = RES_PROPERTY;
		restriction.pres = &res_prop;
		res_prop.relop = flags == FLAG_CLEAR_READ ? RELOP_NE : RELOP_EQ;
		res_prop.proptag = PROP_TAG_READ;
		res_prop.propval.proptag = PROP_TAG_READ;
		res_prop.propval.pvalue = deconst(&fake_false);
		if (!exmdb_client::load_content_table(
			store_object_get_dir(pstore), 0,
			folder_object_get_id(pfolder), username,
			TABLE_FLAG_NONOTIFICATIONS, &restriction,
			NULL, &table_id, &row_count)) {
			return ecError;
		}
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_ENTRYID;
		if (!exmdb_client::query_table(
			store_object_get_dir(pstore), username,
			0, table_id, &proptags, 0, row_count,
			&tmp_set)) {
			exmdb_client::unload_table(
				store_object_get_dir(
				pstore), table_id);
			return ecError;
		}
		exmdb_client::unload_table(
			store_object_get_dir(
			pstore), table_id);
		if (tmp_set.count > 0) {
			tmp_bins.count = 0;
			tmp_bins.pbin = cu_alloc<BINARY>(tmp_set.count);
			if (NULL == tmp_bins.pbin) {
				return ecError;
			}
			for (size_t i = 0; i < tmp_set.count; ++i) {
				if (1 != tmp_set.pparray[i]->count) {
					continue;
				}
				tmp_bins.pbin[tmp_bins.count] =
					*(BINARY*)tmp_set.pparray[i]->ppropval[0].pvalue;
				tmp_bins.count ++;
			}
			pentryids = &tmp_bins;
		}
	}
	for (size_t i = 0; i < pentryids->count; ++i) {
		if (FALSE == common_util_from_message_entryid(
			pentryids->pbin[i], &b_private, &account_id,
			&folder_id, &message_id)) {
			return ecError;
		}
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore) ||
			folder_id != folder_object_get_id(pfolder)) {
			continue;
		}
		b_notify = FALSE;
		b_changed = FALSE;
		if (FLAG_CLEAR_READ == flags) {
			if (FALSE == exmdb_client_get_message_property(
				store_object_get_dir(pstore), username, 0,
				message_id, PROP_TAG_READ, &pvalue)) {
				return ecError;
			}
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				tmp_byte = 0;
				b_changed = TRUE;
			}
		} else {
			if (FALSE == exmdb_client_get_message_property(
				store_object_get_dir(pstore), username, 0,
				message_id, PROP_TAG_READ, &pvalue)) {
				return ecError;
			}
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				tmp_byte = 1;
				b_changed = TRUE;
				if (FALSE == exmdb_client_get_message_property(
					store_object_get_dir(pstore), username, 0,
					message_id, PROP_TAG_READRECEIPTREQUESTED,
					&pvalue)) {
					return ecError;
				}
				if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
					b_notify = TRUE;
				}
			}
		}
		if (TRUE == b_changed) {
			if (!exmdb_client::set_message_read_state(
				store_object_get_dir(pstore), username,
				message_id, tmp_byte, &read_cn)) {
				return ecError;
			}
		}
		if (TRUE == b_notify) {
			if (!exmdb_client::get_message_brief(
				store_object_get_dir(pstore), pinfo->cpid,
				message_id, &pbrief)) {
				return ecError;
			}
			if (NULL != pbrief) {
				common_util_notify_receipt(
					store_object_get_account(pstore),
					NOTIFY_RECEIPT_READ, pbrief);
			}
			propvals.count = 2;
			propvals.ppropval = propval_buff;
			propval_buff[0].proptag =
				PROP_TAG_READRECEIPTREQUESTED;
			propval_buff[0].pvalue = deconst(&fake_false);
			propval_buff[1].proptag =
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
			propval_buff[1].pvalue = deconst(&fake_false);
			exmdb_client::set_message_properties(
				store_object_get_dir(pstore), username,
				0, message_id, &propvals, &problems);
		}
	}
	return ecSuccess;
}

uint32_t zarafa_server_createfolder(GUID hsession,
	uint32_t hparent_folder, uint32_t folder_type,
	const char *folder_name, const char *folder_comment,
	uint32_t flags, uint32_t *phobject)
{
	XID tmp_xid;
	void *pvalue;
	uint32_t hstore;
	uint64_t tmp_id;
	BINARY *pentryid;
	uint32_t tmp_type;
	uint8_t mapi_type;
	uint64_t last_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	uint32_t tag_access;
	uint32_t permission;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pparent;
	TPROPVAL_ARRAY tmp_propvals;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	if (FOLDER_TYPE_SEARCH != folder_type &&
		FOLDER_TYPE_GENERIC != folder_type) {
		return ecNotSupported;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pparent = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hparent_folder, &mapi_type));
	if (NULL == pparent) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	if (1 != rop_util_get_replid(
		folder_object_get_id(pparent))
		|| FOLDER_TYPE_SEARCH ==
		folder_object_get_type(pparent)) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pparent);
	if (FALSE == store_object_check_private(pstore)
		&& FOLDER_TYPE_SEARCH == folder_type) {
		return ecNotSupported;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pparent),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (!(permission & (PERMISSION_FOLDEROWNER | PERMISSION_CREATESUBFOLDER)))
			return ecAccessDenied;
	}
	if (!exmdb_client::get_folder_by_name(
		store_object_get_dir(pstore),
		folder_object_get_id(pparent),
		folder_name, &folder_id)) {
		return ecError;
	}
	if (0 != folder_id) {
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue) || NULL == pvalue) {
			return ecError;
		}
		if (0 == (flags & FLAG_OPEN_IF_EXISTS) ||
			folder_type != *(uint32_t*)pvalue) {
			return ecDuplicateName;
		}
	} else {
		parent_id = folder_object_get_id(pparent);
		if (!exmdb_client::allocate_cn(
			store_object_get_dir(pstore), &change_num)) {
			return ecError;
		}
		tmp_type = folder_type;
		last_time = rop_util_current_nttime();
		tmp_propvals.count = 9;
		tmp_propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PROP_TAG_PARENTFOLDERID;
		propval_buff[0].pvalue = &parent_id;
		propval_buff[1].proptag = PROP_TAG_FOLDERTYPE;
		propval_buff[1].pvalue = &tmp_type;
		propval_buff[2].proptag = PROP_TAG_DISPLAYNAME;
		propval_buff[2].pvalue = deconst(folder_name);
		propval_buff[3].proptag = PROP_TAG_COMMENT;
		propval_buff[3].pvalue = deconst(folder_comment);
		propval_buff[4].proptag = PROP_TAG_CREATIONTIME;
		propval_buff[4].pvalue = &last_time;
		propval_buff[5].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		propval_buff[5].pvalue = &last_time;
		propval_buff[6].proptag = PROP_TAG_CHANGENUMBER;
		propval_buff[6].pvalue = &change_num;
		tmp_xid.guid = store_object_guid(pstore);
		rop_util_get_gc_array(change_num, tmp_xid.local_id);
		propval_buff[7].proptag = PROP_TAG_CHANGEKEY;
		propval_buff[7].pvalue = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == propval_buff[7].pvalue) {
			return ecError;
		}
		propval_buff[8].proptag = PROP_TAG_PREDECESSORCHANGELIST;
		propval_buff[8].pvalue = common_util_pcl_append(nullptr, static_cast<BINARY *>(propval_buff[7].pvalue));
		if (NULL == propval_buff[8].pvalue) {
			return ecError;
		}
		if (!exmdb_client::create_folder_by_properties(
			store_object_get_dir(pstore), pinfo->cpid,
			&tmp_propvals, &folder_id) || 0 == folder_id) {
			return ecError;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			pentryid = common_util_username_to_addressbook_entryid(
													pinfo->username);
			if (NULL == pentryid) {
				return ecError;
			}
			tmp_id = 1;
			permission = PERMISSION_FOLDEROWNER|PERMISSION_READANY|
						PERMISSION_FOLDERVISIBLE|PERMISSION_CREATE|
						PERMISSION_EDITANY|PERMISSION_DELETEANY|
						PERMISSION_CREATESUBFOLDER;
			permission_row.flags = PERMISSION_DATA_FLAG_ADD_ROW;
			permission_row.propvals.count = 3;
			permission_row.propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PROP_TAG_ENTRYID;
			propval_buff[0].pvalue = pentryid;
			propval_buff[1].proptag = PROP_TAG_MEMBERID;
			propval_buff[1].pvalue = &tmp_id;
			propval_buff[2].proptag = PROP_TAG_MEMBERRIGHTS;
			propval_buff[2].pvalue = &permission;
			if (!exmdb_client::update_folder_permission(
				store_object_get_dir(pstore), folder_id,
				FALSE, 1, &permission_row)) {
				return ecError;
			}
		}
	}
	tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
				TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
				TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
	auto pfolder = folder_object_create(pstore,
		folder_id, folder_type, tag_access);
	if (NULL == pfolder) {
		return ecError;
	}
	if (FOLDER_TYPE_SEARCH == folder_type) {
		/* add the store handle as the parent object handle
			because the caller normaly will not keep the
			handle of parent folder */
		hstore = object_tree_get_store_handle(pinfo->ptree,
				TRUE, store_object_get_account_id(pstore));
		if (INVALID_HANDLE == hstore) {
			return ecError;
		}
		*phobject = object_tree_add_object_handle(pinfo->ptree,
		            hstore, MAPI_FOLDER, pfolder.get());
	} else {
		*phobject = object_tree_add_object_handle(pinfo->ptree,
		            hparent_folder, MAPI_FOLDER, pfolder.get());
	}
	if (INVALID_HANDLE == *phobject) {
		return ecError;
	}
	pfolder.release();
	return ecSuccess;
}

uint32_t zarafa_server_deletefolder(GUID hsession,
	uint32_t hparent_folder, BINARY entryid, uint32_t flags)
{
	BOOL b_done;
	void *pvalue;
	BOOL b_exist;
	BOOL b_partial;
	BOOL b_private;
	int account_id;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	STORE_OBJECT *pstore;
	const char *username;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hparent_folder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == common_util_from_folder_entryid(
		entryid, &b_private, &account_id, &folder_id)) {
		return ecError;
	}
	if (b_private != store_object_check_private(pstore) ||
		account_id != store_object_get_account_id(pstore)) {
		return ecInvalidParam;
	}
	username = NULL;
	if (TRUE == store_object_check_private(pstore)) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return ecAccessDenied;
		}
	} else {
		if (1 == rop_util_get_replid(folder_id) &&
			rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			return ecAccessDenied;
		}
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return ecAccessDenied;
		}
		username = pinfo->username;
	}
	if (!exmdb_client::check_folder_id(
		store_object_get_dir(pstore),
		folder_object_get_id(pfolder),
		&b_exist)) {
		return ecError;
	}
	if (FALSE == b_exist) {
		return ecSuccess;
	}
	BOOL b_normal = (flags & DELETE_FOLDER_FLAG_MESSAGES) ? TRUE : false;
	BOOL b_fai = b_normal;
	BOOL b_sub = (flags & DELETE_FOLDER_FLAG_FOLDERS) ? TRUE : false;
	BOOL b_hard = (flags & DELETE_FOLDER_FLAG_HARD_DELETE) ? TRUE : false;
	if (TRUE == store_object_check_private(pstore)) {
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			return ecError;
		}
		if (NULL == pvalue) {
			return ecSuccess;
		}
		if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
			goto DELETE_FOLDER;
		}
	}
	if (TRUE == b_sub || TRUE == b_normal || TRUE == b_fai) {
		if (!exmdb_client::empty_folder(
			store_object_get_dir(pstore),
			pinfo->cpid, username, folder_id,
			b_hard, b_normal, b_fai, b_sub,
			&b_partial)) {
			return ecError;
		}
		if (TRUE == b_partial) {
			/* failure occurs, stop deleting folder */
			return ecSuccess;
		}
	}
 DELETE_FOLDER:
	if (!exmdb_client::delete_folder(
		store_object_get_dir(pstore),
		pinfo->cpid, folder_id, b_hard,
		&b_done)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_emptyfolder(GUID hsession,
	uint32_t hfolder, uint32_t flags)
{
	BOOL b_partial;
	uint64_t fid_val;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	const char *username;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == store_object_check_private(pstore)) {
		return ecNotSupported;
	}
	fid_val = rop_util_get_gc_value(
		folder_object_get_id(pfolder));
	if (PRIVATE_FID_ROOT == fid_val ||
		PRIVATE_FID_IPMSUBTREE == fid_val) {
		return ecAccessDenied;
	}
	username = NULL;
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (!(permission & (PERMISSION_DELETEANY | PERMISSION_DELETEOWNED)))
			return ecAccessDenied;
		username = pinfo->username;
	}
	BOOL b_fai = (flags & FLAG_DEL_ASSOCIATED) ? TRUE : false;
	BOOL b_hard = (flags & FLAG_HARD_DELETE) ? TRUE : false;
	if (!exmdb_client::empty_folder(
		store_object_get_dir(pstore), pinfo->cpid,
		username, folder_object_get_id(pfolder),
		b_hard, TRUE, b_fai, TRUE, &b_partial)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_copyfolder(GUID hsession,
	uint32_t hsrc_folder, BINARY entryid, uint32_t hdst_folder,
	const char *new_name, uint32_t flags)
{
	BOOL b_done;
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_guest;
	BOOL b_private;
	BOOL b_partial;
	int account_id;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	STORE_OBJECT *pstore1;
	FOLDER_OBJECT *psrc_parent;
	FOLDER_OBJECT *pdst_folder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	psrc_parent = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	              pinfo->ptree, hsrc_folder, &mapi_type));
	if (NULL == psrc_parent) {
		return ecNullObject;
	}
	BOOL b_copy = (flags & FLAG_MOVE) ? false : TRUE;
	if (FOLDER_TYPE_SEARCH == folder_object_get_type(
		psrc_parent) && FALSE == b_copy) {
		return ecNotSupported;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(psrc_parent);
	if (FALSE == common_util_from_folder_entryid(
		entryid, &b_private, &account_id, &folder_id)) {
		return ecError;
	}
	if (b_private != store_object_check_private(pstore) ||
		account_id != store_object_get_account_id(pstore)) {
		return ecInvalidParam;
	}
	pdst_folder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	              pinfo->ptree, hdst_folder, &mapi_type));
	if (NULL == pdst_folder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore1 = folder_object_get_store(pdst_folder);
	if (TRUE == store_object_check_private(pstore)) {
		if (PRIVATE_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			return ecAccessDenied;
		}
	} else {
		if (PUBLIC_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			return ecAccessDenied;
		}
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_READANY)) {
			return ecAccessDenied;
		}
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pdst_folder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (!(permission & (PERMISSION_FOLDEROWNER | PERMISSION_CREATESUBFOLDER)))
			return ecAccessDenied;
		username = pinfo->username;
		b_guest = TRUE;
	} else {
		username = NULL;
		b_guest = FALSE;
	}
	if (pstore != pstore1) {
		if (FALSE == b_copy) {
			if (FALSE == store_object_check_owner_mode(pstore)) {
				if (!exmdb_client::check_folder_permission(
					store_object_get_dir(pstore),
					folder_object_get_id(psrc_parent),
					pinfo->username, &permission)) {
					return ecError;
				}
				if (0 == (permission & PERMISSION_FOLDEROWNER)) {
					return ecAccessDenied;
				}
			}
		}
		gxerr_t err = common_util_remote_copy_folder(pstore, folder_id,
		              pstore1, folder_object_get_id(pdst_folder),
		              new_name);
		if (err != GXERR_SUCCESS) {
			return gxerr_to_hresult(err);
		}
		if (FALSE == b_copy) {
			if (!exmdb_client::empty_folder(
				store_object_get_dir(pstore),
				pinfo->cpid, username, folder_id,
				FALSE, TRUE, TRUE, TRUE, &b_partial)) {
				return ecError;
			}
			if (TRUE == b_partial) {
				/* failure occurs, stop deleting folder */
				return ecSuccess;
			}
			if (!exmdb_client::delete_folder(
				store_object_get_dir(pstore),
				pinfo->cpid, folder_id, FALSE,
				&b_done)) {
				return ecError;
			}
		}
		return ecSuccess;
	}
	if (!exmdb_client::check_folder_cycle(
		store_object_get_dir(pstore), folder_id,
		folder_object_get_id(pdst_folder), &b_cycle)) {
		return ecError;
	}
	if (TRUE == b_cycle) {
		return MAPI_E_FOLDER_CYCLE;
	}
	if (!exmdb_client::movecopy_folder(
		store_object_get_dir(pstore),
		store_object_get_account_id(pstore),
		pinfo->cpid, b_guest, pinfo->username,
		folder_object_get_id(psrc_parent), folder_id,
		folder_object_get_id(pdst_folder), new_name,
		b_copy, &b_exist, &b_partial)) {
		return ecError;
	}
	if (TRUE == b_exist) {
		return ecDuplicateName;
	}
	return ecSuccess;
}

uint32_t zarafa_server_getstoreentryid(
	const char *mailbox_dn, BINARY *pentryid)
{
	EXT_PUSH ext_push;
	char username[UADDR_SIZE];
	char tmp_buff[1024];
	STORE_ENTRYID store_entryid = {};
	
	if (0 == strncasecmp(mailbox_dn, "/o=", 3)) {
		if (!common_util_essdn_to_username(mailbox_dn,
		    username, GX_ARRAY_SIZE(username)))
			return ecError;
	} else {
		gx_strlcpy(username, mailbox_dn, GX_ARRAY_SIZE(username));
		if (!common_util_username_to_essdn(username,
		    tmp_buff, GX_ARRAY_SIZE(tmp_buff)))
			return ecError;
		mailbox_dn = tmp_buff;
	}
	store_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_STORE,
					store_entryid.provider_uid);
	store_entryid.version = 0;
	store_entryid.flag = 0;
	snprintf(store_entryid.dll_name, sizeof(store_entryid.dll_name), "emsmdb.dll");
	store_entryid.wrapped_flags = 0;
	rop_util_get_provider_uid(
		PROVIDER_UID_WRAPPED_PRIVATE,
		store_entryid.wrapped_provider_uid);
	store_entryid.wrapped_type = 0x0000000C;
	store_entryid.pserver_name = username;
	store_entryid.pmailbox_dn = deconst(mailbox_dn);
	pentryid->pv = common_util_alloc(1024);
	if (pentryid->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pentryid->pb, 1024, EXT_FLAG_UTF16))
		return ecError;
	if (EXT_ERR_SUCCESS != ext_buffer_push_store_entryid(
		&ext_push, &store_entryid)) {
		return ecError;
	}
	pentryid->cb = ext_push.offset;
	return ecSuccess;
}

uint32_t zarafa_server_entryidfromsourcekey(
	GUID hsession, uint32_t hstore, BINARY folder_key,
	const BINARY *pmessage_key, BINARY *pentryid)
{
	XID tmp_xid;
	BOOL b_found;
	BINARY *pbin;
	GUID tmp_guid;
	int domain_id;
	uint16_t replid;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	
	if (22 != folder_key.cb || (NULL != pmessage_key
		&& 22 != pmessage_key->cb)) {
		return ecInvalidParam;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == common_util_binary_to_xid(
		&folder_key, &tmp_xid)) {
		return ecNotSupported;
	}
	if (TRUE == store_object_check_private(pstore)) {
		tmp_guid = rop_util_make_user_guid(
			store_object_get_account_id(pstore));
		if (0 != memcmp(&tmp_guid, &tmp_xid.guid, sizeof(GUID))) {
			return ecInvalidParam;
		}
		folder_id = rop_util_make_eid(1, tmp_xid.local_id);
	} else {
		domain_id = rop_util_make_domain_id(tmp_xid.guid);
		if (-1 == domain_id) {
			return ecInvalidParam;
		}
		if (domain_id == store_object_get_account_id(pstore)) {
			replid = 1;
		} else {
			if (NULL != pmessage_key) {
				return ecInvalidParam;
			}
			if (FALSE == system_services_check_same_org(
				domain_id, store_object_get_account_id(pstore))) {
				return ecInvalidParam;
			}
			if (!exmdb_client::get_mapping_replid(store_object_get_dir(pstore),
			    tmp_xid.guid, &b_found, &replid)) {
				return ecError;
			}
			if (FALSE == b_found) {
				return ecNotFound;
			}
		}
		folder_id = rop_util_make_eid(replid, tmp_xid.local_id);
	}
	if (NULL != pmessage_key) {
		if (FALSE == common_util_binary_to_xid(
			pmessage_key, &tmp_xid)) {
			return ecNotSupported;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
			if (0 != memcmp(&tmp_guid, &tmp_xid.guid, sizeof(GUID))) {
				return ecInvalidParam;
			}
			message_id = rop_util_make_eid(1, tmp_xid.local_id);
		} else {
			domain_id = rop_util_make_domain_id(tmp_xid.guid);
			if (-1 == domain_id) {
				return ecInvalidParam;
			}
			if (domain_id != store_object_get_account_id(pstore)) {
				return ecInvalidParam;
			}
			message_id = rop_util_make_eid(1, tmp_xid.local_id);
		}
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
	} else {
		pbin = common_util_to_folder_entryid(pstore, folder_id);
	}
	if (NULL == pbin) {
		return ecError;
	}
	*pentryid = *pbin;
	return ecSuccess;
}

uint32_t zarafa_server_storeadvise(GUID hsession,
	uint32_t hstore, const BINARY *pentryid,
	uint32_t event_mask, uint32_t *psub_id)
{
	char dir[256];
	uint16_t type;
	BOOL b_private;
	int account_id;
	uint8_t mapi_type;
	char tmp_buff[256];
	uint64_t folder_id;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	NOTIFY_ITEM tmp_item;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	folder_id = 0;
	message_id = 0;
	if (NULL != pentryid) {
		type = common_util_get_messaging_entryid_type(*pentryid);
		switch (type) {
		case EITLT_PRIVATE_FOLDER:
		case EITLT_PUBLIC_FOLDER:
			if (FALSE == common_util_from_folder_entryid(
				*pentryid, &b_private, &account_id, &folder_id)) {
				return ecError;
			}
			break;
		case EITLT_PRIVATE_MESSAGE:
		case EITLT_PUBLIC_MESSAGE:
			if (FALSE == common_util_from_message_entryid(
				*pentryid, &b_private, &account_id,
				&folder_id, &message_id)) {
				return ecError;
			}
			break;
		default:
			return ecNotFound;
		}
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore)) {
			return ecInvalidParam;
		}
	}
	if (!exmdb_client::subscribe_notification(
		store_object_get_dir(pstore), event_mask,
		TRUE, folder_id, message_id, psub_id)) {
		return ecError;
	}
	gx_strlcpy(dir, store_object_get_dir(pstore), GX_ARRAY_SIZE(dir));
	pinfo.reset();
	double_list_init(&tmp_item.notify_list);
	tmp_item.hsession = hsession;
	tmp_item.hstore = hstore;
	time(&tmp_item.last_time);
	snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%u|%s", *psub_id, dir);
	std::unique_lock nl_hold(g_notify_lock);
	if (1 != str_hash_add(g_notify_table, tmp_buff, &tmp_item)) {
		nl_hold.unlock();
		exmdb_client::unsubscribe_notification(dir, *psub_id);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_unadvise(GUID hsession,
	uint32_t hstore, uint32_t sub_id)
{	
	char dir[256];
	uint8_t mapi_type;
	char tmp_buff[256];
	NOTIFY_ITEM *pnitem;
	STORE_OBJECT *pstore;
	DOUBLE_LIST_NODE *pnode;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	gx_strlcpy(dir, store_object_get_dir(pstore), GX_ARRAY_SIZE(dir));
	pinfo.reset();
	exmdb_client::unsubscribe_notification(dir, sub_id);
	snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%u|%s", sub_id, dir);
	std::unique_lock nl_hold(g_notify_lock);
	pnitem = static_cast<NOTIFY_ITEM *>(str_hash_query(g_notify_table, tmp_buff));
	if (NULL != pnitem) {
		while ((pnode = double_list_pop_front(&pnitem->notify_list)) != nullptr) {
			common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
			free(pnode);
		}
		double_list_free(&pnitem->notify_list);
	}
	str_hash_remove(g_notify_table, tmp_buff);
	return ecSuccess;
}

uint32_t zarafa_server_notifdequeue(const NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications)
{
	int i;
	int count;
	uint8_t mapi_type;
	char tmp_buff[256];
	NOTIFY_ITEM *pnitem;
	STORE_OBJECT *pstore;
	DOUBLE_LIST_NODE *pnode;
	ZNOTIFICATION* ppnotifications[1024];
	
	auto pinfo = zarafa_server_query_session(psink->hsession);
	if (pinfo == nullptr)
		return ecError;
	count = 0;
	for (i=0; i<psink->count; i++) {
		pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(pinfo->ptree,
		         psink->padvise[i].hstore, &mapi_type));
		if (NULL == pstore || MAPI_STORE != mapi_type) {
			continue;
		}
		sprintf(tmp_buff, "%u|%s",
			psink->padvise[i].sub_id,
			store_object_get_dir(pstore));
		std::unique_lock nl_hold(g_notify_lock);
		pnitem = static_cast<NOTIFY_ITEM *>(str_hash_query(g_notify_table, tmp_buff));
		if (NULL == pnitem) {
			continue;
		}
		time(&pnitem->last_time);
		while ((pnode = double_list_pop_front(&pnitem->notify_list)) != nullptr) {
			ppnotifications[count] = common_util_dup_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata), true);
			common_util_free_znotification(static_cast<ZNOTIFICATION *>(pnode->pdata));
			free(pnode);
			if (NULL != ppnotifications[count]) {
				count ++;
			}
			if (1024 == count) {
				break;
			}
		}
		nl_hold.unlock();
		if (1024 == count) {
			break;
		}
	}
	if (count > 0) {
		pinfo.reset();
		pnotifications->count = count;
		pnotifications->ppnotification = cu_alloc<ZNOTIFICATION *>(count);
		if (NULL == pnotifications->ppnotification) {
			return ecError;
		}
		memcpy(pnotifications->ppnotification,
			ppnotifications, sizeof(void*)*count);
		return ecSuccess;
	}
	auto psink_node = me_alloc<SINK_NODE>();
	if (NULL == psink_node) {
		return ecError;
	}
	psink_node->node.pdata = psink_node;
	psink_node->clifd = common_util_get_clifd();
	time(&psink_node->until_time);
	psink_node->until_time += timeval;
	psink_node->sink.hsession = psink->hsession;
	psink_node->sink.count = psink->count;
	psink_node->sink.padvise = me_alloc<ADVISE_INFO>(psink->count);
	if (NULL == psink_node->sink.padvise) {
		free(psink_node);
		return ecError;
	}
	memcpy(psink_node->sink.padvise, psink->padvise,
				psink->count*sizeof(ADVISE_INFO));
	double_list_append_as_tail(
		&pinfo->sink_list, &psink_node->node);
	return ecNotFound;
}

uint32_t zarafa_server_queryrows(
	GUID hsession, uint32_t htable, uint32_t start,
	uint32_t count, const RESTRICTION *prestriction,
	const PROPTAG_ARRAY *pproptags, TARRAY_SET *prowset)
{
	uint32_t row_num;
	int32_t position;
	uint8_t mapi_type;
	uint8_t table_type;
	TARRAY_SET tmp_set;
	TABLE_OBJECT *ptable;
	uint32_t *pobject_type = nullptr;
	TAGGED_PROPVAL *ppropvals;
	static const uint32_t object_type_store = OBJECT_STORE;
	static const uint32_t object_type_folder = OBJECT_FOLDER;
	static const uint32_t object_type_message = OBJECT_MESSAGE;
	static const uint32_t object_type_attachment = OBJECT_ATTACHMENT;
	
	if (count > 0x7FFFFFFF) {
		count = 0x7FFFFFFF;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	table_type = table_object_get_table_type(ptable);
	if (0xFFFFFFFF != start) {
		table_object_set_position(ptable, start);
	}
	if (NULL != prestriction) {
		switch (table_object_get_table_type(ptable)) {
		case HIERARCHY_TABLE:
		case CONTENT_TABLE:
		case RULE_TABLE:
			row_num = table_object_get_total(ptable);
			if (row_num > count) {
				row_num = count;
			}
			prowset->count = 0;
			prowset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_num);
			if (NULL == prowset->pparray) {
				return ecError;
			}
			while (TRUE) {
				if (FALSE == table_object_match_row(ptable,
					TRUE, prestriction, &position)) {
					return ecError;
				}
				if (position < 0) {
					break;
				}
				table_object_set_position(ptable, position);
				if (FALSE == table_object_query_rows(ptable,
					TRUE, pproptags, 1, &tmp_set)) {
					return ecError;
				}
				if (1 != tmp_set.count) {
					break;
				}
				table_object_seek_current(ptable, TRUE, 1);
				prowset->pparray[prowset->count] = tmp_set.pparray[0];
				prowset->count ++;
				if (count == prowset->count) {
					break;
				}
			}
			break;
		case ATTACHMENT_TABLE:
		case RECIPIENT_TABLE:
		case USER_TABLE:
			if (FALSE == table_object_filter_rows(ptable,
				count, prestriction, pproptags, prowset)) {
				return ecError;
			}
			break;
		default:
			return ecNotSupported;
		}
	} else {
		if (FALSE == table_object_query_rows(ptable,
			TRUE, pproptags, count, prowset)) {
			return ecError;
		}
		table_object_seek_current(ptable, TRUE, prowset->count);
	}
	pinfo.reset();
	if ((STORE_TABLE != table_type &&
		HIERARCHY_TABLE != table_type &&
		CONTENT_TABLE != table_type &&
		ATTACHMENT_TABLE != table_type)
		|| (NULL != pproptags &&
		common_util_index_proptags(pproptags,
		PROP_TAG_OBJECTTYPE) < 0)) {
		return ecSuccess;
	}
	switch (table_type) {
	case STORE_TABLE:
		pobject_type = deconst(&object_type_store);
		break;
	case HIERARCHY_TABLE:
		pobject_type = deconst(&object_type_folder);
		break;
	case CONTENT_TABLE:
		pobject_type = deconst(&object_type_message);
		break;
	case ATTACHMENT_TABLE:
		pobject_type = deconst(&object_type_attachment);
		break;
	}
	for (size_t i = 0; i < prowset->count; ++i) {
		ppropvals = cu_alloc<TAGGED_PROPVAL>(prowset->pparray[i]->count + 1);
		if (NULL == ppropvals) {
			return ecError;
		}
		memcpy(ppropvals, prowset->pparray[i]->ppropval,
			sizeof(TAGGED_PROPVAL)*prowset->pparray[i]->count);
		ppropvals[prowset->pparray[i]->count].proptag = PROP_TAG_OBJECTTYPE;
		ppropvals[prowset->pparray[i]->count].pvalue = pobject_type;
		prowset->pparray[i]->ppropval = ppropvals;
		prowset->pparray[i]->count ++;
	}
	return ecSuccess;
}
	
uint32_t zarafa_server_setcolumns(GUID hsession, uint32_t htable,
	const PROPTAG_ARRAY *pproptags, uint32_t flags)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_set_columns(ptable, pproptags)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_seekrow(GUID hsession,
	uint32_t htable, uint32_t bookmark, int32_t seek_rows,
	int32_t *psought_rows)
{
	BOOL b_exist;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	uint32_t original_position;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	switch (bookmark) {
	case BOOKMARK_BEGINNING:
		if (seek_rows < 0) {
			return ecInvalidParam;
		}
		original_position = 0;
		table_object_set_position(ptable, static_cast<uint32_t>(seek_rows));
		break;
	case BOOKMARK_END: {
		if (seek_rows > 0) {
			return ecInvalidParam;
		}
		original_position = table_object_get_total(ptable);
		/* underflow safety check for s32t */
		uint32_t dwoff = seek_rows != INT32_MIN ? -seek_rows :
		                 static_cast<uint32_t>(INT32_MIN) + 1;
		if (dwoff > table_object_get_total(ptable))
			table_object_set_position(ptable, 0);
		else
			table_object_set_position(ptable, table_object_get_total(ptable) - dwoff);
		break;
	}
	case BOOKMARK_CURRENT: {
		original_position = table_object_get_position(ptable);
		if (seek_rows < 0) {
			/* underflow safety check for s32t */
			uint32_t dwoff = seek_rows != INT32_MIN ? -seek_rows :
			                 static_cast<uint32_t>(INT32_MIN) + 1;
			if (dwoff > original_position)
				table_object_set_position(ptable, 0);
			else
				table_object_set_position(ptable, original_position - dwoff);
			break;
		}
		auto upoff = static_cast<uint32_t>(seek_rows);
		if (original_position > static_cast<uint32_t>(UINT32_MAX) - upoff)
			/* overflow safety check for u32t+u32t */
			return 0;
		table_object_set_position(ptable, original_position + upoff);
		break;
	}
	default: {
		original_position = table_object_get_position(ptable);
		if (FALSE == table_object_retrieve_bookmark(
			ptable, bookmark, &b_exist)) {
			return ecError;
		}
		if (FALSE == b_exist) {
			return ecNotFound;
		}
		auto original_position1 = table_object_get_position(ptable);
		if (seek_rows < 0) {
			/* underflow safety check for s32t */
			uint32_t dwoff = seek_rows != INT32_MIN ? -seek_rows :
			                 static_cast<uint32_t>(INT32_MIN) + 1;
			if (dwoff > original_position1)
				table_object_set_position(ptable, 0);
			else
				table_object_set_position(ptable, original_position1 - dwoff);
			break;
		}
		auto upoff = static_cast<uint32_t>(seek_rows);
		if (original_position1 > static_cast<uint32_t>(UINT32_MAX) - upoff)
			/* overflow check for u32t+u32t */
			return 0;
		table_object_set_position(ptable, original_position1 + upoff);
		break;
	}
	}
	*psought_rows = table_object_get_position(
					ptable) - original_position;
	return ecSuccess;
}

uint32_t zarafa_server_sorttable(GUID hsession,
	uint32_t htable, const SORTORDER_SET *psortset)
{
	int i, j;
	BOOL b_max;
	uint16_t type;
	uint8_t mapi_type;
	BOOL b_multi_inst;
	uint32_t tmp_proptag;
	TABLE_OBJECT *ptable;
	const PROPTAG_ARRAY *pcolumns;
	
	if (psortset->count > MAXIMUM_SORT_COUNT) {
		return ecTooComplex;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	if (CONTENT_TABLE != table_object_get_table_type(ptable)) {
		return ecSuccess;
	}
	b_max = FALSE;
	b_multi_inst = FALSE;
	for (i=0; i<psortset->ccategories; i++) {
		for (j=i+1; j<psortset->count; j++) {
			if (psortset->psort[i].propid ==
				psortset->psort[j].propid &&
				psortset->psort[i].type ==
				psortset->psort[j].type) {
				return ecInvalidParam;
			}
		}
	}
	for (i=0; i<psortset->count; i++) {
		tmp_proptag = PROP_TAG(psortset->psort[i].type, psortset->psort[i].propid);
		if (PROP_TAG_DEPTH == tmp_proptag ||
			PROP_TAG_INSTID == tmp_proptag ||
			PROP_TAG_INSTANCENUM == tmp_proptag ||
			PROP_TAG_CONTENTCOUNT == tmp_proptag ||
			PROP_TAG_CONTENTUNREADCOUNT == tmp_proptag) {
			return ecInvalidParam;
		}	
		switch (psortset->psort[i].table_sort) {
		case TABLE_SORT_ASCEND:
		case TABLE_SORT_DESCEND:
			break;
		case TABLE_SORT_MAXIMUM_CATEGORY:
		case TABLE_SORT_MINIMUM_CATEGORY:
			if (0 == psortset->ccategories ||
				psortset->ccategories != i) {
				return ecInvalidParam;
			}
			break;
		default:
			return ecInvalidParam;
		}
		type = psortset->psort[i].type;
		if (type & MV_FLAG) {
			/* we do not support multivalue property
				without multivalue instances */
			if (!(type & MV_INSTANCE)) {
				return ecNotSupported;
			}
			type &= ~MV_INSTANCE;
			/* MUST NOT contain more than one multivalue property! */
			if (TRUE == b_multi_inst) {
				return ecInvalidParam;
			}
			b_multi_inst = TRUE;
		}
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
		case PT_SRESTRICT:
		case PT_ACTIONS:
		case PT_BINARY:
		case PT_MV_SHORT:
		case PT_MV_LONG:
		case PT_MV_I8:
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
		case PT_MV_CLSID:
		case PT_MV_BINARY:
			break;
		case PT_UNSPECIFIED:
		case PT_ERROR:
		default:
			return ecInvalidParam;
		}
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psortset->psort[i].table_sort ||
			TABLE_SORT_MINIMUM_CATEGORY ==
			psortset->psort[i].table_sort) {
			if (TRUE == b_max || i != psortset->ccategories) {
				return ecInvalidParam;
			}
			b_max = TRUE;
		}
	}
	pcolumns = table_object_get_columns(ptable);
	if (TRUE == b_multi_inst && NULL != pcolumns) {
		if (FALSE == common_util_verify_columns_and_sorts(
			pcolumns, psortset)) {
			return ecNotSupported;
		}
	}
	if (FALSE == table_object_set_sorts(ptable, psortset)) {
		return ecError;
	}
	table_object_unload(ptable);
	table_object_clear_bookmarks(ptable);
	table_object_clear_position(ptable);
	return ecSuccess;
}

uint32_t zarafa_server_getrowcount(GUID hsession,
	uint32_t htable, uint32_t *pcount)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	*pcount = table_object_get_total(ptable);
	return ecSuccess;
}

uint32_t zarafa_server_restricttable(GUID hsession, uint32_t htable,
	const RESTRICTION *prestriction, uint32_t flags)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
	case RULE_TABLE:
	case USER_TABLE:
		break;
	default:
		return ecNotSupported;
	}
	if (FALSE == table_object_set_restriction(ptable, prestriction)) {
		return ecError;
	}
	table_object_unload(ptable);
	table_object_clear_bookmarks(ptable);
	table_object_clear_position(ptable);
	return ecSuccess;
}

uint32_t zarafa_server_findrow(GUID hsession, uint32_t htable,
	uint32_t bookmark, const RESTRICTION *prestriction,
	uint32_t flags, uint32_t *prow_idx)
{
	BOOL b_exist;
	int32_t position;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
	case RULE_TABLE:
		break;
	default:
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	switch (bookmark) {
	case BOOKMARK_BEGINNING:
		table_object_set_position(ptable, 0);
		break;
	case BOOKMARK_END:
		table_object_set_position(ptable,
			table_object_get_total(ptable));
		break;
	case BOOKMARK_CURRENT:
		break;
	default:
		if (RULE_TABLE == table_object_get_table_type(ptable)) {
			return ecNotSupported;
		}
		if (FALSE == table_object_retrieve_bookmark(
			ptable, bookmark, &b_exist)) {
			return ecInvalidBookmark;
		}
		break;
	}
	if (FALSE == table_object_match_row(ptable,
		TRUE, prestriction, &position)) {
		return ecError;
	}
	if (position < 0) {
		return ecNotFound;
	}
	table_object_set_position(ptable, position);
	*prow_idx = position;
	return ecSuccess;
}

uint32_t zarafa_server_createbookmark(GUID hsession,
	uint32_t htable, uint32_t *pbookmark)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
		break;
	default:
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	if (FALSE == table_object_create_bookmark(
		ptable, pbookmark)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_freebookmark(GUID hsession,
	uint32_t htable, uint32_t bookmark)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	ptable = static_cast<TABLE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, htable, &mapi_type));
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (MAPI_TABLE != mapi_type) {
		return ecNotSupported;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
		break;
	default:
		return ecNotSupported;
	}
	table_object_remove_bookmark(ptable, bookmark);
	return ecSuccess;
}

uint32_t zarafa_server_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid)
{
	BINARY *pbin;
	uint8_t mapi_type;
	uint64_t folder_id;
	char temp_class[256];
	STORE_OBJECT *pstore;
	
	if (NULL == pstrclass) {
		pstrclass = "";
	}
	if (FALSE == common_util_check_message_class(pstrclass)) {
		return ecInvalidParam;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == store_object_check_private(pstore)) {
		return ecNotSupported;
	}
	if (!exmdb_client::get_folder_by_class(
		store_object_get_dir(pstore), pstrclass,
		&folder_id, temp_class)) {
		return ecError;
	}
	pbin = common_util_to_folder_entryid(pstore, folder_id);
	if (NULL == pbin) {
		return ecError;
	}
	*pentryid = *pbin;
	return ecSuccess;
}

uint32_t zarafa_server_modifyrecipients(GUID hsession,
	uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list)
{
	BOOL b_found;
	BINARY *pbin;
	uint32_t *prowid;
	uint8_t mapi_type;
	EXT_PULL ext_pull;
	uint32_t tmp_flags;
	char tmp_buff[256];
	uint8_t tmp_uid[16];
	uint32_t last_rowid;
	TPROPVAL_ARRAY *prcpt;
	uint8_t fake_true = 1;
	uint8_t fake_false = 0;
	uint8_t provider_uid[16];
	TAGGED_PROPVAL *ppropval;
	MESSAGE_OBJECT *pmessage;
	TAGGED_PROPVAL tmp_propval;
	ONEOFF_ENTRYID oneoff_entry;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (prcpt_list->count >= 0x7FEF || (MODRECIP_ADD != flags &&
		MODRECIP_MODIFY != flags && MODRECIP_REMOVE != flags)) {
		return ecInvalidParam;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (MODRECIP_MODIFY == flags) {
		message_object_empty_rcpts(pmessage);
	} else if (MODRECIP_REMOVE == flags) {
		for (size_t i = 0; i < prcpt_list->count; ++i) {
			prcpt = prcpt_list->pparray[i];
			b_found = FALSE;
			for (size_t j = 0; j < prcpt->count; ++j) {
				if (PROP_TAG_ROWID == prcpt->ppropval[j].proptag) {
					prcpt->count = 1;
					prcpt->ppropval = prcpt->ppropval + j;
					b_found = TRUE;
					break;
				}
			}
			if (FALSE == b_found) {
				return ecInvalidParam;
			}
		}
		if (FALSE == message_object_set_rcpts(pmessage, prcpt_list)) {
			return ecError;
		}
		return ecSuccess;
	}
	if (FALSE == message_object_get_rowid_begin(pmessage, &last_rowid)) {
		return ecError;
	}
	for (size_t i = 0; i < prcpt_list->count; ++i, ++last_rowid) {
		if (NULL == common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_ENTRYID) &&
			NULL == common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_EMAILADDRESS) &&
			NULL == common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_SMTPADDRESS)) {
			return ecInvalidParam;
		}
		prowid = static_cast<uint32_t *>(common_util_get_propvals(
		         prcpt_list->pparray[i], PROP_TAG_ROWID));
		if (NULL != prowid) {
			if (*prowid < last_rowid) {
				*prowid = last_rowid;
			} else {
				last_rowid = *prowid;
			}
		} else {
			prcpt = prcpt_list->pparray[i];
			ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 1);
			if (NULL == ppropval) {
				return ecError;
			}
			memcpy(ppropval, prcpt->ppropval,
				sizeof(TAGGED_PROPVAL)*prcpt->count);
			ppropval[prcpt->count].proptag = PROP_TAG_ROWID;
			ppropval[prcpt->count].pvalue = cu_alloc<uint32_t>();
			if (NULL == ppropval[prcpt->count].pvalue) {
				return ecError;
			}
			*(uint32_t*)ppropval[prcpt->count].pvalue = last_rowid;
			prcpt->ppropval = ppropval;
			prcpt->count ++;
			pbin = static_cast<BINARY *>(common_util_get_propvals(prcpt, PROP_TAG_ENTRYID));
			if (NULL == pbin || (NULL !=
				common_util_get_propvals(
				prcpt, PROP_TAG_EMAILADDRESS) &&
				NULL != common_util_get_propvals(
				prcpt, PROP_TAG_ADDRESSTYPE) &&
				NULL != common_util_get_propvals(
				prcpt, PROP_TAG_DISPLAYNAME))) {
				continue;
			}
			ext_buffer_pull_init(&ext_pull, pbin->pb,
					pbin->cb, common_util_alloc, 0);
			if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
				&ext_pull, &tmp_flags) || 0 != tmp_flags) {
				continue;
			}
			if (EXT_ERR_SUCCESS != ext_buffer_pull_bytes(
				&ext_pull, provider_uid, 16)) {
				continue;
			}
			rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK, tmp_uid);
			if (0 == memcmp(tmp_uid, provider_uid, 16)) {
				ext_buffer_pull_init(&ext_pull, pbin->pb,
					pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
				if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
					&ext_pull, &ab_entryid)) {
					continue;
				}
				if (ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER
					!= ab_entryid.type) {
					continue;
				}
				ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 4);
				if (NULL == ppropval) {
					return ecError;
				}
				memcpy(ppropval, prcpt->ppropval,
					prcpt->count*sizeof(TAGGED_PROPVAL));
				prcpt->ppropval = ppropval;
				tmp_propval.proptag = PROP_TAG_ADDRESSTYPE;
				tmp_propval.pvalue  = deconst("EX");
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_EMAILADDRESS;
				tmp_propval.pvalue = common_util_dup(ab_entryid.px500dn);
				if (NULL == tmp_propval.pvalue) {
					return ecError;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_SMTPADDRESS;
				if (!common_util_essdn_to_username(ab_entryid.px500dn,
				    tmp_buff, GX_ARRAY_SIZE(tmp_buff)))
					continue;
				tmp_propval.pvalue = common_util_dup(tmp_buff);
				if (NULL == tmp_propval.pvalue) {
					return ecError;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				if (FALSE == system_services_get_user_displayname(
					tmp_buff, tmp_buff)) {
					continue;	
				}
				tmp_propval.proptag = PROP_TAG_DISPLAYNAME;
				tmp_propval.pvalue = common_util_dup(tmp_buff);
				if (NULL == tmp_propval.pvalue) {
					return ecError;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				continue;
			}
			rop_util_get_provider_uid(PROVIDER_UID_ONE_OFF, tmp_uid);
			if (0 == memcmp(tmp_uid, provider_uid, 16)) {
				ext_buffer_pull_init(&ext_pull, pbin->pb,
					pbin->cb, common_util_alloc, EXT_FLAG_UTF16);
				if (EXT_ERR_SUCCESS != ext_buffer_pull_oneoff_entryid(
					&ext_pull, &oneoff_entry) || 0 != strcasecmp(
					oneoff_entry.paddress_type, "SMTP")) {
					continue;
				}
				ppropval = cu_alloc<TAGGED_PROPVAL>(prcpt->count + 5);
				if (NULL == ppropval) {
					return ecError;
				}
				memcpy(ppropval, prcpt->ppropval,
					prcpt->count*sizeof(TAGGED_PROPVAL));
				prcpt->ppropval = ppropval;
				tmp_propval.proptag = PROP_TAG_ADDRESSTYPE;
				tmp_propval.pvalue  = deconst("SMTP");
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_EMAILADDRESS;
				tmp_propval.pvalue = common_util_dup(
						oneoff_entry.pmail_address);
				if (NULL == tmp_propval.pvalue) {
					return ecError;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_SMTPADDRESS;
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_DISPLAYNAME;
				tmp_propval.pvalue = common_util_dup(
						oneoff_entry.pdisplay_name);
				if (NULL == tmp_propval.pvalue) {
					return ecError;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_SENDRICHINFO;
				tmp_propval.pvalue = (oneoff_entry.ctrl_flags & CTRL_FLAG_NORICH) ? &fake_false : &fake_true;
				common_util_set_propvals(prcpt, &tmp_propval);
			}
		}
	}
	if (FALSE == message_object_set_rcpts(pmessage, prcpt_list)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_submitmessage(GUID hsession, uint32_t hmessage)
{
	int timer_id;
	void *pvalue;
	BOOL b_marked;
	time_t cur_time;
	uint32_t tmp_num;
	uint8_t mapi_type;
	uint16_t rcpt_num;
	char username[UADDR_SIZE];
	const char *account;
	uint32_t permission;
	uint32_t mail_length;
	STORE_OBJECT *pstore;
	uint64_t submit_time;
	uint32_t deferred_time;
	uint32_t message_flags;
	char command_buff[1024];
	MESSAGE_OBJECT *pmessage;
	uint32_t proptag_buff[6];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	pstore = message_object_get_store(pmessage);
	if (FALSE == store_object_check_private(pstore)) {
		return ecNotSupported;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_mailbox_permission(
			store_object_get_dir(pstore), pinfo->username,
			&permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_SENDAS)) {
			return ecAccessDenied;
		}
	}
	if (0 == message_object_get_id(pmessage)) {
		return ecNotSupported;
	}
	if (TRUE == message_object_check_importing(pmessage) ||
		FALSE == message_object_check_writable(pmessage)) {
		return ecAccessDenied;
	}
	if (FALSE == message_object_get_recipient_num(
		pmessage, &rcpt_num)) {
		return ecError;
	}
	if (rcpt_num > common_util_get_param(COMMON_UTIL_MAX_RCPT)) {
		return ecTooManyRecips;
	}
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_ASSOCIATED;
	if (FALSE == message_object_get_properties(
		pmessage, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_ASSOCIATED);
	/* FAI message cannot be sent */
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		return ecAccessDenied;
	}
	if (!common_util_check_delegate(pmessage, username, GX_ARRAY_SIZE(username))) {
		return ecError;
	}
	account = store_object_get_account(pstore);
	if ('\0' == username[0]) {
		gx_strlcpy(username, account, GX_ARRAY_SIZE(username));
	} else {
		if (FALSE == common_util_check_delegate_permission_ex(
			account, username)) {
			return ecAccessDenied;
		}
	}
	gxerr_t err = common_util_rectify_message(pmessage, username);
	if (err != GXERR_SUCCESS) {
		return gxerr_to_hresult(err);
	}
	tmp_proptags.count = 3;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MAXIMUMSUBMITMESSAGESIZE;
	proptag_buff[1] = PROP_TAG_PROHIBITSENDQUOTA;
	proptag_buff[2] = PROP_TAG_MESSAGESIZEEXTENDED;
	if (FALSE == store_object_get_properties(
		pstore, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}

	auto sendquota = static_cast<uint32_t *>(common_util_get_propvals(&tmp_propvals, PROP_TAG_PROHIBITSENDQUOTA));
	auto storesize = static_cast<uint64_t *>(common_util_get_propvals(&tmp_propvals, PROP_TAG_MESSAGESIZEEXTENDED));
	/* Sendquota is in KiB, storesize in bytes */
	if (sendquota != nullptr && storesize != nullptr &&
	    static_cast<uint64_t>(*sendquota) * 1024 <= *storesize) {
		return ecQuotaExceeded;
	}

	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_MAXIMUMSUBMITMESSAGESIZE);
	ssize_t max_length = -1;
	if (NULL != pvalue) {
		max_length = *(int32_t*)pvalue;
	}
	tmp_proptags.count = 6;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MESSAGESIZE;
	proptag_buff[1] = PROP_TAG_MESSAGEFLAGS;
	proptag_buff[2] = PROP_TAG_DEFERREDSENDTIME;
	proptag_buff[3] = PROP_TAG_DEFERREDSENDNUMBER;
	proptag_buff[4] = PROP_TAG_DEFERREDSENDUNITS;
	proptag_buff[5] = PROP_TAG_DELETEAFTERSUBMIT;
	if (FALSE == message_object_get_properties(
		pmessage, &tmp_proptags, &tmp_propvals)) {
		return ecError;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_MESSAGESIZE);
	if (NULL == pvalue) {
		return ecError;
	}
	mail_length = *(uint32_t*)pvalue;
	if (max_length > 0 && mail_length > static_cast<size_t>(max_length)) {
		return EC_EXCEEDED_SIZE;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_MESSAGEFLAGS);
	if (NULL == pvalue) {
		return ecError;
	}
	message_flags = *(uint32_t*)pvalue;
	/* here we handle the submit request
		differently from exchange_emsmdb.
		we always allow a submitted message
		to be resubmitted */
	BOOL b_unsent = (message_flags & MESSAGE_FLAG_UNSENT) ? TRUE : false;
	pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_DELETEAFTERSUBMIT);
	BOOL b_delete = pvalue != nullptr && *static_cast<uint8_t *>(pvalue) != 0 ? TRUE : false;
	if (0 == (MESSAGE_FLAG_SUBMITTED & message_flags)) {
		if (!exmdb_client::try_mark_submit(
			store_object_get_dir(pstore),
			message_object_get_id(pmessage),
			&b_marked)) {
			return ecError;
		}
		if (FALSE == b_marked) {
			return ecAccessDenied;
		}
		
		deferred_time = 0;
		time(&cur_time);
		submit_time = rop_util_unix_to_nttime(cur_time);
		pvalue = common_util_get_propvals(&tmp_propvals,
								PROP_TAG_DEFERREDSENDTIME);
		if (NULL != pvalue) {
			if (submit_time < *(uint64_t*)pvalue) {
				deferred_time = rop_util_nttime_to_unix(
							*(uint64_t*)pvalue) - cur_time;
			}
		} else {
			pvalue = common_util_get_propvals(&tmp_propvals,
								PROP_TAG_DEFERREDSENDNUMBER);
			if (NULL != pvalue) {
				tmp_num = *(uint32_t*)pvalue;
				pvalue = common_util_get_propvals(&tmp_propvals,
									PROP_TAG_DEFERREDSENDUNITS);
				if (NULL != pvalue) {
					switch (*(uint32_t*)pvalue) {
					case 0:
						deferred_time = tmp_num*60;
						break;
					case 1:
						deferred_time = tmp_num*60*60;
						break;
					case 2:
						deferred_time = tmp_num*60*60*24;
						break;
					case 3:
						deferred_time = tmp_num*60*60*24*7;
						break;
					}
				}
			}
		}
	
		if (deferred_time > 0) {
			snprintf(command_buff, 1024, "%s %s %llu",
				common_util_get_submit_command(),
				store_object_get_account(pstore),
				static_cast<unsigned long long>(rop_util_get_gc_value(
					message_object_get_id(pmessage))));
			timer_id = system_services_add_timer(
					command_buff, deferred_time);
			if (0 == timer_id) {
				exmdb_client::clear_submit(
				store_object_get_dir(pstore),
					message_object_get_id(pmessage),
					b_unsent);
				return ecError;
			}
			exmdb_client::set_message_timer(
				store_object_get_dir(pstore),
				message_object_get_id(pmessage), timer_id);
			message_object_reload(pmessage);
			return ecSuccess;
		}
	}
	if (FALSE == common_util_send_message(pstore,
		message_object_get_id(pmessage), TRUE)) {
		exmdb_client::clear_submit(
			store_object_get_dir(pstore),
			message_object_get_id(pmessage),
			b_unsent);
		return ecError;
	}
	if (FALSE == b_delete) {
		message_object_reload(pmessage);
	} else {
		message_object_clear_unsent(pmessage);
	}
	return ecSuccess;
}

uint32_t zarafa_server_loadattachmenttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	STORE_OBJECT *pstore;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	pstore = message_object_get_store(pmessage);
	ptable = table_object_create(pstore,
		pmessage, ATTACHMENT_TABLE, 0);
	if (NULL == ptable) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
			pinfo->ptree, hmessage, MAPI_TABLE,
			ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_openattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id, uint32_t *phobject)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	auto pattachment = attachment_object_create(pmessage, attach_id);
	if (NULL == pattachment) {
		return ecError;
	}
	if (attachment_object_get_instance_id(pattachment.get()) == 0) {
		return ecNotFound;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree, hmessage,
	            MAPI_ATTACHMENT, pattachment.get());
	if (INVALID_HANDLE == *phobject) {
		return ecError;
	}
	pattachment.release();
	return ecSuccess;
}

uint32_t zarafa_server_createattachment(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == message_object_check_writable(pmessage)) {
		return ecAccessDenied;
	}
	auto pattachment = attachment_object_create(
		pmessage, ATTACHMENT_NUM_INVALID);
	if (NULL == pattachment) {
		return ecError;
	}
	if (attachment_object_get_attachment_num(pattachment.get()) == ATTACHMENT_NUM_INVALID) {
		return ecMaxAttachmentExceeded;
	}
	if (!attachment_object_init_attachment(pattachment.get())) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree, hmessage,
	            MAPI_ATTACHMENT, pattachment.get());
	if (INVALID_HANDLE == *phobject) {
		return ecError;
	}
	pattachment.release();
	return ecSuccess;
}

uint32_t zarafa_server_deleteattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == message_object_check_writable(pmessage)) {
		return ecAccessDenied;
	}
	if (FALSE == message_object_delele_attachment(
		pmessage, attach_id)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_setpropvals(GUID hsession,
	uint32_t hobject, const TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pobject;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (mapi_type) {
	case MAPI_PROFPROPERTY:
		for (i=0; i<ppropvals->count; i++) {
			if (!tpropval_array_set_propval(static_cast<TPROPVAL_ARRAY *>(pobject),
			    &ppropvals->ppropval[i])) {
				return ecError;
			}
		}
		object_tree_touch_profile_sec(pinfo->ptree);
		return ecSuccess;
	case MAPI_STORE:
		if (!store_object_check_owner_mode(static_cast<STORE_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!store_object_set_properties(static_cast<STORE_OBJECT *>(pobject), ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_FOLDER:
		pstore = folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject));
		if (!store_object_check_owner_mode(static_cast<STORE_OBJECT *>(pstore))) {
			if (!exmdb_client::check_folder_permission(store_object_get_dir(pstore),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
			    pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
		}
		if (!folder_object_set_properties(static_cast<FOLDER_OBJECT *>(pobject), ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_MESSAGE:
		if (!message_object_check_writable(static_cast<MESSAGE_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!message_object_set_properties(static_cast<MESSAGE_OBJECT *>(pobject), ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_ATTACHMENT:
		if (!attachment_object_check_writable(static_cast<ATTACHMENT_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!attachment_object_set_properties(static_cast<ATTACHMENT_OBJECT *>(pobject), ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t zarafa_server_getpropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pobject;
	uint8_t mapi_type;
	PROPTAG_ARRAY proptags;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (mapi_type) {
	case MAPI_PROFPROPERTY:
		if (NULL == pproptags) {
			*ppropvals = *(TPROPVAL_ARRAY*)pobject;
		} else {
			ppropvals->count = 0;
			ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
			if (NULL == ppropvals->ppropval) {
				return ecError;
			}
			for (i=0; i<pproptags->count; i++) {
				ppropvals->ppropval[ppropvals->count].proptag =
										pproptags->pproptag[i];
				ppropvals->ppropval[ppropvals->count].pvalue =
					tpropval_array_get_propval(static_cast<TPROPVAL_ARRAY *>(pobject), pproptags->pproptag[i]);
				if (NULL != ppropvals->ppropval[
					ppropvals->count].pvalue) {
					ppropvals->count ++;	
				}
			}
		}
		return ecSuccess;
	case MAPI_STORE:
		if (NULL == pproptags) {
			if (!store_object_get_all_proptags(static_cast<STORE_OBJECT *>(pobject), &proptags)) {
				return ecError;
			}
			pproptags = &proptags;
		}
		if (!store_object_get_properties(static_cast<STORE_OBJECT *>(pobject), pproptags, ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_FOLDER:
		if (NULL == pproptags) {
			if (!folder_object_get_all_proptags(static_cast<FOLDER_OBJECT *>(pobject), &proptags)) {
				return ecError;
			}
			pproptags = &proptags;
		}
		if (!folder_object_get_properties(static_cast<FOLDER_OBJECT *>(pobject), pproptags, ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_MESSAGE:
		if (NULL == pproptags) {
			if (!message_object_get_all_proptags(static_cast<MESSAGE_OBJECT *>(pobject), &proptags)) {
				return ecError;
			}
			pproptags = &proptags;
		}
		if (!message_object_get_properties(static_cast<MESSAGE_OBJECT *>(pobject), pproptags, ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_ATTACHMENT:
		if (NULL == pproptags) {
			if (!attachment_object_get_all_proptags(static_cast<ATTACHMENT_OBJECT *>(pobject), &proptags)) {
				return ecError;
			}
			pproptags = &proptags;
		}
		if (!attachment_object_get_properties(static_cast<ATTACHMENT_OBJECT *>(pobject),
		    pproptags, ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_ABCONT:
		if (NULL == pproptags) {
			container_object_get_container_table_all_proptags(
				&proptags);
			pproptags = &proptags;
		}
		if (!container_object_get_properties(static_cast<CONTAINER_OBJECT *>(pobject),
		    pproptags, ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_MAILUSER:
	case MAPI_DISTLIST:
		if (NULL == pproptags) {
			container_object_get_user_table_all_proptags(&proptags);
			pproptags = &proptags;
		}
		if (!user_object_get_properties(static_cast<USER_OBJECT *>(pobject),
		    pproptags, ppropvals)) {
			return ecError;
		}
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t zarafa_server_deletepropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags)
{
	int i;
	void *pobject;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (mapi_type) {
	case MAPI_PROFPROPERTY:
		for (i=0; i<pproptags->count; i++) {
			tpropval_array_remove_propval(static_cast<TPROPVAL_ARRAY *>(pobject), pproptags->pproptag[i]);
		}
		object_tree_touch_profile_sec(pinfo->ptree);
		return ecSuccess;
	case MAPI_STORE:
		if (!store_object_check_owner_mode(static_cast<STORE_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!store_object_remove_properties(static_cast<STORE_OBJECT *>(pobject), pproptags)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_FOLDER:
		pstore = folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject));
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (!exmdb_client::check_folder_permission(store_object_get_dir(pstore),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
			    pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
		}
		if (!folder_object_remove_properties(static_cast<FOLDER_OBJECT *>(pobject), pproptags)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_MESSAGE:
		if (!message_object_check_writable(static_cast<MESSAGE_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!message_object_remove_properties(static_cast<MESSAGE_OBJECT *>(pobject), pproptags)) {
			return ecError;
		}
		return ecSuccess;
	case MAPI_ATTACHMENT:
		if (!attachment_object_check_writable(static_cast<ATTACHMENT_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!attachment_object_remove_properties(static_cast<ATTACHMENT_OBJECT *>(pobject), pproptags)) {
			return ecError;
		}
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t zarafa_server_setmessagereadflag(
	GUID hsession, uint32_t hmessage, uint32_t flags)
{
	BOOL b_changed;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == message_object_set_readflag(
		pmessage, flags, &b_changed)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_openembedded(GUID hsession,
	uint32_t hattachment, uint32_t flags, uint32_t *phobject)
{
	uint32_t hstore;
	BOOL b_writable;
	uint8_t mapi_type;
	uint32_t tag_access;
	STORE_OBJECT *pstore;
	ATTACHMENT_OBJECT *pattachment;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pattachment = static_cast<ATTACHMENT_OBJECT *>(object_tree_get_object(
	              pinfo->ptree, hattachment, &mapi_type));
	if (NULL == pattachment) {
		return ecNullObject;
	}
	if (MAPI_ATTACHMENT != mapi_type) {
		return ecNotSupported;
	}
	pstore = attachment_object_get_store(pattachment);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		return ecNullObject;
	}
	b_writable = attachment_object_check_writable(pattachment);
	tag_access = attachment_object_get_tag_access(pattachment);
	if ((FLAG_CREATE & flags) && FALSE == b_writable) {
		return ecAccessDenied;
	}
	auto pmessage = message_object_create(pstore,
		FALSE, pinfo->cpid, 0, pattachment,
		tag_access, b_writable, NULL);
	if (NULL == pmessage) {
		return ecError;
	}
	if (message_object_get_instance_id(pmessage.get()) == 0) {
		if (0 == (FLAG_CREATE & flags)) {
			return ecNotFound;
		}
		if (FALSE == b_writable) {
			return ecAccessDenied;
		}
		auto pmessage = message_object_create(pstore, TRUE,
			pinfo->cpid, 0, pattachment, tag_access,
			TRUE, NULL);
		if (NULL == pmessage) {
			return ecError;
		}
		if (!message_object_init_message(pmessage.get(),
		    false, pinfo->cpid)) {
			return ecError;
		}
	}
	/* add the store handle as the parent object handle
		because the caller normaly will not keep the
		handle of attachment */
	*phobject = object_tree_add_object_handle(pinfo->ptree, hstore,
	            MAPI_MESSAGE, pmessage.get());
	if (INVALID_HANDLE == *phobject) {
		return ecError;
	}
	pmessage.release();
	return ecSuccess;
}

uint32_t zarafa_server_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == store_object_get_named_propids(
		pstore, TRUE, ppropnames, ppropids)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_getpropnames(GUID hsession, uint32_t hstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, hstore, &mapi_type));
	if (NULL == pstore) {
		return ecNullObject;
	}
	if (MAPI_STORE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == store_object_get_named_propnames(
		pstore, ppropids, ppropnames)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_copyto(GUID hsession, uint32_t hsrcobject,
	const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject,
	uint32_t flags)
{
	int i;
	BOOL b_cycle;
	BOOL b_collid;
	void *pobject;
	BOOL b_partial;
	uint8_t dst_type;
	uint8_t mapi_type;
	void *pobject_dst;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY tmp_proptags;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hsrcobject, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	pobject_dst = object_tree_get_object(
		pinfo->ptree, hdstobject, &dst_type);
	if (NULL == pobject_dst) {
		return ecNullObject;
	}
	if (mapi_type != dst_type) {
		return ecNotSupported;
	}
	BOOL b_force = (flags & COPY_FLAG_NOOVERWRITE) ? TRUE : false;
	switch (mapi_type) {
	case MAPI_FOLDER: {
		pstore = folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject));
		if (pstore != folder_object_get_store(static_cast<FOLDER_OBJECT *>(pobject_dst))) {
			return ecNotSupported;
		}
		/* MS-OXCPRPT 3.2.5.8, public folder not supported */
		if (FALSE == store_object_check_private(pstore)) {
			return ecNotSupported;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (!exmdb_client::check_folder_permission(store_object_get_dir(pstore),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
			    pinfo->username, &permission)) {
				return ecError;
			}
			if (permission & PERMISSION_FOLDEROWNER) {
				username = NULL;
			} else {
				if (0 == (permission & PERMISSION_READANY)) {
					return ecAccessDenied;
				}
				username = pinfo->username;
			}
			if (!exmdb_client::check_folder_permission(store_object_get_dir(pstore),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject_dst)),
			    pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
		} else {
			username = NULL;
		}
		BOOL b_sub;
		if (common_util_index_proptags(pexclude_proptags,
			PROP_TAG_CONTAINERHIERARCHY) < 0) {
			if (!exmdb_client::check_folder_cycle(store_object_get_dir(pstore),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject_dst)), &b_cycle)) {
				return ecError;
			}
			if (TRUE == b_cycle) {
				return MAPI_E_FOLDER_CYCLE;
			}
			b_sub = TRUE;
		} else {
			b_sub = FALSE;
		}
		BOOL b_normal = common_util_index_proptags(pexclude_proptags, PROP_TAG_CONTAINERCONTENTS) < 0 ? TRUE : false;
		BOOL b_fai    = common_util_index_proptags(pexclude_proptags, PROP_TAG_FOLDERASSOCIATEDCONTENTS) < 0 ? TRUE : false;
		if (!folder_object_get_all_proptags(static_cast<FOLDER_OBJECT *>(pobject), &proptags)) {
			return ecError;
		}
		common_util_reduce_proptags(&proptags, pexclude_proptags);
		tmp_proptags.count = 0;
		tmp_proptags.pproptag = cu_alloc<uint32_t>(proptags.count);
		if (NULL == tmp_proptags.pproptag) {
			return ecError;
		}
		if (FALSE == b_force) {
			if (!folder_object_get_all_proptags(static_cast<FOLDER_OBJECT *>(pobject_dst), &proptags1)) {
				return ecError;
			}
		}
		for (i=0; i<proptags.count; i++) {
			if (folder_object_check_readonly_property(static_cast<FOLDER_OBJECT *>(pobject_dst),
			    proptags.pproptag[i]))
				continue;
			if (FALSE == b_force && common_util_index_proptags(
				&proptags1, proptags.pproptag[i]) >= 0) {
				continue;
			}
			tmp_proptags.pproptag[tmp_proptags.count] = 
									proptags.pproptag[i];
			tmp_proptags.count ++;
		}
		if (!folder_object_get_properties(static_cast<FOLDER_OBJECT *>(pobject),
		    &tmp_proptags, &propvals)) {
			return ecError;
		}
		if (TRUE == b_sub || TRUE == b_normal || TRUE == b_fai) {
			BOOL b_guest = username == nullptr ? false : TRUE;
			if (!exmdb_client::copy_folder_internal(store_object_get_dir(pstore),
			    store_object_get_account_id(pstore), pinfo->cpid,
			    b_guest, pinfo->username,
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
			    b_normal, b_fai, b_sub,
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject_dst)),
			    &b_collid, &b_partial)) {
				return ecError;
			}
			if (TRUE == b_collid) {
				return ecDuplicateName;
			}
			if (!folder_object_set_properties(static_cast<FOLDER_OBJECT *>(pobject_dst), &propvals)) {
				return ecError;
			}
			return ecSuccess;
		}
		if (!folder_object_set_properties(static_cast<FOLDER_OBJECT *>(pobject_dst), &propvals)) {
			return ecError;
		}
		return ecSuccess;
	}
	case MAPI_MESSAGE:
		if (!message_object_check_writable(static_cast<MESSAGE_OBJECT *>(pobject_dst))) {
			return ecAccessDenied;
		}
		if (!message_object_copy_to(static_cast<MESSAGE_OBJECT *>(pobject_dst),
		    static_cast<MESSAGE_OBJECT *>(pobject), pexclude_proptags,
		    b_force, &b_cycle)) {
			return ecError;
		}
		if (TRUE == b_cycle) {
			return ecMsgCycle;
		}
		return ecSuccess;
	case MAPI_ATTACHMENT:
		if (!attachment_object_check_writable(static_cast<ATTACHMENT_OBJECT *>(pobject_dst))) {
			return ecAccessDenied;
		}
		if (!attachment_object_copy_properties(static_cast<ATTACHMENT_OBJECT *>(pobject_dst),
		    static_cast<ATTACHMENT_OBJECT *>(pobject),
		    pexclude_proptags, b_force, &b_cycle)) {
			return ecError;
		}
		if (TRUE == b_cycle) {
			return ecMsgCycle;
		}
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t zarafa_server_savechanges(GUID hsession, uint32_t hobject)
{
	void *pobject;
	BOOL b_touched;
	uint8_t mapi_type;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE == mapi_type) {
		if (!message_object_check_writable(static_cast<MESSAGE_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		if (!message_object_check_orignal_touched(static_cast<MESSAGE_OBJECT *>(pobject), &b_touched)) {
			return ecError;
		}
		if (TRUE == b_touched) {
			return ecObjectModified;
		}
		gxerr_t err = message_object_save(static_cast<MESSAGE_OBJECT *>(pobject));
		if (err != GXERR_SUCCESS) {
			return gxerr_to_hresult(err);
		}
		return ecSuccess;
	} else if (MAPI_ATTACHMENT == mapi_type) {
		if (!attachment_object_check_writable(static_cast<ATTACHMENT_OBJECT *>(pobject))) {
			return ecAccessDenied;
		}
		gxerr_t err = attachment_object_save(static_cast<ATTACHMENT_OBJECT *>(pobject));
		if (err != GXERR_SUCCESS) {
			return gxerr_to_hresult(err);
		}
		return ecSuccess;
	} else {
		return ecNotSupported;
	}
}

uint32_t zarafa_server_hierarchysync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		return ecNullObject;
	}
	auto pctx = icsdownctx_object_create(pfolder, SYNC_TYPE_HIERARCHY);
	if (NULL == pctx) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_ICSDOWNCTX,
	            pctx.get());
	if (INVALID_HANDLE == *phobject) {
		pctx.reset();
		return ecError;
	}
	pctx.release();
	return ecSuccess;
}

uint32_t zarafa_server_contentsync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		return ecNullObject;
	}
	auto pctx = icsdownctx_object_create(pfolder, SYNC_TYPE_CONTENTS);
	if (NULL == pctx) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_ICSDOWNCTX,
	            pctx.get());
	if (INVALID_HANDLE == *phobject) {
		pctx.reset();
		return ecError;
	}
	pctx.release();
	return ecSuccess;
}

uint32_t zarafa_server_configsync(GUID hsession, uint32_t hctx, uint32_t flags,
    const BINARY *pstate, const RESTRICTION *prestriction, uint8_t *pb_changed,
    uint32_t *pcount)
{
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSDOWNCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSDOWNCTX != mapi_type) {
		return ecNotSupported;
	}
	BOOL b_changed = false;
	if (SYNC_TYPE_CONTENTS == icsdownctx_object_get_type(pctx)) {
		if (FALSE == icsdownctx_object_make_content(pctx,
			pstate, prestriction, flags, &b_changed, pcount)) {
			return ecError;
		}
	} else {
		if (FALSE == icsdownctx_object_make_hierarchy(
			pctx, pstate, flags, &b_changed, pcount)) {
			return ecError;
		}
	}
	*pb_changed = !!b_changed;
	return ecSuccess;
}

uint32_t zarafa_server_statesync(GUID hsession,
	uint32_t hctx, BINARY *pstate)
{
	BINARY *pbin;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSDOWNCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSDOWNCTX != mapi_type) {
		return ecNotSupported;
	}
	pbin = icsdownctx_object_get_state(pctx);
	if (NULL == pbin) {
		return ecError;
	}
	*pstate = *pbin;
	return ecSuccess;
}

uint32_t zarafa_server_syncmessagechange(GUID hsession, uint32_t hctx,
    uint8_t *pb_new, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_found;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSDOWNCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSDOWNCTX != mapi_type ||
		SYNC_TYPE_CONTENTS != icsdownctx_object_get_type(pctx)) {
		return ecNotSupported;
	}
	BOOL b_new = false;
	if (FALSE == icsdownctx_object_sync_message_change(
	    pctx, &b_found, &b_new, pproplist)) {
		return ecError;
	}
	*pb_new = !!b_new;
	if (FALSE == b_found) {
		return ecNotFound;
	}
	return ecSuccess;
}

uint32_t zarafa_server_syncfolderchange(GUID hsession,
	uint32_t hctx, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_found;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSDOWNCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSDOWNCTX != mapi_type ||
		SYNC_TYPE_HIERARCHY != icsdownctx_object_get_type(pctx)) {
		return ecNotSupported;
	}
	if (FALSE == icsdownctx_object_sync_folder_change(
		pctx, &b_found, pproplist)) {
		return ecError;
	}
	if (FALSE == b_found) {
		return ecNotFound;
	}
	return ecSuccess;
}

uint32_t zarafa_server_syncreadstatechanges(
	GUID hsession, uint32_t hctx, STATE_ARRAY *pstates)
{
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSDOWNCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSDOWNCTX != mapi_type ||
		SYNC_TYPE_CONTENTS != icsdownctx_object_get_type(pctx)) {
		return ecNotSupported;
	}
	if (FALSE == icsdownctx_object_sync_readstates(
		pctx, pstates)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_syncdeletions(GUID hsession,
	uint32_t hctx, uint32_t flags, BINARY_ARRAY *pbins)
{
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSDOWNCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSDOWNCTX != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == icsdownctx_object_sync_deletions(
		pctx, flags, pbins)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_hierarchyimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type || FOLDER_TYPE_SEARCH
		== folder_object_get_type(pfolder)) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		return ecNullObject;
	}
	auto pctx = icsupctx_object_create(pfolder, SYNC_TYPE_HIERARCHY);
	if (NULL == pctx) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
	            pinfo->ptree, hstore, MAPI_ICSUPCTX, pctx.get());
	if (INVALID_HANDLE == *phobject) {
		pctx.reset();
		return ecError;
	}
	pctx.release();
	return ecSuccess;
}

uint32_t zarafa_server_contentimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		return ecNullObject;
	}
	auto pctx = icsupctx_object_create(pfolder, SYNC_TYPE_CONTENTS);
	if (NULL == pctx) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(
	            pinfo->ptree, hstore, MAPI_ICSUPCTX, pctx.get());
	if (INVALID_HANDLE == *phobject) {
		pctx.reset();
		return ecError;
	}
	pctx.release();
	return ecSuccess;
}

uint32_t zarafa_server_configimport(GUID hsession,
	uint32_t hctx, uint8_t sync_type, const BINARY *pstate)
{
	uint8_t mapi_type;
	ICSUPCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSUPCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == icsupctx_object_upload_state(
		pctx, pstate)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_stateimport(GUID hsession,
	uint32_t hctx, BINARY *pstate)
{
	BINARY *pbin;
	uint8_t mapi_type;
	ICSUPCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSUPCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		return ecNotSupported;
	}
	pbin = icsupctx_object_get_state(pctx);
	if (NULL == pbin) {
		return ecError;
	}
	*pstate = *pbin;
	return ecSuccess;
}

uint32_t zarafa_server_importmessage(GUID hsession, uint32_t hctx,
	uint32_t flags, const TPROPVAL_ARRAY *pproplist, uint32_t *phobject)
{
	BOOL b_fai;
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_owner;
	BINARY *pbin;
	void *pvalue;
	GUID tmp_guid;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission, tag_access = 0;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	
	pvalue = common_util_get_propvals(pproplist, PROP_TAG_ASSOCIATED);
	if (NULL != pvalue) {
		b_fai = *static_cast<uint8_t *>(pvalue) == 0 ? TRUE : false;
	} else {
		pvalue = common_util_get_propvals(
			pproplist, PROP_TAG_MESSAGEFLAGS);
		b_fai = pvalue != nullptr && (*static_cast<uint32_t *>(pvalue) & MESSAGE_FLAG_FAI) ?
		        TRUE : false;
	}
	/*
	 * If there is no sourcekey, it is a new message. That is how
	 * grammm-sync creates new items coming from mobile devices.
	 */
	pbin = static_cast<BINARY *>(common_util_get_propvals(pproplist, PROP_TAG_SOURCEKEY));
	if (pbin == nullptr)
		flags |= SYNC_NEW_MESSAGE;
	BOOL b_new = (flags & SYNC_NEW_MESSAGE) ? TRUE : false;
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSUPCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		return ecNotSupported;
	}
	pstore = icsupctx_object_get_store(pctx);
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_type(pctx)) {
		return ecNotSupported;
	}
	folder_id = icsupctx_object_get_parent_folder_id(pctx);
	if (FALSE == b_new) {
		pbin = static_cast<BINARY *>(common_util_get_propvals(pproplist, PROP_TAG_SOURCEKEY));
		if (pbin == nullptr || pbin->cb != 22) {
			return ecInvalidParam;
		}
		if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
			return ecError;
		}
		tmp_guid = store_object_guid(pstore);
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			return ecInvalidParam;
		}
		message_id = rop_util_make_eid(1, tmp_xid.local_id);
		if (!exmdb_client::check_message(
			store_object_get_dir(pstore), folder_id,
			message_id, &b_exist)) {
			return ecError;
		}
		if (FALSE == b_exist) {
			return ecNotFound;
		}
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			return ecError;
		}
		if (TRUE == b_new) {
			if (0 == (permission & PERMISSION_CREATE)) {
				return ecAccessDenied;
			}
			tag_access = TAG_ACCESS_READ;
			if (permission & (PERMISSION_EDITANY | PERMISSION_EDITOWNED))
				tag_access |= TAG_ACCESS_MODIFY;	
			if (permission & (PERMISSION_DELETEANY | PERMISSION_DELETEOWNED))
				tag_access |= TAG_ACCESS_DELETE;	
		} else {
			if (permission & PERMISSION_FOLDEROWNER) {
				tag_access = TAG_ACCESS_MODIFY|
					TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			} else {
				if (FALSE == exmdb_client_check_message_owner(
					store_object_get_dir(pstore), message_id,
					pinfo->username, &b_owner)) {
					return ecError;
				}
				if (TRUE == b_owner || (permission & PERMISSION_READANY)) {
					tag_access |= TAG_ACCESS_READ;
				}
				if ((permission & PERMISSION_EDITANY) || (TRUE ==
					b_owner && (permission & PERMISSION_EDITOWNED))) {
					tag_access |= TAG_ACCESS_MODIFY;	
				}
				if ((permission & PERMISSION_DELETEANY) || (TRUE ==
					b_owner && (permission & PERMISSION_DELETEOWNED))) {
					tag_access |= TAG_ACCESS_DELETE;	
				}
			}
		}
	} else {
		tag_access = TAG_ACCESS_MODIFY|TAG_ACCESS_READ|TAG_ACCESS_DELETE;
	}
	if (FALSE == b_new) {
		if (FALSE == exmdb_client_get_message_property(
			store_object_get_dir(pstore), NULL, 0,
			message_id, PROP_TAG_ASSOCIATED, &pvalue)) {
			return ecError;
		}
		if (TRUE == b_fai) {
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				return ecInvalidParam;
			}
		} else {
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				return ecInvalidParam;
			}
		}
	} else {
		if (!exmdb_client::allocate_message_id(
			store_object_get_dir(pstore), folder_id,
			&message_id)) {
			return ecError;
		}
	}
	auto pmessage = message_object_create(pstore, b_new,
		pinfo->cpid, message_id, &folder_id, tag_access,
		OPEN_MODE_FLAG_READWRITE, pctx->pstate);
	if (NULL == pmessage) {
		return ecError;
	}
	if (b_new && !message_object_init_message(pmessage.get(),
	    b_fai, pinfo->cpid)) {
		return ecError;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree, hctx,
	            MAPI_MESSAGE, pmessage.get());
	if (*phobject == INVALID_HANDLE) {
		return ecError;
	}
	pmessage.release();
	return ecSuccess;
}

uint32_t zarafa_server_importfolder(GUID hsession,
	uint32_t hctx, const TPROPVAL_ARRAY *ppropvals)
{
	int i;
	XID tmp_xid;
	BOOL b_exist;
	BINARY *pbin;
	BOOL b_guest;
	BOOL b_found;
	void *pvalue;
	GUID tmp_guid;
	int domain_id;
	BOOL b_partial;
	uint64_t nttime;
	uint16_t replid;
	uint64_t tmp_fid;
	uint8_t mapi_type;
	uint32_t tmp_type;
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t parent_id1;
	uint64_t change_num;
	uint32_t permission;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	TPROPVAL_ARRAY *pproplist;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[4];
	TPROPVAL_ARRAY hierarchy_propvals;
	
	pproplist = &hierarchy_propvals;
	hierarchy_propvals.count = 4;
	hierarchy_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_PARENTSOURCEKEY;
	propval_buff[0].pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_PARENTSOURCEKEY);
	if (NULL == propval_buff[0].pvalue) {
		return ecInvalidParam;
	}
	propval_buff[1].proptag = PROP_TAG_SOURCEKEY;
	propval_buff[1].pvalue = common_util_get_propvals(
						ppropvals, PROP_TAG_SOURCEKEY);
	if (NULL == propval_buff[1].pvalue) {
		return ecInvalidParam;
	}
	propval_buff[2].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval_buff[2].pvalue = common_util_get_propvals(
			ppropvals, PROP_TAG_LASTMODIFICATIONTIME);
	if (NULL == propval_buff[2].pvalue) {
		propval_buff[2].pvalue = &nttime;
		nttime = rop_util_current_nttime();
	}
	propval_buff[3].proptag = PROP_TAG_DISPLAYNAME;
	propval_buff[3].pvalue = common_util_get_propvals(
					ppropvals, PROP_TAG_DISPLAYNAME);
	if (NULL == propval_buff[3].pvalue) {
		return ecInvalidParam;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSUPCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		return ecNotSupported;
	}
	pstore = icsupctx_object_get_store(pctx);
	if (SYNC_TYPE_HIERARCHY != icsupctx_object_get_type(pctx)) {
		return ecNotSupported;
	}
	if (0 == ((BINARY*)pproplist->ppropval[0].pvalue)->cb) {
		parent_id1 = icsupctx_object_get_parent_folder_id(pctx);
		if (!exmdb_client::check_folder_id(
			store_object_get_dir(pstore), parent_id1,
			&b_exist)) {
			return ecError;
		}
		if (FALSE == b_exist) {
			return SYNC_E_NO_PARENT;
		}
	} else {
		pbin = static_cast<BINARY *>(pproplist->ppropval[0].pvalue);
		if (pbin == nullptr || pbin->cb != 22) {
			return ecInvalidParam;
		}
		if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
			return ecError;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return ecInvalidParam;
			}
		} else {
			tmp_guid = rop_util_make_domain_guid(
				store_object_get_account_id(pstore));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return ecAccessDenied;
			}
		}
		parent_id1 = rop_util_make_eid(1, tmp_xid.local_id);
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, parent_id1,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			return ecError;
		}
		if (NULL == pvalue) {
			return SYNC_E_NO_PARENT;
		}
	}
	pbin = static_cast<BINARY *>(pproplist->ppropval[1].pvalue);
	if (pbin == nullptr || pbin->cb != 22) {
		return ecInvalidParam;
	}
	if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
		return ecError;
	}
	if (TRUE == store_object_check_private(pstore)) {
		tmp_guid = rop_util_make_user_guid(
			store_object_get_account_id(pstore));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			return ecInvalidParam;
		}
		folder_id = rop_util_make_eid(1, tmp_xid.local_id);
	} else {
		tmp_guid = rop_util_make_domain_guid(
			store_object_get_account_id(pstore));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			domain_id = rop_util_make_domain_id(tmp_xid.guid);
			if (-1 == domain_id) {
				return ecInvalidParam;
			}
			if (FALSE == system_services_check_same_org(
				domain_id, store_object_get_account_id(pstore))) {
				return ecInvalidParam;
			}
			if (!exmdb_client::get_mapping_replid(
				store_object_get_dir(pstore),
				tmp_xid.guid, &b_found, &replid)) {
				return ecError;
			}
			if (FALSE == b_found) {
				return ecInvalidParam;
			}
			folder_id = rop_util_make_eid(replid, tmp_xid.local_id);
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_id);
		}
	}
	if (!exmdb_client::check_folder_id(
		store_object_get_dir(pstore), folder_id,
		&b_exist)) {
		return ecError;
	}
	if (FALSE == b_exist) {
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pstore), parent_id1,
				pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				return ecAccessDenied;
			}
		}
		if (!exmdb_client::get_folder_by_name(store_object_get_dir(pstore),
		    parent_id1, static_cast<char *>(pproplist->ppropval[3].pvalue),
		    &tmp_fid)) {
			return ecError;
		}
		if (0 != tmp_fid) {
			return ecDuplicateName;
		}
		if (!exmdb_client::allocate_cn(
			store_object_get_dir(pstore), &change_num)) {
			return ecError;
		}
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8 + ppropvals->count);
		if (NULL == tmp_propvals.ppropval) {
			return ecError;
		}
		tmp_propvals.ppropval[0].proptag = PROP_TAG_FOLDERID;
		tmp_propvals.ppropval[0].pvalue = &folder_id;
		tmp_propvals.ppropval[1].proptag = PROP_TAG_PARENTFOLDERID;
		tmp_propvals.ppropval[1].pvalue = &parent_id1;
		tmp_propvals.ppropval[2].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		tmp_propvals.ppropval[2].pvalue = pproplist->ppropval[2].pvalue;
		tmp_propvals.ppropval[3].proptag = PROP_TAG_DISPLAYNAME;
		tmp_propvals.ppropval[3].pvalue = pproplist->ppropval[3].pvalue;
		tmp_propvals.ppropval[4].proptag = PROP_TAG_CHANGENUMBER;
		tmp_propvals.ppropval[4].pvalue = &change_num;
		tmp_propvals.count = 5;
		for (i=0; i<ppropvals->count; i++) {
			tmp_propvals.ppropval[tmp_propvals.count] =
								ppropvals->ppropval[i];
			tmp_propvals.count ++;
		}
		if (NULL == common_util_get_propvals(
			&tmp_propvals, PROP_TAG_FOLDERTYPE)) {
			tmp_type = FOLDER_TYPE_GENERIC;
			tmp_propvals.ppropval[tmp_propvals.count].proptag =
											PROP_TAG_FOLDERTYPE;
			tmp_propvals.ppropval[tmp_propvals.count].pvalue =
													&tmp_type;
			tmp_propvals.count ++;
		}
		if (!exmdb_client::create_folder_by_properties(
			store_object_get_dir(pstore), pinfo->cpid,
			&tmp_propvals, &tmp_fid) || folder_id != tmp_fid) {
			return ecError;
		}
		idset_append(pctx->pstate->pseen, change_num);
		return ecSuccess;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return ecAccessDenied;
		}
	}
	if (FALSE == exmdb_client_get_folder_property(
		store_object_get_dir(pstore), 0, folder_id,
		PROP_TAG_PARENTFOLDERID, &pvalue) || NULL == pvalue) {
		return ecError;
	}
	parent_id = *(uint64_t*)pvalue;
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (FALSE == store_object_check_private(pstore)) {
			return ecNotSupported;
		}
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return ecAccessDenied;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pstore), parent_id1,
				pinfo->username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				return ecAccessDenied;
			}
			b_guest = TRUE;
		} else {
			b_guest = FALSE;
		}
		if (!exmdb_client::movecopy_folder(store_object_get_dir(pstore),
		    store_object_get_account_id(pstore), pinfo->cpid, b_guest,
		    pinfo->username, parent_id, folder_id, parent_id1,
		    static_cast<char *>(pproplist->ppropval[3].pvalue), false,
		    &b_exist, &b_partial)) {
			return ecError;
		}
		if (TRUE == b_exist) {
			return ecDuplicateName;
		}
		if (TRUE == b_partial) {
			return ecError;
		}
	}
	if (!exmdb_client::allocate_cn(
		store_object_get_dir(pstore), &change_num)) {
		return ecError;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5 + ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return ecError;
	}
	tmp_propvals.ppropval[0].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	tmp_propvals.ppropval[0].pvalue = pproplist->ppropval[2].pvalue;
	tmp_propvals.ppropval[1].proptag = PROP_TAG_DISPLAYNAME;
	tmp_propvals.ppropval[1].pvalue = pproplist->ppropval[3].pvalue;
	tmp_propvals.ppropval[2].proptag = PROP_TAG_CHANGENUMBER;
	tmp_propvals.ppropval[2].pvalue = &change_num;
	tmp_propvals.count = 3;
	for (i=0; i<ppropvals->count; i++) {
		tmp_propvals.ppropval[tmp_propvals.count] =
							ppropvals->ppropval[i];
		tmp_propvals.count ++;
	}
	if (!exmdb_client::set_folder_properties(
		store_object_get_dir(pstore), pinfo->cpid,
		folder_id, &tmp_propvals, &tmp_problems)) {
		return ecError;
	}
	idset_append(pctx->pstate->pseen, change_num);
	return ecSuccess;
}

uint32_t zarafa_server_importdeletion(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins)
{
	XID tmp_xid;
	void *pvalue;
	BOOL b_exist;
	BOOL b_found;
	uint64_t eid;
	BOOL b_owner;
	int domain_id;
	GUID tmp_guid;
	BOOL b_result;
	BOOL b_partial;
	uint16_t replid;
	uint8_t mapi_type;
	uint8_t sync_type;
	uint64_t folder_id;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	EID_ARRAY message_ids;
	ICSUPCTX_OBJECT *pctx;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSUPCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		return ecNotSupported;
	}
	pstore = icsupctx_object_get_store(pctx);
	sync_type = icsupctx_object_get_type(pctx);
	BOOL b_hard = (flags & SYNC_DELETES_FLAG_HARDDELETE) ? TRUE : false;
	if (SYNC_DELETES_FLAG_HIERARCHY & flags) {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			return ecNotSupported;
		}
	}
	folder_id = icsupctx_object_get_parent_folder_id(pctx);
	username = pinfo->username;
	if (TRUE == store_object_check_owner_mode(pstore)) {
		username = NULL;
	} else {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pstore), folder_id,
				pinfo->username, &permission)) {
				if (permission & (PERMISSION_FOLDEROWNER | PERMISSION_DELETEANY)) {
					username = NULL;	
				} else if (0 == (permission & PERMISSION_DELETEOWNED)) {
					return ecAccessDenied;
				}
			}
		}
	}
	if (SYNC_TYPE_CONTENTS == sync_type) {
		message_ids.count = 0;
		message_ids.pids = cu_alloc<uint64_t>(pbins->count);
		if (NULL == message_ids.pids) {
			return ecError;
		}
	}
	for (size_t i = 0; i < pbins->count; ++i) {
		if (22 != pbins->pbin[i].cb) {
			return ecInvalidParam;
		}
		if (FALSE == common_util_binary_to_xid(
			pbins->pbin + i, &tmp_xid)) {
			return ecError;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return ecInvalidParam;
			}
			eid = rop_util_make_eid(1, tmp_xid.local_id);
		} else {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				tmp_guid = rop_util_make_domain_guid(
					store_object_get_account_id(pstore));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					return ecInvalidParam;
				}
				eid = rop_util_make_eid(1, tmp_xid.local_id);
			} else {
				tmp_guid = rop_util_make_domain_guid(
					store_object_get_account_id(pstore));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					domain_id = rop_util_make_domain_id(tmp_xid.guid);
					if (-1 == domain_id) {
						return ecInvalidParam;
					}
					if (FALSE == system_services_check_same_org(
						domain_id, store_object_get_account_id(pstore))) {
						return ecInvalidParam;
					}
					if (!exmdb_client::get_mapping_replid(
						store_object_get_dir(pstore),
						tmp_xid.guid, &b_found, &replid)) {
						return ecError;
					}
					if (FALSE == b_found) {
						return ecInvalidParam;
					}
					eid = rop_util_make_eid(replid, tmp_xid.local_id);
				} else {
					eid = rop_util_make_eid(1, tmp_xid.local_id);
				}
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (!exmdb_client::check_message(
				store_object_get_dir(pstore), folder_id,
				eid, &b_exist)) {
				return ecError;
			}
		} else {
			if (!exmdb_client::check_folder_id(
				store_object_get_dir(pstore), eid, &b_exist)) {
				return ecError;
			}
		}
		if (FALSE == b_exist) {
			continue;
		}
		if (NULL != username) {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				if (FALSE == exmdb_client_check_message_owner(
					store_object_get_dir(pstore),
					eid, username, &b_owner)) {
					return ecError;
				}
				if (FALSE == b_owner) {
					return ecAccessDenied;
				}
			} else {
				if (!exmdb_client::check_folder_permission(
					store_object_get_dir(pstore),
					eid, username, &permission)) {
					if (0 == (PERMISSION_FOLDEROWNER & permission))	{
						return ecAccessDenied;
					}
				}
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			message_ids.pids[message_ids.count] = eid;
			message_ids.count ++;
		} else {
			if (TRUE == store_object_check_private(pstore)) {
				if (FALSE == exmdb_client_get_folder_property(
					store_object_get_dir(pstore), 0, eid,
					PROP_TAG_FOLDERTYPE, &pvalue)) {
					return ecError;
				}
				if (NULL == pvalue) {
					return ecSuccess;
				}
				if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
					goto DELETE_FOLDER;
				}
			}
			if (!exmdb_client::empty_folder(
				store_object_get_dir(pstore), pinfo->cpid,
				username, eid, b_hard, TRUE, TRUE, TRUE,
				&b_partial) || TRUE == b_partial) {
				return ecError;
			}
 DELETE_FOLDER:
			if (!exmdb_client::delete_folder(
				store_object_get_dir(pstore), pinfo->cpid,
				eid, b_hard, &b_result) || FALSE == b_result) {
				return ecError;
			}
		}
	}
	if (SYNC_TYPE_CONTENTS == sync_type && message_ids.count > 0) {
		if (!exmdb_client::delete_messages(
			store_object_get_dir(pstore),
			store_object_get_account_id(pstore),
			pinfo->cpid, NULL, folder_id, &message_ids,
			b_hard, &b_partial) || TRUE == b_partial) {
			return ecError;
		}
	}
	return ecSuccess;
}

uint32_t zarafa_server_importreadstates(GUID hsession,
	uint32_t hctx, const STATE_ARRAY *pstates)
{
	XID tmp_xid;
	BOOL b_owner;
	void *pvalue;
	GUID tmp_guid;
	uint64_t read_cn;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pctx = static_cast<ICSUPCTX_OBJECT *>(object_tree_get_object(
	       pinfo->ptree, hctx, &mapi_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		return ecNotSupported;
	}
	pstore = icsupctx_object_get_store(pctx);
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_type(pctx)) {
		return ecNotSupported;
	}
	username = NULL;
	if (FALSE == store_object_check_owner_mode(pstore)) {
		folder_id = icsupctx_object_get_parent_folder_id(pctx);
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_READANY)) {
			username = pinfo->username;
		}
	}
	for (size_t i = 0; i < pstates->count; ++i) {
		if (FALSE == common_util_binary_to_xid(
			&pstates->pstate[i].source_key, &tmp_xid)) {
			return ecNotSupported;
		}
		tmp_guid = store_object_guid(pstore);
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			continue;
		}
		message_id = rop_util_make_eid(1, tmp_xid.local_id);
		bool mark_as_read = pstates->pstate[i].message_flags & MESSAGE_FLAG_READ;
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				store_object_get_dir(pstore), message_id,
				username, &b_owner)) {
				return ecError;
			}
			if (FALSE == b_owner) {
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_ASSOCIATED;
		proptag_buff[1] = PROP_TAG_READ;
		if (!exmdb_client::get_message_properties(
			store_object_get_dir(pstore), NULL, 0,
			message_id, &tmp_proptags, &tmp_propvals)) {
			return ecError;
		}
		pvalue = common_util_get_propvals(
			&tmp_propvals, PROP_TAG_ASSOCIATED);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			continue;
		}
		pvalue = common_util_get_propvals(
			&tmp_propvals, PROP_TAG_READ);
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			if (!mark_as_read)
				continue;
		} else {
			if (mark_as_read)
				continue;
		}
		if (TRUE == store_object_check_private(pstore)) {
			if (!exmdb_client::set_message_read_state(
				store_object_get_dir(pstore), NULL, message_id,
				mark_as_read, &read_cn)) {
				return ecError;
			}
		} else {
			if (!exmdb_client::set_message_read_state(
				store_object_get_dir(pstore), pinfo->username,
				message_id, mark_as_read, &read_cn)) {
				return ecError;
			}
		}
		idset_append(pctx->pstate->pread, read_cn);
	}
	return ecSuccess;
}

uint32_t zarafa_server_getsearchcriteria(GUID hsession,
	uint32_t hfolder, BINARY_ARRAY *pfolder_array,
	RESTRICTION **pprestriction, uint32_t *psearch_stat)
{
	BINARY *pbin;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	LONGLONG_ARRAY folder_ids;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	if (FOLDER_TYPE_SEARCH != folder_object_get_type(pfolder)) {
		return ecNotSearchFolder;
	}
	if (!exmdb_client::get_search_criteria(
		store_object_get_dir(pstore),
		folder_object_get_id(pfolder),
		psearch_stat, pprestriction,
		&folder_ids)) {
		return ecError;
	}
	pfolder_array->count = folder_ids.count;
	if (0 == folder_ids.count) {
		pfolder_array->pbin = NULL;
		return ecSuccess;
	}
	pfolder_array->pbin = cu_alloc<BINARY>(folder_ids.count);
	if (NULL == pfolder_array->pbin) {
		return ecError;
	}
	for (size_t i = 0; i < folder_ids.count; ++i) {
		pbin = common_util_to_folder_entryid(
				pstore, folder_ids.pll[i]);
		if (NULL == pbin) {
			return ecError;
		}
		pfolder_array->pbin[i] = *pbin;
	}
	return ecSuccess;
}

uint32_t zarafa_server_setsearchcriteria(
	GUID hsession, uint32_t hfolder, uint32_t flags,
	const BINARY_ARRAY *pfolder_array,
	const RESTRICTION *prestriction)
{
	int db_id;
	BOOL b_result;
	BOOL b_private;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	uint32_t search_status;
	FOLDER_OBJECT *pfolder;
	LONGLONG_ARRAY folder_ids;
	
	if (0 == (flags & SEARCH_FLAG_RESTART) &&
		0 == (flags & SEARCH_FLAG_STOP)) {
		/* make the default search_flags */
		flags |= SEARCH_FLAG_RESTART;	
	}
	if (0 == (flags & SEARCH_FLAG_RECURSIVE) &&
		0 == (flags & SEARCH_FLAG_SHALLOW)) {
		/* make the default search_flags */
		flags |= SEARCH_FLAG_SHALLOW;
	}
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pfolder = static_cast<FOLDER_OBJECT *>(object_tree_get_object(
	          pinfo->ptree, hfolder, &mapi_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (MAPI_FOLDER != mapi_type) {
		return ecNotSupported;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == store_object_check_private(pstore)) {
		return ecNotSupported;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (!exmdb_client::check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return ecAccessDenied;
		}
	}
	if (NULL == prestriction || 0 == pfolder_array->count) {
		if (!exmdb_client::get_search_criteria(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			&search_status, NULL, NULL)) {
			return ecError;
		}
		if (SEARCH_STATUS_NOT_INITIALIZED == search_status) {
			return ecNotInitialized;
		}
		if (0 == (flags & SEARCH_FLAG_RESTART) &&
			NULL == prestriction && 0 == pfolder_array->count) {
			return ecSuccess;
		}
	}
	folder_ids.count = pfolder_array->count;
	folder_ids.pll   = cu_alloc<uint64_t>(folder_ids.count);
	if (NULL == folder_ids.pll) {
		return ecError;
	}
	for (size_t i = 0; i < pfolder_array->count; ++i) {
		if (FALSE == common_util_from_folder_entryid(
			pfolder_array->pbin[i], &b_private,
			&db_id, &folder_ids.pll[i])) {
			return ecError;
		}
		if (FALSE == b_private || db_id !=
			store_object_get_account_id(pstore)) {
			return ecSearchFolderScopeViolation;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pstore), folder_ids.pll[i],
				pinfo->username, &permission)) {
				return ecError;
			}
			if (!(permission & (PERMISSION_FOLDEROWNER | PERMISSION_READANY)))
				return ecAccessDenied;
		}
	}
	if (!exmdb_client::set_search_criteria(
		store_object_get_dir(pstore), pinfo->cpid,
		folder_object_get_id(pfolder), flags,
		prestriction, &folder_ids, &b_result)) {
		return ecError;
	}
	if (FALSE == b_result) {
		return ecSearchFolderScopeViolation;
	}
	return ecSuccess;
}

uint32_t zarafa_server_messagetorfc822(GUID hsession,
	uint32_t hmessage, BINARY *peml_bin)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == common_util_message_to_rfc822(
		message_object_get_store(pmessage),
		message_object_get_id(pmessage), peml_bin)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_rfc822tomessage(GUID hsession,
	uint32_t hmessage, const BINARY *peml_bin)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	pmsgctnt = common_util_rfc822_to_message(
		message_object_get_store(pmessage), peml_bin);
	if (NULL == pmsgctnt) {
		return ecError;
	}
	if (FALSE == message_object_write_message(
		pmessage, pmsgctnt)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_messagetoical(GUID hsession,
	uint32_t hmessage, BINARY *pical_bin)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (FALSE == common_util_message_to_ical(
		message_object_get_store(pmessage),
		message_object_get_id(pmessage), pical_bin)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	pmsgctnt = common_util_ical_to_message(
		message_object_get_store(pmessage), pical_bin);
	if (NULL == pmsgctnt) {
		return ecError;
	}
	if (FALSE == message_object_write_message(
		pmessage, pmsgctnt)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_messagetovcf(GUID hsession,
	uint32_t hmessage, BINARY *pvcf_bin)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	if (!common_util_message_to_vcf(pmessage, pvcf_bin)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin)
{
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	pmessage = static_cast<MESSAGE_OBJECT *>(object_tree_get_object(
	           pinfo->ptree, hmessage, &mapi_type));
	if (NULL == pmessage) {
		return ecNullObject;
	}
	if (MAPI_MESSAGE != mapi_type) {
		return ecNotSupported;
	}
	pmsgctnt = common_util_vcf_to_message(
		message_object_get_store(pmessage), pvcf_bin);
	if (NULL == pmsgctnt) {
		return ecError;
	}
	if (FALSE == message_object_write_message(
		pmessage, pmsgctnt)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_getuseravailability(GUID hsession,
	BINARY entryid, uint64_t starttime, uint64_t endtime,
	char **ppresult_string)
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
	
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	if (!common_util_addressbook_entryid_to_username(entryid,
	    username, GX_ARRAY_SIZE(username)) ||
	    !system_services_get_maildir(username, maildir)) {
		*ppresult_string = NULL;
		return ecSuccess;
	}
	if (0 == strcasecmp(pinfo->username, username)) {
		tmp_len = gx_snprintf(cookie_buff, GX_ARRAY_SIZE(cookie_buff),
			"starttime=%lu;endtime=%lu;dirs=1;dir0=%s",
			starttime, endtime, maildir);
	} else {
		tmp_len = gx_snprintf(cookie_buff, GX_ARRAY_SIZE(cookie_buff),
			"username=%s;starttime=%lu;endtime=%lu;dirs=1;dir0=%s",
			pinfo->username, starttime, endtime, maildir);
	}
	pinfo.reset();
	 if (-1 == pipe(pipes_in)) {
		return ecError;
	}
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
	if (0 != status) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t zarafa_server_setpasswd(const char *username,
	const char *passwd, const char *new_passwd)
{
	if (FALSE == system_services_set_password(
		username, passwd, new_passwd)) {
		return ecAccessDenied;
	}
	return ecSuccess;
}

uint32_t zarafa_server_linkmessage(GUID hsession,
	BINARY search_entryid, BINARY message_entryid)
{
	uint32_t cpid;
	BOOL b_result;
	BOOL b_private;
	BOOL b_private1;
	uint32_t handle;
	char maildir[256];
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t folder_id1;
	uint64_t message_id;
	uint32_t account_id;
	uint32_t account_id1;
	STORE_OBJECT *pstore;
	
	if (common_util_get_messaging_entryid_type(search_entryid) != EITLT_PRIVATE_FOLDER ||
	    !common_util_from_folder_entryid(search_entryid, &b_private,
	    reinterpret_cast<int *>(&account_id), &folder_id) ||
	    b_private != TRUE)
		return ecInvalidParam;
	if (common_util_get_messaging_entryid_type(message_entryid) != EITLT_PRIVATE_MESSAGE ||
	    !common_util_from_message_entryid(message_entryid, &b_private1,
	    reinterpret_cast<int *>(&account_id1), &folder_id1, &message_id) ||
	    b_private1 != TRUE || account_id != account_id1)
		return ecInvalidParam;
	auto pinfo = zarafa_server_query_session(hsession);
	if (pinfo == nullptr)
		return ecError;
	handle = object_tree_get_store_handle(
		pinfo->ptree, b_private, account_id);
	if (INVALID_HANDLE == handle) {
		return ecNullObject;
	}
	if (pinfo->user_id < 0 || static_cast<unsigned int>(pinfo->user_id) != account_id) {
		return ecAccessDenied;
	}
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(pinfo->ptree, handle, &mapi_type));
	if (NULL == pstore || MAPI_STORE != mapi_type) {
		return ecError;
	}
	strcpy(maildir, store_object_get_dir(pstore));
	cpid = pinfo->cpid;
	pinfo.reset();
	if (!exmdb_client::link_message(maildir, cpid,
		folder_id, message_id, &b_result) || FALSE == b_result) {
		return ecError;
	}
	return ecSuccess;
}
