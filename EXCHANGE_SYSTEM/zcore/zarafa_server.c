#include "util.h"
#include "guid.h"
#include "rpc_ext.h"
#include "ab_tree.h"
#include "rop_util.h"
#include "int_hash.h"
#include "str_hash.h"
#include "ext_buffer.h"
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
#include <sys/socket.h>
#include <stdio.h>
#include <poll.h>

typedef struct _NOTIFY_ITEM {
	DOUBLE_LIST notify_list;
	GUID hsession;
	uint32_t hstore;
	time_t last_time;
} NOTIFY_ITEM;

typedef struct _SINK_NODE {
	DOUBLE_LIST_NODE node;
	int clifd;
	time_t until_time;
	NOTIF_SINK sink;
} SINK_NODE;

static int g_table_size;
static BOOL g_notify_stop;
static int g_ping_interval;
static pthread_t g_scan_id;
static int g_cache_interval;
static pthread_key_t g_info_key;
static pthread_mutex_t g_table_lock;
static STR_HASH_TABLE *g_user_table;
static pthread_mutex_t g_notify_lock;
static STR_HASH_TABLE *g_notify_table;
static INT_HASH_TABLE *g_session_table;

static int zarafa_server_get_user_id(GUID hsession)
{
	int user_id;
	
	memcpy(&user_id, hsession.node, sizeof(int));
	return user_id;
}

static USER_INFO* zarafa_server_query_session(GUID hsession)
{
	int user_id;
	USER_INFO *pinfo;
	
	user_id = zarafa_server_get_user_id(hsession);
	pthread_mutex_lock(&g_table_lock);
	pinfo = int_hash_query(g_session_table, user_id);
	if (NULL == pinfo) {
		pthread_mutex_unlock(&g_table_lock);
		return NULL;
	}
	if (0 != guid_compare(&hsession, &pinfo->hsession)) {
		pthread_mutex_unlock(&g_table_lock);
		return NULL;
	}
	pinfo->reference ++;
	time(&pinfo->last_time);
	pthread_mutex_unlock(&g_table_lock);
	pthread_mutex_lock(&pinfo->lock);
	pthread_setspecific(g_info_key, pinfo);
	return pinfo;
}

USER_INFO* zarafa_server_get_info()
{
	return pthread_getspecific(g_info_key);
}

static void zarafa_server_put_user_info(USER_INFO *pinfo)
{
	pthread_mutex_unlock(&pinfo->lock);
	pthread_mutex_lock(&g_table_lock);
	pinfo->reference --;
	pthread_mutex_unlock(&g_table_lock);
	pthread_setspecific(g_info_key, NULL);
}

static void* scan_work_func(void *param)
{
	int count;
	int tv_msec;
	BINARY tmp_bin;
	time_t cur_time;
	USER_INFO *pinfo;
	uint8_t tmp_byte;
	OBJECT_TREE *ptree;
	NOTIFY_ITEM *pnitem;
	INT_HASH_ITER *iter;
	STR_HASH_ITER *iter1;
	struct pollfd fdpoll;
	RPC_RESPONSE response;
	SINK_NODE *psink_node;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST temp_list1;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	
	count = 0;
	double_list_init(&temp_list);
	double_list_init(&temp_list1);
	response.call_id = CALL_ID_NOTIFDEQUEUE;
	response.result = EC_SUCCESS;
	response.payload.notifdequeue.notifications.count = 0;
	response.payload.notifdequeue.notifications.ppnotification = NULL;
	while (FALSE == g_notify_stop) {
		sleep(1);
		count ++;
		if (count >= g_ping_interval) {
			count = 0;
		}
		pthread_mutex_lock(&g_table_lock);
		time(&cur_time);
		iter = int_hash_iter_init(g_session_table);
		for (int_hash_iter_begin(iter);
			FALSE == int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			pinfo = int_hash_iter_get_value(iter, NULL);
			if (0 != pinfo->reference) {
				continue;
			}
			ptail = double_list_get_tail(&pinfo->sink_list);
			while (pnode=double_list_get_from_head(
				&pinfo->sink_list)) {
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
				pnode = malloc(sizeof(DOUBLE_LIST_NODE));
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
		pthread_mutex_unlock(&g_table_lock);
		while (pnode=double_list_get_from_head(&temp_list)) {
			common_util_build_environment();
			exmdb_client_ping_store(pnode->pdata);
			common_util_free_environment();
			free(pnode->pdata);
			free(pnode);
		}
		while (pnode=double_list_get_from_head(&temp_list1)) {
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
				read(psink_node->clifd, &tmp_byte, 1);
			}
			close(psink_node->clifd);
			free(psink_node->sink.padvise);
			free(psink_node);
		}
		if (0 != count) {
			continue;
		}
		time(&cur_time);
		pthread_mutex_lock(&g_notify_lock);
		iter1 = str_hash_iter_init(g_notify_table);
		for (str_hash_iter_begin(iter1);
			FALSE == str_hash_iter_done(iter1);
			str_hash_iter_forward(iter1)) {
			pnitem = str_hash_iter_get_value(iter1, NULL);
			if (cur_time - pnitem->last_time >= g_cache_interval) {
				while (pnode=double_list_get_from_head(
					&pnitem->notify_list)) {
					common_util_free_znotification(pnode->pdata);
					free(pnode);
				}
				double_list_free(&pnitem->notify_list);
				str_hash_iter_remove(iter1);
			}
		}
		pthread_mutex_unlock(&g_notify_lock);
	}
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
	USER_INFO *pinfo;
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
	RPC_RESPONSE response;
	SINK_NODE *psink_node;
	uint64_t old_parentid;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	uint32_t proptag_buff[2];
	ZNOTIFICATION *pnotification;
	NEWMAIL_ZNOTIFICATION *pnew_mail;
	OBJECT_ZNOTIFICATION *pobj_notify;
	
	if (TRUE == b_table) {
		return;
	}
	sprintf(tmp_buff, "%u|%s", notify_id, dir);
	pthread_mutex_lock(&g_notify_lock);
	pitem = str_hash_query(g_notify_table, tmp_buff);
	if (NULL == pitem) {
		pthread_mutex_unlock(&g_notify_lock);
		return;
	}
	hsession = pitem->hsession;
	hstore = pitem->hstore;
	pthread_mutex_unlock(&g_notify_lock);
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return;
	}
	pstore = object_tree_get_object(pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore || MAPI_STORE != mapi_type ||
		0 != strcmp(dir, store_object_get_dir(pstore))) {
		zarafa_server_put_user_info(pinfo);
		return;
	}
	pnotification = common_util_alloc(sizeof(ZNOTIFICATION));
	if (NULL == pnotification) {
		zarafa_server_put_user_info(pinfo);
		return;
	}
	switch (pdb_notify->type) {
	case DB_NOTIFY_TYPE_NEW_MAIL:
		pnotification->event_type = EVENT_TYPE_NEWMAIL;
		pnew_mail = common_util_alloc(sizeof(NEWMAIL_ZNOTIFICATION));
		if (NULL == pnew_mail) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pnotification->pnotification_data = pnew_mail;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_NEW_MAIL*)pdb_notify->pdata)->folder_id);
		message_id = rop_util_make_eid_ex(1,
			((DB_NOTIFY_NEW_MAIL*)pdb_notify->pdata)->message_id);
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pnew_mail->entryid = *pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pnew_mail->parentid = *pbin;
		proptags.count = 2;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_MESSAGECLASS;
		proptag_buff[1] = PROP_TAG_MESSAGEFLAGS;
		if (FALSE == exmdb_client_get_message_properties(dir,
			NULL, 0, message_id, &proptags, &propvals)) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pvalue = common_util_get_propvals(
			&propvals, PROP_TAG_MESSAGECLASS);
		if (NULL == pvalue) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pnew_mail->message_class = pvalue;
		pvalue = common_util_get_propvals(
			&propvals, PROP_TAG_MESSAGEFLAGS);
		if (NULL == pvalue) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pnew_mail->message_flags = *(uint32_t*)pvalue;
		break;
	case DB_NOTIFY_TYPE_FOLDER_CREATED:
		pnotification->event_type = EVENT_TYPE_OBJECTCREATED;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_CREATED*)pdb_notify->pdata)->folder_id);
		parent_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_CREATED*)pdb_notify->pdata)->parent_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, parent_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	case DB_NOTIFY_TYPE_MESSAGE_CREATED:
		pnotification->event_type = EVENT_TYPE_OBJECTCREATED;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_MESSAGE_CREATED*)pdb_notify->pdata)->folder_id);
		message_id = rop_util_make_eid_ex(1,
			((DB_NOTIFY_MESSAGE_CREATED*)pdb_notify->pdata)->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	case DB_NOTIFY_TYPE_FOLDER_DELETED:
		pnotification->event_type = EVENT_TYPE_OBJECTDELETED;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_DELETED*)pdb_notify->pdata)->folder_id);
		parent_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_CREATED*)pdb_notify->pdata)->parent_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, parent_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	case DB_NOTIFY_TYPE_MESSAGE_DELETED:
		pnotification->event_type = EVENT_TYPE_OBJECTDELETED;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_MESSAGE_DELETED*)pdb_notify->pdata)->folder_id);
		message_id = rop_util_make_eid_ex(1,
			((DB_NOTIFY_MESSAGE_DELETED*)pdb_notify->pdata)->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED:
		pnotification->event_type = EVENT_TYPE_OBJECTMODIFIED;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_MODIFIED*)pdb_notify->pdata)->folder_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED:
		pnotification->event_type = EVENT_TYPE_OBJECTMODIFIED;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_MESSAGE_MODIFIED*)pdb_notify->pdata)->folder_id);
		message_id = rop_util_make_eid_ex(1,
			((DB_NOTIFY_MESSAGE_MODIFIED*)pdb_notify->pdata)->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		break;
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED:
		if (DB_NOTIFY_TYPE_FOLDER_MOVED == pdb_notify->type) {
			pnotification->event_type = EVENT_TYPE_OBJECTMOVED;
		} else {
			pnotification->event_type = EVENT_TYPE_OBJECTCOPIED;
		}
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_MVCP*)pdb_notify->pdata)->folder_id);
		parent_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_MVCP*)pdb_notify->pdata)->parent_id);
		old_eid = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_MVCP*)pdb_notify->pdata)->old_folder_id);
		old_parentid = common_util_convert_notification_folder_id(
			((DB_NOTIFY_FOLDER_MVCP*)pdb_notify->pdata)->old_parent_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, parent_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		pbin = common_util_to_folder_entryid(pstore, old_eid);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pold_entryid = pbin;
		pbin = common_util_to_folder_entryid(pstore, old_parentid);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pold_parentid = pbin;
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED:
		if (DB_NOTIFY_TYPE_MESSAGE_MOVED == pdb_notify->type) {
			pnotification->event_type = EVENT_TYPE_OBJECTMOVED;
		} else {
			pnotification->event_type = EVENT_TYPE_OBJECTCOPIED;
		}
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		old_parentid = common_util_convert_notification_folder_id(
			((DB_NOTIFY_MESSAGE_MVCP*)pdb_notify->pdata)->old_folder_id);
		old_eid = rop_util_make_eid_ex(1,
			((DB_NOTIFY_MESSAGE_MVCP*)pdb_notify->pdata)->old_message_id);
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_MESSAGE_MVCP*)pdb_notify->pdata)->folder_id);
		message_id = rop_util_make_eid_ex(1,
			((DB_NOTIFY_MESSAGE_MVCP*)pdb_notify->pdata)->message_id);
		pobj_notify->object_type = OBJECT_MESSAGE;
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		pbin = common_util_to_folder_entryid(
							pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pparentid = pbin;
		pbin = common_util_to_message_entryid(
				pstore, old_parentid, old_eid);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pold_entryid = pbin;
		pbin = common_util_to_folder_entryid(
						pstore, old_parentid);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pold_parentid = pbin;
		break;
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED:
		pnotification->event_type = EVENT_TYPE_SEARCHCOMPLETE;
		pobj_notify = common_util_alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == pobj_notify) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		memset(pobj_notify, 0, sizeof(OBJECT_ZNOTIFICATION));
		pnotification->pnotification_data = pobj_notify;
		folder_id = common_util_convert_notification_folder_id(
			((DB_NOTIFY_SEARCH_COMPLETED*)pdb_notify->pdata)->folder_id);
		pobj_notify->object_type = OBJECT_FOLDER;
		pbin = common_util_to_folder_entryid(pstore, folder_id);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return;
		}
		pobj_notify->pentryid = pbin;
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return;
	}
	for (pnode=double_list_get_head(&pinfo->sink_list); NULL!=pnode;
		pnode=double_list_get_after(&pinfo->sink_list, pnode)) {
		psink_node = (SINK_NODE*)pnode->pdata;
		for (i=0; i<psink_node->sink.count; i++) {
			if (psink_node->sink.padvise[i].sub_id == notify_id
				&& hstore == psink_node->sink.padvise[i].hstore) {
				double_list_remove(&pinfo->sink_list, pnode);
				response.call_id = CALL_ID_NOTIFDEQUEUE;
				response.result = EC_SUCCESS;
				response.payload.notifdequeue.notifications.count = 1;
				response.payload.notifdequeue.notifications.ppnotification =
															&pnotification;
				tv_msec = SOCKET_TIMEOUT * 1000;
				fdpoll.fd = psink_node->clifd;
				fdpoll.events = POLLOUT|POLLWRBAND;
				if (FALSE == rpc_ext_push_response(
					&response, &tmp_bin)) {
					tmp_byte = RESPONSE_CODE_PUSH_ERROR;
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
				zarafa_server_put_user_info(pinfo);
				return;
			}
		}
	}
	pnode = malloc(sizeof(DOUBLE_LIST_NODE));
	if (NULL == pnode) {
		zarafa_server_put_user_info(pinfo);
		return;
	}
	pnode->pdata = common_util_dup_znotification(pnotification, FALSE);
	if (NULL == pnode->pdata) {
		zarafa_server_put_user_info(pinfo);
		free(pnode);
		return;
	}
	pthread_mutex_lock(&g_notify_lock);
	pitem = str_hash_query(g_notify_table, tmp_buff);
	if (NULL != pitem) {
		double_list_append_as_tail(&pitem->notify_list, pnode);
	}
	pthread_mutex_unlock(&g_notify_lock);
	zarafa_server_put_user_info(pinfo);
	if (NULL == pitem) {
		common_util_free_znotification(pnode->pdata);
		free(pnode);
	}
}

void zarafa_server_init(int table_size,
	int cache_interval, int ping_interval)
{
	g_table_size = table_size;
	g_cache_interval = cache_interval;
	g_ping_interval = ping_interval;
	pthread_mutex_init(&g_table_lock, NULL);
	pthread_mutex_init(&g_notify_lock, NULL);
	pthread_key_create(&g_info_key, NULL);
}

int zarafa_server_run()
{
	g_session_table = int_hash_init(
		g_table_size, sizeof(USER_INFO), NULL);
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
		str_hash_free(g_notify_table);
		int_hash_free(g_session_table);
		printf("[zarafa_server]: fail to "
			"create notify hash table\n");
		return -3;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_id,
		NULL, scan_work_func, NULL)) {
		printf("[zarafa_server]: fail to"
			" create scanning thread\n");
		str_hash_free(g_user_table);
		int_hash_free(g_session_table);
		return -4;
	}
	exmdb_client_register_proc(zarafa_server_notification_proc);
	return 0;
}

int zarafa_server_stop()
{
	USER_INFO *pinfo;
	INT_HASH_ITER *iter;
	SINK_NODE *psink_node;
	DOUBLE_LIST_NODE *pnode;
	
	g_notify_stop = TRUE;
	pthread_join(g_scan_id, NULL);
	iter = int_hash_iter_init(g_session_table);
	for (int_hash_iter_begin(iter);
		FALSE == int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		pinfo = int_hash_iter_get_value(iter, NULL);
		while (pnode=double_list_get_from_head(
			&pinfo->sink_list)) {
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
	pthread_mutex_destroy(&g_table_lock);
	pthread_mutex_destroy(&g_notify_lock);
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
	char *pdomain;
	char charset[64];
	char reason[256];
	USER_INFO *pinfo;
	char homedir[256];
	char maildir[256];
	char tmp_name[256];
	USER_INFO tmp_info;
	
	pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		return EC_UNKNOWN_USER;
	}
	pdomain ++;
	if (NULL != password) {
		if (FALSE == system_services_auth_login(
			username, password, maildir, lang,
			reason, 256)) {
			return EC_LOGIN_FAILURE;
		}
	}
	strncpy(tmp_name, username, sizeof(tmp_name));
	lower_string(tmp_name);
	pthread_mutex_lock(&g_table_lock);
	puser_id = str_hash_query(g_user_table, tmp_name);
	if (NULL != puser_id) {
		user_id = *puser_id;
		pinfo = int_hash_query(g_session_table, user_id);
		if (NULL != pinfo) {
			time(&pinfo->last_time);
			*phsession = pinfo->hsession;
			pthread_mutex_unlock(&g_table_lock);
			return EC_SUCCESS;
		}
		str_hash_remove(g_user_table, tmp_name);
	}
	pthread_mutex_unlock(&g_table_lock);
	if (FALSE == system_services_get_id_from_username(
		username, &user_id) ||
		FALSE == system_services_get_homedir(
		pdomain, homedir) ||
		FALSE == system_services_get_domain_ids(
		pdomain, &domain_id, &org_id)) {
		return EC_ERROR;
	}
	if (NULL == password) {
		if (FALSE == system_services_get_maildir(
			username, maildir) ||
			FALSE == system_services_get_user_lang(
			username, lang)) {
			return EC_ERROR;
		}
	}
	tmp_info.reference = 0;
	tmp_info.hsession = guid_random_new();
	memcpy(tmp_info.hsession.node, &user_id, sizeof(int));
	tmp_info.user_id = user_id;
	tmp_info.domain_id = domain_id;
	tmp_info.org_id = org_id;
	strcpy(tmp_info.username, username);
	lower_string(tmp_info.username);
	strcpy(tmp_info.lang, lang);
	if (FALSE == system_services_lang_to_charset(
		lang, charset)) {
		tmp_info.cpid = 1252;
	} else {
		tmp_info.cpid = system_services_charset_to_cpid(charset);
	}
	strcpy(tmp_info.maildir, maildir);
	strcpy(tmp_info.homedir, homedir);
	tmp_info.flags = flags;
	time(&tmp_info.last_time);
	tmp_info.reload_time = tmp_info.last_time;
	double_list_init(&tmp_info.sink_list);
	tmp_info.ptree = object_tree_create(maildir);
	if (NULL == tmp_info.ptree) {
		return EC_ERROR;
	}
	pthread_mutex_lock(&g_table_lock);
	pinfo = int_hash_query(g_session_table, user_id);
	if (NULL != pinfo) {
		*phsession = pinfo->hsession;
		pthread_mutex_unlock(&g_table_lock);
		object_tree_free(tmp_info.ptree);
		return EC_SUCCESS;
	}
	if (1 != int_hash_add(g_session_table, user_id, &tmp_info)) {
		pthread_mutex_unlock(&g_table_lock);
		object_tree_free(tmp_info.ptree);
		return EC_ERROR;
	}
	if (1 != str_hash_add(g_user_table, tmp_name, &user_id)) {
		int_hash_remove(g_session_table, user_id);
		pthread_mutex_unlock(&g_table_lock);
		object_tree_free(tmp_info.ptree);
		return EC_ERROR;
	}
	pinfo = int_hash_query(g_session_table, user_id);
	pthread_mutex_init(&pinfo->lock, NULL);
	pthread_mutex_unlock(&g_table_lock);
	*phsession = tmp_info.hsession;
	return EC_SUCCESS;
}

uint32_t zarafa_server_checksession(GUID hsession)
{
	USER_INFO *pinfo;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
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
		common_util_username_to_essdn(username, x500dn)) {
		return EC_NOT_FOUND;
	}
	tmp_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
							tmp_entryid.provider_uid);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER;
	tmp_entryid.px500dn = x500dn;
	pentryid->pb = common_util_alloc(1280);
	if (NULL == pentryid->pb) {
		return EC_ERROR;
	}
	ext_buffer_push_init(&ext_push, pentryid->pb, 1280, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
		&ext_push, &tmp_entryid)) {
		return EC_ERROR;
	}
	pentryid->cb = ext_push.offset;
	*ppdisplay_name = common_util_dup(display_name);
	*ppx500dn = common_util_dup(x500dn);
	if (NULL == *ppdisplay_name || NULL == *ppx500dn) {
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t zarafa_server_unloadobject(GUID hsession, uint32_t hobject)
{
	USER_INFO *pinfo;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	object_tree_release_object_handle(pinfo->ptree, hobject);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
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
	USER_INFO *pinfo;
	char essdn[1024];
	uint8_t loc_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t address_type;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
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
		zarafa_server_put_user_info(pinfo);
		if (INVALID_HANDLE == handle) {
			return EC_NULL_OBJECT;
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
		zarafa_server_put_user_info(pinfo);
		if (INVALID_HANDLE == handle) {
			return EC_NULL_OBJECT;
		}
		return zarafa_server_openstoreentry(hsession,
			handle, entryid, flags, pmapi_type, phobject);
	}
	if (0 == strncmp(entryid.pb, "/exmdb=", 7)) {
		strncpy(essdn, entryid.pb, sizeof(essdn));
	} else if (TRUE == common_util_parse_addressbook_entryid(
		entryid, &address_type, essdn) &&
		0 == strncmp(essdn, "/exmdb=", 7) &&
		ADDRESSBOOK_ENTRYID_TYPE_REMOTE_USER == address_type) {
		/* do nothing */	
	} else {
		zarafa_server_put_user_info(pinfo);
		return EC_INVALID_PARAMETER;
	}
	if (FALSE == common_util_exmdb_locinfo_from_string(
		essdn + 7, &loc_type, &user_id, &eid)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
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
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	
	handle = object_tree_get_store_handle(
		pinfo->ptree, b_private, user_id);
	zarafa_server_put_user_info(pinfo);
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
	BOOL b_writable;
	char essdn[1024];
	USER_INFO *pinfo;
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
	FOLDER_OBJECT *pfolder;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (0 == entryid.cb) {
		if (TRUE == store_object_check_private(pstore)) {
			folder_id = rop_util_make_eid_ex(1, PRIVATE_FID_ROOT);
		} else {
			folder_id = rop_util_make_eid_ex(1, PUBLIC_FID_ROOT);
		}
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
		if (0 == strncmp(entryid.pb, "/exmdb=", 7)) {
			strncpy(essdn, entryid.pb, sizeof(essdn));
		} else if (TRUE == common_util_parse_addressbook_entryid(
			entryid, &address_type, essdn) &&
			0 == strncmp(essdn, "/exmdb=", 7) &&
			ADDRESSBOOK_ENTRYID_TYPE_REMOTE_USER == address_type) {
			/* do nothing */	
		} else {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		if (FALSE == common_util_exmdb_locinfo_from_string(
			essdn + 7, &loc_type, &account_id, &eid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
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
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		if (LOC_TYPE_PRIVATE_MESSAGE == loc_type ||
			LOC_TYPE_PUBLIC_MESSAGE == loc_type) {
			if (FALSE == exmdb_client_get_message_property(
				store_object_get_dir(pstore), NULL, 0,
				message_id, PROP_TAG_PARENTFOLDERID,
				&pvalue) || NULL == pvalue) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			folder_id = *(uint64_t*)pvalue;
		}
CHECK_LOC:
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore)) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
	}
	if (0 != message_id) {
		if (FALSE == exmdb_client_check_message_deleted(
			store_object_get_dir(pstore), message_id, &b_del)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (TRUE == b_del && 0 == (flags & FLAG_SOFT_DELETE)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		tag_access = 0;
		if (TRUE == store_object_check_owner_mode(pstore)) {
			tag_access = TAG_ACCESS_MODIFY|
				TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			goto PERMISSION_CHECK;
		}
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_READANY) &&
			0 == (permission & PERMISSION_FOLDERVISIBLE) &&
			0 == (permission & PERMISSION_FOLDEROWNER)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (permission & PERMISSION_FOLDEROWNER) {
			tag_access = TAG_ACCESS_MODIFY|
				TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			goto PERMISSION_CHECK;
		}
		if (FALSE == exmdb_client_check_message_owner(
			store_object_get_dir(pstore), message_id,
			pinfo->username, &b_owner)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
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
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (0 == (TAG_ACCESS_MODIFY & tag_access)) {
			b_writable = FALSE;
		} else {
			b_writable = TRUE;
		}
		pmessage = message_object_create(pstore, FALSE, pinfo->cpid,
				message_id, &folder_id, tag_access, b_writable, NULL);
		if (NULL == pmessage) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		*phobject = object_tree_add_object_handle(
			pinfo->ptree, hobject, MAPI_MESSAGE,
			pmessage);
		if (INVALID_HANDLE == *phobject) {
			message_object_free(pmessage);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		} else {
			*pmapi_type = MAPI_MESSAGE;
		}
	} else {
		if (FALSE == exmdb_client_check_folder_id(
			store_object_get_dir(pstore), folder_id,
			&b_exist)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == b_exist) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		if (FALSE == store_object_check_private(pstore)) {
			if (FALSE == exmdb_client_check_folder_deleted(
				store_object_get_dir(pstore), folder_id, &b_del)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (TRUE == b_del && 0 == (flags & FLAG_SOFT_DELETE)) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_FOUND;
			}
		}
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue) || NULL == pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		folder_type = *(uint32_t*)pvalue;
		if (TRUE == store_object_check_owner_mode(pstore)) {
			tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
					TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
					TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
		} else {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore), folder_id,
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
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
			if (0 == (permission & PERMISSION_READANY) &&
				0 == (permission & PERMISSION_FOLDERVISIBLE) &&
				0 == (permission & PERMISSION_FOLDEROWNER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_FOUND;
			}
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
		pfolder = folder_object_create(pstore,
			folder_id, folder_type, tag_access);
		if (NULL == pfolder) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		*phobject = object_tree_add_object_handle(
			pinfo->ptree, hobject, MAPI_FOLDER, pfolder);
		if (INVALID_HANDLE == *phobject) {
			folder_object_free(pfolder);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		} else {
			*pmapi_type = MAPI_FOLDER;
		}
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_openabentry(GUID hsession,
	BINARY entryid, uint8_t *pmapi_type, uint32_t *phobject)
{
	GUID guid;
	int base_id;
	int user_id;
	uint8_t type;
	void *pobject;
	int domain_id;
	AB_BASE *pbase;
	uint32_t minid;
	uint8_t loc_type;
	USER_INFO *pinfo;
	char essdn[1024];
	char tmp_buff[16];
	uint32_t address_type;
	SIMPLE_TREE_NODE *pnode;
	CONTAINER_ID container_id;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	if (0 == pinfo->org_id) {
		base_id = pinfo->domain_id * (-1);
	} else {
		base_id = pinfo->org_id;
	}
	if (0 == entryid.cb) {
		container_id.abtree_id.base_id = base_id;
		container_id.abtree_id.minid = 0xFFFFFFFF;
		pobject = container_object_create(
			CONTAINER_TYPE_ABTREE, container_id);
		if (NULL == pobject) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		*pmapi_type = MAPI_ABCONT;
		*phobject = object_tree_add_object_handle(
			pinfo->ptree, ROOT_HANDLE, *pmapi_type, pobject);
		if (INVALID_HANDLE == *phobject) {
			container_object_free(pobject);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	if (TRUE == common_util_parse_addressbook_entryid(
		entryid, &address_type, essdn)) {
		if (ADDRESSBOOK_ENTRYID_TYPE_CONTAINER == address_type) {
			lower_string(essdn);
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
						zarafa_server_put_user_info(pinfo);
						return EC_NOT_FOUND;
					}
					container_id.exmdb_id.b_private = TRUE;
					type = CONTAINER_TYPE_FOLDER;
				} else {
					if (0 != strncmp(essdn, "/guid=", 6) || 38 != strlen(essdn)) {
						zarafa_server_put_user_info(pinfo);
						return EC_NOT_FOUND;
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
					pbase = ab_tree_get_base(base_id);
					if (NULL == pbase) {
						zarafa_server_put_user_info(pinfo);
						return EC_ERROR;
					}
					pnode = ab_tree_guid_to_node(pbase, guid);
					if (NULL == pnode) {
						ab_tree_put_base(pbase);
						zarafa_server_put_user_info(pinfo);
						return EC_NOT_FOUND;
					}
					minid = ab_tree_get_node_minid(pnode);
					ab_tree_put_base(pbase);
					type = CONTAINER_TYPE_ABTREE;
					container_id.abtree_id.base_id = base_id;
					container_id.abtree_id.minid = minid;
				}
			}
			pobject = container_object_create(type, container_id);
			if (NULL == pobject) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			*pmapi_type = MAPI_ABCONT;
		} else if (ADDRESSBOOK_ENTRYID_TYPE_DLIST == address_type ||
			ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER == address_type) {
			if (FALSE == common_util_essdn_to_ids(
				essdn, &domain_id, &user_id)) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_FOUND;
			}
			if (domain_id != pinfo->domain_id && FALSE ==
				system_services_check_same_org(domain_id,
				pinfo->domain_id)) {
				base_id = domain_id * (-1);
			}
			minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, user_id);
			pobject = user_object_create(base_id, minid);
			if (NULL == pobject) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == user_object_check_valid(pobject)) {
				zarafa_server_put_user_info(pinfo);
				user_object_free(pobject);
				return EC_NOT_FOUND;
			}
			if (ADDRESSBOOK_ENTRYID_TYPE_DLIST == address_type) {
				*pmapi_type = MAPI_DISTLIST;
			} else {
				*pmapi_type = MAPI_MAILUSER;
			}
		} else {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
	} else {
		zarafa_server_put_user_info(pinfo);
		return EC_INVALID_PARAMETER;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree,
						ROOT_HANDLE, *pmapi_type, pobject);
	zarafa_server_put_user_info(pinfo);
	if (INVALID_HANDLE == *phobject) {
		switch (*pmapi_type) {
		case MAPI_ABCONT:
			container_object_free(pobject);
			break;
		case MAPI_MAILUSER:
			user_object_free(pobject);
			break;
		}
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t zarafa_server_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set)
{
	int i;
	int base_id;
	char *pstring;
	AB_BASE *pbase;
	USER_INFO *pinfo;
	BOOL b_ambiguous;
	SINGLE_LIST temp_list;
	PROPTAG_ARRAY proptags;
	SINGLE_LIST result_list;
	SINGLE_LIST_NODE *pnode;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	if (0 == pinfo->org_id) {
		base_id = pinfo->domain_id * (-1);
	} else {
		base_id = pinfo->org_id;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	single_list_init(&result_list);
	for (i=0; i<pcond_set->count; i++) {
		pstring = common_util_get_propvals(
			pcond_set->pparray[i], PROP_TAG_DISPLAYNAME);
		if (NULL == pstring) {
			presult_set->count = 0;
			presult_set->pparray = NULL;
			ab_tree_put_base(pbase);
			zarafa_server_put_user_info(pinfo);
			return EC_SUCCESS;
		}
		if (FALSE == ab_tree_resolvename(pbase,
			pinfo->cpid, pstring, &temp_list)) {
			ab_tree_put_base(pbase);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		switch (single_list_get_nodes_num(&temp_list)) {
		case 0:
			ab_tree_put_base(pbase);
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		case 1:
			break;
		default:
			ab_tree_put_base(pbase);
			zarafa_server_put_user_info(pinfo);
			return EC_AMBIGUOUS_RECIP;
		}
		while (pnode=single_list_get_from_head(&temp_list)) {
			single_list_append_as_tail(&result_list, pnode);
		}
	}
	presult_set->count = 0;
	if (0 == single_list_get_nodes_num(&result_list)) {
		presult_set->pparray = NULL;
		ab_tree_put_base(pbase);
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	presult_set->pparray = common_util_alloc(sizeof(void*)
				*single_list_get_nodes_num(&result_list));
	if (NULL == presult_set->pparray) {
		ab_tree_put_base(pbase);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	container_object_get_user_table_all_proptags(&proptags);
	for (pnode=single_list_get_head(&result_list); NULL!=pnode;
		pnode=single_list_get_after(&result_list, pnode)) {
		presult_set->pparray[presult_set->count] =
			common_util_alloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == presult_set->pparray[presult_set->count] ||
			FALSE == ab_tree_fetch_node_properties( pnode->pdata,
			&proptags, presult_set->pparray[presult_set->count])) {
			ab_tree_put_base(pbase);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		presult_set->count ++;
	}
	ab_tree_put_base(pbase);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set)
{
	void *pobject;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		pperm_set->count = 0;
		return EC_NULL_OBJECT;
	}
	switch (mapi_type) {
	case MAPI_STORE:
		if (FALSE == store_object_get_permissions(
			pobject, pperm_set)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		break;
	case MAPI_FOLDER:
		if (FALSE == folder_object_get_permissions(
			pobject, pperm_set)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	FOLDER_OBJECT *pfolder;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == folder_object_set_permissions(pfolder, pset)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_modifyrules(GUID hsession,
	uint32_t hfolder, uint32_t flags, const RULE_LIST *plist)
{
	int i;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	FOLDER_OBJECT *pfolder;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (MODIFY_RULES_FLAG_REPLACE & flags) {
		for (i=0; i<plist->count; i++) {
			if (plist->prule[i].flags != RULE_DATA_FLAG_ADD_ROW) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
		}
	}
	if (FALSE == folder_object_updaterules(pfolder, flags, plist)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getabgal(GUID hsession, BINARY *pentryid)
{
	void *pvalue;
	
	if (FALSE == container_object_fetch_special_property(
		SPECIAL_CONTAINER_GAL, PROP_TAG_ENTRYID, &pvalue)) {
		return EC_ERROR;	
	}
	if (NULL == pvalue) {
		return EC_NOT_FOUND;
	}
	pentryid->cb = ((BINARY*)pvalue)->cb;
	pentryid->pb = ((BINARY*)pvalue)->pb;
	return EC_SUCCESS;
}

uint32_t zarafa_server_loadstoretable(
	GUID hsession, uint32_t *phobject)
{
	USER_INFO *pinfo;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = table_object_create(NULL, NULL, STORE_TABLE, 0);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, ROOT_HANDLE, MAPI_TABLE,
		ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_openstore(GUID hsession,
	BINARY entryid, uint32_t *phobject)
{
	int user_id;
	char dir[256];
	USER_INFO *pinfo;
	EXT_PULL ext_pull;
	char username[256];
	uint32_t permission;
	uint8_t provider_uid[16];
	STORE_ENTRYID store_entryid;
	
	ext_buffer_pull_init(&ext_pull, entryid.pb,
		entryid.cb, common_util_alloc, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_store_entryid(
		&ext_pull, &store_entryid)) {
		return EC_ERROR;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	rop_util_get_provider_uid(
		PROVIDER_UID_WRAPPED_PUBLIC, provider_uid);
	if (0 == memcmp(store_entryid.wrapped_provider_uid,
		provider_uid, 16)) {
		*phobject = object_tree_get_store_handle(
			pinfo->ptree, FALSE, pinfo->domain_id);
	} else {
		if (FALSE == common_util_essdn_to_uid(
			store_entryid.pmailbox_dn, &user_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		if (pinfo->user_id != user_id) {
			if (FALSE == system_services_get_username_from_id(
				user_id, username) ||
				FALSE == system_services_get_maildir(
				username, dir)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == exmdb_client_check_mailbox_permission(
				dir, pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (PERMISSION_NONE == permission) {
				zarafa_server_put_user_info(pinfo);
				return EC_LOGIN_PERM;
			}
		}
		*phobject = object_tree_get_store_handle(
					pinfo->ptree, TRUE, user_id);
	}
	zarafa_server_put_user_info(pinfo);
	if (INVALID_HANDLE == *phobject) {
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t zarafa_server_openpropfilesec(GUID hsession,
	const FLATUID *puid, uint32_t *phobject)
{
	GUID guid;
	BINARY bin;
	USER_INFO *pinfo;
	TPROPVAL_ARRAY *ppropvals;
	
	bin.cb = 16;
	bin.pb = (void*)puid;
	guid = rop_util_binary_to_guid(&bin);
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ppropvals = object_tree_get_profile_sec(pinfo->ptree, guid);
	if (NULL == ppropvals) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	*phobject = object_tree_add_object_handle(pinfo->ptree,
				ROOT_HANDLE, MAPI_PROFPROPERTY, ppropvals);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	void *pobject;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	switch (mapi_type) {
	case MAPI_FOLDER:
		pstore = folder_object_get_store(pobject);
		ptable = table_object_create(pstore,
			pobject, HIERARCHY_TABLE, flags);
		break;
	case MAPI_ABCONT:
		ptable = table_object_create(NULL,
			pobject, CONTAINER_TABLE, flags);
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hfolder, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	void *pobject;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	switch (mapi_type) {
	case MAPI_FOLDER:
		pstore = folder_object_get_store(pobject);
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore),
				folder_object_get_id(pobject),
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_FOUND;
			}
			if (0 == (permission & PERMISSION_READANY) &&
				0 == (permission & PERMISSION_FOLDEROWNER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_FOUND;
			}
		}
		ptable = table_object_create(
			folder_object_get_store(pobject),
			pobject, CONTENT_TABLE, flags);
		break;
	case MAPI_ABCONT:
		ptable = table_object_create(NULL,
				pobject, USER_TABLE, 0);
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hfolder, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	ptable = table_object_create(
		message_object_get_store(pmessage),
		pmessage, RECIPIENT_TABLE, 0);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hmessage, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_loadruletable(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	TABLE_OBJECT *ptable;
	FOLDER_OBJECT *pfolder;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	folder_id = folder_object_get_id(pfolder);
	ptable = table_object_create(
		folder_object_get_store(pfolder),
		&folder_id, RULE_TABLE, 0);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hfolder, MAPI_TABLE, ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_createmessage(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject)
{
	BOOL b_fai;
	void *pvalue;
	uint32_t hstore;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	int64_t max_quota;
	uint64_t folder_id;
	uint32_t total_mail;
	uint64_t total_size;
	uint32_t tag_access;
	uint32_t permission;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	MESSAGE_OBJECT *pmessage;
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (flags & FLAG_ASSOCIATED) {
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	folder_id = folder_object_get_id(pfolder);
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_CREATE)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		tag_access = TAG_ACCESS_MODIFY|TAG_ACCESS_READ;
		if ((permission & PERMISSION_DELETEOWNED) ||
			(permission & PERMISSION_DELETEANY)) {
			tag_access |= TAG_ACCESS_DELETE;
		}
	} else {
		tag_access = TAG_ACCESS_MODIFY|
			TAG_ACCESS_READ|TAG_ACCESS_DELETE;
	}
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MESSAGESIZEEXTENDED;
	proptag_buff[1] = PROP_TAG_PROHIBITSENDQUOTA;
	proptag_buff[2] = PROP_TAG_ASSOCIATEDCONTENTCOUNT;
	proptag_buff[3] = PROP_TAG_CONTENTCOUNT;
	if (FALSE == store_object_get_properties(
		pstore, &tmp_proptags, &tmp_propvals)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_PROHIBITSENDQUOTA);
	if (NULL == pvalue) {
		max_quota = -1;
	} else {
		max_quota = *(uint32_t*)pvalue;
		max_quota *= 1024;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
					PROP_TAG_MESSAGESIZEEXTENDED);
	if (NULL == pvalue) {
		total_size = 0;
	} else {
		total_size = *(uint64_t*)pvalue;
	}
	if (max_quota > 0 && total_size > max_quota) {
		zarafa_server_put_user_info(pinfo);
		return EC_QUOTA_EXCEEDED;
	}
	total_mail = 0;
	pvalue = common_util_get_propvals(&tmp_propvals,
					PROP_TAG_ASSOCIATEDCONTENTCOUNT);
	if (NULL != pvalue) {
		total_mail += *(uint32_t*)pvalue;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_CONTENTCOUNT);
	if (NULL != pvalue) {
		total_mail += *(uint32_t*)pvalue;
	}
	if (total_mail > common_util_get_param(
		COMMON_UTIL_MAX_MESSAGE)) {
		zarafa_server_put_user_info(pinfo);
		return EC_QUOTA_EXCEEDED;
	}
	if (FALSE == exmdb_client_allocate_message_id(
		store_object_get_dir(pstore), folder_id,
		&message_id)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	pmessage = message_object_create(pstore, TRUE,
			pinfo->cpid, message_id, &folder_id,
			tag_access, TRUE, NULL);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == message_object_init_message(
		pmessage, b_fai, pinfo->cpid)) {
		message_object_free(pmessage);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	/* add the store handle as the parent object handle
		because the caller normaly will not keep the
		handle of folder */
	*phobject = object_tree_add_object_handle(
			pinfo->ptree, hstore, MAPI_MESSAGE,
			pmessage);
	if (INVALID_HANDLE == *phobject) {
		message_object_free(pmessage);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_deletemessages(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags)
{
	int i;
	BOOL b_hard;
	BOOL b_owner;
	void *pvalue;
	EID_ARRAY ids;
	EID_ARRAY ids1;
	int account_id;
	BOOL b_private;
	BOOL b_partial;
	USER_INFO *pinfo;
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
	BOOL notify_non_read = FALSE; /* TODO!!! read from config or USER_INFO */
	
	if (FLAG_HARD_DELETE & flags) {
		b_hard = FALSE;
	} else {
		b_hard = TRUE;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return FALSE;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if ((permission & PERMISSION_DELETEANY) ||
			(permission & PERMISSION_FOLDEROWNER)) {
			username = NULL;
		} else if (permission & PERMISSION_DELETEOWNED) {
			username = pinfo->username;
		} else {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
	} else {
		username = NULL;
	}
	ids.count = 0;
	ids.pids = common_util_alloc(sizeof(uint64_t)*pentryids->count);
	if (NULL == ids.pids) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	for (i=0; i<pentryids->count; i++) {
		if (FALSE == common_util_from_message_entryid(
			pentryids->pbin[i], &b_private, &account_id,
			&folder_id, &message_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore)
			|| folder_id != folder_object_get_id(pfolder)) {
			continue;
		}
		ids.pids[ids.count] = message_id;
		ids.count ++;
	}
	if (FALSE == notify_non_read) {
		if (FALSE == exmdb_client_delete_messages(
			store_object_get_dir(pstore),
			store_object_get_account_id(
			pstore), pinfo->cpid, username,
			folder_object_get_id(pfolder),
			&ids, b_hard, &b_partial)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	ids1.count = 0;
	ids1.pids = common_util_alloc(sizeof(uint64_t)*ids.count);
	if (NULL == ids1.pids) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	for (i=0; i<ids.count; i++) {
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				store_object_get_dir(pstore), ids.pids[i],
				username, &b_owner)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == b_owner) {
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
		proptag_buff[1] = PROP_TAG_READ;
		if (FALSE == exmdb_client_get_message_properties(
			store_object_get_dir(pstore), NULL, 0,
			ids.pids[i], &tmp_proptags, &tmp_propvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		pbrief = NULL;
		pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			pvalue = common_util_get_propvals(
				&tmp_propvals, PROP_TAG_READ);
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				if (FALSE == exmdb_client_get_message_brief(
					store_object_get_dir(pstore), pinfo->cpid,
					ids.pids[i], &pbrief)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
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
	if (FALSE == exmdb_client_delete_messages(
		store_object_get_dir(pstore),
		store_object_get_account_id(
		pstore), pinfo->cpid, username,
		folder_object_get_id(pfolder),
		&ids1, b_hard, &b_partial)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_copymessages(GUID hsession,
	uint32_t hsrcfolder, uint32_t hdstfolder,
	const BINARY_ARRAY *pentryids, uint32_t flags)
{
	int i;
	BOOL b_done;
	BOOL b_copy;
	BOOL b_guest;
	BOOL b_owner;
	EID_ARRAY ids;
	BOOL b_partial;
	BOOL b_private;
	int account_id;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission;
	STORE_OBJECT *pstore;
	STORE_OBJECT *pstore1;
	FOLDER_OBJECT *psrc_folder;
	FOLDER_OBJECT *pdst_folder;
	
	if (0 == pentryids->count) {
		return EC_SUCCESS;
	}
	if (FLAG_MOVE & flags) {
		b_copy = FALSE;
	} else {
		b_copy = TRUE;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	psrc_folder = object_tree_get_object(
		pinfo->ptree, hsrcfolder, &mapi_type);
	if (NULL == psrc_folder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(psrc_folder);
	pdst_folder = object_tree_get_object(
		pinfo->ptree, hdstfolder, &mapi_type);
	if (NULL == pdst_folder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type || FOLDER_TYPE_SEARCH
		== folder_object_get_type(pdst_folder)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore1 = folder_object_get_store(pdst_folder);
	if (pstore != pstore1) {
		if (FALSE == b_copy) {
			b_guest = FALSE;
			if (FALSE == store_object_check_owner_mode(pstore)) {
				if (FALSE == exmdb_client_check_folder_permission(
					store_object_get_dir(pstore),
					folder_object_get_id(psrc_folder),
					pinfo->username, &permission)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				if (permission & PERMISSION_DELETEANY) {
					/* permission to delete any message */
				} else if (permission & PERMISSION_DELETEOWNED) {
					b_guest = TRUE;
				} else {
					zarafa_server_put_user_info(pinfo);
					return EC_ACCESS_DENIED;
				}
			}
		}
		if (FALSE == store_object_check_owner_mode(pstore1)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore1),
				folder_object_get_id(pdst_folder),
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (0 == (permission & PERMISSION_CREATE)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		}
		for (i=0; i<pentryids->count; i++) {
			if (FALSE == common_util_from_message_entryid(
				pentryids->pbin[i], &b_private, &account_id,
				&folder_id, &message_id)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (b_private != store_object_check_private(pstore) ||
				account_id != store_object_get_account_id(pstore) ||
				folder_id != folder_object_get_id(psrc_folder)) {
				continue;
			}
			if (FALSE == common_util_remote_copy_message(
				pstore, message_id, pstore1,
				folder_object_get_id(pdst_folder))) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == b_copy) {
				if (TRUE == b_guest) {
					if (FALSE == exmdb_client_check_message_owner(
						store_object_get_dir(pstore), message_id,
						pinfo->username, &b_owner)) {
						zarafa_server_put_user_info(pinfo);
						return EC_ERROR;
					}
					if (FALSE == b_owner) {
						continue;
					}
				}
				if (FALSE == exmdb_client_delete_message(
					store_object_get_dir(pstore),
					store_object_get_account_id(pstore),
					pinfo->cpid, folder_object_get_id(
					pdst_folder), message_id, FALSE,
					&b_done)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;	
				}
			}
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	ids.count = 0;
	ids.pids = common_util_alloc(sizeof(uint64_t)*pentryids->count);
	if (NULL == ids.pids) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	for (i=0; i<pentryids->count; i++) {
		if (FALSE == common_util_from_message_entryid(
			pentryids->pbin[i], &b_private, &account_id,
			&folder_id, &message_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
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
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pdst_folder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_CREATE)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	if (FALSE == exmdb_client_movecopy_messages(
		store_object_get_dir(pstore),
		store_object_get_account_id(pstore),
		pinfo->cpid, b_guest, pinfo->username,
		folder_object_get_id(psrc_folder),
		folder_object_get_id(pdst_folder),
		b_copy, &ids, &b_partial)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_setreadflags(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags)
{
	int i;
	void *pvalue;
	BOOL b_private;
	BOOL b_changed;
	int account_id;
	uint64_t read_cn;
	uint8_t tmp_byte;
	USER_INFO *pinfo;
	uint32_t table_id;
	uint8_t mapi_type;
	uint32_t row_count;
	uint64_t folder_id;
	TARRAY_SET tmp_set;
	uint64_t message_id;
	uint32_t tmp_proptag;
	STORE_OBJECT *pstore;
	const char *username;
	BOOL b_notify = TRUE; /* TODO!!! read from config or USER_INFO */
	BINARY_ARRAY tmp_bins;
	PROPTAG_ARRAY proptags;
	FOLDER_OBJECT *pfolder;
	PROBLEM_ARRAY problems;
	MESSAGE_CONTENT *pbrief;
	TPROPVAL_ARRAY propvals;
	RESTRICTION restriction;
	RESTRICTION_PROPERTY res_prop;
	static uint8_t fake_false = 0;
	TAGGED_PROPVAL propval_buff[2];
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	if (TRUE == store_object_check_owner_mode(pstore)) {
		username = NULL;
	} else {
		username = pinfo->username;
	}
	if (0 == pentryids->count) {
		restriction.rt = RESTRICTION_TYPE_PROPERTY;
		restriction.pres = &res_prop;
		if (FLAG_CLEAR_READ == flags) {
			res_prop.relop = RELOP_NE;
		} else {
			res_prop.relop = RELOP_EQ;
		}
		res_prop.proptag = PROP_TAG_READ;
		res_prop.propval.proptag = PROP_TAG_READ;
		res_prop.propval.pvalue = &fake_false;
		if (FALSE == exmdb_client_load_content_table(
			store_object_get_dir(pstore), 0,
			folder_object_get_id(pfolder), username,
			TABLE_FLAG_NONOTIFICATIONS, &restriction,
			NULL, &table_id, &row_count)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_ENTRYID;
		if (FALSE == exmdb_client_query_table(
			store_object_get_dir(pstore), username,
			0, table_id, &proptags, 0, row_count,
			&tmp_set)) {
			exmdb_client_unload_table(
				store_object_get_dir(
				pstore), table_id);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		exmdb_client_unload_table(
			store_object_get_dir(
			pstore), table_id);
		if (tmp_set.count > 0) {
			tmp_bins.count = 0;
			tmp_bins.pbin = common_util_alloc(
				tmp_set.count*sizeof(BINARY));
			if (NULL == tmp_bins.pbin) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			for (i=0; i<tmp_set.count; i++) {
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
	for (i=0; i<pentryids->count; i++) {
		if (FALSE == common_util_from_message_entryid(
			pentryids->pbin[i], &b_private, &account_id,
			&folder_id, &message_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
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
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				tmp_byte = 0;
				b_changed = TRUE;
			}
		} else {
			if (FALSE == exmdb_client_get_message_property(
				store_object_get_dir(pstore), username, 0,
				message_id, PROP_TAG_READ, &pvalue)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				tmp_byte = 1;
				b_changed = TRUE;
				if (FALSE == exmdb_client_get_message_property(
					store_object_get_dir(pstore), username, 0,
					message_id, PROP_TAG_READRECEIPTREQUESTED,
					&pvalue)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
					b_notify = TRUE;
				}
			}
		}
		if (TRUE == b_changed) {
			if (FALSE == exmdb_client_set_message_read_state(
				store_object_get_dir(pstore), username,
				message_id, tmp_byte, &read_cn)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
		}
		if (TRUE == b_notify) {
			if (FALSE == exmdb_client_get_message_brief(
				store_object_get_dir(pstore), pinfo->cpid,
				message_id, &pbrief)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
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
			propval_buff[0].pvalue = &fake_false;
			propval_buff[1].proptag =
				PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
			propval_buff[1].pvalue = &fake_false;
			exmdb_client_set_message_properties(
				store_object_get_dir(pstore), username,
				0, message_id, &propvals, &problems);
		}
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
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
	uint32_t result;
	BINARY *pentryid;
	USER_INFO *pinfo;
	uint32_t tmp_type;
	uint8_t mapi_type;
	uint64_t last_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	uint32_t tag_access;
	uint32_t permission;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	FOLDER_OBJECT *pparent;
	TPROPVAL_ARRAY tmp_propvals;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	if (FOLDER_TYPE_SEARCH != folder_type &&
		FOLDER_TYPE_GENERIC != folder_type) {
		return EC_NOT_SUPPORTED;	
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pparent = object_tree_get_object(
		pinfo->ptree, hparent_folder,
		&mapi_type);
	if (NULL == pparent) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (1 != rop_util_get_replid(
		folder_object_get_id(pparent))
		|| FOLDER_TYPE_SEARCH ==
		folder_object_get_type(pparent)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pparent);
	if (FALSE == store_object_check_private(pstore)
		&& FOLDER_TYPE_SEARCH == folder_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pparent),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_CREATESUBFOLDER)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == exmdb_client_get_folder_by_name(
		store_object_get_dir(pstore),
		folder_object_get_id(pparent),
		folder_name, &folder_id)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (0 != folder_id) {
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue) || NULL == pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (0 == (flags & FLAG_OPEN_IF_EXISTS) ||
			folder_type != *(uint32_t*)pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_DUPLICATE_NAME;
		}
	} else {
		parent_id = folder_object_get_id(pparent);
		if (FALSE == exmdb_client_allocate_cn(
			store_object_get_dir(pstore), &change_num)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
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
		propval_buff[2].pvalue = (void*)folder_name;
		propval_buff[3].proptag = PROP_TAG_COMMENT;
		propval_buff[3].pvalue = (void*)folder_comment;
		propval_buff[4].proptag = PROP_TAG_CREATIONTIME;
		propval_buff[4].pvalue = &last_time;
		propval_buff[5].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		propval_buff[5].pvalue = &last_time;
		propval_buff[6].proptag = PROP_TAG_CHANGENUMBER;
		propval_buff[6].pvalue = &change_num;
		if (TRUE == store_object_check_private(pstore)) {
			tmp_xid.guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
		} else {
			tmp_xid.guid = rop_util_make_domain_guid(
				store_object_get_account_id(pstore));
		}
		rop_util_get_gc_array(change_num, tmp_xid.local_id);
		propval_buff[7].proptag = PROP_TAG_CHANGEKEY;
		propval_buff[7].pvalue = common_util_xid_to_binary(22, &tmp_xid);
		if (NULL == propval_buff[7].pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		propval_buff[8].proptag = PROP_TAG_PREDECESSORCHANGELIST;
		propval_buff[8].pvalue = common_util_pcl_append(
							NULL, propval_buff[7].pvalue);
		if (NULL == propval_buff[8].pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == exmdb_client_create_folder_by_properties(
			store_object_get_dir(pstore), pinfo->cpid,
			&tmp_propvals, &folder_id) || 0 == folder_id) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			pentryid = common_util_username_to_addressbook_entryid(
													pinfo->username);
			if (NULL == pentryid) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
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
			if (FALSE == exmdb_client_update_folder_permission(
				store_object_get_dir(pstore), folder_id,
				FALSE, 1, &permission_row)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
		}
	}
	tag_access = TAG_ACCESS_MODIFY | TAG_ACCESS_READ |
				TAG_ACCESS_DELETE | TAG_ACCESS_HIERARCHY |
				TAG_ACCESS_CONTENTS | TAG_ACCESS_FAI_CONTENTS;
	pfolder = folder_object_create(pstore,
		folder_id, folder_type, tag_access);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FOLDER_TYPE_SEARCH == folder_type) {
		/* add the store handle as the parent object handle
			because the caller normaly will not keep the
			handle of parent folder */
		hstore = object_tree_get_store_handle(pinfo->ptree,
				TRUE, store_object_get_account_id(pstore));
		if (INVALID_HANDLE == hstore) {
			folder_object_free(pfolder);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		*phobject = object_tree_add_object_handle(
			pinfo->ptree, hstore, MAPI_FOLDER, pfolder);
	} else {
		*phobject = object_tree_add_object_handle(
					pinfo->ptree, hparent_folder,
					MAPI_FOLDER, pfolder);
	}
	if (INVALID_HANDLE == *phobject) {
		folder_object_free(pfolder);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_deletefolder(GUID hsession,
	uint32_t hparent_folder, BINARY entryid, uint32_t flags)
{
	BOOL b_fai;
	BOOL b_sub;
	BOOL b_hard;
	BOOL b_done;
	void *pvalue;
	BOOL b_exist;
	BOOL b_normal;
	BOOL b_partial;
	BOOL b_private;
	int account_id;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	STORE_OBJECT *pstore;
	const char *username;
	FOLDER_OBJECT *pfolder;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hparent_folder,
		&mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == common_util_from_folder_entryid(
		entryid, &b_private, &account_id, &folder_id)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (b_private != store_object_check_private(pstore) ||
		account_id != store_object_get_account_id(pstore)) {
		zarafa_server_put_user_info(pinfo);
		return EC_INVALID_PARAMETER;	
	}
	username = NULL;
	if (TRUE == store_object_check_private(pstore)) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	} else {
		if (1 == rop_util_get_replid(folder_id) &&
			rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		username = pinfo->username;
	}
	if (FALSE == exmdb_client_check_folder_id(
		store_object_get_dir(pstore),
		folder_object_get_id(pfolder),
		&b_exist)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == b_exist) {
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	if (flags & DELETE_FOLDER_FLAG_MESSAGES) {
		b_normal = TRUE;
		b_fai = TRUE;
	} else {
		b_normal = FALSE;
		b_fai = FALSE;
	}
	if (flags & DELETE_FOLDER_FLAG_FOLDERS) {
		b_sub = TRUE;
	} else {
		b_sub = FALSE;
	}
	if (flags & DELETE_FOLDER_FLAG_HARD_DELETE) {
		b_hard = TRUE;
	} else {
		b_hard = FALSE;
	}
	if (TRUE == store_object_check_private(pstore)) {
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, folder_id,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (NULL == pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_SUCCESS;
		}
		if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
			goto DELETE_FOLDER;
		}
	}
	if (TRUE == b_sub || TRUE == b_normal || TRUE == b_fai) {
		if (FALSE == exmdb_client_empty_folder(
			store_object_get_dir(pstore),
			pinfo->cpid, username, folder_id,
			b_hard, b_normal, b_fai, b_sub,
			&b_partial)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (TRUE == b_partial) {
			/* failure occurs, stop deleting folder */
			zarafa_server_put_user_info(pinfo);
			return EC_SUCCESS;
		}
	}
DELETE_FOLDER:
	if (FALSE == exmdb_client_delete_folder(
		store_object_get_dir(pstore),
		pinfo->cpid, folder_id, b_hard,
		&b_done)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_emptyfolder(GUID hsession,
	uint32_t hfolder, uint32_t flags)
{
	BOOL b_fai;
	BOOL b_hard;
	BOOL b_partial;
	USER_INFO *pinfo;
	uint64_t fid_val;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	STORE_OBJECT *pstore;
	const char *username;
	FOLDER_OBJECT *pfolder;
	
	if (flags & FLAG_DEL_ASSOCIATED) {
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	if (flags & FLAG_HARD_DELETE) {
		b_hard = TRUE;
	} else {
		b_hard = FALSE;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == store_object_check_private(pstore)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	fid_val = rop_util_get_gc_value(
		folder_object_get_id(pfolder));
	if (PRIVATE_FID_ROOT == fid_val ||
		PRIVATE_FID_IPMSUBTREE == fid_val) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	username = NULL;
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_DELETEANY) &&
			0 == (permission & PERMISSION_DELETEOWNED)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		username = pinfo->username;
	}
	if (FALSE == exmdb_client_empty_folder(
		store_object_get_dir(pstore), pinfo->cpid,
		username, folder_object_get_id(pfolder),
		b_hard, TRUE, b_fai, TRUE, &b_partial)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_copyfolder(GUID hsession,
	uint32_t hsrc_folder, BINARY entryid, uint32_t hdst_folder,
	const char *new_name, uint32_t flags)
{
	BOOL b_done;
	BOOL b_copy;
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_guest;
	BOOL b_private;
	BOOL b_partial;
	int account_id;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	STORE_OBJECT *pstore1;
	FOLDER_OBJECT *psrc_parent;
	FOLDER_OBJECT *pdst_folder;
	
	if (FLAG_MOVE & flags) {
		b_copy = FALSE;
	} else {
		b_copy = TRUE;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	psrc_parent = object_tree_get_object(
		pinfo->ptree, hsrc_folder, &mapi_type);
	if (NULL == psrc_parent) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (FOLDER_TYPE_SEARCH == folder_object_get_type(
		psrc_parent) && FALSE == b_copy) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(psrc_parent);
	if (FALSE == common_util_from_folder_entryid(
		entryid, &b_private, &account_id, &folder_id)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (b_private != store_object_check_private(pstore) ||
		account_id != store_object_get_account_id(pstore)) {
		zarafa_server_put_user_info(pinfo);
		return EC_INVALID_PARAMETER;
	}
	pdst_folder = object_tree_get_object(
		pinfo->ptree, hdst_folder, &mapi_type);
	if (NULL == pdst_folder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore1 = folder_object_get_store(pdst_folder);
	if (TRUE == store_object_check_private(pstore)) {
		if (PRIVATE_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	} else {
		if (PUBLIC_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_READANY)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pdst_folder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_CREATESUBFOLDER)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		username = pinfo->username;
		b_guest = TRUE;
	} else {
		username = NULL;
		b_guest = FALSE;
	}
	if (pstore != pstore1) {
		if (FALSE == b_copy) {
			if (FALSE == store_object_check_owner_mode(pstore)) {
				if (FALSE == exmdb_client_check_folder_permission(
					store_object_get_dir(pstore),
					folder_object_get_id(psrc_parent),
					pinfo->username, &permission)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				if (0 == (permission & PERMISSION_FOLDEROWNER)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ACCESS_DENIED;
				}
			}
		}
		if (FALSE == common_util_remote_copy_folder(pstore,
			folder_id, pstore1, folder_object_get_id(pdst_folder),
			new_name)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (FALSE == b_copy) {
			if (FALSE == exmdb_client_empty_folder(
				store_object_get_dir(pstore),
				pinfo->cpid, username, folder_id,
				FALSE, TRUE, TRUE, TRUE, &b_partial)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (TRUE == b_partial) {
				/* failure occurs, stop deleting folder */
				zarafa_server_put_user_info(pinfo);
				return EC_SUCCESS;
			}
			if (FALSE == exmdb_client_delete_folder(
				store_object_get_dir(pstore),
				pinfo->cpid, folder_id, FALSE,
				&b_done)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	if (FALSE == exmdb_client_check_folder_cycle(
		store_object_get_dir(pstore), folder_id,
		folder_object_get_id(pdst_folder), &b_cycle)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	if (TRUE == b_cycle) {
		zarafa_server_put_user_info(pinfo);
		return EC_FOLDER_CYCLE;
	}
	if (FALSE == exmdb_client_movecopy_folder(
		store_object_get_dir(pstore),
		store_object_get_account_id(pstore),
		pinfo->cpid, b_guest, pinfo->username,
		folder_object_get_id(psrc_parent), folder_id,
		folder_object_get_id(pdst_folder), new_name,
		b_copy, &b_exist, &b_partial)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (TRUE == b_exist) {
		zarafa_server_put_user_info(pinfo);
		return EC_DUPLICATE_NAME;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getstoreentryid(
	const char *mailbox_dn, BINARY *pentryid)
{
	BINARY *pbin;
	EXT_PUSH ext_push;
	char username[256];
	char tmp_buff[1024];
	STORE_ENTRYID store_entryid;
	
	if (0 == strncasecmp(mailbox_dn, "/o=", 3)) {
		if (FALSE == common_util_essdn_to_username(
			mailbox_dn, username)) {
			return EC_ERROR;
		}
	} else {
		strncpy(username, mailbox_dn, 256);
		if (FALSE == common_util_username_to_essdn(
			username, tmp_buff)) {
			return EC_ERROR;	
		}
		mailbox_dn = tmp_buff;
	}
	store_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_STORE,
					store_entryid.provider_uid);
	store_entryid.version = 0;
	store_entryid.flag = 0;
	memcpy(store_entryid.dll_name, "emsmdb.dll", 14);
	store_entryid.wrapped_flags = 0;
	rop_util_get_provider_uid(
		PROVIDER_UID_WRAPPED_PRIVATE,
		store_entryid.wrapped_provider_uid);
	store_entryid.wrapped_type = 0x0000000C;
	store_entryid.pserver_name = username;
	store_entryid.pmailbox_dn = (void*)mailbox_dn;
	pentryid->pb = common_util_alloc(1024);
	if (NULL == pentryid->pb) {
		return EC_ERROR;
	}
	ext_buffer_push_init(&ext_push,
		pentryid->pb, 1024, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_store_entryid(
		&ext_push, &store_entryid)) {
		return EC_ERROR;	
	}
	pentryid->cb = ext_push.offset;
	return EC_SUCCESS;
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
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	
	if (22 != folder_key.cb || (NULL != pmessage_key
		&& 22 != pmessage_key->cb)) {
		return EC_INVALID_PARAMETER;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == common_util_binary_to_xid(
		&folder_key, &tmp_xid)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (TRUE == store_object_check_private(pstore)) {
		tmp_guid = rop_util_make_user_guid(
			store_object_get_account_id(pstore));
		if (0 != memcmp(&tmp_guid, &tmp_xid.guid, sizeof(GUID))) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;	
		}
		folder_id = rop_util_make_eid(1, tmp_xid.local_id);
	} else {
		domain_id = rop_util_make_domain_id(tmp_xid.guid);
		if (-1 == domain_id) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		if (domain_id == store_object_get_account_id(pstore)) {
			replid = 1;
		} else {
			if (NULL != pmessage_key) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			if (FALSE == system_services_check_same_org(
				domain_id, store_object_get_account_id(pstore))) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			if (FALSE == exmdb_client_get_mapping_replid(
				store_object_get_dir(pstore),
				&tmp_xid.guid, &b_found, &replid)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == b_found) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_FOUND;
			}
		}
		folder_id = rop_util_make_eid(replid, tmp_xid.local_id);
	}
	if (NULL != pmessage_key) {
		if (FALSE == common_util_binary_to_xid(
			pmessage_key, &tmp_xid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
			if (0 != memcmp(&tmp_guid, &tmp_xid.guid, sizeof(GUID))) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;	
			}
			message_id = rop_util_make_eid(1, tmp_xid.local_id);
		} else {
			domain_id = rop_util_make_domain_id(tmp_xid.guid);
			if (-1 == domain_id) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			if (domain_id != store_object_get_account_id(pstore)) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			message_id = rop_util_make_eid(1, tmp_xid.local_id);
		}
		pbin = common_util_to_message_entryid(
				pstore, folder_id, message_id);
	} else {
		pbin = common_util_to_folder_entryid(pstore, folder_id);
	}
	zarafa_server_put_user_info(pinfo);
	if (NULL == pbin) {
		return EC_ERROR;
	}
	*pentryid = *pbin;
	return EC_SUCCESS;
}

uint32_t zarafa_server_storeadvise(GUID hsession,
	uint32_t hstore, const BINARY *pentryid,
	uint32_t event_mask, uint32_t *psub_id)
{
	char dir[256];
	uint16_t type;
	BOOL b_private;
	int account_id;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	char tmp_buff[256];
	uint64_t folder_id;
	uint64_t message_id;
	STORE_OBJECT *pstore;
	NOTIFY_ITEM tmp_item;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
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
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			break;
		case EITLT_PRIVATE_MESSAGE:
		case EITLT_PUBLIC_MESSAGE:
			if (FALSE == common_util_from_message_entryid(
				*pentryid, &b_private, &account_id,
				&folder_id, &message_id)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			break;
		default:
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		if (b_private != store_object_check_private(pstore) ||
			account_id != store_object_get_account_id(pstore)) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
	}
	if (FALSE == exmdb_client_subscribe_notification(
		store_object_get_dir(pstore), event_mask,
		TRUE, folder_id, message_id, psub_id)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	strcpy(dir, store_object_get_dir(pstore));
	zarafa_server_put_user_info(pinfo);
	double_list_init(&tmp_item.notify_list);
	tmp_item.hsession = hsession;
	tmp_item.hstore = hstore;
	time(&tmp_item.last_time);
	sprintf(tmp_buff, "%u|%s", *psub_id, dir);
	pthread_mutex_lock(&g_notify_lock);
	if (1 != str_hash_add(g_notify_table, tmp_buff, &tmp_item)) {
		pthread_mutex_unlock(&g_notify_lock);
		exmdb_client_unsubscribe_notification(dir, *psub_id);
		return EC_ERROR;
	}
	pthread_mutex_unlock(&g_notify_lock);
	return EC_SUCCESS;
}

uint32_t zarafa_server_unadvise(GUID hsession,
	uint32_t hstore, uint32_t sub_id)
{	
	char dir[256];
	USER_INFO *pinfo;
	uint8_t mapi_type;
	char tmp_buff[256];
	NOTIFY_ITEM *pnitem;
	STORE_OBJECT *pstore;
	DOUBLE_LIST_NODE *pnode;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	strcpy(dir, store_object_get_dir(pstore));
	zarafa_server_put_user_info(pinfo);
	exmdb_client_unsubscribe_notification(dir, sub_id);
	sprintf(tmp_buff, "%u|%s", sub_id, dir);
	pthread_mutex_lock(&g_notify_lock);
	pnitem = str_hash_query(g_notify_table, tmp_buff);
	if (NULL != pnitem) {
		while (pnode=double_list_get_from_head(
			&pnitem->notify_list)) {
			common_util_free_znotification(pnode->pdata);
			free(pnode);
		}
		double_list_free(&pnitem->notify_list);
	}
	str_hash_remove(g_notify_table, tmp_buff);
	pthread_mutex_unlock(&g_notify_lock);
	return EC_SUCCESS;
}

uint32_t zarafa_server_notifdequeue(const NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications)
{
	int i;
	int count;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	char tmp_buff[256];
	NOTIFY_ITEM *pnitem;
	STORE_OBJECT *pstore;
	SINK_NODE *psink_node;
	DOUBLE_LIST_NODE *pnode;
	ZNOTIFICATION* ppnotifications[1024];
	
	pinfo = zarafa_server_query_session(psink->hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	count = 0;
	for (i=0; i<psink->count; i++) {
		pstore = object_tree_get_object(pinfo->ptree,
				psink->padvise[i].hstore, &mapi_type);
		if (NULL == pstore || MAPI_STORE != mapi_type) {
			continue;
		}
		sprintf(tmp_buff, "%u|%s",
			psink->padvise[i].sub_id,
			store_object_get_dir(pstore));
		pthread_mutex_lock(&g_notify_lock);
		pnitem = str_hash_query(g_notify_table, tmp_buff);
		if (NULL == pnitem) {
			pthread_mutex_unlock(&g_notify_lock);
			continue;
		}
		time(&pnitem->last_time);
		while (pnode=double_list_get_from_head(&pnitem->notify_list)) {
			ppnotifications[count] = common_util_dup_znotification(
												pnode->pdata, TRUE);
			common_util_free_znotification(pnode->pdata);
			free(pnode);
			if (NULL != ppnotifications[count]) {
				count ++;
			}
			if (1024 == count) {
				break;
			}
		}
		pthread_mutex_unlock(&g_notify_lock);
		if (1024 == count) {
			break;
		}
	}
	if (count > 0) {
		zarafa_server_put_user_info(pinfo);
		pnotifications->count = count;
		pnotifications->ppnotification =
			common_util_alloc(sizeof(void*)*count);
		if (NULL == pnotifications->ppnotification) {
			return EC_ERROR;
		}
		memcpy(pnotifications->ppnotification,
			ppnotifications, sizeof(void*)*count);
		return EC_SUCCESS;
	}
	psink_node = malloc(sizeof(SINK_NODE));
	if (NULL == psink_node) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	psink_node->node.pdata = psink_node;
	psink_node->clifd = common_util_get_clifd();
	time(&psink_node->until_time);
	psink_node->until_time += timeval;
	psink_node->sink.hsession = psink->hsession;
	psink_node->sink.count = psink->count;
	psink_node->sink.padvise = malloc(
		sizeof(ADVISE_INFO)*psink->count);
	if (NULL == psink_node->sink.padvise) {
		zarafa_server_put_user_info(pinfo);
		free(psink_node);
		return EC_ERROR;
	}
	memcpy(psink_node->sink.padvise, psink->padvise,
				psink->count*sizeof(ADVISE_INFO));
	double_list_append_as_tail(
		&pinfo->sink_list, &psink_node->node);
	zarafa_server_put_user_info(pinfo);
	return EC_NOT_FOUND;
}

uint32_t zarafa_server_queryrows(
	GUID hsession, uint32_t htable, uint32_t start,
	uint32_t count, const RESTRICTION *prestriction,
	const PROPTAG_ARRAY *pproptags, TARRAY_SET *prowset)
{
	int i;
	uint32_t row_num;
	int32_t position;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint8_t table_type;
	TARRAY_SET tmp_set;
	TABLE_OBJECT *ptable;
	uint32_t *pobject_type;
	TAGGED_PROPVAL *ppropvals;
	static uint32_t object_type_store = OBJECT_STORE;
	static uint32_t object_type_folder = OBJECT_FOLDER;
	static uint32_t object_type_message = OBJECT_MESSAGE;
	static uint32_t object_type_attachment = OBJECT_ATTACHMENT;
	
	if (count > 0x7FFFFFFF) {
		count = 0x7FFFFFFF;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
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
			prowset->pparray = common_util_alloc(
				sizeof(TPROPVAL_ARRAY*)*row_num);
			if (NULL == prowset->pparray) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			while (TRUE) {
				if (FALSE == table_object_match_row(ptable,
					TRUE, prestriction, &position)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				if (position < 0) {
					break;
				}
				table_object_set_position(ptable, position);
				if (FALSE == table_object_query_rows(ptable,
					TRUE, pproptags, 1, &tmp_set)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;	
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
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			break;
		default:
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
	} else {
		if (FALSE == table_object_query_rows(ptable,
			TRUE, pproptags, count, prowset)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		table_object_seek_current(ptable, TRUE, prowset->count);
	}
	zarafa_server_put_user_info(pinfo);
	if ((STORE_TABLE != table_type &&
		HIERARCHY_TABLE != table_type &&
		CONTENT_TABLE != table_type &&
		ATTACHMENT_TABLE != table_type)
		|| (NULL != pproptags &&
		common_util_index_proptags(pproptags,
		PROP_TAG_OBJECTTYPE) < 0)) {
		return EC_SUCCESS;
	}
	switch (table_type) {
	case STORE_TABLE:
		pobject_type = &object_type_store;
		break;
	case HIERARCHY_TABLE:
		pobject_type = &object_type_folder;
		break;
	case CONTENT_TABLE:
		pobject_type = &object_type_message;
		break;
	case ATTACHMENT_TABLE:
		pobject_type = &object_type_attachment;
		break;
	}
	for (i=0; i<prowset->count; i++) {
		ppropvals = common_util_alloc(
			sizeof(TAGGED_PROPVAL)*
			(prowset->pparray[i]->count + 1));
		if (NULL == ppropvals) {
			return EC_ERROR;
		}
		memcpy(ppropvals, prowset->pparray[i]->ppropval,
			sizeof(TAGGED_PROPVAL)*prowset->pparray[i]->count);
		ppropvals[prowset->pparray[i]->count].proptag = PROP_TAG_OBJECTTYPE;
		ppropvals[prowset->pparray[i]->count].pvalue = pobject_type;
		prowset->pparray[i]->ppropval = ppropvals;
		prowset->pparray[i]->count ++;
	}
	return EC_SUCCESS;
}
	
uint32_t zarafa_server_setcolumns(GUID hsession, uint32_t htable,
	const PROPTAG_ARRAY *pproptags, uint32_t flags)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_set_columns(ptable, pproptags)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_seekrow(GUID hsession,
	uint32_t htable, uint32_t bookmark, int32_t seek_rows,
	int32_t *psought_rows)
{
	BOOL b_exist;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	int32_t original_position;
	int32_t original_position1;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	switch (bookmark) {
	case SEEK_POS_BEGIN:
		if (seek_rows < 0) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		original_position = 0;
		table_object_set_position(ptable, seek_rows);
		break;
	case SEEK_POS_END:
		if (seek_rows > 0) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		original_position = table_object_get_total(ptable);
		if (table_object_get_total(ptable) + seek_rows < 0) {
			table_object_set_position(ptable, 0);
		} else {
			table_object_set_position(ptable,
				table_object_get_total(ptable) + seek_rows);
		}
		break;
	case SEEK_POS_CURRENT:
		original_position = table_object_get_position(ptable);
		if (original_position + seek_rows < 0) {
			table_object_set_position(ptable, 0);
		} else {
			table_object_set_position(ptable,
				original_position + seek_rows);
		}
		break;
	default:
		original_position = table_object_get_position(ptable);
		if (FALSE == table_object_retrieve_bookmark(
			ptable, bookmark, &b_exist)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == b_exist) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		original_position1 = table_object_get_position(ptable);
		if (original_position1 + seek_rows < 0) {
			table_object_set_position(ptable, 0);
		} else {
			table_object_set_position(ptable,
				original_position1 + seek_rows);
		}
		break;
	}
	*psought_rows = table_object_get_position(
					ptable) - original_position;
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_sorttable(GUID hsession,
	uint32_t htable, const SORTORDER_SET *psortset)
{
	int i, j;
	BOOL b_max;
	uint16_t type;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	BOOL b_multi_inst;
	uint32_t tmp_proptag;
	TABLE_OBJECT *ptable;
	const PROPTAG_ARRAY *pcolumns;
	
	if (psortset->count > MAXIMUM_SORT_COUNT) {
		return EC_TOO_COMPLEX;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (CONTENT_TABLE != table_object_get_table_type(ptable)) {
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	b_max = FALSE;
	b_multi_inst = FALSE;
	for (i=0; i<psortset->ccategories; i++) {
		for (j=i+1; j<psortset->count; j++) {
			if (psortset->psort[i].propid ==
				psortset->psort[j].propid &&
				psortset->psort[i].type ==
				psortset->psort[j].type) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;	
			}
		}
	}
	for (i=0; i<psortset->count; i++) {
		tmp_proptag = psortset->psort[i].propid;
		tmp_proptag <<= 16;
		tmp_proptag |= psortset->psort[i].type;
		if (PROP_TAG_DEPTH == tmp_proptag ||
			PROP_TAG_INSTID == tmp_proptag ||
			PROP_TAG_INSTANCENUM == tmp_proptag ||
			PROP_TAG_CONTENTCOUNT == tmp_proptag ||
			PROP_TAG_CONTENTUNREADCOUNT == tmp_proptag) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;	
		}	
		switch (psortset->psort[i].table_sort) {
		case TABLE_SORT_ASCEND:
		case TABLE_SORT_DESCEND:
			break;
		case TABLE_SORT_MAXIMUM_CATEGORY:
		case TABLE_SORT_MINIMUM_CATEGORY:
			if (0 == psortset->ccategories ||
				psortset->ccategories != i) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			break;
		default:
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		type = psortset->psort[i].type;
		if (type & 0x1000) {
			/* do not support multivalue property
				without multivalue instances */
			if (0 == (type & 0x2000)) {
				zarafa_server_put_user_info(pinfo);
				return EC_NOT_SUPPORTED;
			}
			type &= ~0x2000;
			/* MUST NOT contain more than one multivalue property! */
			if (TRUE == b_multi_inst) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			b_multi_inst = TRUE;
		}
		switch (type) {
		case PROPVAL_TYPE_SHORT:
		case PROPVAL_TYPE_LONG:
		case PROPVAL_TYPE_FLOAT:
		case PROPVAL_TYPE_DOUBLE:
		case PROPVAL_TYPE_CURRENCY:
		case PROPVAL_TYPE_FLOATINGTIME:
		case PROPVAL_TYPE_BYTE:
		case PROPVAL_TYPE_OBJECT:
		case PROPVAL_TYPE_LONGLONG:
		case PROPVAL_TYPE_STRING:
		case PROPVAL_TYPE_WSTRING:
		case PROPVAL_TYPE_FILETIME:
		case PROPVAL_TYPE_GUID:
		case PROPVAL_TYPE_SVREID:
		case PROPVAL_TYPE_RESTRICTION:
		case PROPVAL_TYPE_RULE:
		case PROPVAL_TYPE_BINARY:
		case PROPVAL_TYPE_SHORT_ARRAY:
		case PROPVAL_TYPE_LONG_ARRAY:
		case PROPVAL_TYPE_LONGLONG_ARRAY:
		case PROPVAL_TYPE_STRING_ARRAY:
		case PROPVAL_TYPE_WSTRING_ARRAY:
		case PROPVAL_TYPE_GUID_ARRAY:
		case PROPVAL_TYPE_BINARY_ARRAY:
			break;
		case PROPVAL_TYPE_UNSPECIFIED:
		case PROPVAL_TYPE_ERROR:
		default:
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psortset->psort[i].table_sort ||
			TABLE_SORT_MINIMUM_CATEGORY ==
			psortset->psort[i].table_sort) {
			if (TRUE == b_max || i != psortset->ccategories) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			b_max = TRUE;
		}
	}
	pcolumns = table_object_get_columns(ptable);
	if (TRUE == b_multi_inst && NULL != pcolumns) {
		if (FALSE == common_util_verify_columns_and_sorts(
			pcolumns, psortset)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;	
		}
	}
	if (FALSE == table_object_set_sorts(ptable, psortset)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	table_object_unload(ptable);
	table_object_clear_bookmarks(ptable);
	table_object_clear_position(ptable);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getrowcount(GUID hsession,
	uint32_t htable, uint32_t *pcount)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*pcount = table_object_get_total(ptable);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_restricttable(GUID hsession, uint32_t htable,
	const RESTRICTION *prestriction, uint32_t flags)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
	case RULE_TABLE:
	case USER_TABLE:
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_set_restriction(ptable, prestriction)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	table_object_unload(ptable);
	table_object_clear_bookmarks(ptable);
	table_object_clear_position(ptable);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_findrow(GUID hsession, uint32_t htable,
	uint32_t bookmark, const RESTRICTION *prestriction,
	uint32_t flags, uint32_t *prow_idx)
{
	BOOL b_exist;
	USER_INFO *pinfo;
	int32_t position;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
	case RULE_TABLE:
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	switch (bookmark) {
	case SEEK_POS_BEGIN:
		table_object_set_position(ptable, 0);
		break;
	case SEEK_POS_END:
		table_object_set_position(ptable,
			table_object_get_total(ptable));
		break;
	case SEEK_POS_CURRENT:
		break;
	default:
		if (RULE_TABLE == table_object_get_table_type(ptable)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
		if (FALSE == table_object_retrieve_bookmark(
			ptable, bookmark, &b_exist)) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_BOOKMARK;
		}
		break;
	}
	if (FALSE == table_object_match_row(ptable,
		TRUE, prestriction, &position)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	if (position < 0) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	table_object_set_position(ptable, position);
	zarafa_server_put_user_info(pinfo);
	*prow_idx = position;
	return EC_SUCCESS;
}

uint32_t zarafa_server_createbookmark(GUID hsession,
	uint32_t htable, uint32_t *pbookmark)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == table_object_create_bookmark(
		ptable, pbookmark)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_freebookmark(GUID hsession,
	uint32_t htable, uint32_t bookmark)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	ptable = object_tree_get_object(
		pinfo->ptree, htable, &mapi_type);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_TABLE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	switch (table_object_get_table_type(ptable)) {
	case HIERARCHY_TABLE:
	case CONTENT_TABLE:
		break;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	table_object_remove_bookmark(ptable, bookmark);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid)
{
	BINARY *pbin;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	char temp_class[256];
	STORE_OBJECT *pstore;
	
	if (NULL == pstrclass) {
		pstrclass = "";
	}
	if (FALSE == common_util_check_message_class(pstrclass)) {
		return EC_INVALID_PARAMETER;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == store_object_check_private(pstore)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == exmdb_client_get_folder_by_class(
		store_object_get_dir(pstore), pstrclass,
		&folder_id, temp_class)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	pbin = common_util_to_folder_entryid(pstore, folder_id);
	if (NULL == pbin) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	*pentryid = *pbin;
	return EC_SUCCESS;
}

uint32_t zarafa_server_modifyrecipients(GUID hsession,
	uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list)
{
	int i, j;
	BOOL b_found;
	BINARY *pbin;
	USER_INFO *pinfo;
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
		return EC_INVALID_PARAMETER;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (MODRECIP_MODIFY == flags) {
		message_object_empty_rcpts(pmessage);
	} else if (MODRECIP_REMOVE == flags) {
		for (i=0; i<prcpt_list->count; i++) {
			prcpt = prcpt_list->pparray[i];
			b_found = FALSE;
			for (j=0; j<prcpt->count; j++) {
				if (PROP_TAG_ROWID == prcpt->ppropval[j].proptag) {
					prcpt->count = 1;
					prcpt->ppropval = prcpt->ppropval + j;
					b_found = TRUE;
					break;
				}
			}
			if (FALSE == b_found) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
		}
		if (FALSE == message_object_set_rcpts(pmessage, prcpt_list)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	if (FALSE == message_object_get_rowid_begin(pmessage, &last_rowid)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	for (i=0; i<prcpt_list->count; i++,last_rowid++) {
		if (NULL == common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_ENTRYID) &&
			NULL == common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_EMAILADDRESS) &&
			NULL == common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_SMTPADDRESS)) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;	
		}
		prowid = common_util_get_propvals(
			prcpt_list->pparray[i], PROP_TAG_ROWID);
		if (NULL != prowid) {
			if (*prowid < last_rowid) {
				*prowid = last_rowid;
			} else {
				last_rowid = *prowid;
			}
		} else {
			prcpt = prcpt_list->pparray[i];
			ppropval = common_util_alloc(
				sizeof(TAGGED_PROPVAL)*(prcpt->count + 1));
			if (NULL == ppropval) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			memcpy(ppropval, prcpt->ppropval,
				sizeof(TAGGED_PROPVAL)*prcpt->count);
			ppropval[prcpt->count].proptag = PROP_TAG_ROWID;
			ppropval[prcpt->count].pvalue =
				common_util_alloc(sizeof(uint32_t));
			if (NULL == ppropval[prcpt->count].pvalue) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			*(uint32_t*)ppropval[prcpt->count].pvalue = last_rowid;
			prcpt->ppropval = ppropval;
			prcpt->count ++;
			pbin = common_util_get_propvals(
					prcpt, PROP_TAG_ENTRYID);
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
				ppropval = common_util_alloc((prcpt->count + 4)
									*sizeof(TAGGED_PROPVAL));
				if (NULL == ppropval) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				memcpy(ppropval, prcpt->ppropval,
					prcpt->count*sizeof(TAGGED_PROPVAL));
				prcpt->ppropval = ppropval;
				tmp_propval.proptag = PROP_TAG_ADDRESSTYPE;
				tmp_propval.pvalue = "EX";
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_EMAILADDRESS;
				tmp_propval.pvalue = common_util_dup(ab_entryid.px500dn);
				if (NULL == tmp_propval.pvalue) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_SMTPADDRESS;
				if (FALSE == common_util_essdn_to_username(
					ab_entryid.px500dn, tmp_buff)) {
					continue;
				}
				tmp_propval.pvalue = common_util_dup(tmp_buff);
				if (NULL == tmp_propval.pvalue) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				if (FALSE == system_services_get_user_displayname(
					tmp_buff, tmp_buff)) {
					continue;	
				}
				tmp_propval.proptag = PROP_TAG_DISPLAYNAME;
				tmp_propval.pvalue = common_util_dup(tmp_buff);
				if (NULL == tmp_propval.pvalue) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
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
				ppropval = common_util_alloc((prcpt->count + 5)
									*sizeof(TAGGED_PROPVAL));
				if (NULL == ppropval) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				memcpy(ppropval, prcpt->ppropval,
					prcpt->count*sizeof(TAGGED_PROPVAL));
				prcpt->ppropval = ppropval;
				tmp_propval.proptag = PROP_TAG_ADDRESSTYPE;
				tmp_propval.pvalue = "SMTP";
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_EMAILADDRESS;
				tmp_propval.pvalue = common_util_dup(
						oneoff_entry.pmail_address);
				if (NULL == tmp_propval.pvalue) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_SMTPADDRESS;
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_DISPLAYNAME;
				tmp_propval.pvalue = common_util_dup(
						oneoff_entry.pdisplay_name);
				if (NULL == tmp_propval.pvalue) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
				tmp_propval.proptag = PROP_TAG_SENDRICHINFO;
				if (CTRL_FLAG_NORICH & oneoff_entry.ctrl_flags) {
					tmp_propval.pvalue = &fake_false;
				} else {
					tmp_propval.pvalue = &fake_true;
				}
				common_util_set_propvals(prcpt, &tmp_propval);
			}
		}
	}
	if (FALSE == message_object_set_rcpts(pmessage, prcpt_list)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_submitmessage(GUID hsession, uint32_t hmessage)
{
	int timer_id;
	void *pvalue;
	BOOL b_marked;
	BOOL b_unsent;
	BOOL b_delete;
	time_t cur_time;
	uint32_t tmp_num;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint16_t rcpt_num;
	char username[256];
	int32_t max_length;
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
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = message_object_get_store(pmessage);
	if (FALSE == store_object_check_private(pstore)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_mailbox_permission(
			store_object_get_dir(pstore), pinfo->username,
			&permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_SENDAS)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (0 == message_object_get_id(pmessage)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (TRUE == message_object_check_importing(pmessage) ||
		FALSE == message_object_check_writable(pmessage)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	if (FALSE == message_object_get_recipient_num(
		pmessage, &rcpt_num)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	if (rcpt_num > common_util_get_param(COMMON_UTIL_MAX_RCPT)) {
		zarafa_server_put_user_info(pinfo);
		return EC_TOO_MANY_RECIPIENTS;
	}
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_ASSOCIATED;
	if (FALSE == message_object_get_properties(
		pmessage, &tmp_proptags, &tmp_propvals)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_ASSOCIATED);
	/* FAI message cannot be sent */
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	if (FALSE == common_util_check_delegate(pmessage, username)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	account = store_object_get_account(pstore);
	if ('\0' == username[0]) {
		strcpy(username, account);
	} else {
		if (FALSE == common_util_check_delegate_permission_ex(
			account, username)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == common_util_rectify_message(pmessage, username)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_MAXIMUMSUBMITMESSAGESIZE;
	if (FALSE == store_object_get_properties(
		pstore, &tmp_proptags, &tmp_propvals)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
				PROP_TAG_MAXIMUMSUBMITMESSAGESIZE);
	max_length = -1;
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
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_MESSAGESIZE);
	if (NULL == pvalue) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	mail_length = *(uint32_t*)pvalue;
	if (max_length > 0 && mail_length > max_length) {
		zarafa_server_put_user_info(pinfo);
		return EC_EXCEEDED_SIZE;
	}
	pvalue = common_util_get_propvals(
		&tmp_propvals, PROP_TAG_MESSAGEFLAGS);
	if (NULL == pvalue) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	message_flags = *(uint32_t*)pvalue;
	/* here we handle the submit request
		differently from exchange_emsmdb.
		we always allow a submitted message
		to be resubmitted */
	if (message_flags & MESSAGE_FLAG_UNSENT) {
		b_unsent = TRUE;
	} else {
		b_unsent = FALSE;
	}
	pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_DELETEAFTERSUBMIT);
	b_delete = FALSE;
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_delete = TRUE;
	}
	if (0 == (MESSAGE_FLAG_SUBMITTED & message_flags)) {
		if (FALSE == exmdb_client_try_mark_submit(
			store_object_get_dir(pstore),
			message_object_get_id(pmessage),
			&b_marked)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (FALSE == b_marked) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
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
				rop_util_get_gc_value(
					message_object_get_id(pmessage)));
			timer_id = system_services_add_timer(
					command_buff, deferred_time);
			if (0 == timer_id) {
				exmdb_client_clear_submit(
				store_object_get_dir(pstore),
					message_object_get_id(pmessage),
					b_unsent);
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			exmdb_client_set_message_timer(
				store_object_get_dir(pstore),
				message_object_get_id(pmessage), timer_id);
			message_object_reload(pmessage);
			zarafa_server_put_user_info(pinfo);
			return EC_SUCCESS;
		}
	}
	if (FALSE == common_util_send_message(pstore,
		message_object_get_id(pmessage), TRUE)) {
		exmdb_client_clear_submit(
			store_object_get_dir(pstore),
			message_object_get_id(pmessage),
			b_unsent);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == b_delete) {
		message_object_reload(pmessage);
	} else {
		message_object_clear_unsent(pmessage);
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_loadattachmenttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	TABLE_OBJECT *ptable;
	STORE_OBJECT *pstore;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = message_object_get_store(pmessage);
	ptable = table_object_create(pstore,
		pmessage, ATTACHMENT_TABLE, 0);
	if (NULL == ptable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
			pinfo->ptree, hmessage, MAPI_TABLE,
			ptable);
	if (INVALID_HANDLE == *phobject) {
		table_object_free(ptable);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_openattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id, uint32_t *phobject)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	MESSAGE_OBJECT *pmessage;
	ATTACHMENT_OBJECT *pattachment;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = message_object_get_store(pmessage);
	pattachment = attachment_object_create(pmessage, attach_id);
	if (NULL == pattachment) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (0 == attachment_object_get_instance_id(pattachment)) {
		attachment_object_free(pattachment);
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hmessage, MAPI_ATTACHMENT,
		pattachment);
	if (INVALID_HANDLE == *phobject) {
		attachment_object_free(pattachment);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_createattachment(GUID hsession,
	uint32_t hmessage, uint32_t *phobject)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	MESSAGE_OBJECT *pmessage;
	ATTACHMENT_OBJECT *pattachment;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = message_object_get_store(pmessage);
	if (FALSE == message_object_check_writable(pmessage)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	pattachment = attachment_object_create(
		pmessage, ATTACHMENT_NUM_INVALID);
	if (NULL == pattachment) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (attachment_object_get_attachment_num(
		pattachment) == ATTACHMENT_NUM_INVALID) {
		attachment_object_free(pattachment);
		zarafa_server_put_user_info(pinfo);
		return EC_ATTACHMENT_EXCEEDED;
	}
	if (FALSE == attachment_object_init_attachment(pattachment)) {
		attachment_object_free(pattachment);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hmessage, MAPI_ATTACHMENT,
		pattachment);
	if (INVALID_HANDLE == *phobject) {
		attachment_object_free(pattachment);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_deleteattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	ATTACHMENT_OBJECT *pattachment;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == message_object_check_writable(pmessage)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	if (FALSE == message_object_delele_attachment(
		pmessage, attach_id)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_setpropvals(GUID hsession,
	uint32_t hobject, const TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pobject;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	switch (mapi_type) {
	case MAPI_PROFPROPERTY:
		for (i=0; i<ppropvals->count; i++) {
			if (FALSE == tpropval_array_set_propval(
				pobject, &ppropvals->ppropval[i])) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
		}
		object_tree_touch_profile_sec(pinfo->ptree);
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_STORE:
		if (FALSE == store_object_check_owner_mode(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == store_object_set_properties(
			pobject, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_FOLDER:
		pstore = folder_object_get_store(pobject);
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore),
				folder_object_get_id(pobject),
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		}
		if (FALSE == folder_object_set_properties(
			pobject, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_MESSAGE:
		if (FALSE == message_object_check_writable(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == message_object_set_properties(
			pobject, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_ATTACHMENT:
		if (FALSE == attachment_object_check_writable(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == attachment_object_set_properties(
			pobject, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;	
	}
}

uint32_t zarafa_server_getpropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pobject;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	PROPTAG_ARRAY proptags;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	switch (mapi_type) {
	case MAPI_PROFPROPERTY:
		if (NULL == pproptags) {
			*ppropvals = *(TPROPVAL_ARRAY*)pobject;
		} else {
			ppropvals->count = 0;
			ppropvals->ppropval = common_util_alloc(
				sizeof(TAGGED_PROPVAL)*pproptags->count);
			if (NULL == ppropvals->ppropval) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			for (i=0; i<pproptags->count; i++) {
				ppropvals->ppropval[ppropvals->count].proptag =
										pproptags->pproptag[i];
				ppropvals->ppropval[ppropvals->count].pvalue =
							tpropval_array_get_propval(pobject,
							pproptags->pproptag[i]);
				if (NULL != ppropvals->ppropval[
					ppropvals->count].pvalue) {
					ppropvals->count ++;	
				}
			}
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_STORE:
		if (NULL == pproptags) {
			if (FALSE == store_object_get_all_proptags(
				pobject, &proptags)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			pproptags = &proptags;
		}
		if (FALSE == store_object_get_properties(
			pobject, pproptags, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_FOLDER:
		if (NULL == pproptags) {
			if (FALSE == folder_object_get_all_proptags(
				pobject, &proptags)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			pproptags = &proptags;
		}
		if (FALSE == folder_object_get_properties(
			pobject, pproptags, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_MESSAGE:
		if (NULL == pproptags) {
			if (FALSE == message_object_get_all_proptags(
				pobject, &proptags)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			pproptags = &proptags;
		}
		if (FALSE == message_object_get_properties(
			pobject, pproptags, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_ATTACHMENT:
		if (NULL == pproptags) {
			if (FALSE == attachment_object_get_all_proptags(
				pobject, &proptags)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			pproptags = &proptags;
		}
		if (FALSE == attachment_object_get_properties(
			pobject, pproptags, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_ABCONT:
		if (NULL == pproptags) {
			container_object_get_container_table_all_proptags(
				&proptags);
			pproptags = &proptags;
		}
		if (FALSE == container_object_get_properties(
			pobject, pproptags, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_MAILUSER:
	case MAPI_DISTLIST:
		if (NULL == pproptags) {
			container_object_get_user_table_all_proptags(&proptags);
			pproptags = &proptags;
		}
		if (FALSE == user_object_get_properties(
			pobject, pproptags, ppropvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;	
	}
}

uint32_t zarafa_server_deletepropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags)
{
	int i;
	void *pobject;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint32_t permission;
	STORE_OBJECT *pstore;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	switch (mapi_type) {
	case MAPI_PROFPROPERTY:
		for (i=0; i<pproptags->count; i++) {
			tpropval_array_remove_propval(
				pobject, pproptags->pproptag[i]);
		}
		object_tree_touch_profile_sec(pinfo->ptree);
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_STORE:
		if (FALSE == store_object_check_owner_mode(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == store_object_remove_properties(
			pobject, pproptags)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_FOLDER:
		pstore = folder_object_get_store(pobject);
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore),
				folder_object_get_id(pobject),
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		}
		if (FALSE == folder_object_remove_properties(
			pobject, pproptags)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_MESSAGE:
		if (FALSE == message_object_check_writable(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == message_object_remove_properties(
			pobject, pproptags)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	case MAPI_ATTACHMENT:
		if (FALSE == attachment_object_check_writable(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == attachment_object_remove_properties(
			pobject, pproptags)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;	
	}
}

uint32_t zarafa_server_setmessagereadflag(
	GUID hsession, uint32_t hmessage, uint32_t flags)
{
	BOOL b_changed;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == message_object_set_readflag(
		pmessage, flags, &b_changed)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_openembedded(GUID hsession,
	uint32_t hattachment, uint32_t flags, uint32_t *phobject)
{
	uint32_t hstore;
	BOOL b_writable;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint32_t tag_access;
	STORE_OBJECT *pstore;
	MESSAGE_OBJECT *pmessage;
	ATTACHMENT_OBJECT *pattachment;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pattachment = object_tree_get_object(
		pinfo->ptree, hattachment, &mapi_type);
	if (NULL == pattachment) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ATTACHMENT != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = attachment_object_get_store(pattachment);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	b_writable = attachment_object_check_writable(pattachment);
	tag_access = attachment_object_get_tag_access(pattachment);
	if ((FLAG_CREATE & flags) && FALSE == b_writable) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	pmessage = message_object_create(pstore,
		FALSE, pinfo->cpid, 0, pattachment,
		tag_access, b_writable, NULL);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (0 == message_object_get_instance_id(pmessage)) {
		if (0 == (FLAG_CREATE & flags)) {
			message_object_free(pmessage);
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
		message_object_free(pmessage);
		if (FALSE == b_writable) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;	
		}
		pmessage = message_object_create(pstore, TRUE,
			pinfo->cpid, 0, pattachment, tag_access,
			TRUE, NULL);
		if (NULL == pmessage) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == message_object_init_message(
			pmessage, FALSE, pinfo->cpid)) {
			message_object_free(pmessage);
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
	}
	/* add the store handle as the parent object handle
		because the caller normaly will not keep the
		handle of attachment */
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_MESSAGE,
		pmessage);
	if (INVALID_HANDLE == *phobject) {
		message_object_free(pmessage);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == store_object_get_named_propids(
		pstore, TRUE, ppropnames, ppropids)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getpropnames(GUID hsession, uint32_t hstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pstore = object_tree_get_object(
		pinfo->ptree, hstore, &mapi_type);
	if (NULL == pstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == store_object_get_named_propnames(
		pstore, ppropids, ppropnames)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_copyto(GUID hsession, uint32_t hsrcobject,
	const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject,
	uint32_t flags)
{
	int i;
	BOOL b_fai;
	BOOL b_sub;
	BOOL b_guest;
	BOOL b_force;
	BOOL b_cycle;
	BOOL b_normal;
	BOOL b_collid;
	void *pobject;
	BOOL b_partial;
	uint8_t dst_type;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	void *pobject_dst;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY tmp_proptags;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hsrcobject, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	pobject_dst = object_tree_get_object(
		pinfo->ptree, hdstobject, &dst_type);
	if (NULL == pobject_dst) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (mapi_type != dst_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (flags & COPY_FLAG_NOOVERWRITE) {
		b_force = FALSE;
	} else {
		b_force = TRUE;
	}
	switch (mapi_type) {
	case MAPI_FOLDER:
		pstore = folder_object_get_store(pobject);
		if (pstore != folder_object_get_store(pobject_dst)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
		/* MS-OXCPRPT 3.2.5.8, public folder not supported */
		if (FALSE == store_object_check_private(pstore)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore),
				folder_object_get_id(pobject),
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (permission & PERMISSION_FOLDEROWNER) {
				username = NULL;
			} else {
				if (0 == (permission & PERMISSION_READANY)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ACCESS_DENIED;
				}
				username = pinfo->username;
			}
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore),
				folder_object_get_id(pobject_dst),
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		} else {
			username = NULL;
		}
		if (common_util_index_proptags(pexclude_proptags,
			PROP_TAG_CONTAINERHIERARCHY) < 0) {
			if (FALSE == exmdb_client_check_folder_cycle(
				store_object_get_dir(pstore),
				folder_object_get_id(pobject),
				folder_object_get_id(pobject_dst), &b_cycle)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (TRUE == b_cycle) {
				zarafa_server_put_user_info(pinfo);
				return EC_FOLDER_CYCLE;
			}
			b_sub = TRUE;
		} else {
			b_sub = FALSE;
		}
		if (common_util_index_proptags(pexclude_proptags,
			PROP_TAG_CONTAINERCONTENTS) < 0) {
			b_normal = TRUE;
		} else {
			b_normal = FALSE;
		}
		if (common_util_index_proptags(pexclude_proptags,
			PROP_TAG_FOLDERASSOCIATEDCONTENTS) < 0) {
			b_fai = TRUE;	
		} else {
			b_fai = FALSE;
		}
		if (FALSE == folder_object_get_all_proptags(
			pobject, &proptags)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		common_util_reduce_proptags(&proptags, pexclude_proptags);
		tmp_proptags.count = 0;
		tmp_proptags.pproptag = common_util_alloc(
					sizeof(uint32_t)*proptags.count);
		if (NULL == tmp_proptags.pproptag) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == b_force) {
			if (FALSE == folder_object_get_all_proptags(
				pobject_dst, &proptags1)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
		}
		for (i=0; i<proptags.count; i++) {
			if (TRUE == folder_object_check_readonly_property(
				pobject_dst, proptags.pproptag[i])) {
				continue;
			}
			if (FALSE == b_force && common_util_index_proptags(
				&proptags1, proptags.pproptag[i]) >= 0) {
				continue;
			}
			tmp_proptags.pproptag[tmp_proptags.count] = 
									proptags.pproptag[i];
			tmp_proptags.count ++;
		}
		if (FALSE == folder_object_get_properties(
			pobject, &tmp_proptags, &propvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (TRUE == b_sub || TRUE == b_normal || TRUE == b_fai) {
			if (NULL == username) {
				b_guest = FALSE;
			} else {
				b_guest = TRUE;
			}
			if (FALSE == exmdb_client_copy_folder_internal(
				store_object_get_dir(pstore),
				store_object_get_account_id(pstore),
				pinfo->cpid, b_guest, pinfo->username,
				folder_object_get_id(pobject), b_normal, b_fai,
				b_sub, folder_object_get_id(pobject_dst),
				&b_collid, &b_partial)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (TRUE == b_collid) {
				zarafa_server_put_user_info(pinfo);
				return EC_COLLIDING_NAMES;
			}
			if (FALSE == folder_object_set_properties(
				pobject_dst, &propvals)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			zarafa_server_put_user_info(pinfo);
			return EC_SUCCESS;
		}
		if (FALSE == folder_object_set_properties(
			pobject_dst, &propvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		zarafa_server_put_user_info(pinfo);	
		return EC_SUCCESS;
	case MAPI_MESSAGE:
		if (FALSE == message_object_check_writable(pobject_dst)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == message_object_copy_to(pobject_dst,
			pobject, pexclude_proptags, b_force, &b_cycle)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (TRUE == b_cycle) {
			zarafa_server_put_user_info(pinfo);
			return EC_MESSAGE_CYCLE;
		}
		zarafa_server_put_user_info(pinfo);	
		return EC_SUCCESS;
	case MAPI_ATTACHMENT:
		if (FALSE == attachment_object_check_writable(pobject_dst)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == attachment_object_copy_properties(pobject_dst,
			pobject, pexclude_proptags, b_force, &b_cycle)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (TRUE == b_cycle) {
			zarafa_server_put_user_info(pinfo);
			return EC_MESSAGE_CYCLE;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	default:
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;	
	}
}

uint32_t zarafa_server_savechanges(GUID hsession, uint32_t hobject)
{
	void *pobject;
	BOOL b_touched;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint32_t tmp_proptag;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pobject = object_tree_get_object(
		pinfo->ptree, hobject, &mapi_type);
	if (NULL == pobject) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE == mapi_type) {
		if (FALSE == message_object_check_writable(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == message_object_check_orignal_touched(
			pobject, &b_touched)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (TRUE == b_touched) {
			zarafa_server_put_user_info(pinfo);
			return EC_OBJECT_MODIFIED;
		}
		if (FALSE == message_object_save(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	} else if (MAPI_ATTACHMENT == mapi_type) {
		if (FALSE == attachment_object_check_writable(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == attachment_object_save(pobject)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	} else {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
}

uint32_t zarafa_server_hierarchysync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	pctx = icsdownctx_object_create(pfolder, SYNC_TYPE_HIERARCHY);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_ICSDOWNCTX,
		pctx);
	if (INVALID_HANDLE == *phobject) {
		icsdownctx_object_free(pctx);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_contentsync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	pctx = icsdownctx_object_create(pfolder, SYNC_TYPE_CONTENTS);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_ICSDOWNCTX,
		pctx);
	if (INVALID_HANDLE == *phobject) {
		icsdownctx_object_free(pctx);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_configsync(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY *pstate,
	const RESTRICTION *prestriction, BOOL *pb_changed,
	uint32_t *pcount)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSDOWNCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (SYNC_TYPE_CONTENTS == icsdownctx_object_get_type(pctx)) {
		if (FALSE == icsdownctx_object_make_content(pctx,
			pstate, prestriction, flags, pb_changed, pcount)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
	} else {
		if (FALSE == icsdownctx_object_make_hierarchy(
			pctx, pstate, flags, pb_changed, pcount)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_statesync(GUID hsession,
	uint32_t hctx, BINARY *pstate)
{
	BINARY *pbin;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSDOWNCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pbin = icsdownctx_object_get_state(pctx);
	if (NULL == pbin) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	*pstate = *pbin;
	return EC_SUCCESS;
}

uint32_t zarafa_server_syncmessagechange(GUID hsession,
	uint32_t hctx, BOOL *pb_new, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_found;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSDOWNCTX != mapi_type ||
		SYNC_TYPE_CONTENTS != icsdownctx_object_get_type(pctx)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == icsdownctx_object_sync_message_change(
		pctx, &b_found, pb_new, pproplist)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == b_found) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_syncfolderchange(GUID hsession,
	uint32_t hctx, TPROPVAL_ARRAY *pproplist)
{
	BOOL b_found;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSDOWNCTX != mapi_type ||
		SYNC_TYPE_HIERARCHY != icsdownctx_object_get_type(pctx)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == icsdownctx_object_sync_folder_change(
		pctx, &b_found, pproplist)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == b_found) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_FOUND;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_syncreadstatechanges(
	GUID hsession, uint32_t hctx, STATE_ARRAY *pstates)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSDOWNCTX != mapi_type ||
		SYNC_TYPE_CONTENTS != icsdownctx_object_get_type(pctx)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == icsdownctx_object_sync_readstates(
		pctx, pstates)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_syncdeletions(GUID hsession,
	uint32_t hctx, uint32_t flags, BINARY_ARRAY *pbins)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSDOWNCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSDOWNCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == icsdownctx_object_sync_deletions(
		pctx, flags, pbins)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_hierarchyimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type || FOLDER_TYPE_SEARCH
		== folder_object_get_type(pfolder)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	pctx = icsupctx_object_create(pfolder, SYNC_TYPE_HIERARCHY);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_ICSUPCTX, pctx);
	if (INVALID_HANDLE == *phobject) {
		icsupctx_object_free(pctx);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_contentimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject)
{
	uint32_t hstore;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	hstore = object_tree_get_store_handle(pinfo->ptree,
					store_object_check_private(pstore),
					store_object_get_account_id(pstore));
	if (INVALID_HANDLE == hstore) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	pctx = icsupctx_object_create(pfolder, SYNC_TYPE_CONTENTS);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hstore, MAPI_ICSUPCTX, pctx);
	if (INVALID_HANDLE == *phobject) {
		icsupctx_object_free(pctx);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_configimport(GUID hsession,
	uint32_t hctx, uint8_t sync_type, const BINARY *pstate)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSUPCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == icsupctx_object_upload_state(
		pctx, pstate)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_stateimport(GUID hsession,
	uint32_t hctx, BINARY *pstate)
{
	BINARY *pbin;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	ICSUPCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pbin = icsupctx_object_get_state(pctx);
	if (NULL == pbin) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	*pstate = *pbin;
	return EC_SUCCESS;
}

uint32_t zarafa_server_importmessage(GUID hsession, uint32_t hctx,
	uint32_t flags, const TPROPVAL_ARRAY *pproplist, uint32_t *phobject)
{
	BOOL b_new;
	BOOL b_fai;
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_owner;
	BINARY *pbin;
	void *pvalue;
	GUID tmp_guid;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint32_t tag_access;
	uint64_t message_id;
	uint32_t permission;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	MESSAGE_OBJECT *pmessage;
	
	pvalue = common_util_get_propvals(pproplist, PROP_TAG_ASSOCIATED);
	if (NULL != pvalue) {
		if (0 == *(uint8_t*)pvalue) {
			b_fai = FALSE;
		} else {
			b_fai = TRUE;
		}
	} else {
		pvalue = common_util_get_propvals(
			pproplist, PROP_TAG_MESSAGEFLAGS);
		if (NULL != pvalue) {
			if ((*(uint32_t*)pvalue) & MESSAGE_FLAG_FAI) {
				b_fai = TRUE;
			} else {
				b_fai = FALSE;
			}
		} else {
			b_fai = FALSE;
		}
	}
	if (flags & SYNC_NEW_MESSAGE) {
		b_new = TRUE;
	} else {
		b_new = FALSE;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = icsupctx_object_get_store(pctx);
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_type(pctx)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	folder_id = icsupctx_object_get_parent_folder_id(pctx);
	if (FALSE == b_new) {
		pbin = common_util_get_propvals(pproplist, PROP_TAG_SOURCEKEY);
		if (22 != pbin->cb) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
		} else {
			tmp_guid = rop_util_make_domain_guid(
				store_object_get_account_id(pstore));
		}
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		message_id = rop_util_make_eid(1, tmp_xid.local_id);
		if (FALSE == exmdb_client_check_message(
			store_object_get_dir(pstore), folder_id,
			message_id, &b_exist)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (FALSE == b_exist) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_FOUND;
		}
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (TRUE == b_new) {
			if (0 == (permission & PERMISSION_CREATE)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
			tag_access = TAG_ACCESS_READ;
			if ((permission & PERMISSION_EDITANY) ||
				(permission & PERMISSION_EDITOWNED)) {
				tag_access |= TAG_ACCESS_MODIFY;	
			}
			if ((permission & PERMISSION_DELETEANY) ||
				(permission & PERMISSION_DELETEOWNED)) {
				tag_access |= TAG_ACCESS_DELETE;	
			}
		} else {
			if (permission & PERMISSION_FOLDEROWNER) {
				tag_access = TAG_ACCESS_MODIFY|
					TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			} else {
				if (FALSE == exmdb_client_check_message_owner(
					store_object_get_dir(pstore), message_id,
					pinfo->username, &b_owner)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;	
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
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (TRUE == b_fai) {
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
		} else {
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
		}
	} else {
		if (FALSE == exmdb_client_allocate_message_id(
			store_object_get_dir(pstore), folder_id,
			&message_id)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
	}
	pmessage = message_object_create(pstore, b_new,
		pinfo->cpid, message_id, &folder_id, tag_access,
		OPEN_MODE_FLAG_READWRITE, pctx->pstate);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (TRUE == b_new) {
		if (FALSE == message_object_init_message(
			pmessage, b_fai, pinfo->cpid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
	}
	*phobject = object_tree_add_object_handle(
		pinfo->ptree, hctx, MAPI_MESSAGE, pmessage);
	if (INVALID_HANDLE == *phobject) {
		message_object_free(pmessage);
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
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
	uint32_t result;
	uint16_t replid;
	uint64_t tmp_fid;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint32_t tmp_type;
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t parent_id1;
	uint64_t change_num;
	uint32_t permission;
	const char *username;
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
		return EC_INVALID_PARAMETER;
	}
	propval_buff[1].proptag = PROP_TAG_SOURCEKEY;
	propval_buff[1].pvalue = common_util_get_propvals(
						ppropvals, PROP_TAG_SOURCEKEY);
	if (NULL == propval_buff[1].pvalue) {
		return EC_INVALID_PARAMETER;
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
		return EC_INVALID_PARAMETER;
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = icsupctx_object_get_store(pctx);
	if (SYNC_TYPE_HIERARCHY != icsupctx_object_get_type(pctx)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (0 == ((BINARY*)pproplist->ppropval[0].pvalue)->cb) {
		parent_id1 = icsupctx_object_get_parent_folder_id(pctx);
		if (FALSE == exmdb_client_check_folder_id(
			store_object_get_dir(pstore), parent_id1,
			&b_exist)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (FALSE == b_exist) {
			zarafa_server_put_user_info(pinfo);
			return EC_NO_PARENT_FOLDER;
		}
	} else {
		pbin = pproplist->ppropval[0].pvalue;
		if (22 != pbin->cb) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
		} else {
			tmp_guid = rop_util_make_domain_guid(
				store_object_get_account_id(pstore));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		}
		parent_id1 = rop_util_make_eid(1, tmp_xid.local_id);
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pstore), 0, parent_id1,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (NULL == pvalue) {
			zarafa_server_put_user_info(pinfo);
			return EC_NO_PARENT_FOLDER;
		}
	}
	pbin = pproplist->ppropval[1].pvalue;
	if (22 != pbin->cb) {
		zarafa_server_put_user_info(pinfo);
		return EC_INVALID_PARAMETER;
	}
	if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (TRUE == store_object_check_private(pstore)) {
		tmp_guid = rop_util_make_user_guid(
			store_object_get_account_id(pstore));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		folder_id = rop_util_make_eid(1, tmp_xid.local_id);
	} else {
		tmp_guid = rop_util_make_domain_guid(
			store_object_get_account_id(pstore));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			domain_id = rop_util_make_domain_id(tmp_xid.guid);
			if (-1 == domain_id) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			if (FALSE == system_services_check_same_org(
				domain_id, store_object_get_account_id(pstore))) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			if (FALSE == exmdb_client_get_mapping_replid(
				store_object_get_dir(pstore),
				tmp_xid.guid, &b_found, &replid)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == b_found) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			folder_id = rop_util_make_eid(replid, tmp_xid.local_id);
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_id);
		}
	}
	if (FALSE == exmdb_client_check_folder_id(
		store_object_get_dir(pstore), folder_id,
		&b_exist)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	if (FALSE == b_exist) {
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore), parent_id1,
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		}
		if (FALSE == exmdb_client_get_folder_by_name(
			store_object_get_dir(pstore), parent_id1,
			pproplist->ppropval[3].pvalue, &tmp_fid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 != tmp_fid) {
			zarafa_server_put_user_info(pinfo);
			return EC_DUPLICATE_NAME;
		}
		if (FALSE == exmdb_client_allocate_cn(
			store_object_get_dir(pstore), &change_num)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = common_util_alloc(
			(8 + ppropvals->count)*sizeof(TAGGED_PROPVAL));
		if (NULL == tmp_propvals.ppropval) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
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
		if (FALSE == exmdb_client_create_folder_by_properties(
			store_object_get_dir(pstore), pinfo->cpid,
			&tmp_propvals, &tmp_fid) || folder_id != tmp_fid) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		idset_append(pctx->pstate->pseen, change_num);
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == exmdb_client_get_folder_property(
		store_object_get_dir(pstore), 0, folder_id,
		PROP_TAG_PARENTFOLDERID, &pvalue) || NULL == pvalue) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	parent_id = *(uint64_t*)pvalue;
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (FALSE == store_object_check_private(pstore)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore), parent_id1,
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
			b_guest = TRUE;
		} else {
			b_guest = FALSE;
		}
		if (FALSE == exmdb_client_movecopy_folder(
			store_object_get_dir(pstore),
			store_object_get_account_id(pstore),
			pinfo->cpid, b_guest, pinfo->username,
			parent_id, folder_id, parent_id1,
			pproplist->ppropval[3].pvalue, FALSE,
			&b_exist, &b_partial)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (TRUE == b_exist) {
			zarafa_server_put_user_info(pinfo);
			return EC_DUPLICATE_NAME;
		}
		if (TRUE == b_partial) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
	}
	if (FALSE == exmdb_client_allocate_cn(
		store_object_get_dir(pstore), &change_num)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = common_util_alloc(
		(5 + ppropvals->count)*sizeof(TAGGED_PROPVAL));
	if (NULL == tmp_propvals.ppropval) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
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
	if (FALSE == exmdb_client_set_folder_properties(
		store_object_get_dir(pstore), pinfo->cpid,
		folder_id, &tmp_propvals, &tmp_problems)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	idset_append(pctx->pstate->pseen, change_num);
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_importdeletion(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins)
{
	int i;
	XID tmp_xid;
	BOOL b_hard;
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
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint8_t sync_type;
	uint64_t folder_id;
	uint32_t permission;
	const char *username;
	STORE_OBJECT *pstore;
	EID_ARRAY message_ids;
	ICSUPCTX_OBJECT *pctx;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = icsupctx_object_get_store(pctx);
	sync_type = icsupctx_object_get_type(pctx);
	if (SYNC_DELETES_FLAG_HARDDELETE & flags) {
		b_hard = TRUE;
	} else {
		b_hard = FALSE;
	}
	if (SYNC_DELETES_FLAG_HIERARCHY & flags) {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
	}
	folder_id = icsupctx_object_get_parent_folder_id(pctx);
	username = pinfo->username;
	if (TRUE == store_object_check_owner_mode(pstore)) {
		username = NULL;
	} else {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore), folder_id,
				pinfo->username, &permission)) {
				if ((permission & PERMISSION_FOLDEROWNER) ||
					(permission & PERMISSION_DELETEANY)) {
					username = NULL;	
				} else if (0 == (permission & PERMISSION_DELETEOWNED)) {
					zarafa_server_put_user_info(pinfo);
					return EC_ACCESS_DENIED;
				}
			}
		}
	}
	if (SYNC_TYPE_CONTENTS == sync_type) {
		message_ids.count = 0;
		message_ids.pids = common_util_alloc(
				sizeof(uint64_t)*pbins->count);
		if (NULL == message_ids.pids) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
	}
	for (i=0; i<pbins->count; i++) {
		if (22 != pbins->pbin[i].cb) {
			zarafa_server_put_user_info(pinfo);
			return EC_INVALID_PARAMETER;
		}
		if (FALSE == common_util_binary_to_xid(
			pbins->pbin + i, &tmp_xid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				zarafa_server_put_user_info(pinfo);
				return EC_INVALID_PARAMETER;
			}
			eid = rop_util_make_eid(1, tmp_xid.local_id);
		} else {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				tmp_guid = rop_util_make_domain_guid(
					store_object_get_account_id(pstore));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					zarafa_server_put_user_info(pinfo);
					return EC_INVALID_PARAMETER;
				}
				eid = rop_util_make_eid(1, tmp_xid.local_id);
			} else {
				tmp_guid = rop_util_make_domain_guid(
					store_object_get_account_id(pstore));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					domain_id = rop_util_make_domain_id(tmp_xid.guid);
					if (-1 == domain_id) {
						zarafa_server_put_user_info(pinfo);
						return EC_INVALID_PARAMETER;
					}
					if (FALSE == system_services_check_same_org(
						domain_id, store_object_get_account_id(pstore))) {
						zarafa_server_put_user_info(pinfo);
						return EC_INVALID_PARAMETER;
					}
					if (FALSE == exmdb_client_get_mapping_replid(
						store_object_get_dir(pstore),
						tmp_xid.guid, &b_found, &replid)) {
						zarafa_server_put_user_info(pinfo);
						return EC_ERROR;
					}
					if (FALSE == b_found) {
						zarafa_server_put_user_info(pinfo);
						return EC_INVALID_PARAMETER;
					}
					eid = rop_util_make_eid(replid, tmp_xid.local_id);
				} else {
					eid = rop_util_make_eid(1, tmp_xid.local_id);
				}
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (FALSE == exmdb_client_check_message(
				store_object_get_dir(pstore), folder_id,
				eid, &b_exist)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
		} else {
			if (FALSE == exmdb_client_check_folder_id(
				store_object_get_dir(pstore), eid, &b_exist)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
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
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;	
				}
				if (FALSE == b_owner) {
					zarafa_server_put_user_info(pinfo);
					return EC_ACCESS_DENIED;
				}
			} else {
				if (FALSE == exmdb_client_check_folder_permission(
					store_object_get_dir(pstore),
					eid, username, &permission)) {
					if (0 == (PERMISSION_FOLDEROWNER & permission))	{
						zarafa_server_put_user_info(pinfo);
						return EC_ACCESS_DENIED;
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
					zarafa_server_put_user_info(pinfo);
					return EC_ERROR;	
				}
				if (NULL == pvalue) {
					zarafa_server_put_user_info(pinfo);
					return EC_SUCCESS;
				}
				if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
					goto DELETE_FOLDER;
				}
			}
			if (FALSE == exmdb_client_empty_folder(
				store_object_get_dir(pstore), pinfo->cpid,
				username, eid, b_hard, TRUE, TRUE, TRUE,
				&b_partial) || TRUE == b_partial) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
DELETE_FOLDER:
			if (FALSE == exmdb_client_delete_folder(
				store_object_get_dir(pstore), pinfo->cpid,
				eid, b_hard, &b_result) || FALSE == b_result) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
		}
	}
	if (SYNC_TYPE_CONTENTS == sync_type && message_ids.count > 0) {
		if (FALSE == exmdb_client_delete_messages(
			store_object_get_dir(pstore),
			store_object_get_account_id(pstore),
			pinfo->cpid, NULL, folder_id, &message_ids,
			b_hard, &b_partial) || TRUE == b_partial) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_importreadstates(GUID hsession,
	uint32_t hctx, const STATE_ARRAY *pstates)
{
	int i;
	XID tmp_xid;
	BOOL b_owner;
	void *pvalue;
	GUID tmp_guid;
	USER_INFO *pinfo;
	uint64_t read_cn;
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission;
	uint8_t mark_as_read;
	const char *username;
	STORE_OBJECT *pstore;
	ICSUPCTX_OBJECT *pctx;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pctx = object_tree_get_object(
		pinfo->ptree, hctx, &mapi_type);
	if (NULL == pctx) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_ICSUPCTX != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = icsupctx_object_get_store(pctx);
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_type(pctx)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	username = NULL;
	if (FALSE == store_object_check_owner_mode(pstore)) {
		folder_id = icsupctx_object_get_parent_folder_id(pctx);
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore), folder_id,
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);	
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_READANY)) {
			username = pinfo->username;
		}
	}
	for (i=0; i<pstates->count; i++) {
		if (FALSE == common_util_binary_to_xid(
			&pstates->pstate[i].source_key, &tmp_xid)) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_SUPPORTED;
		}
		if (TRUE == store_object_check_private(pstore)) {
			tmp_guid = rop_util_make_user_guid(
				store_object_get_account_id(pstore));
		} else {
			tmp_guid = rop_util_make_domain_guid(
				store_object_get_account_id(pstore));
		}
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			continue;
		}
		message_id = rop_util_make_eid(1, tmp_xid.local_id);
		if (pstates->pstate[i].message_flags & MESSAGE_FLAG_READ) {
			mark_as_read = 1;
		} else {
			mark_as_read = 0;
		}
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				store_object_get_dir(pstore), message_id,
				username, &b_owner)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;
			}
			if (FALSE == b_owner) {
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_ASSOCIATED;
		proptag_buff[1] = PROP_TAG_READ;
		if (FALSE == exmdb_client_get_message_properties(
			store_object_get_dir(pstore), NULL, 0,
			message_id, &tmp_proptags, &tmp_propvals)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		pvalue = common_util_get_propvals(
			&tmp_propvals, PROP_TAG_ASSOCIATED);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			continue;
		}
		pvalue = common_util_get_propvals(
			&tmp_propvals, PROP_TAG_READ);
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			if (0 == mark_as_read) {
				continue;
			}
		} else {
			if (0 != mark_as_read) {
				continue;
			}
		}
		if (TRUE == store_object_check_private(pstore)) {
			if (FALSE == exmdb_client_set_message_read_state(
				store_object_get_dir(pstore), NULL, message_id,
				mark_as_read, &read_cn)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
		} else {
			if (FALSE == exmdb_client_set_message_read_state(
				store_object_get_dir(pstore), pinfo->username,
				message_id, mark_as_read, &read_cn)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
		}
		idset_append(pctx->pstate->pread, read_cn);
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_getsearchcriteria(GUID hsession,
	uint32_t hfolder, BINARY_ARRAY *pfolder_array,
	RESTRICTION **pprestriction, uint32_t *psearch_stat)
{
	int i;
	BINARY *pbin;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	FOLDER_OBJECT *pfolder;
	LONGLONG_ARRAY folder_ids;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	if (FOLDER_TYPE_SEARCH != folder_object_get_type(pfolder)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SEARCH_FOLDER;
	}
	if (FALSE == exmdb_client_get_search_criteria(
		store_object_get_dir(pstore),
		folder_object_get_id(pfolder),
		psearch_stat, pprestriction,
		&folder_ids)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	pfolder_array->count = folder_ids.count;
	if (0 == folder_ids.count) {
		pfolder_array->pbin = NULL;
		zarafa_server_put_user_info(pinfo);
		return EC_SUCCESS;
	}
	pfolder_array->pbin = common_util_alloc(
			sizeof(BINARY)*folder_ids.count);
	if (NULL == pfolder_array->pbin) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	for (i=0; i<folder_ids.count; i++) {
		pbin = common_util_to_folder_entryid(
				pstore, folder_ids.pll[i]);
		if (NULL == pbin) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		pfolder_array->pbin[i] = *pbin;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_setsearchcriteria(
	GUID hsession, uint32_t hfolder, uint32_t flags,
	const BINARY_ARRAY *pfolder_array,
	const RESTRICTION *prestriction)
{
	int i;
	int db_id;
	BOOL b_result;
	BOOL b_private;
	USER_INFO *pinfo;
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
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pfolder = object_tree_get_object(
		pinfo->ptree, hfolder, &mapi_type);
	if (NULL == pfolder) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_FOLDER != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pstore = folder_object_get_store(pfolder);
	if (FALSE == store_object_check_private(pstore)) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == store_object_check_owner_mode(pstore)) {
		if (FALSE == exmdb_client_check_folder_permission(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			pinfo->username, &permission)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ACCESS_DENIED;
		}
	}
	if (NULL == prestriction || 0 == pfolder_array->count) {
		if (FALSE == exmdb_client_get_search_criteria(
			store_object_get_dir(pstore),
			folder_object_get_id(pfolder),
			&search_status, NULL, NULL)) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;
		}
		if (SEARCH_STATUS_NOT_INITIALIZED == search_status) {
			zarafa_server_put_user_info(pinfo);
			return EC_NOT_INITIALIZED;
		}
		if (0 == (flags & SEARCH_FLAG_RESTART) &&
			NULL == prestriction && 0 == pfolder_array->count) {
			zarafa_server_put_user_info(pinfo);
			return EC_SUCCESS;
		}
	}
	folder_ids.count = pfolder_array->count;
	folder_ids.pll = common_util_alloc(
		sizeof(uint64_t)*folder_ids.count);
	if (NULL == folder_ids.pll) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	for (i=0; i<pfolder_array->count; i++) {
		if (FALSE == common_util_from_folder_entryid(
			pfolder_array->pbin[i], &b_private,
			&db_id, &folder_ids.pll[i])) {
			zarafa_server_put_user_info(pinfo);
			return EC_ERROR;	
		}
		if (FALSE == b_private || db_id !=
			store_object_get_account_id(pstore)) {
			zarafa_server_put_user_info(pinfo);
			return EC_SEARCH_SCOPE_VIOLATED;
		}
		if (FALSE == store_object_check_owner_mode(pstore)) {
			if (FALSE == exmdb_client_check_folder_permission(
				store_object_get_dir(pstore), folder_ids.pll[i],
				pinfo->username, &permission)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER) &&
				0 == (permission & PERMISSION_READANY)) {
				zarafa_server_put_user_info(pinfo);
				return EC_ACCESS_DENIED;
			}
		}
	}
	if (FALSE == exmdb_client_set_search_criteria(
		store_object_get_dir(pstore), pinfo->cpid,
		folder_object_get_id(pfolder), flags,
		prestriction, &folder_ids, &b_result)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	if (FALSE == b_result) {
		zarafa_server_put_user_info(pinfo);
		return EC_SEARCH_SCOPE_VIOLATED;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_messagetorfc822(GUID hsession,
	uint32_t hmessage, BINARY *peml_bin)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == common_util_message_to_rfc822(
		message_object_get_store(pmessage),
		message_object_get_id(pmessage), peml_bin)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_rfc822tomessage(GUID hsession,
	uint32_t hmessage, const BINARY *peml_bin)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	MESSAGE_CONTENT *pmsgctnt;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pmsgctnt = common_util_rfc822_to_message(
		message_object_get_store(pmessage), peml_bin);
	if (NULL == pmsgctnt) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == message_object_write_message(
		pmessage, pmsgctnt)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_messagetoical(GUID hsession,
	uint32_t hmessage, BINARY *pical_bin)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == common_util_message_to_ical(
		message_object_get_store(pmessage),
		message_object_get_id(pmessage), pical_bin)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	MESSAGE_CONTENT *pmsgctnt;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pmsgctnt = common_util_ical_to_message(
		message_object_get_store(pmessage), pical_bin);
	if (NULL == pmsgctnt) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == message_object_write_message(
		pmessage, pmsgctnt)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_messagetovcf(GUID hsession,
	uint32_t hmessage, BINARY *pvcf_bin)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == common_util_message_to_vcf(
		message_object_get_store(pmessage),
		message_object_get_id(pmessage), pvcf_bin)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
}

uint32_t zarafa_server_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin)
{
	USER_INFO *pinfo;
	uint8_t mapi_type;
	MESSAGE_OBJECT *pmessage;
	MESSAGE_CONTENT *pmsgctnt;
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	pmessage = object_tree_get_object(
		pinfo->ptree, hmessage, &mapi_type);
	if (NULL == pmessage) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (MAPI_MESSAGE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_NOT_SUPPORTED;
	}
	pmsgctnt = common_util_vcf_to_message(
		message_object_get_store(pmessage), pvcf_bin);
	if (NULL == pmsgctnt) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	if (FALSE == message_object_write_message(
		pmessage, pmsgctnt)) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;	
	}
	zarafa_server_put_user_info(pinfo);
	return EC_SUCCESS;
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
	USER_INFO *pinfo;
	char maildir[256];
	char username[256];
	char tool_path[256];
	char tool_command[256];
	char cookie_buff[1024];
	int pipes_in[2] = {-1, -1};
	int pipes_out[2] = {-1, -1};
	
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	if (FALSE == common_util_addressbook_entryid_to_username(
		entryid, username) || FALSE ==
		system_services_get_maildir(username, maildir)) {
		zarafa_server_put_user_info(pinfo);
		*ppresult_string = NULL;
		return EC_SUCCESS;
	}
	if (0 == strcasecmp(pinfo->username, username)) {
		tmp_len = snprintf(cookie_buff, sizeof(cookie_buff),
			"starttime=%lu;endtime=%lu;dirs=1;dir0=%s",
			starttime, endtime, maildir);
	} else {
		tmp_len = snprintf(cookie_buff, sizeof(cookie_buff),
			"username=%s;starttime=%lu;endtime=%lu;dirs=1;dir0=%s",
			pinfo->username, starttime, endtime, maildir);
	}
	zarafa_server_put_user_info(pinfo);
	 if (-1 == pipe(pipes_in)) {
		return EC_ERROR;
	}
	if (-1 == pipe(pipes_out)) {
		close(pipes_in[0]);
		close(pipes_in[1]);
		return EC_ERROR;
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
		*ptoken = '\0';
		ptoken ++;
		sprintf(tool_command, "./%s", ptoken);
		chdir(tool_path);
		argv[0] = tool_command;
		argv[1] = NULL;
		if (execve(tool_command, argv, NULL) == -1) {
			exit(-1);
		}
	} else if (pid < 0) {
		close(pipes_in[0]);
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(pipes_out[1]);
		return EC_ERROR;
	}
	close(pipes_in[0]);
	close(pipes_out[1]);
	write(pipes_in[1], cookie_buff, tmp_len);
	close(pipes_in[1]);
	*ppresult_string = common_util_alloc(1024*1024);
	if (NULL == *ppresult_string) {
		waitpid(pid, &status, 0);
		return EC_ERROR;
	}
	offset = 0;
	while ((tmp_len = read(pipes_out[0], *ppresult_string
		+ offset, 1024*1024 - offset)) > 0) {
		offset += tmp_len;
		if (offset >= 1024*1024) {
			waitpid(pid, &status, 0);
			close(pipes_out[0]);
			return EC_ERROR;
		}
	}
	(*ppresult_string)[offset] = '\0';
	close(pipes_out[0]);
	waitpid(pid, &status, 0);
	if (0 != status) {
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t zarafa_server_setpasswd(const char *username,
	const char *passwd, const char *new_passwd)
{
	if (FALSE == system_services_set_password(
		username, passwd, new_passwd)) {
		return EC_ACCESS_DENIED;	
	}
	return EC_SUCCESS;
}

uint32_t zarafa_server_linkmessage(GUID hsession,
	BINARY search_entryid, BINARY message_entryid)
{
	uint32_t cpid;
	BOOL b_result;
	BOOL b_private;
	BOOL b_private1;
	uint32_t handle;
	USER_INFO *pinfo;
	char maildir[256];
	uint8_t mapi_type;
	uint64_t folder_id;
	uint64_t folder_id1;
	uint64_t message_id;
	uint32_t account_id;
	uint32_t account_id1;
	STORE_OBJECT *pstore;
	
	if (EITLT_PRIVATE_FOLDER != common_util_get_messaging_entryid_type(
		search_entryid) || FALSE == common_util_from_folder_entryid(
		search_entryid, &b_private, &account_id, &folder_id) ||
		TRUE != b_private) {
		return EC_INVALID_PARAMETER;
	}
	if (EITLT_PRIVATE_MESSAGE != common_util_get_messaging_entryid_type(
		message_entryid) || FALSE == common_util_from_message_entryid(
		message_entryid, &b_private1, &account_id1, &folder_id1,
		&message_id) || TRUE != b_private1 || account_id != account_id1) {
		return EC_INVALID_PARAMETER;	
	}
	pinfo = zarafa_server_query_session(hsession);
	if (NULL == pinfo) {
		return EC_ERROR;
	}
	handle = object_tree_get_store_handle(
		pinfo->ptree, b_private, account_id);
	if (INVALID_HANDLE == handle) {
		zarafa_server_put_user_info(pinfo);
		return EC_NULL_OBJECT;
	}
	if (account_id != pinfo->user_id) {
		zarafa_server_put_user_info(pinfo);
		return EC_ACCESS_DENIED;
	}
	pstore = object_tree_get_object(pinfo->ptree, handle, &mapi_type);
	if (NULL == pstore || MAPI_STORE != mapi_type) {
		zarafa_server_put_user_info(pinfo);
		return EC_ERROR;
	}
	strcpy(maildir, store_object_get_dir(pstore));
	cpid = pinfo->cpid;
	zarafa_server_put_user_info(pinfo);
	if (FALSE == exmdb_client_link_message(maildir, cpid,
		folder_id, message_id, &b_result) || FALSE == b_result) {
		return EC_ERROR;	
	}
	return EC_SUCCESS;
}
