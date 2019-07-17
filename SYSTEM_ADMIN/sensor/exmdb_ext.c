#include "exmdb_ext.h"
#include "rop_util.h"
#include "idset.h"


static int exmdb_ext_push_connect_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_string(pext,
				ppayload->connect.prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext,
			ppayload->connect.remote_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
			ppayload->connect.b_private);
}

static int exmdb_ext_push_listen_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
			ppayload->listen_notification.remote_id);
}	

static int exmdb_ext_push_subscribe_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint16(pext,
		ppayload->subscribe_notification.notificaton_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->subscribe_notification.b_whole);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->subscribe_notification.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->subscribe_notification.message_id);
}

static int exmdb_ext_push_unsubscribe_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unsubscribe_notification.sub_id);
}

int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_WCOUNT)) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_advance(&ext_push, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	status = ext_buffer_push_uint8(&ext_push, prequest->call_id);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	if (CALL_ID_CONNECT == prequest->call_id) {
		status = exmdb_ext_push_connect_request(
				&ext_push, &prequest->payload);
		goto END_PUSH_REQUEST;
	} else if (CALL_ID_LISTEN_NOTIFICATION == prequest->call_id) {
		status = exmdb_ext_push_listen_notification_request(
							&ext_push, &prequest->payload);
		goto END_PUSH_REQUEST;
	}
	status = ext_buffer_push_string(&ext_push, prequest->dir);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	switch (prequest->call_id) {
	case CALL_ID_PING_STORE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_subscribe_notification_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_unsubscribe_notification_request(
									&ext_push, &prequest->payload);
		break;
	default:
		ext_buffer_push_free(&ext_push);
		return EXT_ERR_BAD_SWITCH;
	}
END_PUSH_REQUEST:
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	pbin_out->cb = ext_push.offset;
	ext_push.offset = 0;
	ext_buffer_push_uint32(&ext_push,
		pbin_out->cb - sizeof(uint32_t));
	/* memory referneced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.data;
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_pull_subscribe_notification_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->subscribe_notification.sub_id);
}

/* CALL_ID_CONNECT, CALL_ID_LISTEN_NOTIFICATION not included */
int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXT_BUFFER_ALLOC auto_alloc, EXMDB_RESPONSE *presponse)
{
	int status;
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, auto_alloc, EXT_FLAG_WCOUNT);
	switch (presponse->call_id) {
	case CALL_ID_PING_STORE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		return exmdb_ext_pull_subscribe_notification_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	EXT_BUFFER_ALLOC auto_alloc, DB_NOTIFY_DATAGRAM *pnotify)
{
	int status;
	uint8_t tmp_byte;
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, auto_alloc, EXT_FLAG_WCOUNT);
	status = ext_buffer_pull_string(&ext_pull, &pnotify->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(&ext_pull, &pnotify->b_table);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_long_array(&ext_pull, &pnotify->id_array);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(&ext_pull, &pnotify->db_notify.type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (pnotify->db_notify.type) {
	case DB_NOTIFY_TYPE_NEW_MAIL:
		pnotify->db_notify.pdata = auto_alloc(
					sizeof(DB_NOTIFY_NEW_MAIL));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint32(&ext_pull,
			&((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->message_flags);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_string(&ext_pull,
			(char**)&((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->pmessage_class);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}
