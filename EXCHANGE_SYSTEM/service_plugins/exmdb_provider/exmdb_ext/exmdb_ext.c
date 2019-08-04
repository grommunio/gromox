#include "exmdb_ext.h"
#include "rop_util.h"
#include "idset.h"

static int exmdb_ext_pull_connect_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_string(pext,
				&ppayload->connect.prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_string(pext,
			&ppayload->connect.remote_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
			&ppayload->connect.b_private);
}

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

static int exmdb_ext_pull_listen_notification_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_string(pext,
			&ppayload->listen_notification.remote_id);
}

static int exmdb_ext_push_listen_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
			ppayload->listen_notification.remote_id);
}

static int exmdb_ext_pull_get_named_propids_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->get_named_propids.b_create);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_named_propids.ppropnames =
		common_util_alloc(sizeof(PROPNAME_ARRAY));
	if (NULL == ppayload->get_named_propids.ppropnames) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_propname_array(pext,
		ppayload->get_named_propids.ppropnames);
}

static int exmdb_ext_push_get_named_propids_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->get_named_propids.b_create);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_propname_array(pext,
		ppayload->get_named_propids.ppropnames);
}

static int exmdb_ext_pull_get_named_propnames_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	ppayload->get_named_propnames.ppropids =
		common_util_alloc(sizeof(PROPID_ARRAY));
	if (NULL == ppayload->get_named_propnames.ppropids) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_propid_array(pext,
		ppayload->get_named_propnames.ppropids);
}

static int exmdb_ext_push_get_named_propnames_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_propid_array(pext,
		ppayload->get_named_propnames.ppropids);
}

static int exmdb_ext_pull_get_mapping_guid_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_mapping_guid.replid);
}

static int exmdb_ext_push_get_mapping_guid_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint16(pext,
		ppayload->get_mapping_guid.replid);
}

static int exmdb_ext_pull_get_mapping_replid_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_guid(pext,
		&ppayload->get_mapping_replid.guid);
}

static int exmdb_ext_push_get_mapping_replid_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_guid(pext,
		&ppayload->get_mapping_replid.guid);
}

static int exmdb_ext_pull_get_store_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_store_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_store_properties.pproptags = 
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->get_store_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->get_store_properties.pproptags);
}

static int exmdb_ext_push_get_store_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_store_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_store_properties.pproptags);
}

static int exmdb_ext_pull_set_store_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_store_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->set_store_properties.ppropvals = 
		common_util_alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->set_store_properties.ppropvals) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_tpropval_array(pext,
		ppayload->set_store_properties.ppropvals);
}

static int exmdb_ext_push_set_store_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_store_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_store_properties.ppropvals);
}

static int exmdb_ext_pull_remove_store_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	ppayload->remove_store_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->remove_store_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->remove_store_properties.pproptags);
}

static int exmdb_ext_push_remove_store_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_store_properties.pproptags);
}

static int exmdb_ext_pull_check_mailbox_permission_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_string(pext,
		&ppayload->check_mailbox_permission.username);
}

static int exmdb_ext_push_check_mailbox_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
		ppayload->check_mailbox_permission.username);
}

static int exmdb_ext_pull_get_folder_by_class_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_string(pext,
		&ppayload->get_folder_by_class.str_class);
}

static int exmdb_ext_push_get_folder_by_class_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
		ppayload->get_folder_by_class.str_class);
}

static int exmdb_ext_pull_set_folder_by_class_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_folder_by_class.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext,
		&ppayload->set_folder_by_class.str_class);
}

static int exmdb_ext_push_set_folder_by_class_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->set_folder_by_class.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext,
		ppayload->set_folder_by_class.str_class);
}

static int exmdb_ext_pull_check_folder_id_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->check_folder_id.folder_id);
}

static int exmdb_ext_push_check_folder_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->check_folder_id.folder_id);
}

static int exmdb_ext_pull_query_folder_messages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->query_folder_messages.folder_id);
}

static int exmdb_ext_push_query_folder_messages_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->query_folder_messages.folder_id);
}

static int exmdb_ext_pull_check_folder_deleted_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->check_folder_deleted.folder_id);
}

static int exmdb_ext_push_check_folder_deleted_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->check_folder_deleted.folder_id);
}

static int exmdb_ext_pull_get_folder_by_name_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_folder_by_name.parent_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext,
		&ppayload->get_folder_by_name.str_name);
}

static int exmdb_ext_push_get_folder_by_name_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->get_folder_by_name.parent_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext,
		ppayload->get_folder_by_name.str_name);
}

static int exmdb_ext_pull_check_folder_permission_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->check_folder_permission.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext,
		&ppayload->check_folder_permission.username);
}

static int exmdb_ext_push_check_folder_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->check_folder_permission.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext,
		ppayload->check_folder_permission.username);
}

static int exmdb_ext_pull_create_folder_by_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->create_folder_by_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->create_folder_by_properties.pproperties =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->create_folder_by_properties.pproperties) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_tpropval_array(pext,
		ppayload->create_folder_by_properties.pproperties);
}

static int exmdb_ext_push_create_folder_by_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->create_folder_by_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext,
		ppayload->create_folder_by_properties.pproperties);
}

static int exmdb_ext_pull_get_folder_all_proptags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_folder_all_proptags.folder_id);
}

static int exmdb_ext_push_get_folder_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_folder_all_proptags.folder_id);
}

static int exmdb_ext_pull_get_folder_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_folder_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_folder_properties.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_folder_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->get_folder_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->get_folder_properties.pproptags);
}

static int exmdb_ext_push_get_folder_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_folder_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->get_folder_properties.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_folder_properties.pproptags);
}

static int exmdb_ext_pull_set_folder_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->set_folder_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_folder_properties.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->set_folder_properties.pproperties =
		common_util_alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->set_folder_properties.pproperties) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_tpropval_array(pext,
		ppayload->set_folder_properties.pproperties);
}

static int exmdb_ext_push_set_folder_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->set_folder_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->set_folder_properties.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_folder_properties.pproperties);
}

static int exmdb_ext_pull_remove_folder_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->remove_folder_properties.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->remove_folder_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->remove_folder_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->remove_folder_properties.pproptags);
}

static int exmdb_ext_push_remove_folder_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->remove_folder_properties.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_folder_properties.pproptags);
}

static int exmdb_ext_pull_delete_folder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->delete_folder.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->delete_folder.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->delete_folder.b_hard);
}

static int exmdb_ext_push_delete_folder_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
			ppayload->delete_folder.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->delete_folder.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->delete_folder.b_hard);
}

static int exmdb_ext_pull_empty_folder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->empty_folder.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->empty_folder.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->empty_folder.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->empty_folder.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->empty_folder.b_hard);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->empty_folder.b_normal);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->empty_folder.b_fai);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->empty_folder.b_sub);
}

static int exmdb_ext_push_empty_folder_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->empty_folder.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->empty_folder.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->empty_folder.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->empty_folder.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->empty_folder.b_hard);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->empty_folder.b_normal);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->empty_folder.b_fai);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->empty_folder.b_sub);
}

static int exmdb_ext_pull_check_folder_cycle_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->check_folder_cycle.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->check_folder_cycle.dst_fid);
}

static int exmdb_ext_push_check_folder_cycle_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->check_folder_cycle.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->check_folder_cycle.dst_fid);
}

static int exmdb_ext_pull_copy_folder_internal_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->copy_folder_internal.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->copy_folder_internal.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_guest);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->copy_folder_internal.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->copy_folder_internal.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->copy_folder_internal.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_normal);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_fai);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_sub);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->copy_folder_internal.dst_fid);
}

static int exmdb_ext_push_copy_folder_internal_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->copy_folder_internal.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->copy_folder_internal.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->copy_folder_internal.b_guest);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->copy_folder_internal.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->copy_folder_internal.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->copy_folder_internal.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->copy_folder_internal.b_normal);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->copy_folder_internal.b_fai);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->copy_folder_internal.b_sub);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->copy_folder_internal.dst_fid);
}

static int exmdb_ext_pull_get_search_criteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_search_criteria.folder_id);
}

static int exmdb_ext_push_get_search_criteria_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_search_criteria.folder_id);
}

static int exmdb_ext_pull_set_search_criteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->set_search_criteria.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_search_criteria.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->set_search_criteria.search_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->set_search_criteria.prestriction = NULL;
	} else {
		ppayload->set_search_criteria.prestriction =
			common_util_alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->set_search_criteria.prestriction) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_restriction(pext,
			ppayload->set_search_criteria.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	ppayload->set_search_criteria.pfolder_ids =
		common_util_alloc(sizeof(LONGLONG_ARRAY));
	if (NULL == ppayload->set_search_criteria.pfolder_ids) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_longlong_array(pext,
		ppayload->set_search_criteria.pfolder_ids);
}

static int exmdb_ext_push_set_search_criteria_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->set_search_criteria.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->set_search_criteria.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->set_search_criteria.search_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->set_search_criteria.prestriction) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_restriction(pext,
			ppayload->set_search_criteria.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_push_longlong_array(pext,
		ppayload->set_search_criteria.pfolder_ids);
}

static int exmdb_ext_pull_movecopy_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->movecopy_message.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->movecopy_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_message.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_message.dst_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_message.dst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_message.b_move);
}

static int exmdb_ext_push_movecopy_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->movecopy_message.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->movecopy_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_message.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_message.dst_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_message.dst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_message.b_move);
}

static int exmdb_ext_pull_movecopy_messages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->movecopy_messages.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->movecopy_messages.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->movecopy_messages.b_guest);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->movecopy_messages.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->movecopy_messages.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_messages.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_messages.dst_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->movecopy_messages.b_copy);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->movecopy_messages.pmessage_ids =
		common_util_alloc(sizeof(EID_ARRAY));
	if (NULL == ppayload->movecopy_messages.pmessage_ids) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_eid_array(pext,
		ppayload->movecopy_messages.pmessage_ids);
}

static int exmdb_ext_push_movecopy_messages_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->movecopy_messages.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->movecopy_messages.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->movecopy_messages.b_guest);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->movecopy_messages.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->movecopy_messages.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_messages.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_messages.dst_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->movecopy_messages.b_copy);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_eid_array(pext,
		ppayload->movecopy_messages.pmessage_ids);
}

static int exmdb_ext_pull_movecopy_folder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->movecopy_folder.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->movecopy_folder.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->movecopy_folder.b_guest);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->movecopy_folder.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->movecopy_folder.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_folder.src_pid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_folder.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->movecopy_folder.dst_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_string(pext,
		&ppayload->movecopy_folder.str_new);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_folder.b_copy);
}

static int exmdb_ext_push_movecopy_folder_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->movecopy_folder.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->movecopy_folder.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->movecopy_folder.b_guest);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->movecopy_folder.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->movecopy_folder.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_folder.src_pid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_folder.src_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->movecopy_folder.dst_fid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext,
		ppayload->movecopy_folder.str_new);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_folder.b_copy);
}

static int exmdb_ext_pull_delete_messages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->delete_messages.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->delete_messages.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->delete_messages.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->delete_messages.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->delete_messages.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->delete_messages.pmessage_ids =
		common_util_alloc(sizeof(EID_ARRAY));
	if (NULL == ppayload->delete_messages.pmessage_ids) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_eid_array(pext,
		ppayload->delete_messages.pmessage_ids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->delete_messages.b_hard);
}

static int exmdb_ext_push_delete_messages_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->delete_messages.account_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->delete_messages.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->delete_messages.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->delete_messages.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->delete_messages.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		ppayload->delete_messages.pmessage_ids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->delete_messages.b_hard);
}

static int exmdb_ext_pull_get_message_brief_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_message_brief.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_message_brief.message_id);
}

static int exmdb_ext_push_get_message_brief_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_message_brief.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_brief.message_id);
}

static int exmdb_ext_pull_sum_hierarchy_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->sum_hierarchy.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->sum_hierarchy.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->sum_hierarchy.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->sum_hierarchy.b_depth);
}

static int exmdb_ext_push_sum_hierarchy_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->sum_hierarchy.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->sum_hierarchy.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->sum_hierarchy.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_push_bool(pext,
		ppayload->sum_hierarchy.b_depth);
}

static int exmdb_ext_pull_load_hierarchy_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->load_hierarchy_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_hierarchy_table.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->load_hierarchy_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint8(pext,
		&ppayload->load_hierarchy_table.table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_hierarchy_table.prestriction = NULL;
	} else {
		ppayload->load_hierarchy_table.prestriction =
			common_util_alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->load_hierarchy_table.prestriction) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_restriction(pext,
			ppayload->load_hierarchy_table.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_push_load_hierarchy_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->load_hierarchy_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->load_hierarchy_table.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->load_hierarchy_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint8(pext,
		ppayload->load_hierarchy_table.table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->load_hierarchy_table.prestriction) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_restriction(pext,
			ppayload->load_hierarchy_table.prestriction);
	}
}

static int exmdb_ext_pull_sum_content_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->sum_content.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->sum_content.b_fai);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->sum_content.b_deleted);
}

static int exmdb_ext_push_sum_content_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->sum_content.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
			ppayload->sum_content.b_fai);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->sum_content.b_deleted);
}

static int exmdb_ext_pull_load_content_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_content_table.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->load_content_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_content_table.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->load_content_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint8(pext,
		&ppayload->load_content_table.table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_content_table.prestriction = NULL;
	} else {
		ppayload->load_content_table.prestriction =
			common_util_alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->load_content_table.prestriction) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_restriction(pext,
			ppayload->load_content_table.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_content_table.psorts = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->load_content_table.psorts =
		common_util_alloc(sizeof(SORTORDER_SET));
	if (NULL == ppayload->load_content_table.psorts) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_sortorder_set(pext,
			ppayload->load_content_table.psorts);
}

static int exmdb_ext_push_load_content_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->load_content_table.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->load_content_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->load_content_table.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->load_content_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint8(pext,
		ppayload->load_content_table.table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->load_content_table.prestriction) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_restriction(pext,
			ppayload->load_content_table.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL == ppayload->load_content_table.psorts) {
		return ext_buffer_push_uint8(pext, 0);
	}
	status = ext_buffer_push_uint8(pext, 1);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_sortorder_set(pext,
		ppayload->load_content_table.psorts);
}

static int exmdb_ext_pull_reload_content_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->reload_content_table.table_id);
}

static int exmdb_ext_push_reload_content_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->reload_content_table.table_id);
}

static int exmdb_ext_pull_load_permission_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->load_permission_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext,
		&ppayload->load_permission_table.table_flags);
}

static int exmdb_ext_push_load_permission_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->load_permission_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint8(pext,
		ppayload->load_permission_table.table_flags);
}

static int exmdb_ext_pull_load_rule_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->load_rule_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext,
		&ppayload->load_rule_table.table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_rule_table.prestriction = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->load_rule_table.prestriction =
			common_util_alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->load_rule_table.prestriction) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_restriction(pext,
			ppayload->load_rule_table.prestriction);
	}
}

static int exmdb_ext_push_load_rule_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->load_rule_table.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext,
		ppayload->load_rule_table.table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->load_rule_table.prestriction) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_restriction(pext,
			ppayload->load_rule_table.prestriction);
	}
}

static int exmdb_ext_pull_unload_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->unload_table.table_id);
}

static int exmdb_ext_push_unload_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unload_table.table_id);
}

static int exmdb_ext_pull_sum_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->sum_table.table_id);
}

static int exmdb_ext_push_sum_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->sum_table.table_id);
}

static int exmdb_ext_pull_query_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->query_table.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext, &ppayload->query_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &ppayload->query_table.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &ppayload->query_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->query_table.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->query_table.pproptags) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_proptag_array(pext,
				ppayload->query_table.pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->query_table.start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_int32(pext,
		&ppayload->query_table.row_needed);
}

static int exmdb_ext_push_query_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->query_table.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->query_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, ppayload->query_table.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, ppayload->query_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(
		pext, ppayload->query_table.pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, ppayload->query_table.start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_int32(pext, ppayload->query_table.row_needed);
}

static int exmdb_ext_pull_match_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->match_table.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->match_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext,
			&ppayload->match_table.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->match_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->match_table.b_forward);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->match_table.start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->match_table.pres =
		common_util_alloc(sizeof(RESTRICTION));
	if (NULL == ppayload->match_table.pres) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_restriction(pext,
				ppayload->match_table.pres);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->match_table.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->match_table.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
			ppayload->match_table.pproptags);
}

static int exmdb_ext_push_match_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->match_table.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->match_table.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext,
			ppayload->match_table.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->match_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->match_table.b_forward);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->match_table.start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_restriction(
		pext, ppayload->match_table.pres);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
			ppayload->match_table.pproptags);
}

static int exmdb_ext_pull_locate_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->locate_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->locate_table.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->locate_table.inst_num);
}

static int exmdb_ext_push_locate_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->locate_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->locate_table.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->locate_table.inst_num);
}

static int exmdb_ext_pull_read_table_row_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->read_table_row.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->read_table_row.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->read_table_row.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->read_table_row.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->read_table_row.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->read_table_row.pproptags) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_proptag_array(pext,
			ppayload->read_table_row.pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->read_table_row.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->read_table_row.inst_num);
}

static int exmdb_ext_push_read_table_row_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->read_table_row.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->read_table_row.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->read_table_row.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->read_table_row.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext,
			ppayload->read_table_row.pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->read_table_row.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->read_table_row.inst_num);
}

static int exmdb_ext_pull_mark_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->mark_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->mark_table.position);
}

static int exmdb_ext_push_mark_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->mark_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->mark_table.position);
}

static int exmdb_ext_pull_get_table_all_proptags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_table_all_proptags.table_id);
}

static int exmdb_ext_push_get_table_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_table_all_proptags.table_id);
}

static int exmdb_ext_pull_expand_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->expand_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->expand_table.inst_id);
}

static int exmdb_ext_push_expand_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->expand_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->expand_table.inst_id);
}

static int exmdb_ext_pull_collapse_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->collapse_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->collapse_table.inst_id);
}

static int exmdb_ext_push_collapse_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->collapse_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->collapse_table.inst_id);
}

static int exmdb_ext_pull_store_table_state_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->store_table_state.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->store_table_state.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->store_table_state.inst_num);
}

static int exmdb_ext_push_store_table_state_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->store_table_state.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->store_table_state.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->store_table_state.inst_num);
}

static int exmdb_ext_pull_restore_table_state_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->restore_table_state.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->restore_table_state.state_id);
}

static int exmdb_ext_push_restore_table_state_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->restore_table_state.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->restore_table_state.state_id);
}

static int exmdb_ext_pull_check_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->check_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->check_message.message_id);
}

static int exmdb_ext_push_check_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->check_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->check_message.message_id);
}

static int exmdb_ext_pull_check_message_deleted_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->check_message_deleted.message_id);
}

static int exmdb_ext_push_check_message_deleted_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->check_message_deleted.message_id);
}

static int exmdb_ext_pull_load_message_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->load_message_instance.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->load_message_instance.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_message_instance.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->load_message_instance.b_new);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->load_message_instance.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->load_message_instance.message_id);
}

static int exmdb_ext_push_load_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->load_message_instance.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->load_message_instance.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->load_message_instance.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->load_message_instance.b_new);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->load_message_instance.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->load_message_instance.message_id);
}

static int exmdb_ext_pull_load_embedded_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->load_embedded_instance.b_new);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_embedded_instance.attachment_instance_id);
}

static int exmdb_ext_push_load_embedded_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->load_embedded_instance.b_new);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->load_embedded_instance.attachment_instance_id);
}

static int exmdb_ext_pull_get_embeded_cn_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_embeded_cn.instance_id);
}

static int exmdb_ext_push_get_embeded_cn_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_embeded_cn.instance_id);
}

static int exmdb_ext_pull_reload_message_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->reload_message_instance.instance_id);
}

static int exmdb_ext_push_reload_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->reload_message_instance.instance_id);
}

static int exmdb_ext_pull_clear_message_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->clear_message_instance.instance_id);
}

static int exmdb_ext_push_clear_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->clear_message_instance.instance_id);
}

static int exmdb_ext_pull_read_message_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->read_message_instance.instance_id);
}

static int exmdb_ext_push_read_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->read_message_instance.instance_id);
}

static int exmdb_ext_pull_write_message_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->write_message_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->write_message_instance.pmsgctnt =
		common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == ppayload->write_message_instance.pmsgctnt) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_message_content(pext,
		ppayload->write_message_instance.pmsgctnt);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->write_message_instance.b_force);
}

static int exmdb_ext_push_write_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->write_message_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_message_content(pext,
		ppayload->write_message_instance.pmsgctnt);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->write_message_instance.b_force);
}

static int exmdb_ext_pull_load_attachment_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_attachment_instance.message_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_attachment_instance.attachment_num);
}

static int exmdb_ext_push_load_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->load_attachment_instance.message_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->load_attachment_instance.attachment_num);
}

static int exmdb_ext_pull_create_attachment_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->create_attachment_instance.message_instance_id);
}

static int exmdb_ext_push_create_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->create_attachment_instance.message_instance_id);
}

static int exmdb_ext_pull_read_attachment_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->read_attachment_instance.instance_id);
}

static int exmdb_ext_push_read_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->read_attachment_instance.instance_id);
}

static int exmdb_ext_pull_write_attachment_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->write_attachment_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->write_attachment_instance.pattctnt =
		common_util_alloc(sizeof(ATTACHMENT_CONTENT));
	if (NULL == ppayload->write_attachment_instance.pattctnt) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_tpropval_array(pext,
		&ppayload->write_attachment_instance.pattctnt->proplist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != tmp_byte) {
		ppayload->write_attachment_instance.pattctnt->pembedded =
						common_util_alloc(sizeof(MESSAGE_CONTENT));
		if (NULL == ppayload->write_attachment_instance.pattctnt->pembedded) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_message_content(pext,
			ppayload->write_attachment_instance.pattctnt->pembedded);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		ppayload->write_attachment_instance.pattctnt->pembedded = NULL;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->write_attachment_instance.b_force);
}

static int exmdb_ext_push_write_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->write_attachment_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_tpropval_array(pext,
		&ppayload->write_attachment_instance.pattctnt->proplist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->write_attachment_instance.pattctnt->pembedded) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_message_content(pext,
			ppayload->write_attachment_instance.pattctnt->pembedded);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_push_bool(pext,
		ppayload->write_attachment_instance.b_force);
}

static int exmdb_ext_pull_delete_message_instance_attachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->delete_message_instance_attachment.message_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->delete_message_instance_attachment.attachment_num);
}

static int exmdb_ext_push_delete_message_instance_attachment_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->delete_message_instance_attachment.message_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->delete_message_instance_attachment.attachment_num);
}

static int exmdb_ext_pull_flush_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->flush_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->flush_instance.account = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		return ext_buffer_pull_string(pext,
			&ppayload->flush_instance.account);
	}
}

static int exmdb_ext_push_flush_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->flush_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->flush_instance.account) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_string(pext,
			ppayload->flush_instance.account);
	}
}

static int exmdb_ext_pull_unload_instance_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->unload_instance.instance_id);
}

static int exmdb_ext_push_unload_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unload_instance.instance_id);
}

static int exmdb_ext_pull_get_instance_all_proptags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_instance_all_proptags.instance_id);
}

static int exmdb_ext_push_get_instance_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_instance_all_proptags.instance_id);
}

static int exmdb_ext_pull_get_instance_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_instance_properties.size_limit);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_instance_properties.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_instance_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->get_instance_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->get_instance_properties.pproptags);
}

static int exmdb_ext_push_get_instance_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_instance_properties.size_limit);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->get_instance_properties.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_instance_properties.pproptags);
}

static int exmdb_ext_pull_set_instance_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->set_instance_properties.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->set_instance_properties.pproperties =
		common_util_alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->set_instance_properties.pproperties) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_tpropval_array(pext,
		ppayload->set_instance_properties.pproperties);
}

static int exmdb_ext_push_set_instance_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->set_instance_properties.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_instance_properties.pproperties);
}

static int exmdb_ext_pull_remove_instance_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->remove_instance_properties.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->remove_instance_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->remove_instance_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->remove_instance_properties.pproptags);
}

static int exmdb_ext_push_remove_instance_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->remove_instance_properties.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_instance_properties.pproptags);
}

static int exmdb_ext_pull_check_instance_cycle_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->check_instance_cycle.src_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->check_instance_cycle.dst_instance_id);
}

static int exmdb_ext_push_check_instance_cycle_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->check_instance_cycle.src_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->check_instance_cycle.dst_instance_id);
}

static int exmdb_ext_pull_empty_message_instance_rcpts_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->empty_message_instance_rcpts.instance_id);
}

static int exmdb_ext_push_empty_message_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->empty_message_instance_rcpts.instance_id);
}

static int exmdb_ext_pull_get_message_instance_rcpts_num_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_message_instance_rcpts_num.instance_id);	
}

static int exmdb_ext_push_get_message_instance_rcpts_num_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_rcpts_num.instance_id);	
}

static int exmdb_ext_pull_get_message_instance_rcpts_all_proptags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_message_instance_rcpts_all_proptags.instance_id);	
}

static int exmdb_ext_push_get_message_instance_rcpts_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_rcpts_all_proptags.instance_id);	
}

static int exmdb_ext_pull_get_message_instance_rcpts_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_message_instance_rcpts.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_message_instance_rcpts.row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_message_instance_rcpts.need_count);
}

static int exmdb_ext_push_get_message_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_rcpts.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_rcpts.row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext,
		ppayload->get_message_instance_rcpts.need_count);
}

static int exmdb_ext_pull_update_message_instance_rcpts_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->update_message_instance_rcpts.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->update_message_instance_rcpts.pset =
			common_util_alloc(sizeof(TARRAY_SET));
	if (NULL == ppayload->update_message_instance_rcpts.pset) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_tarray_set(pext,
		ppayload->update_message_instance_rcpts.pset);
}

static int exmdb_ext_push_update_message_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->update_message_instance_rcpts.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tarray_set(pext,
		ppayload->update_message_instance_rcpts.pset);
}

static int exmdb_ext_pull_copy_instance_rcpts_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_instance_rcpts.b_force);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->copy_instance_rcpts.src_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->copy_instance_rcpts.dst_instance_id);
}

static int exmdb_ext_push_copy_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->copy_instance_rcpts.b_force);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->copy_instance_rcpts.src_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->copy_instance_rcpts.dst_instance_id);
}

static int exmdb_ext_pull_empty_message_instance_attachments_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->empty_message_instance_attachments.instance_id);	
}

static int exmdb_ext_push_empty_message_instance_attachments_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->empty_message_instance_attachments.instance_id);	
}

static int exmdb_ext_pull_get_message_instance_attachments_num_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_message_instance_attachments_num.instance_id);
}

static int exmdb_ext_push_get_message_instance_attachments_num_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_attachments_num.instance_id);
}

static int exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->get_message_instance_attachment_table_all_proptags.instance_id);
}

static int exmdb_ext_push_get_message_instance_attachment_table_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_attachment_table_all_proptags.instance_id);
}

static int exmdb_ext_pull_query_message_instance_attachment_table_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->query_message_instance_attachment_table.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->query_message_instance_attachment_table.pproptags =
						common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->query_message_instance_attachment_table.pproptags) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_proptag_array(pext,
		ppayload->query_message_instance_attachment_table.pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->query_message_instance_attachment_table.start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_int32(pext,
		&ppayload->query_message_instance_attachment_table.row_needed);
}

static int exmdb_ext_push_query_message_instance_attachment_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->query_message_instance_attachment_table.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext,
		ppayload->query_message_instance_attachment_table.pproptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->query_message_instance_attachment_table.start_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_int32(pext,
		ppayload->query_message_instance_attachment_table.row_needed);
}

static int exmdb_ext_pull_copy_instance_attachments_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_instance_attachments.b_force);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->copy_instance_attachments.src_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->copy_instance_attachments.dst_instance_id);
}

static int exmdb_ext_push_copy_instance_attachments_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->copy_instance_attachments.b_force);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->copy_instance_attachments.src_instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->copy_instance_attachments.dst_instance_id);
}

static int exmdb_ext_pull_set_message_instance_conflict_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->set_message_instance_conflict.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->set_message_instance_conflict.pmsgctnt =
			common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == ppayload->set_message_instance_conflict.pmsgctnt) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_message_content(pext,
		ppayload->set_message_instance_conflict.pmsgctnt);
}

static int exmdb_ext_push_set_message_instance_conflict_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->set_message_instance_conflict.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_message_content(pext,
		ppayload->set_message_instance_conflict.pmsgctnt);
}

static int exmdb_ext_pull_get_message_rcpts_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_message_rcpts.message_id);
}

static int exmdb_ext_push_get_message_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_rcpts.message_id);
}

static int exmdb_ext_pull_get_message_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->get_message_properties.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->get_message_properties.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_message_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_message_properties.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_message_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->get_message_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->get_message_properties.pproptags);
}

static int exmdb_ext_push_get_message_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->get_message_properties.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->get_message_properties.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->get_message_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->get_message_properties.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_message_properties.pproptags);
}

static int exmdb_ext_pull_set_message_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->set_message_properties.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->set_message_properties.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->set_message_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_message_properties.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->set_message_properties.pproperties =
		common_util_alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->set_message_properties.pproperties) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_tpropval_array(pext,
		ppayload->set_message_properties.pproperties);
}

static int exmdb_ext_push_set_message_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->set_message_properties.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->set_message_properties.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->set_message_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->set_message_properties.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_message_properties.pproperties);
}

static int exmdb_ext_pull_set_message_read_state_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->set_message_read_state.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->set_message_read_state.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_message_read_state.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext,
		&ppayload->set_message_read_state.mark_as_read);
}

static int exmdb_ext_push_set_message_read_state_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->set_message_read_state.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->set_message_read_state.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->set_message_read_state.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->set_message_read_state.mark_as_read);
}

static int exmdb_ext_pull_remove_message_properties_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->remove_message_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->remove_message_properties.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->remove_message_properties.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->remove_message_properties.pproptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->remove_message_properties.pproptags);
}

static int exmdb_ext_push_remove_message_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->remove_message_properties.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->remove_message_properties.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_message_properties.pproptags);
}

static int exmdb_ext_pull_allocate_message_id_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->allocate_message_id.folder_id);
}

static int exmdb_ext_push_allocate_message_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->allocate_message_id.folder_id);
}

static int exmdb_ext_pull_get_message_group_id_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_message_group_id.message_id);
}

static int exmdb_ext_push_get_message_group_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_group_id.message_id);
}

static int exmdb_ext_pull_set_message_group_id_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_message_group_id.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->set_message_group_id.group_id);
}

static int exmdb_ext_push_set_message_group_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->set_message_group_id.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->set_message_group_id.group_id);
}

static int exmdb_ext_pull_save_change_indices_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->save_change_indices.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->save_change_indices.cn);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->save_change_indices.pindices =
		common_util_alloc(sizeof(INDEX_ARRAY));
	if (NULL == ppayload->save_change_indices.pindices) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_proptag_array(pext,
		ppayload->save_change_indices.pindices);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->save_change_indices.pungroup_proptags =
			common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->save_change_indices.pungroup_proptags) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_proptag_array(pext,
		ppayload->save_change_indices.pungroup_proptags);
}

static int exmdb_ext_push_save_change_indices_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->save_change_indices.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->save_change_indices.cn);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext,
		ppayload->save_change_indices.pindices);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		ppayload->save_change_indices.pungroup_proptags);
}

static int exmdb_ext_pull_get_change_indices_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_change_indices.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_change_indices.cn);
}

static int exmdb_ext_push_get_change_indices_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->get_change_indices.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->get_change_indices.cn);
}

static int exmdb_ext_pull_mark_modified_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->mark_modified.message_id);
}

static int exmdb_ext_push_mark_modified_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->mark_modified.message_id);
}

static int exmdb_ext_pull_try_mark_submit_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->try_mark_submit.message_id);
}

static int exmdb_ext_push_try_mark_submit_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->try_mark_submit.message_id);
}

static int exmdb_ext_pull_clear_submit_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->clear_submit.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->clear_submit.b_unsent);
}

static int exmdb_ext_push_clear_submit_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->clear_submit.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->clear_submit.b_unsent);
}

static int exmdb_ext_pull_link_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->link_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->link_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->link_message.message_id);
}

static int exmdb_ext_push_link_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->link_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->link_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->link_message.message_id);
}

static int exmdb_ext_pull_unlink_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->unlink_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->unlink_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->unlink_message.message_id);
}

static int exmdb_ext_push_unlink_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->unlink_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->unlink_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->unlink_message.message_id);
}

static int exmdb_ext_pull_rule_new_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	if (0 == tmp_byte) {
		ppayload->rule_new_message.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->rule_new_message.username);
		if (EXT_ERR_SUCCESS != status) {
			return EXT_ERR_SUCCESS;
		}
	}
	status = ext_buffer_pull_string(pext,
		&ppayload->rule_new_message.account);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->rule_new_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->rule_new_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->rule_new_message.message_id);
}

static int exmdb_ext_push_rule_new_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->rule_new_message.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return EXT_ERR_SUCCESS;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return EXT_ERR_SUCCESS;
		}
		status = ext_buffer_push_string(pext,
			ppayload->rule_new_message.username);
		if (EXT_ERR_SUCCESS != status) {
			return EXT_ERR_SUCCESS;
		}
	}
	status = ext_buffer_push_string(pext,
		ppayload->rule_new_message.account);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->rule_new_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->rule_new_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->rule_new_message.message_id);
}

static int exmdb_ext_pull_set_message_timer_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->set_message_timer.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->set_message_timer.timer_id);
}

static int exmdb_ext_push_set_message_timer_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->set_message_timer.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->set_message_timer.timer_id);
}

static int exmdb_ext_pull_get_message_timer_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_message_timer.message_id);
}

static int exmdb_ext_push_get_message_timer_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_timer.message_id);
}

static int exmdb_ext_pull_empty_folder_permission_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->empty_folder_permission.folder_id);
}

static int exmdb_ext_push_empty_folder_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->empty_folder_permission.folder_id);
}

static int exmdb_ext_pull_update_folder_permission_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->update_folder_permission.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->update_folder_permission.b_freebusy);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext,
		&ppayload->update_folder_permission.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == ppayload->update_folder_permission.count) {
		ppayload->update_folder_permission.prow = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->update_folder_permission.prow = common_util_alloc(
			sizeof(PERMISSION_DATA)*ppayload->update_folder_permission.count);
		if (NULL == ppayload->update_folder_permission.prow) {
			return EXT_ERR_ALLOC;
		}
		for (i=0; i<ppayload->update_folder_permission.count; i++) {
			status = ext_buffer_pull_permission_data(pext,
				ppayload->update_folder_permission.prow + i);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return EXT_ERR_SUCCESS;
	}
}

static int exmdb_ext_push_update_folder_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->update_folder_permission.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bool(pext,
		ppayload->update_folder_permission.b_freebusy);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext,
		ppayload->update_folder_permission.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<ppayload->update_folder_permission.count; i++) {
		status = ext_buffer_push_permission_data(pext,
			ppayload->update_folder_permission.prow + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_pull_empty_folder_rule_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->empty_folder_rule.folder_id);
}

static int exmdb_ext_push_empty_folder_rule_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->empty_folder_rule.folder_id);
}

static int exmdb_ext_pull_update_folder_rule_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->update_folder_rule.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext,
		&ppayload->update_folder_rule.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == ppayload->update_folder_rule.count) {
		ppayload->update_folder_rule.prow = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->update_folder_rule.prow = common_util_alloc(
			sizeof(RULE_DATA)*ppayload->update_folder_rule.count);
		if (NULL == ppayload->update_folder_rule.prow) {
			return EXT_ERR_ALLOC;
		}
		for (i=0; i<ppayload->update_folder_rule.count; i++) {
			status = ext_buffer_pull_rule_data(pext,
				ppayload->update_folder_rule.prow + i);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return EXT_ERR_SUCCESS;
	}
}

static int exmdb_ext_push_update_folder_rule_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->update_folder_rule.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext,
		ppayload->update_folder_rule.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<ppayload->update_folder_rule.count; i++) {
		status = ext_buffer_push_rule_data(pext,
			ppayload->update_folder_rule.prow + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_pull_delivery_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_string(pext,
		&ppayload->delivery_message.from_address);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_string(pext,
		&ppayload->delivery_message.account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->delivery_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->delivery_message.pmsg =
		common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == ppayload->delivery_message.pmsg) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_message_content(
		pext, ppayload->delivery_message.pmsg);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext,
		&ppayload->delivery_message.pdigest);
}

static int exmdb_ext_push_delivery_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_string(pext,
		ppayload->delivery_message.from_address);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext,
		ppayload->delivery_message.account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->delivery_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_message_content(
		pext, ppayload->delivery_message.pmsg);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext,
		ppayload->delivery_message.pdigest);
}

static int exmdb_ext_pull_write_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_string(pext,
		&ppayload->write_message.account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->write_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->write_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->write_message.pmsgctnt =
		common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == ppayload->write_message.pmsgctnt) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_message_content(pext,
		ppayload->write_message.pmsgctnt);
}

static int exmdb_ext_push_write_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_string(pext,
		ppayload->write_message.account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->write_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->write_message.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_message_content(pext,
		ppayload->write_message.pmsgctnt);
}
	
static int exmdb_ext_pull_read_message_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->read_message.username = NULL;
	} else {
		status = ext_buffer_pull_string(pext,
			&ppayload->read_message.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_uint32(pext, &ppayload->read_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext, &ppayload->read_message.message_id);
}

static int exmdb_ext_push_read_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->read_message.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->read_message.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint32(pext, ppayload->read_message.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext, ppayload->read_message.message_id);
}

static int exmdb_ext_pull_get_content_sync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	BINARY tmp_bin;
	uint8_t tmp_byte;
	
	memset(&ppayload->get_content_sync,
		0, sizeof(REQ_GET_CONTENT_SYNC));
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_content_sync.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != tmp_byte) {
		status = ext_buffer_pull_string(pext,
			&ppayload->get_content_sync.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_exbinary(pext, &tmp_bin);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_content_sync.pgiven =
		idset_init(FALSE, REPL_TYPE_ID);
	if (NULL == ppayload->get_content_sync.pgiven) {
		return EXT_ERR_ALLOC;
	}
	if (FALSE == idset_deserialize(
		ppayload->get_content_sync.pgiven, &tmp_bin)) {
		idset_free(ppayload->get_content_sync.pgiven);
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		goto PULL_CONTENT_SYNC_FAILURE;
	}
	if (0 != tmp_byte) {
		status = ext_buffer_pull_exbinary(pext, &tmp_bin);
		if (EXT_ERR_SUCCESS != status) {
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		ppayload->get_content_sync.pseen =
			idset_init(FALSE, REPL_TYPE_ID);
		if (NULL == ppayload->get_content_sync.pseen) {
			status = EXT_ERR_ALLOC;
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		if (FALSE == idset_deserialize(
			ppayload->get_content_sync.pseen, &tmp_bin)) {
			status = EXT_ERR_FORMAT;
			goto PULL_CONTENT_SYNC_FAILURE;	
		}
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		goto PULL_CONTENT_SYNC_FAILURE;
	}
	if (0 != tmp_byte) {
		status = ext_buffer_pull_exbinary(pext, &tmp_bin);
		if (EXT_ERR_SUCCESS != status) {
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		ppayload->get_content_sync.pseen_fai =
			idset_init(FALSE, REPL_TYPE_ID);
		if (NULL == ppayload->get_content_sync.pseen_fai) {
			status = EXT_ERR_ALLOC;
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		if (FALSE == idset_deserialize(
			ppayload->get_content_sync.pseen_fai, &tmp_bin)) {
			status = EXT_ERR_FORMAT;
			goto PULL_CONTENT_SYNC_FAILURE;	
		}
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		goto PULL_CONTENT_SYNC_FAILURE;
	}
	if (0 != tmp_byte) {
		status = ext_buffer_pull_exbinary(pext, &tmp_bin);
		if (EXT_ERR_SUCCESS != status) {
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		ppayload->get_content_sync.pread =
			idset_init(FALSE, REPL_TYPE_ID);
		if (NULL == ppayload->get_content_sync.pread) {
			status = EXT_ERR_ALLOC;
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		if (FALSE == idset_deserialize(
			ppayload->get_content_sync.pread, &tmp_bin)) {
			status = EXT_ERR_FORMAT;
			goto PULL_CONTENT_SYNC_FAILURE;	
		}
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_content_sync.cpid);
	if (EXT_ERR_SUCCESS != status) {
		goto PULL_CONTENT_SYNC_FAILURE;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		goto PULL_CONTENT_SYNC_FAILURE;
	}
	if (0 != tmp_byte) {
		ppayload->get_content_sync.prestriction =
			common_util_alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->get_content_sync.prestriction) {
			status = EXT_ERR_ALLOC;
			goto PULL_CONTENT_SYNC_FAILURE;
		}
		status = ext_buffer_pull_restriction(pext,
			ppayload->get_content_sync.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			goto PULL_CONTENT_SYNC_FAILURE;
		}
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->get_content_sync.b_ordered);
	if (EXT_ERR_SUCCESS != status) {
		goto PULL_CONTENT_SYNC_FAILURE;
	}
	return EXT_ERR_SUCCESS;
	
PULL_CONTENT_SYNC_FAILURE:
	idset_free(ppayload->get_content_sync.pgiven);
	if (NULL != ppayload->get_content_sync.pseen) {
		idset_free(ppayload->get_content_sync.pseen);
	}
	if (NULL != ppayload->get_content_sync.pseen_fai) {
		idset_free(ppayload->get_content_sync.pseen_fai);
	}
	if (NULL != ppayload->get_content_sync.pread) {
		idset_free(ppayload->get_content_sync.pread);
	}
	return status;
}

static int exmdb_ext_push_get_content_sync_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	BINARY *pbin;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->get_content_sync.folder_id);
	if (EXT_ERR_SUCCESS) {
		return status;
	}
	if (NULL == ppayload->get_content_sync.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->get_content_sync.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	pbin = idset_serialize_replid(
		ppayload->get_content_sync.pgiven);
	if (NULL == pbin) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_exbinary(pext, pbin);
	if (EXT_ERR_SUCCESS != status) {
		rop_util_free_binary(pbin);
		return status;
	}
	rop_util_free_binary(pbin);
	if (NULL == ppayload->get_content_sync.pseen) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pbin = idset_serialize_replid(
			ppayload->get_content_sync.pseen);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	if (NULL == ppayload->get_content_sync.pseen_fai) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pbin = idset_serialize_replid(
			ppayload->get_content_sync.pseen_fai);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	if (NULL == ppayload->get_content_sync.pread) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pbin = idset_serialize_replid(
			ppayload->get_content_sync.pread);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->get_content_sync.cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->get_content_sync.prestriction) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_restriction(pext,
			ppayload->get_content_sync.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_push_bool(pext,
		ppayload->get_content_sync.b_ordered);
}

static int exmdb_ext_pull_get_hierarchy_sync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	BINARY tmp_bin;
	uint8_t tmp_byte;
	
	memset(&ppayload->get_hierarchy_sync,
		0, sizeof(REQ_GET_HIERARCHY_SYNC));
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_hierarchy_sync.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != tmp_byte) {
		status = ext_buffer_pull_string(pext,
			&ppayload->get_hierarchy_sync.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_pull_exbinary(pext, &tmp_bin);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	ppayload->get_hierarchy_sync.pgiven =
		idset_init(FALSE, REPL_TYPE_ID);
	if (NULL == ppayload->get_hierarchy_sync.pgiven) {
		return EXT_ERR_ALLOC;
	}
	if (FALSE == idset_deserialize(
		ppayload->get_hierarchy_sync.pgiven, &tmp_bin)) {
		idset_free(ppayload->get_hierarchy_sync.pgiven);
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		idset_free(ppayload->get_hierarchy_sync.pgiven);
		return status;
	}
	if (0 != tmp_byte) {
		status = ext_buffer_pull_exbinary(pext, &tmp_bin);
		if (EXT_ERR_SUCCESS != status) {
			idset_free(ppayload->get_hierarchy_sync.pgiven);
			return status;
		}
		ppayload->get_hierarchy_sync.pseen =
			idset_init(FALSE, REPL_TYPE_ID);
		if (NULL == ppayload->get_hierarchy_sync.pseen) {
			idset_free(ppayload->get_hierarchy_sync.pgiven);
			return EXT_ERR_ALLOC;
		}
		if (FALSE == idset_deserialize(
			ppayload->get_hierarchy_sync.pseen, &tmp_bin)) {
			idset_free(ppayload->get_hierarchy_sync.pseen);
			idset_free(ppayload->get_hierarchy_sync.pgiven);
			return EXT_ERR_FORMAT;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_push_get_hierarchy_sync_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	BINARY *pbin;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->get_hierarchy_sync.folder_id);
	if (EXT_ERR_SUCCESS) {
		return status;
	}
	if (NULL == ppayload->get_hierarchy_sync.username) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_string(pext,
			ppayload->get_hierarchy_sync.username);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	pbin = idset_serialize_replid(
		ppayload->get_hierarchy_sync.pgiven);
	if (NULL == pbin) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_exbinary(pext, pbin);
	if (EXT_ERR_SUCCESS != status) {
		rop_util_free_binary(pbin);
		return status;
	}
	rop_util_free_binary(pbin);
	if (NULL == ppayload->get_hierarchy_sync.pseen) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pbin = idset_serialize_replid(
			ppayload->get_hierarchy_sync.pseen);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_pull_allocate_ids_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->allocate_ids.count);
}

static int exmdb_ext_push_allocate_ids_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->allocate_ids.count);
}

static int exmdb_ext_pull_subscribe_notification_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext,
		&ppayload->subscribe_notification.notificaton_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_bool(pext,
		&ppayload->subscribe_notification.b_whole);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->subscribe_notification.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->subscribe_notification.message_id);
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

static int exmdb_ext_pull_unsubscribe_notification_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->unsubscribe_notification.sub_id);
}

static int exmdb_ext_push_unsubscribe_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unsubscribe_notification.sub_id);
}

static int exmdb_ext_pull_transport_new_mail_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->transport_new_mail.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->transport_new_mail.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->transport_new_mail.message_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext,
		&ppayload->transport_new_mail.pstr_class);
}

static int exmdb_ext_push_transport_new_mail_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->transport_new_mail.folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->transport_new_mail.message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->transport_new_mail.message_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext,
		ppayload->transport_new_mail.pstr_class);
}

static int exmdb_ext_pull_check_contact_address_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_pull_string(pext,
		&ppayload->check_contact_address.paddress);
}

static int exmdb_ext_push_check_contact_address_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
		ppayload->check_contact_address.paddress);
}

int exmdb_ext_pull_request(const BINARY *pbin_in,
	EXMDB_REQUEST *prequest)
{
	int status;
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
	status = ext_buffer_pull_uint8(&ext_pull, &prequest->call_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (CALL_ID_CONNECT == prequest->call_id) {
		return exmdb_ext_pull_connect_request(
				&ext_pull, &prequest->payload);
	} else if (CALL_ID_LISTEN_NOTIFICATION == prequest->call_id) {
		return exmdb_ext_pull_listen_notification_request(
							&ext_pull, &prequest->payload);
	}
	status = ext_buffer_pull_string(&ext_pull, &prequest->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (prequest->call_id) {
	case CALL_ID_PING_STORE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_ALL_NAMED_PROPIDS:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_NAMED_PROPIDS:
		return exmdb_ext_pull_get_named_propids_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_NAMED_PROPNAMES:
		return exmdb_ext_pull_get_named_propnames_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_MAPPING_GUID:
		return exmdb_ext_pull_get_mapping_guid_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GET_MAPPING_REPLID:
		return exmdb_ext_pull_get_mapping_replid_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_STORE_ALL_PROPTAGS:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_STORE_PROPERTIES:
		return exmdb_ext_pull_get_store_properties_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SET_STORE_PROPERTIES:
		return exmdb_ext_pull_set_store_properties_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_REMOVE_STORE_PROPERTIES:
		return exmdb_ext_pull_remove_store_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_MAILBOX_PERMISSION:
		return exmdb_ext_pull_check_mailbox_permission_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_GET_FOLDER_BY_CLASS:
		return exmdb_ext_pull_get_folder_by_class_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SET_FOLDER_BY_CLASS:
		return exmdb_ext_pull_set_folder_by_class_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_FOLDER_CLASS_TABLE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_CHECK_FOLDER_ID:
		return exmdb_ext_pull_check_folder_id_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_QUERY_FOLDER_MESSAGES:
		return exmdb_ext_pull_query_folder_messages_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_FOLDER_DELETED:
		return exmdb_ext_pull_check_folder_deleted_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_FOLDER_BY_NAME:
		return exmdb_ext_pull_get_folder_by_name_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_FOLDER_PERMISSION:
		return exmdb_ext_pull_check_folder_permission_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_CREATE_FOLDER_BY_PROPERTIES:
		return exmdb_ext_pull_create_folder_by_properties_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_GET_FOLDER_ALL_PROPTAGS:
		return exmdb_ext_pull_get_folder_all_proptags_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_GET_FOLDER_PROPERTIES:
		return exmdb_ext_pull_get_folder_properties_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SET_FOLDER_PROPERTIES:
		return exmdb_ext_pull_set_folder_properties_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_REMOVE_FOLDER_PROPERTIES:
		return exmdb_ext_pull_remove_folder_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_DELETE_FOLDER:
		return exmdb_ext_pull_delete_folder_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_EMPTY_FOLDER:
		return exmdb_ext_pull_empty_folder_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_FOLDER_CYCLE:
		return exmdb_ext_pull_check_folder_cycle_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_COPY_FOLDER_INTERNAL:
		return exmdb_ext_pull_copy_folder_internal_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_SEARCH_CRITERIA:
		return exmdb_ext_pull_get_search_criteria_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SET_SEARCH_CRITERIA:
		return exmdb_ext_pull_set_search_criteria_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_MOVECOPY_MESSAGE:
		return exmdb_ext_pull_movecopy_message_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_MOVECOPY_MESSAGES:
		return exmdb_ext_pull_movecopy_messages_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_MOVECOPY_FOLDER:
		return exmdb_ext_pull_movecopy_folder_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_DELETE_MESSAGES:
		return exmdb_ext_pull_delete_messages_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_BRIEF:
		return exmdb_ext_pull_get_message_brief_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SUM_HIERARCHY:
		return exmdb_ext_pull_sum_hierarchy_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_HIERARCHY_TABLE:
		return exmdb_ext_pull_load_hierarchy_table_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SUM_CONTENT:
		return exmdb_ext_pull_sum_content_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_CONTENT_TABLE:
		return exmdb_ext_pull_load_content_table_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_RELOAD_CONTENT_TABLE:
		return exmdb_ext_pull_reload_content_table_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_PERMISSION_TABLE:
		return exmdb_ext_pull_load_permission_table_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_RULE_TABLE:
		return exmdb_ext_pull_load_rule_table_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_UNLOAD_TABLE:
		return exmdb_ext_pull_unload_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_SUM_TABLE:
		return exmdb_ext_pull_sum_table_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_QUERY_TABLE:
		return exmdb_ext_pull_query_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_MATCH_TABLE:
		return exmdb_ext_pull_match_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_LOCATE_TABLE:
		return exmdb_ext_pull_locate_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_READ_TABLE_ROW:
		return exmdb_ext_pull_read_table_row_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_MARK_TABLE:
		return exmdb_ext_pull_mark_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GET_TABLE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_table_all_proptags_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_EXPAND_TABLE:
		return exmdb_ext_pull_expand_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_COLLAPSE_TABLE:
		return exmdb_ext_pull_collapse_table_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_STORE_TABLE_STATE:
		return exmdb_ext_pull_store_table_state_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_RESTORE_TABLE_STATE:
		return exmdb_ext_pull_restore_table_state_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_MESSAGE:
		return exmdb_ext_pull_check_message_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_MESSAGE_DELETED:
		return exmdb_ext_pull_check_message_deleted_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_MESSAGE_INSTANCE:
		return exmdb_ext_pull_load_message_instance_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_EMBEDDED_INSTANCE:
		return exmdb_ext_pull_load_embedded_instance_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_GET_EMBEDED_CN:
		return exmdb_ext_pull_get_embeded_cn_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_RELOAD_MESSAGE_INSTANCE:
		return exmdb_ext_pull_reload_message_instance_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_CLEAR_MESSAGE_INSTANCE:
		return exmdb_ext_pull_clear_message_instance_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_READ_MESSAGE_INSTANCE:
		return exmdb_ext_pull_read_message_instance_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_WRITE_MESSAGE_INSTANCE:
		return exmdb_ext_pull_write_message_instance_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_LOAD_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_load_attachment_instance_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_CREATE_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_create_attachment_instance_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_READ_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_read_attachment_instance_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_WRITE_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_write_attachment_instance_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		return exmdb_ext_pull_delete_message_instance_attachment_request(
											&ext_pull, &prequest->payload);
	case CALL_ID_FLUSH_INSTANCE:
		return exmdb_ext_pull_flush_instance_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_UNLOAD_INSTANCE:
		return exmdb_ext_pull_unload_instance_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GET_INSTANCE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_instance_all_proptags_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_GET_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_get_instance_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_SET_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_set_instance_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_REMOVE_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_remove_instance_properties_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_INSTANCE_CYCLE:
		return exmdb_ext_pull_check_instance_cycle_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_RCPTS:
		return exmdb_ext_pull_empty_message_instance_rcpts_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_NUM:
		return exmdb_ext_pull_get_message_instance_rcpts_num_request(
										&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		return exmdb_ext_pull_get_message_instance_rcpts_all_proptags_request(
												&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS:
		return exmdb_ext_pull_get_message_instance_rcpts_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_UPDATE_MESSAGE_INSTANCE_RCPTS:
		return exmdb_ext_pull_update_message_instance_rcpts_request(
									&ext_pull, &prequest->payload);
	case CALL_ID_COPY_INSTANCE_RCPTS:
		return exmdb_ext_pull_copy_instance_rcpts_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		return exmdb_ext_pull_empty_message_instance_attachments_request(
											&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		return exmdb_ext_pull_get_message_instance_attachments_num_request(
											&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_request(
															&ext_pull, &prequest->payload);
	case CALL_ID_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		return exmdb_ext_pull_query_message_instance_attachment_table_request(
												&ext_pull, &prequest->payload);
	case CALL_ID_COPY_INSTANCE_ATTACHMENTS:
		return exmdb_ext_pull_copy_instance_attachments_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_SET_MESSAGE_INSTANCE_CONFLICT:
		return exmdb_ext_pull_set_message_instance_conflict_request(
										&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_RCPTS:
		return exmdb_ext_pull_get_message_rcpts_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_get_message_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_SET_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_set_message_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_SET_MESSAGE_READ_STATE:
		return exmdb_ext_pull_set_message_read_state_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_REMOVE_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_remove_message_properties_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_ALLOCATE_MESSAGE_ID:
		return exmdb_ext_pull_allocate_message_id_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_ALLOCATE_CN:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_MESSAGE_GROUP_ID:
		return exmdb_ext_pull_get_message_group_id_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SET_MESSAGE_GROUP_ID:
		return exmdb_ext_pull_set_message_group_id_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SAVE_CHANGE_INDICES:
		return exmdb_ext_pull_save_change_indices_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_GET_CHANGE_INDICES:
		return exmdb_ext_pull_get_change_indices_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_MARK_MODIFIED:
		return exmdb_ext_pull_mark_modified_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_TRY_MARK_SUBMIT:
		return exmdb_ext_pull_try_mark_submit_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_CLEAR_SUBMIT:
		return exmdb_ext_pull_clear_submit_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_LINK_MESSAGE:
		return exmdb_ext_pull_link_message_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_UNLINK_MESSAGE:
		return exmdb_ext_pull_unlink_message_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_RULE_NEW_MESSAGE:
		return exmdb_ext_pull_rule_new_message_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_SET_MESSAGE_TIMER:
		return exmdb_ext_pull_set_message_timer_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GET_MESSAGE_TIMER:
		return exmdb_ext_pull_get_message_timer_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_EMPTY_FOLDER_PERMISSION:
		return exmdb_ext_pull_empty_folder_permission_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_UPDATE_FOLDER_PERMISSION:
		return exmdb_ext_pull_update_folder_permission_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_EMPTY_FOLDER_RULE:
		return exmdb_ext_pull_empty_folder_rule_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_UPDATE_FOLDER_RULE:
		return exmdb_ext_pull_update_folder_rule_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_DELIVERY_MESSAGE:
		return exmdb_ext_pull_delivery_message_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_WRITE_MESSAGE:
		return exmdb_ext_pull_write_message_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_READ_MESSAGE:
		return exmdb_ext_pull_read_message_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GET_CONTENT_SYNC:
		return exmdb_ext_pull_get_content_sync_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GET_HIERARCHY_SYNC:
		return exmdb_ext_pull_get_hierarchy_sync_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_ALLOCATE_IDS:
		return exmdb_ext_pull_allocate_ids_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		return exmdb_ext_pull_subscribe_notification_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		return exmdb_ext_pull_unsubscribe_notification_request(
								&ext_pull, &prequest->payload);
	case CALL_ID_TRANSPORT_NEW_MAIL:
		return exmdb_ext_pull_transport_new_mail_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_CHECK_CONTACT_ADDRESS:
		return exmdb_ext_pull_check_contact_address_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_UNLOAD_STORE:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
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
	case CALL_ID_GET_ALL_NAMED_PROPIDS:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_NAMED_PROPIDS:
		status = exmdb_ext_push_get_named_propids_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_NAMED_PROPNAMES:
		status = exmdb_ext_push_get_named_propnames_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MAPPING_GUID:
		status = exmdb_ext_push_get_mapping_guid_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MAPPING_REPLID:
		status = exmdb_ext_push_get_mapping_replid_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_STORE_ALL_PROPTAGS:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_STORE_PROPERTIES:
		status = exmdb_ext_push_get_store_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_STORE_PROPERTIES:
		status = exmdb_ext_push_set_store_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_REMOVE_STORE_PROPERTIES:
		status = exmdb_ext_push_remove_store_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_MAILBOX_PERMISSION:
		status = exmdb_ext_push_check_mailbox_permission_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_FOLDER_BY_CLASS:
		status = exmdb_ext_push_get_folder_by_class_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_FOLDER_BY_CLASS:
		status = exmdb_ext_push_set_folder_by_class_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_FOLDER_CLASS_TABLE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_CHECK_FOLDER_ID:
		status = exmdb_ext_push_check_folder_id_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_QUERY_FOLDER_MESSAGES:
		status = exmdb_ext_push_query_folder_messages_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_FOLDER_DELETED:
		status = exmdb_ext_push_check_folder_deleted_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_FOLDER_BY_NAME:
		status = exmdb_ext_push_get_folder_by_name_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_FOLDER_PERMISSION:
		status = exmdb_ext_push_check_folder_permission_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_CREATE_FOLDER_BY_PROPERTIES:
		status = exmdb_ext_push_create_folder_by_properties_request(
										&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_FOLDER_ALL_PROPTAGS:
		status = exmdb_ext_push_get_folder_all_proptags_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_FOLDER_PROPERTIES:
		status = exmdb_ext_push_get_folder_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_FOLDER_PROPERTIES:
		status = exmdb_ext_push_set_folder_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_REMOVE_FOLDER_PROPERTIES:
		status = exmdb_ext_push_remove_folder_properties_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_DELETE_FOLDER:
		status = exmdb_ext_push_delete_folder_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_EMPTY_FOLDER:
		status = exmdb_ext_push_empty_folder_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_FOLDER_CYCLE:
		status = exmdb_ext_push_check_folder_cycle_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_COPY_FOLDER_INTERNAL:
		status = exmdb_ext_push_copy_folder_internal_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_SEARCH_CRITERIA:
		status = exmdb_ext_push_get_search_criteria_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_SEARCH_CRITERIA:
		status = exmdb_ext_push_set_search_criteria_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_MOVECOPY_MESSAGE:
		status = exmdb_ext_push_movecopy_message_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_MOVECOPY_MESSAGES:
		status = exmdb_ext_push_movecopy_messages_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_MOVECOPY_FOLDER:
		status = exmdb_ext_push_movecopy_folder_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_DELETE_MESSAGES:
		status = exmdb_ext_push_delete_messages_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_BRIEF:
		status = exmdb_ext_push_get_message_brief_request(
							&ext_push,  &prequest->payload);
		break;
	case CALL_ID_SUM_HIERARCHY:
		status = exmdb_ext_push_sum_hierarchy_request(
						&ext_push,  &prequest->payload);
		break;
	case CALL_ID_LOAD_HIERARCHY_TABLE:
		status = exmdb_ext_push_load_hierarchy_table_request(
							&ext_push,  &prequest->payload);
		break;
	case CALL_ID_SUM_CONTENT:
		status = exmdb_ext_push_sum_content_request(
					&ext_push,  &prequest->payload);
		break;
	case CALL_ID_LOAD_CONTENT_TABLE:
		status = exmdb_ext_push_load_content_table_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_RELOAD_CONTENT_TABLE:
		status = exmdb_ext_push_reload_content_table_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_LOAD_PERMISSION_TABLE:
		status = exmdb_ext_push_load_permission_table_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_LOAD_RULE_TABLE:
		status = exmdb_ext_push_load_rule_table_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_UNLOAD_TABLE:
		status = exmdb_ext_push_unload_table_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_SUM_TABLE:
		status = exmdb_ext_push_sum_table_request(
					&ext_push, &prequest->payload);
		break;
	case CALL_ID_QUERY_TABLE:
		status = exmdb_ext_push_query_table_request(
					&ext_push, &prequest->payload);
		break;
	case CALL_ID_MATCH_TABLE:
		status = exmdb_ext_push_match_table_request(
					&ext_push, &prequest->payload);
		break;
	case CALL_ID_LOCATE_TABLE:
		status = exmdb_ext_push_locate_table_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_READ_TABLE_ROW:
		status = exmdb_ext_push_read_table_row_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_MARK_TABLE:
		status = exmdb_ext_push_mark_table_request(
					&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_TABLE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_table_all_proptags_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_EXPAND_TABLE:
		status = exmdb_ext_push_expand_table_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_COLLAPSE_TABLE:
		status = exmdb_ext_push_collapse_table_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_STORE_TABLE_STATE:
		status = exmdb_ext_push_store_table_state_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_RESTORE_TABLE_STATE:
		status = exmdb_ext_push_restore_table_state_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_MESSAGE:
		status = exmdb_ext_push_check_message_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_MESSAGE_DELETED:
		status = exmdb_ext_push_check_message_deleted_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_LOAD_MESSAGE_INSTANCE:
		status = exmdb_ext_push_load_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_LOAD_EMBEDDED_INSTANCE:
		status = exmdb_ext_push_load_embedded_instance_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_EMBEDED_CN:
		status = exmdb_ext_push_get_embeded_cn_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_RELOAD_MESSAGE_INSTANCE:
		status = exmdb_ext_push_reload_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_CLEAR_MESSAGE_INSTANCE:
		status = exmdb_ext_push_clear_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_READ_MESSAGE_INSTANCE:
		status = exmdb_ext_push_read_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_WRITE_MESSAGE_INSTANCE:
		status = exmdb_ext_push_write_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_LOAD_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_load_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_CREATE_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_create_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_READ_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_read_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_WRITE_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_write_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		status = exmdb_ext_push_delete_message_instance_attachment_request(
											&ext_push, &prequest->payload);
		break;
	case CALL_ID_FLUSH_INSTANCE:
		status = exmdb_ext_push_flush_instance_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_UNLOAD_INSTANCE:
		status = exmdb_ext_push_unload_instance_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_INSTANCE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_instance_all_proptags_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_get_instance_properties_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_set_instance_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_REMOVE_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_remove_instance_properties_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_INSTANCE_CYCLE:
		status = exmdb_ext_push_check_instance_cycle_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_empty_message_instance_rcpts_request(
										&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_NUM:
		status = exmdb_ext_push_get_message_instance_rcpts_num_request(
										&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		status = exmdb_ext_push_get_message_instance_rcpts_all_proptags_request(
												&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_get_message_instance_rcpts_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_UPDATE_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_update_message_instance_rcpts_request(
										&ext_push, &prequest->payload);
		break;
	case CALL_ID_COPY_INSTANCE_RCPTS:
		status = exmdb_ext_push_copy_instance_rcpts_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		status = exmdb_ext_push_empty_message_instance_attachments_request(
											&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		status = exmdb_ext_push_get_message_instance_attachments_num_request(
												&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_message_instance_attachment_table_all_proptags_request(
															&ext_push, &prequest->payload);
		break;
	case CALL_ID_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		status = exmdb_ext_push_query_message_instance_attachment_table_request(
												&ext_push, &prequest->payload);
		break;
	case CALL_ID_COPY_INSTANCE_ATTACHMENTS:
		status = exmdb_ext_push_copy_instance_attachments_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_MESSAGE_INSTANCE_CONFLICT:
		status = exmdb_ext_push_set_message_instance_conflict_request(
										&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_RCPTS:
		status = exmdb_ext_push_get_message_rcpts_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_get_message_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_set_message_properties_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_MESSAGE_READ_STATE:
		status = exmdb_ext_push_set_message_read_state_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_REMOVE_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_remove_message_properties_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_ALLOCATE_MESSAGE_ID:
		status = exmdb_ext_push_allocate_message_id_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_ALLOCATE_CN:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_MESSAGE_GROUP_ID:
		status = exmdb_ext_push_get_message_group_id_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_MESSAGE_GROUP_ID:
		status = exmdb_ext_push_set_message_group_id_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_SAVE_CHANGE_INDICES:
		status = exmdb_ext_push_save_change_indices_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_CHANGE_INDICES:
		status = exmdb_ext_push_get_change_indices_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_MARK_MODIFIED:
		status = exmdb_ext_push_mark_modified_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_TRY_MARK_SUBMIT:
		status = exmdb_ext_push_try_mark_submit_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_CLEAR_SUBMIT:
		status = exmdb_ext_push_clear_submit_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_LINK_MESSAGE:
		status = exmdb_ext_push_link_message_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_UNLINK_MESSAGE:
		status = exmdb_ext_push_unlink_message_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_RULE_NEW_MESSAGE:
		status = exmdb_ext_push_rule_new_message_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_SET_MESSAGE_TIMER:
		status = exmdb_ext_push_set_message_timer_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_MESSAGE_TIMER:
		status = exmdb_ext_push_get_message_timer_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_EMPTY_FOLDER_PERMISSION:
		status = exmdb_ext_push_empty_folder_permission_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_UPDATE_FOLDER_PERMISSION:
		status = exmdb_ext_push_update_folder_permission_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_EMPTY_FOLDER_RULE:
		status = exmdb_ext_push_empty_folder_rule_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_UPDATE_FOLDER_RULE:
		status = exmdb_ext_push_update_folder_rule_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_DELIVERY_MESSAGE:
		status = exmdb_ext_push_delivery_message_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_WRITE_MESSAGE:
		status = exmdb_ext_push_write_message_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_READ_MESSAGE:
		status = exmdb_ext_push_read_message_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_CONTENT_SYNC:
		status = exmdb_ext_push_get_content_sync_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_GET_HIERARCHY_SYNC:
		status = exmdb_ext_push_get_hierarchy_sync_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_ALLOCATE_IDS:
		status = exmdb_ext_push_allocate_ids_request(
						&ext_push, &prequest->payload);
		break;
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_subscribe_notification_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_unsubscribe_notification_request(
									&ext_push, &prequest->payload);
		break;
	case CALL_ID_TRANSPORT_NEW_MAIL:
		status = exmdb_ext_push_transport_new_mail_request(
							&ext_push, &prequest->payload);
		break;
	case CALL_ID_CHECK_CONTACT_ADDRESS:
		status = exmdb_ext_push_check_contact_address_request(
								&ext_push, &prequest->payload);
		break;
	case CALL_ID_UNLOAD_STORE:
		status = EXT_ERR_SUCCESS;
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

static int exmdb_ext_pull_get_all_named_propids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_propid_array(pext,
		&ppayload->get_all_named_propids.propids);
}

static int exmdb_ext_push_get_all_named_propids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_propid_array(pext,
		&ppayload->get_all_named_propids.propids);
}

static int exmdb_ext_pull_get_named_propids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_propid_array(pext,
		&ppayload->get_named_propids.propids);
}

static int exmdb_ext_push_get_named_propids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_propid_array(pext,
		&ppayload->get_named_propids.propids);
}

static int exmdb_ext_pull_get_named_propnames_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_propname_array(pext,
		&ppayload->get_named_propnames.propnames);
}

static int exmdb_ext_push_get_named_propnames_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_propname_array(pext,
		&ppayload->get_named_propnames.propnames);
}

static int exmdb_ext_pull_get_mapping_guid_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->get_mapping_guid.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_guid(pext,
		&ppayload->get_mapping_guid.guid);
}

static int exmdb_ext_push_get_mapping_guid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->get_mapping_guid.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_guid(pext,
		&ppayload->get_mapping_guid.guid);
}

static int exmdb_ext_pull_get_mapping_replid_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->get_mapping_replid.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_mapping_replid.replid);
}

static int exmdb_ext_push_get_mapping_replid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->get_mapping_replid.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext,
		ppayload->get_mapping_replid.replid);
}

static int exmdb_ext_pull_get_store_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_store_all_proptags.proptags);
}

static int exmdb_ext_push_get_store_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_store_all_proptags.proptags);
}

static int exmdb_ext_pull_get_store_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_store_properties.propvals);
}

static int exmdb_ext_push_get_store_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tpropval_array(pext,
		&ppayload->get_store_properties.propvals);
}

static int exmdb_ext_pull_set_store_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_store_properties.problems);
}

static int exmdb_ext_push_set_store_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_problem_array(pext,
		&ppayload->set_store_properties.problems);
}

static int exmdb_ext_pull_check_mailbox_permission_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->check_mailbox_permission.permission);
}

static int exmdb_ext_push_check_mailbox_permission_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->check_mailbox_permission.permission);
}

static int exmdb_ext_pull_get_folder_by_class_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_folder_by_class.id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext,
		&ppayload->get_folder_by_class.str_explicit);
}

static int exmdb_ext_push_get_folder_by_class_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
		ppayload->get_folder_by_class.id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext,
		ppayload->get_folder_by_class.str_explicit);
}

static int exmdb_ext_pull_set_folder_by_class_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->set_folder_by_class.b_result);
}

static int exmdb_ext_push_set_folder_by_class_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->set_folder_by_class.b_result);
}

static int exmdb_ext_pull_get_folder_class_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->get_folder_class_table.table);
}

static int exmdb_ext_push_get_folder_class_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tarray_set(pext,
		&ppayload->get_folder_class_table.table);
}

static int exmdb_ext_pull_check_folder_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_folder_id.b_exist);
}

static int exmdb_ext_push_check_folder_id_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_folder_id.b_exist);
}

static int exmdb_ext_pull_query_folder_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->query_folder_messages.set);
}

static int exmdb_ext_push_query_folder_messages_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tarray_set(pext,
		&ppayload->query_folder_messages.set);
}

static int exmdb_ext_pull_check_folder_deleted_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_folder_deleted.b_del);
}

static int exmdb_ext_push_check_folder_deleted_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_folder_deleted.b_del);
}

static int exmdb_ext_pull_get_folder_by_name_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_folder_by_name.folder_id);
}

static int exmdb_ext_push_get_folder_by_name_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_folder_by_name.folder_id);
}

static int exmdb_ext_pull_check_folder_permission_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->check_folder_permission.permission);
}

static int exmdb_ext_push_check_folder_permission_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->check_folder_permission.permission);
}

static int exmdb_ext_pull_create_folder_by_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->create_folder_by_properties.folder_id);
}

static int exmdb_ext_push_create_folder_by_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->create_folder_by_properties.folder_id);
}

static int exmdb_ext_pull_get_folder_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_folder_all_proptags.proptags);
}

static int exmdb_ext_push_get_folder_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_folder_all_proptags.proptags);
}

static int exmdb_ext_pull_get_folder_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_folder_properties.propvals);
}

static int exmdb_ext_push_get_folder_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tpropval_array(pext,
		&ppayload->get_folder_properties.propvals);
}

static int exmdb_ext_pull_set_folder_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_folder_properties.problems);
}

static int exmdb_ext_push_set_folder_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_problem_array(pext,
		&ppayload->set_folder_properties.problems);
}

static int exmdb_ext_pull_delete_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->delete_folder.b_result);
}

static int exmdb_ext_push_delete_folder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->delete_folder.b_result);
}

static int exmdb_ext_pull_empty_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->empty_folder.b_partial);
}

static int exmdb_ext_push_empty_folder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->empty_folder.b_partial);
}

static int exmdb_ext_pull_check_folder_cycle_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_folder_cycle.b_cycle);
}

static int exmdb_ext_push_check_folder_cycle_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_folder_cycle.b_cycle);
}

static int exmdb_ext_pull_copy_folder_internal_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_collid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_partial);
}

static int exmdb_ext_push_copy_folder_internal_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->copy_folder_internal.b_collid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->copy_folder_internal.b_partial);
}

static int exmdb_ext_pull_get_search_criteria_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_search_criteria.search_status);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->get_search_criteria.prestriction = NULL;
	} else {
		ppayload->get_search_criteria.prestriction =
			common_util_alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->get_search_criteria.prestriction) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_restriction(pext,
			ppayload->get_search_criteria.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_pull_longlong_array(pext,
		&ppayload->get_search_criteria.folder_ids);
}

static int exmdb_ext_push_get_search_criteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_search_criteria.search_status);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->get_search_criteria.prestriction) {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_restriction(pext,
			ppayload->get_search_criteria.prestriction);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ext_buffer_push_longlong_array(pext,
		&ppayload->get_search_criteria.folder_ids);
}

static int exmdb_ext_pull_set_search_criteria_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->set_search_criteria.b_result);
}
	
static int exmdb_ext_push_set_search_criteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->set_search_criteria.b_result);
}

static int exmdb_ext_pull_movecopy_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_message.b_result);
}

static int exmdb_ext_push_movecopy_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_message.b_result);
}

static int exmdb_ext_pull_movecopy_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_messages.b_partial);
}

static int exmdb_ext_push_movecopy_messages_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_messages.b_partial);
}

static int exmdb_ext_pull_movecopy_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->movecopy_folder.b_exist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_folder.b_partial);
}

static int exmdb_ext_push_movecopy_folder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->movecopy_folder.b_exist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_folder.b_partial);
}

static int exmdb_ext_pull_delete_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->delete_messages.b_partial);
}

static int exmdb_ext_push_delete_messages_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->delete_messages.b_partial);
}

static int exmdb_ext_pull_get_message_brief_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (0 == tmp_byte) {
		ppayload->get_message_brief.pbrief = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_message_brief.pbrief =
			common_util_alloc(sizeof(MESSAGE_CONTENT));
		if (NULL == ppayload->get_message_brief.pbrief) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_message_content(pext,
				ppayload->get_message_brief.pbrief);
	}
}

static int exmdb_ext_push_get_message_brief_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->get_message_brief.pbrief) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_message_content(pext,
				ppayload->get_message_brief.pbrief);
	}
}

static int exmdb_ext_pull_sum_hierarchy_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->sum_hierarchy.count);
}

static int exmdb_ext_push_sum_hierarchy_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->sum_hierarchy.count);
}

static int exmdb_ext_pull_load_hierarchy_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_hierarchy_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_hierarchy_table.row_count);
}

static int exmdb_ext_push_load_hierarchy_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->load_hierarchy_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->load_hierarchy_table.row_count);
}

static int exmdb_ext_pull_sum_content_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->sum_content.count);
}

static int exmdb_ext_push_sum_content_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->sum_content.count);
}

static int exmdb_ext_pull_load_content_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_content_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_content_table.row_count);
}

static int exmdb_ext_push_load_content_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->load_content_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->load_content_table.row_count);
}

static int exmdb_ext_pull_load_permission_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_permission_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_permission_table.row_count);
}

static int exmdb_ext_push_load_permission_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->load_permission_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->load_permission_table.row_count);
}

static int exmdb_ext_pull_load_rule_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->load_rule_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_rule_table.row_count);
}

static int exmdb_ext_push_load_rule_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->load_rule_table.table_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->load_rule_table.row_count);
}

static int exmdb_ext_pull_sum_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
			&ppayload->sum_table.rows);
}

static int exmdb_ext_push_sum_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
			ppayload->sum_table.rows);
}

static int exmdb_ext_pull_query_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(
		pext, &ppayload->query_table.set);
}

static int exmdb_ext_push_query_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tarray_set(
		pext, &ppayload->query_table.set);
}

static int exmdb_ext_pull_match_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_int32(pext,
		&ppayload->match_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tpropval_array(pext,
			&ppayload->match_table.propvals);	
}

static int exmdb_ext_push_match_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_int32(pext,
		ppayload->match_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_tpropval_array(pext,
			&ppayload->match_table.propvals);	
}

static int exmdb_ext_pull_locate_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_int32(pext,
		&ppayload->locate_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->locate_table.row_type);
}

static int exmdb_ext_push_locate_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_int32(pext,
		ppayload->locate_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->locate_table.row_type);
}

static int exmdb_ext_pull_read_table_row_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->read_table_row.propvals);
}

static int exmdb_ext_push_read_table_row_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tpropval_array(pext,
		&ppayload->read_table_row.propvals);
}

static int exmdb_ext_pull_mark_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext,
			&ppayload->mark_table.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->mark_table.inst_num);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->mark_table.row_type);
}

static int exmdb_ext_push_mark_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint64(pext,
			ppayload->mark_table.inst_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->mark_table.inst_num);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->mark_table.row_type);
}

static int exmdb_ext_pull_get_table_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_table_all_proptags.proptags);
}

static int exmdb_ext_push_get_table_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_table_all_proptags.proptags);
}

static int exmdb_ext_pull_expand_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->expand_table.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext,
		&ppayload->expand_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->expand_table.row_count);
}

static int exmdb_ext_push_expand_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->expand_table.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext,
		ppayload->expand_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->expand_table.row_count);
}

static int exmdb_ext_pull_collapse_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_bool(pext,
		&ppayload->collapse_table.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext,
		&ppayload->collapse_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->collapse_table.row_count);
}

static int exmdb_ext_push_collapse_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_bool(pext,
		ppayload->collapse_table.b_found);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_int32(pext,
		ppayload->collapse_table.position);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->collapse_table.row_count);
}

static int exmdb_ext_pull_store_table_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->store_table_state.state_id);
}

static int exmdb_ext_push_store_table_state_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->store_table_state.state_id);
}

static int exmdb_ext_pull_restore_table_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_int32(pext,
		&ppayload->restore_table_state.position);
}

static int exmdb_ext_push_restore_table_state_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_int32(pext,
		ppayload->restore_table_state.position);
}

static int exmdb_ext_pull_check_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_message.b_exist);
}

static int exmdb_ext_push_check_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_message.b_exist);
}

static int exmdb_ext_pull_check_message_deleted_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_message_deleted.b_del);
}

static int exmdb_ext_push_check_message_deleted_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_message_deleted.b_del);
}

static int exmdb_ext_pull_load_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_message_instance.instance_id);
}

static int exmdb_ext_push_load_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->load_message_instance.instance_id);
}

static int exmdb_ext_pull_load_embedded_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_embedded_instance.instance_id);
}

static int exmdb_ext_push_load_embedded_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->load_embedded_instance.instance_id);
}

static int exmdb_ext_pull_get_embeded_cn_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->get_embeded_cn.pcn = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_embeded_cn.pcn =
			common_util_alloc(sizeof(uint64_t));
		if (NULL == ppayload->get_embeded_cn.pcn) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint64(pext,
			ppayload->get_embeded_cn.pcn);
	}
}

static int exmdb_ext_push_get_embeded_cn_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->get_embeded_cn.pcn) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_uint64(pext,
			*(uint64_t*)ppayload->get_embeded_cn.pcn);
	}
}

static int exmdb_ext_pull_reload_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->reload_message_instance.b_result);
}

static int exmdb_ext_push_reload_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->reload_message_instance.b_result);
}

static int exmdb_ext_pull_read_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_message_content(pext,
		&ppayload->read_message_instance.msgctnt);
}

static int exmdb_ext_push_read_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_message_content(pext,
		&ppayload->read_message_instance.msgctnt);
}

static int exmdb_ext_pull_write_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_proptag_array(pext,
		&ppayload->write_message_instance.proptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_problem_array(pext,
		&ppayload->write_message_instance.problems);
}

static int exmdb_ext_push_write_message_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_proptag_array(pext,
		&ppayload->write_message_instance.proptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_problem_array(pext,
		&ppayload->write_message_instance.problems);
}

static int exmdb_ext_pull_load_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_attachment_instance.instance_id);
}

static int exmdb_ext_push_load_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->load_attachment_instance.instance_id);
}

static int exmdb_ext_pull_create_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->create_attachment_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext,
		&ppayload->create_attachment_instance.attachment_num);
}

static int exmdb_ext_push_create_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->create_attachment_instance.instance_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext,
		ppayload->create_attachment_instance.attachment_num);
}

static int exmdb_ext_pull_read_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_tpropval_array(pext,
		&ppayload->read_attachment_instance.attctnt.proplist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != tmp_byte) {
		ppayload->read_attachment_instance.attctnt.pembedded =
					common_util_alloc(sizeof(MESSAGE_CONTENT));
		if (NULL == ppayload->read_attachment_instance.attctnt.pembedded) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_message_content(pext,
			ppayload->read_attachment_instance.attctnt.pembedded);
	} else {
		ppayload->read_attachment_instance.attctnt.pembedded = NULL;
		return EXT_ERR_SUCCESS;
	}
}

static int exmdb_ext_push_read_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_tpropval_array(pext,
		&ppayload->read_attachment_instance.attctnt.proplist);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL == ppayload->read_attachment_instance.attctnt.pembedded) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_message_content(pext,
			ppayload->read_attachment_instance.attctnt.pembedded);
	}
}

static int exmdb_ext_pull_write_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->write_attachment_instance.problems);
}

static int exmdb_ext_push_write_attachment_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_problem_array(pext,
		&ppayload->write_attachment_instance.problems);
}

static int exmdb_ext_pull_flush_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->flush_instance.b_result);
}

static int exmdb_ext_push_flush_instance_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->flush_instance.b_result);
}

static int exmdb_ext_pull_get_instance_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_instance_all_proptags.proptags);
}

static int exmdb_ext_push_get_instance_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_instance_all_proptags.proptags);
}

static int exmdb_ext_pull_get_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_instance_properties.propvals);
}

static int exmdb_ext_push_get_instance_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tpropval_array(pext,
		&ppayload->get_instance_properties.propvals);
}

static int exmdb_ext_pull_set_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_instance_properties.problems);
}

static int exmdb_ext_push_set_instance_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_problem_array(pext,
		&ppayload->set_instance_properties.problems);
}

static int exmdb_ext_pull_remove_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->remove_instance_properties.problems);
}

static int exmdb_ext_push_remove_instance_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_problem_array(pext,
		&ppayload->remove_instance_properties.problems);
}

static int exmdb_ext_pull_check_instance_cycle_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_instance_cycle.b_cycle);
}

static int exmdb_ext_push_check_instance_cycle_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_instance_cycle.b_cycle);
}

static int exmdb_ext_pull_get_message_instance_rcpts_num_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_message_instance_rcpts_num.num);
}

static int exmdb_ext_push_get_message_instance_rcpts_num_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint16(pext,
		ppayload->get_message_instance_rcpts_num.num);
}

static int exmdb_ext_pull_get_message_instance_rcpts_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_message_instance_rcpts_all_proptags.proptags);
}

static int exmdb_ext_push_get_message_instance_rcpts_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_message_instance_rcpts_all_proptags.proptags);
}

static int exmdb_ext_pull_get_message_instance_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->get_message_instance_rcpts.set);
}

static int exmdb_ext_push_get_message_instance_rcpts_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tarray_set(pext,
		&ppayload->get_message_instance_rcpts.set);
}

static int exmdb_ext_pull_copy_instance_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->copy_instance_rcpts.b_result);
}

static int exmdb_ext_push_copy_instance_rcpts_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->copy_instance_rcpts.b_result);
}

static int exmdb_ext_pull_get_message_instance_attachments_num_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_message_instance_attachments_num.num);
}

static int exmdb_ext_push_get_message_instance_attachments_num_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint16(pext,
		ppayload->get_message_instance_attachments_num.num);
}

static int exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_message_instance_attachment_table_all_proptags.proptags);
}

static int exmdb_ext_push_get_message_instance_attachment_table_all_proptags_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_message_instance_attachment_table_all_proptags.proptags);
}

static int exmdb_ext_pull_query_message_instance_attachment_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->query_message_instance_attachment_table.set);
}

static int exmdb_ext_push_query_message_instance_attachment_table_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tarray_set(pext,
		&ppayload->query_message_instance_attachment_table.set);
}

static int exmdb_ext_pull_copy_instance_attachments_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->copy_instance_attachments.b_result);
}

static int exmdb_ext_push_copy_instance_attachments_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->copy_instance_attachments.b_result);
}

static int exmdb_ext_pull_get_message_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->get_message_rcpts.set);
}

static int exmdb_ext_push_get_message_rcpts_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tarray_set(pext,
		&ppayload->get_message_rcpts.set);
}

static int exmdb_ext_pull_get_message_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_message_properties.propvals);
}

static int exmdb_ext_push_get_message_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_tpropval_array(pext,
		&ppayload->get_message_properties.propvals);
}

static int exmdb_ext_pull_set_message_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_message_properties.problems);
}

static int exmdb_ext_push_set_message_properties_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_problem_array(pext,
		&ppayload->set_message_properties.problems);
}

static int exmdb_ext_pull_set_message_read_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->set_message_read_state.read_cn);
}

static int exmdb_ext_push_set_message_read_state_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->set_message_read_state.read_cn);
}

static int exmdb_ext_pull_allocate_message_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->allocate_message_id.message_id);
}

static int exmdb_ext_push_allocate_message_id_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->allocate_message_id.message_id);
}

static int exmdb_ext_pull_allocate_cn_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
			&ppayload->allocate_cn.cn);
}

static int exmdb_ext_push_allocate_cn_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
			ppayload->allocate_cn.cn);
}

static int exmdb_ext_pull_get_message_group_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->get_message_group_id.pgroup_id = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_message_group_id.pgroup_id =
				common_util_alloc(sizeof(uint32_t));
		if (NULL == ppayload->get_message_group_id.pgroup_id) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext,
			ppayload->get_message_group_id.pgroup_id);
	}
}

static int exmdb_ext_push_get_message_group_id_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->get_message_group_id.pgroup_id) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_uint32(pext,
			*ppayload->get_message_group_id.pgroup_id);
	}
}

static int exmdb_ext_pull_get_change_indices_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_proptag_array(pext,
		&ppayload->get_change_indices.indices);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_change_indices.ungroup_proptags);
}

static int exmdb_ext_push_get_change_indices_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_proptag_array(pext,
		&ppayload->get_change_indices.indices);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_proptag_array(pext,
		&ppayload->get_change_indices.ungroup_proptags);
}

static int exmdb_ext_pull_try_mark_submit_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->try_mark_submit.b_marked);
}

static int exmdb_ext_push_try_mark_submit_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->try_mark_submit.b_marked);
}

static int exmdb_ext_pull_link_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->link_message.b_result);
}

static int exmdb_ext_push_link_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->link_message.b_result);
}

static int exmdb_ext_pull_get_message_timer_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->get_message_timer.ptimer_id = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_message_timer.ptimer_id =
			common_util_alloc(sizeof(uint32_t));
		if (NULL == ppayload->get_message_timer.ptimer_id) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext,
			ppayload->get_message_timer.ptimer_id);
	}
}

static int exmdb_ext_push_get_message_timer_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->get_message_timer.ptimer_id) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_uint32(pext,
			*ppayload->get_message_timer.ptimer_id);
	}
}

static int exmdb_ext_pull_update_folder_rule_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->update_folder_rule.b_exceed);
}

static int exmdb_ext_push_update_folder_rule_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->update_folder_rule.b_exceed);
}

static int exmdb_ext_pull_delivery_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->delivery_message.result);
}

static int exmdb_ext_push_delivery_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->delivery_message.result);
}

static int exmdb_ext_pull_write_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->write_message.b_result);
}

static int exmdb_ext_push_write_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->write_message.b_result);
}

static int exmdb_ext_pull_read_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == tmp_byte) {
		ppayload->read_message.pmsgctnt = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->read_message.pmsgctnt =
		common_util_alloc(sizeof(MESSAGE_CONTENT));
	if (NULL == ppayload->read_message.pmsgctnt) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_message_content(
		pext, ppayload->read_message.pmsgctnt);
}

static int exmdb_ext_push_read_message_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	if (NULL == ppayload->read_message.pmsgctnt) {
		return ext_buffer_push_uint8(pext, 0);
	}
	status = ext_buffer_push_uint8(pext, 1);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_message_content(
		pext, ppayload->read_message.pmsgctnt);
}

static int exmdb_ext_pull_get_content_sync_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_content_sync.fai_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_content_sync.fai_total);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_content_sync.normal_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_content_sync.normal_total);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.updated_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.chg_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_content_sync.last_cn);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.given_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.deleted_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.nolonger_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.read_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_content_sync.unread_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_content_sync.last_readcn);
}

static int exmdb_ext_push_get_content_sync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_content_sync.fai_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->get_content_sync.fai_total);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext,
		ppayload->get_content_sync.normal_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->get_content_sync.normal_total);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.updated_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.chg_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->get_content_sync.last_cn);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.given_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.deleted_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.nolonger_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.read_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_content_sync.unread_mids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext,
		ppayload->get_content_sync.last_readcn);
}

static int exmdb_ext_pull_get_hierarchy_sync_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint32(pext,
		&ppayload->get_hierarchy_sync.fldchgs.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == ppayload->get_hierarchy_sync.fldchgs.count) {
		ppayload->get_hierarchy_sync.fldchgs.pfldchgs = NULL;
	} else {
		ppayload->get_hierarchy_sync.fldchgs.pfldchgs =
			common_util_alloc(sizeof(TPROPVAL_ARRAY)*
			ppayload->get_hierarchy_sync.fldchgs.count);
		if (NULL == ppayload->get_hierarchy_sync.fldchgs.pfldchgs) {
			return EXT_ERR_ALLOC;
		}
		for (i=0; i<ppayload->get_hierarchy_sync.fldchgs.count; i++) {
			status = ext_buffer_pull_tpropval_array(pext,
				ppayload->get_hierarchy_sync.fldchgs.pfldchgs + i);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	status = ext_buffer_pull_uint64(pext,
		&ppayload->get_hierarchy_sync.last_cn);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_eid_array(pext,
		&ppayload->get_hierarchy_sync.given_fids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_eid_array(pext,
		&ppayload->get_hierarchy_sync.deleted_fids);
}

static int exmdb_ext_push_get_hierarchy_sync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint32(pext,
		ppayload->get_hierarchy_sync.fldchgs.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<ppayload->get_hierarchy_sync.fldchgs.count; i++) {
		status = ext_buffer_push_tpropval_array(pext,
			ppayload->get_hierarchy_sync.fldchgs.pfldchgs + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint64(pext,
		ppayload->get_hierarchy_sync.last_cn);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_eid_array(pext,
		&ppayload->get_hierarchy_sync.given_fids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_eid_array(pext,
		&ppayload->get_hierarchy_sync.deleted_fids);
}

static int exmdb_ext_pull_allocate_ids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->allocate_ids.begin_eid);
}

static int exmdb_ext_push_allocate_ids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->allocate_ids.begin_eid);
}

static int exmdb_ext_pull_subscribe_notification_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->subscribe_notification.sub_id);
}

static int exmdb_ext_push_subscribe_notification_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->subscribe_notification.sub_id);
}

static int exmdb_ext_pull_check_contact_address_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_contact_address.b_found);
}

static int exmdb_ext_push_check_contact_address_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_push_bool(pext,
		ppayload->check_contact_address.b_found);
}

/* CALL_ID_CONNECT, CALL_ID_LISTEN_NOTIFICATION not included */
int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXMDB_RESPONSE *presponse)
{
	int status;
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
	switch (presponse->call_id) {
	case CALL_ID_PING_STORE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_ALL_NAMED_PROPIDS:
		return exmdb_ext_pull_get_all_named_propids_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_GET_NAMED_PROPIDS:
		return exmdb_ext_pull_get_named_propids_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_GET_NAMED_PROPNAMES:
		return exmdb_ext_pull_get_named_propnames_response(
							&ext_pull,  &presponse->payload);
	case CALL_ID_GET_MAPPING_GUID:
		return exmdb_ext_pull_get_mapping_guid_response(
						&ext_pull,  &presponse->payload);
	case CALL_ID_GET_MAPPING_REPLID:
		return exmdb_ext_pull_get_mapping_replid_response(
						&ext_pull,  &presponse->payload);
	case CALL_ID_GET_STORE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_store_all_proptags_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_GET_STORE_PROPERTIES:
		return exmdb_ext_pull_get_store_properties_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_SET_STORE_PROPERTIES:
		return exmdb_ext_pull_set_store_properties_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_REMOVE_STORE_PROPERTIES:
		return EXT_ERR_SUCCESS;
	case CALL_ID_CHECK_MAILBOX_PERMISSION:
		return exmdb_ext_pull_check_mailbox_permission_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_GET_FOLDER_BY_CLASS:
		return exmdb_ext_pull_get_folder_by_class_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_SET_FOLDER_BY_CLASS:
		return exmdb_ext_pull_set_folder_by_class_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_GET_FOLDER_CLASS_TABLE:
		return exmdb_ext_pull_get_folder_class_table_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_FOLDER_ID:
		return exmdb_ext_pull_check_folder_id_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_QUERY_FOLDER_MESSAGES:
		return exmdb_ext_pull_query_folder_messages_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_FOLDER_DELETED:
		return exmdb_ext_pull_check_folder_deleted_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_GET_FOLDER_BY_NAME:
		return exmdb_ext_pull_get_folder_by_name_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_FOLDER_PERMISSION:
		return exmdb_ext_pull_check_folder_permission_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_CREATE_FOLDER_BY_PROPERTIES:
		return exmdb_ext_pull_create_folder_by_properties_response(
									&ext_pull, &presponse->payload);
	case CALL_ID_GET_FOLDER_ALL_PROPTAGS:
		return exmdb_ext_pull_get_folder_all_proptags_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_GET_FOLDER_PROPERTIES:
		return exmdb_ext_pull_get_folder_properties_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_SET_FOLDER_PROPERTIES:
		return exmdb_ext_pull_set_folder_properties_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_REMOVE_FOLDER_PROPERTIES:
		return EXT_ERR_SUCCESS;
	case CALL_ID_DELETE_FOLDER:
		return exmdb_ext_pull_delete_folder_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_EMPTY_FOLDER:
		return exmdb_ext_pull_empty_folder_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_FOLDER_CYCLE:
		return exmdb_ext_pull_check_folder_cycle_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_COPY_FOLDER_INTERNAL:
		return exmdb_ext_pull_copy_folder_internal_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_GET_SEARCH_CRITERIA:
		return exmdb_ext_pull_get_search_criteria_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_SET_SEARCH_CRITERIA:
		return exmdb_ext_pull_set_search_criteria_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_MOVECOPY_MESSAGE:
		return exmdb_ext_pull_movecopy_message_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_MOVECOPY_MESSAGES:
		return exmdb_ext_pull_movecopy_messages_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_MOVECOPY_FOLDER:
		return exmdb_ext_pull_movecopy_folder_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_DELETE_MESSAGES:
		return exmdb_ext_pull_delete_messages_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_GET_MESSAGE_BRIEF:
		return exmdb_ext_pull_get_message_brief_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_SUM_HIERARCHY:
		return exmdb_ext_pull_sum_hierarchy_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_LOAD_HIERARCHY_TABLE:
		return exmdb_ext_pull_load_hierarchy_table_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_SUM_CONTENT:
		return exmdb_ext_pull_sum_content_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_LOAD_CONTENT_TABLE:
		return exmdb_ext_pull_load_content_table_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_RELOAD_CONTENT_TABLE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_LOAD_PERMISSION_TABLE:
		return exmdb_ext_pull_load_permission_table_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_LOAD_RULE_TABLE:
		return exmdb_ext_pull_load_rule_table_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_UNLOAD_TABLE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_SUM_TABLE:
		return exmdb_ext_pull_sum_table_response(
				&ext_pull, &presponse->payload);
	case CALL_ID_QUERY_TABLE:
		return exmdb_ext_pull_query_table_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_MATCH_TABLE:
		return exmdb_ext_pull_match_table_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_LOCATE_TABLE:
		return exmdb_ext_pull_locate_table_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_READ_TABLE_ROW:
		return exmdb_ext_pull_read_table_row_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_MARK_TABLE:
		return exmdb_ext_pull_mark_table_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_GET_TABLE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_table_all_proptags_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_EXPAND_TABLE:
		return exmdb_ext_pull_expand_table_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_COLLAPSE_TABLE:
		return exmdb_ext_pull_collapse_table_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_STORE_TABLE_STATE:
		return exmdb_ext_pull_store_table_state_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_RESTORE_TABLE_STATE:
		return exmdb_ext_pull_restore_table_state_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_MESSAGE:
		return exmdb_ext_pull_check_message_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_MESSAGE_DELETED:
		return exmdb_ext_pull_check_message_deleted_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_LOAD_MESSAGE_INSTANCE:
		return exmdb_ext_pull_load_message_instance_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_LOAD_EMBEDDED_INSTANCE:
		return exmdb_ext_pull_load_embedded_instance_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_GET_EMBEDED_CN:
		return exmdb_ext_pull_get_embeded_cn_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_RELOAD_MESSAGE_INSTANCE:
		return exmdb_ext_pull_reload_message_instance_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_CLEAR_MESSAGE_INSTANCE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_READ_MESSAGE_INSTANCE:
		return exmdb_ext_pull_read_message_instance_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_WRITE_MESSAGE_INSTANCE:
		return exmdb_ext_pull_write_message_instance_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_LOAD_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_load_attachment_instance_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_CREATE_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_create_attachment_instance_response(
									&ext_pull, &presponse->payload);
	case CALL_ID_READ_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_read_attachment_instance_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_WRITE_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_write_attachment_instance_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		return EXT_ERR_SUCCESS;
	case CALL_ID_FLUSH_INSTANCE:
		return exmdb_ext_pull_flush_instance_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_UNLOAD_INSTANCE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_INSTANCE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_instance_all_proptags_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_GET_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_get_instance_properties_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_SET_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_set_instance_properties_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_REMOVE_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_remove_instance_properties_response(
									&ext_pull, &presponse->payload);
	case CALL_ID_CHECK_INSTANCE_CYCLE:
		return exmdb_ext_pull_check_instance_cycle_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_RCPTS:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_NUM:
		return exmdb_ext_pull_get_message_instance_rcpts_num_response(
										&ext_pull, &presponse->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		return exmdb_ext_pull_get_message_instance_rcpts_all_proptags_response(
												&ext_pull, &presponse->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS:
		return exmdb_ext_pull_get_message_instance_rcpts_response(
									&ext_pull, &presponse->payload);
	case CALL_ID_UPDATE_MESSAGE_INSTANCE_RCPTS:
		return EXT_ERR_SUCCESS;
	case CALL_ID_COPY_INSTANCE_RCPTS:
		return exmdb_ext_pull_copy_instance_rcpts_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		return exmdb_ext_pull_get_message_instance_attachments_num_response(
											&ext_pull, &presponse->payload);
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_response(
															&ext_pull, &presponse->payload);
	case CALL_ID_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		return exmdb_ext_pull_query_message_instance_attachment_table_response(
												&ext_pull, &presponse->payload);
	case CALL_ID_COPY_INSTANCE_ATTACHMENTS:
		return exmdb_ext_pull_copy_instance_attachments_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_SET_MESSAGE_INSTANCE_CONFLICT:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_MESSAGE_RCPTS:
		return exmdb_ext_pull_get_message_rcpts_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_GET_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_get_message_properties_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_SET_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_set_message_properties_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_SET_MESSAGE_READ_STATE:
		return exmdb_ext_pull_set_message_read_state_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_REMOVE_MESSAGE_PROPERTIES:
		return EXT_ERR_SUCCESS;
	case CALL_ID_ALLOCATE_MESSAGE_ID:
		return exmdb_ext_pull_allocate_message_id_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_ALLOCATE_CN:
		return exmdb_ext_pull_allocate_cn_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_GET_MESSAGE_GROUP_ID:
		return exmdb_ext_pull_get_message_group_id_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_SET_MESSAGE_GROUP_ID:
		return EXT_ERR_SUCCESS;
	case CALL_ID_SAVE_CHANGE_INDICES:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_CHANGE_INDICES:
		return exmdb_ext_pull_get_change_indices_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_MARK_MODIFIED:
		return EXT_ERR_SUCCESS;
	case CALL_ID_TRY_MARK_SUBMIT:
		return exmdb_ext_pull_try_mark_submit_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_CLEAR_SUBMIT:
		return EXT_ERR_SUCCESS;
	case CALL_ID_LINK_MESSAGE:
		return exmdb_ext_pull_link_message_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_UNLINK_MESSAGE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_RULE_NEW_MESSAGE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_SET_MESSAGE_TIMER:
		return EXT_ERR_SUCCESS;
	case CALL_ID_GET_MESSAGE_TIMER:
		return exmdb_ext_pull_get_message_timer_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_EMPTY_FOLDER_PERMISSION:
		return EXT_ERR_SUCCESS;
	case CALL_ID_UPDATE_FOLDER_PERMISSION:
		return EXT_ERR_SUCCESS;
	case CALL_ID_EMPTY_FOLDER_RULE:
		return EXT_ERR_SUCCESS;
	case CALL_ID_UPDATE_FOLDER_RULE:
		return exmdb_ext_pull_update_folder_rule_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_DELIVERY_MESSAGE:
		return exmdb_ext_pull_delivery_message_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_WRITE_MESSAGE:
		return exmdb_ext_pull_write_message_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_READ_MESSAGE:
		return exmdb_ext_pull_read_message_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_GET_CONTENT_SYNC:
		return exmdb_ext_pull_get_content_sync_response(
						&ext_pull, &presponse->payload);
	case CALL_ID_GET_HIERARCHY_SYNC:
		return exmdb_ext_pull_get_hierarchy_sync_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_ALLOCATE_IDS:
		return exmdb_ext_pull_allocate_ids_response(
					&ext_pull, &presponse->payload);
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		return exmdb_ext_pull_subscribe_notification_response(
								&ext_pull, &presponse->payload);
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		return EXT_ERR_SUCCESS;
	case CALL_ID_TRANSPORT_NEW_MAIL:
		return EXT_ERR_SUCCESS;
	case CALL_ID_CHECK_CONTACT_ADDRESS:
		return exmdb_ext_pull_check_contact_address_response(
							&ext_pull, &presponse->payload);
	case CALL_ID_UNLOAD_STORE:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

/* CALL_ID_CONNECT, CALL_ID_LISTEN_NOTIFICATION not included */
int exmdb_ext_push_response(const EXMDB_RESPONSE *presponse,
	BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_WCOUNT)) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_uint8(&ext_push, RESPONSE_CODE_SUCCESS);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	status = ext_buffer_push_advance(&ext_push, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	switch (presponse->call_id) {
	case CALL_ID_PING_STORE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_ALL_NAMED_PROPIDS:
		status = exmdb_ext_push_get_all_named_propids_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_NAMED_PROPIDS:
		status = exmdb_ext_push_get_named_propids_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_NAMED_PROPNAMES:
		status = exmdb_ext_push_get_named_propnames_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MAPPING_GUID:
		status = exmdb_ext_push_get_mapping_guid_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MAPPING_REPLID:
		status = exmdb_ext_push_get_mapping_replid_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_STORE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_store_all_proptags_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_STORE_PROPERTIES:
		status = exmdb_ext_push_get_store_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_STORE_PROPERTIES:
		status = exmdb_ext_push_set_store_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_REMOVE_STORE_PROPERTIES:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_CHECK_MAILBOX_PERMISSION:
		status = exmdb_ext_push_check_mailbox_permission_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_FOLDER_BY_CLASS:
		status = exmdb_ext_push_get_folder_by_class_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_FOLDER_BY_CLASS:
		status = exmdb_ext_push_set_folder_by_class_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_FOLDER_CLASS_TABLE:
		status = exmdb_ext_push_get_folder_class_table_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_FOLDER_ID:
		status = exmdb_ext_push_check_folder_id_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_QUERY_FOLDER_MESSAGES:
		status = exmdb_ext_push_query_folder_messages_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_FOLDER_DELETED:
		status = exmdb_ext_push_check_folder_deleted_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_FOLDER_BY_NAME:
		status = exmdb_ext_push_get_folder_by_name_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_FOLDER_PERMISSION:
		status = exmdb_ext_push_check_folder_permission_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_CREATE_FOLDER_BY_PROPERTIES:
		status = exmdb_ext_push_create_folder_by_properties_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_FOLDER_ALL_PROPTAGS:
		status = exmdb_ext_push_get_folder_all_proptags_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_FOLDER_PROPERTIES:
		status = exmdb_ext_push_get_folder_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_FOLDER_PROPERTIES:
		status = exmdb_ext_push_set_folder_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_REMOVE_FOLDER_PROPERTIES:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_DELETE_FOLDER:
		status = exmdb_ext_push_delete_folder_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_EMPTY_FOLDER:
		status = exmdb_ext_push_empty_folder_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_FOLDER_CYCLE:
		status = exmdb_ext_push_check_folder_cycle_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_COPY_FOLDER_INTERNAL:
		status = exmdb_ext_push_copy_folder_internal_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_SEARCH_CRITERIA:
		status = exmdb_ext_push_get_search_criteria_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_SEARCH_CRITERIA:
		status = exmdb_ext_push_set_search_criteria_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_MOVECOPY_MESSAGE:
		status = exmdb_ext_push_movecopy_message_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_MOVECOPY_MESSAGES:
		status = exmdb_ext_push_movecopy_messages_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_MOVECOPY_FOLDER:
		status = exmdb_ext_push_movecopy_folder_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_DELETE_MESSAGES:
		status = exmdb_ext_push_delete_messages_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MESSAGE_BRIEF:
		status = exmdb_ext_push_get_message_brief_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_SUM_HIERARCHY:
		status = exmdb_ext_push_sum_hierarchy_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOAD_HIERARCHY_TABLE:
		status = exmdb_ext_push_load_hierarchy_table_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SUM_CONTENT:
		status = exmdb_ext_push_sum_content_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOAD_CONTENT_TABLE:
		status = exmdb_ext_push_load_content_table_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_RELOAD_CONTENT_TABLE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_LOAD_PERMISSION_TABLE:
		status = exmdb_ext_push_load_permission_table_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOAD_RULE_TABLE:
		status = exmdb_ext_push_load_rule_table_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNLOAD_TABLE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_SUM_TABLE:
		status = exmdb_ext_push_sum_table_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_QUERY_TABLE:
		status = exmdb_ext_push_query_table_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_MATCH_TABLE:
		status = exmdb_ext_push_match_table_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOCATE_TABLE:
		status = exmdb_ext_push_locate_table_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_READ_TABLE_ROW:
		status = exmdb_ext_push_read_table_row_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_MARK_TABLE:
		status = exmdb_ext_push_mark_table_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_TABLE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_table_all_proptags_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_EXPAND_TABLE:
		status = exmdb_ext_push_expand_table_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_COLLAPSE_TABLE:
		status = exmdb_ext_push_collapse_table_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_STORE_TABLE_STATE:
		status = exmdb_ext_push_store_table_state_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_RESTORE_TABLE_STATE:
		status = exmdb_ext_push_restore_table_state_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_MESSAGE:
		status = exmdb_ext_push_check_message_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_MESSAGE_DELETED:
		status = exmdb_ext_push_check_message_deleted_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOAD_MESSAGE_INSTANCE:
		status = exmdb_ext_push_load_message_instance_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOAD_EMBEDDED_INSTANCE:
		status = exmdb_ext_push_load_embedded_instance_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_EMBEDED_CN:
		status = exmdb_ext_push_get_embeded_cn_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_RELOAD_MESSAGE_INSTANCE:
		status = exmdb_ext_push_reload_message_instance_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_CLEAR_MESSAGE_INSTANCE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_READ_MESSAGE_INSTANCE:
		status = exmdb_ext_push_read_message_instance_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_WRITE_MESSAGE_INSTANCE:
		status = exmdb_ext_push_write_message_instance_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOAD_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_load_attachment_instance_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_CREATE_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_create_attachment_instance_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_READ_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_read_attachment_instance_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_WRITE_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_write_attachment_instance_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_FLUSH_INSTANCE:
		status = exmdb_ext_push_flush_instance_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNLOAD_INSTANCE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_INSTANCE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_instance_all_proptags_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_get_instance_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_set_instance_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_REMOVE_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_remove_instance_properties_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECK_INSTANCE_CYCLE:
		status = exmdb_ext_push_check_instance_cycle_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_RCPTS:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_NUM:
		status = exmdb_ext_push_get_message_instance_rcpts_num_response(
										&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		status = exmdb_ext_push_get_message_instance_rcpts_all_proptags_response(
												&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_get_message_instance_rcpts_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_UPDATE_MESSAGE_INSTANCE_RCPTS:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_COPY_INSTANCE_RCPTS:
		status = exmdb_ext_push_copy_instance_rcpts_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		status = exmdb_ext_push_get_message_instance_attachments_num_response(
												&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_message_instance_attachment_table_all_proptags_response(
															&ext_push, &presponse->payload);
		break;
	case CALL_ID_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		status = exmdb_ext_push_query_message_instance_attachment_table_response(
												&ext_push, &presponse->payload);
		break;
	case CALL_ID_COPY_INSTANCE_ATTACHMENTS:
		status = exmdb_ext_push_copy_instance_attachments_response(
									&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_MESSAGE_INSTANCE_CONFLICT:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_MESSAGE_RCPTS:
		status = exmdb_ext_push_get_message_rcpts_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_get_message_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_set_message_properties_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_MESSAGE_READ_STATE:
		status = exmdb_ext_push_set_message_read_state_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_REMOVE_MESSAGE_PROPERTIES:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_ALLOCATE_MESSAGE_ID:
		status = exmdb_ext_push_allocate_message_id_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_ALLOCATE_CN:
		status = exmdb_ext_push_allocate_cn_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_MESSAGE_GROUP_ID:
		status = exmdb_ext_push_get_message_group_id_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SET_MESSAGE_GROUP_ID:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_SAVE_CHANGE_INDICES:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_CHANGE_INDICES:
		status = exmdb_ext_push_get_change_indices_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_MARK_MODIFIED:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_TRY_MARK_SUBMIT:
		status = exmdb_ext_push_try_mark_submit_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CLEAR_SUBMIT:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_LINK_MESSAGE:
		status = exmdb_ext_push_link_message_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNLINK_MESSAGE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_RULE_NEW_MESSAGE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_SET_MESSAGE_TIMER:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_GET_MESSAGE_TIMER:
		status = exmdb_ext_push_get_message_timer_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_EMPTY_FOLDER_PERMISSION:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_EMPTY_FOLDER_RULE:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_UPDATE_FOLDER_RULE:
		status = exmdb_ext_push_update_folder_rule_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_UPDATE_FOLDER_PERMISSION:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_DELIVERY_MESSAGE:
		status = exmdb_ext_push_delivery_message_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_WRITE_MESSAGE:
		status = exmdb_ext_push_write_message_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_READ_MESSAGE:
		status = exmdb_ext_push_read_message_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_CONTENT_SYNC:
		status = exmdb_ext_push_get_content_sync_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GET_HIERARCHY_SYNC:
		status = exmdb_ext_push_get_hierarchy_sync_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_ALLOCATE_IDS:
		status = exmdb_ext_push_allocate_ids_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_subscribe_notification_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_TRANSPORT_NEW_MAIL:
		status = EXT_ERR_SUCCESS;
		break;
	case CALL_ID_CHECK_CONTACT_ADDRESS:
		status = exmdb_ext_push_check_contact_address_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNLOAD_STORE:
		status = EXT_ERR_SUCCESS;
		break;
	default:
		ext_buffer_push_free(&ext_push);
		return EXT_ERR_BAD_SWITCH;
	}
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	pbin_out->cb = ext_push.offset;
	ext_push.offset = 1;
	ext_buffer_push_uint32(&ext_push,
		pbin_out->cb - sizeof(uint32_t) - 1);
	/* memory referneced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.data;
	return EXT_ERR_SUCCESS;
}

int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify)
{
	int status;
	uint8_t tmp_byte;
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
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
		pnotify->db_notify.pdata = common_util_alloc(
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
	case DB_NOTIFY_TYPE_FOLDER_CREATED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_FOLDER_CREATED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_CREATED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_CREATED*)
			pnotify->db_notify.pdata)->parent_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_proptag_array(&ext_pull,
			&((DB_NOTIFY_FOLDER_CREATED*)
			pnotify->db_notify.pdata)->proptags);
	case DB_NOTIFY_TYPE_MESSAGE_CREATED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_MESSAGE_CREATED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_CREATED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_CREATED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_proptag_array(&ext_pull,
			&((DB_NOTIFY_MESSAGE_CREATED*)
			pnotify->db_notify.pdata)->proptags);
	case DB_NOTIFY_TYPE_LINK_CREATED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_LINK_CREATED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->parent_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_proptag_array(&ext_pull,
			&((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->proptags);
	case DB_NOTIFY_TYPE_FOLDER_DELETED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_FOLDER_DELETED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_DELETED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_DELETED*)
			pnotify->db_notify.pdata)->parent_id);
	case DB_NOTIFY_TYPE_MESSAGE_DELETED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_MESSAGE_DELETED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_DELETED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_DELETED*)
			pnotify->db_notify.pdata)->message_id);
	case DB_NOTIFY_TYPE_LINK_DELETED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_LINK_DELETED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_LINK_DELETED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_LINK_DELETED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_LINK_DELETED*)
			pnotify->db_notify.pdata)->parent_id);
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_FOLDER_MODIFIED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_MODIFIED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint8(&ext_pull, &tmp_byte);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (0 == tmp_byte) {
			((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->ptotal = NULL;
		} else {
			((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->ptotal =
				common_util_alloc(sizeof(uint32_t));
			if (NULL == ((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->ptotal) {
				return EXT_ERR_ALLOC;	
			}
			status = ext_buffer_pull_uint32(&ext_pull,
				((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->ptotal);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		status = ext_buffer_pull_uint8(&ext_pull, &tmp_byte);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (0 == tmp_byte) {
			((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->punread = NULL;
		} else {
			((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->punread =
				common_util_alloc(sizeof(uint32_t));
			if (NULL == ((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->punread) {
				return EXT_ERR_ALLOC;	
			}
			status = ext_buffer_pull_uint32(&ext_pull,
				((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->punread);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
		return ext_buffer_pull_proptag_array(&ext_pull,
			&((DB_NOTIFY_FOLDER_MODIFIED*)
			pnotify->db_notify.pdata)->proptags);
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED:
		pnotify->db_notify.pdata = common_util_alloc(
				sizeof(DB_NOTIFY_MESSAGE_MODIFIED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MODIFIED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MODIFIED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_proptag_array(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MODIFIED*)
			pnotify->db_notify.pdata)->proptags);
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED:
		pnotify->db_notify.pdata = common_util_alloc(
						sizeof(DB_NOTIFY_FOLDER_MVCP));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->parent_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->old_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->old_parent_id);
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED:
		pnotify->db_notify.pdata = common_util_alloc(
						sizeof(DB_NOTIFY_MESSAGE_MVCP));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->old_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->old_message_id);
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED:
		pnotify->db_notify.pdata = common_util_alloc(
					sizeof(DB_NOTIFY_SEARCH_COMPLETED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_SEARCH_COMPLETED*)
			pnotify->db_notify.pdata)->folder_id);
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_CHANGED:
	case DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED:
		return EXT_ERR_SUCCESS;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED:
		pnotify->db_notify.pdata = common_util_alloc(
			sizeof(DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_folder_id);
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED:
		pnotify->db_notify.pdata = common_util_alloc(
			sizeof(DB_NOTIFY_CONTENT_TABLE_ROW_ADDED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_instance);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_row_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_instance);
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED:
		pnotify->db_notify.pdata = common_util_alloc(
			sizeof(DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		return status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_folder_id);
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED:
		pnotify->db_notify.pdata = common_util_alloc(
			sizeof(DB_NOTIFY_CONTENT_TABLE_ROW_DELETED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_instance);
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED:
		pnotify->db_notify.pdata = common_util_alloc(
			sizeof(DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_folder_id);
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED:
		pnotify->db_notify.pdata = common_util_alloc(
			sizeof(DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED));
		if (NULL == pnotify->db_notify.pdata) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_instance);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_row_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_uint64(&ext_pull,
			&((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_instance);
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int exmdb_ext_push_db_notify(const DB_NOTIFY_DATAGRAM *pnotify,
	BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (FALSE == ext_buffer_push_init(&ext_push,
		NULL, 0, EXT_FLAG_WCOUNT)) {
		return EXT_ERR_ALLOC;	
	}
	status = ext_buffer_push_advance(&ext_push, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		goto PUSH_NOTIFY_FAILURE;
	}
	status = ext_buffer_push_string(&ext_push, pnotify->dir);
	if (EXT_ERR_SUCCESS != status) {
		goto PUSH_NOTIFY_FAILURE;
	}
	status = ext_buffer_push_bool(&ext_push, pnotify->b_table);
	if (EXT_ERR_SUCCESS != status) {
		goto PUSH_NOTIFY_FAILURE;
	}
	status = ext_buffer_push_long_array(&ext_push, &pnotify->id_array);
	if (EXT_ERR_SUCCESS != status) {
		goto PUSH_NOTIFY_FAILURE;
	}
	status = ext_buffer_push_uint8(&ext_push, pnotify->db_notify.type);
	if (EXT_ERR_SUCCESS != status) {
		goto PUSH_NOTIFY_FAILURE;
	}
	switch (pnotify->db_notify.type) {
	case DB_NOTIFY_TYPE_NEW_MAIL:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint32(&ext_push,
			((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->message_flags);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_string(&ext_push,
			((DB_NOTIFY_NEW_MAIL*)
			pnotify->db_notify.pdata)->pmessage_class);
		break;
	case DB_NOTIFY_TYPE_FOLDER_CREATED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_CREATED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_CREATED*)
			pnotify->db_notify.pdata)->parent_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_proptag_array(&ext_push,
			&((DB_NOTIFY_FOLDER_CREATED*)
			pnotify->db_notify.pdata)->proptags);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_CREATED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_CREATED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_CREATED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_proptag_array(&ext_push,
			&((DB_NOTIFY_MESSAGE_CREATED*)
			pnotify->db_notify.pdata)->proptags);
		break;
	case DB_NOTIFY_TYPE_LINK_CREATED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->parent_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_proptag_array(&ext_push,
			&((DB_NOTIFY_LINK_CREATED*)
			pnotify->db_notify.pdata)->proptags);
		break;
	case DB_NOTIFY_TYPE_FOLDER_DELETED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_DELETED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_DELETED*)
			pnotify->db_notify.pdata)->parent_id);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_DELETED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_DELETED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_DELETED*)
			pnotify->db_notify.pdata)->message_id);
		break;
	case DB_NOTIFY_TYPE_LINK_DELETED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_LINK_DELETED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_LINK_DELETED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_LINK_DELETED*)
			pnotify->db_notify.pdata)->parent_id);
		break;
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_MODIFIED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		if (NULL != ((DB_NOTIFY_FOLDER_MODIFIED*)
			pnotify->db_notify.pdata)->ptotal) {
			status = ext_buffer_push_uint8(&ext_push, 1);
			if (EXT_ERR_SUCCESS != status) {
				goto PUSH_NOTIFY_FAILURE;
			}
			status = ext_buffer_push_uint32(&ext_push,
				*((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->ptotal);
		} else {
			status = ext_buffer_push_uint8(&ext_push, 0);
		}
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		if (NULL != ((DB_NOTIFY_FOLDER_MODIFIED*)
			pnotify->db_notify.pdata)->punread) {
			status = ext_buffer_push_uint8(&ext_push, 1);
			if (EXT_ERR_SUCCESS != status) {
				goto PUSH_NOTIFY_FAILURE;
			}
			status = ext_buffer_push_uint32(&ext_push,
				*((DB_NOTIFY_FOLDER_MODIFIED*)
				pnotify->db_notify.pdata)->punread);
		} else {
			status = ext_buffer_push_uint8(&ext_push, 0);
		}
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_proptag_array(
			&ext_push, &((DB_NOTIFY_FOLDER_MODIFIED*)
			pnotify->db_notify.pdata)->proptags);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_MODIFIED*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_MODIFIED*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_proptag_array(
			&ext_push, &((DB_NOTIFY_MESSAGE_MODIFIED*)
			pnotify->db_notify.pdata)->proptags);
		break;
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->parent_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->old_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_FOLDER_MVCP*)
			pnotify->db_notify.pdata)->old_parent_id);
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->old_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_MESSAGE_MVCP*)
			pnotify->db_notify.pdata)->old_message_id);
		break;
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_SEARCH_COMPLETED*)
			pnotify->db_notify.pdata)->folder_id);
		break;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_CHANGED:
	case DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED:
		break;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_folder_id);
		break;
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->row_instance);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_row_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_ADDED*)
			pnotify->db_notify.pdata)->after_instance);
		break;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_folder_id);
		break;
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_DELETED*)
			pnotify->db_notify.pdata)->row_instance);
		break;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_folder_id);
		break;
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED:
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_message_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->row_instance);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_row_id);
		if (EXT_ERR_SUCCESS != status) {
			goto PUSH_NOTIFY_FAILURE;
		}
		status = ext_buffer_push_uint64(&ext_push,
			((DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED*)
			pnotify->db_notify.pdata)->after_instance);
		break;
	default:
		status = EXT_ERR_BAD_SWITCH;
		break;
	}
	if (EXT_ERR_SUCCESS == status) {
		pbin_out->cb = ext_push.offset;
		pbin_out->pb = ext_push.data;
		*(uint32_t*)pbin_out->pb = ext_push.offset - sizeof(uint32_t);
		return EXT_ERR_SUCCESS;
	}
PUSH_NOTIFY_FAILURE:
	ext_buffer_push_free(&ext_push);
	return status;
}

