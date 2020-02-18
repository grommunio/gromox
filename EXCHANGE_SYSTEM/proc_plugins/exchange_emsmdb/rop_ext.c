#include "emsmdb_interface.h"
#include "rop_processor.h"
#include "logon_object.h"
#include "endian_macro.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include "ext_buffer.h"
#include "lzxpress.h"
#include "rop_ext.h"

static int rop_ext_push_logon_time(EXT_PUSH *pext, const LOGON_TIME *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->second);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->minute);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->hour);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->day_of_week);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->day);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->month);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext, r->year);
}


static int rop_ext_push_ghost_server(EXT_PUSH *pext, const GHOST_SERVER *r)
{
	int i;
	int status;
	
	if (0 == r->server_count || r->cheap_server_count > r->server_count) {
		return EXT_ERR_FORMAT;
	}
	status = ext_buffer_push_uint16(pext, r->server_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->cheap_server_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->server_count; i++) {
		status = ext_buffer_push_string(pext, r->ppservers[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_null_dest_response(
	EXT_PUSH *pext, const NULL_DST_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_push_property_problem(
	EXT_PUSH *pext, const PROPERTY_PROBLEM *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->index);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->err);
}

static int rop_ext_push_problem_array(EXT_PUSH *pext, const PROBLEM_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = rop_ext_push_property_problem(pext, r->pproblem + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_propidname_array(
	EXT_PUSH *pext, const PROPIDNAME_ARRAY *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_uint16(pext, r->ppropid[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_push_property_name(pext, r->ppropname + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_message_read_stat(
	EXT_PULL *pext, MESSAGE_READ_STAT *r)
{
	int status;
	
	status = ext_buffer_pull_sbinary(pext, &r->message_xid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->mark_as_read);
}

static int rop_ext_pull_logon_request(EXT_PULL *pext, LOGON_REQUEST *r)
{
	int status;
	uint16_t size;
	
	status = ext_buffer_pull_uint8(pext, &r->logon_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->open_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->store_stat);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == size) {
		r->pessdn = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pessdn = pext->alloc(size);
	if (NULL == r->pessdn) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_pull_bytes(pext, r->pessdn, size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if ('\0' != r->pessdn[size - 1]) {
		return EXT_ERR_FORMAT;
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_logon_pmb_response(
	EXT_PUSH *pext, const LOGON_PMB_RESPONSE *r)
{
	int i;
	int status;
	
	status = ext_buffer_push_uint8(pext, r->logon_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<13; i++) {
		status = ext_buffer_push_uint64(pext, r->folder_ids[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint8(pext, r->response_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->mailbox_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->replica_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->replica_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = rop_ext_push_logon_time(pext, &r->logon_time);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->gwart_time);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->store_stat);
}

static int rop_ext_push_logon_pf_response(
	EXT_PUSH *pext, const LOGON_PF_RESPONSE *r)
{
	
	int i;
	int status;
	
	status = ext_buffer_push_uint8(pext, r->logon_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<13; i++) {
		status = ext_buffer_push_uint64(pext, r->folder_ids[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ext_buffer_push_uint16(pext, r->replica_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_guid(pext, &r->replica_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_guid(pext, &r->per_user_guid);
}

static int rop_ext_push_logon_redirect_response(
	EXT_PUSH *pext, const LOGON_REDIRECT_RESPONSE *r)
{
	int status;
	uint8_t size;
	
	status = ext_buffer_push_uint8(pext, r->logon_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	size = strlen(r->pserver_name) + 1;
	status = ext_buffer_push_uint8(pext, size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->pserver_name, size);
}

static int rop_ext_pull_getreceivefolder_request(
	EXT_PULL *pext, GETRECEIVEFOLDER_REQUEST *r)
{
	return ext_buffer_pull_string(pext, &r->pstr_class);
}

static int rop_ext_push_getreceivefolder_response(
	EXT_PUSH *pext, const GETRECEIVEFOLDER_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->pstr_class);
}

static int rop_ext_pull_setreceivefolder_request(
	EXT_PULL *pext, SETRECEIVEFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_string(pext, &r->pstr_class);
}

static int rop_ext_push_getreceivefoldertable_response(
	EXT_PUSH *pext, GETRECEIVEFOLDERTABLE_RESPONSE *r)
{
	int i;
	int status;
	PROPTAG_ARRAY columns;
	uint32_t proptags[3] = {PROP_TAG_FOLDERID,
							PROP_TAG_MESSAGECLASS_STRING8,
							PROP_TAG_LASTMODIFICATIONTIME};
	
	columns.count = 3;
	columns.pproptag = proptags;
	status = ext_buffer_push_uint32(pext, r->rows.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->rows.count; i++) {
		status = ext_buffer_push_property_row(
			pext, &columns, &r->rows.prows[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_getstorestat_response(
	EXT_PUSH *pext, const GETSTORESTAT_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->stat);	
}

static int rop_ext_pull_getowningservers_request(
	EXT_PULL *pext, GETOWNINGSERVERS_REQUEST *r)
{
	return ext_buffer_pull_uint64(pext, &r->folder_id);
}

static int rop_ext_push_getowningservers_response(
	EXT_PUSH *pext, const GETOWNINGSERVERS_RESPONSE *r)
{
	return rop_ext_push_ghost_server(pext, &r->ghost);
}

static int rop_ext_pull_publicfolderisghosted_request(
	EXT_PULL *pext, PUBLICFOLDERISGHOSTED_REQUEST *r)
{
	return ext_buffer_pull_uint64(pext, &r->folder_id);
}

static int rop_ext_push_publicfolderisghosted_response(
	EXT_PUSH *pext, const PUBLICFOLDERISGHOSTED_RESPONSE *r)
{
	int status;
	
	if (NULL != r->pghost) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return rop_ext_push_ghost_server(pext, r->pghost);
	} else {
		return ext_buffer_push_uint8(pext, 0);
	}
}

static int rop_ext_pull_longtermidfromid_request(
	EXT_PULL *pext, LONGTERMIDFROMID_REQUEST *r)
{
	return ext_buffer_pull_uint64(pext, &r->id);
}

static int rop_ext_push_longtermidfromid_response(
	EXT_PUSH *pext, const LONGTERMIDFROMID_RESPONSE *r)
{
	return ext_buffer_push_long_term_id(pext, &r->long_term_id);
}

static int rop_ext_pull_idfromlongtermid_request(
	EXT_PULL *pext, IDFROMLONGTERMID_REQUEST *r)
{
	return ext_buffer_pull_long_term_id(pext, &r->long_term_id);
}

static int rop_ext_push_idfromlongtermid_response(
	EXT_PUSH *pext, const IDFROMLONGTERMID_RESPONSE *r)
{
	return ext_buffer_push_uint64(pext, r->id);
}

static int rop_ext_pull_getperuserlongtermids_request(
	EXT_PULL *pext, GETPERUSERLONGTERMIDS_REQUEST *r)
{
	return ext_buffer_pull_guid(pext, &r->guid);
}

static int rop_ext_push_getperuserlongtermids_response(
	EXT_PUSH *pext, const GETPERUSERLONGTERMIDS_RESPONSE *r)
{	
	return ext_buffer_push_long_term_id_array(pext, &r->ids);
}

static int rop_ext_pull_getperuserguid_request(
	EXT_PULL *pext, GETPERUSERGUID_REQUEST *r)
{
	return ext_buffer_pull_long_term_id(pext, &r->long_term_id);
}

static int rop_ext_push_getperuserguid_response(
	EXT_PUSH *pext, const GETPERUSERGUID_RESPONSE *r)
{
	return ext_buffer_push_guid(pext, &r->guid);
}

static int rop_ext_pull_readperuserinformation_request(
	EXT_PULL *pext, READPERUSERINFORMATION_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_long_term_id(pext, &r->long_folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->data_offset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext, &r->max_data_size);
}

static int rop_ext_push_readperuserinformation_response(
	EXT_PUSH *pext, const READPERUSERINFORMATION_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->has_finished);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_sbinary(pext, &r->data);
}

static int rop_ext_pull_writeperuserinformation_request(EXT_PULL *pext,
	WRITEPERUSERINFORMATION_REQUEST *r, BOOL b_private)
{
	int status;
	
	status = ext_buffer_pull_long_term_id(pext, &r->long_folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->has_finished);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->offset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_sbinary(pext, &r->data);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->offset && TRUE == b_private) {
		r->pguid = pext->alloc(sizeof(GUID));
		if (NULL == r->pguid) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_guid(pext, r->pguid);
	}
	r->pguid = NULL;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_openfolder_request(
	EXT_PULL *pext, OPENFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->open_flags);
}

static int rop_ext_push_openfolder_response(
	EXT_PUSH *pext, const OPENFOLDER_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->has_rules);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pghost) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return rop_ext_push_ghost_server(pext, r->pghost);
	} else {
		return ext_buffer_push_uint8(pext, 0);
	}
}

static int rop_ext_pull_createfolder_request(
	EXT_PULL *pext, CREATEFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->folder_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->use_unicode);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->open_existing);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->use_unicode) {
		status = ext_buffer_pull_string(pext, &r->pfolder_name);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_string(pext, &r->pfolder_comment);
	} else {
		status = ext_buffer_pull_wstring(pext, &r->pfolder_name);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_pull_wstring(pext, &r->pfolder_comment);
	}
}

static int rop_ext_push_createfolder_response(
	EXT_PUSH *pext, const CREATEFOLDER_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint64(pext, r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->is_existing);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != r->is_existing) {
		status = ext_buffer_push_uint8(pext, r->has_rules);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (NULL != r->pghost) {
			status = ext_buffer_push_uint8(pext, 1);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
			return rop_ext_push_ghost_server(pext, r->pghost);
		} else {
			return ext_buffer_push_uint8(pext, 0);
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_deletefolder_request(
	EXT_PULL *pext, DELETEFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext, &r->folder_id);
}

static int rop_ext_push_deletefolder_response(
	EXT_PUSH *pext, const DELETEFOLDER_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_setsearchcriteria_request(
	EXT_PULL *pext, SETSEARCHCRITERIA_REQUEST *r)
{
	int status;
	uint32_t offset;
	uint16_t res_size;
	
	status = ext_buffer_pull_uint16(pext, &res_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == res_size) {
		r->pres = NULL;
	} else {
		r->pres = pext->alloc(sizeof(RESTRICTION));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		offset = pext->offset + res_size;
		status = ext_buffer_pull_restriction(pext, r->pres);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (pext->offset > offset) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	status = ext_buffer_pull_slonglong_array(pext, &r->folder_ids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->search_flags);
}

static int rop_ext_pull_getsearchcriteria_request(
	EXT_PULL *pext, GETSEARCHCRITERIA_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->use_unicode);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->include_restriction);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->include_folders);
}

static int rop_ext_push_getsearchcriteria_response(
	EXT_PUSH *pext, const GETSEARCHCRITERIA_RESPONSE *r)
{
	int status;
	uint32_t offset1;
	uint32_t offset2;
	uint16_t res_size;
	
	if (NULL == r->pres) {
		status = ext_buffer_push_uint16(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		offset1 = pext->offset;
		status = ext_buffer_push_advance(pext, sizeof(uint16_t));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_restriction(pext, r->pres);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		res_size = pext->offset - (offset1 + sizeof(uint16_t));
		offset2 = pext->offset;
		pext->offset = offset1;
		status = ext_buffer_push_uint16(pext, res_size);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		pext->offset = offset2;
	}
	status = ext_buffer_push_uint8(pext, r->logon_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_slonglong_array(pext, &r->folder_ids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->search_status);
}

static int rop_ext_pull_movecopymessages_request(
	EXT_PULL *pext, MOVECOPYMESSAGES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_slonglong_array(pext, &r->message_ids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->want_copy);
}

static int rop_ext_push_movecopymessages_response(
	EXT_PUSH *pext, const MOVECOPYMESSAGES_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_movefolder_request(
	EXT_PULL *pext, MOVEFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->use_unicode);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->use_unicode) {
		return ext_buffer_pull_string(pext, &r->pnew_name);
	} else {
		return ext_buffer_pull_wstring(pext, &r->pnew_name);
	}
}

static int rop_ext_push_movefolder_response(
	EXT_PUSH *pext, const MOVEFOLDER_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_copyfolder_request(
	EXT_PULL *pext, COPYFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_recursive);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->use_unicode);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->use_unicode) {
		return ext_buffer_pull_string(pext, &r->pnew_name);
	} else {
		return ext_buffer_pull_wstring(pext, &r->pnew_name);
	}
}

static int rop_ext_push_copyfolder_response(
	EXT_PUSH *pext, const COPYFOLDER_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_emptyfolder_request(
	EXT_PULL *pext, EMPTYFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->want_delete_associated);
}

static int rop_ext_push_emptyfolder_response(
	EXT_PUSH *pext, const EMPTYFOLDER_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_harddeletemessagesandsubfolders_request(
	EXT_PULL *pext, HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->want_delete_associated);
}

static int rop_ext_push_harddeletemessagesandsubfolders_response(
	EXT_PUSH *pext, const HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_deletemessages_request(
	EXT_PULL *pext, DELETEMESSAGES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->notify_non_read);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_slonglong_array(pext, &r->message_ids);
}

static int rop_ext_push_deletemessages_response(
	EXT_PUSH *pext, const DELETEMESSAGES_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_harddeletemessages_request(
	EXT_PULL *pext, HARDDELETEMESSAGES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->notify_non_read);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_slonglong_array(pext, &r->message_ids);
}

static int rop_ext_push_harddeletemessages_response(
	EXT_PUSH *pext, const DELETEMESSAGES_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_gethierarchytable_request(
	EXT_PULL *pext, GETHIERARCHYTABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->table_flags);
}

static int rop_ext_push_gethierarchytable_response(
	EXT_PUSH *pext, const GETHIERARCHYTABLE_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->row_count);
}

static int rop_ext_pull_getcontentstable_request(
	EXT_PULL *pext, GETCONTENTSTABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->table_flags);
}

static int rop_ext_push_getcontentstable_response(
	EXT_PUSH *pext, const GETCONTENTSTABLE_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->row_count);
}

static int rop_ext_pull_setcolumns_request(
	EXT_PULL *pext, SETCOLUMNS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_push_setcolumns_response(
	EXT_PUSH *pext, const SETCOLUMNS_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->table_status);
}

static int rop_ext_pull_sorttable_request(
	EXT_PULL *pext, SORTTABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->table_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_sortorder_set(pext, &r->sort_criteria);
}

static int rop_ext_push_sorttable_response(
	EXT_PUSH *pext, const SORTTABLE_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->table_status);
}

static int rop_ext_pull_restrict_request(
	EXT_PULL *pext, RESTRICT_REQUEST *r)
{
	int status;
	uint32_t offset;
	uint16_t res_size;
	
	status = ext_buffer_pull_uint8(pext, &r->res_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &res_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == res_size) {
		r->pres = NULL;
	} else {
		r->pres = pext->alloc(sizeof(RESTRICTION));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		offset = pext->offset + res_size;
		status = ext_buffer_pull_restriction(pext, r->pres);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (pext->offset > offset) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_restrict_response(
	EXT_PUSH *pext, const RESTRICT_RESPONSE *r)
{	
	return ext_buffer_push_uint8(pext, r->table_status);
}

static int rop_ext_pull_queryrows_request(
	EXT_PULL *pext, QUERYROWS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->forward_read);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext, &r->row_count);
}

static int rop_ext_push_queryrows_response(
	EXT_PUSH *pext, const QUERYROWS_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->seek_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->bin_rows.pb, r->bin_rows.cb);
}

static int rop_ext_push_abort_response(
	EXT_PUSH *pext, const ABORT_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->table_status);
}

static int rop_ext_push_getstatus_response(
	EXT_PUSH *pext, const GETSTATUS_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->table_status);
}

static int rop_ext_push_queryposition_response(
	EXT_PUSH *pext, const QUERYPOSITION_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->numerator);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->denominator);
}

static int rop_ext_pull_seekrow_request(EXT_PULL *pext, SEEKROW_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->seek_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->offset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->want_moved_count);
}

static int rop_ext_push_seekrow_response(
	EXT_PUSH *pext, const SEEKROW_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->has_soughtless);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_int32(pext, r->offset_sought);
}

static int rop_ext_pull_seekrowbookmark_request(
	EXT_PULL *pext, SEEKROWBOOKMARK_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_sbinary(pext, &r->bookmark);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_int32(pext, &r->offset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->want_moved_count);
}

static int rop_ext_push_seekrowbookmark_response(
	EXT_PUSH *pext, const SEEKROWBOOKMARK_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->row_invisible);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->has_soughtless);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->offset_sought);
}

static int rop_ext_pull_seekrowfractional_request(
	EXT_PULL *pext, SEEKROWFRACTIONAL_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->numerator);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->denominator);
}

static int rop_ext_push_createbookmark_response(
	EXT_PUSH *pext, const CREATEBOOKMARK_RESPONSE *r)
{
	return ext_buffer_push_sbinary(pext, &r->bookmark);
}

static int rop_ext_push_querycolumnsall_response(
	EXT_PUSH *pext, const QUERYCOLUMNSALL_RESPONSE *r)
{
	return ext_buffer_push_proptag_array(pext, &r->proptags);
}

static int rop_ext_pull_findrow_request(EXT_PULL *pext, FINDROW_REQUEST *r)
{
	int status;
	uint32_t offset;
	uint16_t res_size;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &res_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == res_size) {
		r->pres = NULL;
	} else {
		r->pres = pext->alloc(sizeof(RESTRICTION));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		offset = pext->offset + res_size;
		status = ext_buffer_pull_restriction(pext, r->pres);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (pext->offset > offset) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	status = ext_buffer_pull_uint8(pext, &r->seek_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_sbinary(pext, &r->bookmark);
}

static int rop_ext_push_findrow_response(
	EXT_PUSH *pext, const FINDROW_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->bookmark_invisible);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prow) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_property_row(
					pext, r->pcolumns, r->prow);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return EXT_ERR_SUCCESS;
	} else {
		return ext_buffer_push_uint8(pext, 0);
	}
}

static int rop_ext_pull_freebookmark_request(EXT_PULL *pext,
	FREEBOOKMARK_REQUEST *r)
{
	return ext_buffer_pull_sbinary(pext, &r->bookmark);
}

static int rop_ext_pull_expandrow_request(EXT_PULL *pext,
	EXPANDROW_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->max_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext, &r->category_id);
}

static int rop_ext_push_expandrow_response(
	EXT_PUSH *pext, const EXPANDROW_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->expanded_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->bin_rows.pb, r->bin_rows.cb);
}

static int rop_ext_pull_collapserow_request(EXT_PULL *pext,
	COLLAPSEROW_REQUEST *r)
{
	return ext_buffer_pull_uint64(pext, &r->category_id);
}

static int rop_ext_push_collapserow_response(EXT_PUSH *pext,
	const COLLAPSEROW_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->collapsed_count);
}

static int rop_ext_pull_getcollapsestate_request(EXT_PULL *pext,
	GETCOLLAPSESTATE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->row_instance);
}

static int rop_ext_push_getcollapsestate_response(EXT_PUSH *pext,
	const GETCOLLAPSESTATE_RESPONSE *r)
{
	return ext_buffer_push_sbinary(pext, &r->collapse_state);
}

static int rop_ext_pull_setcollapsestate_request(EXT_PULL *pext,
	SETCOLLAPSESTATE_REQUEST *r)
{
	return ext_buffer_pull_sbinary(pext, &r->collapse_state);
}

static int rop_ext_push_setcollapsestate_response(EXT_PUSH *pext,
	const SETCOLLAPSESTATE_RESPONSE *r)
{
	return ext_buffer_push_sbinary(pext, &r->bookmark);
}

static int rop_ext_pull_openmessage_request(
	EXT_PULL *pext, OPENMESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->open_mode_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext, &r->message_id);
}

static int rop_ext_push_openmessage_response(
	EXT_PUSH *pext, const OPENMESSAGE_RESPONSE *r)
{
	uint8_t i;
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint32_t last_offset;
	
	status = ext_buffer_push_uint8(pext, r->has_named_properties);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_typed_string(pext, &r->subject_prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_typed_string(pext, &r->normalized_subject);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->recipient_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext, &r->recipient_columns);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->row_count) {
		return ext_buffer_push_uint8(pext, 0);
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint8_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->row_count; i++) {
		last_offset = pext->offset;
		status = ext_buffer_push_openrecipient_row(pext,
			&r->recipient_columns, &r->precipient_row[i]);
		if (EXT_ERR_SUCCESS != status ||
			pext->alloc_size - pext->offset < 256) {
			pext->offset = last_offset;
			break;
		}
	}
	if (0 == i) {
		return status;
	}
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint8(pext, i);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_createmessage_request(
	EXT_PULL *pext, CREATEMESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->associated_flag);
}

static int rop_ext_push_createmessage_response(
	EXT_PUSH *pext, CREATEMESSAGE_RESPONSE *r)
{
	int status;
	
	if (NULL != r->pmessage_id) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_uint64(pext, *r->pmessage_id);
	} else {
		return ext_buffer_push_uint8(pext, 0);
	}
}

static int rop_ext_pull_savechangesmessage_request(
	EXT_PULL *pext, SAVECHANGESMESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->save_flags);
}

static int rop_ext_push_savechangesmessage_response(
	EXT_PUSH *pext, const SAVECHANGESMESSAGE_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext, r->message_id);
}

static int rop_ext_pull_removeallrecipients_request(
	EXT_PULL *pext, REMOVEALLRECIPIENTS_REQUEST *r)
{
	return ext_buffer_pull_uint32(pext, &r->reserved);
}

static int rop_ext_pull_modifyrecipients_request(
	EXT_PULL *pext, MODIFYRECIPIENTS_REQUEST *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_proptag_array(pext, &r->proptags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->prow = NULL;
	} else {
		r->prow = pext->alloc(sizeof(MODIFYRECIPIENT_ROW)*r->count);
		if (NULL == r->prow) {
			return EXT_ERR_ALLOC;
		}
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_modifyrecipient_row(
					pext, &r->proptags, r->prow + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_readrecipients_request(
	EXT_PULL *pext, READRECIPIENTS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->row_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext, &r->reserved);
}

static int rop_ext_push_readrecipients_response(
	EXT_PUSH *pext, READRECIPIENTS_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext,
		r->bin_recipients.pb, r->bin_recipients.cb);
}

static int rop_ext_pull_reloadcachedinformation_request(
	EXT_PULL *pext, RELOADCACHEDINFORMATION_REQUEST *r)
{
	return ext_buffer_pull_uint16(pext, &r->reserved);
}

static int rop_ext_push_reloadcachedinformation_response(
	EXT_PUSH *pext, RELOADCACHEDINFORMATION_RESPONSE *r)
{
	uint8_t i;
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint32_t last_offset;
	
	status = ext_buffer_push_uint8(pext, r->has_named_properties);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_typed_string(pext, &r->subject_prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_typed_string(pext, &r->normalized_subject);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->recipient_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext, &r->recipient_columns);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->row_count) {
		return ext_buffer_push_uint8(pext, 0);
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint8_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->row_count; i++) {
		last_offset = pext->offset;
		status = ext_buffer_push_openrecipient_row(pext,
			&r->recipient_columns, &r->precipient_row[i]);
		if (EXT_ERR_SUCCESS != status ||
			pext->alloc_size - pext->offset < 256) {
			pext->offset = last_offset;
			break;
		}
	}
	if (0 == i) {
		return status;
	}
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint8(pext, i);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_setmessagestatus_request(
	EXT_PULL *pext, SETMESSAGESTATUS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->message_status);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->status_mask);
}

static int rop_ext_push_setmessagestatus_response(
	EXT_PUSH *pext, const SETMESSAGESTATUS_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->message_status);
}

static int rop_ext_pull_getmessagestatus_request(
	EXT_PULL *pext, GETMESSAGESTATUS_REQUEST *r)
{
	return ext_buffer_pull_uint64(pext, &r->message_id);
}

static int rop_ext_push_getmessagestatus_response(
	EXT_PUSH *pext, const GETMESSAGESTATUS_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->message_status);
}

static int rop_ext_pull_setreadflags_request(
	EXT_PULL *pext, SETREADFLAGS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->read_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_slonglong_array(pext, &r->message_ids);
}

static int rop_ext_push_setreadflags_response(
	EXT_PUSH *pext, const SETREADFLAGS_RESPONSE *r)
{
	return ext_buffer_push_uint8(pext, r->partial_completion);
}

static int rop_ext_pull_setmessagereadflag_request(EXT_PULL *pext,
	SETMESSAGEREADFLAG_REQUEST *r, BOOL b_private)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (TRUE == b_private) {
		r->pclient_data = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		r->pclient_data = pext->alloc(sizeof(LONG_TERM_ID));
		if (NULL == r->pclient_data) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_long_term_id(pext, r->pclient_data);
	}
}

static int rop_ext_push_setmessagereadflag_response(
	EXT_PUSH *pext, const SETMESSAGEREADFLAG_RESPONSE *r)
{
	int status;
	
	if (0 != r->read_changed && NULL != r->pclient_data) {
		status = ext_buffer_push_uint8(pext, 1);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		status = ext_buffer_push_uint8(pext, r->logon_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_long_term_id(pext, r->pclient_data);
	}
	return ext_buffer_push_uint8(pext, 0);
}

static int rop_ext_pull_openattachment_request(
	EXT_PULL *pext, OPENATTACHMENT_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->attachment_id);
}

static int rop_ext_pull_createattachment_request(
	EXT_PULL *pext, CREATEATTACHMENT_REQUEST *r)
{
	return ext_buffer_pull_uint8(pext, &r->hindex);
}

static int rop_ext_push_createattachment_response(
	EXT_PUSH *pext, const CREATEATTACHMENT_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->attachment_id);
}

static int rop_ext_pull_deleteattachment_request(
	EXT_PULL *pext, DELETEATTACHMENT_REQUEST *r)
{
	return ext_buffer_pull_uint32(pext, &r->attachment_id);
}

static int rop_ext_pull_savechangesattachment_request(
	EXT_PULL *pext, SAVECHANGESATTACHMENT_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->save_flags);
}

static int rop_ext_pull_openembeddedmessage_request(
	EXT_PULL *pext, OPENEMBEDDEDMESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->open_embedded_flags);
}

static int rop_ext_push_openembeddedmessage_response(
	EXT_PUSH *pext, const OPENEMBEDDEDMESSAGE_RESPONSE *r)
{
	int i;
	int status;
	uint32_t offset;
	uint32_t offset1;
	uint32_t last_offset;
	
	status = ext_buffer_push_uint8(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->has_named_properties);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_typed_string(pext, &r->subject_prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_typed_string(pext, &r->normalized_subject);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->recipient_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_proptag_array(pext, &r->recipient_columns);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->row_count) {
		return ext_buffer_push_uint8(pext, 0);
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint8_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->row_count; i++) {
		last_offset = pext->offset;
		status = ext_buffer_push_openrecipient_row(pext,
			&r->recipient_columns, &r->precipient_row[i]);
		if (EXT_ERR_SUCCESS != status ||
			pext->alloc_size - pext->offset < 256) {
			pext->offset = last_offset;
			break;
		}
	}
	if (0 == i) {
		return status;
	}
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint8(pext, i);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_getattachmenttable_request(
	EXT_PULL *pext, GETATTACHMENTTABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->table_flags);
}

static int rop_ext_push_getvalidattachments_response(
	EXT_PUSH *pext, const GETVALIDATTACHMENTS_RESPONSE *r)
{	
	return ext_buffer_push_long_array(pext, &r->attachment_ids);
}

static int rop_ext_pull_submitmessage_request(
	EXT_PULL *pext, SUBMITMESSAGE_REQUEST *r)
{
	return ext_buffer_pull_uint8(pext, &r->submit_flags);
}

static int rop_ext_pull_abortsubmit_request(
	EXT_PULL *pext, ABORTSUBMIT_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext, &r->message_id);
}


static int rop_ext_push_getaddresstypes_response(
	EXT_PUSH *pext, const GETADDRESSTYPES_RESPONSE *r)
{
	int i;
	int status;
	uint16_t size;
	uint32_t offset;
	uint32_t offset1;
	
	status = ext_buffer_push_uint16(pext, r->address_types.count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset;
	status = ext_buffer_push_advance(pext, sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<r->address_types.count; i++) {
		status = ext_buffer_push_string(pext, r->address_types.ppstr[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	size = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	status = ext_buffer_push_uint16(pext, size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	pext->offset = offset1;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_spoolerlockmessage_request(
	EXT_PULL *pext, SPOOLERLOCKMESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->lock_stat);
}

static int rop_ext_push_transportsend_response(
	EXT_PUSH *pext, const TRANSPORTSEND_RESPONSE *r)
{
	int status;
	
	if (NULL == r->ppropvals) {
		return ext_buffer_push_uint8(pext, 1);
	} else {
		status = ext_buffer_push_uint8(pext, 0);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		return ext_buffer_push_tpropval_array(pext, r->ppropvals);
	}
}

static int rop_ext_pull_transportnewmail_request(
	EXT_PULL *pext, TRANSPORTNEWMAIL_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_string(pext, &r->pstr_class);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->message_flags);
}

static int rop_ext_push_gettransportfolder_response(
	EXT_PUSH *pext, const GETTRANSPORTFOLDER_RESPONSE *r)
{
	return ext_buffer_push_uint64(pext, r->folder_id);
}

static int rop_ext_pull_optionsdata_request(
	EXT_PULL *pext, OPTIONSDATA_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_string(pext, &r->paddress_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->want_win32);
}

static int rop_ext_push_optionsdata_response(
	EXT_PUSH *pext, const OPTIONSDATA_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_sbinary(pext, &r->options_info);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_sbinary(pext, &r->help_file);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (r->help_file.cb > 0) {
		return ext_buffer_push_string(pext, r->pfile_name);
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_getpropertyidsfromnames_request(
	EXT_PULL *pext, GETPROPERTYIDSFROMNAMES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_propname_array(pext, &r->propnames);
}

static int rop_ext_push_getpropertyidsfromnames_response(
	EXT_PUSH *pext, const GETPROPERTYIDSFROMNAMES_RESPONSE *r)
{
	return ext_buffer_push_propid_array(pext, &r->propids);
}

static int rop_ext_pull_getnamesfrompropertyids_request(
	EXT_PULL *pext, GETNAMESFROMPROPERTYIDS_REQUEST *r)
{
	return ext_buffer_pull_propid_array(pext, &r->propids);
}

static int rop_ext_push_getnamesfrompropertyids_response(
	EXT_PUSH *pext, const GETNAMESFROMPROPERTYIDS_RESPONSE *r)
{
	return ext_buffer_push_propname_array(pext, &r->propnames);
}

static int rop_ext_pull_getpropertiesspecific_request(
	EXT_PULL *pext, GETPROPERTIESSPECIFIC_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->size_limit);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->want_unicode);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_push_getpropertiesspecific_response(
	EXT_PUSH *pext, const GETPROPERTIESSPECIFIC_RESPONSE *r)
{
	return ext_buffer_push_property_row(pext, r->pproptags, &r->row);
}

static int rop_ext_pull_getpropertiesall_request(
	EXT_PULL *pext, GETPROPERTIESALL_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->size_limit);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint16(pext, &r->want_unicode);
}

static int rop_ext_push_getpropertiesall_response(
	EXT_PUSH *pext, const GETPROPERTIESALL_RESPONSE *r)
{
	return ext_buffer_push_tpropval_array(pext, &r->propvals);
}

static int rop_ext_push_getpropertieslist_response(
	EXT_PUSH *pext, const GETPROPERTIESLIST_RESPONSE *r)
{
	return ext_buffer_push_proptag_array(pext, &r->proptags);
}

static int rop_ext_pull_setproperties_request(
	EXT_PULL *pext, SETPROPERTIES_REQUEST *r)
{
	int status;
	uint16_t size;
	uint32_t offset;
	
	status = ext_buffer_pull_uint16(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + size;
	status = ext_buffer_pull_tpropval_array(pext, &r->propvals);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_setproperties_response(
	EXT_PUSH *pext, const SETPROPERTIES_RESPONSE *r)
{
	return rop_ext_push_problem_array(pext, &r->problems);
}

static int rop_ext_pull_setpropertiesnoreplicate_request(
	EXT_PULL *pext, SETPROPERTIESNOREPLICATE_REQUEST *r)
{
	int status;
	uint16_t size;
	uint32_t offset;
	
	status = ext_buffer_pull_uint16(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + size;
	status = ext_buffer_pull_tpropval_array(pext, &r->propvals);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_push_setpropertiesnoreplicate_response(
	EXT_PUSH *pext, const SETPROPERTIESNOREPLICATE_RESPONSE *r)
{
	return rop_ext_push_problem_array(pext, &r->problems);
}

static int rop_ext_pull_deleteproperties_request(
	EXT_PULL *pext,	DELETEPROPERTIES_REQUEST *r)
{
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_push_deleteproperties_response(
	EXT_PUSH *pext, const DELETEPROPERTIES_RESPONSE *r)
{
	return rop_ext_push_problem_array(pext, &r->problems);
}

static int rop_ext_pull_deletepropertiesnoreplicate_request(
	EXT_PULL *pext, DELETEPROPERTIESNOREPLICATE_REQUEST *r)
{
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_push_deletepropertiesnoreplicate_response(
	EXT_PUSH *pext, const DELETEPROPERTIESNOREPLICATE_RESPONSE *r)
{
	return rop_ext_push_problem_array(pext, &r->problems);
}

static int rop_ext_pull_querynamedproperties_request(
	EXT_PULL *pext, QUERYNAMEDPROPERTIES_REQUEST *r)
{
	int status;
	uint8_t has_guid;
	
	status = ext_buffer_pull_uint8(pext, &r->query_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &has_guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == has_guid) {
		r->pguid = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pguid = pext->alloc(sizeof(GUID));
	if (NULL == r->pguid) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_guid(pext, r->pguid);
}

static int rop_ext_push_querynamedproperties_response(
	EXT_PUSH *pext, QUERYNAMEDPROPERTIES_RESPONSE *r)
{
	return rop_ext_push_propidname_array(pext, &r->propidnames);
}

static int rop_ext_pull_copyproperties_request(
	EXT_PULL *pext, COPYPROPERTIES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->copy_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_push_copyproperties_response(
	EXT_PUSH *pext, const COPYPROPERTIES_RESPONSE *r)
{
	return rop_ext_push_problem_array(pext, &r->problems);
}

static int rop_ext_pull_copyto_request(EXT_PULL *pext, COPYTO_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_asynchronous);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_subobjects);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->copy_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->excluded_proptags);
}

static int rop_ext_push_copyto_response(EXT_PUSH *pext,
	const COPYTO_RESPONSE *r)
{
	return rop_ext_push_problem_array(pext, &r->problems);
}

static int rop_ext_pull_progress_request(EXT_PULL *pext,
	PROGRESS_REQUEST *r)
{
	return ext_buffer_pull_uint8(pext, &r->want_cancel);
}

static int rop_ext_push_progress_response(
	EXT_PUSH *pext, const PROGRESS_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, r->logon_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->completed_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint32(pext, r->total_count);
}

static int rop_ext_pull_openstream_request(
	EXT_PULL *pext, OPENSTREAM_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->proptag);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->flags);
}

static int rop_ext_push_openstream_response(
	EXT_PUSH *pext, const OPENSTREAM_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->stream_size);
}

static int rop_ext_pull_readstream_request(
	EXT_PULL *pext, READSTREAM_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->byte_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0xBABE == r->byte_count) {
		return ext_buffer_pull_uint32(pext, &r->max_byte_count);
	} else {
		r->max_byte_count = 0;
		return EXT_ERR_SUCCESS;
	}
}

static int rop_ext_push_readstream_response(
	EXT_PUSH *pext, const READSTREAM_RESPONSE *r)
{
	return ext_buffer_push_sbinary(pext, &r->data);
}

static int rop_ext_pull_writestream_request(
	EXT_PULL *pext, WRITESTREAM_REQUEST *r)
{
	return ext_buffer_pull_sbinary(pext, &r->data);
}

static int rop_ext_push_writestream_response(
	EXT_PUSH *pext, const WRITESTREAM_RESPONSE *r)
{
	return ext_buffer_push_uint16(pext, r->written_size);
}

static int rop_ext_push_getstreamsize_response(
	EXT_PUSH *pext, const GETSTREAMSIZE_RESPONSE *r)
{
	return ext_buffer_push_uint32(pext, r->stream_size);
}

static int rop_ext_pull_setstreamsize_request(
	EXT_PULL *pext, SETSTREAMSIZE_REQUEST *r)
{
	return ext_buffer_pull_uint64(pext, &r->stream_size);
}

static int rop_ext_pull_seekstream_request(
	EXT_PULL *pext, SEEKSTREAM_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->seek_pos);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_int64(pext, &r->offset);
}

static int rop_ext_push_seekstream_response(
	EXT_PUSH *pext, const SEEKSTREAM_RESPONSE *r)
{
	return ext_buffer_push_uint64(pext, r->new_pos);
}

static int rop_ext_pull_copytostream_request(
	EXT_PULL *pext, COPYTOSTREAM_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint64(pext, &r->byte_count);
}

static int rop_ext_push_copytostream_response(
	EXT_PUSH *pext, const COPYTOSTREAM_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint64(pext, r->read_bytes);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext, r->written_bytes);
}

static int rop_ext_push_copytostream_null_dest_response(
	EXT_PUSH *pext, const COPYTOSTREAM_NULL_DEST_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint32(pext, r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint64(pext, r->read_bytes);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint64(pext, r->written_bytes);
}

static int rop_ext_pull_lockregionstream_request(
	EXT_PULL *pext, LOCKREGIONSTREAM_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->region_offset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->region_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->lock_flags);
}

static int rop_ext_pull_unlockregionstream_request(
	EXT_PULL *pext, UNLOCKREGIONSTREAM_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint64(pext, &r->region_offset);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint64(pext, &r->region_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->lock_flags);
}

static int rop_ext_pull_writeandcommitstream_request(
	EXT_PULL *pext, WRITEANDCOMMITSTREAM_REQUEST *r)
{
	return ext_buffer_pull_sbinary(pext, &r->data);
}

static int rop_ext_push_writeandcommitstream_response(
	EXT_PUSH *pext, const WRITEANDCOMMITSTREAM_RESPONSE *r)
{
	return ext_buffer_push_uint16(pext, r->written_size);
}

static int rop_ext_pull_clonestream_request(
	EXT_PULL *pext, CLONESTREAM_REQUEST *r)
{
	return ext_buffer_pull_uint8(pext, &r->hindex);
}

static int rop_ext_pull_modifypermissions_request(
	EXT_PULL *pext, MODIFYPERMISSIONS_REQUEST *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		r->prow = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->prow = pext->alloc(sizeof(PERMISSION_DATA)*r->count);
	if (NULL == r->prow) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_permission_data(pext, r->prow + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_getpermissionstable_request(
	EXT_PULL *pext, GETPERMISSIONSTABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->flags);
}

static int rop_ext_pull_modifyrules_request(
	EXT_PULL *pext, MODIFYRULES_REQUEST *r)
{
	int i;
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->prow = pext->alloc(sizeof(RULE_DATA)*r->count);
	if (NULL == r->prow) {
		return EXT_ERR_SUCCESS;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_rule_data(pext, r->prow + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_getrulestable_request(
	EXT_PULL *pext, GETRULESTABLE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->flags);
}

static int rop_ext_pull_updatedeferredactionmessages_request(
	EXT_PULL *pext, UPDATEDEFERREDACTIONMESSAGES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_sbinary(pext, &r->server_entry_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_sbinary(pext, &r->client_entry_id);
}

static int rop_ext_pull_fasttransferdestconfigure_request(
	EXT_PULL *pext, FASTTRANSFERDESTCONFIGURE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->source_operation);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->flags);
}

static int rop_ext_pull_fasttransferdestputbuffer_request(
	EXT_PULL *pext, FASTTRANSFERDESTPUTBUFFER_REQUEST *r)
{
	return ext_buffer_pull_sbinary(pext, &r->transfer_data);	
}

static int rop_ext_push_fasttransferdestputbuffer_response(
	EXT_PUSH *pext,	const FASTTRANSFERDESTPUTBUFFER_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->transfer_status);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->in_progress_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->total_step_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext, r->used_size);
}

static int rop_ext_pull_fasttransfersourcegetbuffer_request(
	EXT_PULL *pext, FASTTRANSFERSOURCEGETBUFFER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint16(pext, &r->buffer_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0xBABE == r->buffer_size) {
		return ext_buffer_pull_uint16(pext, &r->max_buffer_size);
	} else {
		r->max_buffer_size = 0;
		return EXT_ERR_SUCCESS;
	}
}

static int rop_ext_push_fasttransfersourcegetbuffer_response(
	EXT_PUSH *pext, const FASTTRANSFERSOURCEGETBUFFER_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->transfer_status);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->in_progress_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->total_step_count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_sbinary(pext, &r->transfer_data);
}

static int rop_ext_pull_fasttransfersourcecopyfolder_request(
	EXT_PULL *pext, FASTTRANSFERSOURCECOPYFOLDER_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->send_options);
}

static int rop_ext_pull_fasttransfersourcecopymessages_request(
	EXT_PULL *pext, FASTTRANSFERSOURCECOPYMESSAGES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_slonglong_array(pext, &r->message_ids);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->send_options);
}

static int rop_ext_pull_fasttransfersourcecopyto_request(
	EXT_PULL *pext, FASTTRANSFERSOURCECOPYTO_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->level);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint32(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->send_options);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_pull_fasttransfersourcecopyproperties_request(
	EXT_PULL *pext, FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->level);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->send_options);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_pull_tellversion_request(
	EXT_PULL *pext, TELLVERSION_REQUEST *r)
{
	int i;
	int status;
	
	for (i=0; i<3; i++) {
		status = ext_buffer_pull_uint16(pext, r->version + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_syncconfigure_request(
	EXT_PULL *pext, SYNCCONFIGURE_REQUEST *r)
{
	int status;
	uint32_t offset;
	uint16_t res_size;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->sync_type);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->send_options);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &r->sync_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint16(pext, &res_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == res_size) {
		r->pres = NULL;
	} else {
		r->pres = pext->alloc(sizeof(RESTRICTION));
		if (NULL == r->pres) {
			return EXT_ERR_ALLOC;
		}
		offset = pext->offset + res_size;
		status = ext_buffer_pull_restriction(pext, r->pres);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (pext->offset > offset) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	status = ext_buffer_pull_uint32(pext, &r->extra_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_proptag_array(pext, &r->proptags);
}

static int rop_ext_pull_syncimportmessagechange_request(
	EXT_PULL *pext, SYNCIMPORTMESSAGECHANGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->import_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

static int rop_ext_push_syncimportmessagechange_response(
	EXT_PUSH *pext, const SYNCIMPORTMESSAGECHANGE_RESPONSE *r)
{
	return ext_buffer_push_uint64(pext, r->message_id);
}

static int rop_ext_pull_syncimportreadstatechanges_request(
	EXT_PULL *pext, SYNCIMPORTREADSTATECHANGES_REQUEST *r)
{
	int status;
	uint16_t size;
	uint32_t offset;
	MESSAGE_READ_STAT tmp_array[0x1000];
	
	status = ext_buffer_pull_uint16(pext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == size) {
		return EXT_ERR_FORMAT;
	}
	r->count = 0;
	offset = pext->offset + size;
	while (pext->offset < offset && r->count < 0x1000) {
		status = rop_ext_pull_message_read_stat(pext, tmp_array + r->count);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->count ++;
	}
	if (pext->offset != offset) {
		return EXT_ERR_FORMAT;
	}
	r->pread_stat = pext->alloc(sizeof(MESSAGE_READ_STAT)*r->count);
	if (NULL == r->pread_stat) {
		return EXT_ERR_ALLOC;
	}
	memcpy(r->pread_stat, tmp_array, sizeof(MESSAGE_READ_STAT)*r->count);
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_syncimporthierarchychange_request(
	EXT_PULL *pext, SYNCIMPORTHIERARCHYCHANGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_tpropval_array(pext, &r->hichyvals);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

static int rop_ext_push_syncimporthierarchychange_response(
	EXT_PUSH *pext, const SYNCIMPORTHIERARCHYCHANGE_RESPONSE *r)
{
	return ext_buffer_push_uint64(pext, r->folder_id);
}

static int rop_ext_pull_syncimportdeletes_request(
	EXT_PULL *pext, SYNCIMPORTDELETES_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_tpropval_array(pext, &r->propvals);
}

static int rop_ext_pull_syncimportmessagemove_request(
	EXT_PULL *pext, SYNCIMPORTMESSAGEMOVE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_exbinary(pext, &r->src_folder_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_exbinary(pext, &r->src_message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_exbinary(pext, &r->change_list);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_exbinary(pext, &r->dst_message_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_exbinary(pext, &r->change_number);
}

static int rop_ext_push_syncimportmessagemove_response(
	EXT_PUSH *pext, const SYNCIMPORTMESSAGEMOVE_RESPONSE *r)
{
	return ext_buffer_push_uint64(pext, r->message_id);
}

static int rop_ext_pull_syncopencollector_request(
	EXT_PULL *pext, SYNCOPENCOLLECTOR_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint8(pext, &r->is_content_collector);
}

static int rop_ext_pull_syncgettransferstate_request(
	EXT_PULL *pext, SYNCGETTRANSFERSTATE_REQUEST *r)
{
	return ext_buffer_pull_uint8(pext, &r->hindex);
}

static int rop_ext_pull_syncuploadstatestreambegin_request(
	EXT_PULL *pext, SYNCUPLOADSTATESTREAMBEGIN_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint32(pext, &r->proptag_stat);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_pull_uint32(pext, &r->buffer_size);
}

static int rop_ext_pull_syncuploadstatestreamcontinue_request(
	EXT_PULL *pext, SYNCUPLOADSTATESTREAMCONTINUE_REQUEST *r)
{
	return ext_buffer_pull_exbinary(pext, &r->stream_data);
}

static int rop_ext_pull_setlocalreplicamidsetdeleted_request(
	EXT_PULL *pext, SETLOCALREPLICAMIDSETDELETED_REQUEST *r)
{
	int i;
	int status;
	uint32_t offset;
	uint16_t data_size;
	
	status = ext_buffer_pull_uint16(pext, &data_size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	offset = pext->offset + data_size;
	status = ext_buffer_pull_uint32(pext, &r->count);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == r->count) {
		return EXT_ERR_FORMAT;
	}
	r->prange = pext->alloc(sizeof(LONG_TERM_ID_RANGE)*r->count);
	if (NULL == r->prange) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		status = ext_buffer_pull_long_term_id_rang(pext, r->prange + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (pext->offset > offset) {
		return EXT_ERR_FORMAT;
	}
	pext->offset = offset;
	return EXT_ERR_SUCCESS;
}

static int rop_ext_pull_getlocalreplicaids_request(
	EXT_PULL *pext, GETLOCALREPLICAIDS_REQUEST *r)
{
	return ext_buffer_pull_uint32(pext, &r->count);	
}

static int rop_ext_push_getlocalreplicaids_response(
	EXT_PUSH *pext, const GETLOCALREPLICAIDS_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_guid(pext, &r->guid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bytes(pext, r->global_count, 6);
}

static int rop_ext_pull_registernotification_request(
	EXT_PULL *pext, REGISTERNOTIFICATION_REQUEST *r)
{
	int status;
	
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->notification_types);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->reserved);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->want_whole_store);
	if (0 == r->want_whole_store) {
		r->pfolder_id = pext->alloc(sizeof(uint64_t));
		if (NULL == r->pfolder_id) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_pull_uint64(pext, r->pfolder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		r->pmessage_id = pext->alloc(sizeof(uint64_t));
		if (NULL == r->pmessage_id) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint64(pext, r->pmessage_id);
	} else {
		r->pfolder_id = NULL;
		r->pmessage_id = NULL;
		return EXT_ERR_SUCCESS;
	}
}

static int rop_ext_push_notification_data(
	EXT_PUSH *pext, const NOTIFICATION_DATA *r)
{
	int status;
	
	status = ext_buffer_push_uint16(pext, r->notification_flags);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->ptable_event) {
		status = ext_buffer_push_uint16(pext, *r->ptable_event);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->prow_folder_id) {
		status = ext_buffer_push_uint64(pext, *r->prow_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->prow_message_id) {
		status = ext_buffer_push_uint64(pext, *r->prow_message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->prow_instance) {
		status = ext_buffer_push_uint32(pext, *r->prow_instance);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pafter_folder_id) {
		status = ext_buffer_push_uint64(pext, *r->pafter_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pafter_row_id) {
		status = ext_buffer_push_uint64(pext, *r->pafter_row_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pafter_instance) {
		status = ext_buffer_push_uint32(pext, *r->pafter_instance);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->prow_data) {
		status = ext_buffer_push_sbinary(pext, r->prow_data);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pfolder_id) {
		status = ext_buffer_push_uint64(pext, *r->pfolder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pmessage_id) {
		status = ext_buffer_push_uint64(pext, *r->pmessage_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pparent_id) {
		status = ext_buffer_push_uint64(pext, *r->pparent_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pold_folder_id) {
		status = ext_buffer_push_uint64(pext, *r->pold_folder_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pold_message_id) {
		status = ext_buffer_push_uint64(pext, *r->pold_message_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pold_parent_id) {
		status = ext_buffer_push_uint64(pext, *r->pold_parent_id);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pproptags) {
		status = ext_buffer_push_proptag_array(pext, r->pproptags);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->ptotal_count) {
		status = ext_buffer_push_uint32(pext, *r->ptotal_count);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->punread_count) {
		status = ext_buffer_push_uint32(pext, *r->punread_count);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->pmessage_flags) {
		status = ext_buffer_push_uint32(pext, *r->pmessage_flags);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (NULL != r->punicode_flag) {
		status = ext_buffer_push_uint8(pext, *r->punicode_flag);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		if (0 == *r->punicode_flag) {
			status = ext_buffer_push_string(pext, r->pstr_class);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		} else {
			status = ext_buffer_push_wstring(pext, r->pstr_class);
			if (EXT_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return EXT_ERR_SUCCESS;
}

int rop_ext_push_notify_response(EXT_PUSH *pext,
	const NOTIFY_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, ROP_ID_NOTIFY);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->handle);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint8(pext, r->logon_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return rop_ext_push_notification_data(pext, &r->notification_data);
}

int rop_ext_push_pending_response(EXT_PUSH *pext,
	const PENDING_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, ROP_ID_PENDING);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_uint16(pext, r->session_index);
}

int rop_ext_push_buffertoosmall_response(EXT_PUSH *pext,
	const BUFFERTOOSMALL_RESPONSE *r)
{
	int status;
	
	status = ext_buffer_push_uint8(pext, ROP_ID_BUFFERTOOSMALL);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint16(pext, r->size_needed);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_sbinary(pext, &r->buffer);
}
	
static int rop_ext_pull_rop_request(EXT_PULL *pext, ROP_REQUEST *r)
{
	int status;
	LOGON_OBJECT *plogon;
	EMSMDB_INFO *pemsmdb_info;
	
	r->bookmark.pb = (uint8_t*)pext->data + pext->offset;
	r->bookmark.cb = pext->data_size - pext->offset;
	status = ext_buffer_pull_uint8(pext, &r->rop_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->logon_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_pull_uint8(pext, &r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	r->ppayload = NULL;
	
	switch (r->rop_id) {
	case ROP_ID_LOGON:
		r->ppayload = pext->alloc(sizeof(LOGON_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_logon_request(pext, r->ppayload);
	case ROP_ID_GETRECEIVEFOLDER:
		r->ppayload = pext->alloc(sizeof(GETRECEIVEFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getreceivefolder_request(pext, r->ppayload);
	case ROP_ID_SETRECEIVEFOLDER:
		r->ppayload = pext->alloc(sizeof(SETRECEIVEFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setreceivefolder_request(pext, r->ppayload);
	case ROP_ID_GETRECEIVEFOLDERTABLE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETSTORESTAT:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETOWNINGSERVERS:
		r->ppayload = pext->alloc(sizeof(GETOWNINGSERVERS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getowningservers_request(pext, r->ppayload);
	case ROP_ID_PUBLICFOLDERISGHOSTED:
		r->ppayload = pext->alloc(sizeof(PUBLICFOLDERISGHOSTED_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_publicfolderisghosted_request(pext, r->ppayload);
	case ROP_ID_LONGTERMIDFROMID:
		r->ppayload = pext->alloc(sizeof(LONGTERMIDFROMID_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_longtermidfromid_request(pext, r->ppayload);
	case ROP_ID_IDFROMLONGTERMID:
		r->ppayload = pext->alloc(sizeof(IDFROMLONGTERMID_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_idfromlongtermid_request(pext, r->ppayload);
	case ROP_ID_GETPERUSERLONGTERMIDS:
		r->ppayload = pext->alloc(sizeof(GETPERUSERLONGTERMIDS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getperuserlongtermids_request(pext, r->ppayload);
	case ROP_ID_GETPERUSERGUID:
		r->ppayload = pext->alloc(sizeof(GETPERUSERGUID_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getperuserguid_request(pext, r->ppayload);
	case ROP_ID_READPERUSERINFORMATION:
		r->ppayload = pext->alloc(sizeof(READPERUSERINFORMATION_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_readperuserinformation_request(pext, r->ppayload);
	case ROP_ID_WRITEPERUSERINFORMATION:
		r->ppayload = pext->alloc(sizeof(WRITEPERUSERINFORMATION_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		plogon = rop_processor_get_logon_object(pemsmdb_info->plogmap, r->logon_id);
		if (NULL == plogon) {
			return EXT_ERR_INVALID_OBJECT;
		}
		return rop_ext_pull_writeperuserinformation_request(pext,
				r->ppayload, logon_object_check_private(plogon));
	case ROP_ID_OPENFOLDER:
		r->ppayload = pext->alloc(sizeof(OPENFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_openfolder_request(pext, r->ppayload);
	case ROP_ID_CREATEFOLDER:
		r->ppayload = pext->alloc(sizeof(CREATEFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_createfolder_request(pext, r->ppayload);
	case ROP_ID_DELETEFOLDER:
		r->ppayload = pext->alloc(sizeof(DELETEFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_deletefolder_request(pext, r->ppayload);
	case ROP_ID_SETSEARCHCRITERIA:
		r->ppayload = pext->alloc(sizeof(SETSEARCHCRITERIA_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setsearchcriteria_request(pext, r->ppayload);
	case ROP_ID_GETSEARCHCRITERIA:
		r->ppayload = pext->alloc(sizeof(GETSEARCHCRITERIA_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getsearchcriteria_request(pext, r->ppayload);
	case ROP_ID_MOVECOPYMESSAGES:
		r->ppayload = pext->alloc(sizeof(MOVECOPYMESSAGES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_movecopymessages_request(pext, r->ppayload);
	case ROP_ID_MOVEFOLDER:
		r->ppayload = pext->alloc(sizeof(MOVEFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_movefolder_request(pext, r->ppayload);
	case ROP_ID_COPYFOLDER:
		r->ppayload = pext->alloc(sizeof(COPYFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_copyfolder_request(pext, r->ppayload);
	case ROP_ID_EMPTYFOLDER:
		r->ppayload = pext->alloc(sizeof(EMPTYFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_emptyfolder_request(pext, r->ppayload);
	case ROP_ID_HARDDELETEMESSAGESANDSUBFOLDERS:
		r->ppayload = pext->alloc(sizeof(HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_harddeletemessagesandsubfolders_request(pext, r->ppayload);
	case ROP_ID_DELETEMESSAGES:
		r->ppayload = pext->alloc(sizeof(DELETEMESSAGES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_deletemessages_request(pext, r->ppayload);
	case ROP_ID_HARDDELETEMESSAGES:
		r->ppayload = pext->alloc(sizeof(HARDDELETEMESSAGES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_harddeletemessages_request(pext, r->ppayload);
	case ROP_ID_GETHIERARCHYTABLE:
		r->ppayload = pext->alloc(sizeof(GETHIERARCHYTABLE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_gethierarchytable_request(pext, r->ppayload);
	case ROP_ID_GETCONTENTSTABLE:
		r->ppayload = pext->alloc(sizeof(GETCONTENTSTABLE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getcontentstable_request(pext, r->ppayload);
	case ROP_ID_SETCOLUMNS:
		r->ppayload = pext->alloc(sizeof(SETCOLUMNS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setcolumns_request(pext, r->ppayload);
	case ROP_ID_SORTTABLE:
		r->ppayload = pext->alloc(sizeof(SORTTABLE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_sorttable_request(pext, r->ppayload);
	case ROP_ID_RESTRICT:
		r->ppayload = pext->alloc(sizeof(RESTRICT_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_restrict_request(pext, r->ppayload);
	case ROP_ID_QUERYROWS:
		r->ppayload = pext->alloc(sizeof(QUERYROWS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_queryrows_request(pext, r->ppayload);
	case ROP_ID_ABORT:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETSTATUS:
		return EXT_ERR_SUCCESS;
	case ROP_ID_QUERYPOSITION:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SEEKROW:
		r->ppayload = pext->alloc(sizeof(SEEKROW_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_seekrow_request(pext, r->ppayload);
	case ROP_ID_SEEKROWBOOKMARK:
		r->ppayload = pext->alloc(sizeof(SEEKROWBOOKMARK_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_seekrowbookmark_request(pext, r->ppayload);
	case ROP_ID_SEEKROWFRACTIONAL:
		r->ppayload = pext->alloc(sizeof(SEEKROWFRACTIONAL_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_seekrowfractional_request(pext, r->ppayload);
	case ROP_ID_CREATEBOOKMARK:
		return EXT_ERR_SUCCESS;
	case ROP_ID_QUERYCOLUMNSALL:
		return EXT_ERR_SUCCESS;
	case ROP_ID_FINDROW:
		r->ppayload = pext->alloc(sizeof(FINDROW_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_findrow_request(pext, r->ppayload);
	case ROP_ID_FREEBOOKMARK:
		r->ppayload = pext->alloc(sizeof(FREEBOOKMARK_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_freebookmark_request(pext, r->ppayload);
	case ROP_ID_RESETTABLE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_EXPANDROW:
		r->ppayload = pext->alloc(sizeof(EXPANDROW_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_expandrow_request(pext, r->ppayload);
	case ROP_ID_COLLAPSEROW:
		r->ppayload = pext->alloc(sizeof(COLLAPSEROW_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_collapserow_request(pext, r->ppayload);
	case ROP_ID_GETCOLLAPSESTATE:
		r->ppayload = pext->alloc(sizeof(GETCOLLAPSESTATE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getcollapsestate_request(pext, r->ppayload);
	case ROP_ID_SETCOLLAPSESTATE:
		r->ppayload = pext->alloc(sizeof(SETCOLLAPSESTATE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setcollapsestate_request(pext, r->ppayload);
	case ROP_ID_OPENMESSAGE:
		r->ppayload = pext->alloc(sizeof(OPENMESSAGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_openmessage_request(pext, r->ppayload);
	case ROP_ID_CREATEMESSAGE:
		r->ppayload = pext->alloc(sizeof(CREATEMESSAGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_createmessage_request(pext, r->ppayload);
	case ROP_ID_SAVECHANGESMESSAGE:
		r->ppayload = pext->alloc(sizeof(SAVECHANGESMESSAGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_savechangesmessage_request(pext, r->ppayload);
	case ROP_ID_REMOVEALLRECIPIENTS:
		r->ppayload = pext->alloc(sizeof(REMOVEALLRECIPIENTS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_removeallrecipients_request(pext, r->ppayload);
	case ROP_ID_MODIFYRECIPIENTS:
		r->ppayload = pext->alloc(sizeof(MODIFYRECIPIENTS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_modifyrecipients_request(pext, r->ppayload);
	case ROP_ID_READRECIPIENTS:
		r->ppayload = pext->alloc(sizeof(READRECIPIENTS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_readrecipients_request(pext, r->ppayload);
	case ROP_ID_RELOADCACHEDINFORMATION:
		r->ppayload = pext->alloc(sizeof(RELOADCACHEDINFORMATION_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_reloadcachedinformation_request(pext, r->ppayload);
	case ROP_ID_SETMESSAGESTATUS:
		r->ppayload = pext->alloc(sizeof(SETMESSAGESTATUS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setmessagestatus_request(pext, r->ppayload);
	case ROP_ID_GETMESSAGESTATUS:
		r->ppayload = pext->alloc(sizeof(GETMESSAGESTATUS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getmessagestatus_request(pext, r->ppayload);
	case ROP_ID_SETREADFLAGS:
		r->ppayload = pext->alloc(sizeof(SETREADFLAGS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setreadflags_request(pext, r->ppayload);
	case ROP_ID_SETMESSAGEREADFLAG:
		r->ppayload = pext->alloc(sizeof(SETMESSAGEREADFLAG_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		plogon = rop_processor_get_logon_object(pemsmdb_info->plogmap, r->logon_id);
		if (NULL == plogon) {
			return EXT_ERR_INVALID_OBJECT;
		}
		return rop_ext_pull_setmessagereadflag_request(pext,
				r->ppayload, logon_object_check_private(plogon));
	case ROP_ID_OPENATTACHMENT:
		r->ppayload = pext->alloc(sizeof(OPENATTACHMENT_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_openattachment_request(pext, r->ppayload);
	case ROP_ID_CREATEATTACHMENT:
		r->ppayload = pext->alloc(sizeof(CREATEATTACHMENT_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_createattachment_request(pext, r->ppayload);
	case ROP_ID_DELETEATTACHMENT:
		r->ppayload = pext->alloc(sizeof(DELETEATTACHMENT_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_deleteattachment_request(pext, r->ppayload);
	case ROP_ID_SAVECHANGESATTACHMENT:
		r->ppayload = pext->alloc(sizeof(SAVECHANGESATTACHMENT_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_savechangesattachment_request(pext, r->ppayload);
	case ROP_ID_OPENEMBEDDEDMESSAGE:
		r->ppayload = pext->alloc(sizeof(OPENEMBEDDEDMESSAGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_openembeddedmessage_request(pext, r->ppayload);
	case ROP_ID_GETATTACHMENTTABLE:
		r->ppayload = pext->alloc(sizeof(GETATTACHMENTTABLE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getattachmenttable_request(pext, r->ppayload);
	case ROP_ID_GETVALIDATTACHMENTS:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SUBMITMESSAGE:
		r->ppayload = pext->alloc(sizeof(SUBMITMESSAGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_submitmessage_request(pext, r->ppayload);
	case ROP_ID_ABORTSUBMIT:
		r->ppayload = pext->alloc(sizeof(ABORTSUBMIT_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_abortsubmit_request(pext, r->ppayload);
	case ROP_ID_GETADDRESSTYPES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SETSPOOLER:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SPOOLERLOCKMESSAGE:
		r->ppayload = pext->alloc(sizeof(SPOOLERLOCKMESSAGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_spoolerlockmessage_request(pext, r->ppayload);
	case ROP_ID_TRANSPORTSEND:
		return EXT_ERR_SUCCESS;
	case ROP_ID_TRANSPORTNEWMAIL:
		r->ppayload = pext->alloc(sizeof(TRANSPORTNEWMAIL_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_transportnewmail_request(pext, r->ppayload);
	case ROP_ID_GETTRANSPORTFOLDER:
		return EXT_ERR_SUCCESS;
	case ROP_ID_OPTIONSDATA:
		r->ppayload = pext->alloc(sizeof(OPTIONSDATA_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_optionsdata_request(pext, r->ppayload);
	case ROP_ID_GETPROPERTYIDSFROMNAMES:
		r->ppayload = pext->alloc(sizeof(GETPROPERTYIDSFROMNAMES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getpropertyidsfromnames_request(pext, r->ppayload);
	case ROP_ID_GETNAMESFROMPROPERTYIDS:
		r->ppayload = pext->alloc(sizeof(GETNAMESFROMPROPERTYIDS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getnamesfrompropertyids_request(pext, r->ppayload);
	case ROP_ID_GETPROPERTIESSPECIFIC:
		r->ppayload = pext->alloc(sizeof(GETPROPERTIESSPECIFIC_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getpropertiesspecific_request(pext, r->ppayload);
	case ROP_ID_GETPROPERTIESALL:
		r->ppayload = pext->alloc(sizeof(GETPROPERTIESALL_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getpropertiesall_request(pext, r->ppayload);
	case ROP_ID_GETPROPERTIESLIST:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SETPROPERTIES:
		r->ppayload = pext->alloc(sizeof(SETPROPERTIES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setproperties_request(pext, r->ppayload);
	case ROP_ID_SETPROPERTIESNOREPLICATE:
		r->ppayload = pext->alloc(sizeof(SETPROPERTIESNOREPLICATE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setpropertiesnoreplicate_request(pext, r->ppayload);
	case ROP_ID_DELETEPROPERTIES:
		r->ppayload = pext->alloc(sizeof(DELETEPROPERTIES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_deleteproperties_request(pext, r->ppayload);
	case ROP_ID_DELETEPROPERTIESNOREPLICATE:
		r->ppayload = pext->alloc(sizeof(DELETEPROPERTIESNOREPLICATE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_deletepropertiesnoreplicate_request(pext, r->ppayload);
	case ROP_ID_QUERYNAMEDPROPERTIES:
		r->ppayload = pext->alloc(sizeof(QUERYNAMEDPROPERTIES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_querynamedproperties_request(pext, r->ppayload);
	case ROP_ID_COPYPROPERTIES:
		r->ppayload = pext->alloc(sizeof(COPYPROPERTIES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_copyproperties_request(pext, r->ppayload);
	case ROP_ID_COPYTO:
		r->ppayload = pext->alloc(sizeof(COPYTO_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_copyto_request(pext, r->ppayload);
	case ROP_ID_PROGRESS:
		r->ppayload = pext->alloc(sizeof(PROGRESS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_progress_request(pext, r->ppayload);
	case ROP_ID_OPENSTREAM:
		r->ppayload = pext->alloc(sizeof(OPENSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_openstream_request(pext, r->ppayload);
	case ROP_ID_READSTREAM:
		r->ppayload = pext->alloc(sizeof(READSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_readstream_request(pext, r->ppayload);
	case ROP_ID_WRITESTREAM:
		r->ppayload = pext->alloc(sizeof(WRITESTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_writestream_request(pext, r->ppayload);
	case ROP_ID_COMMITSTREAM:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETSTREAMSIZE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SETSTREAMSIZE:
		r->ppayload = pext->alloc(sizeof(SETSTREAMSIZE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setstreamsize_request(pext, r->ppayload);
	case ROP_ID_SEEKSTREAM:
		r->ppayload = pext->alloc(sizeof(SEEKSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_seekstream_request(pext, r->ppayload);
	case ROP_ID_COPYTOSTREAM:
		r->ppayload = pext->alloc(sizeof(COPYTOSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_copytostream_request(pext, r->ppayload);
	case ROP_ID_LOCKREGIONSTREAM:
		r->ppayload = pext->alloc(sizeof(LOCKREGIONSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_lockregionstream_request(pext, r->ppayload);
	case ROP_ID_UNLOCKREGIONSTREAM:
		r->ppayload = pext->alloc(sizeof(UNLOCKREGIONSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_unlockregionstream_request(pext, r->ppayload);
	case ROP_ID_WRITEANDCOMMITSTREAM:
		r->ppayload = pext->alloc(sizeof(WRITEANDCOMMITSTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_writeandcommitstream_request(pext, r->ppayload);
	case ROP_ID_CLONESTREAM:
		r->ppayload = pext->alloc(sizeof(CLONESTREAM_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_clonestream_request(pext, r->ppayload);
	case ROP_ID_MODIFYPERMISSIONS:
		r->ppayload = pext->alloc(sizeof(MODIFYPERMISSIONS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_modifypermissions_request(pext, r->ppayload);
	case ROP_ID_GETPERMISSIONSTABLE:
		r->ppayload = pext->alloc(sizeof(GETPERMISSIONSTABLE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getpermissionstable_request(pext, r->ppayload);
	case ROP_ID_MODIFYRULES:
		r->ppayload = pext->alloc(sizeof(MODIFYRULES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_modifyrules_request(pext, r->ppayload);
	case ROP_ID_GETRULESTABLE:
		r->ppayload = pext->alloc(sizeof(GETRULESTABLE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getrulestable_request(pext, r->ppayload);
	case ROP_ID_UPDATEDEFERREDACTIONMESSAGES:
		r->ppayload = pext->alloc(sizeof(UPDATEDEFERREDACTIONMESSAGES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_updatedeferredactionmessages_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERDESTCONFIGURE:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERDESTCONFIGURE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransferdestconfigure_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERDESTPUTBUFFER:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERDESTPUTBUFFER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransferdestputbuffer_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCEGETBUFFER:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERSOURCEGETBUFFER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransfersourcegetbuffer_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCECOPYFOLDER:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERSOURCECOPYFOLDER_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransfersourcecopyfolder_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCECOPYMESSAGES:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERSOURCECOPYMESSAGES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransfersourcecopymessages_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCECOPYTO:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERSOURCECOPYTO_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransfersourcecopyto_request(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCECOPYPROPERTIES:
		r->ppayload = pext->alloc(sizeof(FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_fasttransfersourcecopyproperties_request(pext, r->ppayload);
	case ROP_ID_TELLVERSION:
		r->ppayload = pext->alloc(sizeof(TELLVERSION_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_tellversion_request(pext, r->ppayload);
	case ROP_ID_SYNCCONFIGURE:
		r->ppayload = pext->alloc(sizeof(SYNCCONFIGURE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncconfigure_request(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTMESSAGECHANGE:
		r->ppayload = pext->alloc(sizeof(SYNCIMPORTMESSAGECHANGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncimportmessagechange_request(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTREADSTATECHANGES:
		r->ppayload = pext->alloc(sizeof(SYNCIMPORTREADSTATECHANGES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncimportreadstatechanges_request(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTHIERARCHYCHANGE:
		r->ppayload = pext->alloc(sizeof(SYNCIMPORTHIERARCHYCHANGE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncimporthierarchychange_request(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTDELETES:
		r->ppayload = pext->alloc(sizeof(SYNCIMPORTDELETES_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncimportdeletes_request(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTMESSAGEMOVE:
		r->ppayload = pext->alloc(sizeof(SYNCIMPORTMESSAGEMOVE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncimportmessagemove_request(pext, r->ppayload);
	case ROP_ID_SYNCOPENCOLLECTOR:
		r->ppayload = pext->alloc(sizeof(SYNCOPENCOLLECTOR_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncopencollector_request(pext, r->ppayload);
	case ROP_ID_SYNCGETTRANSFERSTATE:
		r->ppayload = pext->alloc(sizeof(SYNCGETTRANSFERSTATE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncgettransferstate_request(pext, r->ppayload);
	case ROP_ID_SYNCUPLOADSTATESTREAMBEGIN:
		r->ppayload = pext->alloc(sizeof(SYNCUPLOADSTATESTREAMBEGIN_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncuploadstatestreambegin_request(pext, r->ppayload);
	case ROP_ID_SYNCUPLOADSTATESTREAMCONTINUE:
		r->ppayload = pext->alloc(sizeof(SYNCUPLOADSTATESTREAMCONTINUE_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_syncuploadstatestreamcontinue_request(pext, r->ppayload);
	case ROP_ID_SYNCUPLOADSTATESTREAMEND:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SETLOCALREPLICAMIDSETDELETED:
		r->ppayload = pext->alloc(sizeof(SETLOCALREPLICAMIDSETDELETED_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_setlocalreplicamidsetdeleted_request(pext, r->ppayload);
	case ROP_ID_GETLOCALREPLICAIDS:
		r->ppayload = pext->alloc(sizeof(GETLOCALREPLICAIDS_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_getlocalreplicaids_request(pext, r->ppayload);
	case ROP_ID_REGISTERNOTIFICATION:
		r->ppayload = pext->alloc(sizeof(REGISTERNOTIFICATION_REQUEST));
		if (NULL == r->ppayload) {
			return EXT_ERR_ALLOC;
		}
		return rop_ext_pull_registernotification_request(pext, r->ppayload);
	case ROP_ID_RELEASE:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

/* not including ROP_ID_NOTIFY, ROP_ID_PENDING,
	ROP_ID_BACKOFF, ROP_ID_BUFFERTOOSMALL */
int rop_ext_push_rop_response(EXT_PUSH *pext,
	uint8_t logon_id, ROP_RESPONSE *r)
{
	int status;
	LOGON_OBJECT *plogon;
	EMSMDB_INFO *pemsmdb_info;
	
	if (ROP_ID_GETMESSAGESTATUS == r->rop_id) {
		status = ext_buffer_push_uint8(pext, ROP_ID_SETMESSAGESTATUS);
	} else {
		status = ext_buffer_push_uint8(pext, r->rop_id);
	}
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	
	status = ext_buffer_push_uint8(pext, r->hindex);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->result);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (EC_SUCCESS != r->result) {
		switch (r->rop_id) {
		case ROP_ID_LOGON:
			if (EC_WRONG_SERVER == r->result) {
				return rop_ext_push_logon_redirect_response(pext, r->ppayload);
			}
			break;
		case ROP_ID_GETPROPERTYIDSFROMNAMES:
			if (EC_ERRORS_RETURNED == r->result) {
				goto PUSH_PAYLOAD;
			}
			break;
		case ROP_ID_MOVECOPYMESSAGES:
		case ROP_ID_MOVEFOLDER:
		case ROP_ID_COPYFOLDER:
			if (EC_DST_NULL_OBJECT == r->result) {
				return rop_ext_push_null_dest_response(pext, r->ppayload);
			} else {
				goto PUSH_PAYLOAD;
			}
			break;
		case ROP_ID_COPYPROPERTIES:
		case ROP_ID_COPYTO:
			if (EC_DST_NULL_OBJECT == r->result) {
				return ext_buffer_push_uint32(pext, *(uint8_t*)r->ppayload);
			}
			break;
		case ROP_ID_COPYTOSTREAM:
			if (EC_DST_NULL_OBJECT == r->result) {
				return rop_ext_push_copytostream_null_dest_response(pext, r->ppayload);
			}
			break;
		case ROP_ID_EMPTYFOLDER:
		case ROP_ID_DELETEFOLDER:
		case ROP_ID_DELETEMESSAGES:
		case ROP_ID_HARDDELETEMESSAGES:
		case ROP_ID_HARDDELETEMESSAGESANDSUBFOLDERS:
		case ROP_ID_FASTTRANSFERDESTPUTBUFFER:
		case ROP_ID_FASTTRANSFERSOURCEGETBUFFER:
			goto PUSH_PAYLOAD;
		}
		return EXT_ERR_SUCCESS;
	}

PUSH_PAYLOAD:
	switch (r->rop_id) {
	case ROP_ID_LOGON:
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		plogon = rop_processor_get_logon_object(pemsmdb_info->plogmap, logon_id);
		if (NULL == plogon) {
			return EXT_ERR_INVALID_OBJECT;
		}
		if (TRUE == logon_object_check_private(plogon)) {
			return rop_ext_push_logon_pmb_response(pext, r->ppayload);
		} else {
			return rop_ext_push_logon_pf_response(pext, r->ppayload);
		}
	case ROP_ID_GETRECEIVEFOLDER:
		return rop_ext_push_getreceivefolder_response(pext, r->ppayload);
	case ROP_ID_SETRECEIVEFOLDER:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETRECEIVEFOLDERTABLE:
		return rop_ext_push_getreceivefoldertable_response(pext, r->ppayload);
	case ROP_ID_GETSTORESTAT:
		return rop_ext_push_getstorestat_response(pext, r->ppayload);
	case ROP_ID_GETOWNINGSERVERS:
		return rop_ext_push_getowningservers_response(pext, r->ppayload);
	case ROP_ID_PUBLICFOLDERISGHOSTED:
		return rop_ext_push_publicfolderisghosted_response(pext, r->ppayload);
	case ROP_ID_LONGTERMIDFROMID:
		return rop_ext_push_longtermidfromid_response(pext, r->ppayload);
	case ROP_ID_IDFROMLONGTERMID:
		return rop_ext_push_idfromlongtermid_response(pext, r->ppayload);
	case ROP_ID_GETPERUSERLONGTERMIDS:
		return rop_ext_push_getperuserlongtermids_response(pext, r->ppayload);
	case ROP_ID_GETPERUSERGUID:
		return rop_ext_push_getperuserguid_response(pext, r->ppayload);
	case ROP_ID_READPERUSERINFORMATION:
		return rop_ext_push_readperuserinformation_response(pext, r->ppayload);
	case ROP_ID_WRITEPERUSERINFORMATION:
		return EXT_ERR_SUCCESS;
	case ROP_ID_OPENFOLDER:
		return rop_ext_push_openfolder_response(pext, r->ppayload);
	case ROP_ID_CREATEFOLDER:
		return rop_ext_push_createfolder_response(pext, r->ppayload);
	case ROP_ID_DELETEFOLDER:
		return rop_ext_push_deletefolder_response(pext, r->ppayload);
	case ROP_ID_SETSEARCHCRITERIA:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETSEARCHCRITERIA:
		return rop_ext_push_getsearchcriteria_response(pext, r->ppayload);
	case ROP_ID_MOVECOPYMESSAGES:
		return rop_ext_push_movecopymessages_response(pext, r->ppayload);
	case ROP_ID_MOVEFOLDER:
		return rop_ext_push_movefolder_response(pext, r->ppayload);
	case ROP_ID_COPYFOLDER:
		return rop_ext_push_copyfolder_response(pext, r->ppayload);
	case ROP_ID_EMPTYFOLDER:
		return rop_ext_push_emptyfolder_response(pext, r->ppayload);
	case ROP_ID_HARDDELETEMESSAGESANDSUBFOLDERS:
		return rop_ext_push_harddeletemessagesandsubfolders_response(pext, r->ppayload);
	case ROP_ID_DELETEMESSAGES:
		return rop_ext_push_deletemessages_response(pext, r->ppayload);
	case ROP_ID_HARDDELETEMESSAGES:
		return rop_ext_push_harddeletemessages_response(pext, r->ppayload);
	case ROP_ID_GETHIERARCHYTABLE:
		return rop_ext_push_gethierarchytable_response(pext, r->ppayload);
	case ROP_ID_GETCONTENTSTABLE:
		return rop_ext_push_getcontentstable_response(pext, r->ppayload);
	case ROP_ID_SETCOLUMNS:
		return rop_ext_push_setcolumns_response(pext, r->ppayload);
	case ROP_ID_SORTTABLE:
		return rop_ext_push_sorttable_response(pext, r->ppayload);
	case ROP_ID_RESTRICT:
		return rop_ext_push_restrict_response(pext, r->ppayload);
	case ROP_ID_QUERYROWS:
		return rop_ext_push_queryrows_response(pext, r->ppayload);
	case ROP_ID_ABORT:
		return rop_ext_push_abort_response(pext, r->ppayload);
	case ROP_ID_GETSTATUS:
		return rop_ext_push_getstatus_response(pext, r->ppayload);
	case ROP_ID_QUERYPOSITION:
		return rop_ext_push_queryposition_response(pext, r->ppayload);
	case ROP_ID_SEEKROW:
		return rop_ext_push_seekrow_response(pext, r->ppayload);
	case ROP_ID_SEEKROWBOOKMARK:
		return rop_ext_push_seekrowbookmark_response(pext, r->ppayload);
	case ROP_ID_SEEKROWFRACTIONAL:
		return EXT_ERR_SUCCESS;
	case ROP_ID_CREATEBOOKMARK:
		return rop_ext_push_createbookmark_response(pext, r->ppayload);
	case ROP_ID_QUERYCOLUMNSALL:
		return rop_ext_push_querycolumnsall_response(pext, r->ppayload);
	case ROP_ID_FINDROW:
		return rop_ext_push_findrow_response(pext, r->ppayload);
	case ROP_ID_FREEBOOKMARK:
		return EXT_ERR_SUCCESS;
	case ROP_ID_RESETTABLE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_EXPANDROW:
		return rop_ext_push_expandrow_response(pext, r->ppayload);
	case ROP_ID_COLLAPSEROW:
		return rop_ext_push_collapserow_response(pext, r->ppayload);
	case ROP_ID_GETCOLLAPSESTATE:
		return rop_ext_push_getcollapsestate_response(pext, r->ppayload);
	case ROP_ID_SETCOLLAPSESTATE:
		return rop_ext_push_setcollapsestate_response(pext, r->ppayload);
	case ROP_ID_OPENMESSAGE:
		return rop_ext_push_openmessage_response(pext, r->ppayload);
	case ROP_ID_CREATEMESSAGE:
		return rop_ext_push_createmessage_response(pext, r->ppayload);
	case ROP_ID_SAVECHANGESMESSAGE:
		return rop_ext_push_savechangesmessage_response(pext, r->ppayload);
	case ROP_ID_REMOVEALLRECIPIENTS:
		return EXT_ERR_SUCCESS;
	case ROP_ID_MODIFYRECIPIENTS:
		return EXT_ERR_SUCCESS;
	case ROP_ID_READRECIPIENTS:
		return rop_ext_push_readrecipients_response(pext, r->ppayload);
	case ROP_ID_RELOADCACHEDINFORMATION:
		return rop_ext_push_reloadcachedinformation_response(pext, r->ppayload);
	case ROP_ID_SETMESSAGESTATUS:
		return rop_ext_push_setmessagestatus_response(pext, r->ppayload);
	case ROP_ID_GETMESSAGESTATUS:
		return rop_ext_push_getmessagestatus_response(pext, r->ppayload);
	case ROP_ID_SETREADFLAGS:
		return rop_ext_push_setreadflags_response(pext, r->ppayload);
	case ROP_ID_SETMESSAGEREADFLAG:
		return rop_ext_push_setmessagereadflag_response(pext, r->ppayload);
	case ROP_ID_OPENATTACHMENT:
		return EXT_ERR_SUCCESS;
	case ROP_ID_CREATEATTACHMENT:
		return rop_ext_push_createattachment_response(pext, r->ppayload);
	case ROP_ID_DELETEATTACHMENT:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SAVECHANGESATTACHMENT:
		return EXT_ERR_SUCCESS;
	case ROP_ID_OPENEMBEDDEDMESSAGE:
		return rop_ext_push_openembeddedmessage_response(pext, r->ppayload);
	case ROP_ID_GETATTACHMENTTABLE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETVALIDATTACHMENTS:
		return rop_ext_push_getvalidattachments_response(pext, r->ppayload);
	case ROP_ID_SUBMITMESSAGE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_ABORTSUBMIT:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETADDRESSTYPES:
		return rop_ext_push_getaddresstypes_response(pext, r->ppayload);
	case ROP_ID_SETSPOOLER:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SPOOLERLOCKMESSAGE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_TRANSPORTSEND:
		return rop_ext_push_transportsend_response(pext, r->ppayload);
	case ROP_ID_TRANSPORTNEWMAIL:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETTRANSPORTFOLDER:
		return rop_ext_push_gettransportfolder_response(pext, r->ppayload);
	case ROP_ID_OPTIONSDATA:
		return rop_ext_push_optionsdata_response(pext, r->ppayload);
	case ROP_ID_GETPROPERTYIDSFROMNAMES:
		return rop_ext_push_getpropertyidsfromnames_response(pext, r->ppayload);
	case ROP_ID_GETNAMESFROMPROPERTYIDS:
		return rop_ext_push_getnamesfrompropertyids_response(pext, r->ppayload);
	case ROP_ID_GETPROPERTIESSPECIFIC:
		return rop_ext_push_getpropertiesspecific_response(pext, r->ppayload);
	case ROP_ID_GETPROPERTIESALL:
		return rop_ext_push_getpropertiesall_response(pext, r->ppayload);
	case ROP_ID_GETPROPERTIESLIST:
		return rop_ext_push_getpropertieslist_response(pext, r->ppayload);
	case ROP_ID_SETPROPERTIES:
		return rop_ext_push_setproperties_response(pext, r->ppayload);
	case ROP_ID_SETPROPERTIESNOREPLICATE:
		return rop_ext_push_setpropertiesnoreplicate_response(pext, r->ppayload);
	case ROP_ID_DELETEPROPERTIES:
		return rop_ext_push_deleteproperties_response(pext, r->ppayload);
	case ROP_ID_DELETEPROPERTIESNOREPLICATE:
		return rop_ext_push_deletepropertiesnoreplicate_response(pext, r->ppayload);
	case ROP_ID_QUERYNAMEDPROPERTIES:
		return rop_ext_push_querynamedproperties_response(pext, r->ppayload);
	case ROP_ID_COPYPROPERTIES:
		return rop_ext_push_copyproperties_response(pext, r->ppayload);
	case ROP_ID_COPYTO:
		return rop_ext_push_copyto_response(pext, r->ppayload);
	case ROP_ID_PROGRESS:
		return rop_ext_push_progress_response(pext, r->ppayload);
	case ROP_ID_OPENSTREAM:
		return rop_ext_push_openstream_response(pext, r->ppayload);
	case ROP_ID_READSTREAM:
		return rop_ext_push_readstream_response(pext, r->ppayload);
	case ROP_ID_WRITESTREAM:
		return rop_ext_push_writestream_response(pext, r->ppayload);
	case ROP_ID_COMMITSTREAM:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETSTREAMSIZE:
		return rop_ext_push_getstreamsize_response(pext, r->ppayload);
	case ROP_ID_SETSTREAMSIZE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SEEKSTREAM:
		return rop_ext_push_seekstream_response(pext, r->ppayload);
	case ROP_ID_COPYTOSTREAM:
		return rop_ext_push_copytostream_response(pext, r->ppayload);
	case ROP_ID_LOCKREGIONSTREAM:
		return EXT_ERR_SUCCESS;
	case ROP_ID_UNLOCKREGIONSTREAM:
		return EXT_ERR_SUCCESS;
	case ROP_ID_WRITEANDCOMMITSTREAM:
		return rop_ext_push_writeandcommitstream_response(pext, r->ppayload);
	case ROP_ID_CLONESTREAM:
		return EXT_ERR_SUCCESS;
	case ROP_ID_MODIFYPERMISSIONS:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETPERMISSIONSTABLE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_MODIFYRULES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETRULESTABLE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_UPDATEDEFERREDACTIONMESSAGES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_FASTTRANSFERDESTCONFIGURE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_FASTTRANSFERDESTPUTBUFFER:
		return rop_ext_push_fasttransferdestputbuffer_response(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCEGETBUFFER:
		return rop_ext_push_fasttransfersourcegetbuffer_response(pext, r->ppayload);
	case ROP_ID_FASTTRANSFERSOURCECOPYFOLDER:
		return EXT_ERR_SUCCESS;
	case ROP_ID_FASTTRANSFERSOURCECOPYMESSAGES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_FASTTRANSFERSOURCECOPYTO:
		return EXT_ERR_SUCCESS;
	case ROP_ID_FASTTRANSFERSOURCECOPYPROPERTIES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_TELLVERSION:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCCONFIGURE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCIMPORTMESSAGECHANGE:
		return rop_ext_push_syncimportmessagechange_response(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTREADSTATECHANGES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCIMPORTHIERARCHYCHANGE:
		return rop_ext_push_syncimporthierarchychange_response(pext, r->ppayload);
	case ROP_ID_SYNCIMPORTDELETES:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCIMPORTMESSAGEMOVE:
		return rop_ext_push_syncimportmessagemove_response(pext, r->ppayload);
	case ROP_ID_SYNCOPENCOLLECTOR:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCGETTRANSFERSTATE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCUPLOADSTATESTREAMBEGIN:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCUPLOADSTATESTREAMCONTINUE:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SYNCUPLOADSTATESTREAMEND:
		return EXT_ERR_SUCCESS;
	case ROP_ID_SETLOCALREPLICAMIDSETDELETED:
		return EXT_ERR_SUCCESS;
	case ROP_ID_GETLOCALREPLICAIDS:
		return rop_ext_push_getlocalreplicaids_response(pext, r->ppayload);
	case ROP_ID_REGISTERNOTIFICATION:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int rop_ext_pull_rop_buffer(EXT_PULL *pext, ROP_BUFFER *r)
{
	int status;
	uint16_t i;
	int tmp_num;
	uint16_t size;
	uint8_t *pdata;
	uint8_t *pbuff;
	EXT_PULL subext;
	DOUBLE_LIST_NODE *pnode;
	uint32_t decompressed_len;
	RPC_HEADER_EXT rpc_header_ext;
	
	
	status = ext_buffer_pull_rpc_header_ext(pext, &rpc_header_ext);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	if (0 == (rpc_header_ext.flags & RHE_FLAG_LAST)) {
		return EXT_ERR_HEADER_FLAGS;
	}
	r->rhe_version = rpc_header_ext.version;
	r->rhe_flags = rpc_header_ext.flags;
	double_list_init(&r->rop_list);
	if (0 == rpc_header_ext.size) {
		return EXT_ERR_HEADER_SIZE;
	}
	pbuff = pext->alloc(0x8000);
	if (NULL == pbuff) {
		return EXT_ERR_ALLOC;
	}
	pdata = (uint8_t*)pext->data + pext->offset;
	/* obfuscation case */
	if (rpc_header_ext.flags & RHE_FLAG_XORMAGIC) {
		common_util_obfuscate_data(pdata,
			rpc_header_ext.size_actual);
	}
	/* lzxpress case */
	if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
		decompressed_len = lzxpress_decompress(pdata,
					rpc_header_ext.size, pbuff, 0x8000);
		if (decompressed_len < rpc_header_ext.size_actual) {
			return EXT_ERR_LZXPRESS;
		}
	} else {
		memcpy(pbuff, pdata, rpc_header_ext.size_actual);
	}
	ext_buffer_pull_init(&subext,
		pbuff, rpc_header_ext.size_actual,
		common_util_alloc, EXT_FLAG_UTF16);
	status = ext_buffer_pull_uint16(&subext, &size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	while (subext.offset < size) {
		pnode = pext->alloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			return EXT_ERR_ALLOC;
		}
		pnode->pdata = pext->alloc(sizeof(ROP_REQUEST));
		if (NULL == pnode->pdata) {
			return EXT_ERR_ALLOC;
		}
		status = rop_ext_pull_rop_request(
			&subext, (ROP_REQUEST*)pnode->pdata);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		double_list_append_as_tail(&r->rop_list, pnode);
	}
	tmp_num = (rpc_header_ext.size_actual - size) / sizeof(uint32_t);
	if (0 == tmp_num) {
		r->hnum = 0;
		r->phandles = NULL;
		return EXT_ERR_SUCCESS;
	}
	if (tmp_num > 255) {
		return EXT_ERR_RANGE;
	}
	r->hnum = tmp_num;
	r->phandles = pext->alloc(sizeof(uint32_t)*r->hnum);
	if (NULL == r->phandles) {
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->hnum; i++) {
		status = ext_buffer_pull_uint32(&subext, r->phandles + i);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	return EXT_ERR_SUCCESS;
}

int rop_ext_make_rpc_ext(const void *pbuff_in, uint32_t in_len,
    const ROP_BUFFER *prop_buff, void *pbuff_out, uint32_t *pout_len)
{
	int i;
	int status;
	EXT_PUSH subext;
	EXT_PUSH ext_push;
	uint32_t compressed_len;
	uint8_t ext_buff[0x10000];
	uint8_t tmp_buff[0x10000];
	RPC_HEADER_EXT rpc_header_ext;
	
	ext_buffer_push_init(&subext, ext_buff,
		sizeof(ext_buff), EXT_FLAG_UTF16);
	status = ext_buffer_push_uint16(&subext, in_len + sizeof(uint16_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(&subext, pbuff_in, in_len);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	for (i=0; i<prop_buff->hnum; i++) {
		status = ext_buffer_push_uint32(&subext, prop_buff->phandles[i]);
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
	}
	rpc_header_ext.version = prop_buff->rhe_version;
	rpc_header_ext.flags = prop_buff->rhe_flags;
	rpc_header_ext.size_actual = subext.offset;
	rpc_header_ext.size = rpc_header_ext.size_actual;
	if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
		if (rpc_header_ext.size_actual < MINIMUM_COMPRESS_SIZE) {
			rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
		} else {
			compressed_len = lzxpress_compress(ext_buff,
								subext.offset, tmp_buff);
			if (0 == compressed_len ||
				compressed_len >= subext.offset) {
				/* if we can not get benefit from the
					compression, unmask the compress bit */
				rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
			} else {
				rpc_header_ext.size = compressed_len;
				memcpy(ext_buff, tmp_buff, compressed_len);
			}
		}
	}
	if (rpc_header_ext.flags & RHE_FLAG_XORMAGIC) {
		rpc_header_ext.flags &= ~RHE_FLAG_XORMAGIC;
	}
	ext_buffer_push_init(&ext_push, pbuff_out, *pout_len, EXT_FLAG_UTF16);
	status = ext_buffer_push_rpc_header_ext(&ext_push, &rpc_header_ext);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_bytes(&ext_push, ext_buff, rpc_header_ext.size);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	*pout_len = ext_push.offset;
	return EXT_ERR_SUCCESS;
}

void rop_ext_set_rhe_flag_last(uint8_t *pdata, uint32_t last_offset)
{
	uint16_t flags;
	
	flags = SVAL(pdata, last_offset + sizeof(uint16_t));
	flags |= RHE_FLAG_LAST;
	SSVAL(pdata, last_offset + sizeof(uint16_t), flags);
}
