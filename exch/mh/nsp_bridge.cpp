#include <gromox/rpc_types.hpp>
#include "nsp_bridge.hpp"
#include "nsp_common.hpp"

#define E(s) decltype(nsp_interface_ ## s) nsp_interface_ ## s;
E(bind)
E(unbind)
E(update_stat)
E(query_rows)
E(seek_entries)
E(get_matches)
E(resort_restriction)
E(dntomid)
E(get_proplist)
E(get_props)
E(compare_mids)
E(mod_props)
E(get_specialtable)
E(get_templateinfo)
E(mod_linkatt)
E(query_columns)
E(resolve_namesw)
#undef E

static constexpr int HANDLE_EXCHANGE_NSP = 1;

static inline bool Failed(uint32_t hresult)
{
	return hresult != ecSuccess && hresult != ecWarnWithErrors;
}

uint32_t nsp_bridge_unbind(GUID session_guid, uint32_t reserved)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_unbind(&ses, reserved);
}

uint32_t nsp_bridge_run(GUID& session_guid, const bind_request& request, bind_response& response)
{
	FLATUID server_flatuid;
	NSP_HANDLE ses;

	uint32_t result = nsp_interface_bind(0, request.flags, request.stat, &server_flatuid, &ses);
	if (Failed(result)) {
		session_guid = {};
		response.server_guid = {};
	} else {
		response.server_guid = cu_flatuid_to_guid(server_flatuid);
		session_guid = ses.guid;
	}
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const comparemids_request& request, comparemids_response& response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_compare_mids(ses, request.reserved, request.stat, request.mid1, request.mid2, &response.result1);
}

uint32_t nsp_bridge_run(const GUID& session_guid, const dntomid_request& request, dntomid_response& response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_dntomid(ses, request.reserved, request.names, &response.outmids);
}

uint32_t nsp_bridge_run(const GUID& session_guid, const getmatches_request& request, getmatches_response& response)
{
	NSPRES *nspres = nullptr;
	NSP_ROWSET *outrows = nullptr;
	NSP_PROPNAME *nspname = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.filter != nullptr) {
		nspres = cu_alloc<NSPRES>();
		if (nspres == nullptr ||
		    !cu_restriction_to_nspres(*request.filter, *nspres)) {
			response.mids = nullptr;
			return ecRpcFailed;
		}
	}
	if (request.propname != nullptr) {
		nspname = cu_alloc<NSP_PROPNAME>();
		if (nspname == nullptr ||
		    !cu_propname_to_nsp(*request.propname, *nspname)) {
			response.mids = nullptr;
			return ecRpcFailed;
		}
	}
	uint32_t result = nsp_interface_get_matches(ses, request.reserved1, request.stat,
	                  request.inmids, request.reserved2, nspres, nspname, request.row_count,
	                  &response.mids, request.columns, &outrows);
	if (Failed(result))
		return result;
	if (outrows != nullptr &&
	    !cu_nsp_rowset_to_colrow(request.columns, *outrows, response.column_rows))
		return ecRpcFailed;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const getproplist_request& request, getproplist_response& response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_get_proplist(ses, request.flags, request.mid,
	       request.codepage, &response.proptags);
}

uint32_t nsp_bridge_run(const GUID& session_guid, const getprops_request& request, getprops_response& response)
{
	NSP_PROPROW *row;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	uint32_t result = nsp_interface_get_props(ses, request.flags, request.stat, request.proptags, &row);
	if (Failed(result)) {
		response.row = nullptr;
		return result;
	}
	if (row == nullptr) {
		response.row = nullptr;
	} else {
		response.row = cu_alloc<LTPROPVAL_ARRAY>();
		if (response.row == nullptr ||
		    !cu_nsp_proprow_to_proplist(*row, *response.row)) {
			response.row = nullptr;
			return ecRpcFailed;
		}
	}
	response.codepage = request.stat->codepage;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const getspecialtable_request& request, getspecialtable_response& response)
{
	uint32_t version;
	NSP_ROWSET *rows;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.version != nullptr)
		version = *request.version;
	uint32_t result = nsp_interface_get_specialtable(ses, request.flags, request.stat, &version, &rows);
	if (Failed(result)) {
		response.version = nullptr;
		response.count = 0;
		response.row = nullptr;
		return result;
	}
	if (request.version == nullptr) {
		response.version = nullptr;
	} else {
		*request.version = version;
		response.version = request.version;
	}
	if (rows == nullptr) {
		response.count = 0;
		response.row = nullptr;
		return ecSuccess;
	}
	response.count = rows->crows;
	response.row = cu_alloc<LTPROPVAL_ARRAY>(rows->crows);
	if (response.row == nullptr)
		return ecRpcFailed;
	for (size_t i = 0; i < rows->crows; ++i) {
		if (!cu_nsp_proprow_to_proplist(rows->prows[i], response.row[i])) {
			response.row = nullptr;
			return ecRpcFailed;
		}
	}
	response.codepage = request.stat->codepage;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const gettemplateinfo_request& request, gettemplateinfo_response& response)
{
	NSP_PROPROW *row;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	uint32_t result = nsp_interface_get_templateinfo(ses, request.flags, request.type, request.dn,
	                  request.codepage, request.locale_id, &row);
	if (Failed(result)) {
		response.row = nullptr;
		return result;
	}
	if (row == nullptr) {
		response.row = nullptr;
		return ecSuccess;
	}
	response.row = cu_alloc<LTPROPVAL_ARRAY>();
	if (response.row == nullptr ||
	    !cu_nsp_proprow_to_proplist(*row, *response.row)) {
		response.row = nullptr;
		return ecRpcFailed;
	}
	response.codepage = request.codepage;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const modlinkatt_request& request, modlinkatt_response&)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_mod_linkatt(ses, request.flags, request.proptag,
	       request.mid, &request.entryids);
}

uint32_t nsp_bridge_run(const GUID& session_guid, const modprops_request& request, modprops_response&)
{
	NSP_PROPROW *row = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.values != nullptr) {
		row = cu_alloc<NSP_PROPROW>();
		if (row == nullptr ||
		    !cu_proplist_to_nsp_proprow(*request.values, *row))
			return ecRpcFailed;
	}
	return nsp_interface_mod_props(ses, request.reserved, request.stat,
	       request.proptags, row);
}


uint32_t nsp_bridge_run(const GUID& session_guid, const querycolumns_request& request, querycolumns_response& response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_query_columns(ses, request.reserved, request.flags, &response.columns);
}

uint32_t nsp_bridge_run(const GUID& session_guid, const queryrows_request& request, queryrows_response& response)
{
	NSP_ROWSET *rows = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	uint32_t result = nsp_interface_query_rows(ses, request.flags, request.stat,
	                  request.explicit_table.cvalues, request.explicit_table.pproptag,
	                  request.count, request.columns, &rows);
	if (Failed(result))
		return result;
	if (rows != nullptr &&
	    !cu_nsp_rowset_to_colrow(request.columns, *rows, response.column_rows))
		return ecRpcFailed;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const resolvenames_request& request, resolvenames_response& response)
{
	NSP_ROWSET *rows = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	auto tags = request.proptags;
	uint32_t result = nsp_interface_resolve_namesw(ses, request.reserved, request.stat,
	                  tags, request.names, &response.mids, &rows);
	if (Failed(result))
		return result;
	if (rows != nullptr &&
	    !cu_nsp_rowset_to_colrow(request.proptags, *rows, response.column_rows))
		return ecRpcFailed;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const resortrestriction_request& request, resortrestriction_response& response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_resort_restriction(ses, request.reserved,
	       request.stat, request.inmids, &response.outmids);
}

uint32_t nsp_bridge_run(const GUID& session_guid, const seekentries_request& request, seekentries_response& response)
{
	NSP_ROWSET *rows = nullptr;
	PROPERTY_VALUE *target_val = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};

	if (request.target != nullptr) {
		target_val = cu_alloc<PROPERTY_VALUE>();
		if (target_val == nullptr ||
		    !cu_tpropval_to_propval(*request.target, *target_val))
			return ecRpcFailed;
	}
	uint32_t result = nsp_interface_seek_entries(ses, request.reserved, request.stat,
	                  target_val, request.explicit_table, request.columns, &rows);
	if (Failed(result))
		return result;
	if (rows != nullptr &&
	    !cu_nsp_rowset_to_colrow(request.columns, *rows, response.column_rows))
		return ecRpcFailed;
	return result;
}

uint32_t nsp_bridge_run(const GUID& session_guid, const updatestat_request& request, updatestat_response& response)
{
	int32_t delta;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.delta_requested != 0) {
		response.delta = cu_alloc<int32_t>();
		if (response.delta == nullptr)
			return ecRpcFailed;
	} else {
		response.delta = nullptr;
	}
	uint32_t result = nsp_interface_update_stat(ses, request.reserved, request.stat, &delta);
	if (request.delta_requested != 0)
		*response.delta = delta;
	return result;
}

void nsp_bridge_touch_handle(const GUID&)
{}
