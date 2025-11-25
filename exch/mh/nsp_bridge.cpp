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

static inline bool Failed(ec_error_t hresult)
{
	return hresult != ecSuccess && hresult != ecWarnWithErrors;
}

template<typename T> static inline auto optional_ptr(std::optional<T> &p) { return p ? &*p : nullptr; }
template<typename T> static inline auto optional_ptr(const std::optional<T> &p) { return p ? &*p : nullptr; }
template<typename T> static inline auto optional_ptr(const std::vector<T> &p) { return p.size() != 0 ? &p : nullptr; }

ec_error_t nsp_bridge_unbind(GUID session_guid)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_unbind(&ses);
}

ec_error_t nsp_bridge_run(GUID& session_guid, const bind_request &request,
    bind_response &response)
{
	FLATUID server_flatuid;
	NSP_HANDLE ses;
	auto result = nsp_interface_bind(0, request.flags, request.stat,
	              &server_flatuid, &ses);
	if (Failed(result)) {
		session_guid = {};
		response.server_guid = {};
	} else {
		response.server_guid = server_flatuid;
		session_guid = ses.guid;
	}
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const comparemids_request &request, comparemids_response &response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_compare_mids(ses, request.stat,
	       request.mid1, request.mid2, &response.cmp);
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const dntomid_request &request, dntomid_response &response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_dntomid(ses, request.names, &response.outmids);
}

static inline proptag_cspan optional_columns(const LPROPTAG_ARRAY *a)
{
	return a != nullptr ? proptag_cspan(*a) : proptag_cspan();
}

static inline proptag_cspan optional_columns(const std::optional<std::vector<gromox::proptag_t>> &a)
{
	return a.has_value() ? proptag_cspan(*a) : proptag_cspan();
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const getmatches_request &request, getmatches_response &response)
{
	NSPRES *nspres = nullptr;
	NSP_ROWSET *outrows = nullptr;
	NSP_PROPNAME *nspname = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.filter != nullptr) {
		nspres = cu_alloc<NSPRES>();
		if (nspres == nullptr ||
		    !cu_restriction_to_nspres(*request.filter, *nspres))
			return ecRpcFailed;
	}
	if (request.propname != nullptr) {
		nspname = cu_alloc<NSP_PROPNAME>();
		if (nspname == nullptr ||
		    !cu_propname_to_nsp(*request.propname, *nspname))
			return ecRpcFailed;
	}
	response.stat = request.stat;
	auto result = nsp_interface_get_matches(ses, request.reserved1, response.stat,
	              nspres, nspname, request.row_count,
	              response.mids, optional_ptr(request.columns), &outrows);
	if (Failed(result))
		return result;
	if (outrows != nullptr &&
	    !cu_nsp_rowset_to_colrow(optional_columns(request.columns),
	    *outrows, response.column_rows))
		return ecRpcFailed;
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const getproplist_request &request, getproplist_response &response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_get_proplist(ses, request.flags, request.mid,
	       request.codepage, &response.proptags);
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const getprops_request &request, getprops_response &response)
{
	NSP_PROPROW *row;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	auto result = nsp_interface_get_props(ses, request.flags,
	              request.stat, request.proptags, &row);
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
	response.codepage = request.stat.codepage;
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const getspecialtable_request &request, getspecialtable_response &response)
{
	uint32_t version;
	NSP_ROWSET *rows;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.version != nullptr)
		version = *request.version;
	auto result = nsp_interface_get_specialtable(ses, request.flags,
	              request.stat, &version, &rows);
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
	response.codepage = request.stat.codepage;
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const gettemplateinfo_request &request, gettemplateinfo_response &response)
{
	NSP_PROPROW *row;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	auto result = nsp_interface_get_templateinfo(ses, request.flags, request.type, request.dn,
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

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const modlinkatt_request &request, modlinkatt_response &)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_mod_linkatt(ses, request.flags, request.proptag,
	       request.mid, &request.entryids);
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const modprops_request &request, modprops_response &)
{
	NSP_PROPROW *row = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	if (request.values != nullptr) {
		row = cu_alloc<NSP_PROPROW>();
		if (row == nullptr ||
		    !cu_proplist_to_nsp_proprow(*request.values, *row))
			return ecRpcFailed;
	}
	return nsp_interface_mod_props(ses, request.stat, request.proptags, row);
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const querycolumns_request &request, querycolumns_response &response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	return nsp_interface_query_columns(ses, request.flags, &response.columns);
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const queryrows_request &request, queryrows_response &response)
{
	NSP_ROWSET *rows = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	response.stat = request.stat;
	auto result = nsp_interface_query_rows(ses, request.flags, response.stat,
	              optional_ptr(request.explicit_table), request.count,
	              optional_ptr(request.columns), &rows);
	if (Failed(result))
		return result;
	if (rows != nullptr &&
	    !cu_nsp_rowset_to_colrow(optional_columns(request.columns),
	    *rows, response.column_rows))
		return ecRpcFailed;
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const resolvenames_request &request, resolvenames_response &response)
{
	NSP_ROWSET *rows = nullptr;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	auto tags = request.proptags;
	auto result = nsp_interface_resolve_namesw(ses, request.reserved, request.stat,
	              tags, request.names, &response.mids, &rows);
	if (Failed(result))
		return result;
	if (rows != nullptr &&
	    !cu_nsp_rowset_to_colrow(optional_columns(request.proptags),
	    *rows, response.column_rows))
		return ecRpcFailed;
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const resortrestriction_request &request, resortrestriction_response &response)
{
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	response.stat = request.stat;
	return nsp_interface_resort_restriction(ses, response.stat,
	       request.inmids, &response.outmids);
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const seekentries_request &request, seekentries_response &response)
{
	NSP_ROWSET *rows = nullptr;
	PROPERTY_VALUE target_val{};
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};

	if (!cu_tpropval_to_propval(request.target, target_val))
		return ecRpcFailed;
	response.stat = request.stat;
	auto result = nsp_interface_seek_entries(ses, request.reserved, response.stat,
	              target_val, optional_ptr(request.explicit_table),
	              optional_ptr(request.columns), &rows);
	if (Failed(result))
		return result;
	if (rows != nullptr &&
	    !cu_nsp_rowset_to_colrow(optional_columns(request.columns),
	    *rows, response.column_rows))
		return ecRpcFailed;
	return result;
}

ec_error_t nsp_bridge_run(const GUID &session_guid,
    const updatestat_request &request, updatestat_response &response)
{
	int32_t delta = 0;
	NSP_HANDLE ses = {HANDLE_EXCHANGE_NSP, session_guid};
	response.stat = request.stat;
	auto result = nsp_interface_update_stat(ses, response.stat, &delta);
	if (request.delta_requested != 0)
		response.delta.emplace(delta);
	return result;
}

void nsp_bridge_touch_handle(const GUID&)
{}
