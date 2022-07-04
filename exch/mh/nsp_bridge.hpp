#pragma once
#include <cstdint>
#include <gromox/rpc_types.hpp>
#include "nsp_ops.hpp"

using NSP_HANDLE = CONTEXT_HANDLE;
using STRINGS_ARRAY = STRING_ARRAY;

extern uint32_t nsp_bridge_unbind(GUID session, uint32_t resv);

extern uint32_t nsp_bridge_run(GUID&, const bind_request&, bind_response&);
extern uint32_t nsp_bridge_run(const GUID&, const comparemids_request&, comparemids_response&);
extern uint32_t nsp_bridge_run(const GUID&, const dntomid_request&, dntomid_response&);
extern uint32_t nsp_bridge_run(const GUID&, const getmatches_request&, getmatches_response&);
extern uint32_t nsp_bridge_run(const GUID&, const getproplist_request&, getproplist_response&);
extern uint32_t nsp_bridge_run(const GUID&, const getprops_request&, getprops_response&);
extern uint32_t nsp_bridge_run(const GUID&, const getspecialtable_request&, getspecialtable_response&);
extern uint32_t nsp_bridge_run(const GUID&, const gettemplateinfo_request&, gettemplateinfo_response&);
extern uint32_t nsp_bridge_run(const GUID&, const modlinkatt_request&, modlinkatt_response&);
extern uint32_t nsp_bridge_run(const GUID&, const modprops_request&, modprops_response&);
extern uint32_t nsp_bridge_run(const GUID&, const querycolumns_request&, querycolumns_response&);
extern uint32_t nsp_bridge_run(const GUID&, const queryrows_request&, queryrows_response&);
extern uint32_t nsp_bridge_run(const GUID&, const resolvenames_request&, resolvenames_response&);
extern uint32_t nsp_bridge_run(const GUID&, const resortrestriction_request&, resortrestriction_response&);
extern uint32_t nsp_bridge_run(const GUID&, const seekentries_request&, seekentries_response&);
extern uint32_t nsp_bridge_run(const GUID&, const updatestat_request&, updatestat_response&);

extern void nsp_bridge_touch_handle(const GUID&);

extern int (*nsp_interface_bind)(uint64_t hrpc, uint32_t flags, const STAT *, FLATUID *server_guid, NSP_HANDLE *);
extern uint32_t (*nsp_interface_unbind)(NSP_HANDLE *, uint32_t resv);
extern int (*nsp_interface_update_stat)(NSP_HANDLE, uint32_t resv, STAT *, int32_t *delta);
extern int (*nsp_interface_query_rows)(NSP_HANDLE, uint32_t flags, STAT *, uint32_t table_count, uint32_t *table, uint32_t count, const LPROPTAG_ARRAY *, NSP_ROWSET **);
extern int (*nsp_interface_seek_entries)(NSP_HANDLE, uint32_t resv, STAT *, PROPERTY_VALUE *target, const MID_ARRAY *table, const LPROPTAG_ARRAY *, NSP_ROWSET **);
extern int (*nsp_interface_get_matches)(NSP_HANDLE, uint32_t resv1, STAT *, const MID_ARRAY *resv, uint32_t resv2, const NSPRES *filter, const NSP_PROPNAME *, uint32_t requested, MID_ARRAY **outmids, const LPROPTAG_ARRAY *, NSP_ROWSET **);
extern int (*nsp_interface_resort_restriction)(NSP_HANDLE, uint32_t resv, STAT *, const MID_ARRAY *inmids, MID_ARRAY **outmids);
extern int (*nsp_interface_dntomid)(NSP_HANDLE, uint32_t resv, const STRINGS_ARRAY *names, MID_ARRAY **outmids);
extern int (*nsp_interface_get_proplist)(NSP_HANDLE, uint32_t flags, uint32_t mid, uint32_t codepage, LPROPTAG_ARRAY **);
extern int (*nsp_interface_get_props)(NSP_HANDLE, uint32_t flags, const STAT *, const LPROPTAG_ARRAY *, NSP_PROPROW **);
extern int (*nsp_interface_compare_mids)(NSP_HANDLE, uint32_t resv, const STAT *, uint32_t mid1, uint32_t mid2, uint32_t *result);
extern int (*nsp_interface_mod_props)(NSP_HANDLE, uint32_t resv, const STAT *, const LPROPTAG_ARRAY *, const NSP_PROPROW *);
extern int (*nsp_interface_get_specialtable)(NSP_HANDLE, uint32_t flags, const STAT *, uint32_t *version, NSP_ROWSET **);
extern int (*nsp_interface_get_templateinfo)(NSP_HANDLE, uint32_t flags, uint32_t type, const char *dn, uint32_t codepage, uint32_t locale_id, NSP_PROPROW **);
extern int (*nsp_interface_mod_linkatt)(NSP_HANDLE, uint32_t flags, uint32_t proptag, uint32_t mid, const BINARY_ARRAY *entry_ids);
extern int (*nsp_interface_query_columns)(NSP_HANDLE, uint32_t resv, uint32_t flags, LPROPTAG_ARRAY **cols);
extern int (*nsp_interface_resolve_namesw)(NSP_HANDLE, uint32_t resv, const STAT *, LPROPTAG_ARRAY *&, const STRING_ARRAY *, MID_ARRAY **, NSP_ROWSET **);
