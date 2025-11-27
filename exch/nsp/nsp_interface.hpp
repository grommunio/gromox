#pragma once

#include <gromox/common_types.hpp>

#include "nsp_types.hpp"

/*
 * @resv parameter needs to be 0 for nspiSeekEntries, nspiGetMatches,
 * nspiResolveNames(W), the others don't care (and hence that parameter is not
 * in the argument list).
 */

extern void nsp_interface_init();
extern ec_error_t nsp_interface_bind(uint64_t hrpc, uint32_t flags, const STAT *, FLATUID *server_guid, NSPI_HANDLE *);
extern ec_error_t nsp_interface_unbind(NSPI_HANDLE *);
extern ec_error_t nsp_interface_update_stat(NSPI_HANDLE, STAT *, int32_t *delta);
extern ec_error_t nsp_interface_query_rows(NSPI_HANDLE, uint32_t flags, STAT *, uint32_t table_count, uint32_t *table, uint32_t count, const LPROPTAG_ARRAY *, NSP_ROWSET **);
extern ec_error_t nsp_interface_seek_entries(NSPI_HANDLE, uint32_t, STAT *, const PROPERTY_VALUE &target, const MID_ARRAY *table, const LPROPTAG_ARRAY *, NSP_ROWSET **);
extern ec_error_t nsp_interface_get_matches(NSPI_HANDLE, uint32_t reserved1, STAT *, const NSPRES *filter, const NSP_PROPNAME *, uint32_t requested, MID_ARRAY **outmids, const LPROPTAG_ARRAY *, NSP_ROWSET **);
extern ec_error_t nsp_interface_resort_restriction(NSPI_HANDLE, STAT *, const MID_ARRAY *in, MID_ARRAY **out);
extern ec_error_t nsp_interface_dntomid(NSPI_HANDLE, const STRINGS_ARRAY *names, MID_ARRAY **out);
extern ec_error_t nsp_interface_get_proplist(NSPI_HANDLE, uint32_t flags, uint32_t mid, cpid_t, LPROPTAG_ARRAY **);
extern ec_error_t nsp_interface_get_props(NSPI_HANDLE, uint32_t flags, const STAT *, const LPROPTAG_ARRAY *, NSP_PROPROW **);
extern ec_error_t nsp_interface_compare_mids(NSPI_HANDLE, const STAT *, uint32_t mid1, uint32_t mid2, int32_t *cmp);
extern ec_error_t nsp_interface_mod_props(NSPI_HANDLE, const STAT *, const LPROPTAG_ARRAY *, const NSP_PROPROW *);
extern ec_error_t nsp_interface_get_specialtable(NSPI_HANDLE, uint32_t flags, const STAT *, uint32_t *version, NSP_ROWSET **);
extern ec_error_t nsp_interface_get_templateinfo(NSPI_HANDLE, uint32_t flags, uint32_t type, const char *dn, cpid_t, uint32_t locale_id, NSP_PROPROW **);
extern ec_error_t nsp_interface_mod_linkatt(NSPI_HANDLE, uint32_t flags, gromox::proptag_t, uint32_t mid, const BINARY_ARRAY *entry_ids);
extern ec_error_t nsp_interface_query_columns(NSPI_HANDLE, uint32_t flags, LPROPTAG_ARRAY **cols);
extern ec_error_t nsp_interface_resolve_names(NSPI_HANDLE, uint32_t resv, const STAT *, LPROPTAG_ARRAY *&, const STRINGS_ARRAY *, MID_ARRAY **, NSP_ROWSET **);
extern ec_error_t nsp_interface_resolve_namesw(NSPI_HANDLE, uint32_t resv, const STAT *, LPROPTAG_ARRAY *&, const STRINGS_ARRAY *, MID_ARRAY **, NSP_ROWSET **);
/* clean NSPI_HANDLE by system, not operation of interface */
void nsp_interface_unbind_rpc_handle(uint64_t hrpc);

extern unsigned int g_nsp_trace, g_nsp_synthesize_oneoff;
