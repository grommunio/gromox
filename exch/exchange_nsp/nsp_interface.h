#pragma once
#include "nsp_types.h"
#include "simple_tree.h"

#ifdef __cplusplus
extern "C" {
#endif

void nsp_interface_init(BOOL b_check);
extern int nsp_interface_run(void);
int nsp_interface_bind(uint64_t hrpc, uint32_t flags, STAT *pstat,
	FLATUID *pserver_guid, NSPI_HANDLE *phandle);

uint32_t nsp_interface_unbind(NSPI_HANDLE *phandle, uint32_t reserved);

int nsp_interface_update_stat(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, int32_t *pdelta);

int nsp_interface_query_rows(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, uint32_t table_count, uint32_t *ptable,
	uint32_t count, PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows);

int nsp_interface_seek_entries(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPERTY_VALUE *ptarget, PROPTAG_ARRAY *ptable,
	PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows);

int nsp_interface_get_matches(NSPI_HANDLE handle, uint32_t reserved1,
	STAT *pstat, PROPTAG_ARRAY *preserved, uint32_t reserved2,
	RESTRICTION *pfilter, PROPERTY_NAME *ppropname, uint32_t requested,
	PROPTAG_ARRAY **ppoutmids, PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows);

int nsp_interface_resort_restriction(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pinmids, PROPTAG_ARRAY **ppoutmids);

int nsp_interface_dntomid(NSPI_HANDLE handle, uint32_t reserved,
	STRINGS_ARRAY *pnames, PROPTAG_ARRAY **ppoutmids);

int nsp_interface_get_proplist(NSPI_HANDLE handle, uint32_t flags,
	uint32_t mid, uint32_t codepage, PROPTAG_ARRAY **ppproptags);

int nsp_interface_get_props(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, PROPTAG_ARRAY *pproptags, PROPERTY_ROW **pprows);

int nsp_interface_compare_mids(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, uint32_t mid1, uint32_t mid2, uint32_t *presult);

int nsp_interface_mod_props(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow);

int nsp_interface_get_specialtable(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, uint32_t *pversion, PROPROW_SET **pprows);

int nsp_interface_get_templateinfo(NSPI_HANDLE handle,
	uint32_t flags, uint32_t type, char *pdn, uint32_t codepage,
	uint32_t locale_id, PROPERTY_ROW **ppdata);

int nsp_interface_mod_linkatt(NSPI_HANDLE handle, uint32_t flags,
	uint32_t proptag, uint32_t mid, BINARY_ARRAY *pentry_ids);

int nsp_interface_query_columns(NSPI_HANDLE handle, uint32_t reserved,
	uint32_t flags, PROPTAG_ARRAY **ppcolumns);

int nsp_interface_resolve_names(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, STRINGS_ARRAY *pstrs,
	PROPTAG_ARRAY **ppmids, PROPROW_SET **pprows);

int nsp_interface_resolve_namesw(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, STRINGS_ARRAY *pstrs,
	PROPTAG_ARRAY **ppmids, PROPROW_SET **pprows);

/* clean NSPI_HANDLE by system, not operation of interface */
void nsp_interface_unbind_rpc_handle(uint64_t hrpc);

#ifdef __cplusplus
} /* extern "C" */
#endif
