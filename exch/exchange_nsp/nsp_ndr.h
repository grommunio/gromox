#pragma once
#include "nsp_types.h"
#include <gromox/ndr.hpp>

struct NSPIBIND_IN {
	uint32_t flags;
	STAT stat;
	FLATUID *pserver_guid;
};

struct NSPIBIND_OUT {
	FLATUID *pserver_guid;
	NSPI_HANDLE handle;
	uint32_t result;
};

struct NSPIUNBIND_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
};

struct NSPIUNBIND_OUT {
	NSPI_HANDLE handle;
	uint32_t result;
};

struct NSPIUPDATESTAT_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	int32_t *pdelta;
};

struct NSPIUPDATESTAT_OUT {
	STAT stat;
	int32_t *pdelta;
	uint32_t result;
};

struct NSPIQUERYROWS_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	uint32_t table_count;
	uint32_t *ptable;
	uint32_t count;
	PROPTAG_ARRAY *pproptags;
};

struct NSPIQUERYROWS_OUT {
	STAT stat;
	PROPROW_SET *prows;
	uint32_t result;
};

struct NSPISEEKENTRIES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPERTY_VALUE target;
	PROPTAG_ARRAY *ptable;
	PROPTAG_ARRAY *pproptags;
};

struct NSPISEEKENTRIES_OUT {
	STAT stat;
	PROPROW_SET *prows;
	uint32_t result;
};

struct NSPIGETMATCHES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved1;
	STAT stat;
	PROPTAG_ARRAY *preserved;
	uint32_t reserved2;
	RESTRICTION *pfilter;
	PROPERTY_NAME *ppropname;
	uint32_t requested;
	PROPTAG_ARRAY *pproptags;
};

struct NSPIGETMATCHES_OUT {
	STAT stat;
	PROPTAG_ARRAY *poutmids;
	PROPROW_SET *prows;
	uint32_t result;
};

struct NSPIRESORTRESTRICTION_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY inmids;
	PROPTAG_ARRAY *poutmids;
};

struct NSPIRESORTRESTRICTION_OUT {
	STAT stat;
	PROPTAG_ARRAY *poutmids;
	uint32_t result;
};

struct NSPIDNTOMID_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STRINGS_ARRAY names;
};

struct NSPIDNTOMID_OUT {
	PROPTAG_ARRAY *poutmids;
	uint32_t result;
};

struct NSPIGETPROPLIST_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t mid;
	uint32_t codepage;
};

struct NSPIGETPROPLIST_OUT {
	PROPTAG_ARRAY *pproptags;
	uint32_t result;
};

struct NSPIGETPROPS_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
};

struct NSPIGETPROPS_OUT {
	PROPERTY_ROW *prows;
	uint32_t result;
};

struct NSPICOMPAREMIDS_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	uint32_t mid1;
	uint32_t mid2;
};

struct NSPICOMPAREMIDS_OUT {
	uint32_t result;
	uint32_t result1;
};

struct NSPIMODPROPS_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
	PROPERTY_ROW row;
};

struct NSPIMODPROPS_OUT {
	uint32_t result;
};

struct NSPIGETSPECIALTABLE_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	uint32_t version;
};

struct NSPIGETSPECIALTABLE_OUT {
	uint32_t version;
	PROPROW_SET *prows;
	uint32_t result;
};

struct NSPIGETTEMPLATEINFO_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t type;
	char *pdn;
	uint32_t codepage;
	uint32_t locale_id;
};

struct NSPIGETTEMPLATEINFO_OUT {
	PROPERTY_ROW *pdata;
	uint32_t result;
};

struct NSPIMODLINKATT_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t proptag;
	uint32_t mid;
	BINARY_ARRAY entry_ids;
};

struct NSPIMODLINKATT_OUT {
	uint32_t result;
};

struct NSPIQUERYCOLUMNS_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	uint32_t flags;
};

struct NSPIQUERYCOLUMNS_OUT {
	PROPTAG_ARRAY *pcolumns;
	uint32_t result;
};

struct NSPIRESOLVENAMES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
};

struct NSPIRESOLVENAMES_OUT {
	PROPTAG_ARRAY *pmids;
	PROPROW_SET *prows;
	uint32_t result;
};

struct NSPIRESOLVENAMESW_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
};

struct NSPIRESOLVENAMESW_OUT {
	PROPTAG_ARRAY *pmids;
	PROPROW_SET *prows;
	uint32_t result;
};

#ifdef __cplusplus
extern "C" {
#endif

int nsp_ndr_pull_nspibind(NDR_PULL *pndr, NSPIBIND_IN *r);

int nsp_ndr_push_nspibind(NDR_PUSH *pndr, const NSPIBIND_OUT *r);

int nsp_ndr_pull_nspiunbind(NDR_PULL *pndr, NSPIUNBIND_IN *r);

int nsp_ndr_push_nspiunbind(NDR_PUSH *pndr, const NSPIUNBIND_OUT *r);

int nsp_ndr_pull_nspiupdatestat(NDR_PULL *pndr, NSPIUPDATESTAT_IN *r);

int nsp_ndr_push_nspiupdatestat(NDR_PUSH *pndr, const NSPIUPDATESTAT_OUT *r);

int nsp_ndr_pull_nspiqueryrows(NDR_PULL *pndr, NSPIQUERYROWS_IN *r);

int nsp_ndr_push_nspiqueryrows(NDR_PUSH *pndr, const NSPIQUERYROWS_OUT *r);

int nsp_ndr_pull_nspiseekentries(NDR_PULL *pndr, NSPISEEKENTRIES_IN *r);

int nsp_ndr_push_nspiseekentries(NDR_PUSH *pndr, const NSPISEEKENTRIES_OUT *r);

int nsp_ndr_pull_nspigetmatches(NDR_PULL *pndr, NSPIGETMATCHES_IN *r);

int nsp_ndr_push_nspigetmatches(NDR_PUSH *pndr, const NSPIGETMATCHES_OUT *r);

int nsp_ndr_pull_nspiresortrestriction(NDR_PULL *pndr, NSPIRESORTRESTRICTION_IN *r);

int nsp_ndr_push_nspiresortrestriction(NDR_PUSH *pndr, const NSPIRESORTRESTRICTION_OUT *r);

int nsp_ndr_pull_nspidntomid(NDR_PULL *pndr, NSPIDNTOMID_IN *r);

int nsp_ndr_push_nspidntomid(NDR_PUSH *pndr, const NSPIDNTOMID_OUT *r);

int nsp_ndr_pull_nspigetproplist(NDR_PULL *pndr, NSPIGETPROPLIST_IN *r);

int nsp_ndr_push_nspigetproplist(NDR_PUSH *pndr, const NSPIGETPROPLIST_OUT *r);

int nsp_ndr_pull_nspigetprops(NDR_PULL *pndr, NSPIGETPROPS_IN *r);

int nsp_ndr_push_nspigetprops(NDR_PUSH *pndr, const NSPIGETPROPS_OUT *r);

int nsp_ndr_pull_nspicomparemids(NDR_PULL *pndr, NSPICOMPAREMIDS_IN *r);

int nsp_ndr_push_nspicomparemids(NDR_PUSH *pndr, const NSPICOMPAREMIDS_OUT *r);

int nsp_ndr_pull_nspimodprops(NDR_PULL *pndr, NSPIMODPROPS_IN *r);

int nsp_ndr_push_nspimodprops(NDR_PUSH *pndr, const NSPIMODPROPS_OUT *r);

int nsp_ndr_pull_nspigetspecialtable(NDR_PULL *pndr, NSPIGETSPECIALTABLE_IN *r);

int nsp_ndr_push_nspigetspecialtable(NDR_PUSH *pndr, const NSPIGETSPECIALTABLE_OUT *r);

int nsp_ndr_pull_nspigettemplateinfo(NDR_PULL *pndr, NSPIGETTEMPLATEINFO_IN *r);

int nsp_ndr_push_nspigettemplateinfo(NDR_PUSH *pndr, const NSPIGETTEMPLATEINFO_OUT *r);

int nsp_ndr_pull_nspimodlinkatt(NDR_PULL *pndr, NSPIMODLINKATT_IN *r);

int nsp_ndr_push_nspimodlinkatt(NDR_PUSH *pndr, const NSPIMODLINKATT_OUT *r);

int nsp_ndr_pull_nspiquerycolumns(NDR_PULL *pndr, NSPIQUERYCOLUMNS_IN *r);

int nsp_ndr_push_nspiquerycolumns(NDR_PUSH *pndr, const NSPIQUERYCOLUMNS_OUT *r);

int nsp_ndr_pull_nspiresolvenames(NDR_PULL *pndr, NSPIRESOLVENAMES_IN *r);

int nsp_ndr_push_nspiresolvenames(NDR_PUSH *pndr, const NSPIRESOLVENAMES_OUT *r);

int nsp_ndr_pull_nspiresolvenamesw(NDR_PULL *pndr, NSPIRESOLVENAMESW_IN *r);

int nsp_ndr_push_nspiresolvenamesw(NDR_PUSH *pndr, const NSPIRESOLVENAMESW_OUT *r);

#ifdef __cplusplus
} /* extern "C" */
#endif
