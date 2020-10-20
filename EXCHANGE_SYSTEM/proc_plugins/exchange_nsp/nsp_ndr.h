#pragma once
#include "nsp_types.h"
#include "ndr.h"


typedef struct _NSPIBIND_IN {
	uint32_t flags;
	STAT stat;
	FLATUID *pserver_guid;
} NSPIBIND_IN;

typedef struct _NSPIBIND_OUT {
	FLATUID *pserver_guid;
	NSPI_HANDLE handle;
	uint32_t result;
} NSPIBIND_OUT;

typedef struct _NSPIUNBIND_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
} NSPIUNBIND_IN;

typedef struct _NSPIUNBIND_OUT {
	NSPI_HANDLE handle;
	uint32_t result;
} NSPIUNBIND_OUT;

typedef struct _NSPIUPDATESTAT_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	int32_t *pdelta;
} NSPIUPDATESTAT_IN;

typedef struct _NSPIUPDATESTAT_OUT {
	STAT stat;
	int32_t *pdelta;
	uint32_t result;
} NSPIUPDATESTAT_OUT;

typedef struct _NSPIQUERYROWS_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	uint32_t table_count;
	uint32_t *ptable;
	uint32_t count;
	PROPTAG_ARRAY *pproptags;
} NSPIQUERYROWS_IN;

typedef struct _NSPIQUERYROWS_OUT {
	STAT stat;
	PROPROW_SET *prows;
	uint32_t result;
} NSPIQUERYROWS_OUT;

typedef struct _NSPISEEKENTRIES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPERTY_VALUE target;
	PROPTAG_ARRAY *ptable;
	PROPTAG_ARRAY *pproptags;
} NSPISEEKENTRIES_IN;

typedef struct _NSPISEEKENTRIES_OUT {
	STAT stat;
	PROPROW_SET *prows;
	uint32_t result;
} NSPISEEKENTRIES_OUT;

typedef struct _NSPIGETMATCHES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved1;
	STAT stat;
	PROPTAG_ARRAY *preserved;
	uint32_t reserved2;
	RESTRICTION *pfilter;
	PROPERTY_NAME *ppropname;
	uint32_t requested;
	PROPTAG_ARRAY *pproptags;
} NSPIGETMATCHES_IN;

typedef struct _NSPIGETMATCHES_OUT {
	STAT stat;
	PROPTAG_ARRAY *poutmids;
	PROPROW_SET *prows;
	uint32_t result;
} NSPIGETMATCHES_OUT;

typedef struct _NSPIRESORTRESTRICTION_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY inmids;
	PROPTAG_ARRAY *poutmids;
} NSPIRESORTRESTRICTION_IN;

typedef struct _NSPIRESORTRESTRICTION_OUT {
	STAT stat;
	PROPTAG_ARRAY *poutmids;
	uint32_t result;
} NSPIRESORTRESTRICTION_OUT;

typedef struct _NSPIDNTOMID_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STRINGS_ARRAY names;
} NSPIDNTOMID_IN;

typedef struct _NSPIDNTOMID_OUT {
	PROPTAG_ARRAY *poutmids;
	uint32_t result;
} NSPIDNTOMID_OUT;

typedef struct _NSPIGETPROPLIST_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t mid;
	uint32_t codepage;
} NSPIGETPROPLIST_IN;

typedef struct _NSPIGETPROPLIST_OUT {
	PROPTAG_ARRAY *pproptags;
	uint32_t result;
} NSPIGETPROPLIST_OUT;

typedef struct _NSPIGETPROPS_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
} NSPIGETPROPS_IN;

typedef struct _NSPIGETPROPS_OUT {
	PROPERTY_ROW *prows;
	uint32_t result;
} NSPIGETPROPS_OUT;

typedef struct _NSPICOMPAREMIDS_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	uint32_t mid1;
	uint32_t mid2;
} NSPICOMPAREMIDS_IN;

typedef struct _NSPICOMPAREMIDS_OUT {
	uint32_t result;
	uint32_t result1;
} NSPICOMPAREMIDS_OUT;

typedef struct _NSPIMODPROPS_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
	PROPERTY_ROW row;
} NSPIMODPROPS_IN;

typedef struct _NSPIMODPROPS_OUT {
	uint32_t result;
} NSPIMODPROPS_OUT;

typedef struct _NSPIGETSPECIALTABLE_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	uint32_t version;
} NSPIGETSPECIALTABLE_IN;

typedef struct _NSPIGETSPECIALTABLE_OUT {
	uint32_t version;
	PROPROW_SET *prows;
	uint32_t result;
} NSPIGETSPECIALTABLE_OUT;

typedef struct _NSPIGETTEMPLATEINFO_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t type;
	char *pdn;
	uint32_t codepage;
	uint32_t locale_id;
} NSPIGETTEMPLATEINFO_IN;

typedef struct _NSPIGETTEMPLATEINFO_OUT {
	PROPERTY_ROW *pdata;
	uint32_t result;
} NSPIGETTEMPLATEINFO_OUT;

typedef struct _NSPIMODLINKATT_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t proptag;
	uint32_t mid;
	BINARY_ARRAY entry_ids;
} NSPIMODLINKATT_IN;

typedef struct _NSPIMODLINKATT_OUT {
	uint32_t result;
} NSPIMODLINKATT_OUT;

typedef struct _NSPIQUERYCOLUMNS_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	uint32_t flags;
} NSPIQUERYCOLUMNS_IN;

typedef struct _NSPIQUERYCOLUMNS_OUT {
	PROPTAG_ARRAY *pcolumns;
	uint32_t result;
} NSPIQUERYCOLUMNS_OUT;

typedef struct _NSPIRESOLVENAMES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
} NSPIRESOLVENAMES_IN;

typedef struct _NSPIRESOLVENAMES_OUT {
	PROPTAG_ARRAY *pmids;
	PROPROW_SET *prows;
	uint32_t result;
} NSPIRESOLVENAMES_OUT;

typedef struct _NSPIRESOLVENAMESW_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
} NSPIRESOLVENAMESW_IN;

typedef struct _NSPIRESOLVENAMESW_OUT {
	PROPTAG_ARRAY *pmids;
	PROPROW_SET *prows;
	uint32_t result;
} NSPIRESOLVENAMESW_OUT;

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
