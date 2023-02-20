#pragma once
#include <gromox/ndr.hpp>
#include "nsp_types.h"

enum {
	nspiBind = 0,
	nspiUnbind = 1,
	nspiUpdateStat = 2,
	nspiQueryRows = 3,
	nspiSeekEntries = 4,
	nspiGetMatches = 5,
	nspiResortRestriction = 6,
	nspiDNToMId = 7,
	nspiGetPropList = 8,
	nspiGetProps = 9,
	nspiCompareMIds = 10,
	nspiModProps = 11,
	nspiGetSpecialTable = 12,
	nspiGetTemplateInfo = 13,
	nspiModLinkAtt = 14,
	nspiQueryColumns = 16,
	nspiResolveNames = 19,
	nspiResolveNamesW = 20,
};

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
	LPROPTAG_ARRAY *pproptags;
};

struct NSPIQUERYROWS_OUT {
	STAT stat;
	NSP_ROWSET *prows;
	uint32_t result;
};

struct NSPISEEKENTRIES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPERTY_VALUE target;
	LPROPTAG_ARRAY *ptable;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPISEEKENTRIES_OUT {
	STAT stat;
	NSP_ROWSET *prows;
	uint32_t result;
};

struct NSPIGETMATCHES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved1;
	STAT stat;
	LPROPTAG_ARRAY *preserved;
	uint32_t reserved2;
	NSPRES *pfilter;
	NSP_PROPNAME *ppropname;
	uint32_t requested;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPIGETMATCHES_OUT {
	STAT stat;
	LPROPTAG_ARRAY *poutmids;
	NSP_ROWSET *prows;
	uint32_t result;
};

struct NSPIRESORTRESTRICTION_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	LPROPTAG_ARRAY inmids;
	LPROPTAG_ARRAY *poutmids;
};

struct NSPIRESORTRESTRICTION_OUT {
	STAT stat;
	LPROPTAG_ARRAY *poutmids;
	uint32_t result;
};

struct NSPIDNTOMID_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STRINGS_ARRAY names;
};

struct NSPIDNTOMID_OUT {
	LPROPTAG_ARRAY *poutmids;
	uint32_t result;
};

struct NSPIGETPROPLIST_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t mid;
	cpid_t codepage;
};

struct NSPIGETPROPLIST_OUT {
	LPROPTAG_ARRAY *pproptags;
	uint32_t result;
};

struct NSPIGETPROPS_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPIGETPROPS_OUT {
	NSP_PROPROW *prows;
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
	LPROPTAG_ARRAY *pproptags;
	NSP_PROPROW row;
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
	NSP_ROWSET *prows;
	uint32_t result;
};

struct NSPIGETTEMPLATEINFO_IN {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t type;
	char *pdn;
	cpid_t codepage;
	uint32_t locale_id;
};

struct NSPIGETTEMPLATEINFO_OUT {
	NSP_PROPROW *pdata;
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
	LPROPTAG_ARRAY *pcolumns;
	uint32_t result;
};

struct NSPIRESOLVENAMES_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
};

struct NSPIRESOLVENAMES_OUT {
	LPROPTAG_ARRAY *pmids;
	NSP_ROWSET *prows;
	uint32_t result;
};

struct NSPIRESOLVENAMESW_IN {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
};

struct NSPIRESOLVENAMESW_OUT {
	LPROPTAG_ARRAY *pmids;
	NSP_ROWSET *prows;
	uint32_t result;
};

extern pack_result exchange_nsp_ndr_pull(int op, NDR_PULL *, void **in);
extern pack_result exchange_nsp_ndr_push(int op, NDR_PUSH *, void *out);
