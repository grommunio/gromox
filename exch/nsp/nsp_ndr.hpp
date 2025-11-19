#pragma once
#include <memory>
#include <gromox/defs.h>
#include <gromox/ndr.hpp>
#include "nsp_types.hpp"

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

using nsp_request = rpc_request;
using nsp_response = rpc_response;

struct NSPIBIND_IN final : public nsp_request {
	uint32_t flags;
	STAT stat;
	FLATUID *pserver_guid;
};

struct NSPIBIND_OUT final : public nsp_response {
	FLATUID *pserver_guid;
	NSPI_HANDLE handle;
	ec_error_t result;
};

struct NSPIUNBIND_IN final : public nsp_request {
	NSPI_HANDLE handle;
};

struct NSPIUNBIND_OUT final : public nsp_response {
	NSPI_HANDLE handle;
	ec_error_t result;
};

struct NSPIUPDATESTAT_IN final : public nsp_request {
	NSPI_HANDLE handle;
	STAT stat;
	int32_t *pdelta;
};

struct NSPIUPDATESTAT_OUT final : public nsp_response {
	STAT stat;
	int32_t *pdelta;
	ec_error_t result;
};

struct NSPIQUERYROWS_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	uint32_t table_count;
	uint32_t *ptable;
	uint32_t count;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPIQUERYROWS_OUT final : public nsp_response {
	STAT stat;
	NSP_ROWSET *prows;
	ec_error_t result;
};

struct NSPISEEKENTRIES_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	PROPERTY_VALUE target;
	MINID_ARRAY *ptable;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPISEEKENTRIES_OUT final : public nsp_response {
	STAT stat;
	NSP_ROWSET *prows;
	ec_error_t result;
};

struct NSPIGETMATCHES_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t reserved1;
	STAT stat;
	NSPRES *pfilter;
	NSP_PROPNAME *ppropname;
	uint32_t requested;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPIGETMATCHES_OUT final : public nsp_response {
	STAT stat;
	MINID_ARRAY *poutmids;
	NSP_ROWSET *prows;
	ec_error_t result;
};

struct NSPIRESORTRESTRICTION_IN final : public nsp_request {
	NSPI_HANDLE handle;
	STAT stat;
	MINID_ARRAY inmids;
};

struct NSPIRESORTRESTRICTION_OUT final : public nsp_response {
	STAT stat;
	MINID_ARRAY *poutmids;
	ec_error_t result;
};

struct NSPIDNTOMID_IN final : public nsp_request {
	NSPI_HANDLE handle;
	STRINGS_ARRAY names;
};

struct NSPIDNTOMID_OUT final : public nsp_response {
	MINID_ARRAY *poutmids;
	ec_error_t result;
};

struct NSPIGETPROPLIST_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t mid;
	cpid_t codepage;
};

struct NSPIGETPROPLIST_OUT final : public nsp_response {
	LPROPTAG_ARRAY *pproptags;
	ec_error_t result;
};

struct NSPIGETPROPS_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
};

struct NSPIGETPROPS_OUT final : public nsp_response {
	NSP_PROPROW *prows;
	ec_error_t result;
};

struct NSPICOMPAREMIDS_IN final : public nsp_request {
	NSPI_HANDLE handle;
	STAT stat;
	uint32_t mid1;
	uint32_t mid2;
};

struct NSPICOMPAREMIDS_OUT final : public nsp_response {
	int32_t cmp;
	ec_error_t result;
};

struct NSPIMODPROPS_IN final : public nsp_request {
	NSPI_HANDLE handle;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
	NSP_PROPROW row;
};

struct NSPIMODPROPS_OUT final : public nsp_response {
	ec_error_t result;
};

struct NSPIGETSPECIALTABLE_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
	STAT stat;
	uint32_t version;
};

struct NSPIGETSPECIALTABLE_OUT final : public nsp_response {
	uint32_t version;
	NSP_ROWSET *prows;
	ec_error_t result;
};

struct NSPIGETTEMPLATEINFO_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
	uint32_t type;
	char *pdn;
	cpid_t codepage;
	uint32_t locale_id;
};

struct NSPIGETTEMPLATEINFO_OUT final : public nsp_response {
	NSP_PROPROW *pdata;
	ec_error_t result;
};

struct NSPIMODLINKATT_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
	gromox::proptag_t proptag;
	uint32_t mid;
	BINARY_ARRAY entry_ids;
};

struct NSPIMODLINKATT_OUT final : public nsp_response {
	ec_error_t result;
};

struct NSPIQUERYCOLUMNS_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t flags;
};

struct NSPIQUERYCOLUMNS_OUT final : public nsp_response {
	LPROPTAG_ARRAY *pcolumns;
	ec_error_t result;
};

struct NSPIRESOLVENAMES_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
};

struct NSPIRESOLVENAMES_OUT final : public nsp_response {
	MINID_ARRAY *pmids;
	NSP_ROWSET *prows;
	ec_error_t result;
};

struct NSPIRESOLVENAMESW_IN final : public nsp_request {
	NSPI_HANDLE handle;
	uint32_t reserved;
	STAT stat;
	LPROPTAG_ARRAY *pproptags;
	STRINGS_ARRAY strs;
};

struct NSPIRESOLVENAMESW_OUT final : public nsp_response {
	MINID_ARRAY *pmids;
	NSP_ROWSET *prows;
	ec_error_t result;
};

extern pack_result exchange_nsp_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
extern pack_result exchange_nsp_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);
