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
	STAT stat;
	uint32_t flags = 0;
	FLATUID *pserver_guid = nullptr;
};

struct NSPIBIND_OUT final : public nsp_response {
	FLATUID *pserver_guid = nullptr;
	NSPI_HANDLE handle{};
	ec_error_t result{};
};

struct NSPIUNBIND_IN final : public nsp_request {
	NSPI_HANDLE handle{};
};

struct NSPIUNBIND_OUT final : public nsp_response {
	NSPI_HANDLE handle{};
	ec_error_t result{};
};

struct NSPIUPDATESTAT_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	int32_t *pdelta = nullptr;
};

struct NSPIUPDATESTAT_OUT final : public nsp_response {
	STAT stat;
	ec_error_t result{};
	int32_t *pdelta = nullptr;
};

struct NSPIQUERYROWS_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	uint32_t flags = 0, table_count = 0, count = 0;
	uint32_t *ptable = nullptr;
	LPROPTAG_ARRAY *pproptags = nullptr;
};

struct NSPIQUERYROWS_OUT final : public nsp_response {
	STAT stat;
	ec_error_t result{};
	NSP_ROWSET *prows = nullptr;
};

struct NSPISEEKENTRIES_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	uint32_t reserved = 0;
	PROPERTY_VALUE target{};
	MINID_ARRAY *ptable = nullptr;
	LPROPTAG_ARRAY *pproptags = nullptr;
};

struct NSPISEEKENTRIES_OUT final : public nsp_response {
	STAT stat;
	ec_error_t result{};
	NSP_ROWSET *prows = nullptr;
};

struct NSPIGETMATCHES_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t reserved1 = 0, requested = 0;
	STAT stat;
	NSPRES *pfilter = nullptr;
	NSP_PROPNAME *ppropname = nullptr;
	LPROPTAG_ARRAY *pproptags = nullptr;
};

struct NSPIGETMATCHES_OUT final : public nsp_response {
	STAT stat;
	ec_error_t result{};
	MINID_ARRAY *poutmids = nullptr;
	NSP_ROWSET *prows = nullptr;
};

struct NSPIRESORTRESTRICTION_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	MINID_ARRAY inmids{};
};

struct NSPIRESORTRESTRICTION_OUT final : public nsp_response {
	STAT stat;
	ec_error_t result{};
	MINID_ARRAY *poutmids = nullptr;
};

struct NSPIDNTOMID_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STRINGS_ARRAY names{};
};

struct NSPIDNTOMID_OUT final : public nsp_response {
	MINID_ARRAY *poutmids = nullptr;
	ec_error_t result{};
};

struct NSPIGETPROPLIST_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t flags = 0, mid = 0;
	cpid_t codepage{};
};

struct NSPIGETPROPLIST_OUT final : public nsp_response {
	LPROPTAG_ARRAY *pproptags = nullptr;
	ec_error_t result{};
};

struct NSPIGETPROPS_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	uint32_t flags = 0;
	LPROPTAG_ARRAY *pproptags = nullptr;
};

struct NSPIGETPROPS_OUT final : public nsp_response {
	NSP_PROPROW *prows = nullptr;
	ec_error_t result{};
};

struct NSPICOMPAREMIDS_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	uint32_t mid1 = 0, mid2 = 0;
};

struct NSPICOMPAREMIDS_OUT final : public nsp_response {
	int32_t cmp = 0;
	ec_error_t result{};
};

struct NSPIMODPROPS_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	LPROPTAG_ARRAY *pproptags = nullptr;
	NSP_PROPROW row{};
};

struct NSPIMODPROPS_OUT final : public nsp_response {
	ec_error_t result{};
};

struct NSPIGETSPECIALTABLE_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	STAT stat;
	uint32_t flags = 0, version = 0;
};

struct NSPIGETSPECIALTABLE_OUT final : public nsp_response {
	uint32_t version = 0;
	ec_error_t result{};
	NSP_ROWSET *prows = nullptr;
};

struct NSPIGETTEMPLATEINFO_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t flags = 0, type = 0, locale_id = 0;
	cpid_t codepage{};
	char *pdn = nullptr;
};

struct NSPIGETTEMPLATEINFO_OUT final : public nsp_response {
	NSP_PROPROW *pdata = nullptr;
	ec_error_t result{};
};

struct NSPIMODLINKATT_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t flags = 0, mid = 0;
	gromox::proptag_t proptag{};
	BINARY_ARRAY entry_ids{};
};

struct NSPIMODLINKATT_OUT final : public nsp_response {
	ec_error_t result{};
};

struct NSPIQUERYCOLUMNS_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t flags = 0;
};

struct NSPIQUERYCOLUMNS_OUT final : public nsp_response {
	LPROPTAG_ARRAY *pcolumns = nullptr;
	ec_error_t result{};
};

struct NSPIRESOLVENAMES_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t reserved = 0;
	STAT stat;
	LPROPTAG_ARRAY *pproptags = nullptr;
	STRINGS_ARRAY strs{};
};

struct NSPIRESOLVENAMES_OUT final : public nsp_response {
	MINID_ARRAY *pmids = nullptr;
	NSP_ROWSET *prows = nullptr;
	ec_error_t result{};
};

struct NSPIRESOLVENAMESW_IN final : public nsp_request {
	NSPI_HANDLE handle{};
	uint32_t reserved = 0;
	STAT stat;
	LPROPTAG_ARRAY *pproptags = nullptr;
	STRINGS_ARRAY strs{};
};

struct NSPIRESOLVENAMESW_OUT final : public nsp_response {
	MINID_ARRAY *pmids = nullptr;
	NSP_ROWSET *prows = nullptr;
	ec_error_t result{};
};

extern pack_result exchange_nsp_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
extern pack_result exchange_nsp_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);
