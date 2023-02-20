#pragma once
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include "../nsp/nsp_types.h"

struct nsp_propname2 {
	GUID guid{};
	uint32_t id = 0;
};

struct nsp_rowset2 {
	LPROPTAG_ARRAY columns{};
	uint32_t row_count = 0;
	PROPERTY_ROW *rows = nullptr;
};

struct nsp_entryid {
	uint8_t id_type = 0; ///< cf. %ENTRYID_TYPE_*
	uint8_t r1 = 0, r2 = 0, r3 = 0; ///< reserved: 0x0
	GUID provider_uid{}; ///< NSPI server GUID
	uint32_t r4 = 0x1; ///< constant: 0x1
	uint32_t display_type = 0; ///< must match one of the existing display type value
	union {
		char *dn = nullptr; ///< DN string representing the object GUID
		uint32_t mid; ///<  mid of this object
	} payload;
};

struct nsp_entryids {
	uint32_t count = 0;
	nsp_entryid *entryid = nullptr;
};

struct bind_request {
	uint32_t flags = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	uint8_t *auxin = nullptr;
};

struct bind_response {
	uint32_t status = 0, result = 0;
	GUID server_guid{};
};

struct unbind_request {
	uint32_t reserved = 0, cb_auxin = 0;
	uint8_t *auxin = nullptr;
};

struct unbind_response {
	uint32_t status = 0, result = 0;
};

struct comparemids_request {
	uint32_t reserved = 0, mid1 = 0, mid2 = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	uint8_t *auxin = nullptr;
};

struct comparemids_response {
	uint32_t status = 0, result = 0, result1 = 0;
};

struct dntomid_request {
	uint32_t reserved = 0, cb_auxin = 0;
	STRING_ARRAY *names = nullptr;
	uint8_t *auxin = nullptr;
};

struct dntomid_response {
	uint32_t status = 0, result = 0;
	MID_ARRAY *outmids = nullptr;
};

struct getmatches_request {
	uint32_t reserved1 = 0, reserved2 = 0, row_count = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	MID_ARRAY *inmids = nullptr;
	RESTRICTION *filter = nullptr;
	nsp_propname2 *propname = nullptr;
	LPROPTAG_ARRAY *columns = nullptr;
	uint8_t *auxin = nullptr;
};

struct getmatches_response {
	uint32_t status = 0, result = 0;
	STAT *stat = nullptr;
	MID_ARRAY *mids = nullptr;
	nsp_rowset2 column_rows{};
};

struct getproplist_request {
	uint32_t flags = 0, mid = 0, codepage = CP_ACP, cb_auxin = 0;
	uint8_t *auxin = nullptr;
};

struct getproplist_response {
	uint32_t status = 0, result = 0;
	LPROPTAG_ARRAY *proptags = nullptr;
};

struct getprops_request {
	uint32_t flags = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	LPROPTAG_ARRAY *proptags = nullptr;
	uint8_t *auxin = nullptr;
};

struct getprops_response {
	uint32_t status = 0, result = 0, codepage = CP_ACP;
	LTPROPVAL_ARRAY *row = nullptr;
};

struct getspecialtable_request {
	uint32_t flags = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	uint32_t *version = nullptr;
	uint8_t *auxin = nullptr;
};

struct getspecialtable_response {
	uint32_t status = 0, result = 0, codepage = CP_ACP, count = 0;
	uint32_t *version = nullptr;
	LTPROPVAL_ARRAY *row = nullptr;
};

struct gettemplateinfo_request {
	uint32_t flags = 0, type = 0;
	char *dn = nullptr;
	uint32_t codepage = CP_ACP, locale_id = 0, cb_auxin = 0;
	uint8_t *auxin = nullptr;
};

struct gettemplateinfo_response {
	uint32_t status = 0, result = 0, codepage = CP_ACP;
	LTPROPVAL_ARRAY *row = nullptr;
};

struct modlinkatt_request {
	uint32_t flags = 0, proptag = 0, mid = 0, cb_auxin = 0;
	BINARY_ARRAY entryids{};
	uint8_t *auxin = nullptr;
};

struct modlinkatt_response {
	uint32_t status = 0, result = 0;
};

struct modprops_request {
	uint32_t reserved = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	LPROPTAG_ARRAY *proptags = nullptr;
	LTPROPVAL_ARRAY *values = nullptr;
	uint8_t *auxin = nullptr;
};

struct modprops_response {
	uint32_t status = 0, result = 0;
};

struct queryrows_request {
	uint32_t flags = 0, count = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	LPROPTAG_ARRAY *columns = nullptr;
	MID_ARRAY explicit_table{};
	uint8_t *auxin = nullptr;
};

struct queryrows_response {
	uint32_t status = 0, result = 0;
	STAT *stat = nullptr;
	nsp_rowset2 column_rows{};
};

struct querycolumns_request {
	uint32_t reserved = 0, flags = 0, cb_auxin = 0;
	uint8_t *auxin = nullptr;
};

struct querycolumns_response {
	uint32_t status = 0, result = 0;
	LPROPTAG_ARRAY *columns = nullptr;
};

struct resolvenames_request {
	uint32_t reserved = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	LPROPTAG_ARRAY *proptags = nullptr;
	STRING_ARRAY *names = nullptr;
	uint8_t *auxin = nullptr;
};

struct resolvenames_response {
	uint32_t status = 0, result = 0, codepage = CP_UTF16;
	MID_ARRAY *mids = nullptr;
	nsp_rowset2 column_rows{};
};

struct resortrestriction_request {
	uint32_t reserved = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	MID_ARRAY *inmids = nullptr;
	uint8_t *auxin = nullptr;
};

struct resortrestriction_response {
	uint32_t status = 0, result = 0;
	STAT *stat = nullptr;
	MID_ARRAY *outmids = nullptr;
};

struct seekentries_request {
	uint32_t reserved = 0, cb_auxin = 0;
	STAT *stat = nullptr;
	TAGGED_PROPVAL *target = nullptr;
	MID_ARRAY *explicit_table = nullptr;
	LPROPTAG_ARRAY *columns = nullptr;
	uint8_t *auxin = nullptr;
};

struct seekentries_response {
	uint32_t status = 0, result = 0;
	STAT *stat = nullptr;
	nsp_rowset2 column_rows{};
};

struct updatestat_request {
	uint32_t reserved = 0, cb_auxin = 0;
	uint8_t delta_requested = 0;
	STAT *stat = nullptr;
	uint8_t *auxin = nullptr;
};

struct updatestat_response {
	uint32_t status = 0, result = 0;
	STAT *stat = nullptr;
	int32_t *delta = nullptr;
};

struct getmailboxurl_request {
	uint32_t flags = 0, cb_auxin = 0;
	char *user_dn = nullptr;
	uint8_t *auxin = nullptr;
};

struct getmailboxurl_response {
	uint32_t status = 0, result = 0;
	char server_url[1024]{};
};

struct getaddressbookurl_request {
	uint32_t flags = 0, cb_auxin = 0;
	char *user_dn = nullptr;
	uint8_t *auxin = nullptr;
};

struct getaddressbookurl_response {
	uint32_t status = 0, result = 0;
	char server_url[1024]{};
};

struct nsp_ext_pull : public EXT_PULL {
	pack_result g_nsp_request(bind_request &);
	pack_result g_nsp_request(unbind_request &);
	pack_result g_nsp_request(comparemids_request &);
	pack_result g_nsp_request(dntomid_request &);
	pack_result g_nsp_request(getmatches_request &);
	pack_result g_nsp_request(getproplist_request &);
	pack_result g_nsp_request(getprops_request &);
	pack_result g_nsp_request(getspecialtable_request &);
	pack_result g_nsp_request(gettemplateinfo_request &);
	pack_result g_nsp_request(modlinkatt_request &);
	pack_result g_nsp_request(modprops_request &);
	pack_result g_nsp_request(queryrows_request &);
	pack_result g_nsp_request(querycolumns_request &);
	pack_result g_nsp_request(resolvenames_request &);
	pack_result g_nsp_request(resortrestriction_request &);
	pack_result g_nsp_request(seekentries_request &);
	pack_result g_nsp_request(updatestat_request &);
	pack_result g_nsp_request(getmailboxurl_request &);
	pack_result g_nsp_request(getaddressbookurl_request &);
};

struct nsp_ext_push : public EXT_PUSH {
	pack_result p_nsp_response(const bind_response &);
	pack_result p_nsp_response(const unbind_response &);
	pack_result p_nsp_response(const comparemids_response &);
	pack_result p_nsp_response(const dntomid_response &);
	pack_result p_nsp_response(const getmatches_response &);
	pack_result p_nsp_response(const getproplist_response &);
	pack_result p_nsp_response(const getprops_response &);
	pack_result p_nsp_response(const getspecialtable_response &);
	pack_result p_nsp_response(const gettemplateinfo_response &);
	pack_result p_nsp_response(const modlinkatt_response &);
	pack_result p_nsp_response(const modprops_response &);
	pack_result p_nsp_response(const queryrows_response &);
	pack_result p_nsp_response(const querycolumns_response &);
	pack_result p_nsp_response(const resolvenames_response &);
	pack_result p_nsp_response(const resortrestriction_response &);
	pack_result p_nsp_response(const seekentries_response &);
	pack_result p_nsp_response(const updatestat_response &);
	pack_result p_nsp_response(const getaddressbookurl_response &);
	pack_result p_nsp_response(const getmailboxurl_response &);
};
