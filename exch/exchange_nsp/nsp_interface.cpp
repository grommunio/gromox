// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/oxoabkt.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include "nsp_interface.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include <gromox/ndr_stack.hpp>
#include <gromox/list_file.hpp>
#include "ab_tree.h"
#include <gromox/guid.hpp>
#include <gromox/util.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include "../mysql_adaptor/mysql_adaptor.h"

using namespace gromox;

struct nsp_sort_item {
	uint32_t minid;
	union {
		char *string;
		void *strv;
	};
};

struct dlgitem {
	char user[256];
};

enum {
	TI_TEMPLATE = 0x1,
	TI_SCRIPT = 0x4,
};

static BOOL g_session_check;
static bool (*verify_cpid)(uint32_t cpid);
static BOOL (*get_domain_ids)(const char *domainname,
	int *pdomain_id, int *porg_id);
static BOOL (*get_maildir)(const char *username, char *maildir);
static BOOL (*get_id_from_username)(const char *username, int *puser_id);
static decltype(gromox::abkt_tojson) *nsp_abktojson;
static decltype(gromox::abkt_tobinary) *nsp_abktobinary;

static uint32_t nsp_interface_fetch_property(SIMPLE_TREE_NODE *pnode,
    BOOL b_ephid, uint32_t codepage, uint32_t proptag, PROPERTY_VALUE *pprop,
    void *pbuff, size_t pbsize)
{
	int minid;
	int temp_len;
	char dn[1280]{};
	GUID temp_guid;
	uint8_t node_type;
	const uint8_t *pguid;
	DCERPC_INFO rpc_info;
	uint32_t display_type;
	EPHEMERAL_ENTRYID ephid;
	PERMANENT_ENTRYID permeid;
	
	temp_len = 1024;
	pprop->proptag = proptag;
	pprop->reserved = 0;
	node_type = ab_tree_get_node_type(pnode);
	/* Properties that need to be force-generated */
	switch (proptag) {
	case PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE:
	case PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE_STRING8:
		if (NODE_TYPE_ROOM != node_type &&
		    node_type != NODE_TYPE_PERSON &&
			NODE_TYPE_EQUIPMENT != node_type) {
			return ecNotFound;
		}
		ab_tree_get_server_dn(pnode, dn, sizeof(dn));
		strcat(dn, "/cn=Microsoft Private MDB");
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
			strcpy(static_cast<char *>(pprop->value.pv), dn);
		} else {
			pprop->value.pv = pbuff;
			HX_strlcpy(pprop->value.pstr, dn, pbsize);
		}
		return ecSuccess;
	case PROP_TAG_ADDRESSBOOKOBJECTGUID:
		ab_tree_node_to_guid(pnode, &temp_guid);
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (pprop->value.bin.pv == nullptr)
				return ecMAPIOOM;
		} else {
			pprop->value.bin.pv = deconst(pbuff);
		}
		common_util_guid_to_binary(&temp_guid, &pprop->value.bin);
		return ecSuccess;
	case PROP_TAG_ADDRESSBOOKCONTAINERID:
		pnode = simple_tree_node_get_parent(pnode);
		if (NULL == pnode) {
			pprop->value.l = 0;
		} else {
			pprop->value.l = ab_tree_get_node_minid(pnode);
		}
		return ecSuccess;
	case PROP_TAG_ADDRESSTYPE:
	case PROP_TAG_ADDRESSTYPE_STRING8:
		pprop->value.pstr = deconst("EX");
		return ecSuccess;
	case PROP_TAG_EMAILADDRESS:
	case PROP_TAG_EMAILADDRESS_STRING8:
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return ecInvalidObject;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PROP_TAG_OBJECTTYPE:
		if (NODE_TYPE_MLIST == node_type) {
			pprop->value.l = OT_DISTLIST;
		} else if (NODE_TYPE_FOLDER == node_type) {
			pprop->value.l = OT_FOLDER;
		} else {
			pprop->value.l = OT_MAILUSER;
		}
		return ecSuccess;
	case PROP_TAG_DISPLAYTYPE:
		if (NODE_TYPE_MLIST == node_type) {
			pprop->value.l = DT_DISTLIST;
		} else {
			pprop->value.l = DT_MAILUSER;
		}
		return ecSuccess;
	case PROP_TAG_DISPLAYTYPEEX:
		if (NODE_TYPE_ROOM == node_type) {
			pprop->value.l = DT_ROOM;
		} else if (NODE_TYPE_EQUIPMENT == node_type) {
			pprop->value.l = DT_EQUIPMENT;
		} else {
			pprop->value.l = DT_MAILUSER | DTE_FLAG_ACL_CAPABLE;
		}
		return ecSuccess;
	case PROP_TAG_MAPPINGSIGNATURE:
		pprop->value.bin.cb = 16;
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (NULL == pprop->value.bin.pb) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.bin.pv = pbuff;
		}
		pguid = common_util_get_nspi_guid();
		memcpy(pprop->value.bin.pb, pguid, 16);
		return ecSuccess;
	case PROP_TAG_TEMPLATEID:
		if (NODE_TYPE_MLIST == node_type) {
			display_type = DT_DISTLIST;
		} else {
			display_type = DT_MAILUSER;
		}
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return ecNotFound;
		if (FALSE == common_util_set_permanententryid(
			display_type, NULL, dn, &permeid) || FALSE ==
			common_util_permanent_entryid_to_binary(
			&permeid, &pprop->value.bin)) {
			return ecMAPIOOM;
		}
		return ecSuccess;
	case PROP_TAG_ENTRYID:
	case PROP_TAG_RECORDKEY:
	case PROP_TAG_ORIGINALENTRYID:
		if (NODE_TYPE_MLIST == node_type) {
			display_type = DT_DISTLIST;
		} else {
			display_type = DT_MAILUSER;
		}
		if (FALSE == b_ephid) {
			if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
				return ecNotFound;
			if (FALSE == common_util_set_permanententryid(
				display_type, NULL, dn, &permeid) || FALSE ==
				common_util_permanent_entryid_to_binary(
				&permeid, &pprop->value.bin)) {
				return ecMAPIOOM;
			}
		} else {
			common_util_set_ephemeralentryid(display_type,
				ab_tree_get_node_minid(pnode), &ephid);
			if (FALSE == common_util_ephemeral_entryid_to_binary(
				&ephid, &pprop->value.bin)) {
				return ecMAPIOOM;
			}
		}
		return ecSuccess;
	case PROP_TAG_SEARCHKEY:
		if (!ab_tree_node_to_dn(pnode, dn, GX_ARRAY_SIZE(dn)))
			return ecNotFound;
		pprop->value.bin.cb = strlen(dn) + 4;
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(
				NDR_STACK_OUT, pprop->value.bin.cb);
			if (pprop->value.bin.pc == nullptr)
				return ecMAPIOOM;
		} else {
			pprop->value.bin.pv = pbuff;
		}
		sprintf(pprop->value.bin.pc, "EX:%s", dn);
		HX_strupper(pprop->value.bin.pc);
		return ecSuccess;
	case PROP_TAG_INSTANCEKEY:
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 4);
			if (NULL == pprop->value.bin.pb) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.bin.pv = pbuff;
		}
		pprop->value.bin.cb = 4;
		minid = ab_tree_get_node_minid(pnode);
		pprop->value.bin.pb[0] = minid & 0xFF;
		pprop->value.bin.pb[1] = (minid >> 8) & 0xFF;
		pprop->value.bin.pb[2] = (minid >> 16) & 0xFF;
		pprop->value.bin.pb[3] = (minid >> 24) & 0xFF;
		return ecSuccess;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
		if (node_type != NODE_TYPE_PERSON &&
			node_type != NODE_TYPE_EQUIPMENT &&
			node_type != NODE_TYPE_ROOM) {
			return ecNotFound;
		}
		[[fallthrough]];
	case PROP_TAG_DISPLAYNAME:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
		ab_tree_get_display_name(pnode, codepage, dn);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8:
		if (node_type != NODE_TYPE_PERSON &&
			node_type != NODE_TYPE_EQUIPMENT &&
			node_type != NODE_TYPE_ROOM) {
			return ecNotFound;
		}
		[[fallthrough]];
	case PROP_TAG_DISPLAYNAME_STRING8:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8:
		ab_tree_get_display_name(pnode, codepage, dn);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pv = ndr_stack_alloc(
						NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		return ecSuccess;
	case PROP_TAG_COMPANYNAME:
		ab_tree_get_company_info(pnode, dn, NULL);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PROP_TAG_COMPANYNAME_STRING8:
		ab_tree_get_company_info(pnode, dn, NULL);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		return ecSuccess;
	case PROP_TAG_DEPARTMENTNAME:
		ab_tree_get_department_name(pnode, dn);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PROP_TAG_DEPARTMENTNAME_STRING8:
		ab_tree_get_department_name(pnode, dn);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		return ecSuccess;
	case PROP_TAG_OFFICELOCATION:
		ab_tree_get_company_info(pnode, NULL, dn);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PROP_TAG_OFFICELOCATION_STRING8:
		ab_tree_get_company_info(pnode, NULL, dn);
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			temp_len = 2*strlen(dn) + 1;
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		return ecSuccess;
	case PROP_TAG_ACCOUNT:
	case PROP_TAG_ACCOUNT_STRING8:
	case PROP_TAG_SMTPADDRESS:
	case PROP_TAG_SMTPADDRESS_STRING8:
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (node_type == NODE_TYPE_PERSON ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		} else {
			return ecNotFound;
		}
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (NULL == pprop->value.pstr) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PROP_TAG_ADDRESSBOOKPROXYADDRESSES:
	case PROP_TAG_ADDRESSBOOKPROXYADDRESSES_STRING8: {
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (node_type == NODE_TYPE_PERSON ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		} else {
			return ecNotFound;
		}
		if ('\0' == dn[0]) {
			return ecNotFound;
		}
		std::vector<std::string> alias_list;
		try {
			alias_list = ab_tree_get_object_aliases(pnode, node_type);
		} catch (...) {
		}
		pprop->value.string_array.cvalues = 1 + alias_list.size();
		pprop->value.string_array.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT, pprop->value.string_array.cvalues);
		if (NULL == pprop->value.string_array.ppstr) {
			return ecMAPIOOM;
		}
		pprop->value.string_array.ppstr[0] = ndr_stack_anew<char>(NDR_STACK_OUT, strlen(dn) + 6);
		if (NULL == pprop->value.string_array.ppstr[0]) {
			return ecMAPIOOM;
		}
		sprintf(pprop->value.string_array.ppstr[0], "SMTP:%s", dn);
		size_t i = 1;
		for (const auto &a : alias_list) {
			pprop->value.string_array.ppstr[i] = ndr_stack_anew<char>(NDR_STACK_OUT, a.size() + 6);
			if (pprop->value.string_array.ppstr[i] == nullptr)
				return ecMAPIOOM;
			strcpy(pprop->value.string_array.ppstr[i], "smtp:");
			strcat(pprop->value.string_array.ppstr[i++], a.c_str());
		}
		return ecSuccess;
	}
	case PROP_TAG_ADDRESSBOOKNETWORKADDRESS:
	case PROP_TAG_ADDRESSBOOKNETWORKADDRESS_STRING8:
		rpc_info = get_rpc_info();
		temp_len = strlen(rpc_info.ep_host);
		pprop->value.string_array.cvalues = 2;
		if (NULL == pbuff) {
			pprop->value.string_array.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT, 2);
			if (NULL == pprop->value.string_array.ppstr) {
				return ecMAPIOOM;
			}
			pprop->value.string_array.ppstr[0] = ndr_stack_anew<char>(NDR_STACK_OUT, temp_len + 14);
			if (NULL == pprop->value.string_array.ppstr[0]) {
				return ecMAPIOOM;
			}
			pprop->value.string_array.ppstr[1] = ndr_stack_anew<char>(NDR_STACK_OUT, temp_len - 12);
			if (NULL == pprop->value.string_array.ppstr[1]) {
				return ecMAPIOOM;
			}
		} else {
			pprop->value.string_array.ppstr = (char**)pbuff;
			pprop->value.string_array.ppstr[0] =
				static_cast<char *>(pbuff) + 2 * sizeof(char **);
			pprop->value.string_array.ppstr[1] =
				static_cast<char *>(pbuff) + 2 * sizeof(char **) + temp_len + 1;
		}
		sprintf(pprop->value.string_array.ppstr[0],
			"ncacn_ip_tcp:%s", rpc_info.ep_host);
		sprintf(pprop->value.string_array.ppstr[1],
			"ncacn_http:%s", rpc_info.ep_host);
		return ecSuccess;
	case PROP_TAG_THUMBNAILPHOTO:
		if (node_type != NODE_TYPE_PERSON)
			return ecNotFound;
		ab_tree_get_user_info(pnode, USER_STORE_PATH, dn, GX_ARRAY_SIZE(dn));
		strcat(dn, "/config/portrait.jpg");
		if (FALSE == common_util_load_file(dn, &pprop->value.bin)) {
			return ecNotFound;
		}
		return ecSuccess;
	}
	/* User-defined props */
	if (node_type == NODE_TYPE_PERSON || node_type == NODE_TYPE_ROOM ||
	    node_type == NODE_TYPE_EQUIPMENT || node_type == NODE_TYPE_MLIST) {
		auto ret = ab_tree_fetchprop(pnode, codepage, proptag, pprop);
		if (ret == ecSuccess)
			return ret;
		if (ret != ecNotFound)
			return ret;
	}
	/*
	 * Fallback defaults in case ab_tree does not contain a prop
	 * (in case e.g. a user has not explicitly set SENDRICHINFO=0)
	 */
	switch (proptag) {
	case PROP_TAG_SENDRICHINFO:
		pprop->value.b = 1;
		return ecSuccess;
	}
	return ecNotFound;
}		

static uint32_t nsp_interface_fetch_row(SIMPLE_TREE_NODE *pnode,
	BOOL b_ephid, uint32_t codepage, PROPTAG_ARRAY *pproptags,
	PROPERTY_ROW *prow)
{
	int i;
	uint32_t err_val;
	uint8_t node_type;
	PROPERTY_VALUE *pprop;
	
	node_type = ab_tree_get_node_type(pnode);
	if (node_type > 0x80) {
		return ecInvalidObject;
	}
	for (i=0; i<pproptags->cvalues; i++) {
		pprop = common_util_propertyrow_enlarge(prow);
		if (NULL == pprop) {
			return ecMAPIOOM;
		}
		err_val = nsp_interface_fetch_property(pnode, b_ephid, codepage,
		          pproptags->pproptag[i], pprop, nullptr, 0);
		if (err_val != ecSuccess) {
			pprop->proptag = CHANGE_PROP_TYPE(pprop->proptag, PT_ERROR);
			pprop->value.err = err_val;
		}
	}
	return ecSuccess;
}

void nsp_interface_init(BOOL b_check)
{
	g_session_check = b_check;
}

int nsp_interface_run()
{
#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "exchange_nsp", (s)); \
		return -1; \
	} \
} while (false)

	E(get_domain_ids, "get_domain_ids");
	E(get_maildir, "get_maildir");
	E(get_id_from_username, "get_id_from_username");
	E(verify_cpid, "verify_cpid");
	query_service2("abkt_tojson", nsp_abktojson);
	query_service2("abkt_tobinary", nsp_abktobinary);
	if (nsp_abktojson == nullptr || nsp_abktobinary == nullptr)
		fprintf(stderr, "[exchange_nsp]: address book user interface templates not available\n");
	return 0;
#undef E
}

int nsp_interface_bind(uint64_t hrpc, uint32_t flags,
	STAT *pstat, FLATUID *pserver_guid, NSPI_HANDLE *phandle)
{
	int org_id;
	int base_id;
	int domain_id;
	AB_BASE *pbase;
	DCERPC_INFO rpc_info;
	
	rpc_info = get_rpc_info();
	if (0 != (flags & FLAG_ANONYMOUSLOGIN)) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_FAILONEPROVIDER;
	}
	if (CODEPAGE_UNICODE == pstat->codepage) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return ecNotSupported;
	}
	/* check if valid cpid has been supplied */
	if (!verify_cpid(pstat->codepage)) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_UNKNOWN_CPID;
	}
	auto pdomain = strchr(rpc_info.username, '@');
	if (NULL == pdomain) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return ecLoginFailure;
	}
	pdomain ++;
	if (FALSE == get_domain_ids(pdomain, &domain_id, &org_id)) {
		phandle->handle_type = HANDLE_EXCHANGE_NSP;
		memset(&phandle->guid, 0, sizeof(GUID));
		return ecError;
	}
	phandle->handle_type = HANDLE_EXCHANGE_NSP;
	if (0 == org_id) {
		base_id = domain_id * (-1);
	} else {
		base_id = org_id;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase) {
		memset(&phandle->guid, 0, sizeof(GUID));
		return ecError;
	}
	phandle->guid = pbase->guid;
	ab_tree_put_base(pbase);
	if (NULL != pserver_guid) {
		*(GUID*)pserver_guid = common_util_get_server_guid();
	}
	return ecSuccess;
}

uint32_t nsp_interface_unbind(NSPI_HANDLE *phandle, uint32_t reserved)
{
	memset(phandle, 0, sizeof(NSPI_HANDLE));
	return MAPI_E_UNBINDSUCCESS;
}

static uint32_t nsp_interface_minid_in_list(
	SINGLE_LIST *plist, uint32_t row)
{
	int count;
	SINGLE_LIST_NODE *pnode;
	
	count = 0;
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		if (count == row) {
			return ab_tree_get_node_minid(static_cast<SIMPLE_TREE_NODE *>(pnode->pdata));
		}
		count ++;
	}
	return 0;
}

static void nsp_interface_position_in_list(STAT *pstat, SINGLE_LIST *plist,
    uint32_t *pout_row, uint32_t *pout_last_row, uint32_t *pcount)
{
	BOOL b_found;
	uint32_t row;
	uint32_t minid;
	uint32_t last_row;
	SINGLE_LIST_NODE *pnode;

	*pcount = single_list_get_nodes_num(plist);
	if (*pcount > 0) {
		last_row = *pcount - 1;
	} else {
		last_row = 0;
	}
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		row = pstat->num_pos * (last_row + 1) / pstat->total_rec;
		if (row > last_row) {
			row = last_row;
		}
	} else {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
			row = 0;
		}
		else if (MID_END_OF_TABLE ==  pstat->cur_rec) {
			row = last_row + 1;
		} else {
			b_found = FALSE;
			row = 0;
			for (pnode=single_list_get_head(plist); NULL!=pnode;
				pnode=single_list_get_after(plist, pnode)) {
				minid = ab_tree_get_node_minid(static_cast<SIMPLE_TREE_NODE *>(pnode->pdata));
				if (0 != minid && minid == pstat->cur_rec) {
					b_found = TRUE;
					break;
				}
				row ++;
			}
			if (FALSE == b_found) {
				/* In this case the position is undefined.
				   To avoid problems we will use first row */
				row = 0;
			}
		}
	}
	*pout_row = row;
	*pout_last_row = last_row;
}

static void nsp_interface_position_in_table(STAT *pstat,
	SIMPLE_TREE_NODE *pnode, uint32_t *pout_row,
	uint32_t *pout_last_row, uint32_t *pcount)
{
	BOOL b_found;
	uint32_t row;
	uint32_t minid;
	uint32_t last_row;

	*pcount = ab_tree_get_leaves_num(pnode);
	if (*pcount > 0) {
		last_row = *pcount - 1;
	} else {
		last_row = 0;
	}
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		row = pstat->num_pos * (last_row + 1) / pstat->total_rec;
		if (row > last_row) {
			row = last_row;
		}
	} else {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
			row = 0;
		}
		else if (MID_END_OF_TABLE == pstat->cur_rec) {
			row = last_row + 1;
		} else {
			b_found = FALSE;
			row = 0;
			pnode = simple_tree_node_get_child(pnode);
			if (NULL != pnode) {
				do {
					if (ab_tree_get_node_type(pnode) < 0x80) {
						minid = ab_tree_get_node_minid(pnode);
						if (0 != minid && minid == pstat->cur_rec) {
							b_found = TRUE;
							break;
						}
						row ++;
					}
				} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
				
			}
			if (FALSE == b_found) {
				/* In this case the position is undefined.
				   To avoid problems we will use first row */
				row = 0;
			}
		}
	}
	*pout_row = row;
	*pout_last_row = last_row;
}

static uint32_t nsp_interface_minid_in_table(
	SIMPLE_TREE_NODE *pnode, uint32_t row)
{
	int count;
	
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return 0;
	}
	count = 0;
	do {
		if (count == row) {
			return ab_tree_get_node_minid(pnode);
		}
		if (ab_tree_get_node_type(pnode) < 0x80) {
			count ++;
		}
	} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	return 0;
}

int nsp_interface_update_stat(NSPI_HANDLE handle,
	uint32_t reserved, STAT *pstat, int32_t *pdelta)
{
	int base_id;
	uint32_t row;
	uint32_t total;
	AB_BASE *pbase;
	uint32_t last_row;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		return ecNotSupported;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		return ecError;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return ecError;
	}
	if (0 == pstat->container_id) {
		pgal_list = &pbase->gal_list;
		nsp_interface_position_in_list(pstat,
			pgal_list, &row, &last_row, &total);
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
		if (NULL == pnode) {
			ab_tree_put_base(pbase);
			return ecInvalidBookmark;
		}
		nsp_interface_position_in_table(pstat,
			pnode, &row, &last_row, &total);
	}
	if (pstat->delta != 0) {
		/* adjust row  by delta */
		if (pstat->delta > 0) {
			row += pstat->delta;
			if (row > last_row) {
				row = last_row + 1;
			}
		} else {
			if (abs(pstat->delta) >= row) {
				row = 0;
			} else {
				row -= abs(pstat->delta);
			}
		}
	}
	if (row == last_row + 1) {
		pstat->cur_rec = MID_END_OF_TABLE;
	} else if (0 == row) {
		pstat->cur_rec = MID_BEGINNING_OF_TABLE;
	} else {
		if (0 == pstat->container_id) {
			pstat->cur_rec = nsp_interface_minid_in_list(pgal_list, row);
		} else {
			pstat->cur_rec = nsp_interface_minid_in_table(pnode, row);
		}
		if (0 == pstat->cur_rec) {
			row = 0;
			pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		}
	}
	ab_tree_put_base(pbase);
	if (NULL != pdelta) {
		*pdelta = row - pstat->num_pos;
	}
	pstat->delta = 0;
	pstat->num_pos = row;
	pstat->total_rec = total;
	return ecSuccess;
}

static void nsp_interface_make_ptyperror_row(
	PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow)
{
	int i;
	
	prow->reserved = 0x0;
	prow->cvalues = pproptags->cvalues;
	prow->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, prow->cvalues);
	if (NULL == prow->pprops) {
		return;
	}
	for (i=0; i<prow->cvalues; i++) {
		prow->pprops[i].proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_ERROR);
		prow->pprops[i].reserved = 0x0;
		prow->pprops[i].value.err = 0;
	}
}

int nsp_interface_query_rows(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, uint32_t table_count, uint32_t *ptable,
	uint32_t count, PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows)
{
	int i;
	int base_id;
	BOOL b_ephid;
	int tmp_count;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t last_row;
	uint32_t start_pos, total;
	PROPERTY_ROW *prow;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SINGLE_LIST_NODE *psnode;
	
	
	if (FLAG_EPHID & flags) {
		b_ephid = TRUE;
	} else {
		b_ephid = FALSE;
	}
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*pprows = NULL;
		return ecNotSupported;
	}
	if (0 == count && NULL == ptable) {
		*pprows = NULL;
		return ecInvalidParam;
	}
	
	/* MS-OXNSPI 3.1.4.1.8.10 */
	if (0 == count) {
		count = 1;
	}
	
	if (NULL == pproptags) {
		pproptags = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_IN);
		if (NULL == pproptags) {
			*pprows = NULL;
			return ecMAPIOOM;
		}
		pproptags->cvalues = 7;
		pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, pproptags->cvalues);
		if (pproptags->pproptag == nullptr) {
			*pprows = NULL;
			return ecMAPIOOM;
		}
		pproptags->pproptag[0] = PROP_TAG_ADDRESSBOOKCONTAINERID;
		pproptags->pproptag[1] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[2] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[3] = PROP_TAG_DISPLAYNAME_STRING8;
		pproptags->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pproptags->pproptag[5] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[6] = PROP_TAG_OFFICELOCATION_STRING8;
	} else {
		if (pproptags->cvalues > 100) {
			*pprows = NULL;
			return ecTableTooBig;
		}
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return ecError;
	}
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		*pprows = NULL;
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return ecError;
	}
	
	if (NULL == ptable) {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			nsp_interface_position_in_list(pstat,
				pgal_list, &start_pos, &last_row, &total);
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = ecInvalidBookmark;
				goto EXIT_QUERY_ROWS;
			}
			nsp_interface_position_in_table(pstat,
				pnode, &start_pos, &last_row, &total);
			pnode1 = simple_tree_node_get_child(pnode);
			if (NULL == pnode1) {
				result = ecSuccess;
				goto EXIT_QUERY_ROWS;
			}
		}
		if (0 == total) {
			result = ecSuccess;
			goto EXIT_QUERY_ROWS;
		}
		if (pstat->delta >= 0) {
			start_pos += pstat->delta;
			if (start_pos >= total) {
				start_pos = total;
			}
		} else {
			if (abs(pstat->delta) > pstat->num_pos) {
				start_pos = 0;
			} else {
				start_pos -= abs(pstat->delta);
			}
		}

		tmp_count = total - start_pos;
		if (count < tmp_count) {
			tmp_count = count;
		}
		if (0 == tmp_count) {
			result = ecSuccess;
			goto EXIT_QUERY_ROWS;
		}
		i = 0;
		if (0 == pstat->container_id) {
			for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
				psnode=single_list_get_after(pgal_list, psnode)) {
				if (i >= start_pos && i < start_pos + tmp_count) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow || NULL ==
						common_util_propertyrow_init(prow)) {
						result = ecMAPIOOM;
						goto EXIT_QUERY_ROWS;
					}
					result = nsp_interface_fetch_row(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata),
						b_ephid, pstat->codepage, pproptags, prow);
					if (result != ecSuccess)
						goto EXIT_QUERY_ROWS;
				}
				i ++;
			}
		} else {
			do {
				if (ab_tree_get_node_type(pnode1) > 0x80) {
					continue;
				}
				if (i >= start_pos && i < start_pos + tmp_count) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow || NULL ==
						common_util_propertyrow_init(prow)) {
						result = ecMAPIOOM;
						goto EXIT_QUERY_ROWS;
					}
					result = nsp_interface_fetch_row(pnode1,
						b_ephid, pstat->codepage, pproptags, prow);
					if (result != ecSuccess)
						goto EXIT_QUERY_ROWS;
				}
				i ++;
			} while ((pnode1 = simple_tree_node_get_sibling(pnode1)) != nullptr);
		}

		if (start_pos + tmp_count == last_row + 1) {
			pstat->cur_rec = MID_END_OF_TABLE;
		} else if (0 == start_pos + tmp_count) {
			pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		} else {
			if (0 == pstat->container_id) {
				pstat->cur_rec = nsp_interface_minid_in_list(
							pgal_list, start_pos + tmp_count);
			} else {
				pstat->cur_rec = nsp_interface_minid_in_table(
								pnode, start_pos + tmp_count);
			}
			if (0 == pstat->cur_rec) {
				pstat->cur_rec = MID_BEGINNING_OF_TABLE;
				start_pos = 0;
				tmp_count = 0;
			}
		}
		pstat->delta = 0;
		pstat->num_pos = start_pos + tmp_count;
		pstat->total_rec = total;
	} else {
		for (i=0; i<table_count; i++) {
			prow = common_util_proprowset_enlarge(*pprows);
			if (NULL == prow || NULL ==
				common_util_propertyrow_init(prow)) {
				result = ecMAPIOOM;
				goto EXIT_QUERY_ROWS;
			}
			pnode = ab_tree_minid_to_node(pbase, ptable[i]);
			if (NULL == pnode) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
				continue;
			}
			result = nsp_interface_fetch_row(pnode,
				b_ephid, pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				nsp_interface_make_ptyperror_row(pproptags, prow);
		}
	}
	result = ecSuccess;
	
 EXIT_QUERY_ROWS:
	ab_tree_put_base(pbase);
	if (result != ecSuccess)
		*pprows = NULL;
	return result;
}

int nsp_interface_seek_entries(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, PROPERTY_VALUE *ptarget, MID_ARRAY *ptable,
	PROPTAG_ARRAY *pproptags, PROPROW_SET **pprows)
{
	int base_id, row;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t last_row;
	uint32_t start_pos, total;
	PROPERTY_ROW *prow;
	uint32_t tmp_minid;
	char temp_name[1024];
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*pprows = NULL;
		return ecNotSupported;
	}
	if (0 != reserved) {
		*pprows = NULL;
		return ecNotSupported;
	}
	if (SORT_TYPE_DISPLAYNAME == pstat->sort_type) {
		if (PROP_TAG_DISPLAYNAME != ptarget->proptag &&
			PROP_TAG_DISPLAYNAME_STRING8 != ptarget->proptag) {
			*pprows = NULL;
			return ecError;
		}
	} else if (SORT_TYPE_PHONETICDISPLAYNAME == pstat->sort_type) {
		if (PROP_TAG_ADDRESSBOOKPHONETICDISPLAYNAME != ptarget->proptag
			&& PROP_TAG_ADDRESSBOOKPHONETICDISPLAYNAME_STRING8 != 
			ptarget->proptag) {
			*pprows = NULL;
			return ecError;
		}
	} else {
		*pprows = NULL;
		return ecError;
	}
	if (NULL == pproptags) {
		pproptags = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_IN);
		if (NULL == pproptags) {
			*pprows = NULL;
			return ecMAPIOOM;
		}
		pproptags->cvalues = 7;
		pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, pproptags->cvalues);
		if (pproptags->pproptag == nullptr) {
			*pprows = NULL;
			return ecMAPIOOM;
		}
		pproptags->pproptag[0] = PROP_TAG_ADDRESSBOOKCONTAINERID;
		pproptags->pproptag[1] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[2] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[3] = PROP_TAG_DISPLAYNAME_STRING8;
		pproptags->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pproptags->pproptag[5] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[6] = PROP_TAG_OFFICELOCATION_STRING8;
	} else {
		if (pproptags->cvalues > 100) {
			*pprows = NULL;
			return ecTableTooBig;
		}
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return ecError;
	}
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		*pprows = NULL;
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return ecError;
	}
	
	if (NULL != ptable) {
		row = 0;
		tmp_minid = 0;
		for (int i = 0; i < ptable->cvalues; ++i) {
			pnode1 = ab_tree_minid_to_node(pbase, ptable->pproptag[i]);
			if (NULL == pnode1) {
				continue;
			}
			ab_tree_get_display_name(pnode1, pstat->codepage, temp_name);
			if (strcasecmp(temp_name, ptarget->value.pstr) < 0) {
				continue;
			}
			if (0 == tmp_minid) {
				tmp_minid = ptable->pproptag[i];
				row = i;
			}
			if (0 != tmp_minid) {
				prow = common_util_proprowset_enlarge(*pprows);
				if (NULL == prow || NULL ==
					common_util_propertyrow_init(prow)) {
					result = ecMAPIOOM;
					goto EXIT_SEEK_ENTRIES;
				}
				result = nsp_interface_fetch_row(pnode1, TRUE,
							pstat->codepage, pproptags, prow);
				if (result != ecSuccess)
					nsp_interface_make_ptyperror_row(pproptags, prow);
			}
		}
		
		if (0 == tmp_minid) {
			result = ecNotFound;
			goto EXIT_SEEK_ENTRIES;
		}
		
		pstat->total_rec = (*pprows)->crows;
		pstat->cur_rec = tmp_minid;
		pstat->num_pos = row;
	} else {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			nsp_interface_position_in_list(pstat,
				pgal_list, &start_pos, &last_row, &total);
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = ecInvalidBookmark;
				goto EXIT_SEEK_ENTRIES;
			}
			nsp_interface_position_in_table(pstat,
				pnode, &start_pos, &last_row, &total);
			pnode1 = simple_tree_node_get_child(pnode);
			if (NULL == pnode1) {
				result = ecNotFound;
				goto EXIT_SEEK_ENTRIES;
			}
		}
		
		if (0 == total) {
			result = ecNotFound;
			goto EXIT_SEEK_ENTRIES;
		}
		row = 0;
		if (0 == pstat->container_id) {
			for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
				psnode=single_list_get_after(pgal_list, psnode),row++) {
				if (row < start_pos) {
					continue;
				}
				ab_tree_get_display_name(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata),
					pstat->codepage, temp_name);
				if (strcasecmp(temp_name, ptarget->value.pstr) >= 0) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow ||
						NULL == common_util_propertyrow_init(prow)) {
						result = ecMAPIOOM;
						goto EXIT_SEEK_ENTRIES;
					}
					if (nsp_interface_fetch_row(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata),
					    TRUE, pstat->codepage, pproptags,
					    prow) != ecSuccess) {
						result = ecError;
						goto EXIT_SEEK_ENTRIES;
					}
					break;
				}
			}
			if (NULL == psnode) {
				result = ecNotFound;
				goto EXIT_SEEK_ENTRIES;
			}
			pstat->cur_rec = ab_tree_get_node_minid(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata));
		} else {
			pnode1 = simple_tree_node_get_child(pnode);
			do {
				if (ab_tree_get_node_type(pnode1) > 0x80) {
					continue;
				}
				if (row < start_pos) {
					row ++;
					continue;
				}
				ab_tree_get_display_name(pnode1,
					pstat->codepage, temp_name);
				if (strcasecmp(temp_name, ptarget->value.pstr) >= 0) {
					prow = common_util_proprowset_enlarge(*pprows);
					if (NULL == prow ||
						NULL == common_util_propertyrow_init(prow)) {
						result = ecMAPIOOM;
						goto EXIT_SEEK_ENTRIES;
					}
					if (nsp_interface_fetch_row(pnode1,
					    TRUE, pstat->codepage, pproptags,
					    prow) != ecSuccess) {
						result = ecError;
						goto EXIT_SEEK_ENTRIES;
					}
					break;
				}
				row ++;
			} while ((pnode1 = simple_tree_node_get_sibling(pnode1)) != nullptr);
			if (NULL == pnode1) {
				result = ecNotFound;
				goto EXIT_SEEK_ENTRIES;
			}
			pstat->cur_rec = ab_tree_get_node_minid(pnode1);
		}
		pstat->num_pos = row;
	}
	
	result = ecSuccess;

 EXIT_SEEK_ENTRIES:
	ab_tree_put_base(pbase);
	if (result != ecSuccess)
		*pprows = NULL;
	return result;
}

static BOOL nsp_interface_match_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, RESTRICTION *pfilter)
{
	int i;
	char *ptoken;
	uint8_t node_type;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	
	switch (pfilter->res_type) {
	case RES_AND:
		for (i=0; i<pfilter->res.res_and.cres; i++) {
			if (FALSE == nsp_interface_match_node(pnode,
				codepage, &pfilter->res.res_and.pres[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case RES_OR:
		for (i=0; i<pfilter->res.res_and.cres; i++) {
			if (TRUE == nsp_interface_match_node(pnode,
				codepage, &pfilter->res.res_or.pres[i])) {
				return TRUE;
			}
		}
		return FALSE;
	case RES_NOT:
		if (TRUE == nsp_interface_match_node(pnode,
			codepage, pfilter->res.res_not.pres)) {
			return FALSE;
		}
		return TRUE;
	case RES_CONTENT:
		return FALSE;
	case RES_PROPERTY:
		if (NULL == pfilter->res.res_property.pprop) {
			return TRUE;
		}
		if (PROP_TAG_ANR == pfilter->res.res_property.proptag) {
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PROP_TAG_ACCOUNT, &prop_val, temp_buff,
			    GX_ARRAY_SIZE(temp_buff)) == ecSuccess) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			ptoken = strchr(pfilter->res.res_property.pprop->value.pstr, ':');
			if (NULL != ptoken) {
				/* =SMTP:user@company.com */
				if (NULL != strcasestr(temp_buff, ptoken + 1)) {
					return TRUE;
				}
			} else {
				if (0 == strcasecmp(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PROP_TAG_DISPLAYNAME, &prop_val, temp_buff,
			    GX_ARRAY_SIZE(temp_buff)) == ecSuccess) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			return FALSE;
		} else if (PROP_TAG_ANR_STRING8 == pfilter->res.res_property.proptag) {
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PROP_TAG_ACCOUNT_STRING8, &prop_val, temp_buff,
			    GX_ARRAY_SIZE(temp_buff)) == ecSuccess) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pfilter->res.res_property.pprop->value.pstr, ':');
			if (NULL != ptoken) {
				if (NULL != strcasestr(temp_buff, ptoken + 1)) {
					return TRUE;
				}
			} else {
				if (0 == strcasecmp(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PROP_TAG_DISPLAYNAME_STRING8, &prop_val, temp_buff,
			    GX_ARRAY_SIZE(temp_buff)) == ecSuccess) {
				if (NULL != strcasestr(temp_buff,
					pfilter->res.res_property.pprop->value.pstr)) {
					return TRUE;
				}
			}
			return FALSE;
		}
		if (nsp_interface_fetch_property(pnode, false, codepage,
		    pfilter->res.res_property.proptag, &prop_val,
		    temp_buff, GX_ARRAY_SIZE(temp_buff)) != ecSuccess)
			return FALSE;
		switch (PROP_TYPE(pfilter->res.res_property.proptag)) {
		case PT_SHORT:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (prop_val.value.s <
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (prop_val.value.s <=
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (prop_val.value.s >
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (prop_val.value.s >=
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (prop_val.value.s ==
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (prop_val.value.s !=
					pfilter->res.res_property.pprop->value.s) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case PT_LONG:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (prop_val.value.l <
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (prop_val.value.l <=
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (prop_val.value.l >
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (prop_val.value.l >=
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (prop_val.value.l ==
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (prop_val.value.l !=
					pfilter->res.res_property.pprop->value.l) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case PT_BOOLEAN:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (prop_val.value.b <
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (prop_val.value.b <=
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (prop_val.value.b >
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (prop_val.value.b >=
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (prop_val.value.b ==
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (prop_val.value.b !=
					pfilter->res.res_property.pprop->value.b) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case PT_STRING8:
		case PT_UNICODE:
			switch (pfilter->res.res_property.relop) {
			case RELOP_LT:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) < 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_LE:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) <= 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GT:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) > 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_GE:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) >= 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_EQ:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) == 0) {
					return TRUE;
				}
				return FALSE;
			case RELOP_NE:
				if (strcasecmp(prop_val.value.pstr,
					pfilter->res.res_property.pprop->value.pstr) != 0) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	case RES_PROPCOMPARE:
		return FALSE;
	case RES_BITMASK:
		return FALSE;
	case RES_SIZE:
		return FALSE;
	case RES_EXIST:
		node_type = ab_tree_get_node_type(pnode);
		if (node_type > 0x80) {
			return FALSE;
		}
		if (nsp_interface_fetch_property(pnode, false, codepage,
		    pfilter->res.res_exist.proptag, &prop_val, temp_buff,
		    GX_ARRAY_SIZE(temp_buff)) != ecSuccess)
			return FALSE;
		return TRUE;
	case RES_SUBRESTRICTION:
		return FALSE;
	}	
	return false;
}

int nsp_interface_get_matches(NSPI_HANDLE handle, uint32_t reserved1,
    STAT *pstat, MID_ARRAY *preserved, uint32_t reserved2, RESTRICTION *pfilter,
    NSP_PROPNAME *ppropname, uint32_t requested, MID_ARRAY **ppoutmids,
    LPROPTAG_ARRAY *pproptags, NSP_ROWSET **pprows)
{
	int base_id;
	int user_id;
	AB_BASE *pbase;
	uint32_t i, result, start_pos, last_row, total;
	char maildir[256];
	uint32_t *pproptag;
	PROPERTY_ROW *prow;
	char temp_path[256];
	char temp_buff[1024];
	SINGLE_LIST *pgal_list;
	PROPERTY_VALUE prop_val;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return ecNotSupported;
	}
	if (SORT_TYPE_DISPLAYNAME != pstat->sort_type &&
		SORT_TYPE_PHONETICDISPLAYNAME != pstat->sort_type &&
		SORT_TYPE_DISPLAYNAME_RO != pstat->sort_type &&
		SORT_TYPE_DISPLAYNAME_W != pstat->sort_type) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return ecNotSupported;
	}
	if (0 != reserved1 || NULL != ppropname) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return ecNotSupported;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppoutmids = NULL;
		*pprows = NULL;
		return ecError;
	}
	*ppoutmids = common_util_proptagarray_init();
	if (NULL == *ppoutmids) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	if (NULL == pproptags) {
		*pprows = NULL;
	} else {
		if (pproptags->cvalues > 100) {
			*ppoutmids = NULL;
			*pprows = NULL;
			return ecTableTooBig;
		}
		*pprows = common_util_proprowset_init();
		if (NULL == *pprows) {
			*ppoutmids = NULL;
			return ecMAPIOOM;
		}
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppoutmids = NULL;
		*pprows = NULL;
		return ecError;
	}
	
	if (PROP_TAG_ADDRESSBOOKPUBLICDELEGATES == pstat->container_id) {
		pnode = ab_tree_minid_to_node(pbase, pstat->cur_rec);
		if (NULL == pnode) {
			result = ecInvalidBookmark;
			goto EXIT_GET_MATCHES;
		}
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, temp_buff, GX_ARRAY_SIZE(temp_buff));
		if (FALSE == get_maildir(temp_buff, maildir)) {
			result = ecError;
			goto EXIT_GET_MATCHES;
		}
		snprintf(temp_path, GX_ARRAY_SIZE(temp_path),
		         "%s/config/delegates.txt", maildir);
		auto pfile = list_file_initd(temp_path, nullptr, "%s:256");
		if (NULL == pfile) {
			result = ecSuccess;
			goto EXIT_GET_MATCHES;
		}
		auto item_num = pfile->get_size();
		auto pitem = static_cast<const dlgitem *>(pfile->get_list());
		for (i=0; i<item_num; i++) {
			if ((*ppoutmids)->cvalues > requested) {
				break;
			}
			if (!get_id_from_username(pitem[i].user, &user_id) ||
				NULL == (pnode = ab_tree_uid_to_node(pbase, user_id))) {
				continue;
			}
			if (NULL != pfilter && FALSE == nsp_interface_match_node(
				pnode, pstat->codepage, pfilter)) {
				continue;	
			}
			pproptag = common_util_proptagarray_enlarge(*ppoutmids);
			if (NULL == pproptag) {
				result = ecMAPIOOM;
				goto EXIT_GET_MATCHES;
			}
			*pproptag = ab_tree_get_node_minid(pnode);
		}
		result = ecSuccess;
		goto FETCH_ROWS;
	}
	if (NULL != pfilter) {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			nsp_interface_position_in_list(pstat,
				pgal_list, &start_pos, &last_row, &total);
			i = 0;
			for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
				psnode=single_list_get_after(pgal_list, psnode)) {
				if (i > last_row || (*ppoutmids)->cvalues > requested) {
					break;
				} else if (i < start_pos) {
					i ++;
					continue;
				}
				if (nsp_interface_match_node(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata),
					pstat->codepage, pfilter)) {
					pproptag = common_util_proptagarray_enlarge(*ppoutmids);
					if (NULL == pproptag) {
						result = ecMAPIOOM;
						goto EXIT_GET_MATCHES;
					}
					*pproptag = ab_tree_get_node_minid(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata));
				}
				i ++;
			}
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = ecInvalidBookmark;
				goto EXIT_GET_MATCHES;
			}
			nsp_interface_position_in_table(pstat,
				pnode, &start_pos, &last_row, &total);
			pnode = simple_tree_node_get_child(pnode);
			if (NULL == pnode) {
				result = ecSuccess;
				goto EXIT_GET_MATCHES;
			}
			i = 0;
			do {
				if (i > last_row || (*ppoutmids)->cvalues > requested) {
					break;
				} else if (i < start_pos) {
					i ++;
					continue;
				}
				if (TRUE == nsp_interface_match_node(pnode,
					pstat->codepage, pfilter)) {
					pproptag = common_util_proptagarray_enlarge(*ppoutmids);
					if (NULL == pproptag) {
						result = ecMAPIOOM;
						goto EXIT_GET_MATCHES;
					}
					*pproptag = ab_tree_get_node_minid(pnode);
				}
				i ++;
			} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->cur_rec);
		if (pnode != nullptr && nsp_interface_fetch_property(pnode,
		    TRUE, pstat->codepage, pstat->container_id, &prop_val,
		    temp_buff, GX_ARRAY_SIZE(temp_buff)) == ecSuccess) {
			pproptag = common_util_proptagarray_enlarge(*ppoutmids);
			if (NULL == pproptag) {
				result = ecMAPIOOM;
				goto EXIT_GET_MATCHES;
			}
			*pproptag = ab_tree_get_node_minid(pnode);
		}
	}

 FETCH_ROWS:
	if (NULL != *pprows) {
		for (i=0; i<(*ppoutmids)->cvalues; i++) {
			prow = common_util_proprowset_enlarge(*pprows);
			if (NULL == prow || NULL ==
				common_util_propertyrow_init(prow)) {
				result = ecMAPIOOM;
				goto EXIT_GET_MATCHES;
			}
			pnode = ab_tree_minid_to_node(pbase, (*ppoutmids)->pproptag[i]);
			if (NULL == pnode) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
			} else {
				result = nsp_interface_fetch_row(pnode, TRUE,
				         pstat->codepage, pproptags, prow);
				if (result != ecSuccess)
					nsp_interface_make_ptyperror_row(pproptags, prow);
			}
		}
	}
	
	result = ecSuccess;
	
 EXIT_GET_MATCHES:
	ab_tree_put_base(pbase);
	if (result != ecSuccess) {
		*ppoutmids = NULL;
		*pprows = NULL;
	} else {
		/* MS-OXNSPI 3.1.4.1.10.16 */
		pstat->container_id = pstat->cur_rec;
	}
	return result;
}

static int nsp_interface_cmpstring(const void *p1, const void *p2)
{
	return strcasecmp(static_cast<const nsp_sort_item *>(p1)->string,
	       static_cast<const nsp_sort_item *>(p2)->string);
}

int nsp_interface_resort_restriction(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, MID_ARRAY *pinmids, MID_ARRAY **ppoutmids)
{
	int i;
	int count;
	int base_id;
	BOOL b_found;
	AB_BASE *pbase;
	char temp_buff[1024];
	SIMPLE_TREE_NODE *pnode;
	
	if (NULL == pstat || CODEPAGE_UNICODE == pstat->codepage) {
		*ppoutmids = NULL;
		return ecNotSupported;
	}
	auto parray = ndr_stack_anew<nsp_sort_item>(NDR_STACK_IN, pinmids->cvalues);
	if (NULL == parray) {
		*ppoutmids = NULL;
		return ecMAPIOOM;
	}
	*ppoutmids = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_OUT);
	if (NULL == *ppoutmids) {
		return ecMAPIOOM;
	}
	(*ppoutmids)->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pinmids->cvalues);
	if (NULL == (*ppoutmids)->pproptag) {
		*ppoutmids = NULL;
		return ecMAPIOOM;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppoutmids = NULL;
		return ecError;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppoutmids = NULL;
		return ecError;
	}
	count = 0;
	b_found = FALSE;
	for (i=0; i<pinmids->cvalues; i++) {
		pnode = ab_tree_minid_to_node(pbase, pinmids->pproptag[i]);
		if (NULL == pnode) {
			continue;
		}
		parray[count].minid = pinmids->pproptag[i];
		if (pstat->cur_rec == pinmids->pproptag[i]) {
			b_found = TRUE;
		}
		ab_tree_get_display_name(pnode, pstat->codepage, temp_buff);
		parray[count].strv = ndr_stack_alloc(
			NDR_STACK_IN, strlen(temp_buff) + 1);
		if (NULL == parray[count].string) {
			ab_tree_put_base(pbase);
			*ppoutmids = NULL;
			return ecMAPIOOM;
		}
		strcpy(parray[count].string, temp_buff);
		count ++;
	}
	qsort(parray, count, sizeof(nsp_sort_item), nsp_interface_cmpstring);
	(*ppoutmids)->cvalues = count;
	for (i=0; i<count; i++) {
		(*ppoutmids)->pproptag[i] = parray[i].minid;
	}
	pstat->total_rec = count;
	if (FALSE == b_found) {
		pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		pstat->num_pos = 0;
	}
	ab_tree_put_base(pbase);
	return ecSuccess;
}

int nsp_interface_dntomid(NSPI_HANDLE handle, uint32_t reserved,
    STRINGS_ARRAY *pnames, MID_ARRAY **ppoutmids)
{
	int i;
	int base_id;
	AB_BASE *pbase;
	SIMPLE_TREE_NODE *ptnode;
	
	if (NULL == pnames) {
		*ppoutmids = NULL;
		return ecSuccess;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppoutmids = NULL;
		return ecError;
	}
	*ppoutmids = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_OUT);
	if (NULL == *ppoutmids) {
		return ecMAPIOOM;
	}
	(*ppoutmids)->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pnames->count);
	if (NULL == (*ppoutmids)->pproptag) {
		*ppoutmids = NULL;
		return ecMAPIOOM;
	}
	(*ppoutmids)->cvalues = pnames->count;
	memset((*ppoutmids)->pproptag, 0, sizeof(uint32_t)*pnames->count);
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppoutmids = NULL;
		return ecError;
	}
	for (i=0; i<pnames->count; i++) {
		if (NULL == pnames->ppstrings[i]) {
			continue;
		}
		ptnode = ab_tree_dn_to_node(pbase, pnames->ppstrings[i]);
		if (NULL != ptnode) {
			(*ppoutmids)->pproptag[i] = ab_tree_get_node_minid(ptnode);
		}
	}
	ab_tree_put_base(pbase);
	return ecSuccess;
}

static int nsp_interface_get_default_proptags(int node_type,
	BOOL b_unicode, PROPTAG_ARRAY *pproptags)
{
#define U(x) (b_unicode ? (x) : CHANGE_PROP_TYPE(PT_STRING8, (x)))
	static constexpr size_t UPPER_LIMIT = 32;
	unsigned int &z = pproptags->cvalues;
	pproptags->cvalues  = 0;
	pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, UPPER_LIMIT);
	if (pproptags->pproptag == nullptr)
		return ecMAPIOOM;

	auto &t = pproptags->pproptag;
	t[z++] = U(PROP_TAG_DISPLAYNAME);
	t[z++] = U(PROP_TAG_ADDRESSTYPE);
	t[z++] = U(PROP_TAG_EMAILADDRESS);
	t[z++] = U(PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE);
	t[z++] = PROP_TAG_OBJECTTYPE;
	t[z++] = PROP_TAG_DISPLAYTYPE;
	t[z++] = PROP_TAG_DISPLAYTYPEEX;
	t[z++] = PROP_TAG_ENTRYID;
	t[z++] = PROP_TAG_RECORDKEY;
	t[z++] = PROP_TAG_ORIGINALENTRYID;
	t[z++] = PROP_TAG_SEARCHKEY;
	t[z++] = PROP_TAG_INSTANCEKEY;
	t[z++] = PROP_TAG_MAPPINGSIGNATURE;
	t[z++] = PROP_TAG_SENDRICHINFO;
	t[z++] = PROP_TAG_TEMPLATEID;
	t[z++] = PROP_TAG_ADDRESSBOOKOBJECTGUID;
	switch (node_type) {
	case NODE_TYPE_DOMAIN:
	case NODE_TYPE_GROUP:
	case NODE_TYPE_CLASS:
		return ecInvalidObject;
	case NODE_TYPE_PERSON:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		t[z++] = U(PROP_TAG_NICKNAME);
		t[z++] = U(PROP_TAG_TITLE);
		t[z++] = U(PROP_TAG_PRIMARYTELEPHONENUMBER);
		t[z++] = U(PROP_TAG_MOBILETELEPHONENUMBER);
		t[z++] = U(PROP_TAG_HOMEADDRESSSTREET);
		t[z++] = U(PROP_TAG_COMMENT);
		t[z++] = U(PROP_TAG_COMPANYNAME);
		t[z++] = U(PROP_TAG_DEPARTMENTNAME);
		t[z++] = U(PROP_TAG_OFFICELOCATION);
		t[z++] = U(PROP_TAG_SMTPADDRESS);
		t[z++] = U(PROP_TAG_ACCOUNT);
		t[z++] = U(PROP_TAG_TRANSMITTABLEDISPLAYNAME);
		t[z++] = U(PROP_TAG_ADDRESSBOOKPROXYADDRESSES);
		t[z++] = U(PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE);
		t[z++] = PROP_TAG_CREATIONTIME;
		if (node_type == NODE_TYPE_PERSON)
			t[z++] = PROP_TAG_THUMBNAILPHOTO;
		break;
	case NODE_TYPE_MLIST:
		t[z++] = U(PROP_TAG_SMTPADDRESS);
		t[z++] = U(PROP_TAG_COMPANYNAME);
		t[z++] = U(PROP_TAG_DEPARTMENTNAME);
		t[z++] = U(PROP_TAG_ADDRESSBOOKPROXYADDRESSES);
		t[z++] = PROP_TAG_CREATIONTIME;
		break;
	case NODE_TYPE_FOLDER:
		t[z++] = PROP_TAG_COMPANYNAME_STRING8;
		t[z++] = PROP_TAG_DEPARTMENTNAME_STRING8;
		break;
	default:
		return ecInvalidObject;
	}
	assert(z <= UPPER_LIMIT);
	return ecSuccess;
#undef U
}


int nsp_interface_get_proplist(NSPI_HANDLE handle, uint32_t flags,
	uint32_t mid, uint32_t codepage, PROPTAG_ARRAY **ppproptags)
{
	int i;
	int count;
	int base_id;
	BOOL b_unicode;
	AB_BASE *pbase;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	SIMPLE_TREE_NODE *pnode;
	
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppproptags = NULL;
		return ecError;
	}
	if (0 == mid) {
		*ppproptags = NULL;
		return ecInvalidObject;
	}
	if (CODEPAGE_UNICODE == codepage) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	*ppproptags = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_OUT);
	if (NULL == *ppproptags) {
		return ecMAPIOOM;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppproptags = NULL;
		return ecError;
	}
	pnode = ab_tree_minid_to_node(pbase, mid);
	if (NULL == pnode) {
		ab_tree_put_base(pbase);
		*ppproptags = NULL;
		return ecInvalidObject;
	}
	if (nsp_interface_get_default_proptags(ab_tree_get_node_type(pnode),
	    b_unicode, *ppproptags) == ecSuccess) {
		count = 0;
		for (i=0; i<(*ppproptags)->cvalues; i++) {
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    (*ppproptags)->pproptag[i], &prop_val, temp_buff,
			    GX_ARRAY_SIZE(temp_buff)) != ecSuccess)
				continue;
			if (i != count) {
				(*ppproptags)->pproptag[count] = (*ppproptags)->pproptag[i];
			}
			count ++;
		}
		(*ppproptags)->cvalues = count;
	} else {
		*ppproptags = NULL;
	}
	ab_tree_put_base(pbase);
	return ecSuccess;
}

int nsp_interface_get_props(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, PROPTAG_ARRAY *pproptags, PROPERTY_ROW **pprows)
{
	int i;
	int count;
	int base_id;
	BOOL b_ephid;
	uint32_t row;
	uint32_t total;
	AB_BASE *pbase;
	BOOL b_unicode;
	BOOL b_proptags;
	uint32_t result;
	uint32_t last_row;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL == pstat) {
		*pprows = NULL;
		return ecNotSupported;
	}
	if (flags & FLAG_EPHID) {
		b_ephid = TRUE;
	} else {
		b_ephid = FALSE;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return ecError;
	}
	if (CODEPAGE_UNICODE == pstat->codepage) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	if (TRUE == b_unicode && NULL != pproptags) {
		for (i=0; i<pproptags->cvalues; i++) {
			if (PROP_TYPE(pproptags->pproptag[i]) == PT_STRING8) {
				*pprows = NULL;
				return ecNotSupported;
			}
		}
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*pprows = NULL;
		return ecError;
	}
	
	if (pstat->cur_rec <= 0x10) {
		if (0 == pstat->container_id) {
			pgal_list = &pbase->gal_list;
			if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
				psnode = single_list_get_head(pgal_list);
			} else if (MID_END_OF_TABLE == pstat->cur_rec) {
				psnode = single_list_get_tail(pgal_list);
			} else {
				nsp_interface_position_in_list(pstat,
					pgal_list, &row, &last_row, &total);
				for (i=0,psnode=single_list_get_head(pgal_list);
				     psnode != NULL && i < row; ++i)
					psnode = single_list_get_after(pgal_list, psnode);
			}
			if (NULL == psnode) {
				pnode1 = NULL;
			} else {
				pnode1 = static_cast<decltype(pnode1)>(psnode->pdata);
			}
		} else {
			pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
			if (NULL == pnode) {
				result = ecInvalidBookmark;
				goto EXIT_GET_PROPS;
			}
			nsp_interface_position_in_table(pstat,
					pnode, &row, &last_row, &total);
			pnode1 = simple_tree_node_get_child(pnode);
			if (NULL != pnode1) {
				i = 0;
				do {
					if (ab_tree_get_node_type(pnode1) > 0x80) {
						continue;
					}
					i ++;
					if (i == row) {
						break;
					}
				} while ((pnode1 = simple_tree_node_get_sibling(pnode1)) != nullptr);
			}
		}
	} else {
		pnode1 = ab_tree_minid_to_node(pbase, pstat->cur_rec);
		if (NULL != pnode1) {
			if (0 != pstat->container_id) {
				pnode = ab_tree_minid_to_node(
					pbase, pstat->container_id);
				if (NULL == pnode) {
					result = ecInvalidBookmark;
					goto EXIT_GET_PROPS;
				}
			}
		}
	}
	b_proptags = TRUE;
	if (NULL == pproptags) {
		b_proptags = FALSE;
		pproptags = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_IN);
		if (NULL == pproptags) {
			result = ecMAPIOOM;
			goto EXIT_GET_PROPS;
		}
		result = nsp_interface_get_default_proptags(
			ab_tree_get_node_type(pnode1), b_unicode, pproptags);
		if (result != ecSuccess)
			goto EXIT_GET_PROPS;
	} else if (pproptags->cvalues > 100) {
		result = ecTableTooBig;
		goto EXIT_GET_PROPS;
	}
	*pprows = common_util_propertyrow_init(NULL);
	if (NULL == *pprows) {
		result = ecMAPIOOM;
		goto EXIT_GET_PROPS;
	}
	/* MS-OXNSPI 3.1.4.1.7.11 */
	if (NULL == pnode1) {
		nsp_interface_make_ptyperror_row(pproptags, *pprows);
		result = ecWarnWithErrors;
	} else {
		result = nsp_interface_fetch_row(pnode1, b_ephid,
					pstat->codepage, pproptags, *pprows);
	}
	if (result == ecSuccess) {
		if (FALSE == b_proptags) {
			count = 0;
			for (i=0; i<(*pprows)->cvalues; i++) {
				if (PROP_TYPE((*pprows)->pprops[i].proptag) == PT_ERROR &&
				    (*pprows)->pprops[i].value.err == ecNotFound)
					continue;
				if (i != count) {
					(*pprows)->pprops[count] = (*pprows)->pprops[i];
				}
				count ++;
			}
			(*pprows)->cvalues = count;
		} else {
			for (i=0; i<(*pprows)->cvalues; i++) {
				if (PROP_TYPE((*pprows)->pprops[i].proptag) == PT_ERROR) {
					result = ecWarnWithErrors;
					break;
				}
			}
		}
	}
	
 EXIT_GET_PROPS:
	ab_tree_put_base(pbase);
	if (result != ecSuccess && result != ecWarnWithErrors)
		*pprows = NULL;
	return result;
}

int nsp_interface_compare_mids(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, uint32_t mid1, uint32_t mid2, uint32_t *presult)
{
	int i;
	int base_id;
	uint32_t result;
	uint32_t minid;
	int pos1, pos2;
	AB_BASE *pbase;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	
	
	if (NULL != pstat && CODEPAGE_UNICODE == pstat->codepage) {
		return ecNotSupported;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		return ecError;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return ecError;
	}
	
	pos1 = -1;
	pos2 = -1;
	i = 0;
	if (NULL == pstat || 0 == pstat->container_id) {
		pgal_list = &pbase->gal_list;
		for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
			psnode=single_list_get_after(pgal_list, psnode)) {
			minid = ab_tree_get_node_minid(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata));
			if (minid == mid1) {
				pos1 = i;
			}
			if (minid == mid2) {
				pos2 = i;
			}
			i ++;
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
		if (NULL == pnode) {
			result = ecInvalidBookmark;
			goto EXIT_COMPARE_MIDS;
		}
		pnode = simple_tree_node_get_child(pnode);
		if (NULL == pnode) {
			result = ecInvalidBookmark;
			goto EXIT_COMPARE_MIDS;
		}
		do {
			minid = ab_tree_get_node_minid(pnode);
			if (minid == mid1) {
				pos1 = i;
			}
			if (minid == mid2) {
				pos2 = i;
			}
			i ++;
		} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	}
	
	if (-1 == pos1 || -1 == pos2) {
		result = ecError;
		goto EXIT_COMPARE_MIDS;
	}
	*presult = pos2 - pos1;
	
	result = ecSuccess;
	
 EXIT_COMPARE_MIDS:
	ab_tree_put_base(pbase);
	return result;
}

int nsp_interface_mod_props(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow)
{
	return ecNotSupported;
}

static BOOL nsp_interface_build_specialtable(PROPERTY_ROW *prow,
	BOOL b_unicode, uint32_t codepage, BOOL has_child,
	unsigned int depth, int container_id, const char *str_dname,
	PERMANENT_ENTRYID *ppermeid_parent, PERMANENT_ENTRYID *ppermeid)
{
	int tmp_len;
	char tmp_title[1024];
	
	
	prow->reserved = 0x0;
	if (0 == depth) {
		prow->cvalues = 6;
	} else {
		prow->cvalues = 7;
	}
	prow->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, prow->cvalues);
	if (NULL == prow->pprops) {
		return FALSE;
	}
	
	/* PROP_TAG_ENTRYID */
	prow->pprops[0].proptag = PROP_TAG_ENTRYID;
	prow->pprops[0].reserved = 0;
	if (FALSE == common_util_permanent_entryid_to_binary(
		ppermeid, &prow->pprops[0].value.bin)) {
		prow->pprops[0].proptag = CHANGE_PROP_TYPE(prow->pprops[0].proptag, PT_ERROR);
		prow->pprops[0].value.err = ecMAPIOOM;
	}
	
	/* PROP_TAG_CONTAINERFLAGS */
	prow->pprops[1].proptag = PROP_TAG_CONTAINERFLAGS;
	prow->pprops[1].reserved = 0;
	if (FALSE == has_child) {
		prow->pprops[1].value.l = AB_RECIPIENTS | AB_UNMODIFIABLE;
	} else {
		prow->pprops[1].value.l = AB_RECIPIENTS
			| AB_SUBCONTAINERS | AB_UNMODIFIABLE;
	}
	
	/* PROP_TAG_DEPTH */
	prow->pprops[2].proptag = PROP_TAG_DEPTH;
	prow->pprops[2].reserved = 0;
	prow->pprops[2].value.l = depth;
	
	/* PROP_TAG_ADDRESSBOOKCONTAINERID */
	prow->pprops[3].proptag = PROP_TAG_ADDRESSBOOKCONTAINERID;
	prow->pprops[3].reserved = 0;
	prow->pprops[3].value.l = container_id;
	
	/* PROP_TAG_DISPLAYNAME PROP_TAG_DISPLAYNAME_STRING8 */
	prow->pprops[4].reserved = 0;
	if (TRUE == b_unicode) {
		prow->pprops[4].proptag = PROP_TAG_DISPLAYNAME;
	} else {
		prow->pprops[4].proptag = PROP_TAG_DISPLAYNAME_STRING8;
	}
	if (NULL == str_dname) {
		prow->pprops[4].value.pstr = NULL;
	} else {
		if (TRUE == b_unicode) {
			tmp_len = strlen(str_dname) + 1;
			prow->pprops[4].value.pv =
				ndr_stack_alloc(NDR_STACK_OUT, tmp_len);
			memcpy(prow->pprops[4].value.pstr, str_dname, tmp_len);
		} else {
			tmp_len = common_util_from_utf8(codepage,
				str_dname, tmp_title, sizeof(tmp_title));
			if (-1 == tmp_len) {
				prow->pprops[4].value.pstr = NULL;
			} else {
				prow->pprops[4].value.pv =
					ndr_stack_alloc(NDR_STACK_OUT, tmp_len);
				memcpy(prow->pprops[4].value.pstr, tmp_title, tmp_len);
			}
		}
		if (NULL == prow->pprops[4].value.pstr) {
			prow->pprops[4].proptag = CHANGE_PROP_TYPE(prow->pprops[4].proptag, PT_ERROR);
			prow->pprops[4].value.err = ecMAPIOOM;
		}
	}
	
	/* PROP_TAG_ADDRESSBOOKISMASTER */
	prow->pprops[5].proptag = PROP_TAG_ADDRESSBOOKISMASTER;
	prow->pprops[5].reserved = 0;
	prow->pprops[5].value.b = 0;
	
	/* PROP_TAG_ADDRESSBOOKPARENTENTRYID */
	if (0 != depth) {
		prow->pprops[6].proptag = PROP_TAG_ADDRESSBOOKPARENTENTRYID;
		prow->pprops[6].reserved = 0;
		if (FALSE == common_util_permanent_entryid_to_binary(
			ppermeid_parent, &prow->pprops[6].value.bin)) {
			prow->pprops[6].proptag = CHANGE_PROP_TYPE(prow->pprops[6].proptag, PT_ERROR);
			prow->pprops[6].value.err = ecMAPIOOM;
		}
	}
	return TRUE;
}

static BOOL nsp_interface_has_child(SIMPLE_TREE_NODE *pnode)
{
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return FALSE;
	}
	do {
		if (ab_tree_get_node_type(pnode) > 0x80) {
			return TRUE;
		}
	} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	return FALSE;
}

static uint32_t nsp_interface_get_specialtables_from_node(
	SIMPLE_TREE_NODE *pnode, PERMANENT_ENTRYID *ppermeid_parent,
	BOOL b_unicode, uint32_t codepage, PROPROW_SET *prows)
{
	GUID tmp_guid;
	BOOL has_child;
	uint32_t result;
	int container_id;
	PROPERTY_ROW *prow;
	char str_dname[1024];
	SIMPLE_TREE_NODE *pnode1;
	
	auto ppermeid = ndr_stack_anew<PERMANENT_ENTRYID>(NDR_STACK_OUT);
	if (NULL == ppermeid) {
		return ecMAPIOOM;
	}
	ab_tree_node_to_guid(pnode, &tmp_guid);
	if (FALSE == common_util_set_permanententryid(
		DT_CONTAINER, &tmp_guid, NULL, ppermeid)) {
		return ecMAPIOOM;
	}
	prow = common_util_proprowset_enlarge(prows);
	if (NULL == prow) {
		return ecMAPIOOM;
	}
	has_child = nsp_interface_has_child(pnode);
	container_id = ab_tree_get_node_minid(pnode);
	if (0 == container_id) {
		return ecError;
	}
	ab_tree_get_display_name(pnode, codepage, str_dname);
	if (FALSE == nsp_interface_build_specialtable(
		prow, b_unicode, codepage, has_child,
		simple_tree_node_get_depth(pnode), container_id,
		str_dname, ppermeid_parent, ppermeid)) {
		return ecMAPIOOM;
	}
	if (TRUE == has_child) {
		pnode1 = simple_tree_node_get_child(pnode);
		do {
			if (ab_tree_get_node_type(pnode1) > 0x80) {
				result = nsp_interface_get_specialtables_from_node(
					pnode1, ppermeid, b_unicode, codepage, prows);
				if (result != ecSuccess)
					return result;
			}
		} while ((pnode1 = simple_tree_node_get_sibling(pnode1)) != nullptr);
	}
	return ecSuccess;
}

static uint32_t nsp_interface_get_tree_specialtables(
	SIMPLE_TREE *ptree, BOOL b_unicode, uint32_t codepage,
	PROPROW_SET *prows)
{
	SIMPLE_TREE_NODE *pnode;
	
	pnode = simple_tree_get_root(ptree);
	if (NULL == pnode) {
		return ecError;
	}
	return nsp_interface_get_specialtables_from_node(
			pnode, NULL, b_unicode, codepage, prows);
}

int nsp_interface_get_specialtable(NSPI_HANDLE handle, uint32_t flags,
	STAT *pstat, uint32_t *pversion, PROPROW_SET **pprows)
{
	int base_id;
	BOOL b_unicode;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t codepage;
	PROPERTY_ROW *prow;
	DOMAIN_NODE *pdomain;
	SINGLE_LIST_NODE *pnode;
	PERMANENT_ENTRYID permeid;
	
	
	if (flags & FLAG_CREATIONTEMPLATES) {
		*pprows = NULL;
		/* creation of templates table */
		return ecSuccess;
	}

	if (flags & FLAG_UNICODESTRINGS) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	
	if (NULL == pstat) {
		codepage = 1252;
	} else {
		codepage = pstat->codepage;
	}
	
	/* in MS-OXNSPI 3.1.4.1.3 server processing rules */
	if (FALSE == b_unicode && CODEPAGE_UNICODE == codepage) {
		*pprows = NULL;
		return ecNotSupported;
	}
	
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*pprows = NULL;
		return ecError;
	}
	
	(*pversion) ++;
	
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		return ecMAPIOOM;
	}
	
	/* build the gal root */
	prow = common_util_proprowset_enlarge(*pprows);
	if (NULL == prow) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	
	if (FALSE == common_util_set_permanententryid(
		DT_CONTAINER, NULL, NULL, &permeid)) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	if (FALSE == nsp_interface_build_specialtable(prow,
		b_unicode, codepage, FALSE, 0, 0, NULL, NULL,
		&permeid)) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*pprows = NULL;
		return ecError;
	}
	for (pnode=single_list_get_head(&pbase->list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->list, pnode)) {
		pdomain = static_cast<decltype(pdomain)>(pnode->pdata);
		result = nsp_interface_get_tree_specialtables(
			&pdomain->tree, b_unicode, codepage, *pprows);
		if (result != ecSuccess) {
			ab_tree_put_base(pbase);
			*pprows = NULL;
			return result;
		}
	}
	ab_tree_put_base(pbase);
	return ecSuccess;
}

int nsp_interface_mod_linkatt(NSPI_HANDLE handle, uint32_t flags,
	uint32_t proptag, uint32_t mid, BINARY_ARRAY *pentry_ids)
{
	int base_id, fd;
	AB_BASE *pbase;
	uint32_t result;
	uint32_t tmp_mid;
	char maildir[256];
	char username[324];
	char temp_path[256];
	DCERPC_INFO rpc_info;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	SIMPLE_TREE_NODE *ptnode;
	std::unique_ptr<LIST_FILE> pfile;
	size_t item_num = 0;
	
	if (0 == mid) {
		return ecInvalidObject;
	}
	if (PROP_TAG_ADDRESSBOOKPUBLICDELEGATES != proptag) {
		return ecNotSupported;
	}
	rpc_info = get_rpc_info();
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		return ecError;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		return ecError;
	}
	double_list_init(&tmp_list);
	ptnode = ab_tree_minid_to_node(pbase, mid);
	if (NULL == ptnode) {
		result = ecInvalidObject;
		goto EXIT_MOD_LINKATT;
	}
	switch (ab_tree_get_node_type(ptnode)) {
	case NODE_TYPE_PERSON:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		break;
	default:
		result = ecInvalidObject;
		goto EXIT_MOD_LINKATT;
	}
	ab_tree_get_user_info(ptnode, USER_MAIL_ADDRESS, username, GX_ARRAY_SIZE(username));
	if (0 != strcasecmp(username, rpc_info.username)) {
		result = ecAccessDenied;
		goto EXIT_MOD_LINKATT;
	}
	if (FALSE == get_maildir(username, maildir)) {
		result = ecError;
		goto EXIT_MOD_LINKATT;
	}
	snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s/config/delegates.txt", maildir);
	pfile = list_file_initd(temp_path, nullptr, "%s:256");
	if (NULL != pfile) {
		item_num = pfile->get_size();
		auto pitem = static_cast<const dlgitem *>(pfile->get_list());
		for (decltype(item_num) i = 0; i < item_num; ++i) {
			pnode = static_cast<decltype(pnode)>(malloc(sizeof(*pnode)));
			if (NULL == pnode) {
				result = ecMAPIOOM;
				goto EXIT_MOD_LINKATT;
			}
			pnode->pdata = strdup(pitem[i].user);
			if (NULL == pnode->pdata) {
				free(pnode);
				result = ecMAPIOOM;
				goto EXIT_MOD_LINKATT;
			}
			double_list_append_as_tail(&tmp_list, pnode);
		}
	}
	for (int i = 0; i < pentry_ids->cvalues; ++i) {
		if (pentry_ids->pbin[i].cb < 32) {
			continue;
		}
		if (32 == pentry_ids->pbin[i].cb) {
			tmp_mid = pentry_ids->pbin[i].pb[28];
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[29]) << 8;
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[30]) << 16;
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[31]) << 24;
			ptnode = ab_tree_minid_to_node(pbase, tmp_mid);
		} else {
			ptnode = ab_tree_dn_to_node(pbase, pentry_ids->pbin[i].pc + 28);
		}
		if (NULL == ptnode) {
			continue;
		}
		ab_tree_get_user_info(ptnode, USER_MAIL_ADDRESS, username, GX_ARRAY_SIZE(username));
		if (flags & MOD_FLAG_DELETE) {
			for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
				pnode=double_list_get_after(&tmp_list, pnode)) {
				if (strcasecmp(username, static_cast<char *>(pnode->pdata)) == 0) {
					double_list_remove(&tmp_list, pnode);
					free(pnode->pdata);
					free(pnode);
					break;
				}
			}
		} else {
			for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
				pnode=double_list_get_after(&tmp_list, pnode)) {
				if (strcasecmp(username, static_cast<char *>(pnode->pdata)) == 0)
					break;
			}
			if (NULL == pnode) {
				pnode = static_cast<decltype(pnode)>(malloc(sizeof(*pnode)));
				if (NULL == pnode) {
					result = ecMAPIOOM;
					goto EXIT_MOD_LINKATT;
				}
				pnode->pdata = strdup(username);
				if (NULL == pnode->pdata) {
					free(pnode);
					result = ecMAPIOOM;
					goto EXIT_MOD_LINKATT;
				}
				double_list_append_as_tail(&tmp_list, pnode);
			}
		}
	}
	if (item_num != double_list_get_nodes_num(&tmp_list)) {
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 == fd) {
			result = ecError;
			goto EXIT_MOD_LINKATT;
		}
		for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
			pnode=double_list_get_after(&tmp_list, pnode)) {
			write(fd, pnode->pdata, strlen(static_cast<char *>(pnode->pdata)));
			write(fd, "\r\n", 2);
		}
		close(fd);
	}
	result = ecSuccess;
	
 EXIT_MOD_LINKATT:
	ab_tree_put_base(pbase);
	while ((pnode = double_list_pop_front(&tmp_list)) != nullptr) {
		free(pnode->pdata);
		free(pnode);
	}
	double_list_free(&tmp_list);
	return result;
}

int nsp_interface_query_columns(NSPI_HANDLE handle, uint32_t reserved,
	uint32_t flags, PROPTAG_ARRAY **ppcolumns)
{
	BOOL b_unicode;
	PROPTAG_ARRAY *pcolumns;
	
	if (flags & FLAG_UNICODEPROPTYPES) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
	}
	pcolumns = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_OUT);
	if (NULL == pcolumns) {
		*ppcolumns = NULL;
		return ecMAPIOOM;
	}
	pcolumns->cvalues = 31;
	pcolumns->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pcolumns->cvalues);
	if (NULL == pcolumns->pproptag) {
		*ppcolumns = NULL;
		return ecMAPIOOM;
	}
#define U(x) (b_unicode ? (x) : CHANGE_PROP_TYPE((x), PT_STRING8))
	auto &t = pcolumns->pproptag;
	t[0] = U(PROP_TAG_DISPLAYNAME);
	t[1] = U(PROP_TAG_NICKNAME);
	t[2] = U(PROP_TAG_TITLE);
	t[3] = U(PROP_TAG_BUSINESSTELEPHONENUMBER);
	t[4] = U(PROP_TAG_PRIMARYTELEPHONENUMBER);
	t[5] = U(PROP_TAG_MOBILETELEPHONENUMBER);
	t[6] = U(PROP_TAG_HOMEADDRESSSTREET);
	t[7] = U(PROP_TAG_COMMENT);
	t[8] = U(PROP_TAG_COMPANYNAME);
	t[9] = U(PROP_TAG_DEPARTMENTNAME);
	t[10] = U(PROP_TAG_OFFICELOCATION);
	t[11] = U(PROP_TAG_ADDRESSTYPE);
	t[12] = U(PROP_TAG_SMTPADDRESS);
	t[13] = U(PROP_TAG_EMAILADDRESS);
	t[14] = U(PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE);
	t[15] = U(PROP_TAG_ACCOUNT);
	t[16] = U(PROP_TAG_TRANSMITTABLEDISPLAYNAME);
	t[17] = U(PROP_TAG_ADDRESSBOOKPROXYADDRESSES);
	t[18] = PROP_TAG_OBJECTTYPE;
	t[19] = PROP_TAG_DISPLAYTYPE;
	t[20] = PROP_TAG_DISPLAYTYPEEX;
	t[21] = PROP_TAG_ENTRYID;
	t[22] = PROP_TAG_RECORDKEY;
	t[23] = PROP_TAG_ORIGINALENTRYID;
	t[24] = PROP_TAG_SEARCHKEY;
	t[25] = PROP_TAG_INSTANCEKEY;
	t[26] = PROP_TAG_MAPPINGSIGNATURE;
	t[27] = PROP_TAG_SENDRICHINFO;
	t[28] = PROP_TAG_TEMPLATEID;
	t[29] = PROP_TAG_ADDRESSBOOKOBJECTGUID;
	t[30] = PROP_TAG_CREATIONTIME;
#undef U
	return ecSuccess;
}

int nsp_interface_resolve_names(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, STRINGS_ARRAY *pstrs,
	PROPTAG_ARRAY **ppmids, PROPROW_SET **pprows)
{
	int i;
	char *pstr;
	int temp_len;
	
	for (i=0; i<pstrs->count; i++) {
		temp_len = 2*strlen(pstrs->ppstrings[i]) + 1;
		pstr = ndr_stack_anew<char>(NDR_STACK_IN, temp_len);
		if (NULL == pstr) {
			*ppmids = NULL;
			*pprows = NULL;
			return ecMAPIOOM;
		}
		if (-1 == common_util_to_utf8(pstat->codepage,
			pstrs->ppstrings[i], pstr, temp_len)) {
			pstrs->ppstrings[i] = NULL;
		} else {
			pstrs->ppstrings[i] = pstr;
		}
	}
	return nsp_interface_resolve_namesw(handle, reserved,
				pstat, pproptags, pstrs, ppmids, pprows);
}

static BOOL nsp_interface_resolve_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	if (TRUE == ab_tree_node_to_dn(pnode, dn, sizeof(dn))
		&& 0 == strcasecmp(dn, pstr)) {
		return TRUE;
	}
	ab_tree_get_department_name(pnode, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	switch(ab_tree_get_node_type(pnode)) {
	case NODE_TYPE_PERSON:
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn, GX_ARRAY_SIZE(dn));
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	case NODE_TYPE_MLIST:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	}
	return FALSE;
}

static SIMPLE_TREE_NODE* nsp_interface_resolve_gal(SINGLE_LIST *plist,
	uint32_t codepage, char *pstr, BOOL *pb_ambiguous)
{
	SINGLE_LIST_NODE *pnode;
	SIMPLE_TREE_NODE *ptnode;
	
	ptnode = NULL;
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		if (!nsp_interface_resolve_node(static_cast<SIMPLE_TREE_NODE *>(pnode->pdata), codepage, pstr))
			continue;
		if (NULL != ptnode) {
			*pb_ambiguous = TRUE;
			return NULL;
		} else {
			ptnode = static_cast<decltype(ptnode)>(pnode->pdata);
		}
	}
	if (NULL == ptnode) {
		*pb_ambiguous = FALSE;
		return NULL;
	}
	return ptnode;
}

static uint32_t nsp_interface_fetch_smtp_property(
	const char *paddress, uint32_t proptag, PROPERTY_VALUE *pprop)
{
	pprop->proptag = proptag;
	pprop->reserved = 0;
	switch (proptag) {
	case PROP_TAG_ADDRESSTYPE:
	case PROP_TAG_ADDRESSTYPE_STRING8:
		pprop->value.pstr = deconst("SMTP");
		break;
	case PROP_TAG_EMAILADDRESS:
	case PROP_TAG_EMAILADDRESS_STRING8:
		pprop->value.pv = ndr_stack_alloc(
			NDR_STACK_OUT, strlen(paddress) + 1);
		if (NULL == pprop->value.pstr) {
			return ecMAPIOOM;
		}
		strcpy(pprop->value.pstr, paddress);
		break;
	case PROP_TAG_OBJECTTYPE:
		pprop->value.l = OT_MAILUSER;
		break;
	case PROP_TAG_DISPLAYTYPE:
		pprop->value.l = DT_MAILUSER;
		break;
	case PROP_TAG_DISPLAYTYPEEX:
		pprop->value.l = DT_MAILUSER;
		break;
	case PROP_TAG_SEARCHKEY:
		pprop->value.bin.cb = strlen(paddress) + 6;
		pprop->value.bin.pv = ndr_stack_alloc(
			NDR_STACK_OUT, pprop->value.bin.cb);
		if (pprop->value.bin.pc == nullptr)
			return ecMAPIOOM;
		sprintf(pprop->value.bin.pc, "SMTP:%s", paddress);
		HX_strupper(pprop->value.bin.pc);
		break;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8:
	case PROP_TAG_DISPLAYNAME:
	case PROP_TAG_DISPLAYNAME_STRING8:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE_STRING8:
		pprop->value.pv = ndr_stack_alloc(
			NDR_STACK_OUT, strlen(paddress) + 1);
		if (NULL == pprop->value.pstr) {
			return ecMAPIOOM;
		}
		strcpy(pprop->value.pstr, paddress);
		break;
	default:
		return ecNotFound;
	}
	return ecSuccess;
}

static uint32_t nsp_interface_fetch_smtp_row(const char *paddress,
	PROPTAG_ARRAY *pproptags, PROPERTY_ROW *prow)
{
	int i;
	uint32_t err_val;
	PROPERTY_VALUE *pprop;
	
	for (i=0; i<pproptags->cvalues; i++) {
		pprop = common_util_propertyrow_enlarge(prow);
		if (NULL == pprop) {
			return ecMAPIOOM;
		}
		err_val = nsp_interface_fetch_smtp_property(
			paddress, pproptags->pproptag[i], pprop);
		if (err_val != ecSuccess) {
			pprop->proptag = CHANGE_PROP_TYPE(pprop->proptag, PT_ERROR);
			pprop->value.err = err_val;
		}
	}
	return ecSuccess;
}

int nsp_interface_resolve_namesw(NSPI_HANDLE handle, uint32_t reserved,
	STAT *pstat, PROPTAG_ARRAY *pproptags, STRINGS_ARRAY *pstrs,
    MID_ARRAY **ppmids, NSP_ROWSET **pprows)
{
	int i, j;
	int base_id;
	char *ptoken;
	AB_BASE *pbase;
	uint32_t result;
	BOOL b_ambiguous;
	uint32_t last_row;
	uint32_t start_pos, total;
	uint32_t *pproptag;
	PROPERTY_ROW *prow;
	SIMPLE_TREE_NODE *pnode;
	SIMPLE_TREE_NODE *pnode1;
	SIMPLE_TREE_NODE *pnode2;
	
	if (CODEPAGE_UNICODE == pstat->codepage) {
		*ppmids = NULL;
		*pprows = NULL;
		return ecNotSupported;
	}
	/*
	[MS-OXNPI] 3.1.4.1.17, If the input parameter Reserved contains
	any value other than 0, the server MUST return one of the return
	values specified in section 2.2.1.2, but Outlook 2010 always send
	non-zero so we skip it.
	*/
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*ppmids = NULL;
		*pprows = NULL;
		return ecError;
	}
	if (NULL == pproptags) {
		pproptags = ndr_stack_anew<PROPTAG_ARRAY>(NDR_STACK_IN);
		if (NULL == pproptags) {
			*ppmids = NULL;
			*pprows = NULL;
			return ecMAPIOOM;
		}
		pproptags->cvalues = 7;
		pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, pproptags->cvalues);
		if (pproptags->pproptag == nullptr) {
			*ppmids = NULL;
			*pprows = NULL;
			return ecMAPIOOM;
		}
		pproptags->pproptag[0] = PROP_TAG_ADDRESSBOOKCONTAINERID;
		pproptags->pproptag[1] = PROP_TAG_OBJECTTYPE;
		pproptags->pproptag[2] = PROP_TAG_DISPLAYTYPE;
		pproptags->pproptag[3] = PROP_TAG_DISPLAYNAME_STRING8;
		pproptags->pproptag[4] = PROP_TAG_PRIMARYTELEPHONENUMBER_STRING8;
		pproptags->pproptag[5] = PROP_TAG_DEPARTMENTNAME_STRING8;
		pproptags->pproptag[6] = PROP_TAG_OFFICELOCATION_STRING8;
	} else {
		if (pproptags->cvalues > 100) {
			*ppmids = NULL;
			*pprows = NULL;
			return ecTableTooBig;
		}
	}
	*ppmids = common_util_proptagarray_init();
	if (NULL == *ppmids) {
		*pprows = NULL;
		return ecMAPIOOM;
	}
	*pprows = common_util_proprowset_init();
	if (NULL == *pprows) {
		*ppmids = NULL;
		return ecMAPIOOM;
	}
	pbase = ab_tree_get_base(base_id);
	if (NULL == pbase || (TRUE == g_session_check &&
		0 != guid_compare(&pbase->guid, &handle.guid))) {
		if (NULL != pbase) {
			ab_tree_put_base(pbase);
		}
		*ppmids = NULL;
		*pprows = NULL;
		return ecError;
	}
	
	if (0 == pstat->container_id) {
		for (i=0; i<pstrs->count; i++) {
			pproptag = common_util_proptagarray_enlarge(*ppmids);
			if (NULL == pproptag) {
				result = ecMAPIOOM;
				goto EXIT_RESOLVE_NAMESW;
			}
			if (NULL == pstrs->ppstrings[i]) {
				*pproptag = MID_UNRESOLVED;
				continue;
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pstrs->ppstrings[i], ':');
			if (NULL != ptoken) {
				ptoken ++;
			} else {
				ptoken = pstrs->ppstrings[i];
			}
			pnode = nsp_interface_resolve_gal(&pbase->gal_list,
						pstat->codepage, ptoken, &b_ambiguous);
			if (NULL == pnode) {
				if (TRUE == b_ambiguous) {
					*pproptag = MID_AMBIGUOUS;
				} else {
					if (0 == strncasecmp(pstrs->ppstrings[i],
						"=SMTP:", 6)) {
						prow = common_util_proprowset_enlarge(*pprows);
						if (NULL == prow || NULL ==
							common_util_propertyrow_init(prow)) {
							result = ecMAPIOOM;
							goto EXIT_RESOLVE_NAMESW;
						}
						result = nsp_interface_fetch_smtp_row(
							pstrs->ppstrings[i] + 6, pproptags, prow);
						if (result != ecSuccess)
							goto EXIT_RESOLVE_NAMESW;
						*pproptag = MID_RESOLVED;
					} else {
						*pproptag = MID_UNRESOLVED;
					}
				}
			} else {
				*pproptag = MID_RESOLVED;
				prow = common_util_proprowset_enlarge(*pprows);
				if (NULL == prow || NULL ==
					common_util_propertyrow_init(prow)) {
					result = ecMAPIOOM;
					goto EXIT_RESOLVE_NAMESW;
				}
				result = nsp_interface_fetch_row(pnode, TRUE,
							pstat->codepage, pproptags, prow);
				if (result != ecSuccess)
					goto EXIT_RESOLVE_NAMESW;
			}		
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, pstat->container_id);
		if (NULL == pnode) {
			result = ecInvalidBookmark;
			goto EXIT_RESOLVE_NAMESW;
		}
		nsp_interface_position_in_table(pstat,
			pnode, &start_pos, &last_row, &total);
		for (i=0; i<pstrs->count; i++) {
			pproptag = common_util_proptagarray_enlarge(*ppmids);
			if (NULL == pproptag) {
				result = ecMAPIOOM;
				goto EXIT_RESOLVE_NAMESW;
			}
			if (NULL == pstrs->ppstrings[i]) {
				*pproptag = MID_UNRESOLVED;
				continue;
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pstrs->ppstrings[i], ':');
			if (NULL != ptoken) {
				ptoken ++;
			} else {
				ptoken = pstrs->ppstrings[i];
			}
			*pproptag = MID_UNRESOLVED;
			for (j=0,pnode1=simple_tree_node_get_child(pnode);
				NULL!=pnode1&&j>=start_pos&&j<=last_row;
			     pnode1 = simple_tree_node_get_sibling(pnode1)) {
				if (ab_tree_get_node_type(pnode1) > 0x80) {
					continue;
				}
				if (TRUE == nsp_interface_resolve_node(
					pnode1, pstat->codepage, ptoken)) {
					if (MID_RESOLVED == *pproptag) {
						*pproptag = MID_AMBIGUOUS;
						break;
					} else {
						*pproptag = MID_RESOLVED;
						pnode2 = pnode1;
					}
				}
				j ++;
			}
			if (MID_RESOLVED == *pproptag) {
				prow = common_util_proprowset_enlarge(*pprows);
				if (NULL == prow || NULL ==
					common_util_propertyrow_init(prow)) {
					result = ecMAPIOOM;
					goto EXIT_RESOLVE_NAMESW;
				}
				result = nsp_interface_fetch_row(pnode2, TRUE,
							pstat->codepage, pproptags, prow);
				if (result != ecSuccess)
					goto EXIT_RESOLVE_NAMESW;
			}
		}
	}
	result = ecSuccess;
	
 EXIT_RESOLVE_NAMESW:
	ab_tree_put_base(pbase);
	if (result != ecSuccess) {
		*ppmids = NULL;
		*pprows = NULL;
	}
	return result;
}

void nsp_interface_unbind_rpc_handle(uint64_t hrpc)
{
	/* do nothing */
}

int nsp_interface_get_templateinfo(NSPI_HANDLE handle, uint32_t flags,
    uint32_t type, char *dn, uint32_t codepage, uint32_t locale_id,
    PROPERTY_ROW **ppdata)
{
	*ppdata = nullptr;
	if ((flags & (TI_TEMPLATE | TI_SCRIPT)) != TI_TEMPLATE)
		return ecNotSupported;
	if (!verify_cpid(codepage))
		return MAPI_E_UNKNOWN_CPID;
	if (dn != nullptr) {
		fprintf(stderr, "[exchange_nsp]: unimplemented templateinfo dn=%s\n", dn);
		return MAPI_E_UNKNOWN_LCID;
	}

	char buf[4096];
	snprintf(buf, sizeof(buf), PKGDATADIR "/displayTable-%X-%X.abkt", locale_id, type);
	wrapfd fd = open(buf, O_RDONLY);
	if (fd.get() < 0)
		return MAPI_E_UNKNOWN_LCID;
	std::string tpldata;
	ssize_t have_read;
	while ((have_read = read(fd.get(), buf, sizeof(buf))) > 0)
		tpldata += std::string_view(buf, have_read);
	fd.close();
	try {
		tpldata = nsp_abktobinary(nsp_abktojson(tpldata, 0), codepage, false);
	} catch (const std::runtime_error &e) {
		return MAPI_E_UNKNOWN_LCID;
	}

	auto row = *ppdata = ndr_stack_anew<PROPERTY_ROW>(NDR_STACK_OUT);
	if (row == nullptr)
		return ecMAPIOOM;
	row->reserved = 0;
	row->cvalues  = 1;
	auto val = row->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT);
	if (val == nullptr)
		return ecMAPIOOM;
	val->proptag  = PROP_TAG_TEMPLATEDATA;
	val->reserved = 0;
	val->value.bin.cb = tpldata.size();
	val->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, tpldata.size());
	if (val->value.bin.pv == nullptr)
		return ecMAPIOOM;
	memcpy(val->value.bin.pv, tpldata.data(), tpldata.size());
	return 0;
}
