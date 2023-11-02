// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/ab_tree.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxoabkt.hpp>
#include <gromox/paths.h>
#include <gromox/proc_common.h>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include <gromox/zz_ndr_stack.hpp>
#include "ab_tree.h"
#include "common_util.h"
#include "nsp_interface.hpp"

using namespace std::string_literals;
using namespace gromox;

namespace {

struct nsp_sort_item {
	uint32_t minid;
	union {
		char *string;
		void *strv;
	};
};

}

enum {
	TI_TEMPLATE = 0x1,
	TI_SCRIPT = 0x4,
};

unsigned int g_nsp_trace;
static BOOL g_session_check;
static decltype(mysql_adaptor_get_domain_ids) *get_domain_ids;
static decltype(mysql_adaptor_get_id_from_username) *get_id_from_username;
static decltype(mysql_adaptor_get_maildir) *get_maildir;
static decltype(mysql_adaptor_get_mlist_memb) *get_mlist_memb;

static void nsp_trace(const char *func, bool is_exit, const STAT *s,
    int *delta = nullptr, NSP_ROWSET *outrows = nullptr)
{
	if (g_nsp_trace == 0 || s == nullptr)
		return;
	fprintf(stderr, "%s %s:", is_exit ? "Leaving" : "Entering", func);
	fprintf(stderr," {container=%xh record=%xh delta=%d fpos=%u/%u} ",
		s->container_id, s->cur_rec, s->delta, s->num_pos, s->total_rec);
	if (delta != nullptr)
		fprintf(stderr, "{*pdelta=%d}", *delta);
	if (outrows == nullptr) {
		fprintf(stderr, "\n");
		return;
	}
	fprintf(stderr, "{#outrows=%u}\n", outrows->crows);
	for (size_t k = 0; k < outrows->crows; ++k) {
		auto dispn = outrows->prows[k].getval(PR_DISPLAY_NAME);
		auto eid = outrows->prows[k].getval(PR_ENTRYID);
		fprintf(stderr, "\t#%zu  %s (%u props)\n",
			k, dispn != nullptr ? znul(dispn->pstr) : "",
			outrows->prows[k].cvalues);
		if (eid == nullptr)
			continue;
		fprintf(stderr, "\t#%zu  %s\n", k, bin2txt(eid->bin.pb, eid->bin.cb).c_str());
	}
}

static const BINARY *nsp_photo_rpc(const char *dir)
{
	if (*dir == '\0')
		return nullptr;
	const PROPERTY_NAME xn = {MNID_STRING, PSETID_GROMOX, 0, deconst("photo")};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!get_named_propids(dir, false, &name_req, &name_rsp) ||
	    name_rsp.count != name_req.count || name_rsp.ppropid[0] == 0)
		return nullptr;
	uint32_t proptag = PROP_TAG(PT_BINARY, name_rsp.ppropid[0]);
	const PROPTAG_ARRAY tags = {1, deconst(&proptag)};
	TPROPVAL_ARRAY values{};
	if (!get_store_properties(dir, CP_ACP, &tags, &values))
		return nullptr;
	return values.get<const BINARY>(proptag);
}

static uint32_t nsp_interface_fetch_property(const SIMPLE_TREE_NODE *pnode,
    BOOL b_ephid, cpid_t codepage, uint32_t proptag, PROPERTY_VALUE *pprop,
    void *pbuff, size_t pbsize)
{
	int minid;
	int temp_len;
	char dn[1280]{};
	GUID temp_guid;
	uint32_t display_type;
	EPHEMERAL_ENTRYID ephid;
	PERMANENT_ENTRYID permeid;
	
	temp_len = 1024;
	pprop->proptag = proptag;
	pprop->reserved = 0;
	auto node_type = ab_tree_get_node_type(pnode);
	/* Properties that need to be force-generated */
	switch (proptag) {
	case PR_CREATION_TIME:
		pprop->value.ftime = {};
		return ecSuccess;
	case PR_EMS_AB_HOME_MDB:
	case PR_EMS_AB_HOME_MDB_A:
		if (node_type != abnode_type::user)
			return ecNotFound;
		ab_tree_get_server_dn(pnode, dn, sizeof(dn));
		HX_strlcat(dn, "/cn=Microsoft Private MDB", std::size(dn));
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
			strcpy(static_cast<char *>(pprop->value.pv), dn);
		} else {
			pprop->value.pv = pbuff;
			gx_strlcpy(pprop->value.pstr, dn, pbsize);
		}
		return ecSuccess;
	case PR_EMS_AB_OBJECT_GUID:
		if (!ab_tree_node_to_guid(pnode, &temp_guid))
			return ecServerOOM;
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (pprop->value.bin.pv == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.bin.pv = deconst(pbuff);
		}
		common_util_guid_to_binary(&temp_guid, &pprop->value.bin);
		return ecSuccess;
	case PR_EMS_AB_CONTAINERID:
		pnode = pnode->get_parent();
		pprop->value.l = pnode == nullptr ? 0 : ab_tree_get_node_minid(pnode);
		return ecSuccess;
	case PR_ADDRTYPE:
	case PR_ADDRTYPE_A:
		pprop->value.pstr = deconst("EX");
		return ecSuccess;
	case PR_EMAIL_ADDRESS:
	case PR_EMAIL_ADDRESS_A:
		if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
			return ecInvalidObject;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PR_OBJECT_TYPE: {
		auto t = node_type == abnode_type::mlist ? MAPI_DISTLIST :
		         node_type == abnode_type::folder ? MAPI_FOLDER : MAPI_MAILUSER;
		pprop->value.l = static_cast<uint32_t>(t);
		return ecSuccess;
	}
	case PR_DISPLAY_TYPE:
		pprop->value.l = ab_tree_get_dtyp(pnode);
		return ecSuccess;
	case PR_DISPLAY_TYPE_EX: {
		auto dtypx = ab_tree_get_dtypx(pnode);
		pprop->value.l = dtypx.has_value() ? *dtypx : DT_MAILUSER;
		return ecSuccess;
	}
	case PR_MAPPING_SIGNATURE:
		pprop->value.bin.cb = 16;
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (pprop->value.bin.pb == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.bin.pv = pbuff;
		}
		memcpy(pprop->value.bin.pb, &muidEMSAB, sizeof(muidEMSAB));
		return ecSuccess;
	case PR_TEMPLATEID:
		display_type = node_type == abnode_type::mlist ? DT_DISTLIST : DT_MAILUSER;
		if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
			return ecNotFound;
		if (!common_util_set_permanententryid(display_type, nullptr, dn, &permeid) ||
		    !common_util_permanent_entryid_to_binary(&permeid, &pprop->value.bin))
			return ecServerOOM;
		return ecSuccess;
	case PR_ENTRYID:
	case PR_RECORD_KEY:
	case PR_ORIGINAL_ENTRYID:
		display_type = node_type == abnode_type::mlist ? DT_DISTLIST : DT_MAILUSER;
		if (!b_ephid) {
			if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
				return ecNotFound;
			if (!common_util_set_permanententryid(display_type,
			    nullptr, dn, &permeid) ||
			    !common_util_permanent_entryid_to_binary(&permeid, &pprop->value.bin))
				return ecServerOOM;
		} else {
			common_util_set_ephemeralentryid(display_type,
				ab_tree_get_node_minid(pnode), &ephid);
			if (!common_util_ephemeral_entryid_to_binary(&ephid,
			    &pprop->value.bin))
				return ecServerOOM;
		}
		return ecSuccess;
	case PR_SEARCH_KEY:
		if (!ab_tree_node_to_dn(pnode, dn, std::size(dn)))
			return ecNotFound;
		pprop->value.bin.cb = strlen(dn) + 4;
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(
				NDR_STACK_OUT, pprop->value.bin.cb);
			if (pprop->value.bin.pc == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.bin.pv = pbuff;
		}
		sprintf(pprop->value.bin.pc, "EX:%s", dn);
		HX_strupper(pprop->value.bin.pc);
		return ecSuccess;
	case PR_INSTANCE_KEY:
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 4);
			if (pprop->value.bin.pb == nullptr)
				return ecServerOOM;
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
	case PR_TRANSMITABLE_DISPLAY_NAME:
		if (node_type != abnode_type::user)
			return ecNotFound;
		[[fallthrough]];
	case PR_DISPLAY_NAME:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
		ab_tree_get_display_name(pnode, codepage, dn, std::size(dn));
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PR_TRANSMITABLE_DISPLAY_NAME_A:
		if (node_type != abnode_type::user)
			return ecNotFound;
		[[fallthrough]];
	case PR_DISPLAY_NAME_A:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A:
		/* @codepage is used to select a translation; it's not for charsets */
		ab_tree_get_display_name(pnode, codepage, dn, std::size(dn));
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn);
			pprop->value.pv = ndr_stack_alloc(
						NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_COMPANY_NAME:
		ab_tree_get_company_info(pnode, dn, NULL);
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PR_COMPANY_NAME_A:
		ab_tree_get_company_info(pnode, dn, NULL);
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn);
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_DEPARTMENT_NAME:
		ab_tree_get_department_name(pnode, dn);
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PR_DEPARTMENT_NAME_A:
		ab_tree_get_department_name(pnode, dn);
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn);
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage,
			dn, pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_OFFICE_LOCATION:
		ab_tree_get_company_info(pnode, NULL, dn);
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PR_OFFICE_LOCATION_A:
		ab_tree_get_company_info(pnode, NULL, dn);
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn);
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		common_util_from_utf8(codepage, dn,
				pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_ACCOUNT:
	case PR_ACCOUNT_A:
	case PR_SMTP_ADDRESS:
	case PR_SMTP_ADDRESS_A:
		if (node_type == abnode_type::mlist)
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		else if (node_type == abnode_type::user)
			gx_strlcpy(dn, znul(ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS)), sizeof(dn));
		else
			return ecNotFound;
		if (*dn == '\0')
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, strlen(dn) + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn);
		return ecSuccess;
	case PR_EMS_AB_PROXY_ADDRESSES:
	case PR_EMS_AB_PROXY_ADDRESSES_A: {
		if (node_type == abnode_type::mlist)
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		else if (node_type == abnode_type::user)
			gx_strlcpy(dn, znul(ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS)), sizeof(dn));
		else
			return ecNotFound;
		if (*dn == '\0')
			return ecNotFound;
		auto alias_list = ab_tree_get_object_aliases(pnode);
		pprop->value.string_array.count = 1 + alias_list.size();
		pprop->value.string_array.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT, pprop->value.string_array.count);
		if (pprop->value.string_array.ppstr == nullptr)
			return ecServerOOM;
		pprop->value.string_array.ppstr[0] = ndr_stack_anew<char>(NDR_STACK_OUT, strlen(dn) + 6);
		if (pprop->value.string_array.ppstr[0] == nullptr)
			return ecServerOOM;
		sprintf(pprop->value.string_array.ppstr[0], "SMTP:%s", dn);
		size_t i = 1;
		for (const auto &a : alias_list) {
			pprop->value.string_array.ppstr[i] = ndr_stack_anew<char>(NDR_STACK_OUT, a.size() + 6);
			if (pprop->value.string_array.ppstr[i] == nullptr)
				return ecServerOOM;
			strcpy(pprop->value.string_array.ppstr[i], "smtp:");
			strcat(pprop->value.string_array.ppstr[i++], a.c_str());
		}
		return ecSuccess;
	}
	case PR_EMS_AB_NETWORK_ADDRESS:
	case PR_EMS_AB_NETWORK_ADDRESS_A: {
		auto rpc_info = get_rpc_info();
		temp_len = strlen(rpc_info.ep_host);
		pprop->value.string_array.count = 2;
		if (NULL == pbuff) {
			pprop->value.string_array.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT, 2);
			if (pprop->value.string_array.ppstr == nullptr)
				return ecServerOOM;
			pprop->value.string_array.ppstr[0] = ndr_stack_anew<char>(NDR_STACK_OUT, temp_len + 14);
			if (pprop->value.string_array.ppstr[0] == nullptr)
				return ecServerOOM;
			pprop->value.string_array.ppstr[1] = ndr_stack_anew<char>(NDR_STACK_OUT, temp_len + 12);
			if (pprop->value.string_array.ppstr[1] == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.string_array.ppstr = static_cast<char **>(pbuff);
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
	}
	case PR_EMS_AB_THUMBNAIL_PHOTO: {
		auto path = ab_tree_get_user_info(pnode, USER_STORE_PATH);
		if (path == nullptr)
			return ecNotFound;
		auto bv = nsp_photo_rpc(dn);
		if (bv != nullptr) {
			pprop->value.bin = *bv;
			return ecSuccess;
		}
		/* Old access for monohost installations */
		gx_strlcpy(dn, path, sizeof(dn));
		HX_strlcat(dn, "/config/portrait.jpg", std::size(dn));
		if (!common_util_load_file(dn, &pprop->value.bin))
			return ecNotFound;
		return ecSuccess;
	}
	}
	/* User-defined props */
	if (node_type == abnode_type::user || node_type == abnode_type::mlist) {
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
	case PR_SEND_RICH_INFO:
		pprop->value.b = 1;
		return ecSuccess;
	}
	return ecNotFound;
}		

static uint32_t nsp_interface_fetch_row(const SIMPLE_TREE_NODE *pnode,
    BOOL b_ephid, cpid_t codepage, const LPROPTAG_ARRAY *pproptags,
    NSP_PROPROW *prow)
{
	uint32_t err_val;
	PROPERTY_VALUE *pprop;
	
	auto node_type = ab_tree_get_node_type(pnode);
	if (node_type >= abnode_type::containers)
		return ecInvalidObject;
	for (size_t i = 0; i < pproptags->cvalues; ++i) {
		pprop = common_util_propertyrow_enlarge(prow);
		if (pprop == nullptr)
			return ecServerOOM;
		err_val = nsp_interface_fetch_property(pnode, b_ephid, codepage,
		          pproptags->pproptag[i], pprop, nullptr, 0);
		if (err_val != ecSuccess) {
			pprop->proptag = CHANGE_PROP_TYPE(pprop->proptag, PT_ERROR);
			pprop->value.err = err_val != ecServerOOM ? err_val : ecMAPIOOM;
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
		mlog(LV_ERR, "nsp: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(get_domain_ids, "get_domain_ids");
	E(get_maildir, "get_maildir");
	E(get_id_from_username, "get_id_from_username");
	E(get_mlist_memb, "get_mlist_memb");
	return 0;
#undef E
}

int nsp_interface_bind(uint64_t hrpc, uint32_t flags, const STAT *pstat,
    FLATUID *pserver_guid, NSPI_HANDLE *phandle)
{
	nsp_trace(__func__, 0, pstat);
	auto rpc_info = get_rpc_info();
	if (flags & fAnonymousLogin) {
		memset(phandle, 0, sizeof(NSPI_HANDLE));
		return MAPI_E_FAILONEPROVIDER;
	}
	if (pstat->codepage == CP_WINUNICODE) {
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
	unsigned int domain_id = 0, org_id = 0;
	if (!get_domain_ids(pdomain, &domain_id, &org_id)) {
		mlog(LV_WARN, "W-2176: could not satisfy nsp_bind request for domain %s: not found", pdomain);
		phandle->handle_type = HANDLE_EXCHANGE_NSP;
		memset(&phandle->guid, 0, sizeof(GUID));
		return ecError;
	}
	phandle->handle_type = HANDLE_EXCHANGE_NSP;
	int base_id = org_id == 0 ? -domain_id : org_id;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr) {
		memset(&phandle->guid, 0, sizeof(GUID));
		return ecError;
	}
	if (g_nsp_trace >= 2)
		ab_tree_dump_base(*pbase);
	phandle->guid = pbase->guid;
	if (NULL != pserver_guid) {
		EXT_PUSH ep;
		ep.init(pserver_guid, sizeof(*pserver_guid), 0);
		if (ep.p_guid(common_util_get_server_guid()) != EXT_ERR_SUCCESS)
			return ecError;
	}
	nsp_trace(__func__, 1, pstat);
	return ecSuccess;
}

uint32_t nsp_interface_unbind(NSPI_HANDLE *phandle, uint32_t reserved)
{
	memset(phandle, 0, sizeof(NSPI_HANDLE));
	return MAPI_E_UNBINDSUCCESS;
}

static inline uint32_t
nsp_interface_minid_in_list(const gal_list_t *plist, size_t row)
{
	auto &list = *plist;
	return row < list.size() ? ab_tree_get_node_minid(list[row]) : 0;
}

static void nsp_interface_position_in_list(const STAT *pstat,
    const gal_list_t *plist, uint32_t *pout_row, uint32_t *pcount)
{
	auto &list = *plist;
	uint32_t row;

	*pcount = std::min(list.size(), static_cast<size_t>(UINT32_MAX));
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		row = *pcount * static_cast<double>(pstat->num_pos) / pstat->total_rec;
		if (row > 0 && row >= *pcount)
			row = *pcount - 1; /* v13 pg72 §3.1.4.5.2 point 5 */
	} else if (pstat->cur_rec == MID_BEGINNING_OF_TABLE) {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		row = 0;
	} else if (pstat->cur_rec == MID_END_OF_TABLE) {
		row = *pcount;
	} else {
		auto it = std::find_if(list.cbegin(), list.cend(),
		          [&pstat](SIMPLE_TREE_NODE *ptr) {
		          	auto minid = ab_tree_get_node_minid(ptr);
		          	return minid != 0 && minid == pstat->cur_rec;
		          });
		/*
		 * When not found, the position is undefined.
		 * To avoid problems we will use first row.
		 */
		row = it != list.cend() ? it - list.cbegin() : 0;
	}
	*pout_row = row;
}

static void nsp_interface_position_in_table(const STAT *pstat,
    const SIMPLE_TREE_NODE *pnode, uint32_t *pout_row, uint32_t *pcount)
{
	BOOL b_found;
	uint32_t row;
	uint32_t minid;

	*pcount = ab_tree_get_leaves_num(pnode);
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		row = std::min(*pcount, static_cast<uint32_t>(*pcount *
		      static_cast<double>(pstat->num_pos) / pstat->total_rec));
	} else if (pstat->cur_rec == MID_BEGINNING_OF_TABLE) {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		row = 0;
	} else if (pstat->cur_rec == MID_END_OF_TABLE) {
		row = *pcount;
	} else {
		b_found = FALSE;
		row = 0;
		pnode = pnode->get_child();
		if (pnode != nullptr) do {
			if (ab_tree_get_node_type(pnode) >= abnode_type::containers ||
			    (ab_tree_hidden(pnode) & AB_HIDE_FROM_AL))
				continue;
			minid = ab_tree_get_node_minid(pnode);
			if (0 != minid && minid == pstat->cur_rec) {
				b_found = TRUE;
				break;
			}
			row++;
		} while ((pnode = pnode->get_sibling()) != nullptr);
		if (!b_found)
			/* In this case the position is undefined.
			   To avoid problems we will use first row */
			row = 0;
	}
	*pout_row = row;
}

static uint32_t nsp_interface_minid_in_table(const SIMPLE_TREE_NODE *pnode,
    uint32_t row)
{
	pnode = pnode->get_child();
	if (pnode == nullptr)
		return 0;
	size_t count = 0;
	do {
		if (count == row)
			return ab_tree_get_node_minid(pnode);
		if (ab_tree_get_node_type(pnode) < abnode_type::containers)
			count ++;
	} while ((pnode = pnode->get_sibling()) != nullptr);
	return 0;
}

int nsp_interface_update_stat(NSPI_HANDLE handle,
	uint32_t reserved, STAT *pstat, int32_t *pdelta)
{
	nsp_trace(__func__, 0, pstat, pdelta);
	int base_id;
	const SIMPLE_TREE_NODE *pnode = nullptr;
	
	if (pstat == nullptr || pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	uint32_t init_row = 0, total = 0;
	if (0 == pstat->container_id) {
		nsp_interface_position_in_list(pstat,
			&pbase->gal_list, &init_row, &total);
	} else {
		pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		nsp_interface_position_in_table(pstat, pnode, &init_row, &total);
	}
	uint32_t row = init_row;
	if (pstat->delta < 0 && static_cast<unsigned int>(-pstat->delta) >= row)
		row = 0;
	else
		row += pstat->delta;
	if (row >= total) {
		row = total;
		pstat->cur_rec = MID_END_OF_TABLE;
	} else {
		pstat->cur_rec = pstat->container_id == 0 ?
		                 nsp_interface_minid_in_list(&pbase->gal_list, row) :
		                 nsp_interface_minid_in_table(pnode, row);
		if (0 == pstat->cur_rec) {
			row = total;
			pstat->cur_rec = MID_END_OF_TABLE;
		}
	}
	if (pdelta != nullptr)
		*pdelta = row - init_row;
	pstat->delta = 0;
	pstat->num_pos = row;
	pstat->total_rec = total;
	nsp_trace(__func__, 1, pstat, pdelta);
	return ecSuccess;
}

static void nsp_interface_make_ptyperror_row(const LPROPTAG_ARRAY *pproptags,
    NSP_PROPROW *prow)
{
	prow->reserved = 0x0;
	prow->cvalues = pproptags->cvalues;
	prow->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, prow->cvalues);
	if (prow->pprops == nullptr)
		return;
	for (size_t i = 0; i < prow->cvalues; ++i) {
		prow->pprops[i].proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_ERROR);
		prow->pprops[i].reserved = 0x0;
		prow->pprops[i].value.err = 0;
	}
}

int nsp_interface_query_rows(NSPI_HANDLE handle, uint32_t flags, STAT *pstat,
    uint32_t table_count, uint32_t *ptable, uint32_t count,
    const LPROPTAG_ARRAY *pproptags, NSP_ROWSET **pprows)
{
	/*
	 * OXNSPI says "implementations SHOULD return as many rows as possible
	 * to improve usability of the server for clients", but then, if you
	 * return more than @count entries, Outlook 2019/2021 crashes.
	 */
	*pprows = nullptr;
	if (g_nsp_trace > 0)
		fprintf(stderr, "nsp_query_rows: table_count=%u count=%u\n", table_count, count);
	nsp_trace(__func__, 0, pstat);
	int base_id;
	uint32_t result;
	uint32_t start_pos, total;
	NSP_PROPROW *prow;
	BOOL b_ephid = (flags & fEphID) ? TRUE : false;
	
	if (pstat == nullptr || pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	if (count == 0 && ptable == nullptr)
		return ecInvalidParam;
	/* MS-OXNSPI 3.1.4.1.8.10 */
	if (count == 0)
		count = 1;
	
	if (NULL == pproptags) {
		auto nt = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (nt == nullptr)
			return ecServerOOM;
		/* OXNSPI v13.1 §3.1.4.1.8 bp 6.2 / NSPI v15 §3.1.4.8 bp 6.2 */
		pproptags = nt;
		nt->cvalues = 7;
		nt->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, nt->cvalues);
		if (nt->pproptag == nullptr)
			return ecServerOOM;
		nt->pproptag[0] = PR_EMS_AB_CONTAINERID;
		nt->pproptag[1] = PR_OBJECT_TYPE;
		nt->pproptag[2] = PR_DISPLAY_TYPE;
		nt->pproptag[3] = PR_DISPLAY_NAME_A;
		nt->pproptag[4] = PR_PRIMARY_TELEPHONE_NUMBER_A;
		nt->pproptag[5] = PR_DEPARTMENT_NAME_A;
		nt->pproptag[6] = PR_OFFICE_LOCATION_A;
	} else if (pproptags->cvalues > 100) {
		return ecTableTooBig;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto rowset = common_util_proprowset_init();
	if (rowset == nullptr)
		return ecServerOOM;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	
	if (ptable != nullptr) {
		for (size_t i = 0; i < table_count; ++i) {
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			auto pnode = ab_tree_minid_to_node(pbase.get(), ptable[i]);
			if (NULL == pnode) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
				continue;
			}
			result = nsp_interface_fetch_row(pnode,
				b_ephid, pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				nsp_interface_make_ptyperror_row(pproptags, prow);
		}
		nsp_trace(__func__, 1, pstat, nullptr, rowset);
		*pprows = rowset;
		return ecSuccess;
	}

	const SIMPLE_TREE_NODE *pnode = nullptr, *pnode1 = nullptr;
	if (0 == pstat->container_id) {
		nsp_interface_position_in_list(pstat,
			&pbase->gal_list, &start_pos, &total);
	} else {
		pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		nsp_interface_position_in_table(pstat,
			pnode, &start_pos, &total);
		pnode1 = pnode->get_child();
		if (NULL == pnode1) {
			nsp_trace(__func__, 1, pstat, nullptr, rowset);
			*pprows = rowset;
			return ecSuccess;
		}
	}
	if (total == 0) {
		nsp_trace(__func__, 1, pstat, nullptr, rowset);
		*pprows = rowset;
		return ecSuccess;
	}
	if (pstat->delta >= 0) {
		start_pos += pstat->delta;
		if (start_pos >= total)
			start_pos = total;
	} else if (static_cast<unsigned int>(-pstat->delta) > pstat->num_pos) {
		start_pos = 0;
	} else {
		start_pos += pstat->delta;
	}

	auto tmp_count = total - start_pos;
	if (count < tmp_count)
		tmp_count = count;
	if (tmp_count == 0) {
		nsp_trace(__func__, 1, pstat, nullptr, rowset);
		*pprows = rowset;
		return ecSuccess;
	}
	size_t i = 0;
	if (0 == pstat->container_id) {
		for (i = start_pos; i < pbase->gal_list.size() &&
		     i < start_pos + tmp_count; ++i) {
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			result = nsp_interface_fetch_row(pbase->gal_list[i],
				 b_ephid, pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
		}
	} else {
		do {
			if (ab_tree_get_node_type(pnode1) >= abnode_type::containers ||
			    (ab_tree_hidden(pnode1) & AB_HIDE_FROM_AL))
				continue;
			if (i >= start_pos + tmp_count)
				break;
			if (i < start_pos) {
				++i;
				continue;
			}
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			result = nsp_interface_fetch_row(pnode1,
				 b_ephid, pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
			i++;
		} while ((pnode1 = pnode1->get_sibling()) != nullptr);
	}

	if (start_pos + tmp_count >= total) {
		pstat->cur_rec = MID_END_OF_TABLE;
	} else {
		pstat->cur_rec = pstat->container_id == 0 ?
		                 nsp_interface_minid_in_list(&pbase->gal_list, start_pos + tmp_count) :
		                 nsp_interface_minid_in_table(pnode, start_pos + tmp_count);
		if (0 == pstat->cur_rec) {
			pstat->cur_rec = MID_END_OF_TABLE;
			start_pos = total;
			tmp_count = 0;
		}
	}
	pstat->delta = 0;
	pstat->num_pos = start_pos + tmp_count;
	pstat->total_rec = total;
#if 0
	if (rowset->crows == 0) {
		auto prow = common_util_proprowset_enlarge(rowset);
		if (prow == nullptr ||
		    common_util_propertyrow_init(prow) == nullptr)
			return ecServerOOM;
		nsp_interface_make_ptyperror_row(pproptags, prow);
	}
#endif
	nsp_trace(__func__, 1, pstat, nullptr, rowset);
	*pprows = rowset;
	return ecSuccess;
}

int nsp_interface_seek_entries(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, PROPERTY_VALUE *ptarget, const MID_ARRAY *ptable,
    const LPROPTAG_ARRAY *pproptags, NSP_ROWSET **pprows)
{
	int base_id;
	uint32_t result;
	NSP_PROPROW *prow;
	uint32_t tmp_minid;
	char temp_name[1024];
	
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	if (pstat == nullptr || pstat->codepage == CP_WINUNICODE ||
	    reserved != 0)
		return ecNotSupported;
	if (pstat->sort_type == SortTypeDisplayName) {
		if (ptarget->proptag != PR_DISPLAY_NAME &&
		    ptarget->proptag != PR_DISPLAY_NAME_A)
			return ecError;
	} else if (pstat->sort_type == SortTypePhoneticDisplayName) {
		if (ptarget->proptag != PR_EMS_AB_PHONETIC_DISPLAY_NAME &&
		    ptarget->proptag != PR_EMS_AB_PHONETIC_DISPLAY_NAME_A)
			return ecError;
	} else {
		return ecError;
	}
	if (NULL == pproptags) {
		auto nt = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (nt == nullptr)
			return ecServerOOM;
		pproptags = nt;
		nt->cvalues = 7;
		nt->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, nt->cvalues);
		if (nt->pproptag == nullptr)
			return ecServerOOM;
		nt->pproptag[0] = PR_EMS_AB_CONTAINERID;
		nt->pproptag[1] = PR_OBJECT_TYPE;
		nt->pproptag[2] = PR_DISPLAY_TYPE;
		nt->pproptag[3] = PR_DISPLAY_NAME_A;
		nt->pproptag[4] = PR_PRIMARY_TELEPHONE_NUMBER_A;
		nt->pproptag[5] = PR_DEPARTMENT_NAME_A;
		nt->pproptag[6] = PR_OFFICE_LOCATION_A;
	} else if (pproptags->cvalues > 100) {
		return ecTableTooBig;
	}
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto rowset = common_util_proprowset_init();
	if (rowset == nullptr)
		return ecServerOOM;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	
	if (NULL != ptable) {
		size_t row = 0;
		tmp_minid = 0;
		for (size_t i = 0; i < ptable->cvalues; ++i) {
			auto pnode1 = ab_tree_minid_to_node(pbase.get(), ptable->pproptag[i]);
			if (pnode1 == nullptr)
				continue;
			ab_tree_get_display_name(pnode1, pstat->codepage, temp_name, std::size(temp_name));
			if (strcasecmp(temp_name, ptarget->value.pstr) < 0)
				continue;
			if (0 == tmp_minid) {
				tmp_minid = ptable->pproptag[i];
				row = i;
			}
			if (tmp_minid == 0)
				continue;
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			result = nsp_interface_fetch_row(pnode1, TRUE,
			         pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				nsp_interface_make_ptyperror_row(pproptags, prow);
		}
		if (tmp_minid == 0)
			return ecNotFound;
		pstat->total_rec = rowset->crows;
		pstat->cur_rec = tmp_minid;
		pstat->num_pos = row;
		nsp_trace(__func__, 1, pstat, nullptr, rowset);
		*pprows = rowset;
		return ecSuccess;
	}

	const SIMPLE_TREE_NODE *pnode = nullptr;
	uint32_t start_pos = 0, total = 0;
	if (0 == pstat->container_id) {
		nsp_interface_position_in_list(pstat,
			&pbase->gal_list, &start_pos, &total);
	} else {
		pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		nsp_interface_position_in_table(pstat,
			pnode, &start_pos, &total);
		auto pnode1 = pnode->get_child();
		if (pnode1 == nullptr)
			return ecNotFound;
	}
	if (total == 0)
		return ecNotFound;

	size_t row = 0;
	start_pos = 0;
	if (0 == pstat->container_id) {
		for (row = start_pos; row < pbase->gal_list.size(); ++row) {
			auto ptr = pbase->gal_list[row];
			ab_tree_get_display_name(ptr,
				pstat->codepage, temp_name, std::size(temp_name));
			if (strcasecmp(temp_name, ptarget->value.pstr) < 0)
				continue;
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			if (nsp_interface_fetch_row(ptr,
			    TRUE, pstat->codepage, pproptags,
			    prow) != ecSuccess)
				return ecError;
			break;
		}
		if (row == pbase->gal_list.size())
			return ecNotFound;
		pstat->cur_rec = ab_tree_get_node_minid(pbase->gal_list[row]);
	} else {
		auto pnode1 = pnode->get_child();
		do {
			if (ab_tree_get_node_type(pnode1) >= abnode_type::containers)
				continue;
			if (row < start_pos) {
				row++;
				continue;
			}
			ab_tree_get_display_name(pnode1, pstat->codepage,
				temp_name, std::size(temp_name));
			if (strcasecmp(temp_name, ptarget->value.pstr) < 0) {
				++row;
				continue;
			}
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			if (nsp_interface_fetch_row(pnode1,
			    TRUE, pstat->codepage, pproptags,
			    prow) != ecSuccess)
				return ecError;
			break;
		} while ((pnode1 = pnode1->get_sibling()) != nullptr);
		if (pnode1 == nullptr)
			return ecNotFound;
		pstat->cur_rec = ab_tree_get_node_minid(pnode1);
	}
	pstat->num_pos = row;
	pstat->total_rec = total;
	*pprows = rowset;
	nsp_trace(__func__, 1, pstat, nullptr, *pprows);
	return ecSuccess;
}

static BOOL nsp_interface_match_node(const SIMPLE_TREE_NODE *pnode,
    cpid_t codepage, const NSPRES *pfilter)
{
	char *ptoken;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	
	switch (pfilter->res_type) {
	case RES_AND:
		for (size_t i = 0; i < pfilter->res.res_andor.cres; ++i)
			if (!nsp_interface_match_node(pnode,
			    codepage, &pfilter->res.res_andor.pres[i]))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (size_t i = 0; i < pfilter->res.res_andor.cres; ++i)
			if (nsp_interface_match_node(pnode,
			    codepage, &pfilter->res.res_andor.pres[i]))
				return TRUE;
		return FALSE;
	case RES_NOT:
		return !nsp_interface_match_node(pnode, codepage,
		       pfilter->res.res_not.pres) ? TRUE : false;
	case RES_CONTENT:
		return FALSE;
	case RES_PROPERTY:
		if (pfilter->res.res_property.pprop == nullptr)
			return TRUE;
		// XXX RESTRICTION_PROPERTY::comparable check
		if (pfilter->res.res_property.proptag == PR_ANR) {
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PR_ACCOUNT, &prop_val, temp_buff,
			    std::size(temp_buff)) == ecSuccess &&
			    strcasestr(temp_buff, pfilter->res.res_property.pprop->value.pstr) != nullptr)
				return TRUE;
			ptoken = strchr(pfilter->res.res_property.pprop->value.pstr, ':');
			if (NULL != ptoken) {
				/* =SMTP:user@company.com */
				if (strcasestr(temp_buff, &ptoken[1]) != nullptr)
					return TRUE;
			} else if (strcasecmp(temp_buff, pfilter->res.res_property.pprop->value.pstr) == 0) {
				return TRUE;
			}
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PR_DISPLAY_NAME, &prop_val, temp_buff,
			    std::size(temp_buff)) == ecSuccess &&
			    strcasestr(temp_buff, pfilter->res.res_property.pprop->value.pstr) != nullptr)
				return TRUE;
			return FALSE;
		} else if (pfilter->res.res_property.proptag == PR_ANR_A) {
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PR_ACCOUNT_A, &prop_val, temp_buff,
			    std::size(temp_buff)) == ecSuccess &&
			    strcasestr(temp_buff, pfilter->res.res_property.pprop->value.pstr) != nullptr)
				return TRUE;
			/* =SMTP:user@company.com */
			ptoken = strchr(pfilter->res.res_property.pprop->value.pstr, ':');
			if (NULL != ptoken) {
				if (strcasestr(temp_buff, &ptoken[1]) != nullptr)
					return TRUE;
			} else if (strcasecmp(temp_buff, pfilter->res.res_property.pprop->value.pstr) == 0) {
				return TRUE;
			}
			if (nsp_interface_fetch_property(pnode, false, codepage,
			    PR_DISPLAY_NAME_A, &prop_val, temp_buff,
			    std::size(temp_buff)) == ecSuccess &&
			    strcasestr(temp_buff, pfilter->res.res_property.pprop->value.pstr) != nullptr)
				return TRUE;
			return FALSE;
		}
		if (nsp_interface_fetch_property(pnode, false, codepage,
		    pfilter->res.res_property.proptag, &prop_val,
		    temp_buff, std::size(temp_buff)) != ecSuccess)
			return FALSE;
		// XXX: convert to RESTRICTION_PROPERTY::eval
		int cmp;
		switch (PROP_TYPE(pfilter->res.res_property.proptag)) {
		case PT_SHORT:
			cmp = three_way_compare(prop_val.value.s, pfilter->res.res_property.pprop->value.s);
			break;
		case PT_LONG:
			cmp = three_way_compare(prop_val.value.l, pfilter->res.res_property.pprop->value.l);
			break;
		case PT_BOOLEAN:
			cmp = three_way_compare(prop_val.value.b, pfilter->res.res_property.pprop->value.b);
			break;
		case PT_STRING8:
		case PT_UNICODE:
			cmp = strcasecmp(prop_val.value.pstr, pfilter->res.res_property.pprop->value.pstr);
			break;
		default:
			mlog(LV_ERR, "E-1967: unhandled proptag %xh", pfilter->res.res_property.proptag);
			return false;
		}
		return three_way_eval(pfilter->res.res_property.relop, cmp) ? TRUE : false;
	case RES_PROPCOMPARE:
		return FALSE;
	case RES_BITMASK:
		return FALSE;
	case RES_SIZE:
		return FALSE;
	case RES_EXIST: {
		auto node_type = ab_tree_get_node_type(pnode);
		if (node_type >= abnode_type::containers)
			return FALSE;
		if (nsp_interface_fetch_property(pnode, false, codepage,
		    pfilter->res.res_exist.proptag, &prop_val, temp_buff,
		    std::size(temp_buff)) != ecSuccess)
			return FALSE;
		return TRUE;
	}
	case RES_SUBRESTRICTION:
	default:
		return FALSE;
	}	
	return false;
}

static std::unordered_set<std::string> delegates_for(const char *dir) try
{
	std::vector<std::string> dl;
	auto path = dir + "/config/delegates.txt"s;
	auto ret = read_file_by_line(path.c_str(), dl);
	if (ret != 0 && ret != ENOENT)
		mlog(LV_ERR, "E-2054: %s: %s", path.c_str(), strerror(ret));
	return std::unordered_set<std::string>{std::make_move_iterator(dl.begin()), std::make_move_iterator(dl.end())};
} catch (const std::bad_alloc &) {
	return {};
}

int nsp_interface_get_matches(NSPI_HANDLE handle, uint32_t reserved1,
    STAT *pstat, const MID_ARRAY *preserved, uint32_t reserved2,
    const NSPRES *pfilter, const NSP_PROPNAME *ppropname,
    uint32_t requested, MID_ARRAY **ppoutmids, const LPROPTAG_ARRAY *pproptags,
    NSP_ROWSET **pprows)
{
	*ppoutmids = nullptr;
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	PROPERTY_VALUE prop_val;
	
	if (pstat == nullptr || pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	if (pstat->sort_type != SortTypeDisplayName &&
	    pstat->sort_type != SortTypePhoneticDisplayName &&
	    pstat->sort_type != SortTypeDisplayName_RO &&
	    pstat->sort_type != SortTypeDisplayName_W)
		return ecNotSupported;
	if (reserved1 != 0 || ppropname != nullptr)
		return ecNotSupported;
	auto base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto outmids = common_util_proptagarray_init();
	if (outmids == nullptr) {
		return ecServerOOM;
	}
	NSP_ROWSET *rowset = nullptr;
	if (pproptags != nullptr) {
		if (pproptags->cvalues > 100)
			return ecTableTooBig;
		rowset = common_util_proprowset_init();
		if (rowset == nullptr)
			return ecServerOOM;
	}
	
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;

	uint32_t result;
	if (pstat->container_id == PR_EMS_AB_MEMBER) {
		auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->cur_rec);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		auto mlistaddr = ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS);
		if (mlistaddr == nullptr)
			return ecNotFound;
		std::vector<std::string> member_list;
		int ret = 0;
		if (!get_mlist_memb(mlistaddr, mlistaddr, &ret, member_list))
			return ecError;
		for (const auto &memb : member_list) {
			if (outmids->cvalues > requested)
				break;
			unsigned int user_id = 0;
			if (!get_id_from_username(memb.c_str(), &user_id))
				continue;
			pnode = ab_tree_uid_to_node(pbase.get(), user_id);
			if (pnode == nullptr ||
			    ab_tree_hidden(pnode) & AB_HIDE_FROM_AL)
				continue;
			if (pfilter != nullptr &&
			    !nsp_interface_match_node(pnode, pstat->codepage, pfilter))
				continue;	
			auto pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			*pproptag = ab_tree_get_node_minid(pnode);
		}
		goto FETCH_ROWS;
	} else if (pstat->container_id == PR_EMS_AB_PUBLIC_DELEGATES) {
		auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->cur_rec);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		char maildir[256];
		auto temp_buff = ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS);
		if (temp_buff == nullptr ||
		    !get_maildir(temp_buff, maildir, std::size(maildir)))
			return ecError;
		auto delegate_list = delegates_for(maildir);
		for (const auto &deleg : delegate_list) {
			if (outmids->cvalues > requested)
				break;
			unsigned int user_id = 0;
			if (!get_id_from_username(deleg.c_str(), &user_id))
				continue;
			pnode = ab_tree_uid_to_node(pbase.get(), user_id);
			if (pnode == nullptr ||
			    ab_tree_hidden(pnode) & AB_HIDE_DELEGATE)
				continue;
			if (pfilter != nullptr &&
			    !nsp_interface_match_node(pnode, pstat->codepage, pfilter))
				continue;	
			auto pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			*pproptag = ab_tree_get_node_minid(pnode);
		}
		goto FETCH_ROWS;
	}
	if (pfilter == nullptr) {
		char temp_buff[1024];
		auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->cur_rec);
		if (pnode != nullptr && nsp_interface_fetch_property(pnode,
		    TRUE, pstat->codepage, pstat->container_id, &prop_val,
		    temp_buff, std::size(temp_buff)) == ecSuccess) {
			auto pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			*pproptag = ab_tree_get_node_minid(pnode);
		}
	} else if (pstat->container_id == 0) {
		uint32_t start_pos, total;
		nsp_interface_position_in_list(pstat,
			&pbase->gal_list, &start_pos, &total);
		for (size_t i = start_pos; i < total &&
		     outmids->cvalues <= requested &&
		     i < pbase->gal_list.size(); ++i) {
			auto ptr = pbase->gal_list[i];
			if (nsp_interface_match_node(ptr, pstat->codepage, pfilter)) {
				auto pproptag = common_util_proptagarray_enlarge(outmids);
				if (pproptag == nullptr)
					return ecServerOOM;
				*pproptag = ab_tree_get_node_minid(ptr);
			}
		}
	} else {
		auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		uint32_t start_pos, total;
		nsp_interface_position_in_table(pstat,
			pnode, &start_pos, &total);
		pnode = pnode->get_child();
		if (NULL == pnode) {
			pstat->container_id = pstat->cur_rec; /* MS-OXNSPI 3.1.4.1.10.16 */
			*ppoutmids = outmids;
			*pprows = rowset;
			nsp_trace(__func__, 1, pstat, nullptr, rowset);
			return ecSuccess;
		}
		size_t i = 0;
		do {
			if (ab_tree_hidden(pnode) & AB_HIDE_FROM_AL)
				continue;
			if (i >= total || outmids->cvalues > requested) {
				break;
			} else if (i < start_pos) {
				i++;
				continue;
			}
			if (nsp_interface_match_node(pnode,
			    pstat->codepage, pfilter)) {
				auto pproptag = common_util_proptagarray_enlarge(outmids);
				if (pproptag == nullptr)
					return ecServerOOM;
				*pproptag = ab_tree_get_node_minid(pnode);
			}
			i++;
		} while ((pnode = pnode->get_sibling()) != nullptr);
	}

 FETCH_ROWS:
	if (rowset != nullptr) {
		for (size_t i = 0; i < outmids->cvalues; ++i) {
			auto prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			auto pnode = ab_tree_minid_to_node(pbase.get(), outmids->pproptag[i]);
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
	
	pstat->container_id = pstat->cur_rec; /* MS-OXNSPI §3.1.4.1.10 bp 16 */
	nsp_trace(__func__, 1, pstat, nullptr, rowset);
	*ppoutmids = outmids;
	*pprows = rowset;
	return ecSuccess;
}

static int nsp_interface_cmpstring(const void *p1, const void *p2)
{
	return strcasecmp(static_cast<const nsp_sort_item *>(p1)->string,
	       static_cast<const nsp_sort_item *>(p2)->string);
}

int nsp_interface_resort_restriction(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, const MID_ARRAY *pinmids, MID_ARRAY **ppoutmids)
{
	*ppoutmids = nullptr;
	nsp_trace(__func__, 0, pstat);
	int base_id;
	BOOL b_found;
	char temp_buff[1024];
	
	if (pstat == nullptr || pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	auto parray = ndr_stack_anew<nsp_sort_item>(NDR_STACK_IN, pinmids->cvalues);
	if (parray == nullptr)
		return ecServerOOM;
	auto outmids = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (outmids == nullptr)
		return ecServerOOM;
	outmids->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pinmids->cvalues);
	if (outmids->pproptag == nullptr)
		return ecServerOOM;
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	size_t count = 0;
	b_found = FALSE;
	for (size_t i = 0; i < pinmids->cvalues; ++i) {
		auto pnode = ab_tree_minid_to_node(pbase.get(), pinmids->pproptag[i]);
		if (pnode == nullptr)
			continue;
		parray[count].minid = pinmids->pproptag[i];
		if (pstat->cur_rec == pinmids->pproptag[i])
			b_found = TRUE;
		ab_tree_get_display_name(pnode, pstat->codepage, temp_buff, std::size(temp_buff));
		parray[count].strv = ndr_stack_alloc(
			NDR_STACK_IN, strlen(temp_buff) + 1);
		if (parray[count].string == nullptr)
			return ecServerOOM;
		strcpy(parray[count++].string, temp_buff);
	}
	qsort(parray, count, sizeof(nsp_sort_item), nsp_interface_cmpstring);
	outmids->cvalues = count;
	for (size_t i = 0; i < count; ++i)
		outmids->pproptag[i] = parray[i].minid;
	pstat->total_rec = count;
	if (!b_found) {
		/* OXNSPI v13 pg 52 p 8 */
		pstat->cur_rec = MID_BEGINNING_OF_TABLE;
		pstat->num_pos = 0;
	}
	nsp_trace(__func__, 1, pstat);
	*ppoutmids = outmids;
	return ecSuccess;
}

int nsp_interface_dntomid(NSPI_HANDLE handle, uint32_t reserved,
    const STRINGS_ARRAY *pnames, MID_ARRAY **ppoutmids)
{
	int base_id;
	
	*ppoutmids = nullptr;
	if (pnames == nullptr)
		return ecSuccess;
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto outmids = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (outmids == nullptr)
		return ecServerOOM;
	outmids->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pnames->count);
	if (outmids->pproptag == nullptr)
		return ecServerOOM;
	outmids->cvalues = pnames->count;
	memset(outmids->pproptag, 0, sizeof(uint32_t) * pnames->count);
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	for (size_t i = 0; i < pnames->count; ++i) {
		if (pnames->ppstr[i] == nullptr)
			continue;
		auto ptnode = ab_tree_dn_to_node(pbase.get(), pnames->ppstr[i]);
		if (ptnode != nullptr)
			outmids->pproptag[i] = ab_tree_get_node_minid(ptnode);
	}
	*ppoutmids = outmids;
	return ecSuccess;
}

static constexpr size_t DFL_TAGS_MAX = 32;

static int nsp_fill_dfl_tags(abnode_type node_type, bool b_unicode,
    uint32_t *t, unsigned int &z)
{
#define U(x) (b_unicode ? (x) : CHANGE_PROP_TYPE((x), PT_STRING8))
	/* 16 props */
	t[z++] = U(PR_DISPLAY_NAME);
	t[z++] = U(PR_ADDRTYPE);
	t[z++] = U(PR_EMAIL_ADDRESS);
	t[z++] = U(PR_EMS_AB_DISPLAY_NAME_PRINTABLE);
	t[z++] = PR_OBJECT_TYPE;
	t[z++] = PR_DISPLAY_TYPE;
	t[z++] = PR_DISPLAY_TYPE_EX;
	t[z++] = PR_ENTRYID;
	t[z++] = PR_RECORD_KEY;
	t[z++] = PR_ORIGINAL_ENTRYID;
	t[z++] = PR_SEARCH_KEY;
	t[z++] = PR_INSTANCE_KEY;
	t[z++] = PR_MAPPING_SIGNATURE;
	t[z++] = PR_SEND_RICH_INFO;
	t[z++] = PR_TEMPLATEID;
	t[z++] = PR_EMS_AB_OBJECT_GUID;
	switch (node_type) {
	case abnode_type::domain:
	case abnode_type::group:
	case abnode_type::abclass:
		return ecInvalidObject;
	case abnode_type::user:
		/* Up to 16 */
		t[z++] = U(PR_NICKNAME);
		t[z++] = U(PR_TITLE);
		t[z++] = U(PR_PRIMARY_TELEPHONE_NUMBER);
		t[z++] = U(PR_MOBILE_TELEPHONE_NUMBER);
		t[z++] = U(PR_HOME_ADDRESS_STREET);
		t[z++] = U(PR_COMMENT);
		t[z++] = U(PR_COMPANY_NAME);
		t[z++] = U(PR_DEPARTMENT_NAME);
		t[z++] = U(PR_OFFICE_LOCATION);
		t[z++] = U(PR_SMTP_ADDRESS);
		t[z++] = U(PR_ACCOUNT);
		t[z++] = U(PR_TRANSMITABLE_DISPLAY_NAME);
		t[z++] = U(PR_EMS_AB_PROXY_ADDRESSES);
		t[z++] = U(PR_EMS_AB_HOME_MDB);
		t[z++] = PR_CREATION_TIME;
		t[z++] = PR_EMS_AB_THUMBNAIL_PHOTO;
		break;
	case abnode_type::mlist:
		t[z++] = U(PR_SMTP_ADDRESS);
		t[z++] = U(PR_COMPANY_NAME);
		t[z++] = U(PR_DEPARTMENT_NAME);
		t[z++] = U(PR_EMS_AB_PROXY_ADDRESSES);
		t[z++] = PR_CREATION_TIME;
		t[z++] = PR_EMS_AB_THUMBNAIL_PHOTO;
		break;
	case abnode_type::folder:
		t[z++] = PR_COMPANY_NAME_A;
		t[z++] = PR_DEPARTMENT_NAME_A;
		break;
	default:
		return ecInvalidObject;
	}
	return ecSuccess;
#undef U
}

static int nsp_interface_get_default_proptags(abnode_type node_type,
	BOOL b_unicode, LPROPTAG_ARRAY *pproptags)
{
	pproptags->cvalues  = 0;
	pproptags->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, DFL_TAGS_MAX);
	if (pproptags->pproptag == nullptr)
		return ecServerOOM;
	auto ret = nsp_fill_dfl_tags(node_type, b_unicode,
	           pproptags->pproptag, pproptags->cvalues);
	assert(pproptags->cvalues <= DFL_TAGS_MAX);
	return ret;
}

int nsp_interface_get_proplist(NSPI_HANDLE handle, uint32_t flags,
    uint32_t mid, cpid_t codepage, LPROPTAG_ARRAY **tags)
{
	int base_id;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (0 == base_id || HANDLE_EXCHANGE_NSP != handle.handle_type) {
		*tags = nullptr;
		return ecError;
	}
	if (0 == mid) {
		*tags = nullptr;
		return ecInvalidObject;
	}
	BOOL b_unicode = codepage == CP_WINUNICODE ? TRUE : false;
	*tags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (*tags == nullptr)
		return ecServerOOM;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid)) {
		*tags = nullptr;
		return ecError;
	}
	auto pnode = ab_tree_minid_to_node(pbase.get(), mid);
	if (NULL == pnode) {
		*tags = nullptr;
		return ecInvalidObject;
	}

	/* Grab tags */
	auto type = ab_tree_get_node_type(pnode);
	uint32_t ntags = 0;
	std::vector<uint32_t> ctags(DFL_TAGS_MAX);
	auto ret = nsp_fill_dfl_tags(type, b_unicode, ctags.data(), ntags);
	assert(ntags <= DFL_TAGS_MAX);
	if (ret != ecSuccess)
		ntags = 0;
	ctags.resize(ntags);
	ab_tree_proplist(pnode, ctags);

	/* Trim tags that have no propval */
	std::sort(ctags.begin(), ctags.end());
	ctags.erase(std::unique(ctags.begin(), ctags.end()), ctags.end());
	ctags.erase(std::remove_if(ctags.begin(), ctags.end(), [&](uint32_t proptag) {
		return nsp_interface_fetch_property(pnode, false, codepage,
		       proptag, &prop_val, temp_buff,
		       std::size(temp_buff)) != ecSuccess;
	}), ctags.end());

	/* Copy out */
	(*tags)->cvalues = ctags.size();
	(*tags)->pproptag = ndr_stack_anew<uint32_t>(ctags.size());
	if ((*tags)->pproptag == nullptr) {
		*tags = nullptr;
		return ecServerOOM;
	}
	memcpy((*tags)->pproptag, ctags.data(), sizeof(uint32_t) * ctags.size());
	return ecSuccess;
}

int nsp_interface_get_props(NSPI_HANDLE handle, uint32_t flags,
    const STAT *pstat, const LPROPTAG_ARRAY *pproptags, NSP_PROPROW **pprows)
{
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	int base_id;
	uint32_t row;
	uint32_t total;
	BOOL b_proptags;
	uint32_t result;
	const SIMPLE_TREE_NODE *pnode1;
	
	if (pstat == nullptr)
		return ecNotSupported;
	BOOL b_ephid = (flags & fEphID) ? TRUE : false;
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	BOOL b_unicode = pstat->codepage == CP_WINUNICODE ? TRUE : false;
	if (b_unicode && pproptags != nullptr)
		for (size_t i = 0; i < pproptags->cvalues; ++i)
			if (PROP_TYPE(pproptags->pproptag[i]) == PT_STRING8)
				return ecNotSupported;
	
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	
	if (pstat->cur_rec <= 0x10) {
		if (0 == pstat->container_id) {
			gal_list_t::const_iterator it;
			if (MID_BEGINNING_OF_TABLE == pstat->cur_rec) {
				it = pbase->gal_list.cbegin();
			} else if (MID_END_OF_TABLE == pstat->cur_rec) {
				it = pbase->gal_list.cend();
			} else {
				nsp_interface_position_in_list(pstat,
					&pbase->gal_list, &row, &total);
				it = pbase->gal_list.cbegin() + row;
			}
			pnode1 = it == pbase->gal_list.cend() ? nullptr : *it;
		} else {
			auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
			if (pnode == nullptr)
				return ecInvalidBookmark;
			nsp_interface_position_in_table(pstat,
					pnode, &row, &total);
			pnode1 = pnode->get_child();
			if (NULL != pnode1) {
				size_t i = 0;
				do {
					if (ab_tree_get_node_type(pnode1) >= abnode_type::containers)
						continue;
					i ++;
					if (i == row)
						break;
				} while ((pnode1 = pnode1->get_sibling()) != nullptr);
			}
		}
	} else {
		pnode1 = ab_tree_minid_to_node(pbase.get(), pstat->cur_rec);
		if (pnode1 != nullptr && pstat->container_id != 0) {
			auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
			if (pnode == nullptr)
				return ecInvalidBookmark;
		}
	}
	b_proptags = TRUE;
	if (NULL == pproptags) {
		b_proptags = FALSE;
		auto nt = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (nt == nullptr)
			return ecServerOOM;
		pproptags = nt;
		result = nsp_interface_get_default_proptags(
			ab_tree_get_node_type(pnode1), b_unicode, nt);
		if (result != ecSuccess)
			return result;
	} else if (pproptags->cvalues > 100) {
		return ecTableTooBig;
	}
	auto rowset = common_util_propertyrow_init(NULL);
	if (rowset == nullptr)
		return ecServerOOM;
	/* MS-OXNSPI 3.1.4.1.7.11 */
	if (NULL == pnode1) {
		nsp_interface_make_ptyperror_row(pproptags, rowset);
		result = ecWarnWithErrors;
	} else {
		result = nsp_interface_fetch_row(pnode1, b_ephid,
		         pstat->codepage, pproptags, rowset);
	}
	if (result != ecSuccess) {
		if (result == ecWarnWithErrors)
			*pprows = rowset;
		NSP_ROWSET rs = {*pprows != nullptr ? 1U : 0U, *pprows};
		nsp_trace(__func__, 1, pstat, nullptr, &rs);
		return result;
	}
	if (!b_proptags) {
		size_t count = 0;
		for (size_t i = 0; i < rowset->cvalues; ++i) {
			if (PROP_TYPE(rowset->pprops[i].proptag) == PT_ERROR &&
			    rowset->pprops[i].value.err == ecNotFound)
				continue;
			if (i != count)
				rowset->pprops[count] = rowset->pprops[i];
			count++;
		}
		rowset->cvalues = count;
	} else {
		for (size_t i = 0; i < rowset->cvalues; ++i) {
			if (PROP_TYPE(rowset->pprops[i].proptag) == PT_ERROR) {
				result = ecWarnWithErrors;
				break;
			}
		}
	}
	if (result == ecSuccess || result == ecWarnWithErrors)
		*pprows = rowset;
	NSP_ROWSET rs = {*pprows != nullptr ? 1U : 0U, *pprows};
	nsp_trace(__func__, 1, pstat, nullptr, &rs);
	return result;
}

int nsp_interface_compare_mids(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, uint32_t mid1, uint32_t mid2, uint32_t *presult)
{
	nsp_trace(__func__, 0, pstat);
	int i;
	int base_id;
	uint32_t minid;
	int pos1, pos2;
	
	if (pstat != nullptr && pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	
	pos1 = -1;
	pos2 = -1;
	i = 0;
	if (NULL == pstat || 0 == pstat->container_id) {
		for (auto ptr : pbase->gal_list) {
			minid = ab_tree_get_node_minid(ptr);
			if (minid == mid1)
				pos1 = i;
			if (minid == mid2)
				pos2 = i;
			i ++;
		}
	} else {
		auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
		if (pnode == nullptr)
			return ecInvalidBookmark;
		pnode = pnode->get_child();
		if (pnode == nullptr)
			return ecInvalidBookmark;
		do {
			minid = ab_tree_get_node_minid(pnode);
			if (minid == mid1)
				pos1 = i;
			if (minid == mid2)
				pos2 = i;
			i ++;
		} while ((pnode = pnode->get_sibling()) != nullptr);
	}
	if (pos1 == -1 || pos2 == -1)
		return ecError;
	*presult = pos2 - pos1;
	nsp_trace(__func__, 1, pstat);
	return ecSuccess;
}

int nsp_interface_mod_props(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, const LPROPTAG_ARRAY *pproptags, const NSP_PROPROW *prow)
{
	nsp_trace(__func__, 1, pstat);
	return ecNotSupported;
}

static BOOL nsp_interface_build_specialtable(NSP_PROPROW *prow,
    BOOL b_unicode, cpid_t codepage, BOOL has_child,
	unsigned int depth, int container_id, const char *str_dname,
	PERMANENT_ENTRYID *ppermeid_parent, PERMANENT_ENTRYID *ppermeid)
{
	int tmp_len;
	char tmp_title[1024];
	
	
	prow->reserved = 0x0;
	prow->cvalues = depth == 0 ? 6 : 7;
	prow->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT, prow->cvalues);
	if (prow->pprops == nullptr)
		return FALSE;
	
	prow->pprops[0].proptag = PR_ENTRYID;
	prow->pprops[0].reserved = 0;
	if (!common_util_permanent_entryid_to_binary(
		ppermeid, &prow->pprops[0].value.bin)) {
		prow->pprops[0].proptag = CHANGE_PROP_TYPE(prow->pprops[0].proptag, PT_ERROR);
		prow->pprops[0].value.err = ecMAPIOOM;
	}
	
	/* PR_CONTAINER_FLAGS */
	prow->pprops[1].proptag = PR_CONTAINER_FLAGS;
	prow->pprops[1].reserved = 0;
	prow->pprops[1].value.l = !has_child ? AB_RECIPIENTS | AB_UNMODIFIABLE :
	                          AB_RECIPIENTS | AB_SUBCONTAINERS | AB_UNMODIFIABLE;
	
	/* PR_DEPTH */
	prow->pprops[2].proptag = PR_DEPTH;
	prow->pprops[2].reserved = 0;
	prow->pprops[2].value.l = depth;
	
	prow->pprops[3].proptag = PR_EMS_AB_CONTAINERID;
	prow->pprops[3].reserved = 0;
	prow->pprops[3].value.l = container_id;
	
	prow->pprops[4].reserved = 0;
	prow->pprops[4].proptag = b_unicode ? PR_DISPLAY_NAME : PR_DISPLAY_NAME_A;
	if (NULL == str_dname) {
		prow->pprops[4].value.pstr = NULL;
	} else {
		if (b_unicode) {
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
	
	prow->pprops[5].proptag = PR_EMS_AB_IS_MASTER;
	prow->pprops[5].reserved = 0;
	prow->pprops[5].value.b = 0;
	
	if (0 != depth) {
		prow->pprops[6].proptag = PR_EMS_AB_PARENT_ENTRYID;
		prow->pprops[6].reserved = 0;
		if (!common_util_permanent_entryid_to_binary(
			ppermeid_parent, &prow->pprops[6].value.bin)) {
			prow->pprops[6].proptag = CHANGE_PROP_TYPE(prow->pprops[6].proptag, PT_ERROR);
			prow->pprops[6].value.err = ecMAPIOOM;
		}
	}
	return TRUE;
}

static BOOL nsp_interface_has_child(const SIMPLE_TREE_NODE *pnode)
{
	pnode = pnode->get_child();
	if (pnode == nullptr)
		return FALSE;
	do {
		if (ab_tree_get_node_type(pnode) >= abnode_type::containers)
			return TRUE;
	} while ((pnode = pnode->get_sibling()) != nullptr);
	return FALSE;
}

static uint32_t nsp_interface_get_specialtables_from_node(
    const SIMPLE_TREE_NODE *pnode, PERMANENT_ENTRYID *ppermeid_parent,
    BOOL b_unicode, cpid_t codepage, NSP_ROWSET *prows)
{
	GUID tmp_guid;
	BOOL has_child;
	uint32_t result;
	int container_id;
	NSP_PROPROW *prow;
	char str_dname[1024];
	
	auto ppermeid = ndr_stack_anew<PERMANENT_ENTRYID>(NDR_STACK_OUT);
	if (ppermeid == nullptr)
		return ecServerOOM;
	if (!ab_tree_node_to_guid(pnode, &tmp_guid))
		return ecServerOOM;
	if (!common_util_set_permanententryid(DT_CONTAINER, &tmp_guid,
	    nullptr, ppermeid))
		return ecServerOOM;
	prow = common_util_proprowset_enlarge(prows);
	if (prow == nullptr)
		return ecServerOOM;
	has_child = nsp_interface_has_child(pnode);
	container_id = ab_tree_get_node_minid(pnode);
	if (container_id == 0)
		return ecError;
	ab_tree_get_display_name(pnode, codepage, str_dname, std::size(str_dname));
	if (!nsp_interface_build_specialtable(prow, b_unicode, codepage, has_child,
	    pnode->get_depth(), container_id,
	    str_dname, ppermeid_parent, ppermeid))
		return ecServerOOM;
	if (!has_child)
		return ecSuccess;
	auto pnode1 = pnode->get_child();
	do {
		if (ab_tree_get_node_type(pnode1) < abnode_type::containers)
			continue;
		result = nsp_interface_get_specialtables_from_node(
		         pnode1, ppermeid, b_unicode, codepage, prows);
		if (result != ecSuccess)
			return result;
	} while ((pnode1 = pnode1->get_sibling()) != nullptr);
	return ecSuccess;
}

static uint32_t nsp_interface_get_tree_specialtables(const SIMPLE_TREE *ptree,
    BOOL b_unicode, cpid_t codepage, NSP_ROWSET *prows)
{
	auto pnode = ptree->get_root();
	if (pnode == nullptr)
		return ecError;
	return nsp_interface_get_specialtables_from_node(
			pnode, NULL, b_unicode, codepage, prows);
}

int nsp_interface_get_specialtable(NSPI_HANDLE handle, uint32_t flags,
    const STAT *pstat, uint32_t *pversion, NSP_ROWSET **pprows)
{
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	int base_id;
	uint32_t result;
	NSP_PROPROW *prow;
	PERMANENT_ENTRYID permeid;
	
	if (flags & NspiAddressCreationTemplates)
		/* creation of templates table */
		return ecSuccess;
	BOOL b_unicode = (flags & NspiUnicodeStrings) ? TRUE : false;
	cpid_t codepage = pstat == nullptr ? static_cast<cpid_t>(1252) : pstat->codepage;
	/* in MS-OXNSPI 3.1.4.1.3 server processing rules */
	if (!b_unicode && codepage == CP_WINUNICODE)
		return ecNotSupported;
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	(*pversion) ++;
	auto rowset = common_util_proprowset_init();
	if (rowset == nullptr)
		return ecServerOOM;
	
	/* build the gal root */
	prow = common_util_proprowset_enlarge(rowset);
	if (prow == nullptr)
		return ecServerOOM;
	if (!common_util_set_permanententryid(DT_CONTAINER,
	    nullptr, nullptr, &permeid))
		return ecServerOOM;
	if (!nsp_interface_build_specialtable(prow, b_unicode, codepage,
	    false, 0, 0, nullptr, nullptr, &permeid))
		return ecServerOOM;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	for (auto &domain : pbase->domain_list) {
		auto pdomain = &domain;
		result = nsp_interface_get_tree_specialtables(
		         &pdomain->tree, b_unicode, codepage, rowset);
		if (result != ecSuccess)
			return result;
	}
	nsp_trace(__func__, 1, pstat, nullptr, rowset);
	*pprows = rowset;
	return ecSuccess;
}

int nsp_interface_mod_linkatt(NSPI_HANDLE handle, uint32_t flags,
    uint32_t proptag, uint32_t mid, const BINARY_ARRAY *pentry_ids) try
{
	int base_id;
	uint32_t tmp_mid;
	char maildir[256];
	
	if (mid == 0)
		return ecInvalidObject;
	if (proptag != PR_EMS_AB_PUBLIC_DELEGATES)
		return ecNotSupported;
	auto rpc_info = get_rpc_info();
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;
	auto ptnode = ab_tree_minid_to_node(pbase.get(), mid);
	if (ptnode == nullptr)
		return ecInvalidObject;
	if (ab_tree_get_node_type(ptnode) != abnode_type::user)
		return ecInvalidObject;
	auto username = ab_tree_get_user_info(ptnode, USER_MAIL_ADDRESS);
	if (username == nullptr || strcasecmp(username, rpc_info.username) != 0)
		return ecAccessDenied;
	if (!get_maildir(username, maildir, std::size(maildir)))
		return ecError;

	auto tmp_list = delegates_for(maildir);
	size_t item_num = tmp_list.size();
	for (size_t i = 0; i < pentry_ids->count; ++i) {
		if (pentry_ids->pbin[i].cb < 20)
			continue;
		if (pentry_ids->pbin[i].cb == 32 &&
		    pentry_ids->pbin[i].pb[0] == ENTRYID_TYPE_EPHEMERAL) {
			tmp_mid = pentry_ids->pbin[i].pb[28];
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[29]) << 8;
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[30]) << 16;
			tmp_mid |= ((uint32_t)pentry_ids->pbin[i].pb[31]) << 24;
			ptnode = ab_tree_minid_to_node(pbase.get(), tmp_mid);
		} else if (pentry_ids->pbin[i].cb >= 28 &&
		    pentry_ids->pbin[i].pb[0] == ENTRYID_TYPE_PERMANENT) {
			ptnode = ab_tree_dn_to_node(pbase.get(), pentry_ids->pbin[i].pc + 28);
		} else {
			mlog(LV_ERR, "E-2039: Unknown NSPI entry ID type %xh",
			        pentry_ids->pbin[i].pb[0]);
			ptnode = nullptr;
		}
		if (ptnode == nullptr)
			continue;
		auto un = ab_tree_get_user_info(ptnode, USER_MAIL_ADDRESS);
		if (un != nullptr) {
			if (flags & MOD_FLAG_DELETE)
				tmp_list.erase(un);
			else
				tmp_list.emplace(un);
		}
	}
	if (tmp_list.size() == item_num)
		return ecSuccess;
	auto dlg_path = maildir + "/config/delegates.txt"s;
	wrapfd fd = open(dlg_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PUBLIC);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-2024: open %s: %s",
			dlg_path.c_str(), strerror(errno));
		return ecError;
	}
	for (const auto &u : tmp_list) {
		auto wr_ret = write(fd.get(), u.c_str(), u.size());
		if (wr_ret < 0 || static_cast<size_t>(wr_ret) != u.size() ||
		    write(fd.get(), "\r\n", 2) != 2) {
			mlog(LV_ERR, "E-1687: write %s: %s", dlg_path.c_str(), strerror(errno));
			break;
		}
	}
	if (fd.close_wr() != 0) {
		mlog(LV_ERR, "E-1686: write %s: %s", dlg_path.c_str(), strerror(errno));
		return ecError;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1919: ENOMEM");
	return ecServerOOM;
}

int nsp_interface_query_columns(NSPI_HANDLE handle, uint32_t reserved,
	uint32_t flags, LPROPTAG_ARRAY **ppcolumns)
{
	*ppcolumns = nullptr;
	LPROPTAG_ARRAY *pcolumns;
	BOOL b_unicode = (flags & NspiUnicodeProptypes) ? TRUE : false;
	
	pcolumns = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (pcolumns == nullptr)
		return ecServerOOM;
	static constexpr uint32_t utags[] = {
		PR_DISPLAY_NAME, PR_NICKNAME,/* PR_TITLE, */
		PR_BUSINESS_TELEPHONE_NUMBER, PR_PRIMARY_TELEPHONE_NUMBER,
		PR_MOBILE_TELEPHONE_NUMBER, PR_HOME_ADDRESS_STREET, PR_COMMENT,
		PR_COMPANY_NAME, PR_DEPARTMENT_NAME, PR_OFFICE_LOCATION,
		PR_ADDRTYPE, PR_SMTP_ADDRESS,PR_EMAIL_ADDRESS,
		PR_EMS_AB_DISPLAY_NAME_PRINTABLE, PR_ACCOUNT,
		PR_TRANSMITABLE_DISPLAY_NAME, PR_EMS_AB_PROXY_ADDRESSES,
	}, ntags[] = {
		PR_OBJECT_TYPE, PR_DISPLAY_TYPE, PR_DISPLAY_TYPE_EX,
		PR_ENTRYID, PR_RECORD_KEY, PR_ORIGINAL_ENTRYID, PR_SEARCH_KEY,
		PR_INSTANCE_KEY, PR_MAPPING_SIGNATURE, PR_SEND_RICH_INFO,
		PR_TEMPLATEID, PR_EMS_AB_OBJECT_GUID, PR_CREATION_TIME,
	};
	pcolumns->cvalues = std::size(utags) + std::size(ntags);
	pcolumns->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pcolumns->cvalues);
	if (pcolumns->pproptag == nullptr)
		return ecServerOOM;
	size_t i = 0;
	for (auto tag : utags)
		pcolumns->pproptag[i++] = b_unicode ? tag : CHANGE_PROP_TYPE(tag, PT_STRING8);
	for (auto tag : ntags)
		pcolumns->pproptag[i++] = tag;
	*ppcolumns = pcolumns;
	return ecSuccess;
}

int nsp_interface_resolve_names(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, LPROPTAG_ARRAY *&pproptags,
    const STRINGS_ARRAY *pstrs, MID_ARRAY **ppmids, NSP_ROWSET **pprows)
{
	char *pstr;
	
	*ppmids = nullptr;
	*pprows = nullptr;
	for (size_t i = 0; i < pstrs->count; ++i) {
		if (pstrs->ppstr[i] == nullptr)
			continue;
		auto temp_len = mb_to_utf8_len(pstrs->ppstr[i]);
		pstr = ndr_stack_anew<char>(NDR_STACK_IN, temp_len);
		if (pstr == nullptr)
			return ecServerOOM;
		if (common_util_to_utf8(pstat->codepage, pstrs->ppstr[i], pstr, temp_len) == -1)
			pstrs->ppstr[i] = nullptr;
		else
			pstrs->ppstr[i] = pstr;
	}
	return nsp_interface_resolve_namesw(handle, reserved,
				pstat, pproptags, pstrs, ppmids, pprows);
}

static BOOL nsp_interface_resolve_node(const SIMPLE_TREE_NODE *pnode,
    cpid_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn, std::size(dn));
	if (strcasestr(dn, pstr) != nullptr)
		return TRUE;
	if (ab_tree_node_to_dn(pnode, dn, sizeof(dn)) && strcasecmp(dn, pstr) == 0)
		return TRUE;
	ab_tree_get_department_name(pnode, dn);
	if (strcasestr(dn, pstr) != nullptr)
		return TRUE;
	switch(ab_tree_get_node_type(pnode)) {
	case abnode_type::user: {
		auto s = ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		for (const auto &a : ab_tree_get_object_aliases(pnode))
			if (strcasestr(a.c_str(), pstr) != nullptr)
				return TRUE;
		s = ab_tree_get_user_info(pnode, USER_NICK_NAME);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_JOB_TITLE);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_COMMENT);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_MOBILE_TEL);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_BUSINESS_TEL);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		s = ab_tree_get_user_info(pnode, USER_HOME_ADDRESS);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return TRUE;
		break;
	}
	case abnode_type::mlist:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (strcasestr(dn, pstr) != nullptr)
			return TRUE;
		break;
	default:
		break;
	}
	return FALSE;
}

static const SIMPLE_TREE_NODE *nsp_interface_resolve_gal(const AB_BASE &base,
    cpid_t codepage, char *pstr, BOOL *pb_ambiguous)
{
	const SIMPLE_TREE_NODE *ptnode = nullptr;
	
	for (const auto &pair : base.phash) {
		NSAB_NODE *node = pair.second;
		auto ptr = &node->stree;
		if (ab_tree_hidden(ptr) & AB_HIDE_RESOLVE)
			continue;
		if (!nsp_interface_resolve_node(ptr, codepage, pstr))
			continue;
		if (NULL != ptnode) {
			*pb_ambiguous = TRUE;
			return NULL;
		}
		ptnode = ptr;
	}
	if (ptnode != nullptr)
		return ptnode;
	*pb_ambiguous = FALSE;
	return NULL;
}

int nsp_interface_resolve_namesw(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, LPROPTAG_ARRAY *&pproptags,
    const STRINGS_ARRAY *pstrs, MID_ARRAY **ppmids, NSP_ROWSET **pprows)
{
	int base_id;
	char *ptoken;
	uint32_t result;
	BOOL b_ambiguous;
	uint32_t start_pos, total;
	uint32_t *pproptag;
	NSP_PROPROW *prow;
	
	*ppmids = nullptr;
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	if (pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	/*
	[MS-OXNPI] 3.1.4.1.17, If the input parameter Reserved contains
	any value other than 0, the server MUST return one of the return
	values specified in section 2.2.1.2, but Outlook 2010 always send
	non-zero so we skip it.
	*/
	base_id = ab_tree_get_guid_base_id(handle.guid);
	if (base_id == 0 || handle.handle_type != HANDLE_EXCHANGE_NSP)
		return ecError;
	if (NULL == pproptags) {
		auto nt = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (nt == nullptr)
			return ecServerOOM;
		pproptags = nt;
		nt->cvalues = 7;
		nt->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_IN, nt->cvalues);
		if (nt->pproptag == nullptr)
			return ecServerOOM;
		nt->pproptag[0] = PR_EMS_AB_CONTAINERID;
		nt->pproptag[1] = PR_OBJECT_TYPE;
		nt->pproptag[2] = PR_DISPLAY_TYPE;
		nt->pproptag[3] = PR_DISPLAY_NAME_A;
		nt->pproptag[4] = PR_PRIMARY_TELEPHONE_NUMBER_A;
		nt->pproptag[5] = PR_DEPARTMENT_NAME_A;
		nt->pproptag[6] = PR_OFFICE_LOCATION_A;
	} else if (pproptags->cvalues > 100) {
		return ecTableTooBig;
	}
	auto outmids = common_util_proptagarray_init();
	if (outmids == nullptr)
		return ecServerOOM;
	auto rowset = common_util_proprowset_init();
	if (rowset == nullptr)
		return ecServerOOM;
	auto pbase = ab_tree_get_base(base_id);
	if (pbase == nullptr || (g_session_check && pbase->guid != handle.guid))
		return ecError;

	if (0 == pstat->container_id) {
		for (size_t i = 0; i < pstrs->count; ++i) {
			pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			if (pstrs->ppstr[i] == nullptr) {
				*pproptag = MID_UNRESOLVED;
				continue;
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(pstrs->ppstr[i], ':');
			if (ptoken != nullptr)
				ptoken ++;
			else
				ptoken = pstrs->ppstr[i];
			auto pnode = nsp_interface_resolve_gal(*pbase,
						pstat->codepage, ptoken, &b_ambiguous);
			if (NULL == pnode) {
				*pproptag = b_ambiguous ? MID_AMBIGUOUS : MID_UNRESOLVED;
				continue;
			}
			*pproptag = MID_RESOLVED;
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			result = nsp_interface_fetch_row(pnode, false,
			         pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
		}
		*ppmids = outmids;
		*pprows = rowset;
		nsp_trace(__func__, 1, pstat, nullptr, *pprows);
		return ecSuccess;
	}

	auto pnode = ab_tree_minid_to_node(pbase.get(), pstat->container_id);
	if (pnode == nullptr)
		return ecInvalidBookmark;
	nsp_interface_position_in_table(pstat,
		pnode, &start_pos, &total);
	for (size_t i = 0; i < pstrs->count; ++i) {
		pproptag = common_util_proptagarray_enlarge(outmids);
		if (pproptag == nullptr)
			return ecServerOOM;
		if (pstrs->ppstr[i] == nullptr) {
			*pproptag = MID_UNRESOLVED;
			continue;
		}
		/* =SMTP:user@company.com */
		ptoken = strchr(pstrs->ppstr[i], ':');
		if (ptoken != nullptr)
			ptoken++;
		else
			ptoken = pstrs->ppstr[i];
		*pproptag = MID_UNRESOLVED;
		size_t j;
		const SIMPLE_TREE_NODE *pnode1, *pnode2 = nullptr;
		for (j = 0, pnode1 = pnode->get_child();
		     NULL != pnode1 && j >= start_pos && j < total;
		     pnode1 = pnode1->get_sibling()) {
			if (ab_tree_get_node_type(pnode1) >= abnode_type::containers)
				continue;
			if (nsp_interface_resolve_node(pnode1,
			    pstat->codepage, ptoken)) {
				if (MID_RESOLVED == *pproptag) {
					*pproptag = MID_AMBIGUOUS;
					break;
				} else {
					*pproptag = MID_RESOLVED;
					pnode2 = pnode1;
				}
			}
			j++;
		}
		if (MID_RESOLVED == *pproptag) {
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			result = nsp_interface_fetch_row(pnode2, false,
			         pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
		}
	}
	*ppmids = outmids;
	*pprows = rowset;
	nsp_trace(__func__, 1, pstat, nullptr, *pprows);
	return ecSuccess;
}

void nsp_interface_unbind_rpc_handle(uint64_t hrpc)
{
	/* do nothing */
}

int nsp_interface_get_templateinfo(NSPI_HANDLE handle, uint32_t flags,
    uint32_t type, const char *dn, cpid_t codepage, uint32_t locale_id,
    NSP_PROPROW **ppdata)
{
	*ppdata = nullptr;
	if ((flags & (TI_TEMPLATE | TI_SCRIPT)) != TI_TEMPLATE)
		return ecNotSupported;
	if (!verify_cpid(codepage))
		return MAPI_E_UNKNOWN_CPID;
	if (dn != nullptr) {
		mlog(LV_WARN, "nsp: unimplemented templateinfo dn=%s", dn);
		return MAPI_E_UNKNOWN_LCID;
	}

	char buf[4096];
	snprintf(buf, sizeof(buf), PKGDATADIR "/%x-%x.abkt", locale_id, type);
	wrapfd fd = open(buf, O_RDONLY);
	if (fd.get() < 0)
		return MAPI_E_UNKNOWN_LCID;
	std::string tpldata;
	ssize_t have_read;
	while ((have_read = read(fd.get(), buf, sizeof(buf))) > 0)
		tpldata += std::string_view(buf, have_read);
	fd.close_rd();
	try {
		/* .abkt files are Unicode, transform them to 8-bit codepage */
		tpldata = abkt_tobinary(abkt_tojson(tpldata, CP_ACP), codepage, false);
	} catch (const std::bad_alloc &) {
		return ecServerOOM;
	} catch (const std::runtime_error &) {
		return MAPI_E_UNKNOWN_LCID;
	}

	auto row = ndr_stack_anew<NSP_PROPROW>(NDR_STACK_OUT);
	if (row == nullptr)
		return ecServerOOM;
	row->reserved = 0;
	row->cvalues  = 1;
	auto val = row->pprops = ndr_stack_anew<PROPERTY_VALUE>(NDR_STACK_OUT);
	if (val == nullptr)
		return ecServerOOM;
	val->proptag  = PR_EMS_TEMPLATE_BLOB;
	val->reserved = 0;
	val->value.bin.cb = tpldata.size();
	val->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, tpldata.size());
	if (val->value.bin.pv == nullptr)
		return ecServerOOM;
	memcpy(val->value.bin.pv, tpldata.data(), tpldata.size());
	*ppdata = row;
	return 0;
}
