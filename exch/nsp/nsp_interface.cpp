// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
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
#include <fmt/core.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/ab_tree.hpp>
#include <gromox/archive.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
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
#include "common_util.hpp"
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
static gromox::archive abkt_archive;

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
	const PROPERTY_NAME xn = {MNID_STRING, PSETID_Gromox, 0, deconst("photo")};
	const PROPNAME_ARRAY name_req = {1, deconst(&xn)};
	PROPID_ARRAY name_rsp{};
	if (!get_named_propids(dir, false, &name_req, &name_rsp) ||
	    name_rsp.size() != name_req.size() || name_rsp[0] == 0)
		return nullptr;
	uint32_t proptag = PROP_TAG(PT_BINARY, name_rsp[0]);
	const PROPTAG_ARRAY tags = {1, deconst(&proptag)};
	TPROPVAL_ARRAY values{};
	if (!get_store_properties(dir, CP_ACP, &tags, &values))
		return nullptr;
	return values.get<const BINARY>(proptag);
}

static ec_error_t nsp_fetchprop(const ab_tree::ab_node &node, cpid_t codepage, unsigned int proptag, PROPERTY_VALUE *prop)
{
	const sql_user *user = node.fetch_user();
	if (!user)
		return ecNotFound;
	auto it = user->propvals.find(proptag);
	if (it == user->propvals.cend())
		return ecNotFound;

	switch (PROP_TYPE(proptag)) {
	case PT_BOOLEAN:
		prop->value.b = strtol(it->second.c_str(), nullptr, 0) != 0;
		return ecSuccess;
	case PT_SHORT:
		prop->value.s = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_LONG:
	case PT_OBJECT:
		prop->value.l = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_FLOAT:
		prop->value.flt = strtod(it->second.c_str(), nullptr);
		return ecSuccess;
	case PT_DOUBLE:
	case PT_APPTIME:
		prop->value.dbl = strtod(it->second.c_str(), nullptr);
		return ecSuccess;
	case PT_I8:
	case PT_CURRENCY:
		prop->value.ll = strtoll(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_SYSTIME:
		common_util_day_to_filetime(it->second.c_str(), &prop->value.ftime);
		return ecSuccess;
	case PT_STRING8: {
		auto tg = ndr_stack_anew<char>(NDR_STACK_OUT, it->second.size() + 1);
		if (tg == nullptr)
			return ecServerOOM;
		auto ret = cu_utf8_to_mb(codepage, it->second.c_str(), tg, it->second.size());
		if (ret < 0)
			return ecError;
		tg[ret] = '\0';
		prop->value.pstr = tg;
		return ecSuccess;
	}
	case PT_UNICODE: {
		auto tg = ndr_stack_anew<char>(NDR_STACK_OUT, it->second.size() + 1);
		if (tg == nullptr)
			return ecServerOOM;
		strcpy(tg, it->second.c_str());
		prop->value.pstr = tg;
		return ecSuccess;
	}
	case PT_BINARY: {
		prop->value.bin.cb = it->second.size();
		prop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, it->second.size());
		if (prop->value.bin.pv == nullptr)
			return ecServerOOM;
		memcpy(prop->value.bin.pv, it->second.data(), prop->value.bin.cb);
		return ecSuccess;
	}
	case PT_MV_UNICODE: {
		auto &x = prop->value.string_array;
		x.count = 1;
		x.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT);
		if (x.ppstr == nullptr)
			return ecServerOOM;
		auto tg = ndr_stack_anew<char>(NDR_STACK_OUT, it->second.size() + 1);
		if (tg == nullptr)
			return ecServerOOM;
		strcpy(tg, it->second.c_str());
		x.ppstr[0] = tg;
		return ecSuccess;
	}
	}
	return ecNotFound;
}

static ec_error_t nsp_interface_fetch_property(const ab_tree::ab_node &node,
    BOOL b_ephid, cpid_t codepage, uint32_t proptag, PROPERTY_VALUE *pprop,
    void *pbuff, size_t pbsize)
{
	size_t temp_len;
	std::string dn;
	EPHEMERAL_ENTRYID ephid;
	EMSAB_ENTRYID permeid;
	
	temp_len = 1024;
	pprop->proptag = proptag;
	pprop->reserved = 0;
	auto node_type = node.type();
	/* Properties that need to be force-generated */
	switch (proptag) {
	case PR_CREATION_TIME:
		pprop->value.ftime = {};
		return ecSuccess;
	case PR_EMS_AB_HOME_MDB:
	case PR_EMS_AB_HOME_MDB_A: {
		if (node_type != ab_tree::abnode_type::user)
			return ecNotFound;
		std::string mdbdn;
		auto err = node.mdbdn(mdbdn);
		if (err != ecSuccess)
			return err;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, mdbdn.size() + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
			gx_strlcpy(static_cast<char *>(pprop->value.pv), mdbdn.c_str(), mdbdn.size() + 1);
		} else {
			pprop->value.pv = pbuff;
			gx_strlcpy(pprop->value.pstr, mdbdn.c_str(), pbsize);
		}
		return ecSuccess;
	}
	case PR_EMS_AB_OBJECT_GUID: {
		GUID temp_guid = node.guid();
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, 16);
			if (pprop->value.bin.pv == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.bin.pv = deconst(pbuff);
		}
		common_util_guid_to_binary(&temp_guid, &pprop->value.bin);
		return ecSuccess;
	}
	case PR_EMS_AB_CONTAINERID: // TODO: ???
		pprop->value.l = 0;
		return ecSuccess;
	case PR_ADDRTYPE:
	case PR_ADDRTYPE_A:
		pprop->value.pstr = deconst("EX");
		return ecSuccess;
	case PR_EMAIL_ADDRESS:
	case PR_EMAIL_ADDRESS_A:
		if (!node.dn(dn))
			return ecInvalidObject;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, dn.size() + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn.c_str());
		return ecSuccess;
	case PR_OBJECT_TYPE: {
		auto t = node_type == ab_tree::abnode_type::mlist ? MAPI_DISTLIST : MAPI_MAILUSER;
		pprop->value.l = static_cast<uint32_t>(t);
		return ecSuccess;
	}
	case PR_DISPLAY_TYPE:
		pprop->value.l = node.dtyp();
		return ecSuccess;
	case PR_DISPLAY_TYPE_EX: {
		auto dtypx = node.dtypx();
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
		if (!node.dn(dn))
			return ecNotFound;
		if (!common_util_set_permanententryid(node.etyp(),
		    nullptr, dn.c_str(), &permeid) ||
		    !common_util_permanent_entryid_to_binary(&permeid, &pprop->value.bin))
			return ecServerOOM;
		return ecSuccess;
	case PR_ENTRYID:
	case PR_RECORD_KEY:
	case PR_ORIGINAL_ENTRYID:
		if (!b_ephid) {
			if (!node.dn(dn))
				return ecNotFound;
			if (!common_util_set_permanententryid(node.etyp(),
			    nullptr, dn.c_str(), &permeid) ||
			    !common_util_permanent_entryid_to_binary(&permeid, &pprop->value.bin))
				return ecServerOOM;
		} else {
			common_util_set_ephemeralentryid(node.etyp(),
				node.mid, &ephid);
			if (!common_util_ephemeral_entryid_to_binary(&ephid,
			    &pprop->value.bin))
				return ecServerOOM;
		}
		return ecSuccess;
	case PR_SEARCH_KEY:
		if (!node.dn(dn))
			return ecNotFound;
		pprop->value.bin.cb = uint32_t(dn.size() + 4);
		if (NULL == pbuff) {
			pprop->value.bin.pv = ndr_stack_alloc(
				NDR_STACK_OUT, pprop->value.bin.cb);
			if (pprop->value.bin.pc == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.bin.pv = pbuff;
		}
		sprintf(pprop->value.bin.pc, "EX:%s", dn.c_str());
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
		cpu_to_le32p(pprop->value.bin.pb, node.mid);
		return ecSuccess;
	case PR_TRANSMITABLE_DISPLAY_NAME:
		if (node_type != ab_tree::abnode_type::user)
			return ecNotFound;
		[[fallthrough]];
	case PR_DISPLAY_NAME:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE:
		dn = node.displayname();
		if (dn.empty())
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, dn.size() + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn.c_str());
		return ecSuccess;
	case PR_TRANSMITABLE_DISPLAY_NAME_A:
		if (node_type != ab_tree::abnode_type::user)
			return ecNotFound;
		[[fallthrough]];
	case PR_DISPLAY_NAME_A:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE_A:
		/* @codepage is used to select a translation; it's not for charsets */
		dn = node.displayname();
		if (dn.empty())
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn.c_str());
			pprop->value.pv = ndr_stack_alloc(
						NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		cu_utf8_to_mb(codepage, dn.c_str(),
				pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_COMPANY_NAME:
		if (!node.company_info(&dn, nullptr))
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, dn.size() + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn.c_str());
		return ecSuccess;
	case PR_COMPANY_NAME_A:
		if (!node.company_info(&dn, nullptr))
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn.c_str());
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		cu_utf8_to_mb(codepage,
			dn.c_str(), pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_DEPARTMENT_NAME:
	case PR_DEPARTMENT_NAME_A:
		return ecNotFound;
	case PR_OFFICE_LOCATION:
		if (!node.company_info(nullptr, &dn))
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, dn.size() + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn.c_str());
		return ecSuccess;
	case PR_OFFICE_LOCATION_A:
		if (!node.company_info(nullptr, &dn))
			return ecNotFound;
		if (NULL == pbuff) {
			temp_len = utf8_to_mb_len(dn.c_str());
			pprop->value.pv = ndr_stack_alloc(NDR_STACK_OUT, temp_len);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		cu_utf8_to_mb(codepage, dn.c_str(),
				pprop->value.pstr, temp_len);
		return ecSuccess;
	case PR_ACCOUNT:
	case PR_ACCOUNT_A:
	case PR_SMTP_ADDRESS:
	case PR_SMTP_ADDRESS_A:
		if (node_type == ab_tree::abnode_type::mlist)
			node.mlist_info(&dn, nullptr, nullptr);
		else if (node_type == ab_tree::abnode_type::user)
			dn = znul(node.user_info(ab_tree::userinfo::mail_address));
		else
			return ecNotFound;
		if (dn.empty())
			return ecNotFound;
		if (NULL == pbuff) {
			pprop->value.pv = ndr_stack_alloc(
				NDR_STACK_OUT, dn.size() + 1);
			if (pprop->value.pstr == nullptr)
				return ecServerOOM;
		} else {
			pprop->value.pv = pbuff;
		}
		strcpy(pprop->value.pstr, dn.c_str());
		return ecSuccess;
	case PR_EMS_AB_PROXY_ADDRESSES:
	case PR_EMS_AB_PROXY_ADDRESSES_A: {
		if (node_type == ab_tree::abnode_type::mlist)
			node.mlist_info(&dn, nullptr, nullptr);
		else if (node_type == ab_tree::abnode_type::user)
			dn = znul(node.user_info(ab_tree::userinfo::mail_address));
		else
			return ecNotFound;
		if (dn.empty())
			return ecNotFound;
		auto alias_list = node.aliases();
		pprop->value.string_array.count = uint32_t(1 + alias_list.size());
		pprop->value.string_array.ppstr = ndr_stack_anew<char *>(NDR_STACK_OUT, pprop->value.string_array.count);
		if (pprop->value.string_array.ppstr == nullptr)
			return ecServerOOM;
		pprop->value.string_array.ppstr[0] = ndr_stack_anew<char>(NDR_STACK_OUT, dn.size() + 6);
		if (pprop->value.string_array.ppstr[0] == nullptr)
			return ecServerOOM;
		sprintf(pprop->value.string_array.ppstr[0], "SMTP:%s", dn.c_str());
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
		auto path = node.user_info(ab_tree::userinfo::store_path);
		if (path == nullptr)
			return ecNotFound;
		auto bv = nsp_photo_rpc(dn.c_str());
		if (bv != nullptr) {
			pprop->value.bin = *bv;
			return ecSuccess;
		}
		/* Old access for monohost installations */
		dn = path;
		dn += "/config/portrait.jpg";
		if (!common_util_load_file(dn.c_str(), &pprop->value.bin))
			return ecNotFound;
		return ecSuccess;
	}
	}
	/* User-defined props */
	if (node_type == ab_tree::abnode_type::user || node_type == ab_tree::abnode_type::mlist) {
		auto ret = nsp_fetchprop(node, codepage, proptag, pprop);
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

static ec_error_t nsp_interface_fetch_row(const ab_tree::ab_node &node,
    BOOL b_ephid, cpid_t codepage, const LPROPTAG_ARRAY *pproptags,
    NSP_PROPROW *prow)
{
	PROPERTY_VALUE *pprop;
	
	auto node_type = node.type();
	if (node_type >= ab_tree::abnode_type::containers)
		return ecInvalidObject;
	for (size_t i = 0; i < pproptags->cvalues; ++i) {
		pprop = common_util_propertyrow_enlarge(prow);
		if (pprop == nullptr)
			return ecServerOOM;
		auto err_val = nsp_interface_fetch_property(node, b_ephid, codepage,
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
	static constexpr char pk[] = PKGDATADIR "/abkt.pak";
	auto err = abkt_archive.open(pk);
	if (err != 0)
		mlog(LV_ERR, "Could not read %s: %s. Addressbook dialogs have not been loaded.", pk, strerror(err));
}

ec_error_t nsp_interface_bind(uint64_t hrpc, uint32_t flags, const STAT *pstat,
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
	if (!mysql_adaptor_get_domain_ids(pdomain, &domain_id, &org_id)) {
		mlog(LV_WARN, "W-2176: could not satisfy nsp_bind request for domain %s: not found", pdomain);
		phandle->handle_type = HANDLE_EXCHANGE_NSP;
		memset(&phandle->guid, 0, sizeof(GUID));
		return ecError;
	}
	phandle->handle_type = HANDLE_EXCHANGE_NSP;
	int base_id = org_id == 0 ? -domain_id : org_id;
	auto pbase = ab_tree::AB.get(base_id);
	if (pbase == nullptr) {
		memset(&phandle->guid, 0, sizeof(GUID));
		return ecError;
	}
	if (g_nsp_trace >= 2)
		pbase->dump();
	phandle->guid = pbase->guid();
	if (NULL != pserver_guid) {
		EXT_PUSH ep;
		ep.init(pserver_guid, sizeof(*pserver_guid), 0);
		if (ep.p_guid(common_util_get_server_guid()) != EXT_ERR_SUCCESS)
			return ecError;
	}
	nsp_trace(__func__, 1, pstat);
	return ecSuccess;
}

ec_error_t nsp_interface_unbind(NSPI_HANDLE *phandle, uint32_t reserved)
{
	if (g_nsp_trace > 0)
		fprintf(stderr, "Entering %s\n", __func__);
	memset(phandle, 0, sizeof(NSPI_HANDLE));
	return MAPI_E_UNBINDSUCCESS;
}

static void nsp_interface_position_in_list(const STAT *pstat,
    const ab_tree::ab_base *base, uint32_t *pout_row, uint32_t *pcount)
{
	*pcount = uint32_t(base->users());
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		*pout_row = *pcount * static_cast<double>(pstat->num_pos) / pstat->total_rec;
		if (*pout_row > 0 && *pout_row >= *pcount)
			*pout_row = *pcount - 1; /* v13 pg72 §3.1.4.5.2 point 5 */
	} else if (pstat->cur_rec == MID_BEGINNING_OF_TABLE) {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		*pout_row = 0;
	} else if (pstat->cur_rec == MID_END_OF_TABLE) {
		*pout_row = *pcount;
	} else {
		auto it = base->find(pstat->cur_rec);
		/*
		 * When not found, the position is undefined.
		 * To avoid problems we will use first row.
		 */
		*pout_row = it != base->end() && it->type() == ab_tree::minid::address ? it.pos()-base->ubegin().pos() : 0;
	}
}

static void nsp_interface_position_in_table(const STAT *pstat,
    const ab_tree::ab_node &node, uint32_t *pout_row, uint32_t *pcount)
{
	*pcount = uint32_t(node.children());
	if (MID_CURRENT == pstat->cur_rec) {
		/* fractional positioning MS-OXNSPI 3.1.4.5.2 */
		*pout_row = std::min(*pcount, static_cast<uint32_t>(*pcount *
		      static_cast<double>(pstat->num_pos) / pstat->total_rec));
	} else if (pstat->cur_rec == MID_BEGINNING_OF_TABLE) {
		/* absolute positioning MS-OXNSPI 3.1.4.5.1 */
		*pout_row = 0;
	} else if (pstat->cur_rec == MID_END_OF_TABLE) {
		*pout_row = *pcount;
	} else {
		auto it = std::find(node.begin(), node.end(), pstat->cur_rec);
		if (it == node.end() || node.base->hidden(pstat->cur_rec) & AB_HIDE_FROM_AL)
			/* In this case the position is undefined.
			   To avoid problems we will use first row */
			*pout_row = 0;
		else
			*pout_row = uint32_t(std::distance(node.begin(), it));
	}
}

ec_error_t nsp_interface_update_stat(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, int32_t *pdelta)
{
	nsp_trace(__func__, 0, pstat, pdelta);
	ab_tree::ab_node node;
	
	if (pstat == nullptr || pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	auto pbase = ab_tree::AB.get(handle.guid);
	if (pbase == nullptr || (g_session_check && pbase->guid() != handle.guid))
		return ecError;
	uint32_t init_row = 0, total = 0;
	if (0 == pstat->container_id) {
		nsp_interface_position_in_list(pstat, pbase.get(), &init_row, &total);
	} else {
		node = {pbase, pstat->container_id};
		if (!node.exists())
			return ecInvalidBookmark;
		nsp_interface_position_in_table(pstat, node, &init_row, &total);
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
		pstat->cur_rec = pstat->container_id == 0 ? pbase->at(row) : node[row];
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

ec_error_t nsp_interface_query_rows(NSPI_HANDLE handle, uint32_t flags,
    STAT *pstat, uint32_t table_count, uint32_t *ptable, uint32_t count,
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
	auto pbase = ab_tree::AB.get(handle.guid);
	if (handle.handle_type != HANDLE_EXCHANGE_NSP || !pbase || (g_session_check && pbase->guid() != handle.guid))
		return ecError;
	auto rowset = common_util_proprowset_init();
	if (rowset == nullptr)
		return ecServerOOM;
	
	if (ptable != nullptr) {
		for (size_t i = 0; i < table_count; ++i) {
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			ab_tree::ab_node node(pbase, ptable[i]);
			if (!node.exists()) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
				continue;
			}
			auto result = nsp_interface_fetch_row(node, b_ephid,
			              pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				nsp_interface_make_ptyperror_row(pproptags, prow);
		}
		nsp_trace(__func__, 1, pstat, nullptr, rowset);
		*pprows = rowset;
		return ecSuccess;
	}

	ab_tree::ab_node node;
	if (0 == pstat->container_id) {
		nsp_interface_position_in_list(pstat, pbase.get(), &start_pos, &total);
	} else {
		node = {pbase, pstat->container_id};
		if (!node.exists())
			return ecInvalidBookmark;
		nsp_interface_position_in_table(pstat, node, &start_pos, &total);
		if (!node.children()) {
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
	if (0 == pstat->container_id) {
		for (auto it = pbase->ubegin() + start_pos; it != pbase->ubegin() + start_pos + tmp_count; ++it) {
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr || common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			ab_tree::ab_node temp(pbase, *it);
			auto result = nsp_interface_fetch_row(temp, b_ephid,
			              pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
		}
	} else {
		auto endidx = std::min(start_pos+tmp_count, uint32_t(node.children()));
		for (auto it = node.begin() + start_pos; it < node.begin() + endidx; ++it) {
			ab_tree::ab_node child(pbase, *it);
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr || common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			auto result = nsp_interface_fetch_row(child, b_ephid,
			              pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
		}
	}

	if (start_pos + tmp_count >= total) {
		pstat->cur_rec = MID_END_OF_TABLE;
	} else {
		pstat->cur_rec = pstat->container_id == 0 ? pbase->at(start_pos + tmp_count) : node.at(start_pos + tmp_count);
		if (0 == pstat->cur_rec) {
			pstat->cur_rec = MID_END_OF_TABLE;
			start_pos = total;
			tmp_count = 0;
		}
	}
	pstat->delta = 0;
	pstat->num_pos = start_pos + tmp_count;
	pstat->total_rec = total;
	nsp_trace(__func__, 1, pstat, nullptr, rowset);
	*pprows = rowset;
	return ecSuccess;
}

ec_error_t nsp_interface_seek_entries(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, PROPERTY_VALUE *ptarget, const MID_ARRAY *ptable,
    const LPROPTAG_ARRAY *pproptags, NSP_ROWSET **pprows)
{
	NSP_PROPROW *prow;
	uint32_t tmp_minid;
	std::string temp_name;
	
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
	auto pbase = ab_tree::AB.get(handle.guid);
	if (!pbase || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && pbase->guid() != handle.guid))
		return ecError;
	auto rowset = common_util_proprowset_init();
	if (rowset == nullptr)
		return ecServerOOM;
	
	if (NULL != ptable) {
		size_t row = 0;
		tmp_minid = 0;
		for (size_t i = 0; i < ptable->cvalues; ++i) {
			ab_tree::ab_node node1{pbase, ptable->pproptag[i]};
			if (!node1.exists())
				continue;
			temp_name = node1.displayname();
			if (strcasecmp(temp_name.c_str(), ptarget->value.pstr) < 0)
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
			auto result = nsp_interface_fetch_row(node1, TRUE,
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

	uint32_t start_pos = 0, total = 0;
	if (0 == pstat->container_id) {
		nsp_interface_position_in_list(pstat, pbase.get(), &start_pos, &total);
	} else {
		ab_tree::ab_node node(pbase, pstat->container_id);
		if (!node.exists())
			return ecInvalidBookmark;
		nsp_interface_position_in_table(pstat, node, &start_pos, &total);
		if (!node.children())
			return ecNotFound;
	}
	if (total == 0)
		return ecNotFound;

	start_pos = 0;
	if (0 == pstat->container_id) {
		auto it = std::lower_bound(pbase->ubegin(), pbase->uend(), ptarget->value.pstr,
		                           [&](ab_tree::minid m1, const char *val)
		                           { return strcasecmp(pbase->displayname(m1).c_str(), val) < 0; });
		if (it == pbase->uend())
			return ecNotFound;
		prow = common_util_proprowset_enlarge(rowset);
		if (prow == nullptr || common_util_propertyrow_init(prow) == nullptr)
			return ecServerOOM;
		if (nsp_interface_fetch_row({pbase, *it}, true, pstat->codepage, pproptags, prow) != ecSuccess)
			return ecError;
		pstat->cur_rec = *it;
		pstat->num_pos = uint32_t(it.pos());
	} else {
		ab_tree::ab_node node(pbase, pstat->container_id);
		if (start_pos >= node.children())
			return ecNotFound;
		auto it = std::lower_bound(node.begin()+start_pos, node.end(), ptarget->value.pstr,
		                           [&](ab_tree::minid m1, const char *val)
		                           {return strcasecmp(pbase->displayname(m1).c_str(), val) < 0;});
		if (it == node.end())
			return ecNotFound;
		prow = common_util_proprowset_enlarge(rowset);
		if (prow == nullptr || common_util_propertyrow_init(prow) == nullptr)
			return ecServerOOM;
		if (nsp_interface_fetch_row({pbase, *it}, TRUE, pstat->codepage, pproptags, prow) != ecSuccess)
				return ecError;
		pstat->cur_rec = *it;
		pstat->num_pos = uint32_t(std::distance(node.begin(), it));
	}
	pstat->total_rec = total;
	*pprows = rowset;
	nsp_trace(__func__, 1, pstat, nullptr, *pprows);
	return ecSuccess;
}

static BOOL nsp_interface_match_node(const ab_tree::ab_node &node,
    cpid_t codepage, const NSPRES *pfilter)
{
	char *ptoken;
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	
	switch (pfilter->res_type) {
	case RES_AND:
		for (size_t i = 0; i < pfilter->res.res_andor.cres; ++i)
			if (!nsp_interface_match_node(node,
			    codepage, &pfilter->res.res_andor.pres[i]))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (size_t i = 0; i < pfilter->res.res_andor.cres; ++i)
			if (nsp_interface_match_node(node,
			    codepage, &pfilter->res.res_andor.pres[i]))
				return TRUE;
		return FALSE;
	case RES_NOT:
		return !nsp_interface_match_node(node, codepage,
		       pfilter->res.res_not.pres) ? TRUE : false;
	case RES_CONTENT:
		return FALSE;
	case RES_PROPERTY:
		if (pfilter->res.res_property.pprop == nullptr)
			return TRUE;
		// XXX RESTRICTION_PROPERTY::comparable check
		if (pfilter->res.res_property.proptag == PR_ANR) {
			if (nsp_interface_fetch_property(node, false, codepage,
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
			if (nsp_interface_fetch_property(node, false, codepage,
			    PR_DISPLAY_NAME, &prop_val, temp_buff,
			    std::size(temp_buff)) == ecSuccess &&
			    strcasestr(temp_buff, pfilter->res.res_property.pprop->value.pstr) != nullptr)
				return TRUE;
			return FALSE;
		} else if (pfilter->res.res_property.proptag == PR_ANR_A) {
			if (nsp_interface_fetch_property(node, false, codepage,
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
			if (nsp_interface_fetch_property(node, false, codepage,
			    PR_DISPLAY_NAME_A, &prop_val, temp_buff,
			    std::size(temp_buff)) == ecSuccess &&
			    strcasestr(temp_buff, pfilter->res.res_property.pprop->value.pstr) != nullptr)
				return TRUE;
			return FALSE;
		}
		if (nsp_interface_fetch_property(node, false, codepage,
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
		auto node_type = node.type();
		if (node_type >= ab_tree::abnode_type::containers)
			return FALSE;
		if (nsp_interface_fetch_property(node, false, codepage,
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

ec_error_t nsp_interface_get_matches(NSPI_HANDLE handle, uint32_t reserved1,
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
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
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

	if (pstat->container_id == PR_EMS_AB_MEMBER) {
		if (!base->exists(pstat->cur_rec))
			return ecInvalidBookmark;
		auto mlistaddr = base->user_info(pstat->cur_rec, ab_tree::userinfo::mail_address);
		if (mlistaddr == nullptr)
			return ecNotFound;
		std::vector<std::string> member_list;
		int ret = 0;
		if (!mysql_adaptor_get_mlist_memb(mlistaddr, mlistaddr, &ret, member_list))
			return ecError;
		for (const auto &memb : member_list) {
			if (outmids->cvalues > requested)
				break;
			unsigned int user_id = 0;
			if (!mysql_adaptor_get_user_ids(memb.c_str(), &user_id, nullptr, nullptr))
				continue;
			ab_tree::ab_node node(base, ab_tree::minid(ab_tree::minid::address, user_id));
			if (!node.exists() || node.hidden() & AB_HIDE_FROM_AL)
				continue;
			if (pfilter != nullptr &&
			    !nsp_interface_match_node(node, pstat->codepage, pfilter))
				continue;	
			auto pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			*pproptag = node.mid;
		}
		goto FETCH_ROWS;
	} else if (pstat->container_id == PR_EMS_AB_PUBLIC_DELEGATES) {
		ab_tree::ab_node node(base, pstat->cur_rec);
		if (!node.exists())
			return ecInvalidBookmark;
		sql_meta_result mres;
		auto temp_buff = node.user_info(ab_tree::userinfo::mail_address);
		if (temp_buff == nullptr ||
		    mysql_adaptor_meta(temp_buff, WANTPRIV_METAONLY, mres) != 0)
			return ecError;
		auto delegate_list = delegates_for(mres.maildir.c_str());
		for (const auto &deleg : delegate_list) {
			if (outmids->cvalues > requested)
				break;
			unsigned int user_id = 0;
			if (!mysql_adaptor_get_user_ids(deleg.c_str(), &user_id, nullptr, nullptr))
				continue;
			node = ab_tree::ab_node(base, ab_tree::minid(ab_tree::minid::address, user_id));
			if (!node.exists() || node.hidden() & AB_HIDE_DELEGATE)
				continue;
			if (pfilter != nullptr &&
			    !nsp_interface_match_node(node, pstat->codepage, pfilter))
				continue;	
			auto pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			*pproptag = node.mid;
		}
		goto FETCH_ROWS;
	}
	if (pfilter == nullptr) {
		char temp_buff[1024];
		ab_tree::ab_node node = {base, pstat->cur_rec};
		if (node.exists() && nsp_interface_fetch_property(node,
		    TRUE, pstat->codepage, pstat->container_id, &prop_val,
		    temp_buff, std::size(temp_buff)) == ecSuccess) {
			auto pproptag = common_util_proptagarray_enlarge(outmids);
			if (pproptag == nullptr)
				return ecServerOOM;
			*pproptag = node.mid;
		}
	} else if (pstat->container_id == 0) {
		uint32_t start_pos, total;
		nsp_interface_position_in_list(pstat, base.get(), &start_pos, &total);
		for (auto it = base->ubegin() + start_pos; it != base->uend() && it-base->ubegin() < total; ++it)
			if (nsp_interface_match_node({base, *it}, pstat->codepage, pfilter)) {
				auto pproptag = common_util_proptagarray_enlarge(outmids);
				if (pproptag == nullptr)
					return ecServerOOM;
				*pproptag = *it;
			}
	} else {
		ab_tree::ab_node node(base, pstat->container_id);
		if (!node.exists())
			return ecInvalidBookmark;
		uint32_t start_pos, total;
		nsp_interface_position_in_table(pstat, node, &start_pos, &total);
		if (start_pos >= node.children()) {
			pstat->container_id = pstat->cur_rec; /* MS-OXNSPI 3.1.4.1.10.16 */
			*ppoutmids = outmids;
			*pprows = rowset;
			nsp_trace(__func__, 1, pstat, nullptr, rowset);
			return ecSuccess;
		}
		for (auto it = node.begin() + start_pos; it != node.end(); ++it)
			if (!(node.hidden() & AB_HIDE_FROM_AL) && nsp_interface_match_node({base, *it}, pstat->codepage, pfilter)) {
				auto pproptag = common_util_proptagarray_enlarge(outmids);
				if (pproptag == nullptr)
					return ecServerOOM;
				*pproptag = *it;
				if (outmids->cvalues >= requested)
					break;
			}
	}

 FETCH_ROWS:
	if (rowset != nullptr) {
		for (size_t i = 0; i < outmids->cvalues; ++i) {
			auto prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			ab_tree::ab_node node(base, outmids->pproptag[i]);
			if (!node.exists()) {
				nsp_interface_make_ptyperror_row(pproptags, prow);
			} else {
				auto result = nsp_interface_fetch_row(node, TRUE,
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

ec_error_t nsp_interface_resort_restriction(NSPI_HANDLE handle, uint32_t reserved,
    STAT *pstat, const MID_ARRAY *pinmids, MID_ARRAY **ppoutmids)
{
	*ppoutmids = nullptr;
	nsp_trace(__func__, 0, pstat);
	bool b_found;
	std::string temp_buff;
	
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
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
		return ecError;
	size_t count = 0;
	b_found = FALSE;
	for (size_t i = 0; i < pinmids->cvalues; ++i) {
		ab_tree::ab_node node(base, pinmids->pproptag[i]);
		if (!node.exists())
			continue;
		parray[count].minid = pinmids->pproptag[i];
		if (pstat->cur_rec == pinmids->pproptag[i])
			b_found = TRUE;
		temp_buff = node.displayname();
		parray[count].strv = ndr_stack_alloc(
			NDR_STACK_IN, temp_buff.size() + 1);
		if (parray[count].string == nullptr)
			return ecServerOOM;
		strcpy(parray[count++].string, temp_buff.c_str());
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

ec_error_t nsp_interface_dntomid(NSPI_HANDLE handle, uint32_t reserved,
    const STRINGS_ARRAY *pnames, MID_ARRAY **ppoutmids)
{
	if (g_nsp_trace > 0)
		fprintf(stderr, "Entering %s\n", __func__);
	*ppoutmids = nullptr;
	if (pnames == nullptr)
		return ecSuccess;
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
		return ecError;
	auto outmids = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (outmids == nullptr)
		return ecServerOOM;
	outmids->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, pnames->count);
	if (outmids->pproptag == nullptr)
		return ecServerOOM;
	outmids->cvalues = pnames->count;
	memset(outmids->pproptag, 0, sizeof(uint32_t) * pnames->count);
	for (size_t i = 0; i < pnames->count; ++i) {
		if (pnames->ppstr[i] == nullptr)
			continue;
		ab_tree::minid mid = base->resolve(pnames->ppstr[i]);
		if (base->exists(mid))
			outmids->pproptag[i] = mid;
		if (g_nsp_trace >= 2)
			fprintf(stderr, "\t[%zu] %s -> %08x\n", i,
				znul(pnames->ppstr[i]), outmids->pproptag[i]);
	}
	*ppoutmids = outmids;
	return ecSuccess;
}

static constexpr size_t DFL_TAGS_MAX = 32;

static ec_error_t nsp_fill_dfl_tags(ab_tree::abnode_type node_type,
    bool b_unicode, uint32_t *t, unsigned int &z)
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
	case ab_tree::abnode_type::domain:
		return ecInvalidObject;
	case ab_tree::abnode_type::user:
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
	case ab_tree::abnode_type::mlist:
		t[z++] = U(PR_SMTP_ADDRESS);
		t[z++] = U(PR_COMPANY_NAME);
		t[z++] = U(PR_DEPARTMENT_NAME);
		t[z++] = U(PR_EMS_AB_PROXY_ADDRESSES);
		t[z++] = PR_CREATION_TIME;
		t[z++] = PR_EMS_AB_THUMBNAIL_PHOTO;
		break;
	default:
		return ecInvalidObject;
	}
	return ecSuccess;
#undef U
}

static ec_error_t nsp_interface_get_default_proptags(ab_tree::abnode_type node_type,
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

ec_error_t nsp_interface_get_proplist(NSPI_HANDLE handle, uint32_t flags,
    uint32_t mid, cpid_t codepage, LPROPTAG_ARRAY **tags)
{
	if (g_nsp_trace > 0)
		fprintf(stderr, "Entering %s\n", __func__);
	char temp_buff[1024];
	PROPERTY_VALUE prop_val;
	
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || HANDLE_EXCHANGE_NSP != handle.handle_type || (g_session_check && base->guid() != handle.guid)) {
		*tags = nullptr;
		return ecError;
	}
	if (mid == 0) {
		*tags = nullptr;
		return ecInvalidObject;
	}
	BOOL b_unicode = codepage == CP_WINUNICODE ? TRUE : false;
	*tags = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_OUT);
	if (*tags == nullptr)
		return ecServerOOM;
	ab_tree::ab_node node(base, mid);
	if (!node.exists()) {
		*tags = nullptr;
		return ecInvalidObject;
	}

	/* Grab tags */
	auto type = node.type();
	uint32_t ntags = 0;
	std::vector<uint32_t> ctags(DFL_TAGS_MAX);
	auto ret = nsp_fill_dfl_tags(type, b_unicode, ctags.data(), ntags);
	assert(ntags <= DFL_TAGS_MAX);
	if (ret != ecSuccess)
		ntags = 0;
	ctags.resize(ntags);
	node.proplist(ctags);

	/* Trim tags that have no propval */
	std::sort(ctags.begin(), ctags.end());
	ctags.erase(std::unique(ctags.begin(), ctags.end()), ctags.end());
	ctags.erase(std::remove_if(ctags.begin(), ctags.end(), [&](uint32_t proptag) {
		return nsp_interface_fetch_property(node, false, codepage,
		       proptag, &prop_val, temp_buff,
		       std::size(temp_buff)) != ecSuccess;
	}), ctags.end());

	/* Copy out */
	(*tags)->cvalues = ctags.size();
	(*tags)->pproptag = ndr_stack_anew<uint32_t>(NDR_STACK_OUT, ctags.size());
	if ((*tags)->pproptag == nullptr) {
		*tags = nullptr;
		return ecServerOOM;
	}
	memcpy((*tags)->pproptag, ctags.data(), sizeof(uint32_t) * ctags.size());
	if (g_nsp_trace >= 2) {
		fprintf(stderr, "Leaving %s\n\ttags[%zu]={", __func__, ctags.size());
		for (auto value : ctags)
			fprintf(stderr, "%x,", value);
		fprintf(stderr, "}\n");
	}
	return ecSuccess;
}

ec_error_t nsp_interface_get_props(NSPI_HANDLE handle, uint32_t flags,
    const STAT *pstat, const LPROPTAG_ARRAY *pproptags, NSP_PROPROW **pprows)
{
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	uint32_t row;
	uint32_t total;
	BOOL b_proptags;
	
	if (pstat == nullptr)
		return ecNotSupported;
	BOOL b_ephid = (flags & fEphID) ? TRUE : false;
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
		return ecError;
	if (g_nsp_trace >= 2) {
		if (pproptags == nullptr) {
			fprintf(stderr, "\ttags=null\n");
		} else {
			fprintf(stderr, "\ttags[%u]={", pproptags->cvalues);
			for (size_t i = 0; i < pproptags->cvalues; ++i)
				fprintf(stderr, "%xh,", pproptags->pproptag[i]);
			fprintf(stderr, "}\n");
		}
	}
	BOOL b_unicode = pstat->codepage == CP_WINUNICODE ? TRUE : false;
	if (b_unicode && pproptags != nullptr)
		for (size_t i = 0; i < pproptags->cvalues; ++i)
			if (PROP_TYPE(pproptags->pproptag[i]) == PT_STRING8)
				return ecNotSupported;
	
	ab_tree::ab_node node;
	if (pstat->cur_rec <= 0x10) {
		if (0 == pstat->container_id) {
			ab_tree::ab_base::iterator it;
			if (ab_tree::minid::BEGINNING_OF_TABLE == pstat->cur_rec) {
				it = base->ubegin();
			} else if (MID_END_OF_TABLE == pstat->cur_rec) {
				it = base->end();
			} else {
				nsp_interface_position_in_list(pstat, base.get(), &row, &total);
				it = base->ubegin() + row;
			}
			if (it != base->end())
				node = {base, *it};
		} else {
			ab_tree::ab_node temp(base, pstat->container_id);
			if (!temp.exists())
				return ecInvalidBookmark;
			nsp_interface_position_in_table(pstat, temp, &row, &total);
			node = {base, temp[row]};
		}
	} else {
		node = {base, pstat->cur_rec};
		if (node.exists() && pstat->container_id != 0 && !base->exists(pstat->container_id))
			return ecInvalidBookmark;
	}
	b_proptags = TRUE;
	if (NULL == pproptags) {
		b_proptags = FALSE;
		auto nt = ndr_stack_anew<LPROPTAG_ARRAY>(NDR_STACK_IN);
		if (nt == nullptr)
			return ecServerOOM;
		pproptags = nt;
		auto type = node.exists() ? node.type() : ab_tree::abnode_type::user;
		auto result = nsp_interface_get_default_proptags(type, b_unicode, nt);
		if (result != ecSuccess)
			return result;
		if (g_nsp_trace >= 2) {
			fprintf(stderr, "\tdefault tags[%u]={", pproptags->cvalues);
			for (size_t i = 0; i < pproptags->cvalues; ++i)
				fprintf(stderr, "%xh,", pproptags->pproptag[i]);
			fprintf(stderr, "}\n");
		}
	} else if (pproptags->cvalues > 100) {
		return ecTableTooBig;
	}
	auto rowset = common_util_propertyrow_init(NULL);
	if (rowset == nullptr)
		return ecServerOOM;
	/* MS-OXNSPI 3.1.4.1.7.11 */
	ec_error_t result;
	if (!node.exists()) {
		nsp_interface_make_ptyperror_row(pproptags, rowset);
		result = ecWarnWithErrors;
	} else {
		result = nsp_interface_fetch_row(node, b_ephid,
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

ec_error_t nsp_interface_compare_mids(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, uint32_t mid1, uint32_t mid2, int32_t *cmp)
{
	nsp_trace(__func__, 0, pstat);
	
	if (pstat != nullptr && pstat->codepage == CP_WINUNICODE)
		return ecNotSupported;
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
		return ecError;

	if (NULL == pstat || 0 == pstat->container_id) {
		auto it1 = base->find(mid1);
		auto it2 = base->find(mid2);
		if (it1 == base->end() || it2 == base->end())
			return ecError;
		auto dx = it2.pos() <=> it1.pos();
		*cmp = dx == 0 ? 0 : dx < 0 ? -1 : 1;
	} else {
		ab_tree::ab_node node(base, pstat->container_id);
		if (!node.exists() || !node.children())
			return ecInvalidBookmark;
		auto it1 = std::find(node.begin(), node.end(), mid1);
		auto it2 = std::find(node.begin(), node.end(), mid2);
		if (it1 == node.end() || it2 == node.end())
			return ecError;
		auto dx = std::distance(it1, it2);
		*cmp = dx == 0 ? 0 : dx < 0 ? -1 : 1;
	}
	nsp_trace(__func__, 1, pstat);
	return ecSuccess;
}

ec_error_t nsp_interface_mod_props(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, const LPROPTAG_ARRAY *pproptags, const NSP_PROPROW *prow)
{
	nsp_trace(__func__, 1, pstat);
	return ecNotSupported;
}

static BOOL nsp_interface_build_specialtable(NSP_PROPROW *prow,
    BOOL b_unicode, cpid_t codepage, BOOL has_child,
    unsigned int depth, int container_id, const char *str_dname,
    EMSAB_ENTRYID *ppermeid_parent, EMSAB_ENTRYID *ppermeid)
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
			tmp_len = cu_utf8_to_mb(codepage,
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

static ec_error_t nsp_interface_get_specialtables_from_node(
    const ab_tree::ab_node &node, EMSAB_ENTRYID *ppermeid_parent,
    BOOL b_unicode, cpid_t codepage, NSP_ROWSET *prows)
{
	GUID tmp_guid;
	bool has_child;
	ab_tree::minid container_id;
	NSP_PROPROW *prow;
	std::string str_dname;
	
	auto ppermeid = ndr_stack_anew<EMSAB_ENTRYID>(NDR_STACK_OUT);
	if (ppermeid == nullptr)
		return ecServerOOM;
	tmp_guid = node.guid();
	if (!common_util_set_permanententryid(DT_CONTAINER, &tmp_guid,
	    nullptr, ppermeid))
		return ecServerOOM;
	prow = common_util_proprowset_enlarge(prows);
	if (prow == nullptr)
		return ecServerOOM;
	has_child = node.children();
	container_id = node.mid;
	if (container_id == 0)
		return ecError;

	str_dname = node.displayname();
	if (!nsp_interface_build_specialtable(prow, b_unicode, codepage, has_child,
	    0, container_id,
	    str_dname.c_str(), ppermeid_parent, ppermeid))
		return ecServerOOM;
	if (!has_child)
		return ecSuccess;
	// NOTE: removed recursion as we only have a "tree" depth of at most 1 at the moment
	return ecSuccess;
}

ec_error_t nsp_interface_get_specialtable(NSPI_HANDLE handle, uint32_t flags,
    const STAT *pstat, uint32_t *pversion, NSP_ROWSET **pprows)
{
	*pprows = nullptr;
	nsp_trace(__func__, 0, pstat);
	NSP_PROPROW *prow;
	EMSAB_ENTRYID permeid;
	
	if (flags & NspiAddressCreationTemplates)
		/* creation of templates table */
		return ecSuccess;
	BOOL b_unicode = (flags & NspiUnicodeStrings) ? TRUE : false;
	cpid_t codepage = pstat == nullptr ? static_cast<cpid_t>(1252) : pstat->codepage;
	/* in MS-OXNSPI 3.1.4.1.3 server processing rules */
	if (!b_unicode && codepage == CP_WINUNICODE)
		return ecNotSupported;
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
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
	for (auto it = base->dbegin(); it != base->dend(); ++it) {
		auto result = nsp_interface_get_specialtables_from_node({base, *it},
		              nullptr, b_unicode, codepage, rowset);
		if (result != ecSuccess)
			return result;
	}
	nsp_trace(__func__, 1, pstat, nullptr, rowset);
	*pprows = rowset;
	return ecSuccess;
}

ec_error_t nsp_interface_mod_linkatt(NSPI_HANDLE handle, uint32_t flags,
    uint32_t proptag, uint32_t mid, const BINARY_ARRAY *pentry_ids) try
{
	if (g_nsp_trace > 0)
		fprintf(stderr, "Entering %s {flags=%xh,proptag=%xh,mid=%xh}\n",
			__func__, flags, proptag, mid);
	if (mid == 0)
		return ecInvalidObject;
	if (proptag != PR_EMS_AB_PUBLIC_DELEGATES)
		return ecNotSupported;
	auto rpc_info = get_rpc_info();
	auto base = ab_tree::AB.get(handle.guid);
	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
		return ecError;
	ab_tree::ab_node tnode(base, mid);
	if (!tnode.exists())
		return ecInvalidObject;
	if (tnode.type() != ab_tree::abnode_type::user)
		return ecInvalidObject;
	auto username = tnode.user_info(ab_tree::userinfo::mail_address);
	if (username == nullptr || strcasecmp(username, rpc_info.username) != 0)
		return ecAccessDenied;
	sql_meta_result mres;
	if (mysql_adaptor_meta(username, WANTPRIV_METAONLY, mres) != 0)
		return ecError;

	auto tmp_list = delegates_for(mres.maildir.c_str());
	size_t item_num = tmp_list.size();
	for (size_t i = 0; i < pentry_ids->count; ++i) {
		if (pentry_ids->pbin[i].cb < 20)
			continue;
		if (pentry_ids->pbin[i].cb == 32 &&
		    pentry_ids->pbin[i].pb[0] == ENTRYID_TYPE_EPHEMERAL) {
			tnode = ab_tree::ab_node(base, le32p_to_cpu(&pentry_ids->pbin[i].pb[28]));
		} else if (pentry_ids->pbin[i].cb >= 28 &&
		    pentry_ids->pbin[i].pb[0] == ENTRYID_TYPE_PERMANENT) {
			tnode = ab_tree::ab_node(base, base->resolve(pentry_ids->pbin[i].pc + 28));
		} else {
			mlog(LV_ERR, "E-2039: Unknown NSPI entry ID type %xh",
			        pentry_ids->pbin[i].pb[0]);
			continue;
		}
		if (!tnode.exists())
			continue;
		auto un = tnode.user_info(ab_tree::userinfo::mail_address);
		if (un != nullptr) {
			if (flags & MOD_FLAG_DELETE)
				tmp_list.erase(un);
			else
				tmp_list.emplace(un);
		}
	}
	if (tmp_list.size() == item_num)
		return ecSuccess;
	auto dlg_path = mres.maildir + "/config/delegates.txt";
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

ec_error_t nsp_interface_query_columns(NSPI_HANDLE handle, uint32_t reserved,
	uint32_t flags, LPROPTAG_ARRAY **ppcolumns)
{
	if (g_nsp_trace > 0)
		fprintf(stderr, "Entering %s {flags=%xh}\n", __func__, flags);
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

ec_error_t nsp_interface_resolve_names(NSPI_HANDLE handle, uint32_t reserved,
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
		if (cu_mb_to_utf8(pstat->codepage, pstrs->ppstr[i], pstr, temp_len) == -1)
			pstrs->ppstr[i] = nullptr;
		else
			pstrs->ppstr[i] = pstr;
	}
	return nsp_interface_resolve_namesw(handle, reserved,
				pstat, pproptags, pstrs, ppmids, pprows);
}

static bool nsp_interface_resolve_node(const ab_tree::ab_node &node, const char *pstr)
{
	std::string dn = node.displayname();

	if (strcasestr(dn.c_str(), pstr) != nullptr)
		return true;
	if (node.dn(dn) && strcasecmp(dn.c_str(), pstr) == 0)
		return true;
	switch (node.type()) {
	case ab_tree::abnode_type::user: {
		auto s = node.user_info(ab_tree::userinfo::mail_address);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		for (const auto &a : node.aliases())
			if (strcasestr(a.c_str(), pstr) != nullptr)
				return true;
		s = node.user_info(ab_tree::userinfo::nick_name);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		s = node.user_info(ab_tree::userinfo::job_title);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		s = node.user_info(ab_tree::userinfo::comment);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		s = node.user_info(ab_tree::userinfo::mobile_tel);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		s = node.user_info(ab_tree::userinfo::business_tel);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		s = node.user_info(ab_tree::userinfo::home_address);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		break;
	}
	case ab_tree::abnode_type::mlist:
		node.mlist_info(&dn, nullptr, nullptr);
		if (strcasestr(dn.c_str(), pstr) != nullptr)
			return TRUE;
		break;
	default:
		break;
	}
	return FALSE;
}

static ab_tree::minid nsp_interface_resolve_gal(const ab_tree::ab::const_base_ref &base,
    const char *pstr, bool& b_ambiguous)
{
	ab_tree::minid res;

	for (ab_tree::minid mid : *base) {
		ab_tree::ab_node node(base, mid);
		if (node.hidden() & AB_HIDE_RESOLVE || !nsp_interface_resolve_node(node, pstr))
			continue;
		if (res.valid()) {
			b_ambiguous = true;
			return ab_tree::minid{};
		}
		res = mid;
	}
	b_ambiguous = !res.valid();
	return res;
}

ec_error_t nsp_interface_resolve_namesw(NSPI_HANDLE handle, uint32_t reserved,
    const STAT *pstat, LPROPTAG_ARRAY *&pproptags,
    const STRINGS_ARRAY *pstrs, MID_ARRAY **ppmids, NSP_ROWSET **pprows)
{
	bool b_ambiguous;
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
	auto base = ab_tree::AB.get(handle.guid);

	if (!base || handle.handle_type != HANDLE_EXCHANGE_NSP || (g_session_check && base->guid() != handle.guid))
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
			const char *ptoken = strchr(pstrs->ppstr[i], ':');
			if (ptoken != nullptr)
				ptoken ++;
			else
				ptoken = pstrs->ppstr[i];
			std::string idn_deco = gx_utf8_to_punycode(ptoken);
			ptoken = idn_deco.c_str();
			auto mid = nsp_interface_resolve_gal(base, ptoken, b_ambiguous);
			if (!mid.valid()) {
				*pproptag = b_ambiguous ? MID_AMBIGUOUS : MID_UNRESOLVED;
				continue;
			}
			*pproptag = MID_RESOLVED;
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr ||
			    common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			auto result = nsp_interface_fetch_row(ab_tree::ab_node(base, mid),
			              false, pstat->codepage, pproptags, prow);
			if (result != ecSuccess)
				return result;
		}
		*ppmids = outmids;
		*pprows = rowset;
		nsp_trace(__func__, 1, pstat, nullptr, *pprows);
		return ecSuccess;
	}

	ab_tree::ab_node node(base, pstat->container_id);
	if (!node.exists())
		return ecInvalidBookmark;
	nsp_interface_position_in_table(pstat,
		node, &start_pos, &total);
	for (size_t i = 0; i < pstrs->count; ++i) {
		pproptag = common_util_proptagarray_enlarge(outmids);
		if (pproptag == nullptr)
			return ecServerOOM;
		if (pstrs->ppstr[i] == nullptr) {
			*pproptag = MID_UNRESOLVED;
			continue;
		}
		/* =SMTP:user@company.com */
		const char *ptoken = strchr(pstrs->ppstr[i], ':');
		if (ptoken != nullptr)
			ptoken++;
		else
			ptoken = pstrs->ppstr[i];
		std::string idn_deco = gx_utf8_to_punycode(ptoken);
		ptoken = idn_deco.c_str();
		*pproptag = MID_UNRESOLVED;
		ab_tree::minid found;
		for (ab_tree::minid mid : node) {
			ab_tree::ab_node node1(base, mid);
			// Removed container check as there are currently no recursive containers
			if (nsp_interface_resolve_node(node, ptoken)) {
				if (*pproptag == ab_tree::minid::RESOLVED) {
					*pproptag = ab_tree::minid::AMBIGUOUS;
					break;
				}
				*pproptag = ab_tree::minid::RESOLVED;
				found = mid;
			}
		}
		if (*pproptag == ab_tree::minid::RESOLVED) {
			prow = common_util_proprowset_enlarge(rowset);
			if (prow == nullptr || common_util_propertyrow_init(prow) == nullptr)
				return ecServerOOM;
			auto result = nsp_interface_fetch_row({base, found},
			              false, pstat->codepage, pproptags, prow);
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

ec_error_t nsp_interface_get_templateinfo(NSPI_HANDLE handle, uint32_t flags,
    uint32_t type, const char *dn, cpid_t codepage, uint32_t locale_id,
    NSP_PROPROW **ppdata)
{
	if (g_nsp_trace > 0)
		fprintf(stderr, "Entering %s {flags=%xh,type=%xh,dn=%s,cpid=%u,lcid=%u}\n",
			__func__, flags, type, znul(dn), codepage, locale_id);
	*ppdata = nullptr;
	if ((flags & (TI_TEMPLATE | TI_SCRIPT)) != TI_TEMPLATE)
		return ecNotSupported;
	if (!verify_cpid(codepage))
		return MAPI_E_UNKNOWN_CPID;
	if (dn != nullptr) {
		mlog(LV_WARN, "nsp: unimplemented templateinfo dn=%s", dn);
		return MAPI_E_UNKNOWN_LCID;
	}

	auto tplfile = abkt_archive.find(fmt::format("{:x}-{:x}.abkt", locale_id, type));
	if (tplfile == nullptr)
		return MAPI_E_UNKNOWN_LCID;
	std::string tpldata;
	try {
		/* .abkt files are Unicode, transform them to 8-bit codepage */
		tpldata = abkt_tobinary(abkt_tojson(*tplfile, CP_ACP), codepage, false);
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
	return ecSuccess;
}
