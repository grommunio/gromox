// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fmt/core.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::ok) return klfdv; } while (false)

using namespace gromox;
DECLARE_PROC_API(,);
#define ZZNDR_NS
#include <gromox/zz_ndr_stack.hpp>

enum {
	RfrGetNewDSA = 0,
	RfrGetFQDNFromServerDN = 1,
};

namespace {

struct RFRGETNEWDSA_IN {
	uint32_t flags;
	char puserdn[1024];
	char punused[256];
	char pserver[256];
};

struct RFRGETNEWDSA_OUT {
	std::string pserver;
	uint32_t result;
};

struct RFRGETFQDNFROMLEGACYDN_IN {
	uint32_t flags;
	uint32_t cb;
	char mbserverdn[1024];
};

struct RFRGETFQDNFROMLEGACYDN_OUT {
	std::string serverfqdn;
	uint32_t result;
};

}

static pack_result exchange_rfr_ndr_pull(int op, NDR_PULL *, void **in);
static int exchange_rfr_dispatch(unsigned int op, const GUID *obj, uint64_t handle, void *in, void **out, ec_error_t *);
static pack_result exchange_rfr_ndr_push(int op, NDR_PUSH *, void *out);

static DCERPC_ENDPOINT *ep_6001, *ep_6002;

static constexpr DCERPC_INTERFACE interface = {
	"exchangeRFR",
	/* {1544f5e0-613c-11d1-93df-00c04fd7bd09} */
	{0x1544f5e0, 0x613c, 0x11d1, {0x93, 0xdf}, {0x00, 0xc0, 0x4f, 0xd7, 0xbd, 0x09}},
	1, exchange_rfr_ndr_pull, exchange_rfr_dispatch, exchange_rfr_ndr_push,
};

BOOL PROC_exchange_rfr(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	if (reason == PLUGIN_FREE) {
		unregister_interface(ep_6002, &interface);
		unregister_interface(ep_6001, &interface);
		return TRUE;
	}
	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_PROC_API(ppdata);
		ep_6001 = register_endpoint("*", 6001);
		if (ep_6001 == nullptr) {
			mlog(LV_ERR, "rfr: failed to register endpoint with port 6001");
			return FALSE;
		}
		ep_6002 = register_endpoint("*", 6002);
		if (ep_6002 == nullptr) {
			mlog(LV_ERR, "rfr: failed to register endpoint with port 6002");
			return FALSE;
		}
		if (!register_interface(ep_6001, &interface) ||
		    !register_interface(ep_6002, &interface)) {
			mlog(LV_ERR, "rfr: failed to register interface");
			return FALSE;
		}
		return TRUE;
	}
	default:
		return TRUE;
	}
}

static ec_error_t rfr_get_newdsa(uint32_t flags, const char *puserdn,
    std::string &server)
{
	char *ptoken;
	char username[UADDR_SIZE];
	char hex_string[32];
	
	auto rpc_info = get_rpc_info();
	unsigned int user_id = 0;
	if (!mysql_adaptor_get_user_ids(rpc_info.username, &user_id, nullptr, nullptr))
		return ecError;
	memset(username, 0, sizeof(username));
	gx_strlcpy(username, rpc_info.username, std::size(username));
	ptoken = strchr(username, '@');
	HX_strlower(username);
	if (ptoken != nullptr)
		ptoken ++;
	else
		ptoken = username;
	encode_hex_int(user_id, hex_string);
	server = fmt::format("{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}@{}",
			username[0], username[1], username[2],
			username[3], username[4], username[5], username[6],
			username[7], username[8], username[9], username[10],
			username[11], hex_string, ptoken);
	return ecSuccess;
}

static ec_error_t rfr_get_fqdnfromlegacydn(uint32_t flags, uint32_t cb,
    const char *mbserverdn, std::string &serverfqdn)
{
	char *ptoken;
	char tmp_buff[1024];
	
	gx_strlcpy(tmp_buff, mbserverdn, std::size(tmp_buff));
	ptoken = strrchr(tmp_buff, '/');
	if (ptoken == nullptr || strncasecmp(ptoken, "/cn=", 4) != 0)
		return rfr_get_newdsa(flags, nullptr, serverfqdn);
	*ptoken = '\0';
	ptoken = strrchr(tmp_buff, '/');
	if (ptoken == nullptr || strncasecmp(ptoken, "/cn=", 4) != 0)
		return rfr_get_newdsa(flags, nullptr, serverfqdn);
	serverfqdn = &ptoken[4];
	return ecSuccess;
}

static pack_result exchange_rfr_ndr_pull(int opnum, NDR_PULL *pndr, void **ppin)
{
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	RFRGETNEWDSA_IN *prfr;
	RFRGETFQDNFROMLEGACYDN_IN *prfr_dn;

	
	switch (opnum) {
	case RfrGetNewDSA:
		prfr = ndr_stack_anew<RFRGETNEWDSA_IN>(NDR_STACK_IN);
		if (prfr == nullptr)
			return pack_result::alloc;
		memset(prfr, 0, sizeof(RFRGETNEWDSA_IN));
		TRY(pndr->g_uint32(&prfr->flags));
		TRY(pndr->g_ulong(&size));
		TRY(pndr->g_ulong(&offset));
		TRY(pndr->g_ulong(&length));
		if (offset != 0 || length > size || length > 1024)
			return pack_result::array_size;
		TRY(pndr->check_str(length, sizeof(uint8_t)));
		TRY(pndr->g_str(prfr->puserdn, length));
		TRY(pndr->g_genptr(&ptr));
		if (0 != ptr) {
			TRY(pndr->g_genptr(&ptr));
			if (0 != ptr) {
				TRY(pndr->g_ulong(&size));
				TRY(pndr->g_ulong(&offset));
				TRY(pndr->g_ulong(&length));
				if (offset != 0 || length > size || length > 256)
					return pack_result::array_size;
				TRY(pndr->check_str(length, sizeof(uint8_t)));
				TRY(pndr->g_str(prfr->punused, length));
			} else {
				prfr->punused[0] = '\0';
			}
		} else {
			prfr->punused[0] = '\0';
		}
		TRY(pndr->g_genptr(&ptr));
		if (0 != ptr) {
			TRY(pndr->g_genptr(&ptr));
			if (0 != ptr) {
				TRY(pndr->g_ulong(&size));
				TRY(pndr->g_ulong(&offset));
				TRY(pndr->g_ulong(&length));
				if (offset != 0 || length > size || length > 256)
					return pack_result::array_size;
				TRY(pndr->check_str(length, sizeof(uint8_t)));
				TRY(pndr->g_str(prfr->pserver, length));
			} else {
				prfr->pserver[0] = '\0';
			}
		} else {
			prfr->pserver[0] = '\0';
		}
		*ppin = prfr;
		return pack_result::ok;
	case RfrGetFQDNFromServerDN:
		prfr_dn = ndr_stack_anew<RFRGETFQDNFROMLEGACYDN_IN>(NDR_STACK_IN);
		if (prfr_dn == nullptr)
			return pack_result::alloc;
		memset(prfr_dn, 0, sizeof(RFRGETFQDNFROMLEGACYDN_IN));
		TRY(pndr->g_uint32(&prfr_dn->flags));
		TRY(pndr->g_uint32(&prfr_dn->cb));
		if (prfr_dn->cb < 10 || prfr_dn->cb > 1024)
			return pack_result::range;
		TRY(pndr->g_ulong(&size));
		TRY(pndr->g_ulong(&offset));
		TRY(pndr->g_ulong(&length));
		if (offset != 0 || length > size || length > 1024)
			return pack_result::array_size;
		TRY(pndr->check_str(length, sizeof(uint8_t)));
		TRY(pndr->g_str(prfr_dn->mbserverdn, length));
		*ppin = prfr_dn;
		return pack_result::ok;
	default:
		return pack_result::bad_switch;
	}
}

static int exchange_rfr_dispatch(unsigned int opnum, const GUID *pobject,
    uint64_t handle, void *pin, void **ppout, ec_error_t *ecode)
{
	RFRGETNEWDSA_OUT *prfr_out;
	RFRGETFQDNFROMLEGACYDN_OUT *prfr_dn_out;
	
	switch (opnum) {
	case RfrGetNewDSA: {
		auto prfr_in = static_cast<RFRGETNEWDSA_IN *>(pin);
		prfr_out = ndr_stack_anew<RFRGETNEWDSA_OUT>(NDR_STACK_OUT);
		if (prfr_out == nullptr)
			return DISPATCH_FAIL;
		try {
			prfr_out->result = rfr_get_newdsa(prfr_in->flags,
			                   prfr_in->puserdn, prfr_out->pserver);
		} catch (const std::bad_alloc &) {
			return DISPATCH_FAIL;
		}
		*ppout = prfr_out;
		return DISPATCH_SUCCESS;
	}
	case RfrGetFQDNFromServerDN: {
		auto prfr_dn_in = static_cast<RFRGETFQDNFROMLEGACYDN_IN *>(pin);
		prfr_dn_out = ndr_stack_anew<RFRGETFQDNFROMLEGACYDN_OUT>(NDR_STACK_OUT);
		if (prfr_dn_out == nullptr)
			return DISPATCH_FAIL;
		try {
			prfr_dn_out->result = rfr_get_fqdnfromlegacydn(prfr_dn_in->flags,
			                      prfr_dn_in->cb, prfr_dn_in->mbserverdn,
			                      prfr_dn_out->serverfqdn);
		} catch (const std::bad_alloc &) {
			return DISPATCH_FAIL;
		}
		*ppout = prfr_dn_out;
		return DISPATCH_SUCCESS;
	}
	default:
		return DISPATCH_FAIL;
	}
}

static pack_result exchange_rfr_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	int length;
	
	switch (opnum) {
	case RfrGetNewDSA: {
		auto prfr = static_cast<RFRGETNEWDSA_OUT *>(pout);
		TRY(pndr->p_unique_ptr(nullptr));
		if (prfr->pserver.empty()) {
			TRY(pndr->p_unique_ptr(nullptr));
		} else {
			TRY(pndr->p_unique_ptr(reinterpret_cast<void *>(0x2)));
			length = prfr->pserver.size() + 1;
			TRY(pndr->p_unique_ptr(prfr->pserver.c_str()));
			TRY(pndr->p_ulong(length));
			TRY(pndr->p_ulong(0));
			TRY(pndr->p_ulong(length));
			TRY(pndr->p_str(prfr->pserver.c_str(), length));
		}
		return pndr->p_uint32(prfr->result);
	}
	case RfrGetFQDNFromServerDN: {
		auto prfr_dn = static_cast<RFRGETFQDNFROMLEGACYDN_OUT *>(pout);
		if (prfr_dn->serverfqdn.empty()) {
			TRY(pndr->p_unique_ptr(nullptr));
		} else {
			length = prfr_dn->serverfqdn.size() + 1;
			TRY(pndr->p_unique_ptr(prfr_dn->serverfqdn.c_str()));
			TRY(pndr->p_ulong(length));
			TRY(pndr->p_ulong(0));
			TRY(pndr->p_ulong(length));
			TRY(pndr->p_str(prfr_dn->serverfqdn.c_str(), length));
		}
		return pndr->p_uint32(prfr_dn->result);
	}
	}
	return pack_result::ok;
}
