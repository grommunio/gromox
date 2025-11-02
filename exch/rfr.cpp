// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
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

struct RFRGETNEWDSA_IN final : public rpc_request {
	uint32_t flags = 0;
	char puserdn[1024]{};
	char punused[256]{};
	char pserver[256]{};
};

struct RFRGETNEWDSA_OUT final : public rpc_response {
	std::string pserver;
	uint32_t result = 0;
};

struct RFRGETFQDNFROMLEGACYDN_IN final : public rpc_request {
	uint32_t flags = 0, cb = 0;
	char mbserverdn[1024]{};
};

struct RFRGETFQDNFROMLEGACYDN_OUT final : public rpc_response {
	std::string serverfqdn;
	uint32_t result = 0;
};

}

static pack_result exchange_rfr_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
static int exchange_rfr_dispatch(unsigned int op, const GUID *obj, uint64_t handle, const rpc_request *, std::unique_ptr<rpc_response> &, ec_error_t *);
static pack_result exchange_rfr_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);

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

static pack_result exchange_rfr_ndr_pull(unsigned int opnum, NDR_PULL &x,
    std::unique_ptr<rpc_request> &in) try
{
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;

	switch (opnum) {
	case RfrGetNewDSA: {
		auto prfr = std::make_unique<RFRGETNEWDSA_IN>();
		TRY(x.g_uint32(&prfr->flags));
		TRY(x.g_ulong(&size));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length));
		if (offset != 0 || length > size || length > 1024)
			return pack_result::array_size;
		TRY(x.check_str(length, sizeof(uint8_t)));
		TRY(x.g_str(prfr->puserdn, length));
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			TRY(x.g_genptr(&ptr));
			if (0 != ptr) {
				TRY(x.g_ulong(&size));
				TRY(x.g_ulong(&offset));
				TRY(x.g_ulong(&length));
				if (offset != 0 || length > size || length > 256)
					return pack_result::array_size;
				TRY(x.check_str(length, sizeof(uint8_t)));
				TRY(x.g_str(prfr->punused, length));
			} else {
				prfr->punused[0] = '\0';
			}
		} else {
			prfr->punused[0] = '\0';
		}
		TRY(x.g_genptr(&ptr));
		if (0 != ptr) {
			TRY(x.g_genptr(&ptr));
			if (0 != ptr) {
				TRY(x.g_ulong(&size));
				TRY(x.g_ulong(&offset));
				TRY(x.g_ulong(&length));
				if (offset != 0 || length > size || length > 256)
					return pack_result::array_size;
				TRY(x.check_str(length, sizeof(uint8_t)));
				TRY(x.g_str(prfr->pserver, length));
			} else {
				prfr->pserver[0] = '\0';
			}
		} else {
			prfr->pserver[0] = '\0';
		}
		in = std::move(prfr);
		return pack_result::ok;
	}
	case RfrGetFQDNFromServerDN: {
		auto prfr_dn = std::make_unique<RFRGETFQDNFROMLEGACYDN_IN>();
		TRY(x.g_uint32(&prfr_dn->flags));
		TRY(x.g_uint32(&prfr_dn->cb));
		if (prfr_dn->cb < 10 || prfr_dn->cb > 1024)
			return pack_result::range;
		TRY(x.g_ulong(&size));
		TRY(x.g_ulong(&offset));
		TRY(x.g_ulong(&length));
		if (offset != 0 || length > size || length > 1024)
			return pack_result::array_size;
		TRY(x.check_str(length, sizeof(uint8_t)));
		TRY(x.g_str(prfr_dn->mbserverdn, length));
		in = std::move(prfr_dn);
		return pack_result::ok;
	}
	default:
		return pack_result::bad_switch;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return pack_result::alloc;
}

static int exchange_rfr_dispatch(unsigned int opnum, const GUID *pobject,
    uint64_t handle, const rpc_request *pin,
    std::unique_ptr<rpc_response> &out, ec_error_t *ecode) try
{
	switch (opnum) {
	case RfrGetNewDSA: {
		auto prfr_in = static_cast<const RFRGETNEWDSA_IN *>(pin);
		auto prfr_out = std::make_unique<RFRGETNEWDSA_OUT>();
		prfr_out->result = rfr_get_newdsa(prfr_in->flags,
		                   prfr_in->puserdn, prfr_out->pserver);
		out = std::move(prfr_out);
		return DISPATCH_SUCCESS;
	}
	case RfrGetFQDNFromServerDN: {
		auto prfr_dn_in = static_cast<const RFRGETFQDNFROMLEGACYDN_IN *>(pin);
		auto prfr_dn_out = std::make_unique<RFRGETFQDNFROMLEGACYDN_OUT>();
		prfr_dn_out->result = rfr_get_fqdnfromlegacydn(prfr_dn_in->flags,
		                      prfr_dn_in->cb, prfr_dn_in->mbserverdn,
		                      prfr_dn_out->serverfqdn);
		out = std::move(prfr_dn_out);
		return DISPATCH_SUCCESS;
	}
	default:
		return DISPATCH_FAIL;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return DISPATCH_FAIL;
}

static pack_result exchange_rfr_ndr_push(unsigned int opnum, NDR_PUSH &x,
    const rpc_response *pout)
{
	int length;
	
	switch (opnum) {
	case RfrGetNewDSA: {
		auto prfr = static_cast<const RFRGETNEWDSA_OUT *>(pout);
		TRY(x.p_unique_ptr(nullptr));
		if (prfr->pserver.empty()) {
			TRY(x.p_unique_ptr(nullptr));
		} else {
			TRY(x.p_unique_ptr(reinterpret_cast<void *>(0x2)));
			length = prfr->pserver.size() + 1;
			TRY(x.p_unique_ptr(prfr->pserver.c_str()));
			TRY(x.p_ulong(length));
			TRY(x.p_ulong(0));
			TRY(x.p_ulong(length));
			TRY(x.p_str(prfr->pserver.c_str(), length));
		}
		return x.p_uint32(prfr->result);
	}
	case RfrGetFQDNFromServerDN: {
		auto prfr_dn = static_cast<const RFRGETFQDNFROMLEGACYDN_OUT *>(pout);
		if (prfr_dn->serverfqdn.empty()) {
			TRY(x.p_unique_ptr(nullptr));
		} else {
			length = prfr_dn->serverfqdn.size() + 1;
			TRY(x.p_unique_ptr(prfr_dn->serverfqdn.c_str()));
			TRY(x.p_ulong(length));
			TRY(x.p_ulong(0));
			TRY(x.p_ulong(length));
			TRY(x.p_str(prfr_dn->serverfqdn.c_str(), length));
		}
		return x.p_uint32(prfr_dn->result);
	}
	}
	return pack_result::ok;
}
