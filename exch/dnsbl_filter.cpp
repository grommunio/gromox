// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstring>
#include <resolv.h>
#include <string>
#include <arpa/inet.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <gromox/config_file.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>

using namespace gromox;
static std::string g_zone_suffix;

/**
 * An empty string is returned when there is nothing to complain about.
 */
static bool dnsbl_check(const char *src, std::string &reason) try
{
#ifndef HAVE_RES_NQUERYDOMAIN
	return true;
#else
	static constexpr char txt[] = "0123456789abcdef";
	if (g_zone_suffix.empty())
		return true;
	struct in6_addr dst;
	if (inet_pton(AF_INET6, src, &dst) != 1) {
		reason = "E-1734: inet_pton";
		return false;
	}
	char dotrep[97];
	dotrep[0] = '\0';
	size_t z = 0;
	for (unsigned int i = 16; i-- > 0; ) {
		dotrep[z++] = txt[dst.s6_addr[i] & 0xF];
		dotrep[z++] = '.';
		dotrep[z++] = txt[(dst.s6_addr[i] & 0xF0) >> 4];
		dotrep[z++] = '.';
	}
	if (z > 0)
		dotrep[--z] = '\0';

	std::remove_pointer_t<res_state> state;
	uint8_t rsp[1500];
	if (res_ninit(&state) != 0) {
		reason = "E-1735: ENOMEM";
		return false;
	}
	auto cl_0 = make_scope_exit([&]() { res_nclose(&state); });
	auto ret = res_nquerydomain(&state, dotrep, g_zone_suffix.c_str(),
	           ns_c_in, ns_t_txt, rsp, std::size(rsp));
	if (ret <= 0)
		return true; /* e.g. NXDOMAIN */

	ns_msg handle;
	if (ns_initparse(rsp, ret, &handle) != 0) {
		reason = "E-1737";
		return false;
	}
	auto flg = ns_msg_getflag(handle, ns_f_rcode);
	if (flg != ns_r_noerror) {
		reason = "E-1738";
		return false;
	}
	reason.clear();
	auto max = ns_msg_end(handle);
	for (unsigned int rrnum = 0; rrnum < ns_msg_count(handle, ns_s_an); ++rrnum) {
		ns_rr rr;
		if (ns_parserr(&handle, ns_s_an, rrnum, &rr) != 0)
			continue;
		if (ns_rr_type(rr) != ns_t_txt)
			continue;
		auto len = ns_rr_rdlen(rr);
		auto ptr = ns_rr_rdata(rr);
		if (len > 0)
			--len;
		if (ptr + len >= max)
			len = 0;
		reason += std::string_view(reinterpret_cast<const char *>(ptr + 1), len);
		reason += "; ";
	}
	return false;
#endif
} catch (const std::bad_alloc &) {
	return false;
}

static BOOL svc_dnsbl_filter(int reason, void **data)
{
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(data);
	auto cfg = config_file_initd("master.cfg", get_config_path(), nullptr);
	if (cfg == nullptr) {
		mlog(LV_ERR, "dnsbl_filter: config_file_initd master.cfg: %s",
			strerror(errno));
		return false;
	}
	// TODO: dnsbl_client=<apikey>.authbl.dq.spamhaus.net=127.0.0.20
	// dnsbl_client=zen.spamhaus.org
	auto str = cfg->get_value("dnsbl_client");
	if (str != nullptr)
		g_zone_suffix = str;
	if (!register_service("ip_filter_judge", dnsbl_check))
		return false;
	return TRUE;
}
SVC_ENTRY(svc_dnsbl_filter);
