// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gromox/config_file.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#if defined(HAVE_CARES)
#	include <ares.h>
#elif defined(HAVE_LDNS)
#	include <ldns/ldns.h>
#elif defined(HAVE_RES_NQUERYDOMAIN)
#	include <netdb.h>
#	include <resolv.h>
#	include <arpa/nameser.h>
#endif

using namespace gromox;
static std::string g_zone_suffix;
DECLARE_SVC_API(,);

#ifdef HAVE_CARES
static std::string abinp_to_str(const ares_dns_rr_t *rr, ares_dns_rr_key_t key)
{
	std::string out;
	size_t cnt = ares_dns_rr_get_abin_cnt(rr, key);
	for (size_t i = 0; i < cnt; ++i) {
		size_t len;
		auto str = ares_dns_rr_get_abin(rr, key, i, &len);
		if (!out.empty())
			out += ' ';
		out.append(reinterpret_cast<const char *>(str), len);
	}
	return out;
}

static void ares_cb_a(void *blocked, ares_status_t status, size_t timeouts,
    const ares_dns_record_t *rsp)
{
	if (status != ARES_SUCCESS || rsp == nullptr)
		return;
	for (size_t i = 0; i < ares_dns_record_rr_cnt(rsp, ARES_SECTION_ANSWER); ++i) {
		auto rr = ares_dns_record_rr_get_const(rsp, ARES_SECTION_ANSWER, i);
		auto rtype = ares_dns_rr_get_type(rr);
		if (rtype == ARES_REC_TYPE_A)
			*static_cast<bool *>(blocked) = true;
	}
}

static void ares_cb_txt(void *reasonp, ares_status_t status, size_t timeouts,
    const ares_dns_record_t *rsp)
{
	if (status != ARES_SUCCESS || rsp == nullptr)
		return;
	auto &reason = *static_cast<std::string *>(reasonp);
	for (size_t i = 0; i < ares_dns_record_rr_cnt(rsp, ARES_SECTION_ANSWER); ++i) {
		auto rr = ares_dns_record_rr_get_const(rsp, ARES_SECTION_ANSWER, i);
		auto rtype = ares_dns_rr_get_type(rr);
		if (rtype != ARES_REC_TYPE_TXT)
			continue;
		size_t keycnt = 0;
		auto keys = ares_dns_rr_get_keys(rtype, &keycnt);
		if (keycnt < 1)
			continue;
		auto dtype = ares_dns_rr_key_datatype(keys[0]);
		if (dtype == ARES_DATATYPE_ABINP) {
			if (!reason.empty())
				reason += "; ";
			reason += abinp_to_str(rr, keys[0]);
		}
	}
}
#endif

/**
 * An empty string is returned when there is nothing to complain about.
 */
static bool dnsbl_check(const char *src, std::string &reason) try
{
	static constexpr char txt[] = "0123456789abcdef";
	if (g_zone_suffix.empty())
		return true;
	struct in6_addr dst;
	if (inet_pton(AF_INET6, src, &dst) != 1) {
		reason = "E-2076: inet_pton";
		return false;
	}
	std::string dotrep;
	dotrep.resize(64);
	size_t z = 0;
	for (unsigned int i = 16; i-- > 0; ) {
		dotrep[z++] = txt[dst.s6_addr[i] & 0xF];
		dotrep[z++] = '.';
		dotrep[z++] = txt[(dst.s6_addr[i] & 0xF0) >> 4];
		dotrep[z++] = '.';
	}
	dotrep += g_zone_suffix;

#if defined(HAVE_CARES)
	ares_channel_t *channel = nullptr;
	auto cl_1 = make_scope_exit([&]() { ares_destroy(channel); });
	ares_options opts{};
	opts.evsys = ARES_EVSYS_DEFAULT;
	auto status = ares_init_options(&channel, &opts, ARES_OPT_EVENT_THREAD);
	if (status != ARES_SUCCESS)
		return true;
	ares_dns_record_t *req = nullptr;
	auto cl_2 = make_scope_exit([&]() { ares_dns_record_destroy(req); });
	status = ares_dns_record_create(&req, 0, ARES_FLAG_RD,
	         ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
	if (status != ARES_SUCCESS)
		return true;
	status = ares_dns_record_query_add(req, dotrep.c_str(),
	         ARES_REC_TYPE_A, ARES_CLASS_IN);
	if (status != ARES_SUCCESS)
		return true;
	bool blocked = false;
	status = ares_send_dnsrec(channel, req, ares_cb_a, &blocked, nullptr);
	if (status != ARES_SUCCESS)
		return true;
	ares_queue_wait_empty(channel, -1);
	if (!blocked)
		return true;
	reason = "Host in blocklist (no reason text available)";
	ares_dns_record_destroy(req);
	req = nullptr;
	status = ares_dns_record_create(&req, 0, ARES_FLAG_RD,
	         ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
	if (status != ARES_SUCCESS)
		return false;
	status = ares_dns_record_query_add(req, dotrep.c_str(),
	         ARES_REC_TYPE_TXT, ARES_CLASS_IN);
	if (status != ARES_SUCCESS)
		return false;
	status = ares_send_dnsrec(channel, req, ares_cb_txt, &reason, nullptr);
	if (status == ARES_SUCCESS)
		ares_queue_wait_empty(channel, -1);
	return false;
#elif defined(HAVE_LDNS)
	auto dname = ldns_dname_new_frm_str(dotrep.c_str());
	if (dname == nullptr) {
		mlog(LV_ERR, "E-1251: ENOMEM");
		return false;
	}
	ldns_resolver *rsv = nullptr;
	auto status = ldns_resolver_new_frm_file(&rsv, nullptr);
	if (status != LDNS_STATUS_OK) {
		mlog(LV_ERR, "E-1250: ENOMEM");
		return false;
	}
	auto cl_0 = make_scope_exit([&]() { ldns_resolver_deep_free(rsv); });
	ldns_pkt *pkt = nullptr;
	status = ldns_resolver_query_status(&pkt, rsv, dname, LDNS_RR_TYPE_A,
	         LDNS_RR_CLASS_IN, LDNS_RD);
	if (status != LDNS_STATUS_OK)
		/* probably SERVFAIL */
		return true;

	auto cl_0a = make_scope_exit([&]() {
		if (pkt != nullptr)
			ldns_pkt_free(pkt);
	});
	/* NXDOMAIN represented as 0-sized list */
	auto rrlist = ldns_pkt_answer(pkt);
	if (rrlist == nullptr) {
		mlog(LV_DEBUG, "E-1744: no packet");
		return false;
	}
	if (ldns_rr_list_rr_count(rrlist) == 0)
		return true;
	ldns_pkt_free(pkt);
	pkt = nullptr;

	/* In blocklist */
	reason = "Host in blocklist (no reason text available)";
	status = ldns_resolver_query_status(&pkt, rsv, dname, LDNS_RR_TYPE_TXT,
	         LDNS_RR_CLASS_IN, LDNS_RD);
	if (status != LDNS_STATUS_OK)
		return false;

	rrlist = ldns_pkt_answer(pkt);
	if (rrlist == nullptr) {
		mlog(LV_DEBUG, "E-1255: no packet");
		return false;
	}
	size_t i = 0;
	for (ldns_rr *rr; (rr = ldns_rr_list_rr(rrlist, i)) != nullptr; ++i) {
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_TXT)
			continue;
		auto rdf = ldns_rr_rdf(rr, 0);
		if (rdf == nullptr)
			continue;
		auto str = ldns_rdf2str(rdf);
		if (str == nullptr) {
			mlog(LV_ERR, "E-1256: ENOMEM");
			return false;
		}
		auto cl_2 = make_scope_exit([&]() { free(str); });
		if (i == 0)
			/* Overwrite filler string "no reason" */
			reason = str;
		else
			reason += str;
		reason += "; ";
	}
	return false;
#elif defined(HAVE_RES_NQUERYDOMAIN)
	/* BIND8-like API in glibc */
	std::remove_pointer_t<res_state> state;
	uint8_t rsp[1500];
	if (res_ninit(&state) != 0) {
		reason = "E-1735: ENOMEM";
		return false;
	}
	auto cl_0 = make_scope_exit([&]() { res_nclose(&state); });
	/*
	 * NQD works differently from /usr/bin/host; if there are no
	 * entries, it will return -1 rather than an empty result list.
	 *
	 * A-typed lookup needed per RFC 5782 p.3 §2.1.
	 */
	auto ret = res_nquery(&state, dotrep.c_str(), ns_c_in, ns_t_a,
	           rsp, std::size(rsp));
	if (ret <= 0 && (h_errno == HOST_NOT_FOUND || h_errno == NO_DATA))
		return true;

	ret = res_nquery(&state, dotrep.c_str(), ns_c_in, ns_t_txt, rsp, std::size(rsp));
	if (ret <= 0) {
		reason = "Host in blocklist (no detailed reason)";
		return false;
	}

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
		/* All types are t_txt anyway (NQD) */
		auto len = ns_rr_rdlen(rr);
		auto ptr = ns_rr_rdata(rr);
		if (len > 0)
			--len;
		if (ptr + len >= max)
			len = 0;
		if (rrnum == 0)
			reason = std::string_view(reinterpret_cast<const char *>(ptr + 1), len);
		else
			reason += std::string_view(reinterpret_cast<const char *>(ptr + 1), len);
		reason += "; ";
	}
	return false;
#else
	static bool g_zone_warn;
	if (g_zone_suffix.empty())
		return true;
	if (!g_zone_warn)
		mlog(LV_ERR, "Cannot perform DNSBL checks; program was built without DNS resolution. "
			"Possible remedy: Deactivate DNSBL in the config file.");
	g_zone_warn = true;
	return false;
#endif
} catch (const std::bad_alloc &) {
	return false;
}

BOOL SVC_dnsbl_filter(enum plugin_op reason, const struct dlfuncs &data)
{
	if (reason == PLUGIN_FREE) {
#ifdef HAVE_CARES
		ares_library_cleanup();
#endif
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
#ifdef HAVE_CARES
	auto status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS) {
		mlog(LV_ERR, "ares_library_init failed");
		return false;
	}
#endif
	LINK_SVC_API(data);
	// TODO: dnsbl_client=<apikey>.authbl.dq.spamhaus.net=127.0.0.20
	// dnsbl_client=zen.spamhaus.org
	auto cfg = config_file_initd("master.cfg", get_config_path(), nullptr);
	if (cfg != nullptr) {
		auto str = cfg->get_value("dnsbl_client");
		if (str != nullptr) {
			while (*str == '.')
				++str;
			g_zone_suffix = str;
		}
	}
	cfg = config_file_initd("gromox.cfg", get_config_path(), nullptr);
	if (cfg != nullptr) {
		auto str = cfg->get_value("dnsbl_client");
		if (str != nullptr) {
			while (*str == '.')
				++str;
			g_zone_suffix = str;
		}
	}
	if (!register_service("ip_filter_judge", dnsbl_check))
		return false;
	return TRUE;
}
