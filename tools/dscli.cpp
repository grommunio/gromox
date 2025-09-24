// SPDX-License-Identifier: AGPL-3.0-or-later  
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <unistd.h>
#include <utility>
#include <tinyxml2.h>
#include <curl/curl.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/util.hpp>
#if defined(HAVE_CARES)
#	include <ares.h>
#	define HAVE_NS 1
#elif defined(HAVE_RES_NQUERYDOMAIN)
#	include <netdb.h>
#	include <resolv.h>
#	include <arpa/nameser.h>
#	define HAVE_NS 1
#endif

struct curl_del {
	void operator()(CURL *x) const { curl_easy_cleanup(x); }
	void operator()(curl_slist *x) const { curl_slist_free_all(x); }
};

using namespace std::string_literals;
using namespace gromox;

static bool g_tty, g_verbose;
static unsigned int g_eas_mode, g_tb_mode;
static constexpr char g_user_agent[] = "Microsoft Office/16"; /* trigger MH codepath */
static char *g_disc_host, *g_disc_url, *g_emailaddr, *g_legacydn, *g_auth_user;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'h', HXTYPE_STRING, &g_disc_host, nullptr, nullptr, 0, "Host to contact (in absence of -e/-H)"},
	{nullptr, 'H', HXTYPE_STRING, &g_disc_url, nullptr, nullptr, 0, "Full autodiscover URL to use"},
	{nullptr, 'e', HXTYPE_STRING, &g_emailaddr, nullptr, nullptr, 0, "Perform discovery for this specific store (username/emailaddr)", "USERNAME"},
	{nullptr, 'u', HXTYPE_STRING, &g_auth_user, nullptr, nullptr, 0, "Use a distinct user for authentication", "USERNAME"},
	{nullptr, 'v', HXTYPE_NONE, &g_verbose, nullptr, nullptr, 0, "Be verbose, dump HTTP and XML"},
	{nullptr, 'x', HXTYPE_STRING, &g_legacydn, nullptr, nullptr, 0, "Legacy DN"},
	{"eas", 0, HXTYPE_NONE, &g_eas_mode, nullptr, nullptr, 0, "Request EAS response"},
	{"ac", 0, HXTYPE_NONE, &g_tb_mode, {}, {}, 0, "Perform Mail Autoconfig request instead of AutoDiscover"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

#ifndef HAVE_NS
static void dnssrv_notbuilt()
{
	fprintf(stderr, "%sThis version was not built with DNS SRV analysis.%s\n",
	        g_tty ? "\e[1;33m" : "", g_tty ? "\e[0m" : "");
}
#endif

static tinyxml2::XMLElement *adc(tinyxml2::XMLElement *e,
    const char *tag, const char *val = nullptr)
{
	auto ch = e->InsertNewChildElement(tag);
	if (val != nullptr)
		ch->SetText(val);
	return ch;
}

static std::unique_ptr<tinyxml2::XMLPrinter>
oxd_make_request(const char *email, const char *dn)
{
	tinyxml2::XMLDocument doc;
	doc.InsertEndChild(doc.NewDeclaration());
	auto root = doc.NewElement("Autodiscover");
	doc.InsertEndChild(root);
	root->SetAttribute("xmlns", "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006");
	auto req = adc(root, "Request");
	if (email != nullptr)
		adc(req, "EMailAddress", email);
	if (dn != nullptr)
		adc(req, "LegacyDN", dn);
	adc(req, "AcceptableResponseSchema", g_eas_mode ?
		"http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006" :
		"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a");

	auto prt = std::make_unique<tinyxml2::XMLPrinter>(nullptr, false, 0);
	doc.Print(prt.get());
	return prt;
	/* tinyxml has no move ctors and no copy ctors, ugh */
}

static size_t oxd_write_null(char *, size_t s, size_t n, void *)
{
	return s * n;
}

static bool oxd_validate_url(CURL *ch, const tinyxml2::XMLElement *elem,
    std::unordered_set<std::string> &seen_urls)
{
	if (elem == nullptr)
		return true;
	auto node = elem->FirstChild();
	if (node == nullptr)
		return true;
	auto url = node->Value();
	if (url == nullptr)
		return true;
	if (seen_urls.find(url) != seen_urls.end())
		return true;
	seen_urls.emplace(url);
	auto ret = curl_easy_setopt(ch, CURLOPT_URL, url);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_perform(ch);
	if (ret != CURLE_OK) {
		fprintf(stderr, "%s: %s\n", url, curl_easy_strerror(ret));
		return false;
	}
	return true;
}

static bool oxd_is_autoconf_response(const std::string &xml_in)
{
	/* https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat */
	tinyxml2::XMLDocument doc;
	auto ret = doc.Parse(xml_in.c_str(), xml_in.size());
	if (ret != tinyxml2::XML_SUCCESS)
		return false;
	auto node = doc.RootElement();
	if (node == nullptr)
		return false;
	auto name = node->Name();
	if (name == nullptr || strcasecmp(name, "clientConfig") != 0)
		return false;
	return true;
}

static bool oxd_is_autodiscover_response(const std::string &xml_in,
    tinyxml2::XMLDocument &doc)
{
	auto ret = doc.Parse(xml_in.c_str(), xml_in.size());
	if (ret != tinyxml2::XML_SUCCESS)
		return false;
	auto node = doc.RootElement();
	if (node == nullptr)
		return false;
	auto name = node->Name();
	if (name == nullptr || strcasecmp(name, "Autodiscover") != 0)
		return false;
	node = node->FirstChildElement("Response");
	if (node == nullptr)
		return false;
	node = node->FirstChildElement("Account");
	if (node == nullptr)
		return false;
	return true;
}

static bool oxd_validate_response(const tinyxml2::XMLDocument &doc)
{
	std::unique_ptr<CURL, curl_del> chp(curl_easy_init());
	if (chp == nullptr) {
		perror("curl_easy_init: ENOMEM\n");
		return false;
	}
	auto cc = curl_easy_setopt(chp.get(), CURLOPT_WRITEFUNCTION, oxd_write_null);
	if (cc != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt: %s\n", curl_easy_strerror(cc));
		return false;
	}
	cc = curl_easy_setopt(chp.get(), CURLOPT_USERAGENT, g_user_agent);
	if (cc != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt: %s\n", curl_easy_strerror(cc));
		return false;
	}

	std::unordered_set<std::string> seen_urls;
	bool ok = true;
	for (auto node = doc.RootElement()->FirstChildElement(); node != nullptr;
	     node = node->NextSiblingElement()) {
		auto name = node->Name();
		if (name == nullptr || strcasecmp(name, "Protocol") != 0)
			continue;
		for (const char *s : {"OOFUrl", "OABUrl", "ASUrl", "EwsUrl", "EmwsUrl", "EcpUrl"}) {
			auto elem = node->FirstChildElement(s);
			if (!oxd_validate_url(chp.get(), elem, seen_urls))
				ok = false;
		}
		for (const char *s : {"MailStore", "AddressBook"}) {
			auto elem = node->FirstChildElement(s);
			if (elem == nullptr)
				continue;
			for (const char *t : {"InternalUrl", "ExternalUrl"})
				if (!oxd_validate_url(chp.get(), elem->FirstChildElement(t), seen_urls))
					ok = false;
		}
	}
	return ok;
}

static size_t oxd_write(char *ptr, size_t size, size_t nemb, void *udata)
{
	static_cast<std::string *>(udata)->append(ptr, size * nemb);
	return size * nemb;
}

#if defined(HAVE_CARES)
static void ares_cb(void *arg, ares_status_t status, size_t timeouts, const ares_dns_record_t *rsp) try
{
	if (status != ARES_SUCCESS || rsp == nullptr)
		return;
	auto &target = *static_cast<std::string *>(arg);
	for (size_t i = 0; i < ares_dns_record_rr_cnt(rsp, ARES_SECTION_ANSWER); ++i) {
		auto rr = ares_dns_record_rr_get_const(rsp, ARES_SECTION_ANSWER, i);
		auto rtype = ares_dns_rr_get_type(rr);
		if (rtype != ARES_REC_TYPE_SRV)
			continue;
		size_t keycnt = 0;
		auto keys = ares_dns_rr_get_keys(rtype, &keycnt);
		if (keycnt < 4 ||
		    ares_dns_rr_key_datatype(keys[2]) != ARES_DATATYPE_U16 ||
		    ares_dns_rr_key_datatype(keys[3]) != ARES_DATATYPE_NAME)
			continue;
		target = ares_dns_rr_get_str(rr, keys[3]);
		if (target.size() > 0 && target.back() == '.')
			target.pop_back();
		target += ":" + std::to_string(ares_dns_rr_get_u16(rr, keys[2]));
		break;
	}
} catch (const std::bad_alloc &) {
}

static std::string domain_to_oxsrv(const char *dom)
{
	std::string target;
	auto status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS)
		return target;
	auto cl_0 = HX::make_scope_exit(ares_library_cleanup);
	ares_channel_t *channel = nullptr;
	auto cl_1 = HX::make_scope_exit([&]() { ares_destroy(channel); });
	ares_options opts{};
	opts.evsys = ARES_EVSYS_DEFAULT;
	status = ares_init_options(&channel, &opts, ARES_OPT_EVENT_THREAD);
	if (status != ARES_SUCCESS)
		return target;
	ares_dns_record_t *req = nullptr;
	auto cl_2 = HX::make_scope_exit([&]() { ares_dns_record_destroy(req); });
	status = ares_dns_record_create(&req, 0, ARES_FLAG_RD,
	         ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
	if (status != ARES_SUCCESS)
		return target;
	status = ares_dns_record_query_add(req, ("_autodiscover._tcp."s + dom).c_str(),
	         ARES_REC_TYPE_SRV, ARES_CLASS_IN);
	if (status != ARES_SUCCESS)
		return target;
	status = ares_send_dnsrec(channel, req, ares_cb, &target, nullptr);
	if (status != ARES_SUCCESS)
		return target;
	ares_queue_wait_empty(channel, -1);
	return target;
}
#elif defined(HAVE_RES_NQUERYDOMAIN)
static std::string domain_to_oxsrv(const char *dom)
{
	std::remove_pointer_t<res_state> state;
	uint8_t rsp[1500];

	if (res_ninit(&state) != 0)
		throw std::bad_alloc();
	auto cl_0 = HX::make_scope_exit([&]() { res_nclose(&state); });
	auto ret = res_nquerydomain(&state, "_autodiscover._tcp", dom, ns_c_in,
	           ns_t_srv, rsp, std::size(rsp));
	if (ret <= 0)
		return {};

	ns_msg handle;
	if (ns_initparse(rsp, ret, &handle) != 0)
		return {};
	if (ns_msg_getflag(handle, ns_f_rcode) != ns_r_noerror)
		return {};

	ns_rr rr;
	if (ns_parserr(&handle, ns_s_an, 0, &rr) != 0)
		return {};
	if (ns_rr_type(rr) != ns_t_srv)
		return {};
	auto ptr = ns_rr_rdata(rr);
	ptr += 3 * sizeof(uint16_t);
	auto port = ns_get16(ptr - sizeof(uint16_t));
	char hostname[256]{};
	ret = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ptr,
	      hostname, std::size(hostname));
	if (ret <= 0)
		return {};
	return hostname + ":"s + std::to_string(port);
}
#endif

static std::vector<std::string> autodisc_url()
{
#define xmlpath "/Autodiscover/Autodiscover.xml"
#define tbac_path "/.well-known/autoconfig/mail/config-v1.1.xml"
	if (g_disc_url != nullptr)
		return {g_disc_url};
	if (g_disc_host != nullptr) {
		if (g_tb_mode)
			return {"https://"s + g_disc_host + tbac_path "?emailaddress=" + g_emailaddr};
		return {"https://"s + g_disc_host + xmlpath};
	}
	if (g_emailaddr != nullptr) {
		auto p = strchr(g_emailaddr, '@');
		if (p != nullptr) {
			auto dom = p + 1;
			/*
			 * In the future, TB may look at _imap._tcp, but who
			 * knows when that is going to happen.
			 */
			if (g_tb_mode)
				return {"https://"s + dom + tbac_path "?emailaddress=" + g_emailaddr};
			std::vector<std::string> out;
			out.emplace_back("https://"s + dom + xmlpath);
			out.emplace_back("https://autodiscover."s + dom + xmlpath);
#ifdef HAVE_NS
			auto srv = domain_to_oxsrv(dom);
			if (!srv.empty())
				out.emplace_back("https://"s + srv + xmlpath);
#else
			dnssrv_notbuilt();
#endif
			return out;
		}
	}
	return {"https://localhost/" xmlpath};
#undef xmlpath
}

static CURLcode setopts_base(CURL *ch, std::string &output_buffer)
{
	auto ret = curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_TCP_NODELAY, 0L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_WRITEDATA, &output_buffer);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, oxd_write);
	if (ret != CURLE_OK)
		return ret;
	if (g_verbose) {
		ret = curl_easy_setopt(ch, CURLOPT_VERBOSE, 1L);
		if (ret != CURLE_OK)
			return ret;
	}
	ret = curl_easy_setopt(ch, CURLOPT_USERAGENT, g_user_agent);
	if (ret != CURLE_OK)
		return ret;
	return CURLE_OK;
}

static CURLcode setopts_oxd(CURL *ch, const char *password, curl_slist *hdrs,
    tinyxml2::XMLPrinter &xml_request, std::string &xml_response)
{
	auto ret = setopts_base(ch, xml_response);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_USERNAME, g_auth_user != nullptr ?
	      g_auth_user : g_emailaddr != nullptr ? g_emailaddr : g_legacydn);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_PASSWORD, password);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_HTTPHEADER, hdrs);
	if (ret != CURLE_OK)
		return ret;
	size_t rqlen = static_cast<std::make_unsigned_t<decltype(xml_request.CStrSize())>>(xml_request.CStrSize());
	if (rqlen > 0)
		--rqlen;
	ret = curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE_LARGE, rqlen);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_POSTFIELDS, xml_request.CStr());
	if (ret != CURLE_OK)
		return ret;
	return CURLE_OK;
}

static int tb_main(const char *email)
{
	std::string xml_response;
	auto ds_urls = autodisc_url();
	assert(!ds_urls.empty());
	std::unique_ptr<CURL, curl_del> chp(curl_easy_init());
	auto ch = chp.get();
	auto result = setopts_base(ch, xml_response);
	if (result != CURLE_OK ||
	    (result = curl_easy_setopt(ch, CURLOPT_URL, ds_urls[0].c_str()))) {
		fprintf(stderr, "curl_easy_setopt(): %s\n", curl_easy_strerror(result));
		return EXIT_FAILURE;
	}
	result = curl_easy_perform(ch);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform(): %s\n", curl_easy_strerror(result));
		return EXIT_FAILURE;
	}
	if (g_verbose) {
		fprintf(stderr, "* Response body:\n");
		printf("%s\n", xml_response.c_str());
	}
	if (!oxd_is_autoconf_response(xml_response)) {
		if (!g_verbose)
			fprintf(stderr, "* No usable response; use -v option for verbose results.\n");
		return EXIT_FAILURE;
	}
	fprintf(stderr, "* Response has validated\n");
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	g_tty = isatty(STDERR_FILENO);
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	auto cl_args = HX::make_scope_exit([]() {
		free(g_disc_host);
		free(g_disc_url);
		free(g_emailaddr);
		free(g_legacydn);
	});
	if (g_disc_url != nullptr && g_disc_host != nullptr) {
		fprintf(stderr, "Can only use one of -H and -h.\n");
		return EXIT_FAILURE;
	}
	if (g_tb_mode) {
		if (g_emailaddr == nullptr) {
			fprintf(stderr, "The -e argument is required for Thunderbird mode.\n");
			return EXIT_FAILURE;
		}
		return tb_main(g_emailaddr);
	}
	auto password = getenv("PASS");
	if (password == nullptr) {
		fprintf(stderr, "A password is required to make an AutoDiscover request. Use the PASS environment variable.\n");
		return EXIT_FAILURE;
	} else if (g_emailaddr == nullptr && g_legacydn == nullptr) {
		fprintf(stderr, "At least one of -e or -x is required to make an AutoDiscover request.\n");
		return EXIT_FAILURE;
	}

	auto xml_request = oxd_make_request(g_emailaddr, g_legacydn);
	std::string xml_response;
	tinyxml2::XMLDocument xd_response;
	std::unique_ptr<CURL, curl_del> chp(curl_easy_init());
	std::unique_ptr<curl_slist, curl_del> hdrs(curl_slist_append(nullptr, "Content-Type: text/xml"));
	auto ch = chp.get();
	auto result = setopts_oxd(ch, password, hdrs.get(), *xml_request, xml_response);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(): %s\n", curl_easy_strerror(result));
		return EXIT_FAILURE;
	}
	if (g_verbose)
		fprintf(stderr, "* Request body:\n%s\n\n", xml_request->CStr());
	for (const auto &url : autodisc_url()) {
		fprintf(stderr, "* Trying %s\n", url.c_str());
		result = curl_easy_setopt(ch, CURLOPT_URL, url.c_str());
		if (result != CURLE_OK)
			return result;
		result = curl_easy_perform(ch);
		if (result != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform <%s>: %s\n", url.c_str(), curl_easy_strerror(result));
			return EXIT_FAILURE;
		}
		long status = 0;
		result = curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &status);
		if (result != CURLE_OK || status >= 400)
			fprintf(stderr, "curl_easy_perform <%s>: HTTP %ld\n",
				url.c_str(), status);
		else if (oxd_is_autodiscover_response(xml_response, xd_response))
			break;
		if (g_verbose)
			fprintf(stderr, "* Response body:\n%s\n", xml_response.c_str());
		xml_response.clear();
	}
	if (g_verbose) {
		fprintf(stderr, "* Response body:\n");
		printf("%s\n", xml_response.c_str());
	}
	if (xml_response.empty()) {
		if (!g_verbose)
			fprintf(stderr, "* No usable response; use -v option for verbose results.\n");
		return EXIT_FAILURE;
	}
	auto ret = oxd_validate_response(xd_response);
	if (!ret) {
		if (!g_verbose)
			fprintf(stderr, "* use -v option for verbose results.\n");
		return EXIT_FAILURE;
	}
	fprintf(stderr, "* Response has validated\n");
	return EXIT_SUCCESS;
}
