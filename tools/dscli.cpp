// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <netdb.h>
#include <resolv.h>
#include <string>
#include <unordered_set>
#include <unistd.h>
#include <utility>
#include <tinyxml2.h>
#include <arpa/nameser.h>
#include <curl/curl.h>
#include <libHX/option.h>
#include <gromox/scope.hpp>

struct curl_del {
	void operator()(CURL *x) const { curl_easy_cleanup(x); }
	void operator()(curl_slist *x) const { curl_slist_free_all(x); }
};

using namespace std::string_literals;
using namespace gromox;

static bool g_tty;
static constexpr char g_user_agent[] = "Microsoft Office/16"; /* trigger MH codepath */
static char *g_disc_host, *g_disc_url, *g_emailaddr, *g_password, *g_legacydn;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'h', HXTYPE_STRING, &g_disc_host, nullptr, nullptr, 0, "Host to contact (in absence of -e/-H)"},
	{nullptr, 'H', HXTYPE_STRING, &g_disc_url, nullptr, nullptr, 0, "Full autodiscover URL to use"},
	{nullptr, 'e', HXTYPE_STRING, &g_emailaddr, nullptr, nullptr, 0, "E-mail address for user lookup"},
	{nullptr, 'p', HXTYPE_STRING, &g_password, nullptr, nullptr, 0, "Use the $PASS environment variable for password"},
	{nullptr, 'x', HXTYPE_STRING, &g_legacydn, nullptr, nullptr, 0, "Legacy DN"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

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
	auto decl = doc.NewDeclaration();
	doc.InsertEndChild(decl);
	auto root = doc.NewElement("Autodiscover");
	doc.InsertEndChild(root);
	root->SetAttribute("xmlns", "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006");
	auto req = adc(root, "Request");
	if (email != nullptr)
		adc(req, "EMailAddress", email);
	if (dn != nullptr)
		adc(req, "LegacyDN", dn);
	adc(req, "AcceptableResponseSchema", "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a");

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

static bool oxd_validate_response(const std::string &xml_in)
{
	tinyxml2::XMLDocument doc;
	auto ret = doc.Parse(xml_in.c_str(), xml_in.size());
	if (ret != tinyxml2::XML_SUCCESS) {
		fprintf(stderr, "Failed to xmlparse response\n");
		return false;
	}
	auto node = doc.RootElement();
	if (node == nullptr) {
		fprintf(stderr, "No Autodiscover root element\n");
		return false;
	}
	auto name = node->Name();
	if (name == nullptr || strcasecmp(name, "Autodiscover") != 0) {
		fprintf(stderr, "No Autodiscover root element\n");
		return false;
	}
	node = node->FirstChildElement("Response");
	if (node == nullptr) {
		fprintf(stderr, "No Response element\n");
		return false;
	}
	node = node->FirstChildElement("Account");
	if (node == nullptr) {
		fprintf(stderr, "No Account element\n");
		return false;
	}

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
	for (node = node->FirstChildElement(); node != nullptr; node = node->NextSiblingElement()) {
		name = node->Name();
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

#ifdef HAVE_RES_NQUERYDOMAIN
static std::string domain_to_oxsrv(const char *dom)
{
	std::remove_pointer_t<res_state> state;
	uint8_t rsp[1500];

	if (res_ninit(&state) != 0)
		throw std::bad_alloc();
	auto cl_0 = make_scope_exit([&]() { res_nclose(&state); });
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
	char hostname[256];
	ret = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ptr,
	      hostname, std::size(hostname));
	if (ret == 0)
		return {};
	return std::string(hostname, ret) + ":" + std::to_string(port);
}
#endif

static std::string autodisc_url()
{
#define xmlpath "/Autodiscover/Autodiscover.xml"
	if (g_disc_url != nullptr)
		return g_disc_url;
	if (g_disc_host != nullptr)
		return "https://"s + g_disc_host + xmlpath;
	if (g_emailaddr != nullptr) {
		auto p = strchr(g_emailaddr, '@');
		if (p != nullptr) {
			auto dom = p + 1;
#ifdef HAVE_RES_NQUERYDOMAIN
			auto srv = domain_to_oxsrv(dom);
			if (!srv.empty())
				return "https://" + srv + xmlpath;
			fprintf(stderr, "%sDNS SRV entry \"_autodiscover._tcp.%s\" is missing!%s\n",
			        g_tty ? "\e[1;33m" : "", dom, g_tty ? "\e[0m" : "" /* ]] */);
#else
			fprintf(stderr, "%sThis version was not built with DNS SRV analysis.%s\n",
			        g_tty ? "\e[1;31m" : "", g_tty ? "\e[0m" : "");
#endif
			return "https://autodiscover."s + dom + xmlpath;
		}
	}
	return "https://localhost/" xmlpath;
#undef xmlpath
}

static CURLcode setopts(CURL *ch, const char *password, curl_slist *hdrs,
    tinyxml2::XMLPrinter &xml_request, std::string &xml_response)
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
	ret= curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_USERNAME, g_emailaddr != nullptr ?
	      g_emailaddr : g_legacydn);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_PASSWORD, password);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_HTTPHEADER, hdrs);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE_LARGE, xml_request.CStrSize());
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_POSTFIELDS, xml_request.CStr());
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_WRITEDATA, &xml_response);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, oxd_write);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_VERBOSE, 1L);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_USERAGENT, g_user_agent);
	if (ret != CURLE_OK)
		return ret;
	ret = curl_easy_setopt(ch, CURLOPT_URL, autodisc_url().c_str());
	if (ret != CURLE_OK)
		return ret;
	return CURLE_OK;
}

int main(int argc, const char **argv)
{
	g_tty = isatty(STDERR_FILENO);
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_args = make_scope_exit([]() {
		free(g_disc_host);
		free(g_disc_url);
		free(g_emailaddr);
		free(g_password);
		free(g_legacydn);
	});
	if (g_disc_url != nullptr && g_disc_host != nullptr) {
		fprintf(stderr, "Can only use one of -H and -h.\n");
		return EXIT_FAILURE;
	}
	auto password = g_password != nullptr ? g_password : getenv("PASS");
	if (password == nullptr) {
		fprintf(stderr, "No password specified. Use the $PASS environment variable.\n");
		return EXIT_FAILURE;
	} else if (g_emailaddr == nullptr && g_legacydn == nullptr) {
		fprintf(stderr, "At least one of -e or -x is required.\n");
		return EXIT_FAILURE;
	}

	auto xml_request = oxd_make_request(g_emailaddr, g_legacydn);
	std::string xml_response;
	std::unique_ptr<CURL, curl_del> chp(curl_easy_init());
	std::unique_ptr<curl_slist, curl_del> hdrs(curl_slist_append(nullptr, "Content-Type: text/xml"));
	auto ch = chp.get();
	auto result = setopts(ch, password, hdrs.get(), *xml_request, xml_response);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(): %s\n", curl_easy_strerror(result));
		return EXIT_FAILURE;
	}
	printf("* Request body:\n%s\n\n", xml_request->CStr());
	result = curl_easy_perform(ch);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform(): %s\n", curl_easy_strerror(result));
		return EXIT_FAILURE;
	}
	printf("* Response body:\n%s\n", xml_response.c_str());
	if (!oxd_validate_response(xml_response))
		return EXIT_FAILURE;
	fprintf(stderr, "* Response has validated\n");
	return EXIT_SUCCESS;
}
