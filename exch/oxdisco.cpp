// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include<functional>
#include <tinyxml2.h>
#include <fmt/core.h>
#include <fmt/printf.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/hpm_common.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/mysql_adaptor.hpp>
#include "mysql_adaptor/sql2.hpp"

using namespace std::string_literals;
using namespace gromox;
using namespace tinyxml2;

namespace {

enum class adv_setting {
	no, yes, not_old_mso, new_mso_only,
};

class OxdiscoPlugin {
	public:
	OxdiscoPlugin();

	BOOL proc(int, const void*, uint64_t);
	static BOOL preproc(int);

	struct _mysql {
		_mysql();

		decltype(mysql_adaptor_get_user_displayname) *get_user_displayname;
		decltype(mysql_adaptor_get_user_ids) *get_user_ids;
		decltype(mysql_adaptor_get_domain_ids) *get_domain_ids;
		decltype(mysql_adaptor_scndstore_hints) *scndstore_hints;
		decltype(mysql_adaptor_get_homeserver) *get_homeserver;
	} mysql; // mysql adaptor function pointers

	private:
	std::string x500_org_name = "Gromox default";
	uint server_id; // Hash of the name of the mail server
	std::string RedirectAddr; // Domain to perform Autodiscover
	std::string RedirectUrl; // URL for a subsequent Autodiscover request
	std::string host_id;
	int request_logging = 0; // 0 = none, 1 = request data
	int response_logging = 0; // 0 = none, 1 = response data
	int pretty_response = 0; // 0 = compact output, 1 = pretty printed response
	adv_setting m_advertise_rpch = adv_setting::yes, m_advertise_mh = adv_setting::yes;
	bool m_validate_scndrequest = true;

	void loadConfig();
	static void writeheader(int, int, size_t);
	BOOL die(int, const char *, const char *) const;
	BOOL resp(int, const char *, const char *, const char *) const;
	int resp_web(tinyxml2::XMLElement *, const char *, const char *, const char *ua) const;
	int resp_eas(tinyxml2::XMLElement *, const char *) const;
	static void resp_mh(XMLElement *, const char *home, const char *dom, const std::string &, const std::string &, const std::string &, const std::string &, bool);
	void resp_rpch(XMLElement *, const char *, const std::string &, const std::string &, const std::string &, const std::string &, bool) const;
	BOOL resp_autocfg(int, const char *) const;
	static tinyxml2::XMLElement *add_child(tinyxml2::XMLElement *, const char *, const char *);
	static tinyxml2::XMLElement *add_child(tinyxml2::XMLElement *, const char *, const std::string &);
	static const char *gtx(tinyxml2::XMLElement &, const char *);
	std::string get_redirect_addr(const char *) const;
	BOOL username_to_essdn(const char *, char *, size_t, int &, int &) const;
	BOOL domainname_to_essdn(const char *, char *, size_t, int &) const;
	static bool advertise_prot(enum adv_setting, const char *ua);
	static std::string get_deploymentid(int, const char *);
	static void get_hex_string(const char *, char *);
};

}

DECLARE_HPM_API();

static constexpr char
	response_xmlns[] = "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006",
	response_outlook_xmlns[] = "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a",
	oxd_server_version[] = "73C0834F", /* 15.00.0847.4040 */
	response_mobile_xmlns[] = "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006",
	msas_base_url[] = "https://{}/Microsoft-Server-ActiveSync",
	mailbox_base_url[] = "https://{}/mapi/{}/?MailboxId={}@{}",
	ews_base_url[] = "https://{}/EWS/{}",
	oab_base_url[] = "https://{}/OAB/",
	server_base_dn[] = "/o={}/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn={}@{}",
	public_folder[] = "Public Folder",
	public_folder_email[] = "public.folder.root@",
	bad_address_code[] = "501",
	bad_address_msg[] = "Bad Address",
	invalid_request_code[] = "600",
	invalid_request_msg[] = "Invalid Request",
	provider_unavailable_code[] = "601",
	provider_unavailable_msg[] = "Provider is not available",
	server_error_code[] = "603",
	server_error_msg[] = "Server Error",
	exchange_asmx[] = "Exchange.asmx",
	header_templ[] =
		"HTTP/1.1 {} {}\r\n"
		"Content-Type: text/xml\r\n"
		"Content-Length: {}\r\n\r\n",
	error_templ[] =
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">"
			"<Response>"
				"<Error Time=\"{}\" Id=\"{}\">"
					"<ErrorCode>{}</ErrorCode>"
					"<Message>{}</Message>"
					"<DebugData />"
				"</Error>"
			"</Response>"
		"</Autodiscover>";

static BOOL unauthed(int);

OxdiscoPlugin::OxdiscoPlugin()
{
	host_id = get_host_ID();
	loadConfig();
	server_id = std::hash<std::string>{}(host_id);

	mlog(LV_DEBUG, "[oxdisco] org %s RedirectAddr %s RedirectUrl %s request_logging %d response_logging %d pretty_response %d",
		x500_org_name.empty() ? "empty" : x500_org_name.c_str(),
		RedirectAddr.empty() ? "empty" : RedirectAddr.c_str(),
		RedirectUrl.empty() ? "empty" : RedirectUrl.c_str(),
		request_logging, response_logging, pretty_response);
}

/**
 * @brief      Preprocess request
 *
 * @param      ctx_id  Request context identifier
 *
 * @return     TRUE if the request is to be processed by this plugin, false otherwise
 */
BOOL OxdiscoPlugin::preproc(int ctx_id)
{
	auto req = get_request(ctx_id);
// In some cases the clients may issue unauthed GET requests
// In such case the plugin issues redirect in response
//	if (strcasecmp(req->method, "POST") != 0)
//		/* emit("All requests must be POST"); */
//		return false;
	char uri[1024];
	req->f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	size_t len = req->f_request_uri.read(uri, arsizeof(uri) - 1);
	if (len == MEM_END_OF_FILE)
		return false;
	uri[len] = '\0';
	if (strcasecmp(uri, "/autodiscover/autodiscover.xml") != 0 &&
			strncasecmp(uri, "/.well-known/autoconfig/mail/config-v1.1.xml", 40) != 0)
		return false;
	return TRUE;
}

/**
 * @brief      Proccess request
 *
 * Checks checks the request data, processes the request and
 * writes the response.
 *
 * @param      ctx_id   Request context identifier
 * @param      content  Request data
 * @param      len      Length of request data
 *
 * @return     TRUE if request was handled, false otherwise
 */
BOOL OxdiscoPlugin::proc(int ctx_id, const void *content, uint64_t len) try
{
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if(!auth_info.b_authed)
		return unauthed(ctx_id);

	char uri[1024];
	auto req = get_request(ctx_id);
	req->f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	size_t l = req->f_request_uri.read(uri, arsizeof(uri) - 1);
	if (l == MEM_END_OF_FILE)
		return false;
	uri[l] = '\0';
	if (strncasecmp(uri, "/.well-known/autoconfig/mail/config-v1.1.xml", 44) == 0 &&
	    (uri[44] == '\0' || uri[44] == '?')) {
		if (strncmp(&uri[44], "?emailaddress=", 14) != 0)
			return resp_autocfg(ctx_id, auth_info.username);
		auto username = &uri[44+14];
		/* still need hex decoding */
		return resp_autocfg(ctx_id, username);
	}

	XMLDocument doc;
	if (doc.Parse(static_cast<const char *>(content), len) != XML_SUCCESS)
		return die(ctx_id, invalid_request_code, invalid_request_msg);

	auto root = doc.RootElement();
	auto name = root != nullptr ? root->Name() : nullptr;
	if (name == nullptr || strcasecmp(name, "Autodiscover") != 0) {
		return die(ctx_id, invalid_request_code, invalid_request_msg);
	}

	if (request_logging > 0)
		mlog(LV_DEBUG, "[oxdisco] incoming: %s", static_cast<const char *>(content));

	auto req_node = root->FirstChildElement("Request");
	if (req_node == nullptr)
		return die(ctx_id, invalid_request_code, invalid_request_msg);

	// TODO LegacyDN element if email is not available?
	auto email = gtx(*req_node, "EMailAddress");
	if (email == nullptr || strchr(email, '@') == nullptr)
		return die(ctx_id, invalid_request_code, invalid_request_msg);

	auto ars = gtx(*req_node, "AcceptableResponseSchema");
	if (ars == nullptr)
		return die(ctx_id, provider_unavailable_code, provider_unavailable_msg);

	if (m_validate_scndrequest && strcasecmp(email, auth_info.username) != 0 &&
	    strncasecmp(email, public_folder_email, 19) != 0) {
		int auth_user_id = 0, auth_domain_id = 0;
		mysql.get_user_ids(auth_info.username, &auth_user_id, &auth_domain_id, nullptr);
		std::vector<sql_user> hints;
		auto err = mysql.scndstore_hints(auth_user_id, hints);
		if (err != 0) {
			mlog(LV_ERR, "oxdisco: error retrieving secondary store hints: %s", strerror(err));
			return -1;
		}
		if (std::none_of(hints.begin(), hints.end(),
		    [&](const sql_user &u) { return strcasecmp(u.username.c_str(), email) == 0; }))
			/* authuser has no scndstore matching email */
			return die(ctx_id, bad_address_code, (bad_address_msg +
			       " (403 Permission Denied)"s).c_str());
	}

	if (!RedirectAddr.empty() || !RedirectUrl.empty()) {
		mlog(LV_DEBUG, "[oxdisco] send redirect response");
	}
	return resp(ctx_id, auth_info.username, email, ars);
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1700: ENOMEM\n");
	return die(ctx_id, server_error_code, server_error_msg);
}

static constexpr cfg_directive autodiscover_cfg_defaults[] = {
	{"RedirectAddr", ""},
	{"RedirectUrl", ""},
	{"oxdisco_advertise_mh", "yes"},
	{"oxdisco_advertise_rpch", "yes"},
	{"oxdisco_validate_scndrequest", "yes", CFG_BOOL},
	{"pretty_response", "0", CFG_BOOL},
	{"request_logging", "0", CFG_BOOL},
	{"response_logging", "0", CFG_BOOL},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static enum adv_setting parse_adv(const char *s)
{
	if (strcasecmp(s, "no") == 0 || strcmp(s, "0") == 0)
		return adv_setting::no;
	else if (strcasecmp(s, "not_old_mso") == 0)
		return adv_setting::not_old_mso;
	else if (strcasecmp(s, "new_mso_only") == 0)
		return adv_setting::new_mso_only;
	return adv_setting::yes;
}

/**
 * @brief      Loads configuration file
 *
 */
void OxdiscoPlugin::loadConfig()
{
	auto c = config_file_initd("autodiscover.ini", get_config_path(), nullptr);
	if (c != nullptr) {
		auto s = c->get_value("organization");
		if (s != nullptr)
			x500_org_name = s;
		s = c->get_value("hostname");
		if (s != nullptr)
			host_id = s;
		s = c->get_value("advertise_mh");
		if (s != nullptr)
			m_advertise_mh = parse_adv(s);
		s = c->get_value("advertise_rpch");
		if (s != nullptr)
			m_advertise_rpch = parse_adv(s);
	}
	/* If there is no autodiscover.cfg, we have an old system and are done. */
	c = config_file_initd("autodiscover.cfg", get_config_path(), nullptr);
	if (c == nullptr || *c->file_name == '\0')
		return;
	/* If there is autodiscover.cfg, ignore autodiscover.ini */
	c = config_file_initd("autodiscover.cfg", get_config_path(), autodiscover_cfg_defaults);
	x500_org_name = c->get_value("x500_org_name");
	RedirectAddr = c->get_value("RedirectAddr");
	RedirectUrl = c->get_value("RedirectUrl");
	request_logging = c->get_ll("request_logging");
	response_logging = c->get_ll("response_logging");
	pretty_response = c->get_ll("pretty_response");
	m_advertise_mh = parse_adv(c->get_value("oxdisco_advertise_mh"));
	m_advertise_rpch = parse_adv(c->get_value("oxdisco_advertise_rpch"));
	m_validate_scndrequest = c->get_ll("oxdisco_validate_scndrequest");
	auto s = c->get_value("oxdisco_exonym");
	if (s != nullptr)
		host_id = s;
}

/**
 * @brief      Return authentication error
 *
 * @param      ctx_id  Request context identifier
 *
 * @return     TRUE if response was written successfully, false otherwise
 */
static BOOL unauthed(int ctx_id)
{
	static constexpr char content[] =
		"HTTP/1.1 401 Unauthorized\r\n"
		"Content-Length: 0\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Connection: Keep-Alive\r\n"
		"WWW-Authenticate: Basic realm=\"autodiscover realm\"\r\n"
		"\r\n";
	return write_response(ctx_id, content, arsizeof(content));
}

/**
 * @brief      Write basic response header
 *
 * @param      ctx_id          Request context identifier
 * @param      code            HTTP response code
 * @param      content_length  Length of the response body
 */
void OxdiscoPlugin::writeheader(int ctx_id, int code, size_t content_length)
{
	const char* status = "OK";
	switch(code) {
	case 400: status = "Bad Request"; break;
	case 500: status = "Internal Server Error"; break;
	}
	auto buff = fmt::format(header_templ, code, status, content_length);
	write_response(ctx_id, buff.c_str(), buff.size());
}

/**
 * @brief      Stop processing request and send error message
 *
 * @param      ctx_id          Request context identifier
 * @param      error_code      Error code for the Autodiscover response
 * @param      error_msg       Error message for the Autodiscover response
 * @return     BOOL always return false
 */
BOOL OxdiscoPlugin::die(int ctx_id, const char *error_code,
    const char *error_msg) const
{
	struct tm timebuf;
	char error_time[13];
	auto rawtime = time(nullptr);
	auto timeinfo = localtime_r(&rawtime, &timebuf);
	strftime(error_time, std::size(error_time), "%T", timeinfo);

	auto data = fmt::format(error_templ, error_time, server_id, error_code, error_msg);
	mlog(LV_DEBUG, "[oxdisco] die response: %zu, %s", data.size(), data.c_str());
	writeheader(ctx_id, 200, data.size());
	write_response(ctx_id, data.c_str(), data.size());
	return false;
}

/**
 * @brief      Gets value of an XMLElement
 *
 * @param      el              XMLElement
 * @param      tag             Tag to get value of
 *
 * @return     const char*     Value of the tag
 */
const char *OxdiscoPlugin::gtx(XMLElement &el, const char *tag)
{
	auto nd = el.FirstChildElement(tag);
	return nd != nullptr ? nd->GetText() : nullptr;
}

/**
 * @brief      Adds new child and set its value if necessary to an XMLElement
 *
 * @param      el              XMLElement
 * @param      tag             Tag to add
 * @param      val             Value of the tag
 * @return     XMLElement*     New child element
 */
XMLElement *OxdiscoPlugin::add_child(XMLElement *el,
	const char *tag, const char *val = nullptr)
{
	auto ch = el->InsertNewChildElement(tag);
	if (val != nullptr)
		ch->SetText(val);
	return ch;
}

XMLElement *OxdiscoPlugin::add_child(XMLElement *el, const char *tag,
    const std::string &val)
{
	auto ch = el->InsertNewChildElement(tag);
	ch->SetText(val.c_str());
	return ch;
}

/**
 * @brief      Create and send response
 *
 * @param      ctx_id          Request context identifier
 * @param      email           Email address for autodiscover
 * @param      ars             Acceptable response schema
 *
 * @return     BOOL            TRUE if response was successful, false otherwise
 */
BOOL OxdiscoPlugin::resp(int ctx_id, const char *authuser,
    const char *email, const char *ars) const
{
	auto req = get_request(ctx_id);
	char user_agent[64];
	req->f_user_agent.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	size_t len = req->f_user_agent.read(user_agent, std::size(user_agent) - 1);
	if (len == MEM_END_OF_FILE)
		*user_agent = '\0';
	else
		user_agent[len] = '\0';

	tinyxml2::XMLDocument respdoc;
	auto decl = respdoc.NewDeclaration();
	respdoc.InsertEndChild(decl);

	auto resproot = respdoc.NewElement("Autodiscover");
	resproot->SetAttribute("xmlns", response_xmlns);
	int ret;

	if (strcasecmp(ars, response_outlook_xmlns) == 0)
		ret = resp_web(resproot, authuser, email, user_agent);
	else if (strcasecmp(ars, response_mobile_xmlns) == 0)
		ret = resp_eas(resproot, email);
	else {
		respdoc.Clear();
		return die(ctx_id, provider_unavailable_code, provider_unavailable_msg);
	}
	if (ret < 0)
		return die(ctx_id, "503", "Internal Server Error");

	int code = 200;
	respdoc.InsertEndChild(resproot);
	XMLPrinter printer(nullptr, !pretty_response);
	respdoc.Print(&printer);

	const char* response = printer.CStr();
	if (response_logging > 0)
		mlog(LV_DEBUG, "[oxdisco] response: %s", response);

	writeheader(ctx_id, code, strlen(response));
	return write_response(ctx_id, response, strlen(response));
}

bool OxdiscoPlugin::advertise_prot(enum adv_setting adv, const char *ua)
{
	switch (adv) {
	case adv_setting::no:
		return false;
	case adv_setting::not_old_mso:
		return strncasecmp(ua, "Microsoft Office/", 17) != 0 ||
		       strtoul(&ua[17], nullptr, 10) >= 16;
	case adv_setting::new_mso_only:
		return strncasecmp(ua, "Microsoft Office/", 17) == 0 &&
		       strtoul(&ua[17], nullptr, 10) >= 16;
	default:
		return true;
	}
}

/**
 * @brief      Create response for outlook schema
 *
 * @param      el
 * @param      email
 */
int OxdiscoPlugin::resp_web(XMLElement *el, const char *authuser,
    const char *email, const char *user_agent) const
{
	auto resp = add_child(el, "Response");
	resp->SetAttribute("xmlns", response_outlook_xmlns);

	if (!RedirectUrl.empty()) {
		auto resp_acc = add_child(resp, "Account");
		add_child(resp_acc, "Action", "redirectUrl");
		add_child(resp_acc, "RedirectUrl", RedirectUrl.c_str());
		return 0;
	}
	else if (!RedirectAddr.empty()) {
		auto resp_acc = add_child(resp, "Account");
		add_child(resp_acc, "Action", "redirectAddr");
		add_child(resp_acc, "RedirectAddr", get_redirect_addr(email));
		return 0;
	}

	auto resp_user = add_child(resp, "User");
	add_child(resp_user, "AutoDiscoverSMTPAddress", email); // TODO get the primary email address

	auto buf = std::make_unique<char[]>(4096);
	auto domain = strchr(email, '@');
	if (domain == nullptr)
		return -1;
	++domain;
	char hex_string[12];
	bool is_private = strncasecmp(email, public_folder_email, 19) != 0;
	std::pair<std::string, std::string> homesrv_buf;
	if (mysql.get_homeserver(email, is_private, homesrv_buf) != 0)
		return -1;
	const char *homesrv = homesrv_buf.second.c_str();
	if (*homesrv == '\0')
		homesrv = host_id.c_str();

	std::string DisplayName, LegacyDN, DeploymentId;
	int user_id = 0, domain_id = 0;
	if (is_private) {
		if (!mysql.get_user_displayname(email, buf.get(), 4096))
			return -1;
		DisplayName = buf.get();
		if (!username_to_essdn(email, buf.get(), 4096, user_id, domain_id))
			return -1;
		LegacyDN = buf.get();

		get_hex_string(email, hex_string);
		DeploymentId = get_deploymentid(user_id, hex_string);
	}
	else {
		DisplayName = public_folder;
		if (!domainname_to_essdn(domain, buf.get(), 4096, domain_id))
			return -1;
		LegacyDN = buf.get();

		get_hex_string(domain, hex_string);
		DeploymentId = get_deploymentid(domain_id, hex_string);
	}

	add_child(resp_user, "DisplayName", DisplayName);
	add_child(resp_user, "LegacyDN", LegacyDN);
	HX_strupper(DeploymentId.data());
	add_child(resp_user, "DeploymentId", DeploymentId);

	auto resp_acc = add_child(resp, "Account");
	add_child(resp_acc, "AccountType", "email");
	add_child(resp_acc, "Action", "settings"); // TODO redirectAddr, redirectUrl
	add_child(resp_acc, "MicrosoftOnline", "False");
	add_child(resp_acc, "ConsumerMailbox", "False");

	auto ews_url = fmt::format(ews_base_url, homesrv, exchange_asmx);
	auto OABUrl = fmt::format(oab_base_url, homesrv);
	auto EcpUrl = fmt::format(ews_base_url, homesrv, "");

	if (advertise_prot(m_advertise_mh, user_agent))
		resp_mh(resp_acc, homesrv, domain, ews_url, OABUrl, EcpUrl,
			DeploymentId, is_private);
	if (advertise_prot(m_advertise_rpch, user_agent))
		resp_rpch(resp_acc, homesrv, ews_url, OABUrl, EcpUrl,
			DeploymentId, is_private);

	std::vector<sql_user> hints;
	if (is_private && strcasecmp(authuser, email) == 0) {
		auto err = mysql.scndstore_hints(user_id, hints);
		if (err != 0) {
			mlog(LV_ERR, "oxdisco: error retrieving secondary store hints: %s", strerror(err));
			return -1;
		}
	}

	if (is_private && hints.size() > 0) {
		for (const auto &user : hints) {
			auto am = add_child(resp_acc, "AlternativeMailbox");
			add_child(am, "Type", "Delegate");
			auto em = user.username.c_str();
			auto dn = user.propvals.find(PR_DISPLAY_NAME);
			/* DispName is required as per OXDSCLI § */
			add_child(am, "DisplayName", dn != user.propvals.end() ? dn->second.c_str() : em);
			add_child(am, "SmtpAddress", em);
			add_child(am, "OwnerSmtpAddress", em);
		}
	}

	if (is_private) {
		auto pfe = fmt::format("{}{}", public_folder_email, domain);
		auto resp_pfi = add_child(resp_acc, "PublicFolderInformation");
		add_child(resp_pfi, "SmtpAddress", pfe);
	}

	return 0;
}

void OxdiscoPlugin::resp_mh(XMLElement *resp_acc, const char *homesrv,
    const char *domain,
    const std::string &ews_url, const std::string &OABUrl,
    const std::string &EcpUrl, const std::string &deploymentid,
    bool is_private)
{
	auto resp_prt = add_child(resp_acc, "Protocol");
	add_child(resp_prt, "OOFUrl", ews_url);
	add_child(resp_prt, "OABUrl", OABUrl);

	add_child(resp_prt, "Type", "EXHTTP");
	add_child(resp_prt, "Server", homesrv);
	add_child(resp_prt, "SSL", "On");
	add_child(resp_prt, "CertPrincipalName", "None");
	add_child(resp_prt, "AuthPackage", "basic");
	add_child(resp_prt, "ServerExclusiveConnect", "on");

	if (is_private) {
		add_child(resp_prt, "ASUrl", ews_url);
		add_child(resp_prt, "EwsUrl", ews_url);
		add_child(resp_prt, "EmwsUrl", ews_url);

		add_child(resp_prt, "EcpUrl", EcpUrl);
		add_child(resp_prt, "EcpUrl-photo", "thumbnail.php");
	}


	/* Protocol Type=mapiHttp */
	resp_prt = add_child(resp_acc, "Protocol");
	resp_prt->SetAttribute("Type", "mapiHttp");
	resp_prt->SetAttribute("Version", "1");
	auto resp_prt_mst = add_child(resp_prt, "MailStore");

	auto mst_url = fmt::format(mailbox_base_url, homesrv, "emsmdb", deploymentid, domain);
	add_child(resp_prt_mst, "InternalUrl", mst_url);
	add_child(resp_prt_mst, "ExternalUrl", mst_url);

	auto abk_url = fmt::format(mailbox_base_url, homesrv, "nspi", deploymentid, domain);
	auto resp_prt_abk = add_child(resp_prt, "AddressBook");
	add_child(resp_prt_abk, "InternalUrl", abk_url);
	add_child(resp_prt_abk, "ExternalUrl", abk_url);
}

void OxdiscoPlugin::resp_rpch(XMLElement *resp_acc, const char *domain,
    const std::string &ews_url, const std::string &OABUrl,
    const std::string &EcpUrl, const std::string &deploymentid,
    bool is_private) const
{
	auto resp_prt = add_child(resp_acc, "Protocol");
	add_child(resp_prt, "Type", "EXCH");

	auto depl_server = fmt::format("{}@{}", deploymentid, domain);
	add_child(resp_prt, "Server", depl_server);
	add_child(resp_prt, "ServerVersion", oxd_server_version);

	auto ServerDN = fmt::format(server_base_dn,
		x500_org_name.c_str(), deploymentid, domain);
	add_child(resp_prt, "ServerDN", ServerDN);

	auto MdbDN = fmt::format(server_base_dn,
		x500_org_name.c_str(), deploymentid, domain);
	MdbDN += "/cn=Microsoft Private MDB";
	add_child(resp_prt, "MdbDN", MdbDN);

	add_child(resp_prt, "AuthPackage", "anonymous");
	add_child(resp_prt, "ServerExclusiveConnect", "off");

	if (is_private) {
		add_child(resp_prt, "OOFUrl", ews_url);
		add_child(resp_prt, "OABUrl", OABUrl);
		add_child(resp_prt, "PublicFolderServer", domain);
		add_child(resp_prt, "ASUrl", ews_url);
		add_child(resp_prt, "EwsUrl", ews_url);
		add_child(resp_prt, "EmwsUrl", ews_url);
		add_child(resp_prt, "EcpUrl", EcpUrl);
		add_child(resp_prt, "EcpUrl-photo", "thumbnail.php");
	}

	/* Protocol EXPR */
	resp_prt = add_child(resp_acc, "Protocol");
	add_child(resp_prt, "Type", "EXPR");
	add_child(resp_prt, "Server", domain);
	add_child(resp_prt, "SSL", "On");
	add_child(resp_prt, "CertPrincipalName", "None");
	add_child(resp_prt, "AuthPackage", "basic");
	add_child(resp_prt, "ServerExclusiveConnect", "on");
	if (is_private) {
		add_child(resp_prt, "OOFUrl", ews_url);
		add_child(resp_prt, "OABUrl", OABUrl);
	}

}

/**
 * @brief      Create response for mobilesync schema
 *
 * @param      el              Response XMLElement
 * @param      email           Email address for autodiscover
 */
int OxdiscoPlugin::resp_eas(XMLElement *el, const char *email) const
{
	auto resp = add_child(el, "Response");
	resp->SetAttribute("xmlns", response_mobile_xmlns);

	add_child(resp, "Culture", "en:us");

	auto resp_user = add_child(resp, "User");
	auto buf = std::make_unique<char[]>(4096);
	if (!mysql.get_user_displayname(email, buf.get(), 4096))
		return -1;
	add_child(resp_user, "DisplayName", buf.get());
	add_child(resp_user, "EMailAddress", email);

	auto resp_act = add_child(resp, "Action");

	auto domain = strchr(email, '@');
	if (domain == nullptr)
		return -1;
	++domain;

	if (!RedirectAddr.empty() && strcasecmp(domain, RedirectAddr.c_str()) != 0) {
		auto redirect_addr = get_redirect_addr(email);
		add_child(resp_act, "Redirect", redirect_addr);
	}
	else {
		auto resp_set = add_child(resp_act, "Settings");
		auto resp_ser = add_child(resp_set, "Server");
		add_child(resp_ser, "Type", "MobileSync");
		auto url = fmt::format(msas_base_url, domain);
		add_child(resp_ser, "Url", url);
		add_child(resp_ser, "Name", url);
	}
	return 0;
}

BOOL OxdiscoPlugin::resp_autocfg(int ctx_id, const char *username) const
{
	tinyxml2::XMLDocument respdoc;
	auto decl = respdoc.NewDeclaration();
	respdoc.InsertEndChild(decl);

	auto resproot = respdoc.NewElement("clientConfig");
	resproot->SetAttribute("version", "1.1");
	respdoc.InsertEndChild(resproot);

	auto t_host_id = host_id.c_str();
	auto resp_prov = add_child(resproot, "emailProvider");
	resp_prov->SetAttribute("id", t_host_id);

	// TODO get all domains?
	add_child(resp_prov, "domain", t_host_id);
	add_child(resp_prov, "displayName", "Gromox Mail");
	add_child(resp_prov, "displayShortName", "Gromox");

	auto resp_imap = add_child(resp_prov, "incomingServer");
	add_child(resp_imap, "type", "imap");
	add_child(resp_imap, "hostname", t_host_id);
	add_child(resp_imap, "port", "143");
	add_child(resp_imap, "socketType", "plain");
	add_child(resp_imap, "authentication", "password-cleartext");
	add_child(resp_imap, "username", username);

	auto resp_smtp = add_child(resp_prov, "outgoingServer");
	add_child(resp_smtp, "type", "smtp");
	add_child(resp_smtp, "hostname", t_host_id);
	add_child(resp_smtp, "port", "25");
	add_child(resp_smtp, "socketType", "plain");
	add_child(resp_smtp, "authentication", "password-cleartext");
	add_child(resp_smtp, "username", username);

	int code = 200;
	XMLPrinter printer(nullptr, !pretty_response);
	respdoc.Print(&printer);

	const char* response = printer.CStr();
	if (response_logging > 0)
		mlog(LV_DEBUG, "[oxdisco] response: %s", response);

	writeheader(ctx_id, code, strlen(response));
	return write_response(ctx_id, response, strlen(response));
}

std::string OxdiscoPlugin::get_redirect_addr(const char *email) const
{
	std::string s_email = email;
	std::string username = s_email.substr(0, s_email.find('@') - 1);
	std::string redirect_addr = username + "@" + RedirectAddr;
	return redirect_addr;
}

BOOL OxdiscoPlugin::username_to_essdn(const char *username, char *pessdn,
    size_t dnmax, int &user_id, int &domain_id) const
{
	char tmp_name[UADDR_SIZE];
	char hex_string[16];
	char hex_string2[16];

	gx_strlcpy(tmp_name, username, GX_ARRAY_SIZE(tmp_name));
	auto pdomain = strchr(tmp_name, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	*pdomain++ = '\0';
	mysql.get_user_ids(username, &user_id, &domain_id, nullptr);
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
			x500_org_name.c_str(), hex_string2, hex_string, tmp_name);
	HX_strupper(pessdn);
	return TRUE;
}

BOOL OxdiscoPlugin::domainname_to_essdn(const char *domainname, char *pessdn,
    size_t dnmax, int &domain_id) const
{
	char hex_string[16];
	int org_id = 0;

	mysql.get_domain_ids(domainname, &domain_id, &org_id);
	encode_hex_int(domain_id, hex_string);
	snprintf(pessdn, dnmax, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s00000000-public.folder.root",
			x500_org_name.c_str(), hex_string);
	HX_strupper(pessdn);
	return TRUE;
}

std::string OxdiscoPlugin::get_deploymentid(const int id,
    const char *hex_string)
{
	char temp_hex[16];
	encode_hex_int(id, temp_hex);
	return fmt::sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%s",
			hex_string[0], hex_string[1], hex_string[2], hex_string[3],
			hex_string[4], hex_string[5], hex_string[6], hex_string[7], 
			hex_string[8], hex_string[9], hex_string[10], hex_string[11], temp_hex);
}

void OxdiscoPlugin::get_hex_string(const char *str, char *hex_string)
{
	size_t l = strlen(str);
	for (size_t i = 0; i < 12; ++i) {
		if (i < l) {
			hex_string[i] = str[i];
		}
		else {
			hex_string[i] = '\0';
		}
	}
}

/**
 * @brief      Initialize mysql adaptor function pointers
 */
OxdiscoPlugin::_mysql::_mysql()
{
#define getService(f) \
	if (query_service2(# f, f) == nullptr) \
		throw std::runtime_error("[ews]: failed to get the \""# f"\" service")
	getService(get_user_displayname);
	getService(get_user_ids);
	getService(get_domain_ids);
	getService(scndstore_hints);
	getService(get_homeserver);
#undef getService
}

///////////////////////////////////////////////////////////////////////////////
//Plugin management

static std::unique_ptr<OxdiscoPlugin> g_oxdisco_plugin;

/**
 * @brief      Initialize plugin
 *
 * @param      apidata  HPM API data
 *
 * @return     TRUE if initialization was successful, false otherwise
 */
static BOOL oxdisco_init(void **apidata)
{
	LINK_HPM_API(apidata)
	HPM_INTERFACE ifc{};
	ifc.preproc = &OxdiscoPlugin::preproc;
	ifc.proc    = [](int ctx, const void *cont, uint64_t len) { return g_oxdisco_plugin->proc(ctx, cont, len); };
	ifc.retr    = [](int ctx) { return HPM_RETRIEVE_DONE; };
	ifc.term    = [](int ctx) {};
	if (!register_interface(&ifc))
		return false;
	try {
		g_oxdisco_plugin.reset(new OxdiscoPlugin());
	}
	catch (std::exception& e) {
		mlog(LV_DEBUG, "[oxdisco] failed to initialize plugin: %s", e.what());
		return false;
	}
	mlog(LV_DEBUG, "[oxdisco]: plugin is loaded into system");
	return TRUE;
}

/**
 * @brief      Plugin main function
 *
 * Used for (de-)initializing the plugin
 *
 * @param      reason  Reason the function is called
 * @param      data    Additional, reason specific data
 *
 * @return     TRUE if successful, false otherwise
 */
static BOOL oxdisco_main(int reason, void **data)
{
	if (reason == PLUGIN_INIT)
		return oxdisco_init(data);
	else if(reason == PLUGIN_FREE)
		g_oxdisco_plugin.reset();
	return TRUE;
}
HPM_ENTRY(oxdisco_main);
