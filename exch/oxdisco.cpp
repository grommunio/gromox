// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
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

using namespace std::string_literals;
using namespace gromox;
using namespace tinyxml2;

namespace {

class OxdiscoPlugin {
	public:
	OxdiscoPlugin();

	BOOL proc(int, const void*, uint64_t);
	static BOOL preproc(int);

	struct _mysql {
		_mysql();

		decltype(mysql_adaptor_get_user_displayname) *get_user_displayname;
		decltype(mysql_adaptor_get_user_ids) *get_user_ids;
	} mysql; // mysql adaptor function pointers

	private:
	tinyxml2::XMLDocument respdoc;
	std::string x500_org_name;
	uint server_id; // Hash of the name of the mail server
	std::string RedirectAddr; // Domain to perform Autodiscover
	std::string RedirectUrl; // URL for a subsequent Autodiscover request
	int user_id;
	int domain_id;
	int request_logging = 0; // 0 = none, 1 = request data
	int response_logging = 0; // 0 = none, 1 = response data
	int pretty_response = 0; // 0 = compact output, 1 = pretty printed response

	void loadConfig();
	void writeheader(int, int, size_t);
	BOOL die(int, const char *, const char *);
	BOOL resp(int, const char *, const char *);
	int resp_pub(tinyxml2::XMLElement *, const char *);
	int resp_web(tinyxml2::XMLElement *, const char *);
	int resp_eas(tinyxml2::XMLElement *, const char *);
	tinyxml2::XMLElement *add_child(tinyxml2::XMLElement *, const char *, const char *);
	tinyxml2::XMLElement *add_child(tinyxml2::XMLElement *, const char *, const std::string &);
	const char *gtx(tinyxml2::XMLElement &, const char *);
	const char *get_redirect_addr(const char *);
	BOOL username_to_essdn(const char *username, char *dn, size_t);
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
	// TODO server_id
	server_id = 123456;
	loadConfig();

	mlog(LV_DEBUG, "[oxdisco] org %s RedirectAddr %s RedirectUrl %s request_logging %d response_logging %d pretty_response %d\n",
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
	if (strcasecmp(uri, "/autodiscover/autodiscover.xml") != 0)
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

	XMLDocument doc;
	if (doc.Parse(static_cast<const char *>(content), len) != XML_SUCCESS)
		return die(ctx_id, invalid_request_code, invalid_request_msg);

	auto root = doc.RootElement();
	auto name = root != nullptr ? root->Name() : nullptr;
	if (name == nullptr || strcasecmp(name, "Autodiscover") != 0) {
		return die(ctx_id, invalid_request_code, invalid_request_msg);
	}

	if (request_logging > 0)
		mlog(LV_DEBUG, "[oxdisco] incoming: %s\n", static_cast<const char *>(content));

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

	// TODO get the main email address of the authenticated user
	if(strcasecmp(email, auth_info.username) != 0)
		return die(ctx_id, bad_address_code, bad_address_msg);

	if (!RedirectAddr.empty() || !RedirectUrl.empty()) {
		mlog(LV_DEBUG, "[oxdisco] send redirect response\n");
	}
	return resp(ctx_id, email, ars);

} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1700: ENOMEM\n");
	return die(ctx_id, server_error_code, server_error_msg);
}

/**
 * @brief      Loads configuration file
 *
 */
void OxdiscoPlugin::loadConfig()
{
	auto pconfig = config_file_initd("autodiscover.cfg", get_config_path(), nullptr);
	const char* found = pconfig->get_value("x500_org_name");
	if (found)
		x500_org_name = found;
	else
		x500_org_name = "Gromox default";

	found = pconfig->get_value("RedirectAddr");
	if (found)
		RedirectAddr = found;

	found = pconfig->get_value("RedirectUrl");
	if (found) {
		RedirectUrl = found;
	}

	pconfig->get_int("request_logging", &request_logging);
	pconfig->get_int("response_logging", &response_logging);
	pconfig->get_int("pretty_response", &pretty_response);
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
BOOL OxdiscoPlugin::die(int ctx_id, const char *error_code, const char *error_msg)
{
	struct tm timebuf;
	char error_time[13];
	auto rawtime = time(nullptr);
	auto timeinfo = localtime_r(&rawtime, &timebuf);
	strftime(error_time, std::size(error_time), "%T", timeinfo);

	auto data = fmt::format(error_templ, error_time, server_id, error_code, error_msg);
	mlog(LV_DEBUG, "[oxdisco] die response: %zu, %s\n", data.size(), data.c_str());
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
BOOL OxdiscoPlugin::resp(int ctx_id, const char *email, const char *ars)
{
	respdoc.Clear();
	auto decl = respdoc.NewDeclaration();
	respdoc.InsertEndChild(decl);

	auto resproot = respdoc.NewElement("Autodiscover");
	resproot->SetAttribute("xmlns", response_xmlns);
	int ret;

	if (strcasecmp(ars, response_outlook_xmlns) == 0)
		ret = resp_web(resproot, email);
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

/**
 * @brief      Create response for outlook schema
 *
 * @param      el
 * @param      email
 */
int OxdiscoPlugin::resp_web(XMLElement *el, const char *email)
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
	if (!mysql.get_user_displayname(email, buf.get(), 4096))
		return -1;
	add_child(resp_user, "DisplayName", buf.get());
	if (!username_to_essdn(email, buf.get(), 4096))
		return -1;
	add_child(resp_user, "LegacyDN", buf.get());
	add_child(resp_user, "EMailAddress", email);

	char hex_string[16];
	encode_hex_int(user_id, hex_string);
	auto deploymentid = fmt::sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%s",
		email[0], email[1], email[2], email[3], email[4], email[5], email[6],
		email[7], email[8], email[9], email[10], email[11], hex_string);
	HX_strupper(deploymentid.data());
	add_child(resp_user, "DeploymentId", deploymentid);

	auto resp_acc = add_child(resp, "Account");
	add_child(resp_acc, "AccountType", "email");
	add_child(resp_acc, "Action", "settings"); // TODO redirectAddr, redirectUrl
	add_child(resp_acc, "MicrosoftOnline", "False");
	add_child(resp_acc, "ConsumerMailbox", "False");

	/* Protocol EXHTTP */
	auto domain = strchr(email, '@');
	++domain;
	auto ews_url = fmt::format(ews_base_url, domain, exchange_asmx);
	auto OABUrl = fmt::format(oab_base_url, domain);
	auto EcpUrl = fmt::format(ews_base_url, domain, "");

	[this](XMLElement *resp_acc, const char *domain, const std::string &ews_url, const std::string &OABUrl, const std::string &EcpUrl, const std::string &deploymentid) {
	auto resp_prt = add_child(resp_acc, "Protocol");
	add_child(resp_prt, "OOFUrl", ews_url);
	add_child(resp_prt, "OABUrl", OABUrl);

	add_child(resp_prt, "Type", "EXHTTP");
	add_child(resp_prt, "Server", domain);
	add_child(resp_prt, "SSL", "On");
	add_child(resp_prt, "CertPrincipalName", "None");
	add_child(resp_prt, "AuthPackage", "basic");

	add_child(resp_prt, "ASUrl", ews_url);
	add_child(resp_prt, "EwsUrl", ews_url);
	add_child(resp_prt, "EmwsUrl", ews_url);

	add_child(resp_prt, "EcpUrl", EcpUrl);
	add_child(resp_prt, "EcpUrl-photo", "thumbnail.php");

	add_child(resp_prt, "ServerExclusiveConnect", "on");

	/* Protocol Type=mapiHttp */
	resp_prt = add_child(resp_acc, "Protocol");
	resp_prt->SetAttribute("Type", "mapiHttp");
	resp_prt->SetAttribute("Version", "1");
	auto resp_prt_mst = add_child(resp_prt, "MailStore");

	auto mst_url = fmt::format(mailbox_base_url, domain, "emsmdb", deploymentid, domain);
	add_child(resp_prt_mst, "InternalUrl", mst_url);
	add_child(resp_prt_mst, "ExternalUrl", mst_url);

	auto abk_url = fmt::format(mailbox_base_url, domain, "nspi", deploymentid, domain);
	auto resp_prt_abk = add_child(resp_prt, "AddressBook");
	add_child(resp_prt_abk, "InternalUrl", abk_url);
	add_child(resp_prt_abk, "ExternalUrl", abk_url);

	}(resp_acc, domain, ews_url, OABUrl, EcpUrl, deploymentid);

	/* Protocol EXCH */
	[this](XMLElement *resp_acc, const char *domain, const std::string &ews_url, const std::string &OABUrl, const std::string &EcpUrl, const std::string &deploymentid) {
	auto resp_prt = add_child(resp_acc, "Protocol");
	add_child(resp_prt, "OOFUrl", ews_url);
	add_child(resp_prt, "OABUrl", OABUrl);
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
	add_child(resp_prt, "PublicFolderServer", domain);
	add_child(resp_prt, "ASUrl", ews_url);
	add_child(resp_prt, "EwsUrl", ews_url);
	add_child(resp_prt, "EmwsUrl", ews_url);
	add_child(resp_prt, "EcpUrl", EcpUrl);
	add_child(resp_prt, "EcpUrl-photo", "thumbnail.php");
	add_child(resp_prt, "ServerExclusiveConnect", "off");

	/* Protocol EXPR */
	resp_prt = add_child(resp_acc, "Protocol");
	add_child(resp_prt, "Type", "EXPR");
	add_child(resp_prt, "Server", domain);
	add_child(resp_prt, "SSL", "On");
	add_child(resp_prt, "CertPrincipalName", "None");
	add_child(resp_prt, "AuthPackage", "basic");
	add_child(resp_prt, "ServerExclusiveConnect", "on");
	add_child(resp_prt, "OOFUrl", ews_url);
	add_child(resp_prt, "OABUrl", OABUrl);

	resp_prt = add_child(resp_acc, "PublicFolderInformation");
	add_child(resp_prt, "SmtpAddress", "public.folder.root@"s + domain);
	}(resp_acc, domain, ews_url, OABUrl, EcpUrl, deploymentid);
	return 0;
}

/**
 * @brief      Create response for public folder Autodiscover
 *
 * @param el
 * @param email
 */
int OxdiscoPlugin::resp_pub(XMLElement *el, const char *email)
{
	auto domain = strchr(email, '@');
	if (domain == nullptr) {
		mlog(LV_DEBUG, "no domain in OXD request\n");
		return -1;
	}
	else {
		mlog(LV_DEBUG, "[oxdisco] pub domain: %s\n", ++domain);
		return 0;
	}
}

/**
 * @brief      Create response for mobilesync schema
 *
 * @param      el              Response XMLElement
 * @param      email           Email address for autodiscover
 */
int OxdiscoPlugin::resp_eas(XMLElement *el, const char *email)
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

const char* OxdiscoPlugin::get_redirect_addr(const char *email)
{
	std::string s_email = email;
	std::string username = s_email.substr(0, s_email.find('@') - 1);
	std::string redirect_addr = username + "@" + RedirectAddr;
	return redirect_addr.c_str();
}

BOOL OxdiscoPlugin::username_to_essdn(const char *username, char *pessdn, size_t dnmax)
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
		mlog(LV_DEBUG, "[oxdisco] failed to initialize plugin: %s\n", e.what());
		return false;
	}
	mlog(LV_DEBUG, "[oxdisco]: plugin is loaded into system\n");
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
