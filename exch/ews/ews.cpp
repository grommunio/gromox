// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_map>

#include <tinyxml2.h>
#include <fmt/core.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/hpm_common.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>

#include "exceptions.hpp"
#include "requests.hpp"
#include "soaputil.hpp"

DECLARE_HPM_API();

using namespace gromox;
using namespace gromox::EWS;
using namespace tinyxml2;

using Exceptions::DispatchError;


///////////////////////////////////////////////////////////////////////////////

void* EWSContext::alloc(size_t count)
{return ndr_stack_alloc(NDR_STACK_IN, count);}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Deserialize request data and call processing function
 *
 * Provides a convenient handler function template when complete
 * de-serialization of request data is desired.
 *
 * @param      request   Request data
 * @param      response  Response data
 *
 * @tparam     T         Request data type
 */
template<typename T>
static void process(const XMLElement* request, XMLElement* response, const EWSContext& context)
{Requests::process(T(request), response, context);}

/**
 * Mapping of request names to handler functions.
 */
const std::unordered_map<std::string, EWSPlugin::Handler> EWSPlugin::requestMap = {
	{"GetUserOofSettingsRequest", process<Structures::mGetUserOofSettingsRequest>},
	{"SetUserOofSettingsRequest", process<Structures::mSetUserOofSettingsRequest>},
	{"GetMailTips", process<Structures::mGetMailTipsRequest>},
	{"GetServiceConfiguration", process<Structures::mGetServiceConfigurationRequest>},
	{"GetUserAvailabilityRequest", process<Structures::mGetUserAvailabilityRequest>},
};

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Preprocess request
 *
 * @param      ctx_id  Request context identifier
 *
 * @return     TRUE if the request is to be processed by this plugin, false otherwise
 */
BOOL EWSPlugin::preproc(int ctx_id)
{
	auto req = get_request(ctx_id);
	if (strcasecmp(req->method, "POST") != 0)
		return false;
	char uri[1024];
	size_t len = req->f_request_uri.read(uri, std::size(uri) - 1);
	if (len == MEM_END_OF_FILE)
		return false;
	uri[len] = '\0';
	if (strcasecmp(uri, "/EWS/Exchange.asmx") != 0)
		return false;
	return TRUE;
}

/**
 * @brief      Write basic response header
 *
 * @param      ctx_id          Request context identifier
 * @param      code            HTTP response code
 * @param      content_length  Length of the response body
 */
void EWSPlugin::writeheader(int ctx_id, int code, size_t content_length)
{
	static constexpr char templ[] =
	        "HTTP/1.1 {} {}\r\n"
	        "Content-Type: text/xml\r\n"
	        "Content-Length: {}\r\n"
	        "\r\n";
	const char* status = "OK";
	switch(code) {
	case 400: status = "Bad Request"; break;
	case 500: status = "Internal Server Error"; break;
	}
	auto rs = fmt::format(templ, code, status, content_length);
	write_response(ctx_id, rs.c_str(), rs.size());
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
	        "Connection: Keep-Alive\r\n"
	        "WWW-Authenticate: Basic realm=\"ews realm\"\r\n"
	        "\r\n";
	return write_response(ctx_id, content, strlen(content));
}

/**
 * @brief      Proccess request
 *
 * Checks if an authentication context exists, dispatches the request and
 * writes the response.
 *
 * @param      ctx_id   Request context identifier
 * @param      content  Request data
 * @param      len      Length of request data
 *
 * @return     TRUE if request was handled, false otherwise
 */
BOOL EWSPlugin::proc(int ctx_id, const void* content, uint64_t len)
{
	auto start = std::chrono::high_resolution_clock::now();
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if(!auth_info.b_authed)
		return unauthed(ctx_id);
	auto[response, code] = dispatch(ctx_id, auth_info, content, len);
	if(response_logging >= 2)
		mlog(LV_DEBUG, "[ews] Response: %s", response.c_str());
	if(response_logging)
	{
		auto end = std::chrono::high_resolution_clock::now();
		double duration = double(std::chrono::duration_cast<std::chrono::microseconds>(end-start).count()) / 1000.0;
		mlog(LV_DEBUG, "[ews] Done, code %d, %lu bytes, %.3fms", code, response.size(), duration);
	}
	if(response.length() > std::numeric_limits<int>::max())
	{
		response = SOAP::Envelope::fault("Server", "Response body to large");
		code = 500;
	}
	writeheader(ctx_id, code, response.length());
	return write_response(ctx_id, response.c_str(), int(response.length()));
}

/**
 * @brief      Dispatch request to appropriate handler
 *
 * @param      ctx_id     Request context identifier
 * @param      auth_info  Authentication context
 * @param      data       Request data
 * @param      len        Length of request data
 *
 * @return     Pair of response content and HTTP response code
 */
std::pair<std::string, int> EWSPlugin::dispatch(int ctx_id, HTTP_AUTH_INFO& auth_info, const void* data, uint64_t len) try
{
	using namespace std::string_literals;
	EWSContext context(ctx_id, auth_info, static_cast<const char*>(data), len, *this);
	if(request_logging >= 2)
		mlog(LV_DEBUG, "[ews] Incoming data: %.*s",
			len > INT_MAX ? INT_MAX : static_cast<int>(len),
			static_cast<const char *>(data));
	if(!rpc_new_stack())
		mlog(LV_ERR, "[ews]: Failed to allocate stack, exmdb might not work");
	auto cl0 = make_scope_exit([]{rpc_free_stack();});
	for(XMLElement* xml = context.request.body->FirstChildElement(); xml; xml = xml->NextSiblingElement())
	{
		XMLElement* responseContainer = context.response.body->InsertNewChildElement(xml->Name());
		if(request_logging)
			mlog(LV_DEBUG, "[ews] Processing %s", xml->Name());
		auto handler = requestMap.find(xml->Name());
		if(handler == requestMap.end())
		    throw Exceptions::UnknownRequestError("Unknown request '"s+xml->Name()+"'.");
		else
			handler->second(xml, responseContainer, context);
	}
	XMLPrinter printer(nullptr, !pretty_response);
	context.response.doc.Print(&printer);
	return {printer.CStr(), 200};
} catch (const Exceptions::InputError &err) {
	return {SOAP::Envelope::fault("Client", err.what()), 200};
} catch (const std::exception &err) {
	return {SOAP::Envelope::fault("Server", err.what()), 500};
}

EWSPlugin::EWSPlugin()
{loadConfig();}

/**
 * @brief      Initialize mysql adaptor function pointers
 */
EWSPlugin::_mysql::_mysql()
{
#define getService(f) \
	if (query_service2(# f, f) == nullptr) \
		throw std::runtime_error("[ews]: failed to get the \""# f"\" service")

	getService(get_maildir);
	getService(get_username_from_id);
#undef getService
}

EWSPlugin::_exmdb::_exmdb()
{
#define EXMIDL(n, p) do { \
	query_service2("exmdb_client_" #n, n); \
	if ((n) == nullptr) { \
		throw std::runtime_error("[ews]: failed to get the \"exmdb_client_"# n"\" service\n"); \
	} \
} while (false);
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
}

static constexpr cfg_directive x500_defaults[] = {
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static constexpr cfg_directive ews_cfg_defaults[] = {
	{"ews_pretty_response", "0", CFG_BOOL},
	{"ews_request_logging", "0", CFG_BOOL},
	{"ews_response_logging", "0", CFG_BOOL},
	CFG_TABLE_END,
};

/**
 * @brief      Load configuration file
 */
void EWSPlugin::loadConfig()
{
	auto cfg = config_file_initd("exmdb_provider.cfg", get_config_path(), x500_defaults);
	x500_org_name = cfg->get_value("x500_org_name");
	mlog(LV_INFO, "[ews]: x500 org name is \"%s\"", x500_org_name.c_str());

	cfg = config_file_initd("ews.cfg", get_config_path(), ews_cfg_defaults);
	pretty_response = cfg->get_ll("ews_pretty_response");
	request_logging = cfg->get_ll("ews_request_logging");
	response_logging = cfg->get_ll("ews_response_logging");
}

///////////////////////////////////////////////////////////////////////////////
//Plugin management

static std::unique_ptr<EWSPlugin> g_ews_plugin; ///< Current plugin

/**
 * @brief      Initialize plugin
 *
 * @param      apidata  HPM API data
 *
 * @return     TRUE if initialization was successful, false otherwise
 */
static BOOL ews_init(void **apidata)
{
	LINK_HPM_API(apidata)
	HPM_INTERFACE ifc{};
	ifc.preproc = &EWSPlugin::preproc;
	ifc.proc    = [](int ctx, const void *cont, uint64_t len) { return g_ews_plugin->proc(ctx, cont, len); };
	ifc.retr    = [](int) {return HPM_RETRIEVE_DONE;};
	ifc.term    = [](int) {};
	if (!register_interface(&ifc))
		return false;
	try {
		g_ews_plugin.reset(new EWSPlugin());
	} catch (const std::exception &e) {
		mlog(LV_ERR, "[ews] failed to initialize plugin: %s", e.what());
		return false;
	}
	return TRUE;
}

/**
 * @brief      Plugin main function
 *
 * Used for (de-)initializing the plugin
 *
 * @param      reason  Reason the function is calles
 * @param      data    Additional, reason specific data
 *
 * @return     TRUE if successful, false otherwise
 */
static BOOL ews_main(int reason, void **data)
{
	if (reason == PLUGIN_INIT)
		return ews_init(data);
	else if(reason == PLUGIN_FREE)
		g_ews_plugin.reset();
	return TRUE;
}

HPM_ENTRY(ews_main);
