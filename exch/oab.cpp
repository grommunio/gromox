// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstring>
#include <string>
#include <gromox/defs.h>
#include <gromox/hpm_common.h>

using namespace std::string_literals;
using namespace gromox;

namespace {

class OabPlugin {
	public:
	OabPlugin();
	http_status proc(int, const void*, uint64_t);
	static BOOL preproc(int);
};

}

DECLARE_HPM_API();

static constexpr char
	response[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><OAB></OAB>",
	header[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"Content-Length: 49\r\n\r\n";

OabPlugin::OabPlugin(){}

/**
 * @brief      Preprocess request
 *
 * @param      ctx_id  Request context identifier
 *
 * @return     TRUE if the request is to be processed by this plugin, false otherwise
 */
BOOL OabPlugin::preproc(int ctx_id)
{
	auto req = get_request(ctx_id);
	return strncasecmp(req->f_request_uri.c_str(), "/OAB", 4) == 0 ? TRUE : false;
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
http_status OabPlugin::proc(int ctx_id, const void *content, uint64_t len) try
{
	// TODO: check if unauthed requests are required
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if (auth_info.auth_status != http_status::ok)
		return http_status::unauthorized;
	auto wr = write_response(ctx_id, header, strlen(header));
	if (wr != http_status::ok)
		return wr;
	return write_response(ctx_id, response, strlen(response));
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1700: ENOMEM\n");
	return http_status::none;
}

///////////////////////////////////////////////////////////////////////////////
//Plugin management

static std::unique_ptr<OabPlugin> g_oab_plugin;

/**
 * @brief      Initialize plugin
 *
 * @param      apidata  HPM API data
 *
 * @return     TRUE if initialization was successful, false otherwise
 */
static BOOL oab_init(void **apidata)
{
	LINK_HPM_API(apidata)
	HPM_INTERFACE ifc{};
	ifc.preproc = &OabPlugin::preproc;
	ifc.proc    = [](int ctx, const void *cont, uint64_t len) { return g_oab_plugin->proc(ctx, cont, len); };
	ifc.retr    = [](int ctx) { return HPM_RETRIEVE_DONE; };
	ifc.term    = [](int ctx) {};
	if (!register_interface(&ifc))
		return false;
	try {
		g_oab_plugin.reset(new OabPlugin());
	}
	catch (std::exception& e) {
		mlog(LV_DEBUG, "[oab] failed to initialize plugin: %s\n", e.what());
		return false;
	}
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
static BOOL oab_main(int reason, void **data)
{
	if (reason == PLUGIN_INIT)
		return oab_init(data);
	else if(reason == PLUGIN_FREE)
		g_oab_plugin.reset();
	return TRUE;
}
HPM_ENTRY(oab_main);
