// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <unordered_map>

#include <tinyxml2.h>
#include <fmt/core.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/hpm_common.h>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>

#include "exceptions.hpp"
#include "hash.hpp"
#include "requests.hpp"
#include "soaputil.hpp"

DECLARE_HPM_API();

namespace gromox::EWS::Exceptions
{

/**
 * @brief      Initialize EWSError
 *
 * @param t    EWS ResponseCode
 * @param m    Error message
 */
EWSError::EWSError(const char* t, const std::string& m) : DispatchError(m), type(t)
{}

void DispatchError::unused() {}
void EWSError::unused() {}

} // gromox::EWS::Exceptions

using namespace gromox;
using namespace gromox::EWS;
using namespace tinyxml2;

using Exceptions::DispatchError;

namespace
{

/**
 * @brief     Convert replica ID to replica GUID
 *
 * Currently only replica IDs 1 and 5 are supported.
 *
 * @param     mbinfo   Mailbox metadata
 * @param     replid   Replica ID
 *
 * @return    Replica GUID
 */
GUID replid_to_replguid(const gromox::EWS::Structures::sMailboxInfo& mbinfo, uint16_t replid)
{
	GUID guid;
	if (replid == 1)
		guid = mbinfo.isPublic ? rop_util_make_domain_guid(mbinfo.accountId) : rop_util_make_user_guid(mbinfo.accountId);
	else if (replid == 5)
		guid = mbinfo.mailboxGuid;
	else
		throw DispatchError(Exceptions::E3193);
	return guid;
}

/**
 * @brief      Write basic response header
 *
 * @param      ctx_id          Request context identifier
 * @param      code            HTTP response code
 * @param      content_length  Length of the response body
 */
void writeheader(int ctx_id, http_status code, size_t content_length)
{
	static constexpr char templ[] =
	        "HTTP/1.1 {} {}\r\n"
	        "Content-Type: text/xml\r\n"
	        "Content-Length: {}\r\n"
	        "\r\n";
	static constexpr char templ_nolen[] =
	        "HTTP/1.1 {} {}\r\n"
	        "Content-Type: text/xml\r\n"
	        "\r\n";
	const char* status = "OK";
	switch(code) {
	case http_status::bad_request: status = "Bad Request"; break;
	case http_status::server_error: status = "Internal Server Error"; break;
	default: break;
	}
	std::string rs = content_length ? fmt::format(templ, static_cast<int>(code), status, content_length) :
	              fmt::format(templ_nolen, int(code), status);
	write_response(ctx_id, rs.c_str(), rs.size());
}

/**
 * @brief      Write content
 *
 * @param      ctx_id    Context Id to write content to
 * @param      data      Data to write
 * @param      log       Whether write data to log
 * @param      loglevel  Log level
 */
void writecontent(int ctx_id, const std::string_view& data, bool log, gx_loglevel loglevel)
{
	write_response(ctx_id, data.data(), int(data.size()));
	if(log)
		mlog(loglevel, "[ews#%d] Response: %s", ctx_id, data.data());
}

} // anonymous namespace


/**
 * @brief      Context data for debugging purposes
 *
 * Will only be present if explicitely requested by the
 * `ews_debug` configuration directive.
 */
struct EWSPlugin::DebugCtx
{
	static constexpr uint8_t FL_LOCK = 1 << 0;
	static constexpr uint8_t FL_RATELIMIT = 1 << 1;
	static constexpr uint8_t FL_LOOP_DETECT = 1 << 2;

	explicit DebugCtx(const std::string_view&);

	std::mutex requestLock{};
	std::mutex hashLock{};
	std::unordered_map<uint64_t, size_t> requestHashes; ///< How often a request with this hash value occurred
	std::chrono::high_resolution_clock::time_point last;
	std::chrono::high_resolution_clock::duration minRequestTime{};
	uint32_t loopThreshold = 0;  ///< How many request repetitions to ignore before warning
	uint8_t flags = 0;
};

/**
 * @brief      Initialize debugging context
 *
 * Takes a string containing comma-separated debugging options.
 * Supported options are:
 * - `sequential`: Disable parallel processing of requests
 * - `rate_limit=<x>`: Only process <x> requests per second.
 *   Currently implies `sequential` (might be changed in the future).
 *
 * @param      opts    Debugging option string
 */
EWSPlugin::DebugCtx::DebugCtx(const std::string_view& opts)
{
	size_t start = 0;
	for(size_t end = opts.find(',', start); start != std::string_view::npos; end = opts.find(',', start))
	{
		std::string_view opt = opts.substr(start, end-start);
		start = end+(end != std::string_view::npos);
		if(opt == "sequential")
			flags |= FL_LOCK;
		else if(opt.substr(0, 11) == "rate_limit=")
		{
			unsigned long rateLimit = uint32_t(std::stoul(std::string(opt.substr(11))));
			if(rateLimit)
			{
				flags |= FL_RATELIMIT | FL_LOCK;
				minRequestTime = std::chrono::nanoseconds(1000000000/rateLimit);
			}
		} else if(opt == "loop_detect")
			flags |= FL_LOOP_DETECT;
		else if(opt.substr(0, 12) == "loop_detect=") {
			flags |= FL_LOOP_DETECT;
			loopThreshold = uint32_t(std::stoul(std::string(opt.substr(12))));
		}
		else
			mlog(LV_WARN, "[ews] Ignoring unknown debug directive '%s'", std::string(opt).c_str());
	}
}

///////////////////////////////////////////////////////////////////////////////

bool EWSPlugin::_exmdb::get_message_property(const char *dir, const char *username, cpid_t cpid, uint64_t message_id,
                                             uint32_t proptag, void **ppval) const
{
	PROPTAG_ARRAY tmp_proptags{1, &proptag};
	TPROPVAL_ARRAY propvals;

	if (!get_message_properties(dir, username, cpid, message_id, &tmp_proptags, &propvals))
		return false;
	*ppval = propvals.count == 1 && propvals.ppropval->proptag == proptag? propvals.ppropval->pvalue : nullptr;
	return true;
}


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
static void process(const XMLElement* request, XMLElement* response, EWSContext& context)
{Requests::process(T(request), response, context);}

/**
 * Mapping of request names to handler functions.
 */
const std::unordered_map<std::string, EWSPlugin::Handler> EWSPlugin::requestMap =
{
	{"CopyFolder", process<Structures::mCopyFolderRequest>},
	{"CopyItem", process<Structures::mCopyItemRequest>},
	{"CreateFolder", process<Structures::mCreateFolderRequest>},
	{"CreateItem", process<Structures::mCreateItemRequest>},
	{"DeleteFolder", process<Structures::mDeleteFolderRequest>},
	{"DeleteItem", process<Structures::mDeleteItemRequest>},
	{"EmptyFolder", process<Structures::mEmptyFolderRequest>},
	{"FindFolder", process<Structures::mFindFolderRequest>},
	{"GetAttachment", process<Structures::mGetAttachmentRequest>},
	{"GetEvents", process<Structures::mGetEventsRequest>},
	{"GetFolder", process<Structures::mGetFolderRequest>},
	{"GetItem", process<Structures::mGetItemRequest>},
	{"GetMailTips", process<Structures::mGetMailTipsRequest>},
	{"GetServiceConfiguration", process<Structures::mGetServiceConfigurationRequest>},
	{"GetStreamingEvents", process<Structures::mGetStreamingEventsRequest>},
	{"GetUserAvailabilityRequest", process<Structures::mGetUserAvailabilityRequest>},
	{"GetUserPhoto", process<Structures::mGetUserPhotoRequest>},
	{"GetUserOofSettingsRequest", process<Structures::mGetUserOofSettingsRequest>},
	{"MoveFolder", process<Structures::mMoveFolderRequest>},
	{"MoveItem", process<Structures::mMoveItemRequest>},
	{"ResolveNames", process<Structures::mResolveNamesRequest>},
	{"SendItem", process<Structures::mSendItemRequest>},
	{"SetUserOofSettingsRequest", process<Structures::mSetUserOofSettingsRequest>},
	{"Subscribe", process<Structures::mSubscribeRequest>},
	{"SyncFolderHierarchy", process<Structures::mSyncFolderHierarchyRequest>},
	{"SyncFolderItems", process<Structures::mSyncFolderItemsRequest>},
	{"UpdateFolder", process<Structures::mUpdateFolderRequest>},
	{"UpdateItem", process<Structures::mUpdateItemRequest>},
	{"Unsubscribe", process<Structures::mUnsubscribeRequest>},
};

///////////////////////////////////////////////////////////////////////////////

static void ews_event_proc(const char*, BOOL table, uint32_t, const DB_NOTIFY*);

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
	return strcasecmp(req->f_request_uri.c_str(), "/EWS/Exchange.asmx") == 0 ? TRUE : false;
}

http_status EWSPlugin::fault(int ctx_id, http_status code, const std::string_view& content)
{
	writeheader(ctx_id, code, content.length());
	if(content.length())
		write_response(ctx_id, content.data(), content.length());
	return code;
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
http_status EWSPlugin::proc(int ctx_id, const void* content, uint64_t len)
{
	auto req = get_request(ctx_id);
	if (req->imethod != http_method::post)
		return http_status::method_not_allowed;
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if (auth_info.auth_status != http_status::ok)
		return http_status::unauthorized;
	dispatch(ctx_id, auth_info, content, len);
	return http_status::ok;
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
http_status EWSPlugin::dispatch(int ctx_id, HTTP_AUTH_INFO& auth_info, const void* data, uint64_t len) try
{
	if(ctx_id < 0 || size_t(ctx_id) >= contexts.size())
		return fault(ctx_id, http_status::server_error, "Invalid context ID");
	std::unique_ptr<std::lock_guard<std::mutex>> lockProxy;
	if(debug)
	{
		if(debug->flags & DebugCtx::FL_LOCK)
			lockProxy.reset(new std::lock_guard(debug->requestLock));
		if(debug->flags & DebugCtx::FL_RATELIMIT)
		{
			auto now = std::chrono::high_resolution_clock::now();
			std::this_thread::sleep_for(debug->last-now+debug->minRequestTime);
			debug->last = now;
		}
		if(debug->flags & DebugCtx::FL_LOOP_DETECT) {
			std::lock_guard hashGuard(debug->hashLock);
			uint64_t hash = FNV()(data, len);
			size_t count = debug->requestHashes[hash]++;
			if(count > debug->loopThreshold)
				mlog(LV_WARN, "[ews#%d]: Possible loop, request hash has been seen %zu time%s before", ctx_id, count,
				count == 1? "" : "s");
		}
	}

	using namespace std::string_literals;
	auto& pc = contexts[ctx_id] = std::make_unique<EWSContext>(ctx_id, auth_info, static_cast<const char*>(data), len, *this);
	EWSContext& context = *pc;
	const XMLElement* request = context.request().body->FirstChildElement();
	if(!request)
		return fault(ctx_id, http_status::bad_request, "Missing request node");
	if(request->NextSibling())
		mlog(LV_WARN, "[ews#%d] Additional request nodes found - ignoring", ctx_id);
	if(!rpc_new_stack())
		mlog(LV_WARN, "[ews#%d] Failed to allocate stack, exmdb might not work", ctx_id);
	auto cl0 = make_scope_exit([]{rpc_free_stack();});
	bool enableLog = logEnabled(request->Name());
	if(enableLog && request_logging >= 2)
		mlog(LV_DEBUG, "[ews#%d] Incoming data: %.*s", ctx_id,  len > INT_MAX ? INT_MAX : static_cast<int>(len),
		     static_cast<const char *>(data));

	XMLElement* responseContainer = context.response().body->InsertNewChildElement(request->Name());
	responseContainer->SetAttribute("xmlns:m", Structures::NS_EWS_Messages::NS_URL);
	responseContainer->SetAttribute("xmlns:t", Structures::NS_EWS_Types::NS_URL);
	if(request_logging)
		mlog(LV_DEBUG, "[ews#%d] Processing %s", ctx_id,  request->Name());
	auto handler = requestMap.find(request->Name());
	if(handler == requestMap.end())
		throw Exceptions::UnknownRequestError("Unknown request '"s+request->Name()+"'.");
	else
		handler->second(request, responseContainer, context);

	context.log(enableLog);
	return http_status::ok;
} catch (const Exceptions::InputError &err) {
	return fault(ctx_id, http_status::ok, SOAP::Envelope::fault("SOAP:Client", err.what()));
} catch (const Exceptions::EWSError &err) {
	return fault(ctx_id, http_status::ok, SOAP::Envelope::fault(err.type.c_str(), err.what()));
} catch (const std::exception &err) {
	return fault(ctx_id, http_status::server_error, SOAP::Envelope::fault("SOAP:Server", err.what()));
}

/**
 * @brief     Check if logging is enabled for this request
 *
 * @param     requestName  Name of the request
 *
 * @return    true if logging is enabled, false otherwise
 */
bool EWSPlugin::logEnabled(const std::string_view& requestName) const
{return std::binary_search(logFilters.begin(), logFilters.end(), requestName) != invertFilter;}

EWSPlugin::EWSPlugin()
{
	loadConfig();
	cache.run(cache_interval);
	contexts.resize(get_context_num());
	exmdb.register_proc(reinterpret_cast<void*>(ews_event_proc));
}

EWSPlugin::~EWSPlugin()
{teardown = true;}

/**
 * @brief      Initialize mysql adaptor function pointers
 */
EWSPlugin::_mysql::_mysql()
{
#define getService(f) \
	if (query_service2(# f, f) == nullptr) \
		throw std::runtime_error("[ews]: failed to get the \""# f"\" service")

	getService(get_domain_ids);
	getService(get_domain_info);
	getService(get_homedir);
	getService(get_id_from_homedir);
	getService(get_id_from_maildir);
	getService(get_maildir);
	getService(get_user_aliases);
	getService(get_user_displayname);
	getService(get_user_ids);
	getService(get_user_properties);
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
	query_service2("exmdb_client_register_proc", register_proc);
	 if(register_proc == nullptr)
		throw std::runtime_error("[ews]: failed to get the \"exmdb_client_register_proc\" service\n");
}

static constexpr cfg_directive x500_defaults[] = {
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static constexpr cfg_directive ews_cfg_defaults[] = {
	{"ews_beta", "0", CFG_BOOL},
	{"ews_cache_attachment_instance_lifetime", "30000"},
	{"ews_cache_embedded_instance_lifetime", "30000"},
	{"ews_cache_interval", "5000"},
	{"ews_cache_message_instance_lifetime", "30000"},
	{"ews_event_stream_interval", "45000"},
	{"ews_experimental", "ews_beta", CFG_ALIAS},
	{"ews_log_filter", "!"},
	{"ews_max_user_photo_size", "5M", CFG_SIZE},
	{"ews_pretty_response", "0", CFG_BOOL},
	{"ews_request_logging", "0"},
	{"ews_response_logging", "0"},
	{"smtp_server_ip", "::1"},
	{"smtp_server_port", "25"},
	CFG_TABLE_END,
};

/**
 * @brief      Load configuration file
 */
void EWSPlugin::loadConfig()
{
	auto cfg = config_file_initd("exmdb_provider.cfg", get_config_path(), x500_defaults);
	if(!cfg)
	{
		mlog(LV_INFO, "[ews]: Failed to load config file");
		return;
	}
	x500_org_name = cfg->get_value("x500_org_name");
	mlog(LV_INFO, "[ews]: x500 org name is \"%s\"", x500_org_name.c_str());

	cfg = config_file_initd("ews.cfg", get_config_path(), ews_cfg_defaults);
	experimental = cfg->get_ll("ews_beta");
	pretty_response = cfg->get_ll("ews_pretty_response");
	request_logging = cfg->get_ll("ews_request_logging");
	response_logging = cfg->get_ll("ews_response_logging");

	cache_interval = std::chrono::milliseconds(cfg->get_ll("ews_cache_interval"));
	cache_attachment_instance_lifetime = std::chrono::milliseconds(cfg->get_ll("ews_cache_attachment_instance_lifetime"));
	cache_message_instance_lifetime = std::chrono::milliseconds(cfg->get_ll("ews_cache_message_instance_lifetime"));
	event_stream_interval = std::chrono::milliseconds(cfg->get_ll("ews_event_stream_interval"));
	cache_embedded_instance_lifetime = std::chrono::milliseconds(cfg->get_ll("ews_cache_embedded_instance_lifetime"));
	max_user_photo_size = cfg->get_ll("ews_max_user_photo_size");

	smtp_server_ip = cfg->get_value("smtp_server_ip");
	smtp_server_port = cfg->get_ll("smtp_server_port");

	const char* logFilter = cfg->get_value("ews_log_filter");
	if(logFilter && strlen(logFilter))
	{
		invertFilter = *logFilter == '!';
		logFilter += invertFilter;
		for(const char* sep = strchr(logFilter, ','); sep != nullptr; logFilter = ++sep, sep = strchr(sep, ','))
			logFilters.emplace_back(std::string_view(logFilter, sep-logFilter));
		if(*logFilter)
			logFilters.emplace_back(logFilter);
		std::sort(logFilters.begin(), logFilters.end());
	}
	const char* debugOpts = cfg->get_value("ews_debug");
	if(debugOpts)
		debug = std::make_unique<DebugCtx>(debugOpts);
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
	auto fail = [](auto&&... args){mlog(LV_ERR, args...); return false;};
	LINK_HPM_API(apidata)
	HPM_INTERFACE ifc{};
	ifc.preproc = &EWSPlugin::preproc;
	ifc.proc    = [](int ctx, const void *cont, uint64_t len) { return g_ews_plugin->proc(ctx, cont, len); };
	ifc.retr    = [](int ctx) {return g_ews_plugin? g_ews_plugin->retr(ctx) : HPM_RETRIEVE_DONE;};
	ifc.term    = [](int ctx) {g_ews_plugin? g_ews_plugin->term(ctx) : void(0);};
	if (!register_interface(&ifc))
		return false;
	try {
		g_ews_plugin.reset(new EWSPlugin());
	} catch (const std::exception &e) {
		return fail("[ews] failed to initialize plugin: %s", e.what());
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

/**
 * @brief      NotificationContext state management
 *
 * Update the notification context, processing available events, and manage
 * state transitions.
 *
 * @return     HPM retrieve return code
 */
int EWSContext::notify()
{
	using namespace Structures;
	using NS = NotificationContext::State;

	if(!m_notify || m_notify->state == NS::S_CLOSED)
		return HPM_RETRIEVE_DONE;
	NotificationContext& nctx = *m_notify;
	if(nctx.state == NS::S_WRITE) { // Just wrote something -> got to sleep and set a wake up timer
		nctx.state = NS::S_SLEEP;
		m_plugin.wakeContext(m_ID, m_plugin.event_stream_interval);
		return HPM_RETRIEVE_WAIT;
	}

	XMLPrinter printer(nullptr, !m_plugin.pretty_response);
	bool logResponse = m_log && m_plugin.response_logging >= 2;
	auto loglevel = m_code == http_status::ok? LV_DEBUG : LV_ERR;

	if(nctx.state == NS::S_INIT) { // First call after initialization -> write context data
		m_response.doc.Print(&printer);
		writeheader(m_ID, m_code, 0);
		writecontent(m_ID, {printer.CStr(), static_cast<size_t>(printer.CStrSize()-1)}, logResponse, loglevel);
		nctx.state = NS::S_WRITE;
		return HPM_RETRIEVE_WRITE;
	}

	mGetStreamingEventsResponse data;
	mGetStreamingEventsResponseMessage& msg = data.ResponseMessages.emplace_back();
	SOAP::Envelope envelope;
	tinyxml2::XMLElement* response = envelope.body->InsertNewChildElement("m:GetStreamingEventsResponse");
	auto flush = [&]() {
		data.serialize(response);
		envelope.doc.Print(&printer);
		writecontent(m_ID, {printer.CStr(), static_cast<size_t>(printer.CStrSize()-1)}, logResponse, loglevel);
		return HPM_RETRIEVE_WRITE;
	};

	if(nctx.state == NS::S_CLOSING) { // Someone closed the stream -> write good bye letter and die
		msg.ConnectionStatus = Enum::Closed;
		msg.success();
		nctx.state = NS::S_CLOSED;
		return flush();
	}

	// S_SLEEP: Just woke up, check for new events and deliver update message
	bool moreAny = false;
	for(const tSubscriptionId& subscription : nctx.subscriptions) {
		try {
			auto[events, more] = getEvents(subscription);
			moreAny = moreAny || more;
			tNotification& notification = msg.Notifications.emplace_back();
			notification.SubscriptionId = subscription;
			notification.events = std::move(events);
			notification.MoreEvents = more;
			if(notification.events.empty())
				notification.events.emplace_back(aStatusEvent());
		}
		catch(...) {
			msg.ErrorSubscriptionIds.emplace_back(subscription);
		}
	}
	for(const tSubscriptionId& subscription : msg.ErrorSubscriptionIds)
		nctx.subscriptions.erase(std::remove(nctx.subscriptions.begin(), nctx.subscriptions.end(), subscription),
		                         nctx.subscriptions.end());
	msg.success();
	// If there are no more subscriptions to monitor or the stream expired, close it
	// If there were more events than we could deliver in one message, proceed with the next chunk right away
	// Otherwise just go back to sleep
	nctx.state = (nctx.subscriptions.empty() || tp_now() > nctx.expire)? NS::S_CLOSING : moreAny? NS::S_SLEEP : NS::S_WRITE;
	if(nctx.state == NS::S_SLEEP)
		m_plugin.wakeContext(m_ID, m_plugin.event_stream_interval);
	return flush();
}

int EWSPlugin::retr(int ctx_id)
{
	if(ctx_id < 0 || size_t(ctx_id) >= contexts.size() || !contexts[ctx_id])
		return HPM_RETRIEVE_DONE;
	EWSContext& context = *contexts[ctx_id];
	switch(context.state()) {
	case EWSContext::S_DEFAULT:
	case EWSContext::S_WRITE: {
		XMLPrinter printer(nullptr, !pretty_response);
		context.response().doc.Print(&printer);
		writeheader(ctx_id, context.code(), printer.CStrSize()-1);
		bool logResponse = context.log() && response_logging >= 2;
		auto loglevel = context.code() == http_status::ok? LV_DEBUG : LV_ERR;
		writecontent(ctx_id, {printer.CStr(), static_cast<size_t>(printer.CStrSize()-1)}, logResponse, loglevel);
		context.state(EWSContext::S_DONE);
		if(context.log() && response_logging)
			mlog(loglevel, "[ews#%d] Done, code %d, %d bytes, %.3fms", ctx_id, int(context.code()), printer.CStrSize()-1,
				 context.age()*1000);
		return HPM_RETRIEVE_WRITE;
	}
	case EWSContext::S_DONE: return HPM_RETRIEVE_DONE;
	case EWSContext::S_STREAM_NOTIFY:
		return context.notify();
	}
	return HPM_RETRIEVE_DONE;
}

void EWSPlugin::term(int ctx)
{if(ctx >= 0 && size_t(ctx) < contexts.size()) contexts[ctx].reset();}


static void ews_event_proc(const char* dir, BOOL table, uint32_t ID, const DB_NOTIFY* notification)
{
	if(g_ews_plugin)
		g_ews_plugin->event(dir, table, ID, notification);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//Cache

EWSPlugin::ExmdbInstance::ExmdbInstance(const EWSPlugin& p, const std::string& d, uint32_t i) :
	plugin(p), dir(d), instanceId(i)
{}

/**
 * @brief     Unload instance
 */
EWSPlugin::ExmdbInstance::~ExmdbInstance()
{plugin.exmdb.unload_instance(dir.c_str(), instanceId);}

/**
 * @brief      Initialize subscription object
 *
 * @param      uname   Name of creating user
 * @param      plugin  Parent plugin
 */
EWSPlugin::Subscription::Subscription(const char* uname, const EWSPlugin& plugin) :
	ews(plugin), username(uname)
{}

/**
 * @brief      Cancel subscription
 */
EWSPlugin::Subscription::~Subscription()
{
	std::lock_guard ss_lock(ews.subscriptionLock);
	for(const auto& subKey : subscriptions)
		ews.unsubscribe(subKey);
	if(waitingContext)
		ews.unlinkSubscription(*waitingContext);
}

/**
 * @brief      Wake up context and die
 */
EWSPlugin::WakeupNotify::~WakeupNotify()
{
	if(g_ews_plugin && !g_ews_plugin->teardown)
		wakeup_context(ID);
}

void EWSPlugin::event(const char* dir, BOOL, uint32_t ID, const DB_NOTIFY* notification) const try
{
	using namespace Structures;
	detail::ExmdbSubscriptionKey key{dir, ID};
	std::unique_lock lock(subscriptionLock);
	auto it = subscriptions.find(key);
	if(it == subscriptions.end())
		return;
	detail::SubscriptionKey subKey = it->second;
	lock.unlock();
	sptr<Subscription> sub;
	try {
		sub = std::get<sptr<Subscription>>(cache.get(subKey));
	} catch (...) { // Key not found or type error
	}
	if(!sub)
		return;
	lock = std::unique_lock(sub->lock);
	sTimePoint now(gromox::time_point::clock::now());
	auto mkFid = [&](uint64_t fid){return tFolderId(mkFolderEntryId(sub->mailboxInfo, rop_util_make_eid_ex(1, fid)).serialize());};
	auto mkMid = [&](uint64_t fid, uint64_t mid){return tItemId(mkMessageEntryId(sub->mailboxInfo, rop_util_make_eid_ex(1, fid), rop_util_make_eid_ex(1, mid)).serialize());};
	switch(notification->type)
	{
	case db_notify_type::new_mail: {
		const DB_NOTIFY_NEW_MAIL* evt = static_cast<DB_NOTIFY_NEW_MAIL*>(notification->pdata);
		sub->events.emplace_back(aNewMailEvent(now, mkMid(evt->folder_id, evt->message_id), mkFid(evt->folder_id)));
		break;
	}
	case db_notify_type::folder_created: {
		const DB_NOTIFY_FOLDER_CREATED* evt = static_cast<DB_NOTIFY_FOLDER_CREATED*>(notification->pdata);
		sub->events.emplace_back(aCreatedEvent(now, mkFid(evt->folder_id), mkFid(evt->parent_id)));
		break;
	}
	case db_notify_type::message_created: {
		const DB_NOTIFY_MESSAGE_CREATED* evt = static_cast<DB_NOTIFY_MESSAGE_CREATED*>(notification->pdata);
		sub->events.emplace_back(aCreatedEvent(now, mkMid(evt->folder_id, evt->message_id), mkFid(evt->folder_id)));
		break;
	}
	case db_notify_type::folder_deleted: {
		const DB_NOTIFY_FOLDER_DELETED* evt = static_cast<DB_NOTIFY_FOLDER_DELETED*>(notification->pdata);
		sub->events.emplace_back(aDeletedEvent(now, mkFid(evt->folder_id), mkFid(evt->parent_id)));
		break;
	}
	case db_notify_type::message_deleted: {
		const DB_NOTIFY_MESSAGE_DELETED* evt = static_cast<DB_NOTIFY_MESSAGE_DELETED*>(notification->pdata);
		sub->events.emplace_back(aDeletedEvent(now, mkMid(evt->folder_id, evt->message_id), mkFid(evt->folder_id)));
		break;
	}
	case db_notify_type::folder_modified: {
		const DB_NOTIFY_FOLDER_MODIFIED* evt = static_cast<DB_NOTIFY_FOLDER_MODIFIED*>(notification->pdata);
		sub->events.emplace_back(tModifiedEvent(now, mkFid(evt->folder_id), mkFid(evt->parent_id)));
		break;
	}
	case db_notify_type::message_modified: {
		const DB_NOTIFY_MESSAGE_MODIFIED* evt = static_cast<DB_NOTIFY_MESSAGE_MODIFIED*>(notification->pdata);
		sub->events.emplace_back(tModifiedEvent(now, mkMid(evt->folder_id, evt->message_id), mkFid(evt->folder_id)));
		break;
	}
	case db_notify_type::folder_moved: {
		const DB_NOTIFY_FOLDER_MVCP* evt = static_cast<DB_NOTIFY_FOLDER_MVCP*>(notification->pdata);
		sub->events.emplace_back(aMovedEvent(now, mkFid(evt->folder_id), mkFid(evt->parent_id), static_cast<aOldFolderId&&>(mkFid(evt->old_folder_id)),
		                                     static_cast<aOldFolderId&&>(mkFid(evt->old_parent_id))));
		break;
	}
	case db_notify_type::message_moved: {
		const DB_NOTIFY_MESSAGE_MVCP* evt = static_cast<DB_NOTIFY_MESSAGE_MVCP*>(notification->pdata);
		sub->events.emplace_back(aMovedEvent(now, mkMid(evt->folder_id, evt->message_id), mkFid(evt->folder_id),
		                                     static_cast<aOldItemId&&>(mkMid(evt->old_folder_id, evt->old_message_id)),
		                                     static_cast<aOldFolderId&&>(mkFid(evt->old_folder_id))));
		break;
	}
	case db_notify_type::folder_copied: {
		const DB_NOTIFY_FOLDER_MVCP* evt = static_cast<DB_NOTIFY_FOLDER_MVCP*>(notification->pdata);
		sub->events.emplace_back(aCopiedEvent(now, mkFid(evt->folder_id), mkFid(evt->parent_id), static_cast<aOldFolderId&&>(mkFid(evt->old_folder_id)),
		                                      static_cast<aOldFolderId&&>(mkFid(evt->old_parent_id))));
		break;
	}
	case db_notify_type::message_copied: {
		const DB_NOTIFY_MESSAGE_MVCP* evt = static_cast<DB_NOTIFY_MESSAGE_MVCP*>(notification->pdata);
		sub->events.emplace_back(aCopiedEvent(now, mkMid(evt->folder_id, evt->message_id), mkFid(evt->folder_id),
		                                      static_cast<aOldItemId&&>(mkMid(evt->old_folder_id, evt->old_message_id)),
		                                      static_cast<aOldFolderId&&>(mkFid(evt->old_folder_id))));
		break;
	}
	default:
		break;
	}
	if(sub->waitingContext)
		// Reschedule next wakeup 0.1 seconds. Should be enough to gather related events.
		// Is still bound to the ObjectCache cleanup cycle and might take significantly longer than that.
		cache.get(*sub->waitingContext, std::chrono::milliseconds(100));
} catch(const std::exception& err)
{mlog(LV_ERR, "Failed to process notification: %s", err.what());}

/**
 * @brief      Load message instance
 *
 * @param      dir   Home directory of user or domain
 * @param      fid   Parent folder ID
 * @param      mid   Message ID
 *
 * @return     Message instance information
 */
std::shared_ptr<EWSPlugin::ExmdbInstance> EWSPlugin::loadMessageInstance(const std::string& dir, uint64_t fid,
                                                                         uint64_t mid) const
{
	detail::MessageInstanceKey mkey{dir, mid};
	try {
		return std::get<std::shared_ptr<EWSPlugin::ExmdbInstance>>(cache.get(mkey, cache_message_instance_lifetime));
	} catch(const std::out_of_range&) {
	}
	uint32_t instanceId;
	if(!exmdb.load_message_instance(dir.c_str(), nullptr, CP_ACP, false,fid, mid, &instanceId))
		throw DispatchError(Exceptions::E3077);
	std::shared_ptr<ExmdbInstance> instance(new ExmdbInstance(*this, dir, instanceId));
	cache.emplace(cache_message_instance_lifetime, mkey, instance);
	return instance;
}

/**
 * @brief      Link subscription to a waiting context
 *
 * Registers the context as waiting for subscription events.
 *
 * If another context is already waiting, it is unlinked and closed.
 *
 * Linking fails if the subscription does not exist or was created by another user.
 *
 * @param      subscriptionId  Id of the subscription
 * @param      ctx             Context to link to
 *
 * @return     true if successful, false otherwise
 */
bool EWSPlugin::linkSubscription(const Structures::tSubscriptionId& subscriptionId, const EWSContext& ctx) const
{
	auto sub = subscription(subscriptionId.ID, subscriptionId.timeout);
	if(!sub || sub->username != ctx.auth_info().username)
		return false;
	std::lock_guard subLock(sub->lock);
	if(sub->waitingContext)
		unlinkSubscription(*sub->waitingContext);
	sub->waitingContext = ctx.ID();
	return true;
}

/**
 * @brief      Load attachment instance
 *
 * @param      dir   Home directory of user or domain
 * @param      fid   Parent folder ID
 * @param      mid   Message ID
 * @param      aid   Attachment ID
 *
 * @return     Attachment instance information
 */
std::shared_ptr<EWSPlugin::ExmdbInstance> EWSPlugin::loadAttachmentInstance(const std::string& dir, uint64_t fid,
                                                                            uint64_t mid, uint32_t aid) const
{
	detail::AttachmentInstanceKey akey{dir, mid, aid};
	try {
		return std::get<std::shared_ptr<EWSPlugin::ExmdbInstance>>(cache.get(akey, cache_attachment_instance_lifetime));
	} catch(const std::out_of_range&) {
	}
	auto messageInstance = loadMessageInstance(dir, fid, mid);
	uint32_t instanceId;
	if(!exmdb.load_attachment_instance(dir.c_str(), messageInstance->instanceId, aid, &instanceId))
		throw DispatchError(Exceptions::E3078);
	std::shared_ptr<ExmdbInstance> instance(new ExmdbInstance(*this, dir, instanceId));
	cache.emplace(cache_message_instance_lifetime, akey, instance);
	return instance;
}

/**
 * @brief      Create subscription
 *
 * @param      ID        Subscription ID
 * @param      username  Owner
 *
 * @return Pointer to created subscription
 */
std::shared_ptr<EWSPlugin::Subscription> EWSPlugin::mksub(const Structures::tSubscriptionId& ID, const char* username) const
{
	using ms = std::chrono::milliseconds;
	auto sub = std::make_shared<Subscription>(username, *this);
	cache.emplace(ms(ID.timeout*60'000), ID.ID, sub);
	return sub;
}

/**
 * @brief     Create subscription
 *
 * @param     username    Name of the creating user
 * @param     maildir     Home directory of subscription target
 * @param     flags       Subscribed events
 * @param     all         Whether to subscribe to all
 * @param     folderId    Folder to subscribe to
 * @param     timeout     Timeout (minutes) of the subscription
 *
 * @return    Subscription key
 */
detail::ExmdbSubscriptionKey EWSPlugin::subscribe(const std::string& maildir, uint16_t flags,
                                                  bool all, uint64_t folderId, gromox::EWS::detail::SubscriptionKey parent) const
{
	detail::ExmdbSubscriptionKey key{maildir, 0};
	if(!exmdb.subscribe_notification(maildir.c_str(), flags, all? TRUE : false, folderId, 0, &key.second))
		throw DispatchError(Exceptions::E3204);
	std::lock_guard lock(subscriptionLock);
	subscriptions.emplace(key, parent);
	return key;
}

/**
 * @brief      Get subscription with given key
 *
 * @param      subscriptionKey   Subscription key
 * @param      username          Name of accessing user
 *
 * @throw      AccessDenied      Accessing user is not the creator of this subscription
 *
 * @return     Pointer to subscription or nullptr if not found
 */
std::shared_ptr<EWSPlugin::Subscription> EWSPlugin::subscription(detail::SubscriptionKey subscriptionKey, uint32_t timeout) const
{
	try {
		return std::get<sptr<Subscription>>(cache.get(subscriptionKey, std::chrono::milliseconds(timeout*60'000)));
	} catch (...) { // Key not found or type error
		return nullptr;
	}
}

/**
 * @brief      Unlink subscription from context
 *
 * Automatically cancels wake up timer, closing the stream immediately.
 *
 * @param      ctx_id  Context to unlink
 */
void EWSPlugin::unlinkSubscription(int ctx_id) const
{
	auto& pOldCtx = contexts[ctx_id];
	if(pOldCtx) {
		pOldCtx->disableEventStream();
		cache.evict(ctx_id);
	}
}

/**
 * @brief      Remove subscription
 *
 * If the supplied username does not match the username of the subscription,
 * the call has no effect.
 *
 * @param      subscriptionKey   Subscription to remove
 * @param      username          Requesting user
 *
 * @return true if subscription was removed, false otherwise
 */
bool EWSPlugin::unsubscribe(detail::SubscriptionKey subscriptionKey, const char* username) const
{
	try {
		CacheKey key = subscriptionKey;
		auto subscription = std::get<sptr<Subscription>>(cache.get(key));
		if(subscription->username != username)
			return false;
		cache.evict(key);
		return true;
	} catch (...) { // Key not found or type error
		return false;
	}
}

/**
 * @brief      Terminate exmdb subscription
 *
 * @param      key    Subscription key
 */
void EWSPlugin::unsubscribe(const detail::ExmdbSubscriptionKey& key) const
{
	subscriptions.erase(key);
	exmdb.unsubscribe_notification(key.first.c_str(), key.second);
}

/**
 * @brief     Schedule context wakeup
 *
 * @param     ID       Context ID
 * @param     timeout  Time until wake up
 */
void EWSPlugin::wakeContext(int ID, std::chrono::milliseconds timeout) const
{cache.emplace(timeout, ID, std::make_shared<WakeupNotify>(ID));}

///////////////////////////////////////////////////////////////////////////////
// Util

/**
 * @brief      Generate folder entry ID
 *
 * @param      mbinfo  Mailbox metadata
 * @param      fid     Folder id
 *
 * @return     Folder entry ID
 */
gromox::EWS::Structures::sFolderEntryId EWSPlugin::mkFolderEntryId(const Structures::sMailboxInfo& mbinfo, uint64_t fid) const
{
	Structures::sFolderEntryId feid{};
	BINARY tmp_bin{0, {.pv = &feid.provider_uid}};
	rop_util_guid_to_binary(mbinfo.mailboxGuid, &tmp_bin);
	feid.folder_type = mbinfo.isPublic? EITLT_PUBLIC_FOLDER : EITLT_PRIVATE_FOLDER;
	feid.database_guid = replid_to_replguid(mbinfo, rop_util_get_replid(fid));
	feid.global_counter = rop_util_get_gc_array(fid);
	return feid;
}

/**
 * @brief      Generate message entry ID
 *
 * @param      mbinfo  Mailbox metadata
 * @param      fid     Parent folder id
 * @param      mid     Message id
 *
 * @return     Message entry ID
 */
Structures::sMessageEntryId EWSPlugin::mkMessageEntryId(const Structures::sMailboxInfo& mbinfo, uint64_t fid, uint64_t mid) const
{
	Structures::sMessageEntryId meid{};
	BINARY tmp_bin{0, {.pv = &meid.provider_uid}};
	rop_util_guid_to_binary(mbinfo.mailboxGuid, &tmp_bin);
	meid.message_type = mbinfo.isPublic? EITLT_PUBLIC_MESSAGE : EITLT_PRIVATE_MESSAGE;
	meid.folder_database_guid = replid_to_replguid(mbinfo, rop_util_get_replid(fid));
	meid.folder_global_counter = rop_util_get_gc_array(fid);
	meid.message_database_guid = replid_to_replguid(mbinfo, rop_util_get_replid(mid));
	meid.message_global_counter = rop_util_get_gc_array(mid);
	return meid;
}

/**
 * @brief      Load embedded instance
 *
 * @param      dir   Home directory of user or domain
 * @param      aid   Attachment ID
 *
 * @return     Embedded instance information
 */
std::shared_ptr<EWSPlugin::ExmdbInstance> EWSPlugin::loadEmbeddedInstance(const std::string& dir, uint32_t aid) const
{
	detail::EmbeddedInstanceKey ekey{dir, aid};
	try {
		return std::get<std::shared_ptr<EWSPlugin::ExmdbInstance>>(cache.get(ekey, cache_embedded_instance_lifetime));
	} catch(const std::out_of_range&) {
	}
	uint32_t instanceId;
	if(!exmdb.load_embedded_instance(dir.c_str(), false, aid, &instanceId))
		throw DispatchError(Exceptions::E3208);
	std::shared_ptr<ExmdbInstance> instance(new ExmdbInstance(*this, dir, instanceId));
	cache.emplace(cache_embedded_instance_lifetime, ekey, instance);
	return instance;
}

///////////////////////////////////////////////////////////////////////////////
// Hashing

template<>
inline uint64_t FNV::operator()(const std::string& str) noexcept
{return operator()(str.data(), str.size());}

size_t std::hash<detail::AttachmentInstanceKey>::operator()(const detail::AttachmentInstanceKey& key) const noexcept
{return FNV(key.dir, key.mid, key.aid).value;}

size_t std::hash<detail::MessageInstanceKey>::operator()(const detail::MessageInstanceKey& key) const noexcept
{return FNV(key.dir, key.mid).value;}

size_t std::hash<detail::ExmdbSubscriptionKey>::operator()(const detail::ExmdbSubscriptionKey& key) const noexcept
{return FNV(key.first, key.second).value;}

size_t std::hash<detail::EmbeddedInstanceKey>::operator()(const detail::EmbeddedInstanceKey& key) const noexcept
{return FNV(key.dir, key.aid).value;}
