// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <csignal>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <variant>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/cookie_parser.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "mh_common.hpp"
#include "nsp_bridge.hpp"
#include "nsp_common.hpp"
#include "nsp_ops.hpp"

using namespace gromox;
using namespace hpm_mh;

DECLARE_HPM_API();

using NspRequest = std::variant<
	bind_request,
	unbind_request,
	comparemids_request,
	dntomid_request,
	getmatches_request,
	getproplist_request,
	getprops_request,
	getspecialtable_request,
	gettemplateinfo_request,
	modlinkatt_request,
	modprops_request,
	querycolumns_request,
	queryrows_request,
	resolvenames_request,
	resortrestriction_request,
	seekentries_request,
	updatestat_request,
	getmailboxurl_request,
	getaddressbookurl_request
>;

using NspResponse = std::variant<
	bind_response,
	unbind_response,
	comparemids_response,
	dntomid_response,
	getmatches_response,
	getproplist_response,
	getprops_response,
	getspecialtable_response,
	gettemplateinfo_response,
	modlinkatt_response,
	modprops_response,
	querycolumns_response,
	queryrows_response,
	resolvenames_response,
	resortrestriction_response,
	seekentries_response,
	updatestat_response,
	getmailboxurl_response,
	getaddressbookurl_response
>;

enum ReqIndex : size_t
{
	IBind,
	IUnbind,
	IComparemids,
	IDntomid,
	IGetmatches,
	IGetproplist,
	IGetprops,
	IGetspecialtable,
	IGettemplateinfo,
	IModlinkatt,
	IModprops,
	IQuerycolumns,
	IQueryrows,
	IResolvenames,
	IResortrestriction,
	ISeekentries,
	IUpdatestat,
	IGetmailboxurl,
	IGetaddressbookurl
};

static constexpr int AVERAGE_SESSION_PER_CONTEXT = 10;

static BOOL (*get_id_from_username)(const char *, int *);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief	NSP processing context struct
 */
struct MhNspContext : public MhContext
{
	template<size_t I> using Request_t = std::variant_alternative_t<I, NspRequest>;	///< Request type by index
	template<size_t I> using Response_t = std::variant_alternative_t<I, NspResponse>; ///< Response type by index

	explicit MhNspContext(int contextId) : MhContext(contextId) {
		ext_push.init(push_buff, static_cast<uint32_t>(arsizeof(push_buff)), EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
		epush = &ext_push;
	}

	uint32_t getaddressbookurl(char* = nullptr);
	uint32_t getmailboxurl();

	NspRequest request{};
	NspResponse response{};
	nsp_ext_pull ext_pull{};
	nsp_ext_push ext_push{};
};

class MhNspPlugin
{
public:

	explicit MhNspPlugin(void**);
	~MhNspPlugin();
	NOMOVE(MhNspPlugin);

	BOOL process(int, const void*, uint64_t);
private:
	using SessionIterator = std::unordered_map<std::string, session_data>::iterator;
	using ProcRes = std::optional<BOOL>;

	static void* scanWork(void*);

	SessionIterator removeSession(SessionIterator);
	SessionIterator removeSession(const char*);

	ProcRes loadCookies(MhNspContext&);
	ProcRes bind(MhNspContext&);
	ProcRes unbind(MhNspContext&);
	ProcRes getMailboxUrl(MhNspContext&);
	ProcRes getAddressBookUrl(MhNspContext&);

	template<size_t RI, bool copystat = false>
	ProcRes proxy(MhNspContext&);

	gromox::atomic_bool stop = false;
	pthread_t scan;
	std::mutex hashLock;
	std::unordered_map<std::string, int> users;
	std::unordered_map<std::string, session_data> sessions;

	static constexpr std::pair<const char *, MhNspPlugin::ProcRes(MhNspPlugin::*)(MhNspContext&)> reqProcessors[19] = {
		{"bind", &MhNspPlugin::bind},
		{"comparemids", &MhNspPlugin::proxy<IComparemids>},
		{"dntomid", &MhNspPlugin::proxy<IDntomid>},
		{"getaddressbookurl", &MhNspPlugin::getAddressBookUrl},
		{"getmailboxurl", &MhNspPlugin::getMailboxUrl},
		{"getmatches", &MhNspPlugin::proxy<IGetmatches, true>},
		{"getproplist", &MhNspPlugin::proxy<IGetproplist>},
		{"getprops", &MhNspPlugin::proxy<IGetprops>},
		{"getspecialtable", &MhNspPlugin::proxy<IGetspecialtable>},
		{"gettemplateinfo", &MhNspPlugin::proxy<IGettemplateinfo>},
		{"modlinkatt", &MhNspPlugin::proxy<IModlinkatt>},
		{"modprops", &MhNspPlugin::proxy<IModprops>},
		{"querycolumn", &MhNspPlugin::proxy<IQuerycolumns>},
		{"queryrows", &MhNspPlugin::proxy<IQueryrows, true>},
		{"resolvenames", &MhNspPlugin::proxy<IResolvenames>},
		{"resortrestriction", &MhNspPlugin::proxy<IResortrestriction, true>},
		{"seekentries", &MhNspPlugin::proxy<ISeekentries, true>},
		{"unbind", &MhNspPlugin::unbind},
		{"updatestat", &MhNspPlugin::proxy<IUpdatestat, true>},
	};
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void* MhNspPlugin::scanWork(void* ptr)
{
	MhNspPlugin& plugin = *static_cast<MhNspPlugin*>(ptr);
	while (!plugin.stop) {
		auto cur_time = time_point::clock::now();
		std::unique_lock hl_hold(plugin.hashLock);
		for (auto entry = plugin.sessions.begin(); entry != plugin.sessions.end(); ) {
			if (entry->second.expire_time < cur_time)
				entry = plugin.removeSession(entry);
			else
				++entry;
		}
		hl_hold.unlock();
		sleep(3);
	}
	return nullptr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief	Initialize NSP plugin
 *
 * @throws	std::runtime_error
 *
 * @param	ppdata	Plugin API data
 */
MhNspPlugin::MhNspPlugin(void** ppdata)
{
	LINK_HPM_API(ppdata)
	if (!query_service1(get_id_from_username))
		throw std::runtime_error("[mh_nsp]: fail to get \"get_id_from_username\" service\n");
	if (!query_service1(nsp_interface_bind) ||
	    !query_service1(nsp_interface_compare_mids) ||
	    !query_service1(nsp_interface_dntomid) ||
	    !query_service1(nsp_interface_get_matches) ||
	    !query_service1(nsp_interface_get_proplist) ||
	    !query_service1(nsp_interface_get_props) ||
	    !query_service1(nsp_interface_get_specialtable) ||
	    !query_service1(nsp_interface_get_templateinfo) ||
	    !query_service1(nsp_interface_mod_linkatt) ||
	    !query_service1(nsp_interface_mod_props) ||
	    !query_service1(nsp_interface_query_columns) ||
	    !query_service1(nsp_interface_query_rows) ||
	    !query_service1(nsp_interface_resolve_namesw) ||
	    !query_service1(nsp_interface_resort_restriction) ||
	    !query_service1(nsp_interface_seek_entries) ||
	    !query_service1(nsp_interface_unbind) ||
	    !query_service1(nsp_interface_update_stat))
		throw std::runtime_error("exchange_nsp not loaded\n");
	size_t context_num = get_context_num();
	users.reserve(AVERAGE_SESSION_PER_CONTEXT*context_num);
	sessions.reserve(AVERAGE_SESSION_PER_CONTEXT*context_num);
	stop = false;
	if (pthread_create(&scan, nullptr, &MhNspPlugin::scanWork, this)) {
		stop = true;
		throw std::runtime_error("failed to create scanning thread");
	}
}

/**
 * @brief	Destructor
 *
 * Stops the scan thread and block until it exited.
 */
MhNspPlugin::~MhNspPlugin()
{
	if (!stop) {
		stop = true;
		if (!pthread_equal(scan, {})) {
			pthread_kill(scan, SIGALRM);
			pthread_join(scan, nullptr);
		}
	}
}

/**
 * @brief	Remove a session
 *
 * Remove session and decrease users session count.
 * If the session count drops to zero, the user is automatically removed.
 *
 * Does not perform locking, any relevant locks must be acquired before calling.
 *
 * @param	session	Iterator to the session to remove
 *
 * @return	Iterator of the next element
 */
MhNspPlugin::SessionIterator MhNspPlugin::removeSession(SessionIterator session)
{
	if (session == sessions.end())
		return session;
	auto user = users.find(session->second.username);
	if (user != users.end() && --user->second <= 0)
		users.erase(user);
	return sessions.erase(session);
}

/**
 * @brief	Remove a session
 *
 * Remove session and decrease users session count.
 * If the session count drops to zero, the user is automatically removed.
 *
 * Does not perform locking, any relevant locks must be acquired before calling.
 *
 * @param	sessionID	ID of the session to remove
 *
 * @return	Iterator of the next element
 */
MhNspPlugin::SessionIterator MhNspPlugin::removeSession(const char* sessionID)
{return removeSession(sessions.find(sessionID));}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static std::unique_ptr<MhNspPlugin> plugin; ///< Global plugin

static BOOL nsp_preproc(int);
static int nsp_retr(int);
static BOOL nsp_proc(int, const void*, uint64_t);

/**
 * @brief	Plugin setup/teardown
 *
 * @param	reason	Whether to create ot destroy plugin
 * @param	plugdata	Data required for creation
 *
 * @return	TRUE if successful, false otherwise
 */
static BOOL hpm_mh_nsp(int reason, void **plugdata)
{
	HPM_INTERFACE interface;

	switch (reason) {
	case PLUGIN_INIT: {
		std::unique_ptr<MhNspPlugin> created;
		try {
			created = std::make_unique<MhNspPlugin>(plugdata);
		} catch(std::bad_alloc& exc) {
			printf("[mh_nsp]: failed to allocate plugin memory (%s)\n", exc.what());
		} catch(std::runtime_error& exc) {
			printf("[mh_nsp]: failed to initialize plugin (%s)\n", exc.what());
		} catch(std::exception& exc) {
			printf("[mh_nsp]: unknown error during initialization (%s)\n", exc.what());
		}
		interface.preproc = nsp_preproc;
		interface.proc = nsp_proc;
		interface.retr = nsp_retr;
		interface.send = nullptr;
		interface.receive = nullptr;
		interface.term = nullptr;
		if (!register_interface(&interface))
			return false;
		plugin = std::move(created);
		printf("[mh_nsp]: plugin is loaded into system\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		plugin.reset();
		return TRUE;
	}
	return false;
}
HPM_ENTRY(hpm_mh_nsp);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief	Preprocess request
 *
 * @param	context_id	ID of request context
 *
 * @return	TRUE if request is valid, false on error
 */
static BOOL nsp_preproc(int context_id)
{
	char tmp_uri[1024];

	auto prequest = get_request(context_id);
	if (strcasecmp(prequest->method, "POST") != 0)
		return false;
	auto tmp_len = prequest->f_request_uri.read(tmp_uri, arsizeof(tmp_uri));
	if (tmp_len == MEM_END_OF_FILE)
		return false;
	tmp_uri[tmp_len] = '\0';
	if (strncasecmp(tmp_uri, "/mapi/nspi/?MailboxId=", 22) != 0)
		return false;
	auto pconnection = get_connection(context_id);
	set_ep_info(context_id, tmp_uri + 22, pconnection->server_port);
	return TRUE;
}

uint32_t MhNspContext::getaddressbookurl(char* dest)
{
	int user_id;
	char username1[UADDR_SIZE], hex_string[32];

	if (dest == nullptr)
		dest = std::get<getaddressbookurl_response>(response).server_url;
	get_id_from_username(auth_info.username, &user_id);
	memset(username1, 0, arsizeof(username1));
	gx_strlcpy(username1, auth_info.username, arsizeof(username1));
	auto token = strchr(username1, '@');
	HX_strlower(username1);
	if (token != nullptr)
		++token;
	else
		token = username1;
	encode_hex_int(user_id, hex_string);
	sprintf(dest, "https://%s/mapi/nspi/?MailboxId="
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%s@%s",
		get_host_ID(), username1[0], username1[1], username1[2], username1[3],
		username1[4], username1[5], username1[6], username1[7], username1[8],
		username1[9], username1[10], username1[11], hex_string, token);
	return ecSuccess;
}

uint32_t MhNspContext::getmailboxurl() try
{
	const auto& req = std::get<getmailboxurl_request>(request);
	auto& resp = std::get<getmailboxurl_response>(response);
	std::string tmp_buff = req.user_dn;
	auto token = strrchr(tmp_buff.data(), '/');
	if (token == nullptr || strncasecmp(token, "/cn=", 4) != 0)
		return getaddressbookurl(resp.server_url);
	*token = '\0';
	token = strrchr(tmp_buff.data(), '/');
	if (token == nullptr || strncasecmp(token, "/cn=", 4) != 0)
		return getaddressbookurl(resp.server_url);
	snprintf(resp.server_url, arsizeof(resp.server_url),
	         "https://%s/mapi/emsmdb/?MailboxId=%s", get_host_ID(), token + 4);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static void produce_session(const char *tag, char *session)
{
	auto cur_time = time(nullptr);
	char temp_time[16], temp_name[16];
	snprintf(temp_time, arsizeof(temp_time), "%lx", static_cast<long>(cur_time));
	if (strlen(tag) >= 16) {
		memcpy(temp_name, tag, 16);
	} else {
		memset(temp_name, '0', 16);
		memcpy(temp_name, tag, strlen(tag));
	}
	for (char *c = temp_name, *end = temp_name+16; c < end; ++c)
		if (!HX_isalpha(*c) && !HX_isdigit(*c))
			*c = !HX_isalpha(*c) && !HX_isdigit(*c)? '0' + rand() % 10 : HX_tolower(*c);
	for (size_t i = 0; i < 32; ++i) {
		auto mod = i % 4;
		auto pos = i / 4;
		session[i] = mod == 0 || mod == 1 ? temp_name[pos*2+mod] :
		             mod == 2 ? 'a' + rand() % 26 : temp_time[pos];
	}
	session[32] = '\0';
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief	Parse request cookies
 *
 * @param	Context object to process
 *
 * @return	std::nullopt if successful, plugin return code otherwise
 */
MhNspPlugin::ProcRes MhNspPlugin::loadCookies(MhNspContext& ctx)
{
	char tmp_buff[1024];
	auto tmp_len = ctx.orig.f_cookie.read(tmp_buff, arsizeof(tmp_buff) - 1);
	if (tmp_len == MEM_END_OF_FILE) {
		if (strcasecmp(ctx.request_value, "Bind") != 0)
			return ctx.error_responsecode(RC_MISSING_COOKIE);
		ctx.session = nullptr;
		if (strcasecmp(ctx.request_value, "PING") == 0) {
			nsp_bridge_touch_handle(ctx.session_guid);
			return ctx.ping_response();
		}
		return std::nullopt;
	}
	tmp_buff[tmp_len] = '\0';
	auto pparser = cookie_parser_init(tmp_buff);
	auto string = cookie_parser_get(pparser, "sid");
	if (string == nullptr || strlen(string) >= arsizeof(ctx.session_string))
		return ctx.error_responsecode(RC_INVALID_CONTEXT_COOKIE);
	gx_strlcpy(ctx.session_string, string, arsizeof(ctx.session_string));
	if (strcasecmp(ctx.request_value, "PING") != 0 &&
	    strcasecmp(ctx.request_value, "Unbind") != 0) {
		string = cookie_parser_get(pparser, "sequence");
		if (string == nullptr || !ctx.sequence_guid.from_str(string))
			return ctx.error_responsecode(RC_INVALID_CONTEXT_COOKIE);
	}
	std::unique_lock hl_hold(hashLock);
	auto it = sessions.find(ctx.session_string);
	if (it == sessions.end())
		return ctx.error_responsecode(RC_INVALID_CONTEXT_COOKIE);
	if (it->second.expire_time < ctx.start_time) {
		removeSession(it);
		return ctx.error_responsecode(RC_INVALID_CONTEXT_COOKIE);
	}
	ctx.session = &it->second;
	if (strcasecmp(ctx.request_value, "PING") != 0 &&
	    strcasecmp(ctx.request_value, "Bind") !=0 &&
	    strcasecmp(ctx.request_value, "Unbind") != 0 &&
	    ctx.sequence_guid != ctx.session->sequence_guid)
			return ctx.error_responsecode(RC_INVALID_SEQUENCE);
	if (strcasecmp(ctx.request_value, "PING") != 0 &&
	    strcasecmp(ctx.request_value, "Unbind") != 0) {
		ctx.sequence_guid = GUID::random_new();
		ctx.session->sequence_guid = ctx.sequence_guid;
	}
	ctx.session_guid = ctx.session->session_guid;
	ctx.session->expire_time = ctx.start_time + session_valid_interval + std::chrono::seconds(60);
	if (strcasecmp(ctx.request_value, "PING") == 0) {
		nsp_bridge_touch_handle(ctx.session_guid);
		return ctx.ping_response();
	}
	return std::nullopt;
}

MhNspPlugin::ProcRes MhNspPlugin::bind(MhNspContext& ctx)
{
	auto& request = ctx.request.emplace<bind_request>();
	auto& response = ctx.response.emplace<bind_response>();
	if (ctx.ext_pull.g_nsp_request(request) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	response.result = nsp_bridge_run(ctx.session_guid, request, response);
	if (response.result != ecSuccess) {
		if (ctx.ext_push.p_nsp_response(response) != EXT_ERR_SUCCESS)
			return ctx.failure_response(RPC_X_BAD_STUB_DATA);
		return std::nullopt;
	}
	if (ctx.session != nullptr) {
		std::lock_guard hl_hold(hashLock);
		auto sd_iter = sessions.find(ctx.session_string);
		if (sd_iter != sessions.end()) {
			auto& psession = sd_iter->second;
			nsp_bridge_unbind(psession.session_guid, 0);
			psession.session_guid = ctx.session_guid;
		}
	} else {
		produce_session(ctx.auth_info.username, ctx.session_string);
		ctx.sequence_guid = GUID::random_new();
		auto exptime = time_point::clock::now() + session_valid_interval + std::chrono::seconds(60);
		std::unique_lock hl_hold(hashLock);
		try {
			auto emplaced = sessions.try_emplace(ctx.session_string, ctx.session_guid, ctx.sequence_guid, ctx.auth_info.username, exptime);
			if (!emplaced.second) {
				hl_hold.unlock();
				nsp_bridge_unbind(ctx.session_guid, 0);
				return ctx.failure_response(ecInsufficientResrc);
			}
			auto ucount = users.emplace(emplaced.first->second.username, 0);
			++ucount.first->second;
		}  catch (std::bad_alloc&) {
			hl_hold.unlock();
			nsp_bridge_unbind(ctx.session_guid, 0);
			return ctx.failure_response(ecMAPIOOM);
		}
	}
	if (ctx.ext_push.p_nsp_response(response) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

MhNspPlugin::ProcRes MhNspPlugin::unbind(MhNspContext& ctx)
{
	auto& request = ctx.request.emplace<unbind_request>();
	auto& response = ctx.response.emplace<unbind_response>();
	if (ctx.ext_pull.g_nsp_request(request) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	response.result = nsp_bridge_unbind(ctx.session_guid, request.reserved);
	std::unique_lock hl_hold(hashLock);
	removeSession(ctx.session_string);
	hl_hold.unlock();
	if (ctx.ext_push.p_nsp_response(response) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

template<size_t RI, bool copystat>
MhNspPlugin::ProcRes MhNspPlugin::proxy(MhNspContext& ctx)
{
	auto& request = ctx.request.emplace<RI>();
	auto& response = ctx.response.emplace<RI>();
	if (ctx.ext_pull.g_nsp_request(request) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	response.result = nsp_bridge_run(ctx.session_guid, request, response);
	if constexpr(copystat)
		response.stat = request.stat;
	if (ctx.ext_push.p_nsp_response(response))
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

MhNspPlugin::ProcRes MhNspPlugin::getMailboxUrl(MhNspContext& ctx)
{
	auto& request = ctx.request.emplace<getmailboxurl_request>();
	auto& response = ctx.response.emplace<getmatches_response>();
	if (ctx.ext_pull.g_nsp_request(request) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	response.result = ctx.getmailboxurl();
	if (ctx.ext_push.p_nsp_response(response) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

MhNspPlugin::ProcRes MhNspPlugin::getAddressBookUrl(MhNspContext& ctx)
{
	auto& request = ctx.request.emplace<getaddressbookurl_request>();
	auto& response = ctx.response.emplace<getaddressbookurl_response>();
	if (ctx.ext_pull.g_nsp_request(request) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	response.result = ctx.getaddressbookurl();
	if (ctx.ext_push.p_nsp_response(response) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

BOOL MhNspPlugin::process(int context_id, const void *content, uint64_t length)
{
	ProcRes result;
	MhNspContext ctx(context_id);
	if (!ctx.auth_info.b_authed)
		return ctx.unauthed();
	if (!ctx.loadHeaders())
		return false;
	if (ctx.request_value[0] == '\0')
		return ctx.error_responsecode(RC_INVALID_VERB);
	if (ctx.request_id[0] == '\0' || ctx.client_info[0] == '\0')
		return ctx.error_responsecode(RC_MISSING_HEADER);
	if ((result = loadCookies(ctx)))
		return result.value();
	set_context(context_id);
	rpc_new_environment();
	auto cleanup_0 = make_scope_exit([&]() { rpc_free_environment(); });

	ctx.ext_pull.init(content, length, cu_alloc1, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	HX_strlower(ctx.request_value);
	auto proc = std::lower_bound(cbegin(reqProcessors), cend(reqProcessors),
	            ctx.request_value, [](const auto &a, const char *b) -> bool {
	            	return strcmp(a.first, b) < 0;
	            });
	if (proc != cend(reqProcessors)) {
		if ((result = (this->*proc->second)(ctx)))
			return result.value();
	} else {
		return false;
	}
	return ctx.normal_response();
}

static int nsp_retr(int)
{ return HPM_RETRIEVE_DONE; }

static BOOL nsp_proc(int context_id, const void *content, uint64_t length)
{ return plugin ? plugin->process(context_id, content, length) : false; }
