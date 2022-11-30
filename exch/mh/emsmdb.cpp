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
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/cookie_parser.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rpc_types.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "mh_common.hpp"

DECLARE_HPM_API();

using namespace gromox;
using namespace hpm_mh;

enum {
	PENDING_STATUS_NONE = 0,
	PENDING_STATUS_WAITING = 1,
	PENDING_STATUS_KEEPALIVE = 2,
};

enum {
	NOTIFICATION_STATUS_NONE = 0,
	NOTIFICATION_STATUS_TIMED = 1,
	NOTIFICATION_STATUS_PENDING = 2,
};

enum {
	HANDLE_EXCHANGE_EMSMDB = 2,
	HANDLE_EXCHANGE_ASYNCEMSMDB = 3,
};

struct ECDOASYNCWAITEX_IN {
	CONTEXT_HANDLE acxh;
	uint32_t flags_in;
};

struct ECDOASYNCWAITEX_OUT {
	uint32_t flags_out; ///< record context_id in the variable for asyncemsmdb_wakeup_proc
	int32_t result;
};

using EMSMDB_HANDLE	= CONTEXT_HANDLE;

namespace {

struct EMSMDB_HANDLE2 : public EMSMDB_HANDLE
{
	EMSMDB_HANDLE2() = default;
	EMSMDB_HANDLE2(const GUID& session_guid)
	{
		handle_type = HANDLE_EXCHANGE_EMSMDB;
		guid = session_guid;
	}
};

struct notification_ctx {
	uint8_t pending_status = 0, notification_status = 0;
	GUID session_guid{};
	time_point pending_time{}; ///< Since when the connection is pending
	time_point start_time{};
};

}

static constexpr size_t	AVERAGE_SESSION_PER_CONTEXT = 10,
	DISPATCH_PENDING = 2,
	FLAG_NOTIFICATION_PENDING = 1;

static BOOL emsmdb_preproc(int context_id);
static BOOL emsmdb_proc(int context_id, const void *content, uint64_t length);
static int emsmdb_retr(int context_id);
static void emsmdb_term(int context_id);
static void asyncemsmdb_wakeup_proc(int context_id, BOOL b_pending);

static int (*asyncemsmdb_interface_async_wait)(uint32_t async_id, ECDOASYNCWAITEX_IN *, ECDOASYNCWAITEX_OUT *);
static void (*asyncemsmdb_interface_register_active)(void *);
static void (*asyncemsmdb_interface_remove)(CONTEXT_HANDLE *);

static int (*emsmdb_interface_connect_ex)(uint64_t, CONTEXT_HANDLE *, const char *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint16_t, uint32_t *, uint32_t *, uint32_t *, uint16_t *, char *, char *, const uint16_t *, uint16_t *, uint16_t *, uint32_t *, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
static int (*emsmdb_interface_rpc_ext2)(CONTEXT_HANDLE *, uint32_t *flags, const uint8_t *, uint32_t, uint8_t *, uint32_t *, const uint8_t *, uint32_t, uint8_t *, uint32_t *, uint32_t *);
static int (*emsmdb_interface_disconnect)(CONTEXT_HANDLE *);
static void (*emsmdb_interface_touch_handle)(CONTEXT_HANDLE *);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Plugin structure declarations

namespace {

struct connect_request {
	char *userdn;
	uint32_t flags, cpid, lcid_string, lcid_sort, cb_auxin;
	uint8_t *auxin;
};

struct connect_response {
	uint32_t status, result, max_polls, max_retry, retry_delay;
	char dn_prefix[1024], displayname[1024];
	uint32_t cb_auxout;
	uint8_t auxout[0x1008];
};

struct execute_request {
	uint32_t flags, cb_in;
	uint8_t *in;
	uint32_t cb_out, cb_auxin;
	uint8_t *auxin;
};

struct execute_response {
	uint32_t status, result, flags, cb_out;
	uint8_t out[0x40000];
	uint32_t cb_auxout;
	uint8_t auxout[0x1008];
};

struct disconnect_request {
	uint32_t cb_auxin;
	uint8_t *auxin;
};

struct disconnect_response {
	uint32_t status, result;
};

struct notificationwait_request {
	uint32_t flags, cb_auxin;
	uint8_t *auxin;
};

struct notificationwait_response {
	uint32_t status, result;
	uint32_t flags_out;
};

struct ems_pull : public EXT_PULL {
	int g_connect_req(connect_request &);
	int g_execute_req(execute_request &);
	int g_disconnect_req(disconnect_request &);
	int g_notificationwait_req(notificationwait_request &);
};

struct ems_push : public EXT_PUSH {
	int p_connect_rsp(const connect_response &);
	int p_execute_rsp(const execute_response &);
	int p_disconnect_rsp(const disconnect_response &);
	int p_notificationwait_rsp(const notificationwait_response &);
};

/**
 * @brief	EMSMDB processing context struct
 */
struct MhEmsmdbContext : public MhContext
{
	explicit MhEmsmdbContext(int contextId) : MhContext(contextId)
	{
		ext_push.init(push_buff, arsizeof(push_buff), EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
		epush = &ext_push;
	}

	BOOL notification_response() const;
	BOOL notification_response(uint32_t, uint32_t) const;

	union {
		connect_request connect;
		disconnect_request disconnect;
		execute_request execute;
		notificationwait_request notificationwait;
	} request{};
	union {
		connect_response connect;
		disconnect_response disconnect;
		execute_response execute;
		notificationwait_response notificationwait;
	} response{};
	ems_pull ext_pull{};
	ems_push ext_push{};
};

class MhEmsmdbPlugin
{
public:
	using SessionIterator = std::unordered_map<std::string, session_data>::iterator;

	explicit MhEmsmdbPlugin(void**);
	~MhEmsmdbPlugin();
	NOMOVE(MhEmsmdbPlugin);

	BOOL process(int, const void*, uint64_t);
	int retr(int);
	void term(int);
	void async_wakeup(int, BOOL);
private:
	using ProcRes = std::optional<BOOL>;

	static void* scanWork(void*);

	SessionIterator removeSession(SessionIterator);
	SessionIterator removeSession(const char*);

	ProcRes loadCookies(MhEmsmdbContext&);
	ProcRes connect(MhEmsmdbContext&);
	ProcRes disconnect(MhEmsmdbContext&);
	ProcRes execute(MhEmsmdbContext&);
	ProcRes wait(MhEmsmdbContext&);

	gromox::atomic_bool stop = true; ///< Whether the scan thread is (to be) stopped
	pthread_t scan;

	std::unordered_set<notification_ctx *> pending;
	std::mutex listLock, hashLock;
	std::unordered_map<std::string, int> users;
	std::unordered_map<std::string, session_data> sessions;
	std::vector<notification_ctx> status;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Plugin structure definitions

/**
 * @brief	Initialize the plugin
 *
 * @param	ppdata	Plugin context data
 */
MhEmsmdbPlugin::MhEmsmdbPlugin(void** ppdata)
{
	LINK_HPM_API(ppdata)
	if (!query_service1(emsmdb_interface_connect_ex) ||
	    !query_service1(emsmdb_interface_rpc_ext2) ||
	    !query_service1(emsmdb_interface_disconnect) ||
	    !query_service1(emsmdb_interface_touch_handle) ||
	    !query_service1(asyncemsmdb_interface_async_wait) ||
	    !query_service1(asyncemsmdb_interface_register_active) ||
	    !query_service1(asyncemsmdb_interface_remove))
		throw std::runtime_error("exchange_emsmdb not loaded");
	size_t contextnum = get_context_num();
	status.resize(contextnum);
	users.reserve(AVERAGE_SESSION_PER_CONTEXT*contextnum);
	sessions.reserve(AVERAGE_SESSION_PER_CONTEXT*contextnum);
	stop = false;
	if (pthread_create(&scan, nullptr, &MhEmsmdbPlugin::scanWork, this)) {
		stop = true;
		throw std::runtime_error("failed to create scanning thread");
	}
}

/**
 * @brief	Destructor
 *
 * Stops the scan thread and block until it exited.
 */
MhEmsmdbPlugin::~MhEmsmdbPlugin()
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
 * @brief	Periodically scan for expired sessions and notifications
 */
void* MhEmsmdbPlugin::scanWork(void* ptr)
{
	MhEmsmdbPlugin& plugin = *static_cast<MhEmsmdbPlugin*>(ptr);
	while (!plugin.stop) {
		auto now = tp_now();
		std::unique_lock hl_hold(plugin.hashLock);
		for (auto entry = plugin.sessions.begin(); entry != plugin.sessions.end();) {
			if (entry->second.expire_time < now)
				entry = plugin.removeSession(entry);
			else
				++entry;
		}
		hl_hold.unlock();
		std::unique_lock ll_hold(plugin.listLock);
		for (auto ctx : plugin.pending) {
			if (now - ctx->pending_time >=
			    response_pending_period - std::chrono::seconds(3)) {
				ctx->pending_time = now;
				ctx->pending_status = PENDING_STATUS_KEEPALIVE;
				wakeup_context(int(ctx-plugin.status.data()));
			}
		}
		ll_hold.unlock();
		sleep(3);
	}
	return nullptr;
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
MhEmsmdbPlugin::SessionIterator MhEmsmdbPlugin::removeSession(SessionIterator session)
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
MhEmsmdbPlugin::SessionIterator MhEmsmdbPlugin::removeSession(const char* sessionID)
{return removeSession(sessions.find(sessionID));}

}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Plugin (de-)initialization

static std::unique_ptr<MhEmsmdbPlugin> plugin;

/**
 * @brief	(De-) Initialize plugin
 *
 * @param	reason	Either PLUGIN_INIT or PLUGIN_FREE
 * @param	ppdata	Context data for initialization
 *
 * @return	TRUE if successful, false otherwise
 */
static BOOL hpm_mh_emsmdb(int reason, void **ppdata)
{
	HPM_INTERFACE interface;

	switch (reason) {
	case PLUGIN_INIT: {
		std::unique_ptr<MhEmsmdbPlugin> created;
		try {
			created = std::make_unique<MhEmsmdbPlugin>(ppdata);
		} catch(std::bad_alloc& exc) {
			mlog(LV_ERR, "mh_emsmdb: failed to allocate plugin memory (%s)", exc.what());
		} catch(std::runtime_error& exc) {
			mlog(LV_ERR, "mh_emsmdb: failed to initialize plugin (%s)", exc.what());
		} catch(std::exception& exc) {
			mlog(LV_ERR, "mh_emsmdb: unknown error during initialization (%s)", exc.what());
		}
		if (!created)
			return false;
		interface.preproc = emsmdb_preproc;
		interface.proc = emsmdb_proc;
		interface.retr = emsmdb_retr;
		interface.send = nullptr;
		interface.receive = nullptr;
		interface.term = emsmdb_term;
		if (!register_interface(&interface))
			return false;
		asyncemsmdb_interface_register_active(reinterpret_cast<void*>(asyncemsmdb_wakeup_proc));
		plugin = std::move(created);
		return TRUE;
	}
	case PLUGIN_FREE:
		plugin.reset();
		return TRUE;
	}
	return false;
}
HPM_ENTRY(hpm_mh_emsmdb);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Response generation

static BOOL notification_response(int ID, time_point start_time, uint32_t result, uint32_t flags_out)
{
	decltype(MhEmsmdbContext::response) response;
	ems_push ext_push;
	char push_buff[32], text_buff[128], chunk_string[32];

	ext_push.init(push_buff, sizeof(push_buff), 0);
	response.notificationwait.status = 0;
	response.notificationwait.result = result;
	response.notificationwait.flags_out = flags_out;
	ext_push.p_notificationwait_rsp(response.notificationwait);

	auto current_time = tp_now();
	auto text_len = render_content(text_buff, current_time, start_time);
	auto tmp_len = sprintf(chunk_string, "%x\r\n", text_len + ext_push.m_offset);
	if (!write_response(ID, chunk_string, tmp_len) ||
	    !write_response(ID, text_buff, text_len) ||
	    !write_response(ID, ext_push.m_udata, ext_push.m_offset) ||
	    !write_response(ID, "\r\n0\r\n\r\n", 7))
		return false;
	return TRUE;
}

BOOL MhEmsmdbContext::notification_response() const
{
	char response_buff[4096];
	auto current_time = tp_now();
	size_t response_len = StringRenderer(response_buff, sizeof(response_buff))
	                      .add(commonHeader, "NotificationWait", request_id, client_info, session_string, current_time)
	                      .add("Transfer-Encoding: chunked\r\n");
	return write_response(ID, response_buff, static_cast<int>(response_len)) &&
	       write_response(ID, "c\r\nPROCESSING\r\n\r\n", 17) ? TRUE : false;
}

BOOL MhEmsmdbContext::notification_response(uint32_t result, uint32_t flags_out) const
{return ::notification_response(ID, start_time, result, flags_out);}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Emsmdb bridge

static uint32_t emsmdb_bridge_connect(const connect_request& request, connect_response& response,
                                       uint16_t& cxr, GUID& ses_guid)
{
	uint32_t timestamp;
	uint16_t best_ver[3]{}, client_ver[3]{}, server_ver[3]{};
	EMSMDB_HANDLE ses;
	uint32_t result = emsmdb_interface_connect_ex(0, &ses, request.userdn,
	                  request.flags, 0, 0, request.cpid, request.lcid_string,
	                  request.lcid_sort, 0, 0, &response.max_polls,
	                  &response.max_retry, &response.retry_delay, &cxr,
	                  response.dn_prefix, response.displayname,
	                  client_ver, server_ver, best_ver, &timestamp,
	                  request.auxin, request.cb_auxin, response.auxout,
	                  &response.cb_auxout);
	if (result != ecSuccess)
		return result;
	ses_guid = ses.guid;
	return ecSuccess;
}

static uint32_t emsmdb_bridge_execute(const GUID& session_guid, const execute_request& request, execute_response& response)
{
	uint32_t trans_time;
	EMSMDB_HANDLE ses = {HANDLE_EXCHANGE_EMSMDB, session_guid};
	return emsmdb_interface_rpc_ext2(&ses, &response.flags, request.in,
	       request.cb_in, response.out, &response.cb_out, request.auxin,
	       request.cb_auxin, response.auxout, &response.cb_auxout,
	       &trans_time);
}

static uint32_t emsmdb_bridge_disconnect(EMSMDB_HANDLE2 ses)
{return emsmdb_interface_disconnect(&ses);}

static void emsmdb_bridge_touch_handle(EMSMDB_HANDLE2 ses)
{emsmdb_interface_touch_handle(&ses);}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Request processing

static void produce_session(const char *tag, char *session)
{
	using gromox::rand;
	time_t cur_time;
	char temp_time[16], temp_name[16];

	time(&cur_time);
	snprintf(temp_time, sizeof(temp_time), "%lx", static_cast<long>(cur_time));
	if (strlen(tag) >= 16) {
		memcpy(temp_name, tag, 16);
	} else {
		memset(temp_name, '0', 16);
		memcpy(temp_name, tag, strlen(tag));
	}
	for (char *c = temp_name, *end = temp_name + 16; c < end; ++c)
		if (!HX_isalpha(*c) && !HX_isdigit(*c))
			*c = !HX_isalpha(*c) && !HX_isdigit(*c) ?
			     '0' + rand() % 10 : HX_tolower(*c);
	for (size_t i = 0; i < 32; ++i) {
		auto mod = i % 4;
		auto pos = i / 4;
		session[i] = mod == 0 || mod == 1 ? temp_name[pos*2+mod] :
		             mod == 2 ? 'a' + rand() % 26 : temp_time[pos];
	}
	session[32] = '\0';
}

/**
 * @brief	Parse request cookies
 *
 * @param	Context object to process
 *
 * @return	std::nullopt if successful, plugin return code otherwise
 */
MhEmsmdbPlugin::ProcRes MhEmsmdbPlugin::loadCookies(MhEmsmdbContext& ctx)
{
	char tmp_buff[1024];
	auto tmp_len = ctx.orig.f_cookie.read(tmp_buff, arsizeof(tmp_buff) - 1);
	if (tmp_len == MEM_END_OF_FILE) {
		if (strcasecmp(ctx.request_value, "Connect"))
			return ctx.error_responsecode(RC_MISSING_COOKIE);
		ctx.session = nullptr;
		return std::nullopt;
	}
	tmp_buff[tmp_len] = '\0';
	auto pparser = cookie_parser_init(tmp_buff);
	auto string = cookie_parser_get(pparser, "sid");
	if (string == nullptr || strlen(string) >= arsizeof(ctx.session_string))
		return ctx.error_responsecode(RC_INVALID_CONTEXT_COOKIE);
	gx_strlcpy(ctx.session_string, string, arsizeof(ctx.session_string));
	if (strcasecmp(ctx.request_value, "PING") != 0 &&
	    strcasecmp(ctx.request_value, "NotificationWait") != 0) {
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
	if (strcasecmp(ctx.session->username, ctx.auth_info.username) != 0)
		return ctx.error_responsecode(RC_NO_PRIVILEGE);
	ctx.session_guid = ctx.session->session_guid;
	if (strcasecmp(ctx.request_value, "Execute") == 0 &&
	    ctx.sequence_guid != ctx.session->sequence_guid)
		return ctx.error_responsecode(RC_INVALID_SEQUENCE);
	if (strcasecmp(ctx.request_value, "PING") != 0 &&
	    strcasecmp(ctx.request_value, "Disconnect") != 0 &&
	    strcasecmp(ctx.request_value, "NotificationWait") != 0) {
		ctx.sequence_guid = GUID::random_new();
		ctx.session->sequence_guid = ctx.sequence_guid;
	}
	ctx.session->expire_time = ctx.start_time + session_valid_interval + std::chrono::seconds(60);
	return std::nullopt;
}

MhEmsmdbPlugin::ProcRes MhEmsmdbPlugin::connect(MhEmsmdbContext &ctx)
{
	if (ctx.ext_pull.g_connect_req(ctx.request.connect) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	uint16_t cxr;
	GUID old_guid;
	ctx.response.connect.status = 0;
	ctx.response.connect.result = emsmdb_bridge_connect(ctx.request.connect, ctx.response.connect, cxr, ctx.session_guid);
	if (ctx.response.connect.result == ecSuccess) {
		if (ctx.session != nullptr) {
			std::unique_lock hl_hold(hashLock);
			auto it = sessions.find(ctx.session_string);
			if (it != sessions.end()) {
				old_guid = ctx.session->session_guid;
				ctx.session->session_guid = ctx.session_guid;
				hl_hold.unlock();
				emsmdb_bridge_disconnect(old_guid);
			}
		} else {
			produce_session(ctx.auth_info.username, ctx.session_string);
			ctx.sequence_guid = GUID::random_new();
			std::unique_lock hl_hold(hashLock);
			auto exptime = tp_now() + session_valid_interval + std::chrono::seconds(60);
			try {
				auto emplaced = sessions.try_emplace(ctx.session_string, ctx.session_guid, ctx.sequence_guid, ctx.auth_info.username, exptime);
				if (!emplaced.second) {
					hl_hold.unlock();
					emsmdb_bridge_disconnect(ctx.session_guid);
					return ctx.failure_response(ecInsufficientResrc);
				}
				auto ucount = users.emplace(emplaced.first->second.username, 0);
				++ucount.first->second;
			}  catch (std::bad_alloc&) {
				hl_hold.unlock();
				emsmdb_bridge_disconnect(ctx.session_guid);
				return ctx.failure_response(ecServerOOM);
			}
		}
	}
	if (ctx.ext_push.p_connect_rsp(ctx.response.connect) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

MhEmsmdbPlugin::ProcRes MhEmsmdbPlugin::disconnect(MhEmsmdbContext &ctx)
{
	if (ctx.ext_pull.g_disconnect_req(ctx.request.disconnect) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	ctx.response.disconnect.status = 0;
	ctx.response.disconnect.result = emsmdb_bridge_disconnect(ctx.session_guid);
	std::unique_lock hl_hold(hashLock);
	removeSession(ctx.session_string);
	hl_hold.unlock();
	if (ctx.ext_push.p_disconnect_rsp(ctx.response.disconnect) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

MhEmsmdbPlugin::ProcRes MhEmsmdbPlugin::execute(MhEmsmdbContext &ctx)
{
	if (ctx.ext_pull.g_execute_req(ctx.request.execute) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	ctx.response.execute.flags = ctx.request.execute.flags;
	ctx.response.execute.cb_out = ctx.request.execute.cb_out;
	ctx.response.execute.status = 0;
	ctx.response.execute.result = emsmdb_bridge_execute(ctx.session_guid, ctx.request.execute, ctx.response.execute);
	if (ctx.ext_push.p_execute_rsp(ctx.response.execute) != EXT_ERR_SUCCESS)
		return ctx.failure_response(RPC_X_BAD_STUB_DATA);
	return std::nullopt;
}

MhEmsmdbPlugin::ProcRes MhEmsmdbPlugin::wait(MhEmsmdbContext &ctx)
{
	ECDOASYNCWAITEX_IN wait_in;
	ECDOASYNCWAITEX_OUT wait_out;
	if (ctx.ext_pull.g_notificationwait_req(ctx.request.notificationwait) != EXT_ERR_SUCCESS)
		return ctx.error_responsecode(RC_INVALID_REQUEST_BODY);
	wait_in.acxh.handle_type = HANDLE_EXCHANGE_ASYNCEMSMDB;
	wait_in.acxh.guid = ctx.session_guid;
	wait_out.flags_out = ctx.ID;
	if (!ctx.notification_response())
		return false;
	if (asyncemsmdb_interface_async_wait(0, &wait_in, &wait_out) == DISPATCH_PENDING) {
		notification_ctx& nctx = status[ctx.ID];
		nctx.pending_status = PENDING_STATUS_WAITING;
		nctx.notification_status = NOTIFICATION_STATUS_NONE;
		nctx.session_guid = ctx.session_guid;
		nctx.start_time = ctx.start_time;
		nctx.pending_time = tp_now();
		std::unique_lock ll_hold(listLock);
		try {
			pending.emplace(&nctx);
		}  catch (std::bad_alloc&) {
			return ctx.failure_response(ecServerOOM);
		}
		ll_hold.unlock();
		return TRUE;
	}
	if (!ctx.notification_response(wait_out.result, wait_out.flags_out))
		return false;
	return TRUE;
}

BOOL MhEmsmdbPlugin::process(int context_id, const void *content, uint64_t length)
{
	ProcRes result;
	MhEmsmdbContext ctx(context_id);
	status[ctx.ID] = {};
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
	if (strcasecmp(ctx.request_value, "PING") == 0) {
		emsmdb_bridge_touch_handle(ctx.session_guid);
		return ctx.ping_response();
	}
	set_context(context_id);
	rpc_new_stack();
	auto cleanup_0 = make_scope_exit([&]() { rpc_free_stack(); });
	auto allocator = [](size_t size) {return ndr_stack_alloc(NDR_STACK_IN, size);};
	ctx.ext_pull.init(content, static_cast<uint32_t>(length), allocator, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	if (strcasecmp(ctx.request_value, "Connect") == 0)
		result = connect(ctx);
	else if (strcasecmp(ctx.request_value, "Disconnect") == 0)
		result = disconnect(ctx);
	else if (strcasecmp(ctx.request_value, "Execute") == 0)
		result = execute(ctx);
	else if (strcasecmp(ctx.request_value, "NotificationWait") == 0)
		result = wait(ctx);
	else
		return false;
	if (result)
		return result.value();
	return ctx.normal_response();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Interface functions

int MhEmsmdbPlugin::retr(int context_id)
{
	switch (status[context_id].notification_status) {
	case NOTIFICATION_STATUS_TIMED:
		notification_response(context_id,
			status[context_id].start_time,
			ecSuccess, 0);
		status[context_id].notification_status = NOTIFICATION_STATUS_NONE;
		return HPM_RETRIEVE_WRITE;
	case NOTIFICATION_STATUS_PENDING:
		notification_response(context_id,
			status[context_id].start_time,
			ecSuccess, FLAG_NOTIFICATION_PENDING);
		status[context_id].notification_status = NOTIFICATION_STATUS_NONE;
		return HPM_RETRIEVE_WRITE;
	}
	switch (status[context_id].pending_status) {
	case PENDING_STATUS_NONE:
		return HPM_RETRIEVE_DONE;
	case PENDING_STATUS_KEEPALIVE:
		write_response(context_id, "7\r\nPENDING\r\n", 12);
		status[context_id].pending_status = PENDING_STATUS_WAITING;
		return HPM_RETRIEVE_WRITE;
	case PENDING_STATUS_WAITING:
		return HPM_RETRIEVE_WAIT;
	}
	return HPM_RETRIEVE_DONE;
}

void MhEmsmdbPlugin::term(int context_id)
{
	EMSMDB_HANDLE acxh;

	if (status[context_id].pending_status == PENDING_STATUS_NONE)
		return;
	acxh.handle_type = 0;
	std::unique_lock ll_hold(listLock);
	if (status[context_id].pending_status != PENDING_STATUS_NONE) {
		acxh.handle_type = HANDLE_EXCHANGE_ASYNCEMSMDB;
		acxh.guid = status[context_id].session_guid;
		pending.erase(&status[context_id]);
		status[context_id].pending_status = PENDING_STATUS_NONE;
	}
	ll_hold.unlock();
	if (acxh.handle_type == HANDLE_EXCHANGE_ASYNCEMSMDB)
		asyncemsmdb_interface_remove(&acxh);
}

void MhEmsmdbPlugin::async_wakeup(int context_id, BOOL b_pending)
{
	std::unique_lock ll_hold(listLock);
	if (status[context_id].pending_status == PENDING_STATUS_NONE)
		return;
	status[context_id].notification_status =
		b_pending ? NOTIFICATION_STATUS_PENDING : NOTIFICATION_STATUS_TIMED;
	pending.erase(&status[context_id]);
	status[context_id].pending_status = PENDING_STATUS_NONE;
	ll_hold.unlock();
	wakeup_context(context_id);
}

static BOOL emsmdb_proc(int context_id, const void *content, uint64_t length)
{ return plugin ? plugin->process(context_id, content, length) : false; }

static int emsmdb_retr(int context_id)
{ return plugin->retr(context_id); }

static void asyncemsmdb_wakeup_proc(int context_id, BOOL b_pending)
{ return plugin->async_wakeup(context_id, b_pending); }

static void emsmdb_term(int context_id)
{ return plugin->term(context_id); }

static BOOL emsmdb_preproc(int context_id)
{
	auto prequest = get_request(context_id);
	if (strcasecmp(prequest->method, "POST") != 0)
		return false;
	char tmp_uri[1024];
	size_t tmp_len = prequest->f_request_uri.read(tmp_uri, sizeof(tmp_uri) - 1);
	if (tmp_len == MEM_END_OF_FILE)
		return false;
	tmp_uri[tmp_len] = '\0';
	if (strncasecmp(tmp_uri, "/mapi/emsmdb/?MailboxId=", 24) != 0)
		return false;
	auto pconnection = get_connection(context_id);
	set_ep_info(context_id, tmp_uri + 24, pconnection->server_port);
	return TRUE;
}

#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

int ems_pull::g_connect_req(connect_request &req)
{
	TRY(g_str(&req.userdn));
	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.cpid));
	TRY(g_uint32(&req.lcid_string));
	TRY(g_uint32(&req.lcid_sort));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int ems_pull::g_execute_req(execute_request &req)
{
	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.cb_in));
	if (req.cb_in == 0) {
		req.in = nullptr;
	} else {
		req.in = static_cast<uint8_t *>(m_alloc(req.cb_in));
		if (req.in == nullptr) {
			req.cb_in = 0;
			return EXT_ERR_ALLOC;
		}
		TRY(g_bytes(req.in, req.cb_in));
	}
	TRY(g_uint32(&req.cb_out));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int ems_pull::g_disconnect_req(disconnect_request &req)
{
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int ems_pull::g_notificationwait_req(notificationwait_request &req)
{
	TRY(g_uint32(&req.flags));
	TRY(g_uint32(&req.cb_auxin));
	if (req.cb_auxin == 0) {
		req.auxin = nullptr;
		return EXT_ERR_SUCCESS;
	}
	req.auxin = static_cast<uint8_t *>(m_alloc(req.cb_auxin));
	if (req.auxin == nullptr) {
		req.cb_auxin = 0;
		return EXT_ERR_ALLOC;
	}
	return g_bytes(req.auxin, req.cb_auxin);
}

int ems_push::p_connect_rsp(const connect_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.max_polls));
	TRY(p_uint32(rsp.max_retry));
	TRY(p_uint32(rsp.retry_delay));
	TRY(p_str(rsp.dn_prefix));
	TRY(p_wstr(rsp.displayname));
	TRY(p_uint32(rsp.cb_auxout));
	if (rsp.cb_auxout == 0)
		return EXT_ERR_SUCCESS;
	return p_bytes(rsp.auxout, rsp.cb_auxout);
}

int ems_push::p_execute_rsp(const execute_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.flags));
	TRY(p_uint32(rsp.cb_out));
	if (rsp.cb_out > 0)
		TRY(p_bytes(rsp.out, rsp.cb_out));
	TRY(p_uint32(rsp.cb_auxout));
	if (rsp.cb_auxout == 0)
		return EXT_ERR_SUCCESS;
	return p_bytes(rsp.auxout, rsp.cb_auxout);
}

int ems_push::p_disconnect_rsp(const disconnect_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	return p_uint32(0);
}

int ems_push::p_notificationwait_rsp(const notificationwait_response &rsp)
{
	TRY(p_uint32(rsp.status));
	TRY(p_uint32(rsp.result));
	TRY(p_uint32(rsp.flags_out));
	return p_uint32(0);
}
