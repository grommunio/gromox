// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <condition_variable>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <span>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/hook_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/plugin.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "delivery.hpp"
#define FILENUM_PER_CONTROL		32
#define MAX_THROWING_NUM		16
#define SCAN_INTERVAL			1
#define MAX_TIMES_NOT_SERVED	5

using namespace gromox;

namespace {

struct hook_service_node {
	void *service_addr = nullptr;
	std::string service_name;
};

struct hook_plug_entity;
struct hook_entry {
	HOOK_FUNCTION hook_addr = nullptr;
	hook_plug_entity *plib = nullptr;
};

struct hook_plug_entity {
	hook_plug_entity() = default;
	hook_plug_entity(hook_plug_entity &&) noexcept;
	~hook_plug_entity();
	void operator=(hook_plug_entity &&) noexcept = delete;

	std::vector<hook_service_node> list_reference;
	std::vector<hook_entry> list_hook;
	PLUGIN_MAIN lib_main = nullptr;
	const char *file_name = nullptr;
	bool completed_init = false;
};
using HOOK_PLUG_ENTITY = hook_plug_entity;

/**
 * @mctx:	message context (main iteration; never used for bounces)
 */
struct THREAD_DATA {
	DOUBLE_LIST_NODE node{};
	pthread_t id{};
	bool wait_on_event = false;
	MESSAGE_CONTEXT mctx;
	std::vector<HOOK_FUNCTION> anti_loop;
	HOOK_FUNCTION last_hook = nullptr, last_thrower = nullptr;
};

}

static void *transporter_queryservice(const char *service, const char *rq, const std::type_info &);

static char				g_path[256];
static std::span<const static_module> g_plugin_names;
static std::string g_local_path;
static HOOK_FUNCTION g_local_hook;
static unsigned int g_threads_max, g_threads_min, g_free_num;
static gromox::atomic_bool g_notify_stop;
static DOUBLE_LIST		g_threads_list;
static DOUBLE_LIST		g_free_threads;
static std::vector<MESSAGE_CONTEXT *> g_free_list, g_queue_list; /* ctx for generating new messages */
static std::list<hook_plug_entity> g_lib_list;
static std::vector<const hook_entry *> g_hook_list;
static std::mutex g_free_threads_mutex, g_threads_list_mutex, g_context_lock;
static std::mutex g_queue_lock, g_cond_mutex;
static std::condition_variable g_waken_cond;
static thread_local THREAD_DATA *g_tls_key;
static pthread_t		 g_scan_id;
static std::unique_ptr<THREAD_DATA[]> g_data_ptr;
static std::unique_ptr<MESSAGE_CONTEXT[]> g_free_ptr;
static HOOK_PLUG_ENTITY *g_cur_lib;

static void *dxp_thrwork(void *);
static void *dxp_scanwork(void *);
static BOOL transporter_register_hook(HOOK_FUNCTION func);
static BOOL transporter_register_local(HOOK_FUNCTION func);
static hook_result transporter_pass_mpc_hooks(MESSAGE_CONTEXT *, THREAD_DATA *);
static MESSAGE_CONTEXT *transporter_get_context();
static void transporter_insert_ctx(MESSAGE_CONTEXT *);
static BOOL transporter_throw_context(MESSAGE_CONTEXT *pcontext); 

static void transporter_enqueue_context(MESSAGE_CONTEXT *pcontext);
static MESSAGE_CONTEXT *transporter_dequeue_context();
static void transporter_log_info(const CONTROL_INFO &, int level, const char *format, ...);

hook_plug_entity::hook_plug_entity(hook_plug_entity &&o) noexcept :
	list_reference(std::move(o.list_reference)),
	lib_main(std::move(o.lib_main)), file_name(std::move(o.file_name)),
	completed_init(std::move(o.completed_init))
{
	o.completed_init = false;
}

static constexpr struct dlfuncs server_funcs = {
	/* .symget = */ transporter_queryservice,
	/* .symreg = */ nullptr,
	/* .get_config_path = */ []() {
		auto r = g_config_file->get_value("config_file_path");
		return r != nullptr ? r : PKGSYSCONFDIR "/delivery:" PKGSYSCONFDIR;
	},
	/* .get_data_path = */ []() {
		auto r = g_config_file->get_value("data_file_path");
		return r != nullptr ? r : PKGDATADIR "/delivery:" PKGDATADIR;
	},
	/* .get_context_num = */ []() { return g_threads_max + g_free_num; },
	/* .get_host_ID = */ []() { return g_config_file->get_value("host_id"); },
	/* .get_prog_id = */ nullptr,
	/* .ndr_stack_alloc = */ nullptr,
	/* .rpc_new_stack = */ nullptr,
	/* .rpc_free_stack = */ nullptr,
	/* PROC_ */ {},
	/* HPM_ */ {},
	/* HOOK_ */
	{
		/* .register_hook = */ transporter_register_hook,
		/* .register_local = */ transporter_register_local,
		/* .get_admin_mailbox = */ []() { return g_config_file->get_value("admin_mailbox"); },
		/* .get_queue_path = */ []() { return g_config_file->get_value("dequeue_path"); },
		/* .get_threads_num = */ []() { return g_threads_max; },
		/* .get_ctx = */ transporter_get_context,
		/* .put_ctx = */ transporter_insert_ctx,
		/* .enqueue_ctx = */ transporter_enqueue_context,
		/* .throw_ctx = */ transporter_throw_context,
	},
};


hook_plug_entity::~hook_plug_entity()
{
	mlog(LV_INFO, "transporter: unloading %s", file_name);
	if (lib_main != nullptr && completed_init)
		lib_main(PLUGIN_FREE, server_funcs);
	g_hook_list.erase(std::remove_if(g_hook_list.begin(), g_hook_list.end(),
		[this](const hook_entry *e) { return e->plib == this; }), g_hook_list.end());
	for (const auto &nd : list_reference)
		service_release(nd.service_name.c_str(), file_name);
}

/*
 *	transporter's initial function
 *	@param
 *		path [in]				plug-ins path
 *		threads_num				threads number to be created
 *		free_num				free contexts number for hooks to throw out
 */
void transporter_init(const char *path, const std::span<const static_module> &names,
    unsigned int threads_min, unsigned int threads_max, unsigned int free_num,
    bool ignerr)
{
	gx_strlcpy(g_path, path, std::size(g_path));
	g_plugin_names = names;
	g_local_path.clear();
	g_notify_stop = false;
	g_threads_min = threads_min;
	g_threads_max = threads_max;
	g_free_num = free_num;
	/* Preallocate so this won't throw down the road */
	g_free_list.reserve(free_num);
	g_queue_list.reserve(free_num);
	double_list_init(&g_threads_list);
	double_list_init(&g_free_threads);
}

/*
 *	@return
 *		0			OK
 *		<>0			fail
 */
int transporter_run()
{
	try {
		g_data_ptr = std::make_unique<THREAD_DATA[]>(g_threads_max);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "transporter: failed to allocate memory for threads data");
		return -2;
	}
	for (size_t i = 0; i < g_threads_max; ++i)
		g_data_ptr[i].node.pdata = &g_data_ptr[i];
	try {
		g_free_ptr = std::make_unique<MESSAGE_CONTEXT[]>(g_free_num);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "transporter: failed to allocate memory for free list");
        return -3;
	}
	for (size_t i = 0; i < g_free_num; ++i) {
		g_free_list.push_back(&g_free_ptr[i]);
	}

	for (const auto &i : g_plugin_names) {
		int ret = transporter_load_library(i);
		if (ret != PLUGIN_LOAD_OK)
			return -7;
	}

	if (g_local_path.empty()) {
		mlog(LV_ERR, "transporter: no local delivery hook registered");
		return -8;
	}

	for (unsigned int i = g_threads_min; i < g_threads_max; ++i)
		double_list_append_as_tail(&g_free_threads, &g_data_ptr[i].node);

	for (size_t i = 0; i < g_threads_min; ++i) {
		g_data_ptr[i].wait_on_event = TRUE;
		auto ret = pthread_create4(&g_data_ptr[i].id, nullptr,
		           dxp_thrwork, &g_data_ptr[i]);
		if (ret != 0) {
			mlog(LV_ERR, "transporter: failed to create transport thread %zu: %s",
			       i, strerror(ret));
			return -10;
        }
		char buf[32];
		snprintf(buf, sizeof(buf), "xprt/%zu", i);
		pthread_setname_np(g_data_ptr[i].id, buf);
		double_list_append_as_tail(&g_threads_list, &g_data_ptr[i].node);
    }
	/* create the scanning thread */
	auto ret = pthread_create4(&g_scan_id, nullptr, dxp_scanwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		mlog(LV_ERR, "transporter: failed to create scanner thread: %s", strerror(ret));
		return -11;
	}
	pthread_setname_np(g_scan_id, "xprt/scan");
	/* make all thread wake up */
	g_waken_cond.notify_all();
	return 0;
}

void transporter_stop()
{
	DOUBLE_LIST_NODE *pnode;

	g_notify_stop = true;
	std::unique_lock tl_hold(g_threads_list_mutex);
	g_waken_cond.notify_all();
	while ((pnode = double_list_pop_front(&g_threads_list)) != nullptr) {
		auto pthr = static_cast<THREAD_DATA *>(pnode->pdata);
		auto id = pthr->id;
		pthread_kill(id, SIGALRM);
		pthread_join(id, nullptr);
	}
	tl_hold.unlock();
	if (!pthread_equal(g_scan_id, {})) {
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, nullptr);
	}
	g_lib_list.clear();
	g_data_ptr.reset();
	g_free_ptr.reset();
	g_path[0] = '\0';
	g_threads_min = 0;
	g_threads_max = 0;
	double_list_free(&g_threads_list);
	double_list_free(&g_free_threads);
}

void transporter_wakeup_one_thread()
{
	g_waken_cond.notify_one();
}

static gromox::hook_result remote_delivery_hook(MESSAGE_CONTEXT *ctx)
{
	auto err = cu_send_mail(ctx->mail, g_outgoing_smtp_url.c_str(),
	           ctx->ctrl.from, ctx->ctrl.rcpt);
	if (err != ecSuccess)
		mlog(LV_ERR, "E-2134: cu_send_mail: %s", mapi_strerror(err));
	return hook_result::stop;
}

/*
 *	make the hooks in mpc process the message context
 *	@param
 *		pcontext [in]			message context pointer
 *		pthr_data [in]			TLS data pointer
 */
static gromox::hook_result transporter_pass_mpc_hooks(MESSAGE_CONTEXT *pcontext,
	THREAD_DATA *pthr_data)
{
	hook_result hook_result = hook_result::xcontinue;
	for (auto phook : g_hook_list) {
			if (pthr_data->last_thrower == phook->hook_addr)
				continue;
			pthr_data->last_hook = phook->hook_addr;
			hook_result = phook->hook_addr(pcontext);
			if (hook_result != hook_result::xcontinue)
				return hook_result;
	}
	if (pthr_data->last_thrower != g_local_hook) {
		pthr_data->last_hook = g_local_hook;
		hook_result = g_local_hook(pcontext);
		if (hook_result != hook_result::xcontinue)
			return hook_result;
	}
	if (pthr_data->last_thrower != remote_delivery_hook) {
		pthr_data->last_hook = remote_delivery_hook;
		hook_result = remote_delivery_hook(pcontext);
		if (hook_result != hook_result::xcontinue)
			return hook_result;
	}
	return hook_result;
}

static void *dxp_thrwork(void *arg)
{
	char *ptr;
	int len, cannot_served_times;
	MESSAGE *pmessage;
	MESSAGE_CONTEXT *pcontext;
	
	auto pthr_data = static_cast<THREAD_DATA *>(arg);
	g_tls_key = pthr_data;
	for (const auto &plug : g_lib_list)
		plug.lib_main(PLUGIN_THREAD_CREATE, server_funcs);
	cannot_served_times = 0;
	if (pthr_data->wait_on_event) {
		std::unique_lock cm_hold(g_cond_mutex);
		g_waken_cond.wait(cm_hold);
	}
	
	while (!g_notify_stop) {
		pmessage = message_dequeue_get();
		if (NULL == pmessage) {
			pcontext = transporter_dequeue_context();	
			if (NULL == pcontext) {
				cannot_served_times ++;
				if (cannot_served_times < MAX_TIMES_NOT_SERVED) {
					sleep(1);
				/* decrease threads pool */
				} else {
					std::unique_lock tl_hold(g_threads_list_mutex);
					if (double_list_get_nodes_num(&g_threads_list) >
						g_threads_min) {
						double_list_remove(&g_threads_list, &pthr_data->node);
						tl_hold.unlock();
						for (auto &plug : g_lib_list)
							plug.lib_main(PLUGIN_THREAD_DESTROY, server_funcs);
						std::unique_lock ft_hold(g_free_threads_mutex);
						double_list_append_as_tail(&g_free_threads,
							&pthr_data->node);
						ft_hold.unlock();
						pthread_detach(pthread_self());
						return nullptr;
					}
					tl_hold.unlock();
					std::unique_lock cm_hold(g_cond_mutex);
					g_waken_cond.wait(cm_hold);
				}
				continue;
			}
			cannot_served_times = 0;
		} else {
			cannot_served_times = 0;
			pcontext = &pthr_data->mctx;
			if (!pcontext->mail.load_from_str(static_cast<char *>(pmessage->mail_begin),
			    pmessage->mail_length)) {
				mlog(LV_ERR, "QID %d: Failed to "
					"load into mail object", pmessage->flush_ID);
				auto ret = message_dequeue_save(pmessage);
				if (ret != 0)
					mlog(LV_ERR, "E-1226: QID %d: Failed to convert from /mes to /save: %s",
						pmessage->flush_ID, strerror(ret));
				else
					message_dequeue_put(pmessage);
				continue;
			}	
			pcontext->ctrl.queue_ID = pmessage->flush_ID;
			pcontext->ctrl.bound_type = pmessage->bound_type;
			pcontext->ctrl.need_bounce = TRUE;
			gx_strlcpy(pcontext->ctrl.from, pmessage->envelope_from, std::size(pcontext->ctrl.from));
			ptr = pmessage->envelope_rcpt;
			while ((len = strlen(ptr)) != 0) {
				len ++;
				pcontext->ctrl.rcpt.emplace_back(ptr);
				ptr += len;
			}
		}
		pthr_data->last_hook = NULL;
		pthr_data->last_thrower = NULL;
		auto pass_result = transporter_pass_mpc_hooks(pcontext, pthr_data);
		if (pass_result == hook_result::xcontinue) {
			transporter_log_info(pcontext->ctrl, LV_DEBUG, "Message cannot be processed by "
				"any hook registered in MPC");
			if (pmessage != nullptr) {
				auto ret = message_dequeue_save(pmessage);
				if (ret != 0) {
					mlog(LV_ERR, "E-1227: QID %d: Failed to convert from /mes to /save: %s",
						pmessage->flush_ID, strerror(ret));
					continue;
				}
			}
		}
		if (pmessage != nullptr) {
			pcontext->ctrl.rcpt.clear();
			pcontext->mail.clear();
			if (pass_result == hook_result::proc_error)
				message_dequeue_save(pmessage);
			message_dequeue_put(pmessage);
		} else {
			transporter_insert_ctx(pcontext);
		}
	}
	for (auto &plug : g_lib_list)
		plug.lib_main(PLUGIN_THREAD_DESTROY, server_funcs);
	return NULL;
}

static void *dxp_scanwork(void *arg)
{
	DOUBLE_LIST_NODE *pnode;

	while (!g_notify_stop) {
		sleep(SCAN_INTERVAL);
		if (message_dequeue_get_param(MESSAGE_DEQUEUE_HOLDING) == 0)
			continue;
		std::unique_lock tl_hold(g_threads_list_mutex);
		if (g_threads_max == double_list_get_nodes_num(&g_threads_list)) {
			continue;
		}
		tl_hold.unlock();
		/* get a thread data node from free list */
		std::unique_lock ft_hold(g_free_threads_mutex);
		pnode = double_list_pop_front(&g_free_threads);
		ft_hold.unlock();
		if (NULL == pnode) {
			continue;
		}
		auto pthr_data = static_cast<THREAD_DATA *>(pnode->pdata);
		auto ret = pthread_create4(&pthr_data->id, nullptr, dxp_thrwork, pthr_data);
		if (ret == 0) {
			pthread_setname_np(pthr_data->id, "xprt/+");
			tl_hold.lock();
			double_list_append_as_tail(&g_threads_list, &pthr_data->node);
			tl_hold.unlock();
		} else {
			mlog(LV_WARN, "W-1446: pthread_create: %s", strerror(ret));
			tl_hold.lock();
			double_list_append_as_tail(&g_free_threads, &pthr_data->node);
			tl_hold.unlock();
		}
	}
	return NULL;
}

/*
 *	load the hook plugin
 *	@param
 *		path [in]					plugin name
 *	@return
 *		PLUGIN_LOAD_OK				OK
 *		PLUGIN_ALREADY_LOADED		plugin is already loaded
 *		PLUGIN_FAIL_OPEN			fail to open share library
 *		PLUGIN_NO_MAIN				cannot find main entry
 *		PLUGIN_FAIL_ALLOCNODE		fail to allocate node for plugin
 *		PLUGIN_FAIL_EXECUTEMAIN		main entry in plugin returns FALSE
 */
int transporter_load_library(const static_module &mod) try
{
	/* check whether the plugin is same as local or remote plugin */
	if (g_local_path == mod.path) {
		mlog(LV_ERR, "transporter: %s is already loaded", mod.path);
		return PLUGIN_ALREADY_LOADED;
	}
	
    /* check whether the library is already loaded */
	if (std::any_of(g_lib_list.cbegin(), g_lib_list.cend(),
	    [&](const hook_plug_entity &p) { return p.file_name == mod.path; })) {
		mlog(LV_ERR, "transporter: %s is already loaded", mod.path);
		return PLUGIN_ALREADY_LOADED;
	}

	hook_plug_entity plug;
	plug.lib_main = mod.efunc;
	plug.file_name = mod.path;
	g_lib_list.push_back(std::move(plug));
	g_cur_lib = &g_lib_list.back();
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!g_cur_lib->lib_main(PLUGIN_INIT, server_funcs)) {
		mlog(LV_ERR, "transporter: error executing the plugin's init function "
			"in %s", g_cur_lib->file_name);
		g_cur_lib = NULL;
		g_lib_list.pop_back();
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	g_cur_lib->completed_init = true;
	g_cur_lib = NULL;
	return PLUGIN_LOAD_OK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1473: ENOMEM");
	return PLUGIN_FAIL_OPEN;
}

static void *transporter_queryservice(const char *service,
    const char *requestor, const std::type_info &ti)
{
    if (NULL == g_cur_lib) {
        return NULL;
    }
	/* check if already exists in the reference list */
	for (auto &nd : g_cur_lib->list_reference)
		if (nd.service_name == service)
			return nd.service_addr;
	auto fn = g_cur_lib->file_name;
	auto ret_addr = service_query(service, fn, ti);
    if (NULL == ret_addr) {
        return NULL;
    }
	try {
		g_cur_lib->list_reference.emplace_back(hook_service_node{deconst(ret_addr), service});
	} catch (const std::bad_alloc &) {
		service_release(service, fn);
		return nullptr;
	}
    return ret_addr;
}

/*
 *	get a free context for throwing
 *	@return
 *		NULL			fail
 *		pointer to context
 */
static MESSAGE_CONTEXT* transporter_get_context()
{
	std::unique_lock ctx_hold(g_context_lock);
	if (g_free_list.size() == 0)
		return NULL;
	auto free_ctx = g_free_list.front();
	g_free_list.erase(g_free_list.begin());
	ctx_hold.unlock();
	auto pcontext = free_ctx;
	pcontext->ctrl.bound_type = BOUND_SELF;
	return pcontext;
}

/*
 *	put the context back into free list
 *	@param
 *		pcontext [in]		context pointer
 */
static void transporter_insert_ctx(MESSAGE_CONTEXT *pcontext)
{
	/* reset the context object */
	pcontext->ctrl.rcpt.clear();
	pcontext->ctrl.queue_ID = 0;
	pcontext->ctrl.bound_type = BOUND_UNKNOWN;
	pcontext->ctrl.need_bounce = FALSE;
	pcontext->ctrl.from[0] = '\0';
	pcontext->mail.clear();
	std::lock_guard ctx_hold(g_context_lock);
	g_free_list.push_back(pcontext);
}

/*
 *	put the context into context queue
 *	@param
 *		pcontext [in]		context pointer
 */
static void transporter_enqueue_context(MESSAGE_CONTEXT *pcontext)
{
	if (reinterpret_cast<uintptr_t>(pcontext) < reinterpret_cast<uintptr_t>(g_free_ptr.get()) ||
	    reinterpret_cast<uintptr_t>(pcontext) > reinterpret_cast<uintptr_t>(g_free_ptr.get() + g_free_num)) {
		mlog(LV_ERR, "transporter: invalid context pointer is detected when some "
				"plugin try to enqueue message context");
		return;
	}
	std::unique_lock q_hold(g_queue_lock);
	g_queue_list.push_back(pcontext); /* reserved, so should not throw */
	q_hold.unlock();
	/* wake up one thread */
	g_waken_cond.notify_one();
}

/*
 *  get a context from context queue
 *  @return
 *		pointer to context, NULL means none
 */
static MESSAGE_CONTEXT* transporter_dequeue_context()
{
	std::unique_lock q_hold(g_queue_lock);
	if (g_queue_list.empty())
		return NULL;
	auto free_ctx = g_queue_list.front();
	g_queue_list.erase(g_queue_list.begin());
	q_hold.unlock();
	return free_ctx;
}

/*
 *	throw a message and this message will be processed by message process chain
 *	@param
 *		pcontext [in]			context pointer
 *	@return
 *		TRUE					OK
 *		FALSE					fail
 */
static BOOL transporter_throw_context(MESSAGE_CONTEXT *pcontext)
{
	BOOL ret_val;

	if (reinterpret_cast<uintptr_t>(pcontext) < reinterpret_cast<uintptr_t>(g_free_ptr.get()) ||
	    reinterpret_cast<uintptr_t>(pcontext) > reinterpret_cast<uintptr_t>(g_free_ptr.get() + g_free_num)) {
		mlog(LV_ERR, "transporter: invalid context pointer is detected when some "
				"plugin try to throw message context");
		return FALSE;
	}
	auto pthr_data = g_tls_key;
	if (NULL == pthr_data) {
		transporter_insert_ctx(pcontext);
		return FALSE;
	}	
	/* check if this hook is throwing the second message */
	if (std::find(pthr_data->anti_loop.cbegin(),
	    pthr_data->anti_loop.cend(), pthr_data->last_hook) !=
	    pthr_data->anti_loop.cend()) {
		mlog(LV_ERR, "transporter: message infinite loop is detected");
		transporter_insert_ctx(pcontext);
		return FALSE;
	}
	if (pthr_data->anti_loop.size() >= MAX_THROWING_NUM) {
		mlog(LV_ERR, "transporter: exceed the maximum depth that one thread "
			"can throw");
		transporter_insert_ctx(pcontext);
        return FALSE;
	}
	try {
		pthr_data->anti_loop.push_back(pthr_data->last_hook);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "transporter: exceed the maximum depth that one thread "
			"can throw");
		transporter_insert_ctx(pcontext);
		return false;
	}
	/* save the last hook and last thrower, like function's call operation */
	auto last_hook = pthr_data->last_hook;
	auto last_thrower = pthr_data->last_thrower;
	pthr_data->last_thrower = pthr_data->last_hook;
	auto pass_result = transporter_pass_mpc_hooks(pcontext, pthr_data);
	if (pass_result == hook_result::xcontinue) {
		ret_val = FALSE;
		transporter_log_info(pcontext->ctrl, LV_DEBUG, "Message cannot be processed by any "
			"hook registered in MPC");
	} else {
		ret_val = TRUE;
	}
	pthr_data->anti_loop.pop_back();
	transporter_insert_ctx(pcontext);
	/* recover last thrower and last hook, like function's return operation */
	pthr_data->last_hook = last_hook;
	pthr_data->last_thrower = last_thrower;
    return ret_val;
}

static BOOL transporter_register_hook(HOOK_FUNCTION func)
{
    if (NULL == func) {
        return FALSE;
    }
    /*check if register hook is invoked only in HOOK_LibMain(PLUGIN_INIT,..)*/
    if (NULL == g_cur_lib) {
        return FALSE;
    }

    /* check if the hook is already registered in hook list */
	if (std::any_of(g_hook_list.cbegin(), g_hook_list.cend(),
	    [&](const hook_entry *e) { return e->hook_addr == func; }))
		return false;
    /* check if there's empty hook in the list */
	g_cur_lib->list_hook.emplace_back(hook_entry{func, g_cur_lib});
	g_hook_list.push_back(&g_cur_lib->list_hook.back());
    return TRUE;
}

static BOOL transporter_register_local(HOOK_FUNCTION func)
{
	if (!g_local_path.empty()) {
		mlog(LV_ERR, "A local hook is already registered (%s), cannot load another",
			g_local_path.c_str());
		return FALSE;
	}
	/* do not need read acquire write lock */
	g_local_hook = func;
	g_local_path = g_cur_lib->file_name;
	return TRUE;
}

static void transporter_log_info(const CONTROL_INFO &ctrl, int level,
    const char *format, ...) try
{
	char log_buf[2048];
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	std::string rcpt_buff;
	static constexpr unsigned int limit = 3;
	unsigned int counter = limit;
	auto nrcpt = ctrl.rcpt.size();
	for (const auto &rcpt : ctrl.rcpt) {
		if (counter == 0)
			break;
		--counter;
		if (rcpt_buff.size() > 0)
			rcpt_buff += ' ';
		rcpt_buff += rcpt;
	}
	if (nrcpt > limit)
		rcpt_buff += " + " + std::to_string(nrcpt - limit) + " others";

	switch (ctrl.bound_type) {
	case BOUND_UNKNOWN:
		mlog(level, "UNKNOWN message FROM: %s, "
			"TO: %s %s", ctrl.from, rcpt_buff.c_str(), log_buf);
		break;
	case BOUND_IN:
		mlog(level, "SMTP message queue-ID: %d, FROM: %s, "
			"TO: %s %s", ctrl.queue_ID, ctrl.from,
			rcpt_buff.c_str(), log_buf);
		break;
	default:
		mlog(level, "APP created message FROM: %s, "
			"TO: %s %s", ctrl.from, rcpt_buff.c_str(), log_buf);
		break;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1080: ENOMEM");
}

void transporter_trigger_all(enum plugin_op ev)
{
	for (auto &plug : g_lib_list) {
		g_cur_lib = &plug;
		plug.lib_main(ev, server_funcs);
	}
	g_cur_lib = nullptr;
}
