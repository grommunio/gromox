// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/flusher_common.h>
#include <gromox/paths.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include <libHX/string.h>
#include <sys/types.h>
#include <utility>
#include "smtp_aux.hpp"
#include "smtp_parser.h"
#define FLUSHER_VERSION     0x00000001
#define MAX_CIRCLE_NUMBER   0x7FFFFFFF

using namespace gromox;

namespace {

struct SERVICE_NODE {
	void			*service_addr;
	std::string service_name;
};

struct FLH_PLUG_ENTITY {
	~FLH_PLUG_ENTITY();
	CANCEL_FUNCTION flush_cancel = nullptr;
	std::vector<SERVICE_NODE> list_ref;
	char file_name[256]{}, path[256]{};
	bool completed_init = false;
};

}

static BOOL flusher_load_plugin();
static void *flusher_queryservice(const char *service, const std::type_info &);
static BOOL flusher_register_cancel(CANCEL_FUNCTION cancel_func);
static int flusher_increase_max_ID();
static void flusher_set_flush_ID(int);
	
static std::unique_ptr<FLH_PLUG_ENTITY> g_flusher_plug;
static bool g_can_register;
static size_t g_max_queue_len;
static std::atomic<int> g_current_ID;

void flusher_init(size_t queue_len) try
{
	static constexpr char path[] = "libgxf_message_enqueue.so";
	g_flusher_plug = std::make_unique<FLH_PLUG_ENTITY>();
	g_flusher_plug->flush_cancel = NULL;
	gx_strlcpy(g_flusher_plug->path, path, GX_ARRAY_SIZE(g_flusher_plug->path));
	auto pname = strrchr(path, '/');
	gx_strlcpy(g_flusher_plug->file_name, pname != nullptr ? pname + 1 : path,
		GX_ARRAY_SIZE(g_flusher_plug->file_name));
	g_max_queue_len = queue_len;
} catch (const std::bad_alloc &) {
}

int flusher_run()
{
	if (NULL == g_flusher_plug) {
		mlog(LV_ERR, "flusher: failed to allocate memory for FLUSHER");
		return -3;
	}
	if (!flusher_load_plugin())
		return -2;
	if (g_current_ID < 0) {
		mlog(LV_ERR, "flusher: flush ID error, should be larger than 0");
		return -4;
	}
	return 0;
}

/*
 *  put the context into the flusher's queue
 *  @param
 *      pcontext    indicate the context object
 *  @return
 *      TRUE    OK to put
 *      FALSE   fail to put
 */
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext) try
{
	FLUSH_ENTITY e, *pentity = &e;
	if (0 == pcontext->flusher.flush_ID) {
		pcontext->flusher.flush_ID = flusher_increase_max_ID();
	}
	
	pentity->is_spam        = pcontext->is_spam;
	pentity->pconnection    = &pcontext->connection;
	pentity->penvelope      = &pcontext->menv;
	pentity->pflusher       = &pcontext->flusher;
	pentity->pstream        = &pcontext->stream;
	pentity->context_ID     = pcontext->context_id;
	pentity->pcontext       = pcontext;
	pentity->command_protocol = pcontext->command_protocol;
	message_enqueue_handle_workitem(e);
	return true;
} catch (const std::bad_alloc &) {
	return false;
}

/*
 *  cancel a flushed mail parts
 *  @param
 *      pcontext [in]   indicate the context object
 */
void flusher_cancel(SMTP_CONTEXT *pcontext)
{
	if (NULL == g_flusher_plug->flush_cancel) {
		return;
	}   
	FLUSH_ENTITY entity;
	entity.is_spam      = pcontext->is_spam;
	entity.pconnection  = &pcontext->connection;
	entity.penvelope    = &pcontext->menv;
	entity.pflusher     = &pcontext->flusher;
	entity.pstream      = &pcontext->stream;

	g_flusher_plug->flush_cancel(&entity);
}

static BOOL flusher_load_plugin()
{
	static void *const server_funcs[] = {reinterpret_cast<void *>(flusher_queryservice)};
	BOOL    main_result;
	
	g_can_register = true; /* so message_enqueue can set g_current_ID at start */
	main_result = FLH_LibMain(PLUGIN_INIT, const_cast<void **>(server_funcs));
	g_can_register = false;
	if (!main_result) {
		mlog(LV_ERR, "flusher: failed to execute init in flusher plugin");
		return FALSE;
	}
	g_flusher_plug->completed_init = true;
	return TRUE;
}

void flusher_stop()
{
	g_flusher_plug.reset();
}

FLH_PLUG_ENTITY::~FLH_PLUG_ENTITY()
{
	if (completed_init && !FLH_LibMain(PLUGIN_FREE, nullptr)) {
		mlog(LV_ERR, "flusher: error executing Flusher_LibMain with "
			   "FLUSHER_LIB_FREE in plugin %s", path);
		return;
	}
	mlog(LV_INFO, "flusher: unloading %s", path);
	/* free the service reference of the plugin */
	if (list_ref.size() > 0)
		for (auto &svc : list_ref)
			service_release(svc.service_name.c_str(), file_name);
}

static int flusher_increase_max_ID()
{
	int current, next;
	do {
		current = g_current_ID.load();
		next = current >= INT32_MAX ? 1 : current + 1;
	} while (!g_current_ID.compare_exchange_strong(current, next));
	return next;
}

static void flusher_set_flush_ID(int ID)
{
	/*
	 * FLH can dictate the starting value at PLUGIN_INIT;
	 * at other times, flusher.cpp is the one telling FLH what IDs to use
	 * (via flusher.cpp setting pcontext->flusher.flush_ID).
	 */
	if (g_can_register)
		g_current_ID = ID;
}

static void *flusher_queryservice(const char *service, const std::type_info &ti)
{
	void *ret_addr;
	
#define E(s, f) \
	do { \
		if (strcmp(service, (s)) == 0) \
			return reinterpret_cast<void *>(f); \
	} while (false)
	E("get_queue_length", +[]() { return g_max_queue_len; });
	E("register_cancel", flusher_register_cancel);
	E("get_host_ID", +[]() { return g_config_file->get_value("host_id"); });
	E("get_extra_num", +[](unsigned int id) {
		auto c = static_cast<smtp_context *>(smtp_parser_get_contexts_list()[id]);
		return smtp_parser_get_extra_num(c);
	});
	E("get_extra_tag", +[](unsigned int id, int pos) {
		auto c = static_cast<smtp_context *>(smtp_parser_get_contexts_list()[id]);
		return smtp_parser_get_extra_tag(c, pos);
	});
	E("get_extra_value", +[](unsigned int id, int pos) {
		auto c = static_cast<smtp_context *>(smtp_parser_get_contexts_list()[id]);
		return smtp_parser_get_extra_value(c, pos);
	});
	E("set_flush_ID", flusher_set_flush_ID);
	E("get_config_path", +[]() {
		auto r = g_config_file->get_value("config_file_path");
		return r != nullptr ? r : PKGSYSCONFDIR;
	});
	E("get_data_path", +[]() {
		auto r = g_config_file->get_value("data_file_path");
		return r != nullptr ? r : PKGDATADIR "/smtp:" PKGDATADIR;
	});
	E("get_state_path", +[]() {
		auto r = g_config_file->get_value("state_file_path");
		return r != nullptr ? r : PKGSTATEDIR;
	});
#undef E
	/* check if already exists in the reference list */
	for (const auto &svc : g_flusher_plug->list_ref)
		if (svc.service_name == service)
			return svc.service_addr;
	ret_addr = service_query(service, g_flusher_plug->file_name, ti);
	if (NULL == ret_addr) {
		return NULL;
	}
	try {
		g_flusher_plug->list_ref.push_back(SERVICE_NODE{ret_addr, service});
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1241: failed to allocate memory for service name");
		service_release(service, g_flusher_plug->file_name);
		return NULL;
	}
	return ret_addr;
}

static BOOL flusher_register_cancel(CANCEL_FUNCTION cancel_func)
{
	if (!g_can_register || g_flusher_plug->flush_cancel != nullptr)
		return FALSE;
	g_flusher_plug->flush_cancel = cancel_func;
	return TRUE;
}
