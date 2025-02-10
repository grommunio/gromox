// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/paths.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

namespace {

struct reference_node {
	std::string module_name;
	int ref_count;
};

struct SVC_PLUG_ENTITY;
struct service_entry {
	std::string service_name;
	void *service_addr;
	SVC_PLUG_ENTITY *plib;
	const std::type_info *type_info;
	std::vector<reference_node> list_reference;
};

struct SVC_PLUG_ENTITY : public gromox::generic_module {
	SVC_PLUG_ENTITY() = default;
	SVC_PLUG_ENTITY(SVC_PLUG_ENTITY &&) noexcept;
	~SVC_PLUG_ENTITY();
	void operator=(SVC_PLUG_ENTITY &&) noexcept = delete;

	std::vector<std::shared_ptr<service_entry>> list_service;
	std::atomic<int> ref_count = 0;
	std::vector<std::string> ref_holders;
};

struct svc_mgr final {
	public:
	svc_mgr(service_init_param &&);
	~svc_mgr();
	int run_early();
	int run();
	BOOL symreg(const char *, void *, const std::type_info &);
	void *symget(const char *, const char *, const std::type_info &);
	void symput(const char *, const char *);
	void trigger_all(enum plugin_op);

	public:
	std::string g_config_dir, g_data_dir;
	unsigned int g_context_num;
	const char *g_program_identifier;
	std::shared_ptr<config_file> g_config_file;

	protected:
	int load_library(const static_module &);

	std::list<SVC_PLUG_ENTITY> g_list_plug;
	std::vector<std::shared_ptr<service_entry>> g_list_service;
	std::span<const static_module> g_plugin_names;
	SVC_PLUG_ENTITY g_system_image;
};

}

extern const char version_info_for_memory_dumps[];
const char version_info_for_memory_dumps[] = "gromox " PACKAGE_VERSION;

static std::optional<svc_mgr> le_svc_mgr;
static thread_local SVC_PLUG_ENTITY *g_cur_plug;

/*
 *  init the service module with the path specified where
 *  we can load the .svc plug-in
 */
svc_mgr::svc_mgr(service_init_param &&parm)
{
	g_context_num = parm.context_num;
	g_config_file = std::move(parm.cfg);
	g_plugin_names = parm.plugin_list;
	g_program_identifier = parm.prog_id;
}

/* See commentary of service_query() why it's done */
static constexpr struct dlfuncs server_funcs = {
	/* .symget = */ service_query,
	/* .symreg = */ service_register_service,
	/* .get_config_path = */ []() { return le_svc_mgr->g_config_dir.c_str(); },
	/* .get_data_path = */ []() { return le_svc_mgr->g_data_dir.c_str(); },
	/* .get_context_num = */ []() { return le_svc_mgr->g_context_num; },
	/* .get_host_ID = */ []() {
                        auto r = le_svc_mgr->g_config_file->get_value("host_id");
                        return r != nullptr ? r : "localhost";
	},
	/* .get_prog_id = */ []() { return le_svc_mgr->g_program_identifier; },
};

int svc_mgr::run_early() try
{
	if (g_config_file == nullptr) {
		g_config_file = std::make_shared<config_file>();
		g_config_file->set_value("config_file_path", PKGSYSCONFDIR);
		g_config_file->set_value("data_file_path", PKGDATADIR);
	}
	g_config_dir = znul(g_config_file->get_value("config_file_path"));
	g_data_dir = znul(g_config_file->get_value("data_file_path"));

	for (const auto &i : g_plugin_names) {
		int ret = load_library(i);
		if (ret == PLUGIN_LOAD_OK) {
			if (g_cur_plug == nullptr)
				continue;
			if (g_cur_plug->lib_main(PLUGIN_EARLY_INIT, server_funcs)) {
				g_cur_plug = nullptr;
				continue;
			}
			g_list_plug.pop_back();
		}
		g_cur_plug = nullptr;
		service_stop();
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	return 0;
} catch (const std::bad_alloc &) {
	return PLUGIN_FAIL_EXECUTEMAIN;
}

int svc_mgr::run()
{
	for (auto it = g_list_plug.begin(); it != g_list_plug.end(); ) {
		g_cur_plug = &*it;
		if (g_cur_plug->lib_main(PLUGIN_INIT, server_funcs)) {
			g_cur_plug->completed_init = true;
			g_cur_plug = nullptr;
			++it;
			continue;
		}
		mlog(LV_ERR, "service: init of %s not successful", znul(g_cur_plug->file_name));
		it = g_list_plug.erase(it);
		g_cur_plug = nullptr;
		service_stop();
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	return 0;
}

svc_mgr::~svc_mgr()
{
	while (!g_list_plug.empty())
		/*
		 * PLUGIN_FREE handlers an invoke service_release, so clear
		 * list_service after the loop.
		 */
		g_list_plug.pop_back();

	g_list_service.clear();
}

/*
 *  load the plug-in in the specified path
 *
 *  @return
 *      PLUGIN_LOAD_OK              success
 *      PLUGIN_ALREADY_LOADED       already loaded by service module
 *      PLUGIN_FAIL_OPEN            error loading the file
 *      PLUGIN_NO_MAIN              error finding library function
 *      PLUGIN_FAIL_ALLOCNODE       fail to allocate memory for a node
 *      PLUGIN_FAIL_EXECUTEMAIN     error executing the plugin's init function
 */
int svc_mgr::load_library(const static_module &mod)
{
	/* check whether the library is already loaded */
	if (std::any_of(g_list_plug.cbegin(), g_list_plug.cend(),
	    [&](const SVC_PLUG_ENTITY &p) { return p.file_name == znul(mod.path); })) {
		mlog(LV_ERR, "%s: already loaded", znul(mod.path));
		return PLUGIN_ALREADY_LOADED;
	}
	SVC_PLUG_ENTITY plug;
	plug.lib_main = mod.efunc;
	plug.file_name = mod.path;
	g_list_plug.push_back(std::move(plug));
	/*
	 *  indicate the current lib node when plugin rigisters service
     *  plugin can only register service in "SVC_LibMain"
	 *  with the parameter PLUGIN_INIT
	 */
	g_cur_plug = &g_list_plug.back();
	return PLUGIN_LOAD_OK;
}

SVC_PLUG_ENTITY::SVC_PLUG_ENTITY(SVC_PLUG_ENTITY &&o) noexcept :
	generic_module(std::move(o)),
	list_service(std::move(o.list_service)), ref_count(o.ref_count.load()),
	ref_holders(std::move(o.ref_holders))
{
	o.ref_count = 0;
}

SVC_PLUG_ENTITY::~SVC_PLUG_ENTITY()
{
	PLUGIN_MAIN func;
	auto plib = this;
	if (plib->ref_count > 0) try {
		auto tx = "Unbalanced refcount on "s + znul(plib->file_name) + ", still held by {";
		for (auto &&s : plib->ref_holders) {
			tx += std::move(s);
			tx += ", ";
		}
		tx += "}";
		mlog(LV_NOTICE, "%s", tx.c_str());
		return;
	} catch (const std::bad_alloc &) {
		mlog(LV_NOTICE, "Unbalanced refcount on %s + ENOMEM", znul(plib->file_name));
		return;
	}
	if (plib->file_name != nullptr)
		mlog(LV_INFO, "service: unloading %s", plib->file_name);
	func = (PLUGIN_MAIN)plib->lib_main;
	if (func != nullptr && plib->completed_init)
		/* notify the plugin that it will be unloaded */
		func(PLUGIN_FREE, server_funcs);
}

/*
 * Publish a symbol to the process.
 *
 * There is no corresponding symbol unexporting. From the invocation
 * of service_stop onwards (also the only place modules can get
 * unloaded), g_list_service is invalid and is left in that state
 * since the process is about to terminate anyway.
 *
 * @func_name:	symbol name
 * @addr:	function address
 * @ti:		typeinfo for function
 */
BOOL svc_mgr::symreg(const char *func_name, void *addr,
    const std::type_info &ti) try
{
	if (func_name == nullptr)
		return FALSE;
	/*check if register service is invoked only in SVC_LibMain(PLUGIN_INIT,..)*/
	auto plug = g_cur_plug;
	if (plug == nullptr)
		plug = &g_system_image;

	/* check if the service is already registered in service list */
	if (std::any_of(g_list_service.begin(), g_list_service.end(),
	    [&](const std::shared_ptr<service_entry> &e) { return e->service_name == func_name; }))
		return FALSE;
	auto e = std::make_shared<service_entry>();
	e->service_name = func_name;
	e->service_addr = addr;
	e->type_info = &ti;
	e->plib = plug;
	g_list_service.push_back(e);
	plug->list_service.push_back(std::move(e));
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1637: ENOMEM");
	return false;
}

/**
 * Obtain a module symbol reference.
 *
 * For e.g. hpm_symbol_get and pdu_symbol_get: those are effectively an
 * implementation of a -rdynamic like feature (and we would not want to rely on
 * rdynamic, for portability reasons).
 *
 * @service_name:	symbol name
 * @module:		name of requesting module
 * @ti:			typeinfo for cross-checking expectations
 */
void *svc_mgr::symget(const char *service_name, const char *module,
    const std::type_info &ti)
{
	/* first find out the service node in global service list */
	auto node = std::find_if(g_list_service.begin(), g_list_service.end(),
	                [&](const std::shared_ptr<service_entry> &e) { return e->service_name == service_name; });
	if (node == g_list_service.end())
		return NULL;
	auto &pservice = *node;
	if (strcmp(ti.name(), pservice->type_info->name()) != 0)
		mlog(LV_ERR, "service: type mismatch on dlname \"%s\" (%s VS %s)",
			service_name, pservice->type_info->name(), ti.name());
	if (module == nullptr)
		/* untracked user */
		return pservice->service_addr;
	/* iterate the service node's reference list and try to find out 
	 * the module name, if the module already exists in the list, just add
	 *  reference cout of module
	 */
	auto pmodule = std::find_if(pservice->list_reference.begin(),
	               pservice->list_reference.end(),
	               [&](const reference_node &m) { return m.module_name == module; });
	if (pmodule == pservice->list_reference.end()) {
		pservice->list_reference.push_back(reference_node{module});
		pmodule = std::prev(pservice->list_reference.end());
	}
	/*
	 * whatever add one reference to ref_count of PLUG_ENTITY
	 */
	pmodule->ref_count ++;
	pservice->plib->ref_count ++;
	pservice->plib->ref_holders.emplace_back(service_name + "@"s + znul(module));
	return pservice->service_addr;

}

/*
 * Drop reference to a symbol
 *
 * @service_name:	symbol name
 * @module:		name of requesting module
 */
void svc_mgr::symput(const char *service_name, const char *module)
{
	auto node = std::find_if(g_list_service.begin(), g_list_service.end(),
	            [&](const std::shared_ptr<service_entry> &e) { return e->service_name == service_name; });
	if (node == g_list_service.end())
		return;
	auto &pservice = *node;
	/* find out the module node in service's reference list */
	auto pmodule = std::find_if(pservice->list_reference.begin(),
	               pservice->list_reference.end(),
	               [&](const reference_node &m) { return m.module_name == module; });
	if (pmodule == pservice->list_reference.end())
		return;
	pmodule->ref_count --;
	/* if reference count of module node is 0, free this node */ 
	if (pmodule->ref_count == 0)
		pservice->list_reference.erase(pmodule);
	pservice->plib->ref_count --;
	auto &rh = pservice->plib->ref_holders;
	auto i = std::find(rh.begin(), rh.end(), service_name + "@"s + znul(module));
	if (i != rh.end())
		rh.erase(i);
}

void svc_mgr::trigger_all(enum plugin_op ev)
{
	for (auto &p : g_list_plug) {
		g_cur_plug = &p;
		p.lib_main(ev, server_funcs);
	}
	g_cur_plug = nullptr;
}

generic_module::generic_module(generic_module &&o) noexcept :
	file_name(std::move(o.file_name)),
	lib_main(std::move(o.lib_main)),
	completed_init(std::move(o.completed_init))
{
	o.completed_init = false;
}

void service_init(service_init_param &&parm)
{
	le_svc_mgr.emplace(std::move(parm));
}

void service_stop()
{
	le_svc_mgr.reset();
}

int service_run_early()
{
	return le_svc_mgr->run_early();
}

int service_run()
{
	return le_svc_mgr->run();
}

BOOL service_register_service(const char *fun, void *addr,
    const std::type_info &ti)
{
	return le_svc_mgr->symreg(fun, addr, ti);
}

void *service_query(const char *fun, const char *caller, const std::type_info &ti)
{
	return le_svc_mgr->symget(fun, caller, ti);
}

void service_release(const char *fun, const char *caller)
{
	return le_svc_mgr->symput(fun, caller);
}

void service_trigger_all(enum plugin_op ev)
{
	return le_svc_mgr->trigger_all(ev);
}
