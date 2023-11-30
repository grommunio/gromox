// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2024 grommunio GmbH
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

}

extern const char version_info_for_memory_dumps[];
const char version_info_for_memory_dumps[] = "gromox " PACKAGE_VERSION;

static int service_load_library(static_module &&);

static std::string g_config_dir, g_data_dir;
static std::list<SVC_PLUG_ENTITY> g_list_plug;
static std::vector<std::shared_ptr<service_entry>> g_list_service;
static thread_local SVC_PLUG_ENTITY *g_cur_plug;
static unsigned int g_context_num;
static std::vector<static_module> g_plugin_names;
static const char *g_program_identifier;
static SVC_PLUG_ENTITY g_system_image;
static std::shared_ptr<config_file> g_config_file;

/*
 *  init the service module with the path specified where
 *  we can load the .svc plug-in
 */
void service_init(service_init_param &&parm)
{
	g_context_num = parm.context_num;
	g_config_file = std::move(parm.cfg);
	g_plugin_names = std::move(parm.plugin_list);
	g_program_identifier = parm.prog_id;
}

/* See commentary of service_query() why it's done */
static constexpr struct dlfuncs server_funcs = {
	/* .symget = */ service_query,
	/* .symreg = */ service_register_service,
	/* .get_config_path = */ []() { return g_config_dir.c_str(); },
	/* .get_data_path = */ []() { return g_data_dir.c_str(); },
	/* .get_context_num = */ []() { return g_context_num; },
	/* .get_host_ID = */ []() {
                        auto r = g_config_file->get_value("host_id");
                        return r != nullptr ? r : "localhost";
	},
	/* .get_prog_id = */ []() { return g_program_identifier; },
};

int service_run_early() try
{
	if (g_config_file == nullptr) {
		g_config_file = std::make_shared<config_file>();
		g_config_file->set_value("config_file_path", PKGSYSCONFDIR);
		g_config_file->set_value("data_file_path", PKGDATADIR);
	}
	g_config_dir = znul(g_config_file->get_value("config_file_path"));
	g_data_dir = znul(g_config_file->get_value("data_file_path"));

	for (auto &&i : g_plugin_names) {
		int ret = service_load_library(std::move(i));
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

int service_run()
{
	for (auto it = g_list_plug.begin(); it != g_list_plug.end(); ) {
		g_cur_plug = &*it;
		if (g_cur_plug->lib_main(PLUGIN_INIT, server_funcs)) {
			g_cur_plug->completed_init = true;
			g_cur_plug = nullptr;
			++it;
			continue;
		}
		mlog(LV_ERR, "service: init of %s not successful",
		        g_cur_plug->file_name.c_str());
		it = g_list_plug.erase(it);
		g_cur_plug = nullptr;
		service_stop();
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	return 0;
}

void service_stop()
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
static int service_load_library(static_module &&mod)
{
	auto path = mod.path.c_str();
	/* check whether the library is already loaded */
	auto it = std::find_if(g_list_plug.cbegin(), g_list_plug.cend(),
	          [&](const SVC_PLUG_ENTITY &p) { return p.file_name == mod.path; });
	if (it != g_list_plug.cend()) {
		mlog(LV_ERR, "%s: already loaded", path);
		return PLUGIN_ALREADY_LOADED;
	}
	SVC_PLUG_ENTITY plug;
	plug.lib_main = mod.efunc;
	plug.file_name = std::move(mod.path);
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
		auto tx = "Unbalanced refcount on " + plib->file_name + ", still held by {";
		for (auto &&s : plib->ref_holders) {
			tx += std::move(s);
			tx += ", ";
		}
		tx += "}";
		mlog(LV_NOTICE, "%s", tx.c_str());
		return;
	} catch (const std::bad_alloc &) {
		mlog(LV_NOTICE, "Unbalanced refcount on %s + ENOMEM", plib->file_name.c_str());
		return;
	}
	if (plib->file_name.size() > 0)
		mlog(LV_INFO, "service: unloading %s", plib->file_name.c_str());
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
BOOL service_register_service(const char *func_name, void *addr,
    const std::type_info &ti) try
{
	if (func_name == nullptr)
		return FALSE;
	/*check if register service is invoked only in SVC_LibMain(PLUGIN_INIT,..)*/
	auto plug = g_cur_plug;
	if (plug == nullptr)
		plug = &g_system_image;

	/* check if the service is already registered in service list */
	auto it = std::find_if(g_list_service.begin(), g_list_service.end(),
	          [&](const std::shared_ptr<service_entry> &e) { return e->service_name == func_name; });
	if (it != g_list_service.end())
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
void *service_query(const char *service_name, const char *module, const std::type_info &ti)
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
void service_release(const char *service_name, const char *module)
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

void service_trigger_all(enum plugin_op ev)
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
