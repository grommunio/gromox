// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2026 grommunio GmbH
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
	int run_library(const generic_module &);

	public:
	std::string g_config_dir, g_data_dir;
	unsigned int g_context_num;
	const char *g_program_identifier;
	std::shared_ptr<config_file> g_config_file;

	protected:
	bool library_present(const generic_module &);
	void insert_library(const generic_module &);

	std::list<SVC_PLUG_ENTITY> g_list_plug;
	std::vector<std::shared_ptr<service_entry>> g_list_service;
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
svc_mgr::svc_mgr(service_init_param &&parm) :
	g_context_num(parm.context_num), g_program_identifier(parm.prog_id),
	g_config_file(std::move(parm.cfg))
{
	if (g_config_file == nullptr) {
		g_config_file = std::make_shared<config_file>();
		g_config_file->set_value("config_file_path", PKGSYSCONFDIR);
		g_config_file->set_value("data_file_path", PKGDATADIR);
	}
	g_config_dir = znul(g_config_file->get_value("config_file_path"));
	g_data_dir = znul(g_config_file->get_value("data_file_path"));
	for (const auto &i : parm.plugin_list)
		insert_library(i);
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

int svc_mgr::run_early()
{
	for (auto it = g_list_plug.begin(); it != g_list_plug.end(); ) {
		if (it->init_state != generic_module::state::uninit)
			continue;
		it->init_state = generic_module::state::early_start;
		if (it->lib_main(PLUGIN_EARLY_INIT, server_funcs)) {
			it->init_state = generic_module::state::early_done;
			++it;
			continue;
		}
		mlog(LV_ERR, "service: init of %s not successful", znul(it->file_name));
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	return PLUGIN_LOAD_OK;
}

int svc_mgr::run()
{
	for (auto it = g_list_plug.begin(); it != g_list_plug.end(); ) {
		if (it->init_state != generic_module::state::uninit &&
		    it->init_state != generic_module::state::early_done)
			continue;
		it->init_state = generic_module::state::init_start;
		g_cur_plug = &*it;
		if (g_cur_plug->lib_main(PLUGIN_INIT, server_funcs)) {
			g_cur_plug = nullptr;
			it->init_state = generic_module::state::init_done;
			++it;
			continue;
		}
		mlog(LV_ERR, "service: init of %s not successful", znul(it->file_name));
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	return PLUGIN_LOAD_OK;
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

bool svc_mgr::library_present(const generic_module &mod)
{
	return std::any_of(g_list_plug.cbegin(), g_list_plug.cend(),
	       [&](const SVC_PLUG_ENTITY &p) {
	       	return strcmp(p.file_name, znul(mod.file_name)) == 0 ||
		       p.lib_main == mod.lib_main;
	       });
}

void svc_mgr::insert_library(const generic_module &mod)
{
	/* check whether the library is already loaded */
	if (library_present(mod))
		return;
	SVC_PLUG_ENTITY plug;
	plug.lib_main = mod.lib_main;
	plug.file_name = mod.file_name;
	g_list_plug.push_back(std::move(plug));
}

/*
 * For use by all kinds of modules to load libraries in the moment they are
 * needed. EARLY_INIT not included on purpose.
 */
int svc_mgr::run_library(const generic_module &mod) try
{
	if (library_present(mod))
		return PLUGIN_LOAD_OK;
	SVC_PLUG_ENTITY plug;
	plug.lib_main = mod.lib_main;
	plug.file_name = mod.file_name;
	g_list_plug.push_back(std::move(plug));
	g_cur_plug = &g_list_plug.back();
	if (!g_cur_plug->lib_main(PLUGIN_INIT, server_funcs)) {
		g_cur_plug = nullptr;
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	g_cur_plug = nullptr;
	return PLUGIN_LOAD_OK;
} catch (const std::bad_alloc &) {
	return PLUGIN_FAIL_ALLOCNODE;
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
	if (plib->init_state != generic_module::state::init_done)
		return;
	if (plib->file_name != nullptr)
		mlog(LV_INFO, "service: unloading %s", plib->file_name);
	auto func = (PLUGIN_MAIN)plib->lib_main;
	if (func != nullptr)
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
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
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
	init_state(std::move(o.init_state))
{
	o.init_state = state::uninit;
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

int service_run_library(const generic_module &mod)
{
	return le_svc_mgr->run_library(mod);
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
