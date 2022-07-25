// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
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

extern std::shared_ptr<CONFIG_FILE> g_config_file;

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

struct SVC_PLUG_ENTITY {
	SVC_PLUG_ENTITY() = default;
	SVC_PLUG_ENTITY(SVC_PLUG_ENTITY &&) noexcept;
	~SVC_PLUG_ENTITY();
	void operator=(SVC_PLUG_ENTITY &&) noexcept = delete;

	std::vector<std::shared_ptr<service_entry>> list_service;
	std::atomic<int> ref_count = 0;
	void *handle = nullptr;
	PLUGIN_MAIN lib_main = nullptr;
	std::string file_name, full_path;
	bool completed_init = false;
};

}

static int service_load_library(const char *);
static void *service_query_service(const char *service, const std::type_info &);
static const char *service_get_plugin_name();
static const char *service_get_config_path();
static const char *service_get_data_path();
static unsigned int service_get_context_num();
static const char *service_get_host_ID();

static char g_config_dir[256], g_data_dir[256], g_state_dir[256];
static std::list<SVC_PLUG_ENTITY> g_list_plug;
static std::vector<std::shared_ptr<service_entry>> g_list_service;
static SVC_PLUG_ENTITY *g_cur_plug;
static unsigned int g_context_num;
static std::vector<std::string> g_plugin_names;
static const char *g_program_identifier;
static SVC_PLUG_ENTITY g_system_image;

static const char *service_get_prog_id() { return g_program_identifier; }

/*
 *  init the service module with the path specified where
 *  we can load the .svc plug-in
 */
void service_init(service_init_param &&parm)
{
	g_context_num = parm.context_num;
	gx_strlcpy(g_config_dir, parm.config_dir, sizeof(g_config_dir));
	gx_strlcpy(g_data_dir, parm.data_dir, sizeof(g_data_dir));
	gx_strlcpy(g_state_dir, parm.state_dir, sizeof(g_state_dir));
	g_plugin_names = std::move(parm.plugin_list);
	g_program_identifier = parm.prog_id;
}

static void *const server_funcs[] = {reinterpret_cast<void *>(service_query_service)};

int service_run_early()
{
	for (const auto &i : g_plugin_names) {
		int ret = service_load_library(i.c_str());
		if (ret == PLUGIN_LOAD_OK) {
			if (g_cur_plug->lib_main(PLUGIN_EARLY_INIT, const_cast<void **>(server_funcs))) {
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
}

int service_run()
{
	for (auto it = g_list_plug.begin(); it != g_list_plug.end(); ) {
		g_cur_plug = &*it;
		if (g_cur_plug->lib_main(PLUGIN_INIT, const_cast<void **>(server_funcs))) {
			g_cur_plug->completed_init = true;
			g_cur_plug = nullptr;
			++it;
			continue;
		}
		fprintf(stderr, "[service]: Init of %s not successful\n",
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
	g_list_plug.clear();
}

/*
 *  load the plug-in in the specified path
 *
 *  @param
 *      path [in]       the plug-in path
 *
 *  @return
 *      PLUGIN_LOAD_OK              success
 *      PLUGIN_ALREADY_LOADED       already loaded by service module
 *      PLUGIN_FAIL_OPEN            error loading the file
 *      PLUGIN_NO_MAIN              error finding library function
 *      PLUGIN_FAIL_ALLOCNODE       fail to allocate memory for a node
 *      PLUGIN_FAIL_EXECUTEMAIN     error executing the plugin's init function
 */
static int service_load_library(const char *path)
{
	const char *fake_path = path;

	/* check whether the library is already loaded */
	auto it = std::find_if(g_list_plug.cbegin(), g_list_plug.cend(),
	          [&](const SVC_PLUG_ENTITY &p) { return p.file_name == path; });
	if (it != g_list_plug.cend()) {
		fprintf(stderr, "[service]: %s is already loaded by service module\n", path);
		return PLUGIN_ALREADY_LOADED;
	}
	SVC_PLUG_ENTITY plug;
	plug.handle = dlopen(path, RTLD_LAZY);
	if (plug.handle == nullptr && strchr(path, '/') == nullptr)
		plug.handle = dlopen((PKGLIBDIR + "/"s + path).c_str(), RTLD_LAZY);
	if (plug.handle == nullptr) {
		fprintf(stderr, "[service]: error loading %s: %s\n", fake_path, dlerror());
		fprintf(stderr, "[service]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
	}
	plug.lib_main = reinterpret_cast<decltype(plug.lib_main)>(dlsym(plug.handle, "SVC_LibMain"));
	if (plug.lib_main == nullptr) {
		fprintf(stderr, "[service]: error finding the SVC_LibMain function in %s\n",
				fake_path);
		fprintf(stderr, "[service]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_NO_MAIN;
	}
	plug.file_name = path;
	plug.full_path = fake_path;
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
	list_service(std::move(o.list_service)), ref_count(o.ref_count.load()),
	handle(o.handle), lib_main(o.lib_main),
	file_name(std::move(o.file_name)), full_path(std::move(o.full_path)),
	completed_init(o.completed_init)
{
	o.ref_count = 0;
	o.handle = nullptr;
	o.completed_init = false;
}

SVC_PLUG_ENTITY::~SVC_PLUG_ENTITY()
{
	PLUGIN_MAIN func;
	auto plib = this;
	if (plib->ref_count > 0) {
		fprintf(stderr, "Unbalanced refcount on %s\n", plib->file_name.c_str());
		return;
	}
	if (plib->file_name.size() > 0)
		fprintf(stderr, "[service]: unloading %s\n", plib->file_name.c_str());
	func = (PLUGIN_MAIN)plib->lib_main;
	if (func != nullptr && plib->completed_init)
		/* notify the plugin that it will be unloaded */
		func(PLUGIN_FREE, NULL);
	if (handle != nullptr)
		dlclose(handle);
}

static const char *service_get_state_path()
{
	return g_state_dir;
}

/*
 *  get services
 *  @param
 *      service    name of service
 *
 *  @return
 *      address of function
 */
static void *service_query_service(const char *service, const std::type_info &ti)
{
    if (0 == strcmp(service, "register_service")) {
		return reinterpret_cast<void *>(service_register_service);
    }
	if (0 == strcmp(service, "get_plugin_name")) {
		return reinterpret_cast<void *>(service_get_plugin_name);
	}
	if (0 == strcmp(service, "get_config_path")) {
		return reinterpret_cast<void *>(service_get_config_path);
	}
	if (0 == strcmp(service, "get_data_path")) {
		return reinterpret_cast<void *>(service_get_data_path);
	}
	if (strcmp(service, "get_state_path") == 0)
		return reinterpret_cast<void *>(service_get_state_path);
	if (0 == strcmp(service, "get_context_num")) {
		return reinterpret_cast<void *>(service_get_context_num);
	}
	if (0 == strcmp(service, "get_host_ID")) {
		return reinterpret_cast<void *>(service_get_host_ID);
	}
	if (strcmp(service, "get_prog_id") == 0)
		return reinterpret_cast<void *>(service_get_prog_id);
	return service_query(service, nullptr, ti);
}

static const char* service_get_plugin_name()
{
	if (NULL == g_cur_plug) {
		return NULL;
	}
	auto fn = g_cur_plug->file_name.c_str();
	return strncmp(fn, "libgxs_", 7) == 0 ? fn + 7 : fn;
}

static const char* service_get_config_path()
{
	return g_config_dir;
}

static const char* service_get_data_path()
{
	return g_data_dir;
}

static unsigned int service_get_context_num()
{
	return g_context_num;
}

static const char* service_get_host_ID()
{
	const char *ret_value = resource_get_string("HOST_ID");
	if (NULL == ret_value) {
		ret_value = "localhost";
	}
	return ret_value;
}

/*
 *  register the plugin-provide service function
 *  @param
 *      func_name [in]    name for the service
 *      addr [in]         pointer of function
 *  @return
 *      TRUE or FALSE
 */
BOOL service_register_service(const char *func_name, void *addr,
    const std::type_info &ti) try
{
	if (NULL == func_name) {
		return FALSE;
	}
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
	fprintf(stderr, "E-1637: ENOMEM\n");
	return false;
}

/*
 *	query the registered service
 *	@param
 *		service_name [in]	indicate the service name
 *		module [in]			indicate the module name
 */
void *service_query(const char *service_name, const char *module, const std::type_info &ti)
{
	/* first find out the service node in global service list */
	auto node = std::find_if(g_list_service.begin(), g_list_service.end(),
	                [&](const std::shared_ptr<service_entry> &e) { return e->service_name == service_name; });
	if (node == g_list_service.end()) {
		static constexpr const char *excl[] =
			{"ip_container_add", "ip_container_remove",
			"ip_filter_add", "ip_filter_judge", "ndr_stack_alloc"};
		if (std::none_of(excl, &excl[GX_ARRAY_SIZE(excl)],
		    [&](const char *s) { return strcmp(service_name, s) == 0; }))
			fprintf(stderr, "[service]: dlname \"%s\" not found\n", service_name);
		return NULL;
	}
	auto &pservice = *node;
	if (strcmp(ti.name(), pservice->type_info->name()) != 0) {
		if (isatty(STDERR_FILENO))
			fprintf(stderr, "\e[33m");
		fprintf(stderr, "[service]: type mismatch on dlname \"%s\" (%s VS %s)",
			service_name, pservice->type_info->name(), ti.name());
		if (isatty(STDERR_FILENO))
			fprintf(stderr, "\e[0m");
		fprintf(stderr, "\n");
	}
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
	return pservice->service_addr;

}

/*
 *	release the queried service
 *	@param
 *		service_name [in]	indicate the service name
 *		module [in]			indicate the module name
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
	if (0 == pmodule->ref_count) {
		pservice->list_reference.erase(pmodule);
	}
	pservice->plib->ref_count --;
}

void service_reload_all()
{
	for (const auto &p : g_list_plug)
		p.lib_main(PLUGIN_RELOAD, nullptr);
}
