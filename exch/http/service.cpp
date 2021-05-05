// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <atomic>
#include <list>
#include <string>
#include <typeinfo>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/paths.h>
#include <gromox/double_list.hpp>
#include "resource.h"
#include "service.h"
#include <gromox/util.hpp>
#include <sys/types.h>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <cstdio>

using namespace std::string_literals;

namespace {
struct REFERENCE_NODE {
	DOUBLE_LIST_NODE	node;
	char				module_name[256];
	int					ref_count;
};
}

struct SVC_PLUG_ENTITY {
	SVC_PLUG_ENTITY();
	SVC_PLUG_ENTITY(SVC_PLUG_ENTITY &&);
	~SVC_PLUG_ENTITY();
	void operator=(SVC_PLUG_ENTITY &&) = delete;

	DOUBLE_LIST list_service{};
	std::atomic<int> ref_count = 0;
	void *handle = nullptr;
	PLUGIN_MAIN lib_main = nullptr;
	TALK_MAIN talk_main = nullptr;
	std::string file_name, full_path;
	bool completed_init = false;
};

namespace {
struct SERVICE_ENTRY {
	DOUBLE_LIST_NODE	node_service;
	DOUBLE_LIST_NODE	node_lib;
    char				service_name[256];
    void				*service_addr;
	SVC_PLUG_ENTITY *plib;	
	const std::type_info *type_info;
	DOUBLE_LIST			list_reference;
};
}

static void *service_query_service(const char *service, const std::type_info &);
static BOOL service_register_talk(TALK_MAIN talk);
static const char *service_get_plugin_name();
static const char *service_get_config_path();
static const char *service_get_data_path();
static unsigned int service_get_context_num();
static const char *service_get_host_ID();

static char g_init_path[256], g_config_dir[256], g_data_dir[256], g_state_dir[256];
static std::list<SVC_PLUG_ENTITY> g_list_plug;
static DOUBLE_LIST		g_list_service;
static SVC_PLUG_ENTITY *g_cur_plug;
static unsigned int g_context_num;
static const char *const *g_plugin_names, *g_program_identifier;
static bool g_ign_loaderr;
static SVC_PLUG_ENTITY g_system_image;

static const char *service_get_prog_id() { return g_program_identifier; }

/*
 *  init the service module with the path specified where
 *  we can load the .svc plug-in
 */
void service_init(const struct service_init_param &parm)
{
	g_context_num = parm.context_num;
	gx_strlcpy(g_init_path, parm.plugin_dir, sizeof(g_init_path));
	gx_strlcpy(g_config_dir, parm.config_dir, sizeof(g_config_dir));
	gx_strlcpy(g_data_dir, parm.data_dir, sizeof(g_data_dir));
	gx_strlcpy(g_state_dir, parm.state_dir, sizeof(g_state_dir));
	g_plugin_names = parm.plugin_list;
	g_ign_loaderr = parm.plugin_ignloaderr;
	g_program_identifier = parm.prog_id;
	double_list_init(&g_list_service);
	double_list_init(&g_system_image.list_service);
}

/*
 *  run the module
 *  @return 
 *      0       success
 *      <0      fail
 */
int service_run()
{
	for (const char *const *i = g_plugin_names; *i != NULL; ++i) {
		int ret = service_load_library(*i);
		if (!g_ign_loaderr && ret != PLUGIN_LOAD_OK)
			return -1;
	}
	return 0;
}

/*
 *  stop the module
 *
 *  @return
 *      0       success
 *      <0      fail
 */
int service_stop()
{
	g_list_plug.clear();
	g_init_path[0] = '\0';
	g_plugin_names = NULL;
	return 0;
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
int service_load_library(const char *path)
{
	static void *const server_funcs[] = {(void *)service_query_service};
	const char *fake_path = path;

	/* check whether the library is already loaded */
	auto it = std::find_if(g_list_plug.cbegin(), g_list_plug.cend(),
	          [&](const SVC_PLUG_ENTITY &p) { return p.file_name == path; });
	if (it != g_list_plug.cend()) {
		printf("[service]: %s is already loaded by service module\n", path);
		return PLUGIN_ALREADY_LOADED;
	}
	SVC_PLUG_ENTITY plug;
	plug.handle = dlopen(path, RTLD_LAZY);
	if (plug.handle == nullptr && strchr(path, '/') == nullptr)
		plug.handle = dlopen((g_init_path + "/"s + path).c_str(), RTLD_LAZY);
	if (plug.handle == nullptr) {
		printf("[service]: error loading %s: %s\n", fake_path, dlerror());
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
	}
	plug.lib_main = reinterpret_cast<decltype(plug.lib_main)>(dlsym(plug.handle, "SVC_LibMain"));
	if (plug.lib_main == nullptr) {
		printf("[service]: error finding the SVC_LibMain function in %s\n",
				fake_path);
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_NO_MAIN;
	}
	plug.file_name = path;
	plug.full_path = fake_path;
	g_list_plug.push_back(std::move(plug));
	/*
	 *  indicate the current lib node when plugin rigisters service
     *  plugin can only register service in "SVC_LibMain"
	 *  whith the paramter PLUGIN_INIT
	 */
	g_cur_plug = &g_list_plug.back();
	/* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!g_cur_plug->lib_main(PLUGIN_INIT, const_cast<void **>(server_funcs))) {
		printf("[service]: error executing the plugin's init function "
				"in %s\n", fake_path);
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		g_list_plug.pop_back();
		g_cur_plug = NULL;
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	g_cur_plug->completed_init = true;
	g_cur_plug = NULL;
	return PLUGIN_LOAD_OK;
}

SVC_PLUG_ENTITY::SVC_PLUG_ENTITY()
{
	/*  for all plugins, there's should be a read-write lock for controlling
	 *  its modification. ervery time, the service function is invoked,
	 *  the read lock is acquired. when the plugin is going to be modified,
	 *  acquire the write lock.
	 */
	double_list_init(&list_service);
}

SVC_PLUG_ENTITY::SVC_PLUG_ENTITY(SVC_PLUG_ENTITY &&o) :
	list_service(o.list_service), ref_count(o.ref_count.load()),
	handle(o.handle), lib_main(o.lib_main), talk_main(o.talk_main),
	file_name(std::move(o.file_name)), full_path(std::move(o.full_path)),
	completed_init(o.completed_init)
{
	o.list_service = {};
	o.ref_count = 0;
	o.handle = nullptr;
	o.completed_init = false;
}

SVC_PLUG_ENTITY::~SVC_PLUG_ENTITY()
{
	DOUBLE_LIST_NODE *pnode;
	PLUGIN_MAIN func;
	auto plib = this;
	if (plib->ref_count > 0) {
		printf("Unbalanced refcount on %s\n", plib->file_name.c_str());
		return;
	}
	if (plib->file_name.size() > 0)
		printf("[service]: unloading %s\n", plib->file_name.c_str());
	func = (PLUGIN_MAIN)plib->lib_main;
	if (func != nullptr && plib->completed_init)
		/* notify the plugin that it will be unloaded */
		func(PLUGIN_FREE, NULL);
	/* check if the there rests service(s) that has not been unrigstered */
	if (0 != double_list_get_nodes_num(&plib->list_service)) {
		for (pnode=double_list_get_head(&plib->list_service); NULL!=pnode;
			 pnode=double_list_get_after(&plib->list_service, pnode)) {
			double_list_remove(&g_list_service,
				&((SERVICE_ENTRY*)(pnode->pdata))->node_service);
		}
		/* free lib's service list */
		while ((pnode = double_list_pop_front(&plib->list_service)) != nullptr) {
			free(pnode->pdata);
			pnode = NULL;
		}
		double_list_free(&plib->list_service);
	}
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
    if (0 == strcmp(service, "register_talk")) {
		return reinterpret_cast<void *>(service_register_talk);
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

/*
 *	get current plugin name
 *	@return
 *		plugin name
 *
 */
static const char* service_get_plugin_name()
{
	if (NULL == g_cur_plug) {
		return NULL;
	}
	auto fn = g_cur_plug->file_name.c_str();
	return strncmp(fn, "libgxs_", 7) == 0 ? fn + 7 : fn;
}

/*
 *	get config folder path
 *	@return
 *		config folder path
 */
static const char* service_get_config_path()
{
	return g_config_dir;
}

/*
 *	get data folder path
 *	@return
 *		data folder path
 */
static const char* service_get_data_path()
{
	return g_data_dir;
}

/*
 *	get system context number
 *	@return
 *		context number
 */
static unsigned int service_get_context_num()
{
	return g_context_num;
}

/*
 *	get system host ID
 *	@return
 *		host ID string
 */
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
BOOL service_register_service(const char *func_name, void *addr, const std::type_info &ti)
{
	 DOUBLE_LIST_NODE *pnode;
	 SERVICE_ENTRY *pservice;

	if (NULL == func_name) {
		return FALSE;
	}
	/*check if register service is invoked only in SVC_LibMain(PLUGIN_INIT,..)*/
	auto plug = g_cur_plug;
	if (plug == nullptr)
		plug = &g_system_image;

	/* check if the service is already registered in service list */
	for (pnode=double_list_get_head(&g_list_service); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_service, pnode)) {
		if (strcmp(((SERVICE_ENTRY*)(pnode->pdata))->service_name, 
			func_name) == 0) {
			break;
		}
	}
	if (NULL != pnode) {
		return FALSE;
	}
	pservice = static_cast<decltype(pservice)>(malloc(sizeof(*pservice)));
	if (NULL == pservice) {
		return FALSE;
	}
	memset(pservice, 0, sizeof(SERVICE_ENTRY));
	pservice->node_service.pdata	= pservice;
	pservice->node_lib.pdata		= pservice;
	pservice->service_addr			= addr;
	pservice->type_info = &ti;
	pservice->plib = plug;
	double_list_init(&pservice->list_reference);
	gx_strlcpy(pservice->service_name, func_name, GX_ARRAY_SIZE(pservice->service_name));
	double_list_append_as_tail(&g_list_service, &pservice->node_service);
	/* append also the service into service list */
	double_list_append_as_tail(&plug->list_service, &pservice->node_lib);
	return TRUE;
}

/*
 *  register the console talk function
 *  @param
 *      talk    pointer to talk function
 *  @return
 *      TRUE or FALSE
 */
static BOOL service_register_talk(TALK_MAIN talk)
{
	if(NULL == g_cur_plug) {
		return FALSE;
	}
	g_cur_plug->talk_main = talk;
	return TRUE;
}

/*
 *	query the registered service
 *	@param
 *		service_name [in]	indicate the service name
 *		module [in]			indicate the module name
 */
void *service_query(const char *service_name, const char *module, const std::type_info &ti)
{
	DOUBLE_LIST_NODE *pnode;
	SERVICE_ENTRY	 *pservice;
	REFERENCE_NODE	 *pmodule;
	
	/* first find out the service node in global service list */
	for (pnode=double_list_get_head(&g_list_service); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_service, pnode)) {
		pservice = (SERVICE_ENTRY*)(pnode->pdata);
		if (strcmp(pservice->service_name, service_name) == 0) {
			break;
		}
	}
	if (NULL == pnode) {
		static constexpr const char *excl[] =
			{"ip_container_add", "ip_container_remove",
			"ip_filter_add", "ip_filter_judge", "ndr_stack_alloc"};
		if (std::none_of(excl, &excl[GX_ARRAY_SIZE(excl)],
		    [&](const char *s) { return strcmp(service_name, s) == 0; }))
			printf("[service]: dlname \"%s\" not found\n", service_name);
		return NULL;
	}
	if (strcmp(ti.name(), pservice->type_info->name()) != 0)
		printf("[service]: type mismatch on dlname \"%s\" (%s VS %s)\n",
			service_name, pservice->type_info->name(), ti.name());
	if (module == nullptr)
		/* untracked user */
		return pservice->service_addr;
	/* iterate the service node's reference list and try to find out 
	 * the module name, if the module already exists in the list, just add
	 *  reference cout of module
	 */
	for (pnode=double_list_get_head(&pservice->list_reference); NULL!=pnode;
		 pnode=double_list_get_after(&pservice->list_reference, pnode)) {
		pmodule = (REFERENCE_NODE*)(pnode->pdata);
		if (strcmp(pmodule->module_name, module) == 0) {
			break;
		}
	}
	if (NULL == pnode) {
		pmodule = static_cast<decltype(pmodule)>(malloc(sizeof(*pmodule)));
		if (NULL == pmodule) {
			printf("[service]: Failed to allocate memory for module node\n");
			return NULL;
		}
		memset(pmodule, 0, sizeof(REFERENCE_NODE));
		pmodule->node.pdata = pmodule;
		gx_strlcpy(pmodule->module_name, module, GX_ARRAY_SIZE(pmodule->module_name));
		double_list_append_as_tail(&pservice->list_reference, &pmodule->node);
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
	DOUBLE_LIST_NODE *pnode;
	SERVICE_ENTRY	 *pservice;
	REFERENCE_NODE	 *pmodule;
	
	
	for (pnode=double_list_get_head(&g_list_service); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_service, pnode)) {
		pservice = (SERVICE_ENTRY*)(pnode->pdata);
		if (strcmp(pservice->service_name, service_name) == 0) {
			break;
		}
	}
	if (NULL == pnode) {
		return;
	}
	/* find out the module node in service's reference list */
	for (pnode=double_list_get_head(&pservice->list_reference); NULL!=pnode;
		 pnode=double_list_get_after(&pservice->list_reference, pnode)) {
		pmodule = (REFERENCE_NODE*)(pnode->pdata);
		if (strcmp(pmodule->module_name, module) == 0) {
			break;
		}
	}
	if (NULL == pnode) {
		return;
	}
	pmodule->ref_count --;
	/* if reference count of module node is 0, free this node */ 
	if (0 == pmodule->ref_count) {
		double_list_remove(&pservice->list_reference, &pmodule->node);
		free(pmodule);
	}
	pservice->plib->ref_count --;
}

/*
 *	pass argments to console talk function of plugin
 *	@param
 *		int				argc
 *		argv [in]		arguments list
 *		reason [out]	buffer for return result
 *		int len			length of reason buffer
 *	@return
 *		PLUGIN_TALK_OK    found plugin
 *		PLUGIN_NO_FILE    plug in not in list
 *		PLUGIN_NO_TALK    plug has not registered talk function
 */
int service_console_talk(int argc, char **argv, char *reason, int len)
{
	auto plib = std::find_if(g_list_plug.cbegin(), g_list_plug.cend(),
	            [&](const SVC_PLUG_ENTITY &p) { return p.file_name == argv[0]; });
	if (plib == g_list_plug.cend())
		return PLUGIN_NO_FILE;
	if (plib->talk_main == nullptr)
		return PLUGIN_NO_TALK;
	plib->talk_main(argc, argv, reason, len);
	return PLUGIN_TALK_OK;
}

void service_reload_all()
{
	for (const auto &p : g_list_plug)
		p.lib_main(PLUGIN_RELOAD, nullptr);
}
