// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <string>
#include <typeinfo>
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

struct REFERENCE_NODE {
	DOUBLE_LIST_NODE	node;
	char				module_name[256];
	int					ref_count;
};

struct PLUG_ENTITY {
	DOUBLE_LIST_NODE	node;
	DOUBLE_LIST			list_service;
	int					ref_count;
    void*				handle;
    PLUGIN_MAIN			lib_main;
    TALK_MAIN			talk_main;
    char				file_name[256];
	char				full_path[256];
	bool completed_init;
};

struct SERVICE_ENTRY {
	DOUBLE_LIST_NODE	node_service;
	DOUBLE_LIST_NODE	node_lib;
    char				service_name[256];
    void				*service_addr;
	PLUG_ENTITY *plib;	
	const std::type_info *type_info;
	DOUBLE_LIST			list_reference;
};

static void *service_query_service(const char *service, const std::type_info &);
static BOOL service_register_talk(TALK_MAIN talk);
static const char *service_get_plugin_name();
static const char *service_get_config_path();
static const char *service_get_data_path();
static int service_get_context_num();
static const char *service_get_host_ID();

static char g_init_path[256], g_config_dir[256], g_data_dir[256], g_state_dir[256];
static DOUBLE_LIST      g_list_plug;
static DOUBLE_LIST		g_list_service;
static PLUG_ENTITY		*g_cur_plug;
static int				g_context_num;
static const char *const *g_plugin_names;
static bool g_ign_loaderr;
static PLUG_ENTITY g_system_image;

/*
 *  init the service module with the path specified where
 *  we can load the .svc plug-in
 */
void service_init(const struct service_init_param &parm)
{
	g_context_num = parm.context_num;
	HX_strlcpy(g_init_path, parm.plugin_dir, sizeof(g_init_path));
	HX_strlcpy(g_config_dir, parm.config_dir, sizeof(g_config_dir));
	HX_strlcpy(g_data_dir, parm.data_dir, sizeof(g_data_dir));
	HX_strlcpy(g_state_dir, parm.state_dir, sizeof(g_state_dir));
	g_plugin_names = parm.plugin_list;
	g_ign_loaderr = parm.plugin_ignloaderr;
	double_list_init(&g_list_plug);
	double_list_init(&g_list_service);
	g_system_image.node.pdata = &g_system_image;
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
	std::vector<std::string> stack;
	DOUBLE_LIST_NODE *pnode;

	for (pnode = double_list_get_head(&g_list_plug); pnode != nullptr;
	     pnode = double_list_get_after(&g_list_plug, pnode)) {
		try {
			stack.push_back(static_cast<PLUG_ENTITY *>(pnode->pdata)->file_name);
		} catch (...) {
		}
	}
	while (!stack.empty()) {
		service_unload_library(stack.back().c_str());
		stack.pop_back();
	}
	double_list_free(&g_list_plug);
	double_list_free(&g_list_service);
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
	DOUBLE_LIST_NODE *pnode;
	PLUGIN_MAIN func;
	PLUG_ENTITY *plib;

	/* check whether the library is already loaded */
	for (pnode=double_list_get_head(&g_list_plug); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_plug, pnode)) {
		if (strcmp(static_cast<PLUG_ENTITY *>(pnode->pdata)->file_name, path) == 0) {
			printf("[service]: %s is already loaded by service module\n", path);
			return PLUGIN_ALREADY_LOADED;
		}
	}
	void *handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL && strchr(path, '/') == NULL) {
		char altpath[256];
		snprintf(altpath, sizeof(altpath), "%s/%s", g_init_path, path);
		handle = dlopen(altpath, RTLD_LAZY);
	}
	if (NULL == handle){
		printf("[service]: error loading %s: %s\n", fake_path, dlerror());
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
	}
	func = (PLUGIN_MAIN)dlsym(handle, "SVC_LibMain");
	if (NULL == func) {
		printf("[service]: error finding the SVC_LibMain function in %s\n",
				fake_path);
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return PLUGIN_NO_MAIN;
	}
	plib = (PLUG_ENTITY*)malloc(sizeof(PLUG_ENTITY));
	if (NULL == plib) {
		printf("[service]: Failed to allocate memory for %s\n", fake_path);
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return PLUGIN_FAIL_ALLOCNODE;
	}
	memset(plib, 0, sizeof(PLUG_ENTITY));
	/* make the node's pdata ponter point to the PLUG_ENTITY struct */
	plib->node.pdata = plib;
	/*  for all plugins, there's should be a read-write lock for controlling
	 *  its modification. ervery time, the service function is invoked,
	 *  the read lock is acquired. when the plugin is going to be modified,
	 *  acquire the write lock.
	 */
	double_list_init(&plib->list_service);
	strncpy(plib->file_name, path, 255);
	strncpy(plib->full_path, fake_path, 255);
	plib->handle = handle;
	plib->lib_main = func;
	/* append the plib node into lib list */
	double_list_append_as_tail(&g_list_plug, &plib->node);
	/*
	 *  indicate the current lib node when plugin rigisters service
     *  plugin can only register service in "SVC_LibMain"
	 *  whith the paramter PLUGIN_INIT
	 */
	g_cur_plug = plib;
	/* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!func(PLUGIN_INIT, const_cast<void **>(server_funcs))) {
		printf("[service]: error executing the plugin's init function "
				"in %s\n", fake_path);
		printf("[service]: the plugin %s is not loaded\n", fake_path);
		/*
		 *  the lib node will automatically removed from libs list in
		 *  service_unload_library function
		 */
		service_unload_library(fake_path);
		g_cur_plug = NULL;
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	plib->completed_init = true;
	g_cur_plug = NULL;
	return PLUGIN_LOAD_OK;
}

/*
 *  unload the plug-in
 *
 *  @return
 *      PLUGIN_UNABLE_UNLOAD	unable unload library
 *		PLUGIN_UNLOAD_OK		success
 *		PLUGIN_NOT_FOUND		plugin is not found in service module
 */
int service_unload_library(const char *path)
{
	DOUBLE_LIST_NODE *pnode;
	PLUGIN_MAIN func;
	PLUG_ENTITY *plib;

	auto ptr = strrchr(path, '/');
	if (NULL != ptr) {
		ptr++;
	} else {
		ptr = (char*)path;
	}
	/* first find the plugin node in lib list */
	for (pnode=double_list_get_head(&g_list_plug); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_plug, pnode)){
		if (0 == strcmp(((PLUG_ENTITY*)(pnode->pdata))->file_name, ptr)) {
			break;
		}
	}
	if(NULL == pnode){
		return PLUGIN_NOT_FOUND;
	}
	plib = (PLUG_ENTITY*)(pnode->pdata);
	if (plib->ref_count > 0) {
		return PLUGIN_UNABLE_UNLOAD;
	}
	func = (PLUGIN_MAIN)plib->lib_main;
	if (plib->completed_init)
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
	double_list_remove(&g_list_plug, &plib->node);
	printf("[service]: unloading %s\n", plib->file_name);
	dlclose(plib->handle);
	free(plib);
	return PLUGIN_UNLOAD_OK;
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
	if (strncmp(g_cur_plug->file_name, "libgxs_", 7) == 0)
		return g_cur_plug->file_name + 7;
	return g_cur_plug->file_name;
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
static int service_get_context_num()
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
	PLUG_ENTITY *plug = g_cur_plug;
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
	HX_strlcpy(pservice->service_name, func_name, GX_ARRAY_SIZE(pservice->service_name));
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
			"ip_filter_judge", "ndr_stack_alloc"};
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
		HX_strlcpy(pmodule->module_name, module, GX_ARRAY_SIZE(pmodule->module_name));
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
	DOUBLE_LIST_NODE *pnode;
	PLUG_ENTITY *plib;

	for (pnode=double_list_get_head(&g_list_plug); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_plug, pnode)) {
		plib = (PLUG_ENTITY*)(pnode->pdata);
		if (0 == strncmp(plib->file_name, argv[0], 256)) {
			if (NULL != plib->talk_main) {
				plib->talk_main(argc, argv, reason, len);
				return PLUGIN_TALK_OK;
			} else {
				return PLUGIN_NO_TALK;
			}
		}
	}
	return PLUGIN_NO_FILE;
}
