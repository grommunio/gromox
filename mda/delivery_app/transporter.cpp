// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <condition_variable>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <pthread.h>
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
#include <gromox/mime_pool.hpp>
#include <gromox/paths.h>
#include <gromox/plugin.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "delivery.hpp"
#define FILENUM_PER_CONTROL		32
#define FILENUM_PER_MIME		32
#define MAX_THROWING_NUM		16
#define SCAN_INTERVAL			1
#define MAX_TIMES_NOT_SERVED	5
#define THREAD_STACK_SIZE       0x400000

using namespace gromox;

namespace {

struct HOOK_PLUG_ENTITY {
    DOUBLE_LIST_NODE    node;
	DOUBLE_LIST			list_reference;
    DOUBLE_LIST         list_hook;
    void*               handle;
    PLUGIN_MAIN         lib_main;
    char                file_name[256];
    char                full_path[256];
	bool completed_init;
};

struct HOOK_ENTRY {
    DOUBLE_LIST_NODE    node_hook;
    DOUBLE_LIST_NODE    node_lib;
    HOOK_FUNCTION       hook_addr;
	HOOK_PLUG_ENTITY *plib;
	int					count;
	BOOL				valid;
};

/* structure for describing service reference */
struct SERVICE_NODE {
    DOUBLE_LIST_NODE    node;
    void                *service_addr;
    char                *service_name;
};

struct FIXED_CONTEXT {
	CONTROL_INFO mail_control{};
	MAIL mail{};
	MESSAGE_CONTEXT context{};
};

struct FREE_CONTEXT {
	CONTROL_INFO mail_control{};
	MAIL mail{};
	MESSAGE_CONTEXT context{};
};

struct CIRCLE_NODE {
	DOUBLE_LIST_NODE node{};
	HOOK_FUNCTION hook_addr = nullptr;
};

struct ANTI_LOOP {
	ANTI_LOOP();
	DOUBLE_LIST free_list{}, thrown_list{};
};

struct THREAD_DATA {
	DOUBLE_LIST_NODE	node;
	pthread_t			id;
	BOOL				wait_on_event;
	FIXED_CONTEXT		fake_context;
	ANTI_LOOP			anti_loop;
	HOOK_FUNCTION		last_hook;
	HOOK_FUNCTION		last_thrower;
};

}

static char				g_path[256];
static std::vector<std::string> g_plugin_names;
static char g_local_path[256], g_remote_path[256];
static HOOK_FUNCTION g_local_hook, g_remote_hook;
static unsigned int g_threads_max, g_threads_min, g_mime_num, g_free_num;
static gromox::atomic_bool g_notify_stop;
static DOUBLE_LIST		g_threads_list;
static DOUBLE_LIST		g_free_threads;
static std::vector<FREE_CONTEXT *> g_free_list, g_queue_list;
static DOUBLE_LIST		g_lib_list;
static DOUBLE_LIST		 g_hook_list;
static DOUBLE_LIST		 g_unloading_list;
static std::mutex g_free_threads_mutex, g_threads_list_mutex, g_context_lock;
static std::mutex g_queue_lock, g_cond_mutex, g_mpc_list_lock, g_count_lock;
static std::condition_variable g_waken_cond;
static thread_local THREAD_DATA *g_tls_key;
static pthread_t		 g_scan_id;
static alloc_limiter<file_block> g_file_allocator("g_file_allocator.d");
static std::shared_ptr<MIME_POOL> g_mime_pool;
static std::unique_ptr<THREAD_DATA[]> g_data_ptr;
static std::unique_ptr<FREE_CONTEXT[]> g_free_ptr;
static HOOK_PLUG_ENTITY *g_cur_lib;
static std::unique_ptr<CIRCLE_NODE[]> g_circles_ptr;

static void transporter_collect_resource();
static void transporter_collect_hooks();
static void *dxp_thrwork(void *);
static void *dxp_scanwork(void *);
static void *transporter_queryservice(const char *service, const std::type_info &);
static BOOL transporter_register_hook(HOOK_FUNCTION func);
static BOOL transporter_register_local(HOOK_FUNCTION func);
static bool transporter_register_remote(HOOK_FUNCTION);
static BOOL transporter_pass_mpc_hooks(MESSAGE_CONTEXT *pcontext,
	THREAD_DATA *pthr_data); 
static void transporter_clean_up_unloading();
static const char *transporter_get_plugin_name();
static const char *transporter_get_host_ID();
static const char *transporter_get_default_domain();
static const char *transporter_get_admin_mailbox();
static const char *transporter_get_config_path();
static const char *transporter_get_data_path();
static const char *transporter_get_queue_path();
static unsigned int transporter_get_threads_num();
static unsigned int transporter_get_context_num();
static MESSAGE_CONTEXT *transporter_get_context();
static void transporter_put_context(MESSAGE_CONTEXT *pcontext);

static BOOL transporter_throw_context(MESSAGE_CONTEXT *pcontext); 

static void transporter_enqueue_context(MESSAGE_CONTEXT *pcontext);
static MESSAGE_CONTEXT *transporter_dequeue_context();
static void transporter_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);

ANTI_LOOP::ANTI_LOOP()
{
	double_list_init(&free_list);
	double_list_init(&thrown_list);
}

/*
 *	transporter's initial function
 *	@param
 *		path [in]				plug-ins path
 *		threads_num				threads number to be created
 *		free_num				free contexts number for hooks to throw out
 *		mime_ratio				how many mimes will be allocated per context
 */
void transporter_init(const char *path, std::vector<std::string> &&names,
    unsigned int threads_min, unsigned int threads_max, unsigned int free_num,
    unsigned int mime_ratio, bool ignerr)
{
	gx_strlcpy(g_path, path, GX_ARRAY_SIZE(g_path));
	g_plugin_names = std::move(names);
	g_local_path[0] = '\0';
	*g_remote_path = '\0';
	g_notify_stop = false;
	g_threads_min = threads_min;
	g_threads_max = threads_max;
	g_free_num = free_num;
	g_mime_num = mime_ratio * (threads_max + free_num);
	/* Preallocate so this won't throw down the road */
	g_free_list.reserve(free_num);
	g_queue_list.reserve(free_num);
	double_list_init(&g_hook_list);
	double_list_init(&g_lib_list);
	double_list_init(&g_unloading_list);
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
		g_circles_ptr = std::make_unique<CIRCLE_NODE[]>(g_threads_max * MAX_THROWING_NUM);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "transporter: failed to allocate memory for circle list");
        return -1;
	}
	try {
		g_data_ptr = std::make_unique<THREAD_DATA[]>(g_threads_max);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "transporter: failed to allocate memory for threads data");
		transporter_collect_resource();
		return -2;
	}
	for (size_t i = 0; i < g_threads_max; ++i) {
		g_data_ptr[i].node.pdata = &g_data_ptr[i];
		auto panti = &g_data_ptr[i].anti_loop;
		for (size_t j = 0; j < MAX_THROWING_NUM; ++j) {
			auto pcircle = &g_circles_ptr[i*MAX_THROWING_NUM+j];
			pcircle->node.pdata = pcircle;
			double_list_append_as_tail(&panti->free_list, &pcircle->node);
		}
	}

	try {
		g_free_ptr = std::make_unique<FREE_CONTEXT[]>(g_free_num);
	} catch (const std::bad_alloc &) {
		transporter_collect_resource();
		mlog(LV_ERR, "transporter: failed to allocate memory for free list");
        return -3;
	}
	for (size_t i = 0; i < g_free_num; ++i) {
		g_free_list.push_back(&g_free_ptr[i]);
	}

	g_mime_pool = MIME_POOL::create(g_mime_num, FILENUM_PER_MIME, "transporter_mime_pool");
	if (NULL == g_mime_pool) {
		transporter_collect_resource();
		mlog(LV_ERR, "transporter: failed to init MIME pool");
        return -4;
	}
	g_file_allocator = alloc_limiter<file_block>(FILENUM_PER_CONTROL * (g_free_num + g_threads_max),
	                   "transporter_file_alloc", "delivery.cfg:threads_num,free_contexts");
	for (unsigned int i = 0; i < g_threads_max; ++i) {
		mem_file_init(&g_data_ptr[i].fake_context.mail_control.f_rcpt_to, &g_file_allocator);
		g_data_ptr[i].fake_context.mail = MAIL(g_mime_pool);
		g_data_ptr[i].fake_context.context.pmail = &g_data_ptr[i].fake_context.mail;
		g_data_ptr[i].fake_context.context.pcontrol = &g_data_ptr[i].fake_context.mail_control;
	}
	for (size_t i = 0; i < g_free_num; ++i) {
		mem_file_init(&g_free_ptr[i].mail_control.f_rcpt_to, &g_file_allocator);
		g_free_ptr[i].mail = MAIL(g_mime_pool);
		g_free_ptr[i].context.pmail = &g_free_ptr[i].mail;
		g_free_ptr[i].context.pcontrol = &g_free_ptr[i].mail_control;
	}

	for (const auto &i : g_plugin_names) {
		int ret = transporter_load_library(i.c_str());
		if (ret != PLUGIN_LOAD_OK) {
			transporter_collect_hooks();
			transporter_collect_resource();
			return -7;
		}
	}

	if ('\0' == g_local_path[0]) {
		mlog(LV_ERR, "transporter: no local delivery hook registered");
		transporter_collect_hooks();
		transporter_collect_resource();
		return -8;
	} else if (*g_remote_path == '\0') {
		mlog(LV_ERR, "transporter: no remote delivery hook registered");
		transporter_collect_hooks();
		transporter_collect_resource();
		return -1;
	}

	for (unsigned int i = g_threads_min; i < g_threads_max; ++i)
		double_list_append_as_tail(&g_free_threads, &g_data_ptr[i].node);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	auto cl_0 = make_scope_exit([&]() { pthread_attr_destroy(&attr); });
	auto ret = pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
	if (ret != 0) {
		mlog(LV_ERR, "transporter: pthread_attr_setstacksize: %s", strerror(ret));
		return -1;
	}

	for (size_t i = 0; i < g_threads_min; ++i) {
		g_data_ptr[i].wait_on_event = TRUE;
		auto ret = pthread_create(&g_data_ptr[i].id, &attr, dxp_thrwork, &g_data_ptr[i]);
		if (ret != 0) {
			transporter_collect_hooks();
			transporter_collect_resource();
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
	ret = pthread_create(&g_scan_id, nullptr, dxp_scanwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		transporter_collect_hooks();
		transporter_collect_resource();
		mlog(LV_ERR, "transporter: failed to create scanner thread: %s", strerror(ret));
		return -11;
	}
	pthread_setname_np(g_scan_id, "xprt/scan");
	/* make all thread wake up */
	g_waken_cond.notify_all();
	return 0;
}

/*
 *	unload all registered hooks, including local hook and remote hook
 */
static void transporter_collect_hooks()
{
	std::vector<std::string> stack;
	DOUBLE_LIST_NODE *pnode;

    for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
         pnode=double_list_get_after(&g_lib_list, pnode)) {
		try {
			stack.push_back(static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata)->file_name);
		} catch (...) {
		}
    }
	while (!stack.empty()) {
		transporter_unload_library(stack.back().c_str());
		stack.pop_back();
    }
	transporter_clean_up_unloading();
	while ((pnode = double_list_pop_front(&g_hook_list)) != nullptr)
		free(pnode->pdata);
}

/*
 *	collect allocated resource in transporter_run
 */
static void transporter_collect_resource()
{
	g_mime_pool.reset();
	g_data_ptr.reset();
	g_free_ptr.reset();
	g_circles_ptr.reset();
}

void transporter_stop()
{
	DOUBLE_LIST_NODE *pnode;
	THREAD_DATA *pthr;

	g_notify_stop = true;
	std::unique_lock tl_hold(g_threads_list_mutex);
	g_waken_cond.notify_all();
	while ((pnode = double_list_pop_front(&g_threads_list)) != nullptr) {
		pthr = (THREAD_DATA*)pnode->pdata;
		auto id = pthr->id;
		pthread_kill(id, SIGALRM);
		pthread_join(id, nullptr);
	}
	tl_hold.unlock();
	if (!pthread_equal(g_scan_id, {})) {
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, nullptr);
	}
	transporter_collect_hooks();
	transporter_collect_resource();
	g_path[0] = '\0';
	g_threads_min = 0;
	g_threads_max = 0;
	g_mime_num = 0;
	double_list_free(&g_hook_list);
	double_list_free(&g_lib_list);
	double_list_free(&g_unloading_list);
	double_list_free(&g_threads_list);
	double_list_free(&g_free_threads);
}

void transporter_wakeup_one_thread()
{
	g_waken_cond.notify_one();
}

/*
 *	make the hooks in mpc process the message context
 *	@param
 *		pcontext [in]			message context pointer
 *		pthr_data [in]			TLS data pointer
 */
static BOOL transporter_pass_mpc_hooks(MESSAGE_CONTEXT *pcontext,
	THREAD_DATA *pthr_data)
{
	DOUBLE_LIST_NODE *pnode, *phead, *ptail;
	HOOK_ENTRY *phook;
	BOOL hook_result;
	
	/*
	 *	first get the head and tail of list, this will be thread safe because 
	 *	the list is growing list, all new nodes will be appended at tail
	 */
	std::unique_lock ml_hold(g_mpc_list_lock);
	phead = double_list_get_head(&g_hook_list);
	ptail = double_list_get_tail(&g_hook_list);
	ml_hold.unlock();
	
	hook_result = FALSE;
	for (pnode=phead; NULL!=pnode;
		pnode=double_list_get_after(&g_hook_list, pnode)) {
		phook = (HOOK_ENTRY*)(pnode->pdata);
		/* check if this hook is valid, if it is, execute the function */
		if (phook->valid) {
			if (pthr_data->last_thrower == phook->hook_addr) {
				goto NEXT_LOOP;
			}
			pthr_data->last_hook = phook->hook_addr;
			std::unique_lock ct_hold(g_count_lock);
			phook->count ++;
			ct_hold.unlock();
			pcontext->pcontrol->f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			hook_result = phook->hook_addr(pcontext);
			ct_hold.lock();
			phook->count --;
			ct_hold.unlock();
			if (hook_result)
				break;
		}
 NEXT_LOOP:
		if (pnode == ptail) {
			break;
		}
	}
	if (hook_result)
		return TRUE;
	if (pthr_data->last_thrower != g_local_hook) {
		pcontext->pcontrol->f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		pthr_data->last_hook = g_local_hook;
		if (g_local_hook(pcontext))
			return TRUE;
	}
	if (pthr_data->last_thrower != g_remote_hook) {
		pcontext->pcontrol->f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		pthr_data->last_hook = g_remote_hook;
		if (g_remote_hook(pcontext))
			return TRUE;
	}
	return FALSE;
}

static void *dxp_thrwork(void *arg)
{
	char *ptr;
	int len, cannot_served_times;
	BOOL b_self, pass_result;
	THREAD_DATA *pthr_data;
	MESSAGE *pmessage;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTEXT *pcontext;
	
	pthr_data = (THREAD_DATA*)arg;
	g_tls_key = pthr_data;
	for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
		pnode=double_list_get_after(&g_lib_list, pnode)) {
		auto plib = static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata);
		((PLUGIN_MAIN)plib->lib_main)(PLUGIN_THREAD_CREATE, NULL);
	}
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
						for (pnode=double_list_get_head(&g_lib_list);
							NULL!=pnode;
							pnode=double_list_get_after(&g_lib_list, pnode)) {
							auto plib = static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata);
							((PLUGIN_MAIN)plib->lib_main)(PLUGIN_THREAD_DESTROY,
														  NULL);
						}
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
			b_self = TRUE;
		} else {
			cannot_served_times = 0;
			pcontext = &pthr_data->fake_context.context;
			if (!pcontext->pmail->retrieve(static_cast<char *>(pmessage->mail_begin), pmessage->mail_length)) {
				mlog(LV_ERR, "QID %d: Failed to "
					"load into mail object", pmessage->flush_ID);
				message_dequeue_save(pmessage);
				message_dequeue_put(pmessage);
				continue;
			}	
			pcontext->pcontrol->queue_ID = pmessage->flush_ID;
			pcontext->pcontrol->bound_type = pmessage->bound_type;
			pcontext->pcontrol->is_spam = pmessage->is_spam;
			pcontext->pcontrol->need_bounce = TRUE;
			gx_strlcpy(pcontext->pcontrol->from, pmessage->envelope_from, arsizeof(pcontext->pcontrol->from));
			ptr = pmessage->envelope_rcpt;
			while ((len = strlen(ptr)) != 0) {
				len ++;
				pcontext->pcontrol->f_rcpt_to.writeline(ptr);
				ptr += len;
			}
			b_self = FALSE;
		}
		pthr_data->last_hook = NULL;
		pthr_data->last_thrower = NULL;
		pass_result = transporter_pass_mpc_hooks(pcontext, pthr_data);
		if (!pass_result) {
			transporter_log_info(pcontext, LV_DEBUG, "Message cannot be processed by "
				"any hook registered in MPC");
			if (!b_self)
				message_dequeue_save(pmessage);
		}
		if (!b_self) {
			pcontext->pcontrol->f_rcpt_to.clear();
			pcontext->pmail->clear();
			message_dequeue_put(pmessage);
		} else {
			transporter_put_context(pcontext);
		}
	}
	for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
		pnode=double_list_get_after(&g_lib_list, pnode)) {
		auto plib = static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata);
		((PLUGIN_MAIN)plib->lib_main)(PLUGIN_THREAD_DESTROY, NULL);
	}
	return NULL;
}

static void *dxp_scanwork(void *arg)
{
	THREAD_DATA *pthr_data;
	DOUBLE_LIST_NODE *pnode;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	auto cl_0 = make_scope_exit([&]() { pthread_attr_destroy(&attr); });
	auto ret = pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
	if (ret != 0) {
		mlog(LV_ERR, "transporter: pthread_attr_setstacksize: %s", strerror(ret));
		return nullptr;
	}

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
		pthr_data = (THREAD_DATA *)pnode->pdata;
		auto ret = pthread_create(&pthr_data->id, &attr, dxp_thrwork, pthr_data);
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
int transporter_load_library(const char* path)
{
	static void *const server_funcs[] = {reinterpret_cast<void *>(transporter_queryservice)};
	const char *fake_path = path;
    DOUBLE_LIST_NODE *pnode;
    PLUGIN_MAIN func;

	transporter_clean_up_unloading();
	/* check whether the plugin is same as local or remote plugin */
	if (strcmp(path, g_local_path) == 0 || strcmp(path, g_remote_path) == 0) {
		mlog(LV_ERR, "transporter: %s is already loaded", path);
		return PLUGIN_ALREADY_LOADED;
	}
	
    /* check whether the library is in unloading list */
    for (pnode=double_list_get_head(&g_unloading_list); NULL!=pnode;
         pnode=double_list_get_after(&g_unloading_list, pnode)) {
		if (strcmp(static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata)->file_name, path) == 0) {
			mlog(LV_ERR, "transporter: %s is already loaded", path);
			return PLUGIN_ALREADY_LOADED;
		}
	}
    /* check whether the library is already loaded */
    for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
         pnode=double_list_get_after(&g_lib_list, pnode)) {
		if (strcmp(static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata)->file_name, path) == 0) {
			mlog(LV_ERR, "transporter: %s is already loaded", path);
			return PLUGIN_ALREADY_LOADED;
		}
	}
	void *handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL && strchr(path, '/') == NULL) try {
		auto altpath = std::string(g_path) + "/" + path;
		handle = dlopen(altpath.c_str(), RTLD_LAZY);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1473: ENOMEM");
		return PLUGIN_FAIL_OPEN;
	}
    if (NULL == handle){
		mlog(LV_ERR, "transporter: error loading %s: %s", fake_path, dlerror());
        return PLUGIN_FAIL_OPEN;
    }
    func = (PLUGIN_MAIN)dlsym(handle, "HOOK_LibMain");
    if (NULL == func) {
		mlog(LV_ERR, "transporter: error finding the HOOK_LibMain function in %s", fake_path);
        dlclose(handle);
        return PLUGIN_NO_MAIN;
    }
	auto plib = me_alloc<HOOK_PLUG_ENTITY>();
    if (NULL == plib) {
		mlog(LV_ERR, "transporter: Failed to allocate memory for %s", fake_path);
        dlclose(handle);
        return PLUGIN_FAIL_ALLOCNODE;
    }
	memset(plib, 0, sizeof(*plib));
    /* make the node's pdata pointer point to the SHARELIB struct */
    plib->node.pdata = plib;
    double_list_init(&plib->list_reference);
    double_list_init(&plib->list_hook);
	strncpy(plib->file_name, path, 255);
    strncpy(plib->full_path, fake_path, 255);
    plib->handle = handle;
    plib->lib_main = func;
    /* append the plib node into lib list */
    double_list_append_as_tail(&g_lib_list, &plib->node);
    g_cur_lib = plib;
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!func(PLUGIN_INIT, const_cast<void **>(server_funcs))) {
		mlog(LV_ERR, "transporter: error executing the plugin's init function "
                "in %s", fake_path);
        /*
         *  the lib node will automatically removed from libs list in
         *  transporter_unload_library function
         */
        transporter_unload_library(fake_path);
		g_cur_lib = NULL;
		return PLUGIN_FAIL_EXECUTEMAIN;
    }
	plib->completed_init = true;
    g_cur_lib = NULL;
    return PLUGIN_LOAD_OK;
}

/*
 *	unload the hook plugin
 *	@param
 *		path [in]					hook plugin name
 *	@return
 *		PLUGIN_NOT_FOUND			cannot find plugin
 *		PLUGIN_UNLOAD_OK			OK
 */
int transporter_unload_library(const char* path)
{
    DOUBLE_LIST_NODE *pnode;
    PLUGIN_MAIN func;

	auto ptr = strrchr(path, '/');
    if (NULL != ptr) {
        ptr++;
    } else {
        ptr = (char*)path;
    }
    /* first find the plugin node in lib list */
    for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
         pnode=double_list_get_after(&g_lib_list, pnode)){
		if (strcmp(static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata)->file_name, ptr) == 0)
            break;
    }
    if (NULL == pnode){
        return PLUGIN_NOT_FOUND;
    }
	auto plib = static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata);
    func = (PLUGIN_MAIN)plib->lib_main;
	if (func != nullptr && plib->completed_init)
		/* notify the plugin that it willbe unloaded */
		func(PLUGIN_FREE, NULL);

	if (0 != double_list_get_nodes_num(&plib->list_hook)) {
        for (pnode=double_list_get_head(&plib->list_hook); NULL!=pnode;
             pnode=double_list_get_after(&plib->list_hook, pnode)) {
			/* invalidate the hook */
            ((HOOK_ENTRY*)(pnode->pdata))->valid = FALSE;
        }
	}
    double_list_remove(&g_lib_list, &plib->node);
	double_list_append_as_tail(&g_unloading_list, &plib->node);
	return PLUGIN_UNLOAD_OK;
}

static void transporter_clean_up_unloading()
{
	DOUBLE_LIST_NODE *pnode, *pnode1;
	HOOK_ENTRY *phook;
	BOOL can_clean;
	std::vector<DOUBLE_LIST_NODE *> stack;

	for (pnode=double_list_get_head(&g_unloading_list); NULL!=pnode;
		pnode=double_list_get_after(&g_unloading_list, pnode)) {
		auto plib = static_cast<HOOK_PLUG_ENTITY *>(pnode->pdata);
		can_clean = TRUE;
		for (pnode1=double_list_get_head(&plib->list_hook); NULL!=pnode1;
			pnode1=double_list_get_after(&plib->list_hook, pnode1)) {
			phook = (HOOK_ENTRY*)(pnode1->pdata);
			if (0 != phook->count) {
				can_clean = FALSE;
			}
		}
		if (can_clean) {
			try {
				stack.push_back(pnode);
			} catch (...) {
			}
			/* empty the list_hook of plib */
			while (double_list_pop_front(&plib->list_hook) != nullptr)
				/* nothing */;
			double_list_free(&plib->list_hook);
			/* free the service reference of the plugin */
			for (pnode1=double_list_get_head(&plib->list_reference); NULL!=pnode1;
				pnode1=double_list_get_after(&plib->list_reference, pnode1)) {
				service_release(((SERVICE_NODE*)(pnode1->pdata))->service_name,
					plib->file_name);
			}
			/* free the reference list */
			while ((pnode1 = double_list_pop_front(&plib->list_reference)) != nullptr) {
				free(((SERVICE_NODE*)(pnode1->pdata))->service_name);
				free(pnode1->pdata);
			}
			mlog(LV_INFO, "transporter: unloading %s", plib->file_name);
			dlclose(plib->handle);
		}
	}
	while (!stack.empty()) {
		double_list_remove(&g_unloading_list, stack.back());
		stack.pop_back();
	}
}

static const char *transporter_get_state_path()
{
	return resource_get_string("STATE_PATH");
}
/*
 *	get services
 *	@param
 *		service [in]			service name
 *	@return
 *		service pointer
 */
static void *transporter_queryservice(const char *service, const std::type_info &ti)
{
	DOUBLE_LIST_NODE *pnode;
    SERVICE_NODE *pservice;
    void *ret_addr;

    if (NULL == g_cur_lib) {
        return NULL;
    }
#define E(s, f) \
	do { \
		if (strcmp(service, (s)) == 0) \
			return reinterpret_cast<void *>(f); \
	} while (false)
	E("register_hook", transporter_register_hook);
	E("register_local", transporter_register_local);
	E("register_remote", transporter_register_remote);
	E("get_host_ID", transporter_get_host_ID);
	E("get_default_domain", transporter_get_default_domain);
	E("get_admin_mailbox", transporter_get_admin_mailbox);
	E("get_plugin_name", transporter_get_plugin_name);
	E("get_config_path", transporter_get_config_path);
	E("get_data_path", transporter_get_data_path);
	E("get_state_path", transporter_get_state_path);
	E("get_queue_path", transporter_get_queue_path);
	E("get_threads_num", transporter_get_threads_num);
	E("get_context_num", transporter_get_context_num);
	E("get_context", transporter_get_context);
	E("put_context", transporter_put_context);
	E("enqueue_context", transporter_enqueue_context);
	E("throw_context", transporter_throw_context);
#undef E
	/* check if already exists in the reference list */
    for (pnode=double_list_get_head(&g_cur_lib->list_reference); NULL!=pnode;
         pnode=double_list_get_after(&g_cur_lib->list_reference, pnode)) {
        pservice =  (SERVICE_NODE*)(pnode->pdata);
        if (0 == strcmp(service, pservice->service_name)) {
            return pservice->service_addr;
        }
    }
	ret_addr = service_query(service, g_cur_lib->file_name, ti);
    if (NULL == ret_addr) {
        return NULL;
    }
	pservice = me_alloc<SERVICE_NODE>();
    if (NULL == pservice) {
		mlog(LV_DEBUG, "transporter: Failed to allocate memory for service node");
        service_release(service, g_cur_lib->file_name);
        return NULL;
    }
	pservice->service_name = me_alloc<char>(strlen(service) + 1);
    if (NULL == pservice->service_name) {
		mlog(LV_DEBUG, "transporter: Failed to allocate memory for service name");
        service_release(service, g_cur_lib->file_name);
        free(pservice);
        return NULL;
    }
    strcpy(pservice->service_name, service);
    pservice->node.pdata = pservice;
    pservice->service_addr = ret_addr;
	double_list_append_as_tail(&g_cur_lib->list_reference, &pservice->node);
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
	auto pcontext = &free_ctx->context;
	pcontext->pcontrol->bound_type = BOUND_SELF;
	return pcontext;
}

/*
 *	put the context back into free list
 *	@param
 *		pcontext [in]		context pointer
 */
static void transporter_put_context(MESSAGE_CONTEXT *pcontext)
{
	/* reset the context object */
	pcontext->pcontrol->f_rcpt_to.clear();
	pcontext->pcontrol->queue_ID = 0;
	pcontext->pcontrol->is_spam = FALSE;
	pcontext->pcontrol->bound_type = BOUND_UNKNOWN;
	pcontext->pcontrol->need_bounce = FALSE;
	pcontext->pcontrol->from[0] = '\0';
	pcontext->pmail->clear();
	auto free_ctx = containerof(pcontext, FREE_CONTEXT, context);
	std::lock_guard ctx_hold(g_context_lock);
	g_free_list.push_back(free_ctx);
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
	auto free_ctx = containerof(pcontext, FREE_CONTEXT, context);
	std::unique_lock q_hold(g_queue_lock);
	g_queue_list.push_back(free_ctx); /* reserved, so should not throw */
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
	return &free_ctx->context;
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
	BOOL ret_val, pass_result;
	DOUBLE_LIST_NODE *pnode;
	CIRCLE_NODE *pcircle;
	HOOK_FUNCTION last_thrower, last_hook;

	if (reinterpret_cast<uintptr_t>(pcontext) < reinterpret_cast<uintptr_t>(g_free_ptr.get()) ||
	    reinterpret_cast<uintptr_t>(pcontext) > reinterpret_cast<uintptr_t>(g_free_ptr.get() + g_free_num)) {
		mlog(LV_ERR, "transporter: invalid context pointer is detected when some "
				"plugin try to throw message context");
		return FALSE;
	}
	auto pthr_data = g_tls_key;
	if (NULL == pthr_data) {
		transporter_put_context(pcontext);
		return FALSE;
	}	
	/* check if this hook is throwing the second message */
	for (pnode=double_list_get_head(&pthr_data->anti_loop.thrown_list);
		NULL!=pnode; pnode=double_list_get_after(
		&pthr_data->anti_loop.thrown_list, pnode)) {
		if (((CIRCLE_NODE*)(pnode->pdata))->hook_addr ==
			pthr_data->last_hook) {
			break;
		}
	}
	if (NULL != pnode) {
		mlog(LV_ERR, "transporter: message infinite loop is detected");
		transporter_put_context(pcontext);
		return FALSE;
	}
	/* append this hook into thrown list */
	pcircle = reinterpret_cast<CIRCLE_NODE *>(double_list_pop_front(&pthr_data->anti_loop.free_list));
	if (NULL == pcircle) {
		mlog(LV_ERR, "transporter: exceed the maximum depth that one thread "
			"can throw");
		transporter_put_context(pcontext);
        return FALSE;
	}
	/* save the last hook and last thrower, like function's call operation */
	last_hook = pthr_data->last_hook;
	last_thrower = pthr_data->last_thrower;
	pcircle->hook_addr = pthr_data->last_hook;
	pthr_data->last_thrower = pthr_data->last_hook;
	double_list_append_as_tail(&pthr_data->anti_loop.thrown_list,
		&pcircle->node);
	pass_result = transporter_pass_mpc_hooks(pcontext, pthr_data);
	if (!pass_result) {
		ret_val = FALSE;
		transporter_log_info(pcontext, LV_DEBUG, "Message cannot be processed by any "
			"hook registered in MPC");
	} else {
		ret_val = TRUE;
	}
	pnode = double_list_pop_back(&pthr_data->anti_loop.thrown_list);
	double_list_append_as_tail(&pthr_data->anti_loop.free_list, pnode);
	transporter_put_context(pcontext);
	/* recover last thrower and last hook, like function's return operation */
	pthr_data->last_hook = last_hook;
	pthr_data->last_thrower = last_thrower;
    return ret_val;
}

static BOOL transporter_register_hook(HOOK_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
   	HOOK_ENTRY *phook;
	BOOL found_hook;

    if (NULL == func) {
        return FALSE;
    }
    /*check if register hook is invoked only in HOOK_LibMain(PLUGIN_INIT,..)*/
    if (NULL == g_cur_lib) {
        return FALSE;
    }

    /* check if the hook is already registered in hook list */
    for (pnode=double_list_get_head(&g_hook_list); NULL!=pnode;
        pnode=double_list_get_after(&g_hook_list, pnode)) {
		phook = (HOOK_ENTRY*)(pnode->pdata);
		if (phook->valid && phook->hook_addr == func)
			break;
    }
    if (NULL != pnode) {
        return FALSE;
    }
    /* check if there's empty hook in the list */
	found_hook = FALSE;
    for (pnode=double_list_get_head(&g_hook_list); NULL!=pnode;
		pnode=double_list_get_after(&g_hook_list, pnode)) {
		phook = (HOOK_ENTRY*)(pnode->pdata);
		if (!phook->valid && phook->count == 0) {
			found_hook = TRUE;
			break;
        }
    }
	if (!found_hook) {
		phook = me_alloc<HOOK_ENTRY>();
		phook->node_hook.pdata = phook;
		phook->node_lib.pdata = phook;
		phook->count = 0;
		phook->valid = FALSE;
	}
    if (NULL == phook) {
        return FALSE;
    }
    phook->plib = g_cur_lib;
	phook->hook_addr = func;
    double_list_append_as_tail(&g_cur_lib->list_hook, &phook->node_lib);
	if (!found_hook) {
    	/* acquire write lock when to modify the hooks list */
		std::lock_guard ml_hold(g_mpc_list_lock);
    	double_list_append_as_tail(&g_hook_list, &phook->node_hook);
    	/* append also the hook into lib's hook list */
	}
	/* validate the hook node */
	phook->valid = TRUE;
    return TRUE;
}

static BOOL transporter_register_local(HOOK_FUNCTION func)
{
	if (g_local_path[0] != '\0') {
		return FALSE;
	}
	/* do not need read acquire write lock */
	g_local_hook = func;
	strcpy(g_local_path, g_cur_lib->file_name);
	return TRUE;
}

static bool transporter_register_remote(HOOK_FUNCTION func)
{
	if (*g_remote_path != '\0')
		return false;
	g_remote_hook = func;
	gx_strlcpy(g_remote_path, g_cur_lib->file_name, arsizeof(g_remote_path));
	return true;
}

static const char* transporter_get_host_ID()
{
	return resource_get_string("HOST_ID");
}

static const char* transporter_get_default_domain()
{
	return resource_get_string("DEFAULT_DOMAIN");
}

static const char* transporter_get_admin_mailbox()
{
	return resource_get_string("ADMIN_MAILBOX");
}

static const char* transporter_get_config_path()
{
	const char *ret_value  = resource_get_string("CONFIG_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGSYSCONFDIR "/delivery:" PKGSYSCONFDIR;
    }
    return ret_value;
}

static const char* transporter_get_data_path()
{
	const char *ret_value = resource_get_string("DATA_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGDATADIR "/delivery:" PKGDATADIR;
    }
    return ret_value;
}

static unsigned int transporter_get_context_num()
{
    return g_threads_max + g_free_num;
}

static unsigned int transporter_get_threads_num()
{
	return g_threads_max;
}

static const char* transporter_get_plugin_name()
{
	if (NULL == g_cur_lib) {
		return NULL;
    }
	if (strncmp(g_cur_lib->file_name, "libgxm_", 7) == 0)
		return g_cur_lib->file_name + 7;
    return g_cur_lib->file_name;
}

static const char* transporter_get_queue_path()
{
	return resource_get_string("DEQUEUE_PATH");
}

static void transporter_log_info(MESSAGE_CONTEXT *pcontext, int level,
    const char *format, ...)
{
	char log_buf[2048], rcpt_buff[2048];
	size_t size_read = 0, rcpt_len = 0, i;
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	/* maximum record 8 rcpt to address */
	pcontext->pcontrol->f_rcpt_to.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = pcontext->pcontrol->f_rcpt_to.readline(rcpt_buff + rcpt_len, 256);
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		rcpt_len += size_read;
		rcpt_buff[rcpt_len] = ' ';
		rcpt_len ++;
	}
	rcpt_buff[rcpt_len] = '\0';

	switch (pcontext->pcontrol->bound_type) {
	case BOUND_UNKNOWN:
		mlog(level, "UNKNOWN message FROM: %s, "
			"TO: %s %s", pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	case BOUND_IN:
	case BOUND_OUT:
	case BOUND_RELAY:
		mlog(level, "SMTP message queue-ID: %d, FROM: %s, "
			"TO: %s %s", pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
			rcpt_buff, log_buf);
		break;
	default:
		mlog(level, "APP created message FROM: %s, "
			"TO: %s %s", pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	}
}
