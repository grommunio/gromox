// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstring>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/paths.h>
#include "transporter.h"
#include "system_services.h"
#include "resource.h"
#include "service.h"
#include <gromox/plugin.hpp>
#include <gromox/single_list.hpp>
#include <gromox/double_list.hpp>
#include <gromox/util.hpp>
#include <sys/types.h>
#include <pthread.h>
#include <dlfcn.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#define FILENUM_PER_CONTROL		32
#define FILENUM_PER_MIME		32
#define MAX_THROWING_NUM		16
#define SCAN_INTERVAL			1
#define MAX_TIMES_NOT_SERVED	5
#define THREAD_STACK_SIZE       0x400000

struct CONTROL_INFO {
    int         queue_ID;
    int         bound_type;
	BOOL		is_spam;
    BOOL        need_bounce;
	char from[324];
    MEM_FILE    f_rcpt_to;
};

struct MESSAGE_CONTEXT {
    CONTROL_INFO *pcontrol;
    MAIL         *pmail;
};

typedef BOOL (*HOOK_FUNCTION)(MESSAGE_CONTEXT*);

struct PLUG_ENTITY {
    DOUBLE_LIST_NODE    node;
	DOUBLE_LIST			list_reference;
    DOUBLE_LIST         list_hook;
    void*               handle;
    PLUGIN_MAIN         lib_main;
    TALK_MAIN           talk_main;
    char                file_name[256];
    char                full_path[256];
	bool completed_init;
};

struct HOOK_ENTRY {
    DOUBLE_LIST_NODE    node_hook;
    DOUBLE_LIST_NODE    node_lib;
    HOOK_FUNCTION       hook_addr;
	PLUG_ENTITY *plib;
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
	CONTROL_INFO	mail_control;
    MAIL			mail;             /* mail object */
	MESSAGE_CONTEXT context;
};

struct FREE_CONTEXT {
	SINGLE_LIST_NODE	node;
	CONTROL_INFO		mail_control;
	MAIL				mail;
	MESSAGE_CONTEXT		context;
};

struct CIRCLE_NODE {
	DOUBLE_LIST_NODE	node;
	HOOK_FUNCTION		hook_addr;
};

struct ANTI_LOOP {
	DOUBLE_LIST		free_list;
	DOUBLE_LIST		throwed_list;
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

static char				g_path[256];
static const char *const *g_plugin_names;
static char				g_local_path[256];
static HOOK_FUNCTION	g_local_hook;
static int				g_threads_max;
static int				g_threads_min;
static int				g_mime_num;
static BOOL				g_notify_stop;
static BOOL             g_domainlist_valid;
static DOUBLE_LIST		g_threads_list;
static DOUBLE_LIST		g_free_threads;
static int				g_free_num;
static SINGLE_LIST		g_free_list;
static SINGLE_LIST		g_queue_list;
static DOUBLE_LIST		g_lib_list;
static DOUBLE_LIST		 g_hook_list;
static DOUBLE_LIST		 g_unloading_list;
static pthread_mutex_t	 g_free_threads_mutex;
static pthread_mutex_t	 g_threads_list_mutex;
static pthread_mutex_t	 g_context_lock;
static pthread_mutex_t	 g_queue_lock;
static pthread_key_t	 g_tls_key;
static pthread_t		 g_scan_id;
static LIB_BUFFER		 *g_file_allocator;
static MIME_POOL		 *g_mime_pool;
static THREAD_DATA		 *g_data_ptr;
static FREE_CONTEXT		 *g_free_ptr;
static PLUG_ENTITY		 *g_cur_lib;
static CIRCLE_NODE		 *g_circles_ptr;
static pthread_cond_t	 g_waken_cond;
static pthread_mutex_t	 g_cond_mutex;
static pthread_mutex_t	 g_mpc_list_lock;
static pthread_mutex_t	 g_count_lock;
static bool g_ign_loaderr;

static void transporter_collect_resource();
static void transporter_collect_hooks();
static void* thread_work_func(void* arg);

static void* scan_work_func(void* arg);
static void *transporter_queryservice(const char *service, const std::type_info &);
static BOOL transporter_register_hook(HOOK_FUNCTION func);
static BOOL transporter_register_local(HOOK_FUNCTION func);
static BOOL transporter_register_talk(TALK_MAIN talk);
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
static int transporter_get_threads_num();
static int transporter_get_context_num();
static MESSAGE_CONTEXT *transporter_get_context();
static void transporter_put_context(MESSAGE_CONTEXT *pcontext);

static BOOL transporter_throw_context(MESSAGE_CONTEXT *pcontext); 

static void transporter_enqueue_context(MESSAGE_CONTEXT *pcontext);
static MESSAGE_CONTEXT *transporter_dequeue_context();
static void transporter_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);

/*
 *	transporter's initial function
 *	@param
 *		path [in]				plug-ins path
 *		threads_num				threads number to be created
 *		free_num				free contexts number for hooks to throw out
 *		mime_ratio				how many mimes will be allocated per context
 */
void transporter_init(const char *path, const char *const *names,
    int threads_min, int threads_max, int free_num, int mime_radito,
    BOOL dm_valid, bool ignerr)
{
	HX_strlcpy(g_path, path, GX_ARRAY_SIZE(g_path));
	g_plugin_names = names;
	g_local_path[0] = '\0';
	g_notify_stop = FALSE;
	g_threads_min = threads_min;
	g_threads_max = threads_max;
	g_free_num = free_num;
	g_mime_num = mime_radito*(threads_max + free_num);
	g_domainlist_valid = dm_valid;
	g_ign_loaderr = ignerr;
	single_list_init(&g_free_list);
	pthread_mutex_init(&g_context_lock, NULL);
	pthread_mutex_init(&g_queue_lock, NULL);
	double_list_init(&g_hook_list);
	double_list_init(&g_lib_list);
	double_list_init(&g_unloading_list);
	pthread_key_create(&g_tls_key, NULL);
	pthread_cond_init(&g_waken_cond, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	double_list_init(&g_threads_list);
	double_list_init(&g_free_threads);
	pthread_mutex_init(&g_threads_list_mutex, NULL);
	pthread_mutex_init(&g_free_threads_mutex, NULL);
	pthread_mutex_init(&g_mpc_list_lock, NULL);
	pthread_mutex_init(&g_count_lock, NULL);
}

/*
 *	run the transport module
 *	@return
 *		0			OK
 *		<>0			fail
 */
int transporter_run()
{
	size_t size;
	int i, j;
	pthread_attr_t attr;
	FREE_CONTEXT *pcontext;
	ANTI_LOOP *panti;
	CIRCLE_NODE *pcircle;
	
	size = sizeof(CIRCLE_NODE)*g_threads_max*MAX_THROWING_NUM;
	g_circles_ptr = (CIRCLE_NODE*)malloc(size);
	if (NULL == g_circles_ptr) {
		printf("[transporter]: Failed to allocate memory for circle list\n");
        return -1;
	}
	memset(g_circles_ptr, 0, size);
	size = sizeof(THREAD_DATA)*g_threads_max;
	g_data_ptr = (THREAD_DATA*)malloc(size);
	if (NULL == g_data_ptr) {
		printf("[transporter]: Failed to allocate memory for threads data\n");
		transporter_collect_resource();
		return -2;
	}
	memset(g_data_ptr, 0, size);
	for (i=0; i<g_threads_max; i++) {
		(g_data_ptr + i)->node.pdata = g_data_ptr + i;
		panti = &(g_data_ptr + i)->anti_loop;
		double_list_init(&panti->free_list);
		double_list_init(&panti->throwed_list);
		for (j=0; j<MAX_THROWING_NUM; j++) {
			pcircle = g_circles_ptr + i*MAX_THROWING_NUM + j;
			pcircle->node.pdata = pcircle;
			double_list_append_as_tail(&panti->free_list, &pcircle->node);
		}
	}
	
	size = sizeof(FREE_CONTEXT)*g_free_num;
	g_free_ptr = (FREE_CONTEXT*)malloc(size);
	if (NULL == g_free_ptr) {
		transporter_collect_resource();
		printf("[transporter]: Failed to allocate memory for free list\n");
        return -3;
	}
	memset(g_free_ptr, 0, size);
	for (i=0; i<g_free_num; i++) {
		pcontext = g_free_ptr + i;
		pcontext->node.pdata = pcontext;
		single_list_append_as_tail(&g_free_list, &pcontext->node);
	}

	g_mime_pool = mime_pool_init(g_mime_num, FILENUM_PER_MIME, TRUE);
	if (NULL == g_mime_pool) {
		transporter_collect_resource();
		printf("[transporter]: Failed to init MIME pool\n");
        return -4;
	}
	g_file_allocator = lib_buffer_init(FILE_ALLOC_SIZE,
		FILENUM_PER_CONTROL*(g_free_num + g_threads_max), TRUE);
	if (NULL == g_file_allocator) {
        transporter_collect_resource();
		printf("[transporter]: Failed to init file allocator\n");
        return -5;
    }
	for (i=0; i<g_threads_max; i++) {
		mem_file_init(&(g_data_ptr + i)->fake_context.mail_control.f_rcpt_to,
			g_file_allocator);
		mail_init(&(g_data_ptr + i)->fake_context.mail, g_mime_pool);
		(g_data_ptr + i)->fake_context.context.pmail = 
				&(g_data_ptr + i)->fake_context.mail;
        (g_data_ptr + i)->fake_context.context.pcontrol =
				&(g_data_ptr + i)->fake_context.mail_control;
	}
	for (i=0; i<g_free_num; i++) {
		mem_file_init(&(g_free_ptr + i)->mail_control.f_rcpt_to,
            g_file_allocator);
		mail_init(&(g_free_ptr + i)->mail, g_mime_pool);
		(g_free_ptr + i)->context.pmail = &(g_free_ptr + i)->mail;
		(g_free_ptr + i)->context.pcontrol = &(g_free_ptr + i)->mail_control;
	}

	for (const char *const *i = g_plugin_names; *i != NULL; ++i) {
		int ret = transporter_load_library(*i);
		if (!g_ign_loaderr && ret != PLUGIN_LOAD_OK) {
			transporter_collect_hooks();
			transporter_collect_resource();
			return -7;
		}
	}

	if ('\0' == g_local_path[0]) {
		printf("[transporter]: there's no local hook registered in system\n");
		transporter_collect_hooks();
		transporter_collect_resource();
		return -8;
	}

	for (i=g_threads_min; i<g_threads_max; i++) {
		double_list_append_as_tail(&g_free_threads, &(g_data_ptr + i)->node);
	}
    for (i=0; i<g_threads_min; i++) {
		(g_data_ptr + i)->wait_on_event = TRUE;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
		int ret = pthread_create(&g_data_ptr[i].id, &attr, thread_work_func, g_data_ptr + i);
		if (ret != 0) {
			transporter_collect_hooks();
			transporter_collect_resource();
			printf("[transporter]: failed to create transport thread %d: %s\n",
			       i, strerror(ret));
			return -10;
        }
		char buf[32];
		snprintf(buf, sizeof(buf), "xprt/%u", i);
		pthread_setname_np(g_data_ptr[i].id, buf);
		pthread_attr_destroy(&attr);
		double_list_append_as_tail(&g_threads_list, &(g_data_ptr + i)->node);
    }
	/* create the scanning thread */
	pthread_attr_init(&attr);
	int ret = pthread_create(&g_scan_id, &attr, scan_work_func, nullptr);
	if (ret != 0) {
		g_notify_stop = TRUE;
		transporter_collect_hooks();
		transporter_collect_resource();
		printf("[transporter]: failed to create scanner thread: %s\n", strerror(ret));
		return -11;
	}
	pthread_setname_np(g_scan_id, "xprt/scan");
    pthread_attr_destroy(&attr);
	/* make all thread wake up */
	pthread_cond_broadcast(&g_waken_cond);
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
			stack.push_back(static_cast<PLUG_ENTITY *>(pnode->pdata)->file_name);
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
	if (NULL != g_file_allocator) {
		lib_buffer_free(g_file_allocator);
		g_file_allocator = NULL;
	}	
    if (NULL != g_mime_pool) {
        mime_pool_free(g_mime_pool);
        g_mime_pool = NULL;
    }
    if (NULL != g_data_ptr) {
        free(g_data_ptr);
        g_data_ptr = NULL;
    }
	if (NULL != g_free_ptr) {
		free(g_free_ptr);
		g_free_ptr = NULL;
	}
	if (NULL != g_circles_ptr) {
		free(g_circles_ptr);
		g_circles_ptr = NULL;
	}
}

/*
 *	stop the transporter module
 *	@return
 *		0				OK
 *		<>0				fail
 */
int transporter_stop()
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	THREAD_DATA *pthr;

	g_notify_stop = TRUE;
	pthread_mutex_lock(&g_threads_list_mutex);
	while ((pnode = double_list_pop_front(&g_threads_list)) != nullptr) {
		pthr = (THREAD_DATA*)pnode->pdata;
		pthread_cond_broadcast(&g_waken_cond);
        pthread_cancel(pthr->id);
	}
	pthread_mutex_unlock(&g_threads_list_mutex);
	pthread_cancel(g_scan_id);
	transporter_collect_hooks();
    for (i=0; i<g_threads_max; i++) {
        mail_free(&(g_data_ptr + i)->fake_context.mail);
    }
	for (i=0; i<g_free_num; i++) {
		mail_free(&(g_free_ptr + i)->mail);
	}
	transporter_collect_resource();
    return 0;
}

/*
 *	transporter's destruct function
 */
void transporter_free()
{
	g_path[0] = '\0';
	g_plugin_names = NULL;
	g_threads_min = 0;
	g_threads_max = 0;
	g_mime_num = 0;
	single_list_free(&g_free_list);
	pthread_mutex_destroy(&g_context_lock);
	pthread_mutex_destroy(&g_queue_lock);
	double_list_free(&g_hook_list);
	double_list_free(&g_lib_list);
	double_list_free(&g_unloading_list);
	pthread_key_delete(g_tls_key);
	pthread_cond_destroy(&g_waken_cond);
	pthread_mutex_destroy(&g_cond_mutex);
	double_list_free(&g_threads_list);
	double_list_free(&g_free_threads);
	pthread_mutex_destroy(&g_threads_list_mutex);
	pthread_mutex_destroy(&g_free_threads_mutex);
	pthread_mutex_destroy(&g_mpc_list_lock);
	pthread_mutex_destroy(&g_count_lock);
}

/*
 *	wake up one thread in threads pool
 */
void transporter_wakeup_one_thread()
{
	pthread_cond_signal(&g_waken_cond);
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
	pthread_mutex_lock(&g_mpc_list_lock);
	phead = double_list_get_head(&g_hook_list);
	ptail = double_list_get_tail(&g_hook_list);
	pthread_mutex_unlock(&g_mpc_list_lock);
	
	hook_result = FALSE;
	for (pnode=phead; NULL!=pnode;
		pnode=double_list_get_after(&g_hook_list, pnode)) {
		phook = (HOOK_ENTRY*)(pnode->pdata);
		/* check if this hook is valid, if it is, execute the function */
		if (TRUE == phook->valid) {
			if (pthr_data->last_thrower == phook->hook_addr) {
				goto NEXT_LOOP;
			}
			pthr_data->last_hook = phook->hook_addr;
			pthread_mutex_lock(&g_count_lock);
			phook->count ++;
			pthread_mutex_unlock(&g_count_lock);
			mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
				MEM_FILE_SEEK_BEGIN);
			hook_result = phook->hook_addr(pcontext);
			pthread_mutex_lock(&g_count_lock);
			phook->count --;
			pthread_mutex_unlock(&g_count_lock);
			if (TRUE == hook_result) {
				break;
			}
		}
 NEXT_LOOP:
		if (pnode == ptail) {
			break;
		}
	}
	if (FALSE == hook_result) {
		if (pthr_data->last_thrower != g_local_hook) {
			mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
				MEM_FILE_SEEK_BEGIN);
			pthr_data->last_hook = g_local_hook;
			if (TRUE == g_local_hook(pcontext)) {
				return TRUE;	
			}
		}
		return FALSE;
	} else {
		return TRUE;
	}
}

/*
 *    thread's work function of transporter
 *    @param
 *        arg [in]    argument passed by thread creator
 */
static void* thread_work_func(void* arg)
{
	char *ptr;
	int len, cannot_served_times;
	BOOL b_self, pass_result;
	THREAD_DATA *pthr_data;
	MESSAGE *pmessage;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTEXT *pcontext;
	PLUG_ENTITY *plib;
	
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthr_data = (THREAD_DATA*)arg;
	pthread_setspecific(g_tls_key, (const void*) pthr_data);
	for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
		pnode=double_list_get_after(&g_lib_list, pnode)) {
		plib = (PLUG_ENTITY*)(pnode->pdata);
		((PLUGIN_MAIN)plib->lib_main)(PLUGIN_THREAD_CREATE, NULL);
	}
	cannot_served_times = 0;
	if (TRUE == pthr_data->wait_on_event) {
		pthread_mutex_lock(&g_cond_mutex);
		pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
		pthread_mutex_unlock(&g_cond_mutex);
	}
	
	while (TRUE != g_notify_stop) {
		pmessage = message_dequeue_get();
		if (NULL == pmessage) {
			pcontext = transporter_dequeue_context();	
			if (NULL == pcontext) {
				cannot_served_times ++;
				if (cannot_served_times < MAX_TIMES_NOT_SERVED) {
					sleep(1);
				/* decrease threads pool */
				} else {
					pthread_mutex_lock(&g_threads_list_mutex);
					if (double_list_get_nodes_num(&g_threads_list) >
						g_threads_min) {
						double_list_remove(&g_threads_list, &pthr_data->node);
						pthread_mutex_unlock(&g_threads_list_mutex);
						for (pnode=double_list_get_head(&g_lib_list);
							NULL!=pnode;
							pnode=double_list_get_after(&g_lib_list, pnode)) {
							plib = (PLUG_ENTITY*)(pnode->pdata);
							((PLUGIN_MAIN)plib->lib_main)(PLUGIN_THREAD_DESTROY,
														  NULL);
						}
						pthread_mutex_lock(&g_free_threads_mutex);
						double_list_append_as_tail(&g_free_threads,
							&pthr_data->node);
						pthread_mutex_unlock(&g_free_threads_mutex);
						pthread_detach(pthread_self());
						return nullptr;
					}
					pthread_mutex_unlock(&g_threads_list_mutex);
					pthread_mutex_lock(&g_cond_mutex);
					pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
					pthread_mutex_unlock(&g_cond_mutex);
				}
				continue;
			}
			cannot_served_times = 0;
			b_self = TRUE;
		} else {
			cannot_served_times = 0;
			pcontext = &pthr_data->fake_context.context;
			if (!mail_retrieve(pcontext->pmail,
			    static_cast<char *>(pmessage->mail_begin),
			    pmessage->mail_length)) {
				system_services_log_info(6, "QID %d: Failed to "
					"load into mail object", pmessage->flush_ID);
				message_dequeue_save(pmessage);
				message_dequeue_put(pmessage);
				continue;
			}	
			pcontext->pcontrol->queue_ID = pmessage->flush_ID;
			pcontext->pcontrol->bound_type = pmessage->bound_type;
			pcontext->pcontrol->is_spam = pmessage->is_spam;
			pcontext->pcontrol->need_bounce = TRUE;
			HX_strlcpy(pcontext->pcontrol->from, pmessage->envelop_from, GX_ARRAY_SIZE(pcontext->pcontrol->from));
			ptr = pmessage->envelop_rcpt;
			while ((len = strlen(ptr)) != 0) {
				len ++;
				mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, ptr);
				ptr += len;
			}
			b_self = FALSE;
		}
		pthr_data->last_hook = NULL;
		pthr_data->last_thrower = NULL;
		pass_result = transporter_pass_mpc_hooks(pcontext, pthr_data);
		if (FALSE == pass_result) {
			transporter_log_info(pcontext, 6, "Message cannot be processed by "
				"any hook registered in MPC");
			if (FALSE == b_self) {
				message_dequeue_save(pmessage);
			}
		}
		if (FALSE == b_self) {
			mem_file_clear(&pcontext->pcontrol->f_rcpt_to);
			mail_clear(pcontext->pmail);
			message_dequeue_put(pmessage);
		} else {
			transporter_put_context(pcontext);
		}
	}
	for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
		pnode=double_list_get_after(&g_lib_list, pnode)) {
		plib = (PLUG_ENTITY*)(pnode->pdata);
		((PLUGIN_MAIN)plib->lib_main)(PLUGIN_THREAD_DESTROY, NULL);
	}
	return NULL;
}


/*
 *    thread's work function of scanner
 *    @param
 *        arg [in]    argument passed by thread creator
 */
static void* scan_work_func(void* arg)
{
	THREAD_DATA *pthr_data;
	DOUBLE_LIST_NODE *pnode;
	pthread_attr_t attr;
	
	while (FALSE == g_notify_stop) {
		sleep(SCAN_INTERVAL);
		if (0 != message_dequeue_get_param(MESSAGE_DEQUEUE_HOLDING)) {
			pthread_mutex_lock(&g_threads_list_mutex);
			if (g_threads_max==double_list_get_nodes_num(&g_threads_list)) {
				pthread_mutex_unlock(&g_threads_list_mutex);
				continue;
			}
			pthread_mutex_unlock(&g_threads_list_mutex);
			/* get a thread data node from free list */
			pthread_mutex_lock(&g_free_threads_mutex);
			pnode = double_list_pop_front(&g_free_threads);
			pthread_mutex_unlock(&g_free_threads_mutex);
			if (NULL == pnode) {
				continue;
			}
			pthr_data = (THREAD_DATA*)pnode->pdata;
			pthread_attr_init(&attr);
			pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
			if (0 == pthread_create(&pthr_data->id, &attr, thread_work_func,
				pthr_data)) {
				pthread_setname_np(pthr_data->id, "xprt/+");
				pthread_mutex_lock(&g_threads_list_mutex);
				double_list_append_as_tail(&g_threads_list, &pthr_data->node);
				pthread_mutex_unlock(&g_threads_list_mutex);
			} else {
				pthread_mutex_lock(&g_free_threads_mutex);
				double_list_append_as_tail(&g_free_threads, &pthr_data->node);
				pthread_mutex_unlock(&g_free_threads_mutex);
			}
			pthread_attr_destroy(&attr);
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
	static void *const server_funcs[] = {(void *)transporter_queryservice};
	const char *fake_path = path;
    DOUBLE_LIST_NODE *pnode;
    PLUGIN_MAIN func;
    PLUG_ENTITY *plib;

	transporter_clean_up_unloading();
	/* check whether the plugin is same as local or remote plugin */
	if (strcmp(path, g_local_path) == 0) {
		printf("[transporter]: %s is already loaded in module\n", path);
		return PLUGIN_ALREADY_LOADED;
	}
	
    /* check whether the library is in unloading list */
    for (pnode=double_list_get_head(&g_unloading_list); NULL!=pnode;
         pnode=double_list_get_after(&g_unloading_list, pnode)) {
		if (strcmp(static_cast<PLUG_ENTITY *>(pnode->pdata)->file_name, path) == 0) {
			printf("[transporter]: %s is already loaded in module\n", path);
			return PLUGIN_ALREADY_LOADED;
		}
	}
    /* check whether the library is already loaded */
    for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
         pnode=double_list_get_after(&g_lib_list, pnode)) {
		if (strcmp(static_cast<PLUG_ENTITY *>(pnode->pdata)->file_name, path) == 0) {
			printf("[transporter]: %s is already loaded in module\n", path);
			return PLUGIN_ALREADY_LOADED;
		}
	}
	void *handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL && strchr(path, '/') == NULL) {
		char altpath[256];
		snprintf(altpath, sizeof(altpath), "%s/%s", g_path, path);
		handle = dlopen(altpath, RTLD_LAZY);
	}
    if (NULL == handle){
        printf("[transporter]: error loading %s: %s\n", fake_path, dlerror());
        printf("[transporter]: the plugin %s is not loaded\n", fake_path);
        return PLUGIN_FAIL_OPEN;
    }
    func = (PLUGIN_MAIN)dlsym(handle, "HOOK_LibMain");
    if (NULL == func) {
        printf("[transporter]: error finding the HOOK_LibMain function in %s\n",
                fake_path);
        printf("[transporter]: the plugin %s is not loaded\n", fake_path);
        dlclose(handle);
        return PLUGIN_NO_MAIN;
    }
    plib = (PLUG_ENTITY*)malloc(sizeof(PLUG_ENTITY));
    if (NULL == plib) {
		printf("[transporter]: Failed to allocate memory for %s\n", fake_path);
        printf("[transporter]: the plugin %s is not loaded\n", fake_path);
        dlclose(handle);
        return PLUGIN_FAIL_ALLOCNODE;
    }
    memset(plib, 0, sizeof(PLUG_ENTITY));
    /* make the node's pdata ponter point to the SHARELIB struct */
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
		printf("[transporter]: error executing the plugin's init function "
                "in %s\n", fake_path);
        printf("[transporter]: the plugin %s is not loaded\n", fake_path);
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
    PLUG_ENTITY *plib;

	auto ptr = strrchr(path, '/');
    if (NULL != ptr) {
        ptr++;
    } else {
        ptr = (char*)path;
    }
    /* first find the plugin node in lib list */
    for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
         pnode=double_list_get_after(&g_lib_list, pnode)){
        if (0 == strcmp(((PLUG_ENTITY*)(pnode->pdata))->file_name, ptr)) {
            break;
        }
    }
    if (NULL == pnode){
        return PLUGIN_NOT_FOUND;
    }
    plib = (PLUG_ENTITY*)(pnode->pdata);
    func = (PLUGIN_MAIN)plib->lib_main;
	if (plib->completed_init)
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
    PLUG_ENTITY *plib;
	HOOK_ENTRY *phook;
	BOOL can_clean;
	std::vector<DOUBLE_LIST_NODE *> stack;

	for (pnode=double_list_get_head(&g_unloading_list); NULL!=pnode;
		pnode=double_list_get_after(&g_unloading_list, pnode)) {
		plib = (PLUG_ENTITY*)pnode->pdata;
		can_clean = TRUE;
		for (pnode1=double_list_get_head(&plib->list_hook); NULL!=pnode1;
			pnode1=double_list_get_after(&plib->list_hook, pnode1)) {
			phook = (HOOK_ENTRY*)(pnode1->pdata);
			if (0 != phook->count) {
				can_clean = FALSE;
			}
		}
		if (TRUE == can_clean) {
			try {
				stack.push_back(pnode);
			} catch (...) {
			}
			/* empty the list_hook of plib */
			while ((pnode1 = double_list_pop_front(&plib->list_hook)) != nullptr)
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
			printf("[transporter]: unloading %s\n", plib->file_name);
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
	E("register_talk", transporter_register_talk);
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
	E("is_domainlist_valid", transporter_domainlist_valid);
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
    pservice = (SERVICE_NODE*)malloc(sizeof(SERVICE_NODE));
    if (NULL == pservice) {
		debug_info("[transporter]: Failed to allocate memory for service node");
        service_release(service, g_cur_lib->file_name);
        return NULL;
    }
    pservice->service_name = (char*)malloc(strlen(service) + 1);
    if (NULL == pservice->service_name) {
		debug_info("[transporter]: Failed to allocate memory for service name");
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
	SINGLE_LIST_NODE *pnode;
	MESSAGE_CONTEXT *pcontext;

	pthread_mutex_lock(&g_context_lock);
	pnode = single_list_pop_front(&g_free_list);	
	pthread_mutex_unlock(&g_context_lock);
	if (NULL == pnode) {
		return NULL;
	}
	pcontext = &((FREE_CONTEXT*)(pnode->pdata))->context;
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
	SINGLE_LIST_NODE *pnode;

	/* reset the context object */
	mem_file_clear(&pcontext->pcontrol->f_rcpt_to);
	pcontext->pcontrol->queue_ID = 0;
	pcontext->pcontrol->is_spam = FALSE;
	pcontext->pcontrol->bound_type = BOUND_UNKNOWN;
	pcontext->pcontrol->need_bounce = FALSE;
	pcontext->pcontrol->from[0] = '\0';
	mail_clear(pcontext->pmail);	
	pnode = (SINGLE_LIST_NODE*)((char*)pcontext -
				(long)(&((FREE_CONTEXT*)0)->context));
	pthread_mutex_lock(&g_context_lock);
    single_list_append_as_tail(&g_free_list, pnode);
    pthread_mutex_unlock(&g_context_lock);
}

/*
 *	put the context into context queue
 *	@param
 *		pcontext [in]		context pointer
 */
static void transporter_enqueue_context(MESSAGE_CONTEXT *pcontext)
{
	SINGLE_LIST_NODE *pnode;

	if ((char*)pcontext < (char*)g_free_ptr ||
		(char*)pcontext > (char*)(g_free_ptr + g_free_num)) {
		printf("[transporter]: invalid context pointer is detected when some "
				"plugin try to enqueue message context\n");
		return;
	}
	pnode = (SINGLE_LIST_NODE*)((char*)pcontext -
				(long)(&((FREE_CONTEXT*)0)->context));
	pthread_mutex_lock(&g_queue_lock);
    single_list_append_as_tail(&g_queue_list, pnode);
    pthread_mutex_unlock(&g_queue_lock);
	/* wake up one thread */
	pthread_cond_signal(&g_waken_cond);
}

/*
 *  get a context from context queue
 *  @return
 *		poiter to context, NULL means none
 */
static MESSAGE_CONTEXT* transporter_dequeue_context()
{
	SINGLE_LIST_NODE *pnode;

	pthread_mutex_lock(&g_queue_lock);
	pnode = single_list_pop_front(&g_queue_list);	
	pthread_mutex_unlock(&g_queue_lock);
	if (NULL == pnode) {
		return NULL;
	}
	return &((FREE_CONTEXT*)(pnode->pdata))->context;
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
	THREAD_DATA *pthr_data;
	DOUBLE_LIST_NODE *pnode;
	CIRCLE_NODE *pcircle;
	HOOK_FUNCTION last_thrower, last_hook;

	if ((char*)pcontext < (char*)g_free_ptr ||
		(char*)pcontext > (char*)(g_free_ptr + g_free_num)) {
		printf("[transporter]: invalid context pointer is detected when some "
				"plugin try to throw message context\n");
		return FALSE;
	}
	pthr_data = (THREAD_DATA*)pthread_getspecific(g_tls_key);
	if (NULL == pthr_data) {
		transporter_put_context(pcontext);
		return FALSE;
	}	
	/* check if this hook is throwing the second message */
	for (pnode=double_list_get_head(&pthr_data->anti_loop.throwed_list);
		NULL!=pnode; pnode=double_list_get_after(
		&pthr_data->anti_loop.throwed_list, pnode)) {
		if (((CIRCLE_NODE*)(pnode->pdata))->hook_addr ==
			pthr_data->last_hook) {
			break;
		}
	}
	if (NULL != pnode) {
		printf("[transporter]: message infinite loop is detected\n");
		transporter_put_context(pcontext);
		return FALSE;
	}
	/* append this hook into throwed list */
	pcircle = reinterpret_cast<CIRCLE_NODE *>(double_list_pop_front(&pthr_data->anti_loop.free_list));
	if (NULL == pcircle) {
		printf("[transporter]: exceed the maximum depth that one thread "
			"can throw\n");
		double_list_insert_as_head(&pthr_data->anti_loop.free_list, &pcircle->node);
		transporter_put_context(pcontext);
        return FALSE;
	}
	/* save the last hook and last thrower, like function's call operation */
	last_hook = pthr_data->last_hook;
	last_thrower = pthr_data->last_thrower;
	pcircle->hook_addr = pthr_data->last_hook;
	pthr_data->last_thrower = pthr_data->last_hook;
	double_list_append_as_tail(&pthr_data->anti_loop.throwed_list,
		&pcircle->node);
	pass_result = transporter_pass_mpc_hooks(pcontext, pthr_data);
	if (FALSE == pass_result) {
		ret_val = FALSE;
		transporter_log_info(pcontext, 6, "Message cannot be processed by any "
			"hook registered in MPC");
	} else {
		ret_val = TRUE;
	}
	pnode = double_list_pop_back(&pthr_data->anti_loop.throwed_list);
	double_list_append_as_tail(&pthr_data->anti_loop.free_list, pnode);
	transporter_put_context(pcontext);
	/* recover last thrower and last hook, like function's return operation */
	pthr_data->last_hook = last_hook;
	pthr_data->last_thrower = last_thrower;
    return ret_val;
}

/*
 *	register a hook into mpc
 *	@param
 *		func [in]		function address
 *	@return
 *		TRUE			OK to register
 *		FALSE			fail
 */
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
        if (TRUE == phook->valid && phook->hook_addr == func) {
            break;
        }
    }
    if (NULL != pnode) {
        return FALSE;
    }
    /* check if there's empty hook in the list */
	found_hook = FALSE;
    for (pnode=double_list_get_head(&g_hook_list); NULL!=pnode;
		pnode=double_list_get_after(&g_hook_list, pnode)) {
		phook = (HOOK_ENTRY*)(pnode->pdata);
		if (FALSE == phook->valid && 0 == phook->count) {
			found_hook = TRUE;
			break;
        }
    }
	if (FALSE == found_hook) {
		phook = (HOOK_ENTRY*)malloc(sizeof(HOOK_ENTRY));
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
	if (FALSE == found_hook) {
    	/* aquire write lock when to modify the hooks list */
		pthread_mutex_lock(&g_mpc_list_lock);
    	double_list_append_as_tail(&g_hook_list, &phook->node_hook);
		pthread_mutex_unlock(&g_mpc_list_lock);
    	/* append also the hook into lib's hook list */
	}
	/* validate the hook node */
	phook->valid = TRUE;
    return TRUE;
}

/*
 *	register the local delivery hook
 *	@param
 *		func [in]			function address
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static BOOL transporter_register_local(HOOK_FUNCTION func)
{
	if (g_local_path[0] != '\0') {
		return FALSE;
	}
	/* do not need read aquire write lock */
	g_local_hook = func;
	strcpy(g_local_path, g_cur_lib->file_name);
	return TRUE;
}

/*
 *	register a console talk function
 *	@param
 *		talk [in]			talk function
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
static BOOL transporter_register_talk(TALK_MAIN talk)
{
    if(NULL == g_cur_lib) {
        return FALSE;
    }
    g_cur_lib->talk_main = talk;
    return TRUE;
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

/*
 *	get the config files path
 *	@return
 *		path string
 */
static const char* transporter_get_config_path()
{
	const char *ret_value  = resource_get_string("CONFIG_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGSYSCONFDIR "/delivery:" PKGSYSCONFDIR;
    }
    return ret_value;
}

/*
 *	get the data files path
 *	@return
 *		path string
 */
static const char* transporter_get_data_path()
{
	const char *ret_value = resource_get_string("DATA_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGDATADIR "/delivery:" PKGDATADIR;
    }
    return ret_value;
}

/*
 *	get context number of system
 *	@return
 *		context number
 */
static int transporter_get_context_num()
{
    return g_threads_max + g_free_num;
}

/*
 *	get threads number of mpc
 *	@return
 *		threads number
 */
static int transporter_get_threads_num()
{
	return g_threads_max;
}

/*
 *	get the plugin name
 *	@return
 *		NULL		fail
 *		plugin name string
 */
static const char* transporter_get_plugin_name()
{
	if (NULL == g_cur_lib) {
		return NULL;
    }
	if (strncmp(g_cur_lib->file_name, "libgxm_", 7) == 0)
		return g_cur_lib->file_name + 7;
    return g_cur_lib->file_name;
}

/*
 *	get the queue path
 *	@return
 *		NULL		fail
 *		queue path string
 */
static const char* transporter_get_queue_path()
{
	return resource_get_string("DEQUEUE_PATH");
}

/*
 *	console talk function for each plugin
 *	@param
 *		argc					arguments number
 *		argv [in]				arguments array
 *		result [out]			result buffer for caller
 *		length					result buffer length
 *	@return
 *		PLUGIN_TALK_OK
 *		PLUGIN_NO_TALK
 *		PLUGIN_NO_FILE
 */
int transporter_console_talk(int argc, char** argv, char *result, int length)
{
    DOUBLE_LIST_NODE *pnode;
    PLUG_ENTITY *plib;

    for (pnode=double_list_get_head(&g_lib_list); NULL!=pnode;
         pnode=double_list_get_after(&g_lib_list, pnode)) {
        plib = (PLUG_ENTITY*)(pnode->pdata);
        if (0 == strncmp(plib->file_name, argv[0], 256)) {
            if (NULL != plib->talk_main) {
                plib->talk_main(argc, argv, result, length);
                return PLUGIN_TALK_OK;
            } else {
                return PLUGIN_NO_TALK;
            }
        }
    }
    return PLUGIN_NO_FILE;
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
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
				  MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
					rcpt_buff + rcpt_len, 256);
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
		system_services_log_info(level, "UNKNOWN message FROM: %s, "
			"TO: %s %s", pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	case BOUND_IN:
	case BOUND_OUT:
	case BOUND_RELAY:
		system_services_log_info(level, "SMTP message queue-ID: %d, FROM: %s, "
			"TO: %s %s", pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
			rcpt_buff, log_buf);
		break;
	default:
		system_services_log_info(level, "APP created message FROM: %s, "
			"TO: %s %s", pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	}
}

int transporter_get_param(int param)
{
	switch (param) {
	case TRANSPORTER_MIN_THREADS:
		return g_threads_min;
	case TRANSPORTER_MAX_THREADS:
		return g_threads_max;
	case TRANSPORTER_CREATED_THREADS:
		return double_list_get_nodes_num(&g_threads_list); 
	}
	return 0;
}

void transporter_validate_domainlist(BOOL b_valid)
{
	g_domainlist_valid = b_valid;
}

BOOL transporter_domainlist_valid()
{
	return g_domainlist_valid;
}
