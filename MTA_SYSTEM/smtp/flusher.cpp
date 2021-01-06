// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <stdbool.h>
#include <gromox/paths.h>
#include "flusher.h"
#include "service.h"
#include "single_list.h"
#include "resource.h"
#include "util.h"
#include <pthread.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FLUSHER_VERSION     0x00000001
#define MAX_CIRCLE_NUMBER   0x7FFFFFFF

typedef struct _FLUSH_ENTITY {
	STREAM           *pstream; 
	CONNECTION       *pconn;
	FLUSH_INFO       *pflusher;     /* the flusher for saving mail 
										information */
	ENVELOP_INFO     *penvelop;
	BOOL             is_spam;       /* whether the mail is spam */
	int              context_ID;
	SMTP_CONTEXT     *pcontext;     /* put at the last of the structure */
	SINGLE_LIST_NODE        node;
} FLUSH_ENTITY;

typedef void (*CANCEL_FUNCTION)(FLUSH_ENTITY*);

typedef struct _SERVICE_NODE{
	SINGLE_LIST_NODE		node;
	void			*service_addr;
	char			*service_name;
} SERVICE_NODE;

typedef struct _PLUG_ENTITY {
	void*           handle;
	PLUGIN_MAIN     appmain;
	CANCEL_FUNCTION flush_cancel;
	TALK_MAIN       console_talk;
	SINGLE_LIST			list_reference;
	char			file_name[256];
	char            path[256];
	bool completed_init;
} PLUG_ENTITY;

static BOOL flusher_load_plugin(char* path);
static BOOL flusher_unload_plugin(void);
static void* flusher_queryservice(const char *service);
static int flusher_get_queue_length(void);
static const char *flusher_get_host_ID(void);
static FLUSH_ENTITY *flusher_get_from_queue(void);
static BOOL flusher_feedback_entity(FLUSH_ENTITY *pentity);

static int flusher_get_extra_num(int context_ID);

static const char* flusher_get_extra_tag(int context_ID, int pos);

static const char* flusher_get_extra_value(int context_ID, int pos);

static BOOL flusher_register_cancel(CANCEL_FUNCTION cancel_func);
static BOOL flusher_register_talk(TALK_MAIN talk_main);
static const char *flusher_get_plugin_name(void);
static const char *flusher_get_config_path(void);
static const char *flusher_get_data_path(void);
static BOOL flusher_is_domainlist_valid(void);
static int flusher_increase_max_ID(void);
static BOOL flusher_set_flush_ID(int ID);
	
static PLUG_ENTITY *g_flusher_plug;
static LIB_BUFFER *g_allocator;
static BOOL g_can_register;
static size_t g_max_queue_len;
static pthread_mutex_t g_flush_mutex;
static pthread_mutex_t g_flush_id_mutex;
static SINGLE_LIST            g_flush_queue;
static unsigned int    g_current_ID;


void flusher_init(const char* path, size_t queue_len)
{
	g_flusher_plug = static_cast<PLUG_ENTITY *>(malloc(sizeof(PLUG_ENTITY)));
	if (NULL == g_flusher_plug) {
		return;
	}
	g_flusher_plug->appmain      = NULL;
	g_flusher_plug->handle       = NULL;
	g_flusher_plug->flush_cancel = NULL;
	g_flusher_plug->console_talk = NULL;
	strcpy(g_flusher_plug->path, path);
	auto pname = strrchr(path, '/');
	strcpy(g_flusher_plug->file_name, pname != NULL ? pname + 1 : path);
	single_list_init(&g_flusher_plug->list_reference);
	g_max_queue_len = queue_len;
}

/*
 *  flusher's destruct function
 */
void flusher_free()
{
	if (NULL != g_flusher_plug) {
		free(g_flusher_plug);
		g_flusher_plug = NULL;
	}
}

/*
 *  run the flusher object
 *  @return
 *       0  success
 *      <>0 fail
 */
int flusher_run()
{
	if (NULL == g_flusher_plug) {
		printf("[flusher]: Failed to allocate memory for FLUSHER\n");
		return -3;
	}
	g_allocator = lib_buffer_init(sizeof(FLUSH_ENTITY), 
		g_max_queue_len, TRUE);

	if (NULL == g_allocator) {
		printf("[flusher]: Failed to allocate FIFO memory\n");
		return -1;
	}
	single_list_init(&g_flush_queue);

	if (FALSE == flusher_load_plugin(g_flusher_plug->path)) {
		return -2;
	}
	
	if (g_current_ID < 0) {
		printf("[flusher]: flush ID error, should be larger than 0\n");
		return -4;
	}
	pthread_mutex_init(&g_flush_mutex, NULL);
	pthread_mutex_init(&g_flush_id_mutex, NULL);
	return 0;
}

/*
 *  stop the flusher object
 *  @return
 *       0  success
 *      <>0 fail
 */
int flusher_stop()
{

	pthread_mutex_destroy(&g_flush_mutex);
	pthread_mutex_destroy(&g_flush_id_mutex);
	single_list_free(&g_flush_queue);
	lib_buffer_free(g_allocator);
	if (TRUE == flusher_unload_plugin())
		return 0;
	return -1;
}

/*
 *  put the context into the flusher's queue
 *  @param
 *      pcontext    indicate the context object
 *  @return
 *      TRUE    OK to put
 *      FALSE   fail to put
 */
BOOL flusher_put_to_queue(SMTP_CONTEXT *pcontext)
{
	BOOL ret_val;

	auto pentity = static_cast<FLUSH_ENTITY *>(lib_buffer_get(g_allocator));
	if (pentity == nullptr)
		return FALSE;
	if (0 == pcontext->flusher.flush_ID) {
		pcontext->flusher.flush_ID = flusher_increase_max_ID();
	}
	
	pentity->is_spam        = pcontext->is_spam;
	pentity->pconn          = &pcontext->connection;
	pentity->penvelop       = &pcontext->mail.envelop;
	pentity->pflusher       = &pcontext->flusher;
	pentity->pstream        = &pcontext->stream;
	pentity->context_ID     = pcontext - smtp_parser_get_contexts_list();
	pentity->pcontext       = pcontext;
	pentity->node.pdata     = pentity;

	pthread_mutex_lock(&g_flush_mutex);
	ret_val = single_list_append_as_tail(&g_flush_queue, &pentity->node);
	pthread_mutex_unlock(&g_flush_mutex);
	return ret_val;
}

static FLUSH_ENTITY* flusher_get_from_queue()
{
	SINGLE_LIST_NODE*   pnode;
	pthread_mutex_lock(&g_flush_mutex);
	pnode = single_list_get_from_head(&g_flush_queue);
	pthread_mutex_unlock(&g_flush_mutex);
	if (NULL == pnode) {
		return NULL;
	}
	return (FLUSH_ENTITY*)pnode->pdata;
}

static BOOL flusher_feedback_entity(FLUSH_ENTITY *pentity)
{
	SMTP_CONTEXT *pcontext;
	pcontext = pentity->pcontext;
	lib_buffer_put(g_allocator, pentity->node.pdata);
	return contexts_pool_wakeup_context(
		(SCHEDULE_CONTEXT*)pcontext, CONTEXT_TURNING);
}

/*
 *  cancel a flushed mail parts
 *  @param
 *      pcontext [in]   indicate the context object
 */
void flusher_cancel(SMTP_CONTEXT *pcontext)
{
	FLUSH_ENTITY entity;

	if (NULL == g_flusher_plug->flush_cancel) {
		return;
	}   
	entity.is_spam      = pcontext->is_spam;
	entity.pconn        = &pcontext->connection;
	entity.penvelop     = &pcontext->mail.envelop;
	entity.pflusher     = &pcontext->flusher;
	entity.pstream      = &pcontext->stream;

	g_flusher_plug->flush_cancel(&entity);
}

static BOOL flusher_load_plugin(char* path)
{
	static void *const server_funcs[] = {reinterpret_cast<void *>(flusher_queryservice)};
	PLUGIN_MAIN appmain     = NULL;
	void    *phandle        = NULL;
	BOOL    main_result;
	
	if (NULL == (phandle = dlopen(path, RTLD_LAZY))) {
		printf("[flusher]: Failed to load flusher plugin %s: %s\n",
			 path, dlerror());
		return FALSE;
	}
	appmain = reinterpret_cast<decltype(appmain)>(dlsym(phandle, "FLH_LibMain"));
	if (NULL == appmain) {
		printf("[flusher]: fail to find FLH_LibMain in %s\n", path);
		dlclose(phandle);
		return FALSE;
	}

	g_flusher_plug->appmain = appmain;
	g_flusher_plug->handle  = phandle;
	g_can_register = TRUE;
	main_result = appmain(PLUGIN_INIT, const_cast<void **>(server_funcs));
	g_can_register = FALSE;
	if (FALSE == main_result) {
		printf("[flusher]: fail to execute init in flusher plugin\n");
		dlclose(phandle);
		g_flusher_plug->appmain = NULL;
		g_flusher_plug->handle = NULL;
		return FALSE;
	}
	g_flusher_plug->completed_init = true;
	return TRUE;
}


static BOOL flusher_unload_plugin()
{
	SINGLE_LIST_NODE *pnode;
	
	if (NULL == g_flusher_plug || NULL == g_flusher_plug->appmain) {
		return FALSE;
	}
	if (g_flusher_plug->completed_init && !g_flusher_plug->appmain(PLUGIN_FREE, NULL)) {
		printf("[flusher]: error executing Flusher_LibMain with "
			   "FLUSHER_LIB_FREE in plugin %s\n", g_flusher_plug->path);
		return FALSE;
	}
	printf("[flusher]: unloading %s\n", g_flusher_plug->path);
	dlclose(g_flusher_plug->handle);
	/* free the service reference of the plugin */
	if (0 != single_list_get_nodes_num(&g_flusher_plug->list_reference)) {
		for (pnode=single_list_get_head(&g_flusher_plug->list_reference); NULL!=pnode;
			 pnode=single_list_get_after(&g_flusher_plug->list_reference, pnode)) {
			service_release(((SERVICE_NODE*)(pnode->pdata))->service_name,
							g_flusher_plug->file_name);
		}
		/* free the reference list */
		while ((pnode = single_list_get_from_head(&g_flusher_plug->list_reference))) {
			free(((SERVICE_NODE*)(pnode->pdata))->service_name);
			free(pnode->pdata);
			pnode = NULL;
		}
	}
	return TRUE;
}

/*
 *  increase the g_current_ID by one, if it exceeds MAX_CIRCLE_NUMBER then
 *  reset it to 1
 *  @return
 *		the increased number
 */
static int flusher_increase_max_ID()
{
	int     current_id;
	pthread_mutex_lock(&g_flush_id_mutex);
	if (MAX_CIRCLE_NUMBER == g_current_ID) {
		g_current_ID = 1;
	} else {
		g_current_ID ++;
	}
	current_id  = g_current_ID;
	pthread_mutex_unlock(&g_flush_id_mutex);
	return current_id;
}

static BOOL flusher_set_flush_ID(int ID)
{
	if (TRUE == g_can_register) {
		g_current_ID = ID;
		return TRUE;
	} else {
		return FALSE;
	}
}

static void* flusher_queryservice(const char *service)
{
	void *ret_addr;
	SERVICE_NODE *pservice;
	SINGLE_LIST_NODE *pnode;
	
#define E(s, f) \
	do { \
		if (strcmp(service, (s)) == 0) \
			return reinterpret_cast<void *>(f); \
	} while (false)
	E("feedback_entity", flusher_feedback_entity);
	E("get_queue_length", flusher_get_queue_length);
	E("register_cancel", flusher_register_cancel);
	E("register_talk", flusher_register_talk);
	E("get_from_queue", flusher_get_from_queue);
	E("get_host_ID", flusher_get_host_ID);
	E("get_extra_num", flusher_get_extra_num);
	E("get_extra_tag", flusher_get_extra_tag);
	E("get_extra_value", flusher_get_extra_value);
	E("set_flush_ID", flusher_set_flush_ID);
	E("inc_flush_ID", flusher_increase_max_ID);
	E("get_plugin_name", flusher_get_plugin_name);
	E("get_config_path", flusher_get_config_path);
	E("get_data_path", flusher_get_data_path);
	E("is_domainlist_valid", flusher_is_domainlist_valid);
#undef E
	/* check if already exists in the reference list */
	for (pnode=single_list_get_head(&g_flusher_plug->list_reference); NULL!=pnode;
		 pnode=single_list_get_after(&g_flusher_plug->list_reference, pnode)) {
		pservice =  (SERVICE_NODE*)(pnode->pdata);
		if (0 == strcmp(service, pservice->service_name)) {
			return pservice->service_addr;
		}
	}
	ret_addr = service_query(service, g_flusher_plug->file_name);
	if (NULL == ret_addr) {
		return NULL;
	}
	pservice = static_cast<SERVICE_NODE *>(malloc(sizeof(SERVICE_NODE)));
	if (NULL == pservice) {
		debug_info("[flusher]: Failed to allocate memory for service node");
		service_release(service, g_flusher_plug->file_name);
		return NULL;
	}
	pservice->service_name = static_cast<char *>(malloc(strlen(service) + 1));
	if (NULL == pservice->service_name) {
		debug_info("[flusher]: Failed to allocate memory for service name");
		service_release(service, g_flusher_plug->file_name);
		free(pservice);
		return NULL;

	}
	strcpy(pservice->service_name, service);
	pservice->node.pdata = pservice;
	pservice->service_addr = ret_addr;
	single_list_append_as_tail(&g_flusher_plug->list_reference, &pservice->node);
	return ret_addr;
}

static int flusher_get_extra_num(int context_ID)
{
	SMTP_CONTEXT* pcontext;

	pcontext = smtp_parser_get_contexts_list();
	pcontext = pcontext + context_ID;
	return smtp_parser_get_extra_num(pcontext);
}
	
static const char* flusher_get_extra_tag(int context_ID, int pos)
{
	SMTP_CONTEXT* pcontext;

	pcontext = smtp_parser_get_contexts_list();
	pcontext = pcontext + context_ID;
	return smtp_parser_get_extra_tag(pcontext, pos);
}

static const char* flusher_get_extra_value(int context_ID, int pos)
{
	SMTP_CONTEXT* pcontext;

	pcontext = smtp_parser_get_contexts_list();
	pcontext = pcontext + context_ID;
	return smtp_parser_get_extra_value(pcontext, pos);
}

static const char *flusher_get_host_ID(void)
{
	return resource_get_string("HOST_ID");
}

static int flusher_get_queue_length()
{
	return g_max_queue_len;
}

void flusher_console_talk(int argc, char** argv, char* result, int len)
{
	if (NULL != g_flusher_plug->console_talk) {
		g_flusher_plug->console_talk(argc, argv, result, len);
	} else {
		sprintf(result, "550 not implement");
	}
}

static BOOL flusher_register_cancel(CANCEL_FUNCTION cancel_func)
{
	if (FALSE == g_can_register || NULL != g_flusher_plug->flush_cancel) {
		return FALSE;
	}
	g_flusher_plug->flush_cancel = cancel_func;
	return TRUE;
}

static BOOL flusher_register_talk(TALK_MAIN talk_main)
{
	if (FALSE == g_can_register || NULL != g_flusher_plug->console_talk) {
		return FALSE;
	}
	g_flusher_plug->console_talk = talk_main;
	return TRUE;
}

static const char* flusher_get_plugin_name()
{
	if (NULL == g_flusher_plug) {
		    return NULL;
	}
	if (strncmp(g_flusher_plug->file_name, "libmtaflh_", 10) == 0)
		return g_flusher_plug->file_name + 10;
	return g_flusher_plug->file_name;
}

static const char* flusher_get_config_path()
{
	const char *ret_value = resource_get_string("CONFIG_FILE_PATH");
	if (NULL == ret_value) {
		ret_value = PKGSYSCONFDIR;
	}
	return ret_value;

}

static const char* flusher_get_data_path()
{
	const char *ret_value = resource_get_string("DATA_FILE_PATH");
	if (NULL == ret_value) {
		ret_value = PKGDATASMTPDIR;
	}
	return ret_value;
}

static BOOL flusher_is_domainlist_valid()
{
	return smtp_parser_domainlist_valid();
}

