#include "hpm_processor.h"
#include "pdu_processor.h"
#include "http_parser.h"
#include "resource.h"
#include "service.h"
#include "vstack.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>

#define SERVICE_VERSION							0x00000001

enum {
	RESP_FAIL,
	RESP_PARTIAL,
	RESP_PENDING,
	RESP_FINAL
};

/* structure for describing service reference */
typedef struct _SERVICE_NODE{
	DOUBLE_LIST_NODE node;
	void *service_addr;
	char *service_name;
} SERVICE_NODE;

typedef struct _HPM_CONTEXT {
	HPM_INTERFACE *pinterface;
	BOOL b_preproc;
	BOOL b_chunked;
	uint32_t chunk_size;
	uint32_t chunk_offset; 
	uint64_t content_length;
	BOOL b_end;
	int cache_fd;
	uint64_t cache_size;
} HPM_CONTEXT;

typedef struct _HTTP_AUTH_INFO {
	BOOL b_authed;
	const char* username;
	const char* password;
	const char* maildir;
	const char* lang;
} HTTP_AUTH_INFO;

static int g_context_num;
static uint64_t g_max_size;
static uint64_t g_cache_size;
static char g_plugins_path[256];
static HPM_PLUGIN *g_cur_plugin;
static DOUBLE_LIST g_plugin_list;
static HPM_CONTEXT *g_context_list;

void hpm_processor_init(int context_num, const char *plugins_path,
	uint64_t cache_size, uint64_t max_size)
{
	g_context_num = context_num;
	double_list_init(&g_plugin_list);
	strcpy(g_plugins_path, plugins_path);
	g_cache_size = cache_size;
	g_max_size = max_size;
}


static BOOL hpm_processor_register_interface(
	HPM_INTERFACE *pinterface)
{
	if (NULL == pinterface->preproc) {
		printf("[hpm_processor]: preproc of interface in %s "
				"cannot be NULL\n", g_cur_plugin->file_name);
		return FALSE;
	}
	if (NULL == pinterface->proc) {
		printf("[hpm_processor]: proc of interface in %s"
			" cannot be NULL\n", g_cur_plugin->file_name);
		return FALSE;
	}
	if (NULL == pinterface->retr) {
		printf("[hpm_processor]: retr of interface in %s"
			" cannot be NULL\n", g_cur_plugin->file_name);
		return FALSE;
	}
	if (NULL != g_cur_plugin->interface.preproc ||
		NULL != g_cur_plugin->interface.proc ||
		NULL != g_cur_plugin->interface.retr) {
		printf("[hpm_processor]: interface has been already"
				" registered in %s", g_cur_plugin->file_name);
		return FALSE;
	}
	memcpy(&g_cur_plugin->interface, pinterface, sizeof(HPM_INTERFACE));
	return TRUE;
}

static BOOL hpm_processor_register_talk(TALK_MAIN talk)
{
    if(NULL == g_cur_plugin) {
        return FALSE;
    }
    g_cur_plugin->talk_main = talk;
    return TRUE;
}

static BOOL hpm_processor_unregister_talk(TALK_MAIN talk)
{
	HPM_PLUGIN *pplugin;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		pplugin = (HPM_PLUGIN*)(pnode->pdata);
		if (pplugin->talk_main == talk) {
			pplugin->talk_main = NULL;
			return TRUE;
		}
	}
	return FALSE;
}

static const char *hpm_processor_get_host_ID()
{
	return resource_get_string(RES_HOST_ID);
}

static const char* hpm_processor_get_default_domain()
{
	return resource_get_string(RES_DEFAULT_DOMAIN);
}

static const char* hpm_processor_get_plugin_name()
{
	if (NULL == g_cur_plugin) {
		return NULL;
	}
	return g_cur_plugin->file_name;
}

static const char* hpm_processor_get_config_path()
{
    const char *ret_value;

    ret_value = resource_get_string(RES_CONFIG_FILE_PATH);
    if (NULL == ret_value) {
        ret_value = "../config";
    }
    return ret_value;
}

static const char* hpm_processor_get_data_path()
{
    const char *ret_value;

    ret_value = resource_get_string(RES_DATA_FILE_PATH);
    if (NULL == ret_value) {
        ret_value = "../data";
    }
    return ret_value;
}

static int hpm_processor_get_context_num()
{
	return g_context_num;
}

static CONNECTION* hpm_processor_get_connection(int context_id)
{
	HTTP_CONTEXT *phttp;
	
	phttp = http_parser_get_contexts_list() + context_id;
	return &phttp->connection;
}

static HTTP_REQUEST* hpm_processor_get_request(int context_id)
{
	HTTP_CONTEXT *phttp;
	
	phttp = http_parser_get_contexts_list() + context_id;
	mem_file_seek(&phttp->request.f_request_uri,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_host,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_user_agent,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_accept,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_accept_language,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_accept_encoding,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_content_type,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_content_length,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_transfer_encoding,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_cookie,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_seek(&phttp->request.f_others,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	return &phttp->request;
}

static HTTP_AUTH_INFO hpm_processor_get_auth_info(int context_id)
{
	HTTP_AUTH_INFO info;
	HTTP_CONTEXT *phttp;
	
	phttp = http_parser_get_contexts_list() + context_id;
	info.b_authed = phttp->b_authed;
	info.username = phttp->username;
	info.password = phttp->password;
	info.maildir = phttp->maildir;
	info.lang = phttp->lang;
	return info;
}

static void hpm_processor_set_ep_info(
	int context_id, const char *host, int port)
{
	HTTP_CONTEXT *phttp;
	
	phttp = http_parser_get_contexts_list() + context_id;
	strncpy(phttp->host, host, sizeof(phttp->host));
	phttp->port = port;
}

static BOOL hpm_processor_write_response(int context_id,
	void *response_buff, int response_len)
{
	HTTP_CONTEXT *phttp;
	
	phttp = http_parser_get_contexts_list() + context_id;
	if (STREAM_WRITE_OK != stream_write(&phttp->stream_out,
		response_buff, response_len)) {
		return FALSE;
	}
	return TRUE;
}

static void hpm_processor_wakeup_context(int context_id)
{
	HTTP_CONTEXT *phttp;
	
	phttp = http_parser_get_contexts_list() + context_id;
	if (SCHED_STAT_WAIT != phttp->sched_stat) {
		return;
	}
	phttp->sched_stat = SCHED_STAT_WRREP;
	contexts_pool_signal((SCHEDULE_CONTEXT*)phttp);
}

static int hpm_processor_getversion()
{
	return SERVICE_VERSION;
}

static void* hpm_processor_queryservice(char *service)
{
	void *ret_addr;
	SERVICE_NODE *pservice;
	DOUBLE_LIST_NODE *pnode;

	if (NULL == g_cur_plugin) {
		return NULL;
	}
	if (strcmp(service, "register_interface") == 0) {
		return hpm_processor_register_interface;
	}
	if (strcmp(service, "register_talk") == 0) {
		return hpm_processor_register_talk;
	}
	if (strcmp(service, "unregister_talk") == 0) {
		return hpm_processor_unregister_talk;
	}
	if (strcmp(service, "get_host_ID") == 0) {
		return hpm_processor_get_host_ID;
	}
	if (strcmp(service, "get_default_domain") == 0) {
		return hpm_processor_get_default_domain;
	}
	if (strcmp(service, "get_plugin_name") == 0) {
		return hpm_processor_get_plugin_name;
	}
	if (strcmp(service, "get_config_path") == 0) {
		return hpm_processor_get_config_path;
	}
	if (strcmp(service, "get_data_path") == 0) {
		return hpm_processor_get_data_path;
	}
	if (strcmp(service, "get_context_num") == 0) {
		return hpm_processor_get_context_num;
	}
	if (strcmp(service, "get_request") == 0) {
		return hpm_processor_get_request;
	}
	if (strcmp(service, "get_auth_info") == 0) {
		return hpm_processor_get_auth_info;
	}
	if (strcmp(service, "get_connection") == 0) {
		return hpm_processor_get_connection;
	}
	if (strcmp(service, "write_response") == 0) {
		return hpm_processor_write_response;
	}
	if (strcmp(service, "wakeup_context") == 0) {
		return hpm_processor_wakeup_context;
	}
	if (strcmp(service, "set_context") == 0) {
		return http_parser_set_context;
	}
	if (strcmp(service, "set_ep_info") == 0) {
		return hpm_processor_set_ep_info;
	}
	if (strcmp(service, "ndr_stack_alloc") == 0) {
		return pdu_processor_ndr_stack_alloc;
	}
	if (strcmp(service, "rpc_new_environment") == 0) {
		return pdu_processor_rpc_new_environment;
	}
	if (strcmp(service, "rpc_free_environment") == 0) {
		return pdu_processor_rpc_free_environment;
	}
	/* check if already exists in the reference list */
	for (pnode=double_list_get_head(&g_cur_plugin->list_reference);
		NULL!=pnode; pnode=double_list_get_after(
		&g_cur_plugin->list_reference, pnode)) {
        pservice = (SERVICE_NODE*)(pnode->pdata);
		if (0 == strcmp(service, pservice->service_name)) {
			return pservice->service_addr;
		}
	}
	ret_addr = service_query(service, g_cur_plugin->file_name);
	if (NULL == ret_addr) {
		return NULL;
	}
	pservice = (SERVICE_NODE*)malloc(sizeof(SERVICE_NODE));
	if (NULL == pservice) {
		debug_info("[hpm_processor]: fail to "
			"allocate memory for service node\n");
		service_release(service, g_cur_plugin->file_name);
		return NULL;
	}
	pservice->service_name = (char*)malloc(strlen(service) + 1);
	if (NULL == pservice->service_name) {
		debug_info("[hpm_processor]: fail to "
			"allocate memory for service name\n");
		service_release(service, g_cur_plugin->file_name);
		free(pservice);
		return NULL;
	}
	strcpy(pservice->service_name, service);
	pservice->node.pdata = pservice;
	pservice->service_addr = ret_addr;
	double_list_append_as_tail(
		&g_cur_plugin->list_reference, &pservice->node);
	return ret_addr;
}

static void hpm_processor_unload_library(const char *plugin_name)
{
	PLUGIN_MAIN func;
	DOUBLE_LIST *plist;
	HPM_PLUGIN *pplugin;
	DOUBLE_LIST_NODE *pnode;
	
    /* first find the plugin node in lib list */
    for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		pplugin = (HPM_PLUGIN*)pnode->pdata;
		if (0 == strcmp(pplugin->file_name, plugin_name)) {
			break;
		}
	}
    if (NULL == pnode){
        return;
    }
	func = (PLUGIN_MAIN)pplugin->lib_main;
	/* notify the plugin that it willbe unloaded */
	func(PLUGIN_FREE, NULL);
	/* free the reference list */
	while ((pnode = double_list_get_from_head(&pplugin->list_reference))) {
		service_release(((SERVICE_NODE*)(pnode->pdata))->service_name,
			pplugin->file_name);
		free(((SERVICE_NODE*)(pnode->pdata))->service_name);
		free(pnode->pdata);
	}
	double_list_free(&pplugin->list_reference);
	double_list_remove(&g_plugin_list, &pplugin->node);
	dlclose(pplugin->handle);
	free(pplugin);
}

static void hpm_processor_load_library(const char* plugin_name)
{
	void *handle;
	PLUGIN_MAIN func;
	HPM_PLUGIN *pplugin;
	void* two_server_funcs[2];
	char buf[256], fake_path[256];
	
	two_server_funcs[0] = (void*)hpm_processor_getversion;
	two_server_funcs[1] = (void*)hpm_processor_queryservice;
	snprintf(fake_path, 256, "%s/%s", g_plugins_path, plugin_name);
	handle = dlopen(fake_path, RTLD_LAZY);
	if (NULL == handle){
		printf("[hpm_processor]: error to load %s"
			" reason: %s\n", fake_path, dlerror());
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		return;
    }
	func = (PLUGIN_MAIN)dlsym(handle, "HPM_LibMain");
	if (NULL == func) {
		printf("[hpm_processor]: error to find "
			"HPM_LibMain function in %s\n", fake_path);
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return;
	}
	pplugin = malloc(sizeof(HPM_PLUGIN));
    if (NULL == pplugin) {
		printf("[hpm_processor]: fail to allocate memory for %s\n", fake_path);
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return;
	}
	memset(pplugin, 0, sizeof(HPM_PLUGIN));
	pplugin->node.pdata = pplugin;
	double_list_init(&pplugin->list_reference);
	strncpy(pplugin->file_name, plugin_name, 255);
	pplugin->handle = handle;
	pplugin->lib_main = func;
	/* append the pendpoint node into endpoint list */
	double_list_append_as_tail(&g_plugin_list, &pplugin->node);
	g_cur_plugin = pplugin;
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
    if (FALSE == func(PLUGIN_INIT, (void**)two_server_funcs) ||
		NULL == pplugin->interface.preproc ||
		NULL == pplugin->interface.proc ||
		NULL == pplugin->interface.retr) {
		printf("[hpm_processor]: error to excute plugin's init "
			"function or interface not registered in %s\n", fake_path);
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		/*
		 *  the lib node will automatically removed from plugin
		 *  list in hpm_processor_unload_library function
		 */
        hpm_processor_unload_library(plugin_name);
		g_cur_plugin = NULL;
		return;
	}
	g_cur_plugin = NULL;
}

int hpm_processor_run()
{
	DIR *dirp;
	int length;
	char temp_path[256];
	struct dirent *direntp;
	
	g_context_list = malloc(sizeof(HPM_CONTEXT)*g_context_num);
	if (NULL == g_context_list) {
		printf("[hpm_processor]: fail to allocate context list\n");
		return -1;
	}
	memset(g_context_list, 0, sizeof(HPM_CONTEXT)*g_context_num);
	dirp = opendir(g_plugins_path);
	if (NULL == dirp) {
		printf("[hpm_processor]: fail to open "
			"plugins' directory %s\n", g_plugins_path);
		return -2;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		/* extended name ".hpm" */
		length = strlen(direntp->d_name);
		if (0 == strcmp(direntp->d_name + length - 4, ".hpm")) {
			hpm_processor_load_library(direntp->d_name);
		}
	}
	closedir(dirp);
	return 0;
}

int hpm_processor_stop()
{
	VSTACK stack;
	LIB_BUFFER *pallocator;
	DOUBLE_LIST_NODE *pnode;
	
	pallocator = vstack_allocator_init(256, 1024, FALSE);
	vstack_init(&stack, pallocator, 256, 1024);
	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		vstack_push(&stack, ((HPM_PLUGIN*)(pnode->pdata))->file_name);
	}
	while (FALSE == vstack_is_empty(&stack)) {
        hpm_processor_unload_library(vstack_get_top(&stack));
        vstack_pop(&stack);
    }
	vstack_free(&stack);
    vstack_allocator_free(pallocator);
	if (NULL != g_context_list) {
		free(g_context_list);
		g_context_list = NULL;
	}
	return 0;
}

void hpm_processor_free()
{
	double_list_free(&g_plugin_list);
}

int hpm_processor_console_talk(int argc,
	char** argv, char *result, int length)
{
	HPM_PLUGIN *pplugin;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		pplugin = (HPM_PLUGIN*)(pnode->pdata);
		if (0 == strncmp(pplugin->file_name, argv[0], 256)) {
			if (NULL != pplugin->talk_main) {
				pplugin->talk_main(argc, argv, result, length);
				return PLUGIN_TALK_OK;
			} else {
				return PLUGIN_NO_TALK;
			}
		}
	}
	return PLUGIN_NO_FILE;
}

void hpm_processor_enum_plugins(ENUM_PLUGINS enum_func)
{
	DOUBLE_LIST_NODE *pnode;

	if (NULL == enum_func) {
		return;
	}
	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		enum_func(((HPM_PLUGIN*)(pnode->pdata))->file_name);
	}
}

BOOL hpm_processor_get_context(HTTP_CONTEXT *phttp)
{
	int tmp_len;
	int context_id;
	BOOL b_chunked;
	char tmp_buff[32];
	HPM_PLUGIN *pplugin;
	HPM_CONTEXT *phpm_ctx;
	DOUBLE_LIST_NODE *pnode;
	uint64_t content_length;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		pplugin = (HPM_PLUGIN*)pnode->pdata;
		if (TRUE == pplugin->interface.preproc(context_id)) {
			tmp_len = mem_file_get_total_length(
				&phttp->request.f_content_length);
			if (0 == tmp_len) {
				content_length = 0;
			} else {
				if (tmp_len >= 32) {
					phpm_ctx->b_preproc = FALSE;
					http_parser_log_info(phttp, 8, "length of "
						"content-length is too long for hpm_processor");
					return FALSE;
				}
				mem_file_seek(&phttp->request.f_content_length,
					MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
				mem_file_read(&phttp->request.f_content_length,
					tmp_buff, tmp_len);
				tmp_buff[tmp_len] = '\0';
				content_length = atoll(tmp_buff);
			}
			if (content_length > g_max_size) {
				phpm_ctx->b_preproc = FALSE;
				http_parser_log_info(phttp, 8, "content-length"
					" is too long for hpm_processor");
				return FALSE;
			}
			b_chunked = FALSE;
			tmp_len = mem_file_get_total_length(
				&phttp->request.f_transfer_encoding);
			if (tmp_len > 0 && tmp_len < 64) {
				mem_file_seek(&phttp->request.f_transfer_encoding,
						MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
				mem_file_read(&phttp->request.f_transfer_encoding,
					tmp_buff, tmp_len);
				tmp_buff[tmp_len] = '\0';
				if (0 == strcasecmp(tmp_buff, "chunked")) {
					b_chunked = TRUE;
				}
			}
			if (TRUE == b_chunked || content_length > g_cache_size) {
				sprintf(tmp_buff, "/tmp/http-%d", context_id);
				phpm_ctx->cache_fd = open(tmp_buff,
					O_CREAT|O_TRUNC|O_RDWR, 0666);
				if (-1 == phpm_ctx->cache_fd) {
					phpm_ctx->b_preproc = FALSE;
					return FALSE;
				}
				phpm_ctx->cache_size = 0;
			} else {
				phpm_ctx->cache_fd = -1;
			}
			phpm_ctx->b_chunked = b_chunked;
			if (TRUE == b_chunked) {
				phpm_ctx->chunk_size = 0;
				phpm_ctx->chunk_offset = 0;
			}
			phpm_ctx->content_length = content_length;
			phpm_ctx->b_end = FALSE;
			phpm_ctx->b_preproc = TRUE;
			phpm_ctx->pinterface = &pplugin->interface;
			return TRUE;
		}
	}
	phpm_ctx->b_preproc = FALSE;
	return FALSE;
}

BOOL hpm_processor_check_context(HTTP_CONTEXT *phttp)
{
	int context_id;
	HPM_CONTEXT *phpm_ctx;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	return phpm_ctx->b_preproc;
}

BOOL hpm_processor_write_request(HTTP_CONTEXT *phttp)
{
	int size;
	int tmp_len;
	char *pbuff;
	char *ptoken;
	int context_id;
	char tmp_buff[1024];
	HPM_CONTEXT *phpm_ctx;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	if (TRUE == phpm_ctx->b_end) {
		return TRUE;
	}
	if (-1 == phpm_ctx->cache_fd) {
		if (phpm_ctx->content_length <=
			stream_get_total_length(&phttp->stream_in)) {
			phpm_ctx->b_end = TRUE;	
		}
		return TRUE;
	}
	if (FALSE == phpm_ctx->b_chunked) {
		if (phpm_ctx->cache_size +
			stream_get_total_length(&phttp->stream_in) <
			phpm_ctx->content_length &&
			stream_get_total_length(&phttp->stream_in) <
			g_cache_size) {
			return TRUE;	
		}
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = stream_getbuffer_for_reading(
			&phttp->stream_in, &size))) {
			if (phpm_ctx->cache_size + size >
				phpm_ctx->content_length) {
				tmp_len = phpm_ctx->content_length
							- phpm_ctx->cache_size;
				stream_backward_reading_ptr(
					&phttp->stream_in, size - tmp_len);
				phpm_ctx->cache_size = phpm_ctx->content_length;
			} else {
				phpm_ctx->cache_size += size;
				tmp_len = size;
			}
			if (tmp_len != write(phpm_ctx->cache_fd, pbuff, tmp_len)) {
				http_parser_log_info(phttp, 8, "fail to"
					" write cache file for hpm_processor");
				return FALSE;
			}
			if (phpm_ctx->cache_size == phpm_ctx->content_length) {
				phpm_ctx->b_end = TRUE;
				return TRUE;
			}
			size = STREAM_BLOCK_SIZE;
		}
	} else {
CHUNK_BEGIN:
		if (phpm_ctx->chunk_size == phpm_ctx->chunk_offset) {
			size = stream_peek_buffer(&phttp->stream_in, tmp_buff, 1024);
			if (size < 5) {
				return TRUE;
			}
			if (0 == strncmp("0\r\n\r\n", tmp_buff, 5)) {
				stream_forward_reading_ptr(&phttp->stream_in, 5);
				phpm_ctx->b_end = TRUE;
				return TRUE;
			}
			ptoken = memmem(tmp_buff, size, "\r\n", 2);
			if (NULL == ptoken) {
				if (1024 == size) {
					http_parser_log_info(phttp, 8, "fail to "
						"parse chunked block for hpm_processor");
					return FALSE;
				}
				return TRUE;
			}
			*ptoken = '\0';
			phpm_ctx->chunk_size = strtol(tmp_buff, NULL, 16);
			if (0 == phpm_ctx->chunk_size) {
				http_parser_log_info(phttp, 8, "fail to "
					"parse chunked block for hpm_processor");
				return FALSE;
			}
			phpm_ctx->chunk_offset = 0;
			tmp_len = ptoken + 2 - tmp_buff;
			stream_forward_reading_ptr(&phttp->stream_in, tmp_len);
		}
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = stream_getbuffer_for_reading(
			&phttp->stream_in, &size))) {
			if (phpm_ctx->chunk_size >= size + phpm_ctx->chunk_offset) {
				if (size != write(phpm_ctx->cache_fd, pbuff, size)) {
					http_parser_log_info(phttp, 8, "fail to "
						"write cache file for hpm_processor");
					return FALSE;
				}
				phpm_ctx->chunk_offset += size;
				phpm_ctx->cache_size += size;
			} else {
				tmp_len = phpm_ctx->chunk_size - phpm_ctx->chunk_offset;
				if (tmp_len != write(phpm_ctx->cache_fd, pbuff, tmp_len)) {
					http_parser_log_info(phttp, 8, "fail to"
						" write cache file for hpm_processor");
					return FALSE;
				}
				stream_backward_reading_ptr(
					&phttp->stream_in, size - tmp_len);
				phpm_ctx->cache_size += tmp_len;
				phpm_ctx->chunk_offset = phpm_ctx->chunk_size;
			}
			if (phpm_ctx->cache_size > g_max_size) {
				http_parser_log_info(phttp, 8, "chunked content"
						" length is too long for hpm_processor");
				return FALSE;
			}
			if (phpm_ctx->chunk_offset == phpm_ctx->chunk_size) {
				goto CHUNK_BEGIN;	
			}
		}
	}
	stream_clear(&phttp->stream_in);
	return TRUE;
}

BOOL hpm_processor_check_end_of_request(HTTP_CONTEXT *phttp)
{
	int context_id;
	HPM_CONTEXT *phpm_ctx;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	return phpm_ctx->b_end;
}

BOOL hpm_processor_proc(HTTP_CONTEXT *phttp)
{
	BOOL b_result;
	void *pcontent;
	int context_id;
	char tmp_path[256];
	struct stat node_stat;
	HPM_CONTEXT *phpm_ctx;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	if (-1 == phpm_ctx->cache_fd) {
		if (0 == phpm_ctx->content_length) {
			pcontent = NULL;
		} else {
			pcontent = malloc(phpm_ctx->content_length);
			if (NULL == pcontent) {
				return FALSE;
			}
			if (phpm_ctx->content_length != stream_peek_buffer(
				&phttp->stream_in, pcontent, phpm_ctx->content_length)) {
				free(pcontent);
				return FALSE;
			}
			stream_forward_reading_ptr(&phttp->stream_in,
				phpm_ctx->content_length);
		}
	} else {
		if (0 != fstat(phpm_ctx->cache_fd, &node_stat)) {
			return FALSE;
		}
		pcontent = malloc(node_stat.st_size);
		if (NULL == pcontent) {
			return FALSE;
		}
		lseek(phpm_ctx->cache_fd, 0, SEEK_SET);
		if (node_stat.st_size != read(phpm_ctx->cache_fd,
			pcontent, node_stat.st_size)) {
			free(pcontent);
			return FALSE;
		}
		close(phpm_ctx->cache_fd);
		phpm_ctx->cache_fd = -1;
		phpm_ctx->content_length = node_stat.st_size;
		sprintf(tmp_path, "/tmp/http-%d", context_id);
		remove(tmp_path);
	}
	b_result = phpm_ctx->pinterface->proc(context_id,
				pcontent, phpm_ctx->content_length);
	phpm_ctx->content_length = 0;
	if (NULL != pcontent) {
		free(pcontent);
	}
	return b_result;
}

int hpm_processor_retrieve_response(HTTP_CONTEXT *phttp)
{
	int context_id;
	HPM_CONTEXT *phpm_ctx;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	return phpm_ctx->pinterface->retr(context_id);
}

void hpm_processor_put_context(HTTP_CONTEXT *phttp)
{
	int context_id;
	char tmp_path[256];
	HPM_CONTEXT *phpm_ctx;
	
	context_id = phttp - http_parser_get_contexts_list();
	phpm_ctx = g_context_list + context_id;
	if (NULL != phpm_ctx->pinterface->term) {
		phpm_ctx->pinterface->term(context_id);
	}
	if (-1 != phpm_ctx->cache_fd) {
		close(phpm_ctx->cache_fd);
		phpm_ctx->cache_fd = -1;
		sprintf(tmp_path, "/tmp/http-%d", context_id);
		remove(tmp_path);
	}
	phpm_ctx->content_length = 0;
	phpm_ctx->b_preproc = FALSE;
	phpm_ctx->pinterface = NULL;
}
