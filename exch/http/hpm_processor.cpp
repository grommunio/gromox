// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <list>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "hpm_processor.h"
#include "http_parser.h"
#include "pdu_processor.h"
#include "resource.h"

using namespace std::string_literals;
using namespace gromox;

enum {
	RESP_FAIL,
	RESP_PARTIAL,
	RESP_PENDING,
	RESP_FINAL
};

namespace {

/* structure for describing service reference */

/**
 * @b_preproc:	one module has signalled interest (has completed preprocessing)
 * @b_end:	the end of the request body has been seen
 */
struct HPM_CONTEXT {
	const HPM_INTERFACE *pinterface = nullptr;
	BOOL b_preproc = false, b_chunked = false, b_end = false;
	int cache_fd = -1;
	uint32_t chunk_size = 0, chunk_offset = 0;
	uint64_t content_length = 0, cache_size = 0;
	std::string tmpfile;
};

}

static int g_context_num;
static uint64_t g_max_size;
static uint64_t g_cache_size;
static HPM_PLUGIN *g_cur_plugin;
static std::list<HPM_PLUGIN> g_plugin_list;
static std::unique_ptr<HPM_CONTEXT[]> g_context_list;
static std::vector<std::string> g_plugin_names;

void hpm_processor_init(int context_num, std::vector<std::string> &&names,
    uint64_t cache_size, uint64_t max_size)
{
	g_context_num = context_num;
	g_plugin_names = std::move(names);
	g_cache_size = cache_size;
	g_max_size = max_size;
}


static BOOL hpm_processor_register_interface(
	HPM_INTERFACE *pinterface)
{
	auto fn = g_cur_plugin->file_name.c_str();
	if (NULL == pinterface->preproc) {
		printf("[hpm_processor]: preproc of interface in %s cannot be NULL\n", fn);
		return FALSE;
	}
	if (NULL == pinterface->proc) {
		printf("[hpm_processor]: proc of interface in %s cannot be NULL\n", fn);
		return FALSE;
	}
	if (NULL == pinterface->retr) {
		printf("[hpm_processor]: retr of interface in %s cannot be NULL\n", fn);
		return FALSE;
	}
	if (NULL != g_cur_plugin->interface.preproc ||
		NULL != g_cur_plugin->interface.proc ||
		NULL != g_cur_plugin->interface.retr) {
		printf("[hpm_processor]: interface has been already registered in %s", fn);
		return FALSE;
	}
	memcpy(&g_cur_plugin->interface, pinterface, sizeof(HPM_INTERFACE));
	return TRUE;
}

static const char *hpm_processor_get_host_ID()
{
	return resource_get_string("HOST_ID");
}

static const char* hpm_processor_get_plugin_name()
{
	if (NULL == g_cur_plugin) {
		return NULL;
	}
	auto fn = g_cur_plugin->file_name.c_str();
	return strncmp(fn, "libgxh_", 7) == 0 ? fn + 7 : fn;
}

static const char* hpm_processor_get_config_path()
{
	const char *ret_value = resource_get_string("CONFIG_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGSYSCONFDIR;
    }
    return ret_value;
}

static const char* hpm_processor_get_data_path()
{
	const char *ret_value = resource_get_string("DATA_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGDATADIR "/http:" PKGDATADIR;
    }
    return ret_value;
}

static const char *hpm_processor_get_state_path()
{
	const char *p = resource_get_string("STATE_PATH");
	return p != nullptr ? p : PKGSTATEDIR;
}

static unsigned int hpm_processor_get_context_num()
{
	return g_context_num;
}

static GENERIC_CONNECTION *hpm_processor_get_connection(unsigned int context_id)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	return &phttp->connection;
}

static HTTP_REQUEST *hpm_processor_get_request(unsigned int context_id)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	phttp->request.f_request_uri.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_host.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_user_agent.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_accept.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_accept_language.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_accept_encoding.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_content_type.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_content_length.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_transfer_encoding.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_cookie.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	phttp->request.f_others.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	return &phttp->request;
}

static HTTP_AUTH_INFO hpm_processor_get_auth_info(unsigned int context_id)
{
	HTTP_AUTH_INFO info;
	
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	info.b_authed = phttp->b_authed;
	info.username = phttp->username;
	info.password = phttp->password;
	info.maildir = phttp->maildir;
	info.lang = phttp->lang;
	return info;
}

static void hpm_processor_set_ep_info(unsigned int context_id,
    const char *host, int port)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	gx_strlcpy(phttp->host, host, GX_ARRAY_SIZE(phttp->host));
	phttp->port = port;
}

static BOOL hpm_processor_write_response(unsigned int context_id,
	void *response_buff, int response_len)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	return phttp->stream_out.write(response_buff, response_len) == STREAM_WRITE_OK ? TRUE : false;
}

static void hpm_processor_wakeup_context(unsigned int context_id)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	if (SCHED_STAT_WAIT != phttp->sched_stat) {
		return;
	}
	phttp->sched_stat = SCHED_STAT_WRREP;
	contexts_pool_signal(phttp);
}

static void hpm_processor_activate_context(unsigned int context_id)
{
	context_pool_activate_context(http_parser_get_contexts_list()[context_id]);
}

static void *hpm_processor_queryservice(const char *service, const std::type_info &ti)
{
	void *ret_addr;

	if (NULL == g_cur_plugin) {
		return NULL;
	}
	if (strcmp(service, "register_interface") == 0) {
		return reinterpret_cast<void *>(hpm_processor_register_interface);
	}
	if (strcmp(service, "register_service") == 0)
		return reinterpret_cast<void *>(service_register_service);
	if (strcmp(service, "get_host_ID") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_host_ID);
	}
	if (strcmp(service, "get_plugin_name") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_plugin_name);
	}
	if (strcmp(service, "get_config_path") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_config_path);
	}
	if (strcmp(service, "get_data_path") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_data_path);
	}
	if (strcmp(service, "get_state_path") == 0)
		return reinterpret_cast<void *>(hpm_processor_get_state_path);
	if (strcmp(service, "get_context_num") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_context_num);
	}
	if (strcmp(service, "get_request") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_request);
	}
	if (strcmp(service, "get_auth_info") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_auth_info);
	}
	if (strcmp(service, "get_connection") == 0) {
		return reinterpret_cast<void *>(hpm_processor_get_connection);
	}
	if (strcmp(service, "write_response") == 0) {
		return reinterpret_cast<void *>(hpm_processor_write_response);
	}
	if (strcmp(service, "wakeup_context") == 0) {
		return reinterpret_cast<void *>(hpm_processor_wakeup_context);
	}
	if (strcmp(service, "activate_context") == 0) {
		return reinterpret_cast<void *>(hpm_processor_activate_context);
	}
	if (strcmp(service, "set_context") == 0) {
		return reinterpret_cast<void *>(http_parser_set_context);
	}
	if (strcmp(service, "set_ep_info") == 0) {
		return reinterpret_cast<void *>(hpm_processor_set_ep_info);
	}
	if (strcmp(service, "ndr_stack_alloc") == 0) {
		return reinterpret_cast<void *>(pdu_processor_ndr_stack_alloc);
	}
	if (strcmp(service, "rpc_new_stack") == 0)
		return reinterpret_cast<void *>(pdu_processor_rpc_new_stack);
	if (strcmp(service, "rpc_free_stack") == 0)
		return reinterpret_cast<void *>(pdu_processor_rpc_free_stack);
	/* check if already exists in the reference list */
	for (const auto &nd : g_cur_plugin->list_reference)
		if (nd.service_name == service)
			return nd.service_addr;
	auto fn = g_cur_plugin->file_name.c_str();
	ret_addr = service_query(service, fn, ti);
	if (NULL == ret_addr) {
		return NULL;
	}
	try {
		hpm_service_node nd;
		nd.service_name = service;
		nd.service_addr = ret_addr;
		g_cur_plugin->list_reference.push_back(std::move(nd));
	} catch (const std::bad_alloc &) {
		service_release(service, fn);
		mlog(LV_ERR, "E-1636: ENOMEM");
		return nullptr;
	}
	return ret_addr;
}

HPM_PLUGIN::HPM_PLUGIN(HPM_PLUGIN &&o) noexcept :
	list_reference(std::move(o.list_reference)), interface(o.interface),
	handle(o.handle), lib_main(o.lib_main),
	file_name(std::move(o.file_name)), completed_init(o.completed_init)
{
	o.handle = nullptr;
	o.completed_init = false;
}

HPM_PLUGIN::~HPM_PLUGIN()
{
	PLUGIN_MAIN func;
	auto pplugin = this;
	if (pplugin->file_name.size() > 0)
		printf("[hpm_processor]: unloading %s\n", pplugin->file_name.c_str());
	func = (PLUGIN_MAIN)pplugin->lib_main;
	if (func != nullptr && pplugin->completed_init)
		/* notify the plugin that it willbe unloaded */
		func(PLUGIN_FREE, NULL);

	/* free the reference list */
	for (const auto &nd : list_reference)
		service_release(nd.service_name.c_str(), pplugin->file_name.c_str());
	if (handle != nullptr)
		dlclose(handle);
}

static int hpm_processor_load_library(const char *plugin_name)
{
	static void *const server_funcs[] = {reinterpret_cast<void *>(hpm_processor_queryservice)};
	const char *fake_path = plugin_name;
	HPM_PLUGIN plug;

	plug.handle = dlopen(plugin_name, RTLD_LAZY);
	if (plug.handle == nullptr && strchr(plugin_name, '/') == nullptr)
		plug.handle = dlopen((PKGLIBDIR + "/"s + plugin_name).c_str(), RTLD_LAZY);
	if (plug.handle == nullptr) {
		printf("[hpm_processor]: error loading %s: %s\n", fake_path, dlerror());
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
    }
	plug.lib_main = reinterpret_cast<decltype(plug.lib_main)>(dlsym(plug.handle, "HPM_LibMain"));
	if (plug.lib_main == nullptr) {
		printf("[hpm_processor]: error finding the "
			"HPM_LibMain function in %s\n", fake_path);
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_NO_MAIN;
	}
	plug.file_name = plugin_name;
	g_plugin_list.push_back(std::move(plug));
	g_cur_plugin = &g_plugin_list.back();
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!g_cur_plugin->lib_main(PLUGIN_INIT, const_cast<void **>(server_funcs)) ||
	    g_cur_plugin->interface.preproc == nullptr ||
	    g_cur_plugin->interface.proc == nullptr ||
	    g_cur_plugin->interface.retr == nullptr) {
		printf("[hpm_processor]: error executing the plugin's init "
			"function, or interface not registered in %s\n", fake_path);
		printf("[hpm_processor]: the plugin %s is not loaded\n", fake_path);
		g_plugin_list.pop_back();
		g_cur_plugin = NULL;
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	g_cur_plugin->completed_init = true;
	g_cur_plugin = NULL;
	return PLUGIN_LOAD_OK;
}

int hpm_processor_run() try
{
	g_context_list = std::make_unique<HPM_CONTEXT[]>(g_context_num);
	for (const auto &i : g_plugin_names) {
		int ret = hpm_processor_load_library(i.c_str());
		if (ret != PLUGIN_LOAD_OK)
			return -1;
	}
	return 0;
} catch (const std::bad_alloc &) {
	printf("[hpm_processor]: Failed to allocate context list\n");
	return -1;
}

void hpm_processor_stop()
{
	g_plugin_list.clear();
	g_context_list.reset();
}

bool hpm_processor_take_request(HTTP_CONTEXT *phttp)
{
	int tmp_len;
	BOOL b_chunked;
	char tmp_buff[64];
	uint64_t content_length;
	
	auto phpm_ctx = &g_context_list[phttp->context_id];
	for (const auto &p : g_plugin_list) {
		auto pplugin = &p;
		if (!pplugin->interface.preproc(phttp->context_id))
			continue;
		tmp_len = phttp->request.f_content_length.get_total_length();
		if (0 == tmp_len) {
			content_length = 0;
		} else {
			if (tmp_len >= 32) {
				phpm_ctx->b_preproc = FALSE;
				phttp->log(LV_DEBUG, "length of "
					"content-length is too long for hpm_processor");
				return FALSE;
			}
			phttp->request.f_content_length.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			phttp->request.f_content_length.read(tmp_buff, tmp_len);
			tmp_buff[tmp_len] = '\0';
			content_length = strtoull(tmp_buff, nullptr, 0);
		}
		if (content_length > g_max_size) {
			phpm_ctx->b_preproc = FALSE;
			phttp->log(LV_DEBUG, "content-length"
				" is too long for hpm_processor");
			return FALSE;
		}
		b_chunked = FALSE;
		tmp_len = phttp->request.f_transfer_encoding.get_total_length();
		if (tmp_len > 0 && static_cast<size_t>(tmp_len) < GX_ARRAY_SIZE(tmp_buff)) {
			phttp->request.f_transfer_encoding.seek(MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			phttp->request.f_transfer_encoding.read(tmp_buff, tmp_len);
			tmp_buff[tmp_len] = '\0';
			if (0 == strcasecmp(tmp_buff, "chunked")) {
				b_chunked = TRUE;
			}
		}
		if (b_chunked || content_length > g_cache_size) {
			auto path = LOCAL_DISK_TMPDIR;
			if (mkdir(path, 0777) < 0 && errno != EEXIST) {
				mlog(LV_ERR, "E-2079: mkdir %s: %s", path, strerror(errno));
				return false;
			}
			phpm_ctx->cache_fd = open_tmpfile(path, &phpm_ctx->tmpfile,
			                     O_RDWR | O_TRUNC);
			if (phpm_ctx->cache_fd < 0) {
				mlog(LV_ERR, "E-2090: open{%s, %s}: %s",
				        path, phpm_ctx->tmpfile.c_str(),
				        strerror(-phpm_ctx->cache_fd));
				phpm_ctx->b_preproc = FALSE;
				return FALSE;
			}
			phpm_ctx->cache_size = 0;
		} else {
			phpm_ctx->cache_fd = -1;
		}
		phpm_ctx->b_chunked = b_chunked;
		if (b_chunked) {
			phpm_ctx->chunk_size = 0;
			phpm_ctx->chunk_offset = 0;
		}
		phpm_ctx->content_length = content_length;
		phpm_ctx->b_end = FALSE;
		phpm_ctx->b_preproc = TRUE;
		phpm_ctx->pinterface = &pplugin->interface;
		return true;
	}
	phpm_ctx->b_preproc = FALSE;
	return FALSE;
}

bool hpm_processor_is_in_charge(HTTP_CONTEXT *phttp)
{
	auto phpm_ctx = &g_context_list[phttp->context_id];
	return phpm_ctx->b_preproc;
}

/**
 * Move the HTTP request body to cache_fd, depending on size.
 */
BOOL hpm_processor_write_request(HTTP_CONTEXT *phttp)
{
	int size;
	int tmp_len;
	void *pbuff;
	char *ptoken;
	char tmp_buff[1024];
	
	auto phpm_ctx = &g_context_list[phttp->context_id];
	if (phpm_ctx->b_end)
		return TRUE;
	if (phpm_ctx->cache_fd < 0) {
		if (phpm_ctx->content_length <= phttp->stream_in.get_total_length())
			phpm_ctx->b_end = TRUE;	
		return TRUE;
	}
	if (!phpm_ctx->b_chunked) {
		if (phpm_ctx->cache_size + phttp->stream_in.get_total_length() < phpm_ctx->content_length &&
		    phttp->stream_in.get_total_length() < g_cache_size)
			return TRUE;	
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = phttp->stream_in.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
			if (phpm_ctx->cache_size + size >
				phpm_ctx->content_length) {
				tmp_len = phpm_ctx->content_length
							- phpm_ctx->cache_size;
				phttp->stream_in.rewind_read_ptr(size - tmp_len);
				phpm_ctx->cache_size = phpm_ctx->content_length;
			} else {
				phpm_ctx->cache_size += size;
				tmp_len = size;
			}
			if (tmp_len != write(phpm_ctx->cache_fd, pbuff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to"
					" write cache file for hpm_processor");
				return FALSE;
			}
			if (phpm_ctx->cache_size == phpm_ctx->content_length) {
				phpm_ctx->b_end = TRUE;
				return TRUE;
			}
			size = STREAM_BLOCK_SIZE;
		}
		phttp->stream_in.clear();
		return TRUE;
	}
 CHUNK_BEGIN:
	if (phpm_ctx->chunk_size == phpm_ctx->chunk_offset) {
		size = phttp->stream_in.peek_buffer(tmp_buff, 1024);
		if (size < 5) {
			return TRUE;
		}
		if (0 == strncmp("0\r\n\r\n", tmp_buff, 5)) {
			phttp->stream_in.fwd_read_ptr(5);
			phpm_ctx->b_end = TRUE;
			return TRUE;
		}
		/*
		 * This is crap. It fails if the client sends the chunk length
		 * one byte at a time...
		 */
		ptoken = static_cast<char *>(memmem(tmp_buff, size, "\r\n", 2));
		if (NULL == ptoken) {
			if (1024 == size) {
				phttp->log(LV_DEBUG, "failed to "
					"parse chunked block for hpm_processor");
				return FALSE;
			}
			return TRUE;
		}
		*ptoken = '\0';
		phpm_ctx->chunk_size = strtol(tmp_buff, NULL, 16);
		if (0 == phpm_ctx->chunk_size) {
			phttp->log(LV_DEBUG, "failed to "
				"parse chunked block for hpm_processor");
			return FALSE;
		}
		phpm_ctx->chunk_offset = 0;
		tmp_len = ptoken + 2 - tmp_buff;
		phttp->stream_in.fwd_read_ptr(tmp_len);
	}
	size = STREAM_BLOCK_SIZE;
	while ((pbuff = phttp->stream_in.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
		if (phpm_ctx->chunk_size >= size + phpm_ctx->chunk_offset) {
			if (size != write(phpm_ctx->cache_fd, pbuff, size)) {
				phttp->log(LV_DEBUG, "failed to "
					"write cache file for hpm_processor");
				return FALSE;
			}
			phpm_ctx->chunk_offset += size;
			phpm_ctx->cache_size += size;
		} else {
			tmp_len = phpm_ctx->chunk_size - phpm_ctx->chunk_offset;
			if (tmp_len != write(phpm_ctx->cache_fd, pbuff, tmp_len)) {
				phttp->log(LV_DEBUG, "failed to"
					" write cache file for hpm_processor");
				return FALSE;
			}
			phttp->stream_in.rewind_read_ptr(size - tmp_len);
			phpm_ctx->cache_size += tmp_len;
			phpm_ctx->chunk_offset = phpm_ctx->chunk_size;
		}
		if (phpm_ctx->cache_size > g_max_size) {
			phttp->log(LV_DEBUG, "chunked content"
				" length is too long for hpm_processor");
			return FALSE;
		}
		if (phpm_ctx->chunk_offset == phpm_ctx->chunk_size) {
			goto CHUNK_BEGIN;
		}
	}
	/*
	 * This is crap. Breaks processing of the next request if the client
	 * sent two requests with one network packet.
	 */
	phttp->stream_in.clear();
	return TRUE;
}

BOOL hpm_processor_check_end_of_request(HTTP_CONTEXT *phttp)
{
	return g_context_list[phttp->context_id].b_end;
}

BOOL hpm_processor_proc(HTTP_CONTEXT *phttp)
{
	BOOL b_result;
	void *pcontent;
	struct stat node_stat;
	
	auto phpm_ctx = &g_context_list[phttp->context_id];
	if (phpm_ctx->cache_fd < 0) {
		if (0 == phpm_ctx->content_length) {
			pcontent = NULL;
		} else {
			pcontent = malloc(phpm_ctx->content_length);
			if (NULL == pcontent) {
				return FALSE;
			}
			if (phttp->stream_in.peek_buffer(static_cast<char *>(pcontent),
			    phpm_ctx->content_length) != phpm_ctx->content_length) {
				free(pcontent);
				return FALSE;
			}
			phttp->stream_in.fwd_read_ptr(phpm_ctx->content_length);
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
		if (!phpm_ctx->tmpfile.empty() &&
		    unlink(phpm_ctx->tmpfile.c_str()) < 0 &&
		    errno != ENOENT)
			mlog(LV_WARN, "W-1347: remove %s: %s",
			        phpm_ctx->tmpfile.c_str(), strerror(errno));
	}
	b_result = phpm_ctx->pinterface->proc(phttp->context_id,
				pcontent, phpm_ctx->content_length);
	phpm_ctx->content_length = 0;
	if (NULL != pcontent) {
		free(pcontent);
	}
	return b_result;
}

BOOL hpm_processor_send(HTTP_CONTEXT *phttp,
	const void *pbuff, int length)
{
	auto id = phttp->context_id;
	return g_context_list[id].pinterface->send(id, pbuff, length);
}

int hpm_processor_receive(HTTP_CONTEXT *phttp,
	char *pbuff, int length)
{
	auto id = phttp->context_id;
	return g_context_list[id].pinterface->receive(id, pbuff, length);
}

int hpm_processor_retrieve_response(HTTP_CONTEXT *phttp)
{
	auto id = phttp->context_id;
	return g_context_list[id].pinterface->retr(id);
}

void hpm_processor_put_context(HTTP_CONTEXT *phttp)
{
	auto phpm_ctx = &g_context_list[phttp->context_id];
	if (NULL != phpm_ctx->pinterface->term) {
		phpm_ctx->pinterface->term(phttp->context_id);
	}
	if (phpm_ctx->cache_fd >= 0) {
		close(phpm_ctx->cache_fd);
		phpm_ctx->cache_fd = -1;
		if (!phpm_ctx->tmpfile.empty() &&
		    unlink(phpm_ctx->tmpfile.c_str()) < 0 &&
		    errno != ENOENT)
			mlog(LV_WARN, "W-1369: remove %s: %s",
			        phpm_ctx->tmpfile.c_str(), strerror(errno));
	}
	phpm_ctx->content_length = 0;
	phpm_ctx->b_preproc = FALSE;
	phpm_ctx->pinterface = NULL;
}

void hpm_processor_trigger(unsigned int ev)
{
	for (auto &p : g_plugin_list) {
		g_cur_plugin = &p;
		p.lib_main(ev, nullptr);
	}
	g_cur_plugin = nullptr;
}
