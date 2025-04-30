// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <list>
#include <span>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "hpm_processor.hpp"
#include "http_parser.hpp"
#include "pdu_processor.hpp"
#include "resource.hpp"

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
 */
struct HPM_CONTEXT {
	const HPM_INTERFACE *pinterface = nullptr;
	BOOL b_preproc = false;
};

}

static unsigned int g_context_num;
static thread_local HPM_PLUGIN *g_cur_plugin;
static std::list<HPM_PLUGIN> g_plugin_list;
static std::unique_ptr<HPM_CONTEXT[]> g_context_list;
static std::span<const static_module> g_plugin_names;

void hpm_processor_init(int context_num, std::span<const static_module> names)
{
	g_context_num = context_num;
	g_plugin_names = std::move(names);
}

static BOOL hpm_processor_register_interface(
	HPM_INTERFACE *pinterface)
{
	auto fn = g_cur_plugin->file_name;
	if (NULL == pinterface->preproc) {
		mlog(LV_ERR, "http_processor: preproc of interface in %s cannot be NULL", fn);
		return FALSE;
	}
	if (NULL == pinterface->proc) {
		mlog(LV_ERR, "http_processor: proc of interface in %s cannot be NULL", fn);
		return FALSE;
	}
	if (NULL == pinterface->retr) {
		mlog(LV_ERR, "http_processor: retr of interface in %s cannot be NULL", fn);
		return FALSE;
	}
	if (NULL != g_cur_plugin->interface.preproc ||
		NULL != g_cur_plugin->interface.proc ||
		NULL != g_cur_plugin->interface.retr) {
		mlog(LV_ERR, "http_processor: interface has already been registered in %s", fn);
		return FALSE;
	}
	memcpy(&g_cur_plugin->interface, pinterface, sizeof(HPM_INTERFACE));
	return TRUE;
}

static HTTP_REQUEST *hpm_processor_get_request(unsigned int context_id)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	return &phttp->request;
}

static HTTP_AUTH_INFO hpm_processor_get_auth_info(unsigned int context_id)
{
	HTTP_AUTH_INFO info;
	
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	info.auth_status = phttp->auth_status;
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
	gx_strlcpy(phttp->host, host, std::size(phttp->host));
	phttp->port = port;
}

static void hpm_processor_wakeup_context(unsigned int context_id)
{
	auto phttp = static_cast<HTTP_CONTEXT *>(http_parser_get_contexts_list()[context_id]);
	if (phttp->sched_stat != hsched_stat::wait)
		return;
	phttp->sched_stat = hsched_stat::wrrep;
	contexts_pool_signal(phttp);
}

static void *hpm_processor_queryservice(const char *service, const char *rq,
    const std::type_info &ti)
{
	void *ret_addr;

	if (g_cur_plugin == nullptr)
		return NULL;
	/* check if already exists in the reference list */
	for (const auto &nd : g_cur_plugin->list_reference)
		if (nd.service_name == service)
			return nd.service_addr;
	auto fn = g_cur_plugin->file_name;
	ret_addr = service_query(service, fn, ti);
	if (ret_addr == nullptr)
		return NULL;
	try {
		g_cur_plugin->list_reference.emplace_back(service_node{ret_addr, service});
	} catch (const std::bad_alloc &) {
		service_release(service, fn);
		mlog(LV_ERR, "E-1636: ENOMEM");
		return nullptr;
	}
	return ret_addr;
}

static constexpr struct dlfuncs server_funcs = {
	/* .symget = */ hpm_processor_queryservice,
	/* .symreg = */ service_register_service,
	/* .get_config_path = */ []() {
		auto r = g_config_file->get_value("config_file_path");
		return r != nullptr ? r : PKGSYSCONFDIR;
	},
	/* .get_data_path = */ []() {
		auto r = g_config_file->get_value("data_file_path");
		return r != nullptr ? r : PKGDATADIR "/http:" PKGDATADIR;
	},
	/* .get_context_num = */ []() { return g_context_num; },
	/* .get_host_ID = */ []() { return g_config_file->get_value("host_id"); },
	/* .get_prog_id = */ nullptr,
	/* .ndr_stack_alloc = */ pdu_processor_ndr_stack_alloc,
	/* .rpc_new_stack = */ pdu_processor_rpc_new_stack,
	/* .rpc_free_stack = */ pdu_processor_rpc_free_stack,
	/* PROC */ {},
	/* HPM_ */
	{
		/* .reg_intf = */ hpm_processor_register_interface,
		/* .get_req = */ hpm_processor_get_request,
		/* .get_auth_info = */ hpm_processor_get_auth_info,
		/* .get_conn = */ [](unsigned int id) {
			auto h = static_cast<http_context *>(http_parser_get_contexts_list()[id]);
			return &h->connection;
		},
		/* .write_response = */ [](unsigned int id, const void *b, size_t z) -> http_status {
			auto h = static_cast<http_context *>(http_parser_get_contexts_list()[id]);
			return h->stream_out.write(b, z) == STREAM_WRITE_OK ?
			       http_status::ok : http_status::none;
		},
		/* .wakeup_ctx = */ hpm_processor_wakeup_context,
		/* .activate_ctx = */ [](unsigned int id) {
			context_pool_activate_context(http_parser_get_contexts_list()[id]);
		},
		/* .set_ctx = */ http_parser_set_context,
		/* .set_ep_info = */ hpm_processor_set_ep_info,
	},
};

HPM_PLUGIN::~HPM_PLUGIN()
{
	PLUGIN_MAIN func;
	auto pplugin = this;
	if (pplugin->completed_init) {
		if (pplugin->file_name != nullptr)
			mlog(LV_INFO, "http_processor: unloading %s", pplugin->file_name);
		func = (PLUGIN_MAIN)pplugin->lib_main;
		if (func != nullptr)
			func(PLUGIN_FREE, server_funcs);
	}

	/* free the reference list */
	for (const auto &nd : list_reference)
		service_release(nd.service_name.c_str(), pplugin->file_name);
}

static int hpm_processor_load_library(const static_module &mod)
{
	HPM_PLUGIN plug;

	plug.lib_main = mod.efunc;
	plug.file_name = mod.path;
	g_plugin_list.push_back(std::move(plug));
	g_cur_plugin = &g_plugin_list.back();
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!g_cur_plugin->lib_main(PLUGIN_INIT, server_funcs) ||
	    g_cur_plugin->interface.preproc == nullptr ||
	    g_cur_plugin->interface.proc == nullptr ||
	    g_cur_plugin->interface.retr == nullptr) {
		mlog(LV_ERR, "http_processor: error executing the plugin's init "
			"function, or interface not registered in %s", g_cur_plugin->file_name);
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
		int ret = hpm_processor_load_library(i);
		if (ret != PLUGIN_LOAD_OK)
			return -1;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "http_processor: failed to allocate context list");
	return -1;
}

void hpm_processor_stop()
{
	while (!g_plugin_list.empty())
		g_plugin_list.pop_back();
	g_context_list.reset();
}

http_status hpm_processor_take_request(http_context *phttp)
{
	auto &rq = phttp->request;
	auto phpm_ctx = &g_context_list[phttp->context_id];
	phpm_ctx->b_preproc = false;
	for (const auto &p : g_plugin_list) {
		auto pplugin = &p;
		if (!pplugin->interface.preproc(phttp->context_id))
			continue;
		if (rq.content_len > g_rqbody_max_size) {
			phttp->log(LV_INFO, "rejected because Content-Length too large "
				"(%llu > %zu; http.cfg:http_rqbody_max_size)",
				static_cast<unsigned long long>(rq.content_len), g_rqbody_max_size);
			return http_status::bad_request;
		}
		if (rq.b_chunked || rq.content_len > g_rqbody_flush_size) {
			auto path = LOCAL_DISK_TMPDIR;
			if (mkdir(path, 0777) < 0 && errno != EEXIST) {
				mlog(LV_ERR, "E-2079: mkdir %s: %s", path, strerror(errno));
				return http_status::server_error;
			}
			auto ret = rq.body_fd.open_anon(path, O_RDWR | O_TRUNC);
			if (ret < 0) {
				mlog(LV_ERR, "E-2090: open(%s)[%s]: %s",
				        path, rq.body_fd.m_path.c_str(),
				        strerror(-ret));
				return http_status::server_error;
			}
			rq.posted_size = 0;
		} else {
			rq.body_fd.close();
		}
		if (rq.b_chunked) {
			rq.chunk_size = 0;
			rq.chunk_offset = 0;
		}
		rq.b_end = false;
		phpm_ctx->b_preproc = TRUE;
		phpm_ctx->pinterface = &pplugin->interface;
		return http_status::ok;
	}
	return http_status::none;
}

bool hpm_processor_is_in_charge(HTTP_CONTEXT *phttp)
{
	auto phpm_ctx = &g_context_list[phttp->context_id];
	return phpm_ctx->b_preproc;
}

/**
 * Move the HTTP request body to cache_fd, depending on size.
 */
http_status http_write_request(HTTP_CONTEXT *phttp)
{
	auto &rq = phttp->request;
	int size;
	int tmp_len;
	void *pbuff;
	char *ptoken;
	char tmp_buff[1024];
	
	if (rq.b_end)
		return http_status::ok;
	if (!rq.b_chunked && rq.body_fd < 0) {
		if (rq.content_len <= phttp->stream_in.get_total_length())
			rq.b_end = true;
		return http_status::ok;
	}
	if (!rq.b_chunked) {
		if (rq.posted_size + phttp->stream_in.get_total_length() < rq.content_len &&
		    phttp->stream_in.get_total_length() < g_rqbody_flush_size)
			return http_status::ok;
		size = STREAM_BLOCK_SIZE;
		while ((pbuff = phttp->stream_in.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
			if (rq.posted_size + size > rq.content_len) {
				tmp_len = rq.content_len - rq.posted_size;
				phttp->stream_in.rewind_read_ptr(size - tmp_len);
				rq.posted_size = rq.content_len;
			} else {
				rq.posted_size += size;
				tmp_len = size;
			}
			if (rq.body_fd >= 0 &&
			    write(rq.body_fd, pbuff, tmp_len) != tmp_len) {
				phttp->log(LV_DEBUG, "failed to"
					" write cache file: %s", strerror(errno));
				return http_status::service_unavailable;
			}
			if (rq.posted_size == rq.content_len) {
				rq.b_end = true;
				return http_status::ok;
			}
			size = STREAM_BLOCK_SIZE;
		}
		phttp->stream_in.clear();
		return http_status::ok;
	}
 CHUNK_BEGIN:
	if (rq.chunk_size == rq.chunk_offset) {
		size = phttp->stream_in.peek_buffer(tmp_buff, 1024);
		if (size < 5)
			return http_status::ok;
		if (0 == strncmp("0\r\n\r\n", tmp_buff, 5)) {
			phttp->stream_in.fwd_read_ptr(5);
			rq.b_end = true;
			return http_status::ok;
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
				return http_status::bad_request;
			}
			return http_status::ok;
		}
		*ptoken = '\0';
		rq.chunk_size = strtol(tmp_buff, nullptr, 16);
		if (rq.chunk_size == 0) {
			phttp->log(LV_DEBUG, "failed to "
				"parse chunked block for hpm_processor");
			return http_status::bad_request;
		}
		rq.chunk_offset = 0;
		tmp_len = ptoken + 2 - tmp_buff;
		phttp->stream_in.fwd_read_ptr(tmp_len);
	}
	size = STREAM_BLOCK_SIZE;
	while ((pbuff = phttp->stream_in.get_read_buf(reinterpret_cast<unsigned int *>(&size))) != nullptr) {
		if (rq.chunk_size >= size + rq.chunk_offset) {
			if (rq.body_fd >= 0 && write(rq.body_fd, pbuff, size) != size) {
				phttp->log(LV_DEBUG, "failed to "
					"write cache file: %s", strerror(errno));
				return http_status::service_unavailable;
			}
			rq.chunk_offset += size;
			rq.posted_size += size;
		} else {
			tmp_len = rq.chunk_size - rq.chunk_offset;
			if (rq.body_fd >= 0 && write(rq.body_fd, pbuff, tmp_len) != tmp_len) {
				phttp->log(LV_DEBUG, "failed to"
					" write cache file: %s", strerror(errno));
				return http_status::service_unavailable;
			}
			phttp->stream_in.rewind_read_ptr(size - tmp_len);
			rq.posted_size += tmp_len;
			rq.chunk_offset = rq.chunk_size;
		}
		if (rq.posted_size > g_rqbody_max_size) {
			phttp->log(LV_DEBUG, "chunked content"
				" length is too long for hpm_processor");
			return http_status::bad_request;
		}
		if (rq.chunk_offset == rq.chunk_size)
			goto CHUNK_BEGIN;
	}
	/*
	 * This is crap. Breaks processing of the next request if the client
	 * sent two requests with one network packet.
	 */
	phttp->stream_in.clear();
	return http_status::ok;
}

BOOL hpm_processor_proc(HTTP_CONTEXT *phttp)
{
	auto &rq = phttp->request;
	void *pcontent;
	struct stat node_stat;
	
	auto phpm_ctx = &g_context_list[phttp->context_id];
	if (rq.body_fd < 0) {
		if (rq.content_len == 0) {
			pcontent = NULL;
		} else {
			pcontent = malloc(rq.content_len);
			if (pcontent == nullptr)
				return FALSE;
			if (phttp->stream_in.peek_buffer(static_cast<char *>(pcontent),
			    rq.content_len) != rq.content_len) {
				free(pcontent);
				return FALSE;
			}
			phttp->stream_in.fwd_read_ptr(rq.content_len);
		}
	} else {
		if (fstat(rq.body_fd, &node_stat) != 0)
			return FALSE;
		pcontent = malloc(node_stat.st_size);
		if (pcontent == nullptr)
			return FALSE;
		lseek(rq.body_fd, 0, SEEK_SET);
		if (read(rq.body_fd, pcontent, node_stat.st_size) != node_stat.st_size) {
			free(pcontent);
			return FALSE;
		}
		rq.body_fd.close();
		rq.content_len = node_stat.st_size;
	}
	auto status = phpm_ctx->pinterface->proc(phttp->context_id,
	              pcontent, rq.content_len);
	rq.content_len = 0;
	if (pcontent != nullptr)
		free(pcontent);
	if (status >= http_status::bad_request) try {
		auto rsp = http_make_err_response(*phttp, status);
		if (phttp->stream_out.write(rsp.c_str(), rsp.size()) != STREAM_WRITE_OK)
			phttp->b_close = TRUE;
		return TRUE;
	} catch (const std::bad_alloc &) {
		phttp->b_close = TRUE;
		return TRUE;
	}
	return status != http_status::none ? TRUE : false;
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

void hpm_processor_insert_ctx(http_context *phttp)
{
	auto &rq = phttp->request;
	auto phpm_ctx = &g_context_list[phttp->context_id];
	if (phpm_ctx->pinterface->term != nullptr)
		phpm_ctx->pinterface->term(phttp->context_id);
	rq.body_fd.close();
	rq.content_len = 0;
	phpm_ctx->b_preproc = FALSE;
	phpm_ctx->pinterface = NULL;
}

void hpm_processor_trigger(enum plugin_op ev)
{
	for (auto &p : g_plugin_list) {
		g_cur_plugin = &p;
		p.lib_main(ev, server_funcs);
	}
	g_cur_plugin = nullptr;
}
