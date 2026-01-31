// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
/*
 *    listener is a module, which listen a certain port and if a connection is
 *    coming, pass the connection in connection filter module and if the
 *    connection is legal, construct a context to represent the connection and 
 *    throw it into contexts pool, or close the connection
 */
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <string>
#include <utility>
#include <libHX/io.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <gromox/contexts_pool.hpp>
#include <gromox/listener_ctx.hpp>
#include <gromox/util.hpp>
#include "http_parser.hpp"
#include "listener.hpp"
#include "resource.hpp"
#include "system_services.hpp"

using namespace gromox;

enum {
	M_UNENCRYPTED_CONN, M_TLS_CONN,
};

static listener_ctx http_listen_ctx;

int listener_init(const char *laddr, uint16_t port, uint16_t tls_port)
{
	if (port == 0 && tls_port == 0)
		return 0;
	http_listen_ctx.m_thread_name = "http_accept";
	if (port != 0 && http_listen_ctx.add_inet(laddr, port, M_UNENCRYPTED_CONN) != 0)
		return -1;
	if (tls_port != 0 && http_listen_ctx.add_inet(laddr, tls_port, M_TLS_CONN) != 0)
		return -1;
	return 0;
}

static int htls_thrwork(generic_connection &&conn)
{
	const bool use_tls = conn.mark == M_TLS_CONN;
	char buff[1024];
	
		if (fcntl(conn.sockd, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1408: fcntl: %s", strerror(errno));
		static const int flag = 1;
		if (setsockopt(conn.sockd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1409: setsockopt: %s", strerror(errno));
		auto pcontext = static_cast<HTTP_CONTEXT *>(contexts_pool_get_context(sctx_status::free));
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			mlog(LV_NOTICE, "Rejecting connection from [%s]:%hu: "
				"reached %d connections (http.cfg:context_num)",
				conn.client_addr, conn.client_port,
				contexts_pool_get_param(MAX_CONTEXTS_NUM));
			auto len = gx_snprintf(buff, std::size(buff), "HTTP/1.1 503 L-202 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				mlog(LV_WARN, "W-1984: write: %s", strerror(errno));
			return 0;
		}
		pcontext->type = sctx_status::constructing;
		/* pass the client ipaddr into the ipaddr filter */
		std::string reason;
		if (!system_services_judge_addr(conn.client_addr, reason)) {
			auto len = gx_snprintf(buff, std::size(buff), "HTTP/1.1 503 L-216 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			if (HXio_fullwrite(conn.sockd, buff, len) < 0)
				mlog(LV_WARN, "W-1983: write: %s", strerror(errno));
			mlog(LV_DEBUG, "Connection %s is denied by ipaddr filter: %s",
				conn.client_addr, reason.c_str());
			/* release the context */
			contexts_pool_insert(pcontext, sctx_status::free);
			return 0;
		}

		/* construct the context object */
		pcontext->connection = std::move(conn);
		pcontext->sched_stat = use_tls ? hsched_stat::initssl : hsched_stat::rdhead;
		/* 
		valid the context and wake up one thread if there are some threads
		block on the condition variable 
		*/
		pcontext->polling_mask = POLLING_READ;
		contexts_pool_insert(pcontext, sctx_status::polling);

	return 0;
}

int listener_trigger_accept()
{
	if (http_listen_ctx.empty())
		return 0;
	auto ret = http_listen_ctx.watch_start(g_httpmain_stop, htls_thrwork);
	if (ret != 0) {
		mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
		return -1;
	}
	return 0;
}

void listener_stop()
{
	http_listen_ctx.reset();
}
