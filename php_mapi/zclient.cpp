// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grommunio GmbH
// This file is part of Gromox.
#include "php.h"
#include <libHX/string.h>
#include <gromox/endian.hpp>
#include <gromox/paths.h>
#include <gromox/zcore_client.hpp>
#include <gromox/zcore_rpc.hpp>
#include "ext.hpp"
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <cerrno>
#include <cstdint>

static int zclient_connect()
{
	int sockd, len;
	struct sockaddr_un un;
	
	sockd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockd < 0) {
		return -1;
	}
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	zstrplus str_server(zend_string_init(ZEND_STRL("zcore_socket"), 0));
	auto sockpath = zend_ini_string(deconst("mapi.zcore_socket"), sizeof("mapi.zcore_socket") - 1, 0);
	gx_strlcpy(un.sun_path, sockpath != nullptr ? sockpath : PKGRUNDIR "/zcore.sock", sizeof(un.sun_path));
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
	if (connect(sockd, (struct sockaddr*)&un, len) < 0) {
		fprintf(stderr, "connect %s: %s\n", un.sun_path, strerror(errno));
		close(sockd);
		return -2;
	}
	return sockd;
}

static zend_bool zclient_read_socket(int sockd, BINARY &pbin)
{
	int read_len;
	uint32_t offset = 0;
	uint8_t resp_buff[5];
	
	pbin.pb = nullptr;
	while (1) {
		if (pbin.pb == nullptr) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin.cb = 1;
				pbin.pb = sta_malloc<uint8_t>(1);
				if (pbin.pb == nullptr)
					return 0;
				pbin.pb[0] = resp_buff[0];
				return 1;
			} else if (5 == read_len) {
				pbin.cb = le32p_to_cpu(resp_buff + 1) + 5;
				pbin.pb = sta_malloc<uint8_t>(pbin.cb);
				if (pbin.pb == nullptr) {
					pbin.cb = 0;
					return 0;
				}
				memcpy(pbin.pb, resp_buff, 5);
				offset = 5;
				if (pbin.cb == offset)
					return 1;
				continue;
			} else {
				return 0;
			}
		}
		read_len = read(sockd, pbin.pb + offset, pbin.cb - offset);
		if (read_len <= 0) {
			return 0;
		}
		offset += read_len;
		if (offset == pbin.cb)
			return 1;
	}
}

static zend_bool zclient_write_socket(int sockd, const BINARY &pbin)
{
	int written_len;
	uint32_t offset;
	
	offset = 0;
	while (1) {
		written_len = write(sockd, pbin.pb + offset, pbin.cb - offset);
		if (written_len <= 0) {
			return 0;
		}
		offset += written_len;
		if (offset == pbin.cb)
			return 1;
	}
}

zend_bool zclient_do_rpc(const zcreq *prequest, zcresp *presponse)
{
	BINARY tmp_bin;
	
	if (rpc_ext_push_request(prequest, &tmp_bin) != pack_result::ok)
		return 0;
	auto sockd = zclient_connect();
	if (sockd < 0) {
		ext_pack_free(tmp_bin.pb);
		return 0;
	}
	if (!zclient_write_socket(sockd, tmp_bin)) {
		ext_pack_free(tmp_bin.pb);
		close(sockd);
		return 0;
	}
	ext_pack_free(tmp_bin.pb);
	if (!zclient_read_socket(sockd, tmp_bin)) {
		close(sockd);
		return 0;
	}
	close(sockd);
	if (tmp_bin.cb < 5 ||
	    static_cast<zcore_response>(tmp_bin.pb[0]) != zcore_response::success) {
		if (NULL != tmp_bin.pb) {
			ext_pack_free(tmp_bin.pb);
		}
		return 0;
	}
	presponse->call_id = prequest->call_id;
	tmp_bin.cb -= 5;
	tmp_bin.pb += 5;
	if (rpc_ext_pull_response(&tmp_bin, presponse) != pack_result::ok) {
		ext_pack_free(tmp_bin.pb - 5);
		return 0;
	}
	ext_pack_free(tmp_bin.pb - 5);
	return 1;
}

uint32_t zclient_setpropval(GUID hsession, uint32_t hobject, uint32_t proptag,
    const void *pvalue)
{
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY propvals;
	
	propvals.count = 1;
	propvals.ppropval = &propval;
	propval.proptag = proptag;
	propval.pvalue = deconst(pvalue);
	return zclient_setpropvals(hsession, hobject, &propvals);
}

uint32_t zclient_getpropval(GUID hsession, uint32_t hobject, uint32_t proptag,
    void **ppvalue)
{
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	
	proptags.count = 1;
	proptags.pproptag = &proptag;
	auto result = zclient_getpropvals(hsession, hobject, &proptags, &propvals);
	if (result != ecSuccess)
		return result;
	*ppvalue = propvals.count == 0 ? nullptr : propvals.ppropval[0].pvalue;
	return ecSuccess;
}
