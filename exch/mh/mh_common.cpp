// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <fmt/core.h>
#include <gromox/clock.hpp>
#include <gromox/util.hpp>
#include "mh_common.hpp"

using namespace gromox;
using namespace hpm_mh;

MhContext::MhContext(int context_id) :
	ID(context_id), orig(*get_request(context_id)),
	auth_info(get_auth_info(context_id)), start_time(tp_now()),
	push_buff(std::make_unique<char[]>(push_buff_size))
{}

bool MhContext::getHeader(char* dest, size_t maxlen)
{
	uint32_t tmp_len;
	orig.f_others.read(&tmp_len, sizeof(uint32_t));
	if (tmp_len >= maxlen)
		 return false;
	orig.f_others.read(dest, tmp_len);
	dest[tmp_len] = '\0';
	return true;
}

bool MhContext::loadHeaders()
{
	uint32_t tmp_len;
	char tmp_buff[1024];
	while (orig.f_others.read(&tmp_len, sizeof(uint32_t)) != MEM_END_OF_FILE) {
		if (tmp_len >= 10 && tmp_len <= 19) {
			orig.f_others.read(tmp_buff, tmp_len);
			if (strncasecmp(tmp_buff, "X-RequestId", 11) == 0) {
				if (!getHeader(request_id, arsizeof(request_id)))
					return false;
				continue;
			} else if (strncasecmp(tmp_buff, "X-ClientInfo", 12) == 0) {
				if (!getHeader(client_info, arsizeof(client_info)))
					return false;
				continue;
			} else if (strncasecmp(tmp_buff, "X-RequestType", 13) == 0) {
				if (!getHeader(request_value, arsizeof(request_value)))
					return false;
				continue;
			} else if (strncasecmp(tmp_buff, "User-Agent", 10) == 0) {
				if (!getHeader(user_agent, std::size(user_agent)))
					return false;
				continue;
			} else if (strncasecmp(tmp_buff, "X-ClientApplication", 19) == 0) {
				if (!getHeader(cl_app, std::size(cl_app)))
					return false;
				continue;
			}
		} else
			orig.f_others.seek(MEM_FILE_READ_PTR, tmp_len, MEM_FILE_SEEK_CUR);
		orig.f_others.read(&tmp_len, sizeof(uint32_t));
		orig.f_others.seek(MEM_FILE_READ_PTR, tmp_len, MEM_FILE_SEEK_CUR);
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief	Write binary status code
 *
 * @param	dest	Destination buffer
 * @param	status	Status code
 */
static char *binStatus(char (&dest)[8], uint32_t status)
{
	EXT_PUSH ext_push;
	if (!ext_push.init(dest, sizeof(dest), 0) ||
	    ext_push.p_uint32(status) != pack_result::success ||
	    ext_push.p_uint32(status) != pack_result::success)
		/* ignore */;
	return dest;
}

static constexpr char commonContent[] = "\r\n%s"; ///< Content template

namespace hpm_mh {

/**
 * @brief	Render message content
 *
 * @param	start	Time stamp of request start
 */
std::string render_content(time_point now, time_point start)
{
	static constexpr char templ[] = "PROCESSING\r\nDONE\r\n"
		"X-ElapsedTime: {}\r\n"
		"X-StartTime: {}\r\n\r\n";
	char dstring[128];
	rfc1123_dstring(dstring, arsizeof(dstring), time_point::clock::to_time_t(start));
	long long elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
	return fmt::format(templ, elapsed, dstring);
}

/**
 * @brief	Generate common headers
 *
 * @param	requestType		Request type
 * @param requestId			Request ID
 * @param clientInfo		Client info
 * @param sid				Session ID
 * @param date				Date string
 */
std::string commonHeader(const char *requestType, const char *requestId,
    const char *clientInfo, const char *sid, time_point date)
{
	static constexpr char templ[] = "HTTP/1.1 200 OK\r\n"
        "Cache-Control: private\r\n"
        "Content-Type: application/mapi-http\r\n"
        "X-RequestType: {}\r\n"
        "X-RequestId: {}\r\n"
        "X-ClientInfo: {}\r\n"
        "X-ResponseCode: 0\r\n"
        "X-PendingPeriod: {}\r\n"
        "X-ExpirationInfo: {}\r\n"
        "X-ServerApplication: Exchange/15.00.0847.4040\r\n"
        "Set-Cookie: sid={}\r\n"
        "Date: {}\r\n";
	using namespace std::chrono;
	char dstring[128];
	rfc1123_dstring(dstring, arsizeof(dstring), gromox::time_point::clock::to_time_t(date));
	return fmt::format(templ, requestType, requestId, clientInfo,
	                static_cast<long long>(duration_cast<milliseconds>(response_pending_period).count()),
	                static_cast<long long>(duration_cast<milliseconds>(session_valid_interval).count()),
	                sid, dstring);
}

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL MhContext::unauthed() const
{
	char dstring[128], tmp_buff[1024];
	rfc1123_dstring(dstring, arsizeof(dstring), time_point::clock::to_time_t(start_time));
	auto tmp_len = snprintf(tmp_buff, sizeof(tmp_buff),
		"HTTP/1.1 401 Unauthorized\r\n"
		"Date: %s\r\n"
		"Content-Length: 0\r\n"
		"Connection: Keep-Alive\r\n"
		"WWW-Authenticate: Basic realm=\"msrpc realm\"\r\n"
		"\r\n", dstring);
	return write_response(ID, tmp_buff, tmp_len);
}

BOOL MhContext::error_responsecode(resp_code response_code) const
{
	char dstring[128], text_buff[512], response_buff[4096];

	auto text_len = sprintf(text_buff,
		"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
		"<html><head>\r\n"
		"<title>MAPI OVER HTTP ERROR</title>\r\n"
		"</head><body>\r\n"
		"<h1>Diagnostic Information</h1>\r\n"
		"<p>%s</p>\r\n"
		"</body></html>\r\n", g_error_text[static_cast<unsigned int>(response_code)]);
	rfc1123_dstring(dstring, arsizeof(dstring), time_point::clock::to_time_t(start_time));
	auto response_len = snprintf(response_buff,
		sizeof(response_buff),
		"HTTP/1.1 200 OK\r\n"
		"Cache-Control: private\r\n"
		"Content-Type: text/html\r\n"
		"X-ResponseCode: %u\r\n"
		"Content-Length: %d\r\n"
		"X-ServerApplication: Exchange/15.00.0847.4040\r\n"
		"Date: %s\r\n\r\n%s",
		static_cast<unsigned int>(response_code), text_len, dstring, text_buff);
	return write_response(ID, response_buff, response_len);
}

BOOL MhContext::ping_response() const try
{
	auto current_time = tp_now();
	auto ct = render_content(current_time, start_time);
	auto rs = commonHeader("PING", request_id, client_info, session_string, current_time) +
	          fmt::format("Content-Length: {}\r\n", ct.size()) +
	          "\r\n" + std::move(ct);
	return write_response(ID, rs.c_str(), rs.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1142: ENOMEM");
	return false;
}

BOOL MhContext::failure_response(uint32_t status) const try
{
	char stbuf[8], seq_string[GUIDSTR_SIZE];
	auto current_time = tp_now();
	auto ct = render_content(current_time, start_time);
	sequence_guid.to_str(seq_string, arsizeof(seq_string));
	auto rs = commonHeader(request_value, request_id, client_info,
	          session_string, current_time) +
	          fmt::format("Content-Length: {}\r\n", ct.size()) +
	          fmt::format("Set-Cookie: sequence={}\r\n", seq_string) +
	          "\r\n" + std::move(ct) + binStatus(stbuf, status);
	return write_response(ID, rs.c_str(), rs.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1143: ENOMEM");
	return false;
}

BOOL MhContext::normal_response() const try
{
	char seq_string[GUIDSTR_SIZE], chunk_string[32];
	auto current_time = tp_now();

	sequence_guid.to_str(seq_string, arsizeof(seq_string));
	auto rs = commonHeader(request_value, request_id, client_info,
	          session_string, current_time) +
	          "Transfer-Encoding: chunked\r\n" +
	          fmt::format("Set-Cookie: sequence={}\r\n\r\n", seq_string);
	if (!write_response(ID, rs.c_str(), rs.size()))
		return false;
	auto ct = render_content(current_time, start_time);
	auto tmp_len = sprintf(chunk_string, "%zx\r\n", ct.size());
	if (!write_response(ID, chunk_string, tmp_len) ||
	    !write_response(ID, ct.c_str(), ct.size()) ||
	    !write_response(ID, "\r\n", 2))
		return false;
	tmp_len = sprintf(chunk_string, "%x\r\n", epush->m_offset);
	if (!write_response(ID, chunk_string, tmp_len) ||
	    !write_response(ID, epush->m_udata, epush->m_offset) ||
	    !write_response(ID, "\r\n0\r\n\r\n", 7))
		return false;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1144: ENOMEM");
	return false;
}
