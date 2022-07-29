// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <gromox/clock.hpp>
#include <gromox/util.hpp>
#include "mh_common.hpp"

using namespace gromox;
using namespace hpm_mh;

MhContext::MhContext(int context_id) :
	ID(context_id), orig(*get_request(context_id)),
	auth_info(get_auth_info(context_id)), start_time(tp_now())
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
		if (tmp_len >= 11 && tmp_len <= 13) {
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
 * @param	maxlen	Buffer size
 * @param	status	Status code
 *
 * @return Number of bytes written
 */
static size_t binStatus(char* dest, size_t maxlen, uint32_t status)
{
	EXT_PUSH ext_push;
	if (!ext_push.init(dest, std::min(uint32_t(8), uint32_t(maxlen)), 0))
		return 0;
	return (ext_push.p_uint32(status) == EXT_ERR_SUCCESS ? 4 : 0) + (ext_push.p_uint32(0) == EXT_ERR_SUCCESS ? 4 : 0);
}

static constexpr char commonContent[] = "\r\n%s"; ///< Content template

namespace hpm_mh {

/**
 * @brief	Render message content
 *
 * @param	dest	Destination buffer
 * @param	now		Current time stamp
 * @param	start	Time stamp of request start
 * @return	Content length
 */
int render_content(char *dest, time_point now, time_point start)
{
	static constexpr char templ[] = "PROCESSING\r\nDONE\r\n"
		"X-ElapsedTime: %lld\r\n"
		"X-StartTime: %s\r\n\r\n";
	char dstring[128];
	rfc1123_dstring(dstring, arsizeof(dstring), time_point::clock::to_time_t(start));
	long long elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
	return sprintf(dest, templ, elapsed, dstring);
}

/**
 * @brief	Generate common headers
 *
 * @param	dest			Destination buffer
 * @param	maxlen			Buffer size
 * @param	requestType		Request type
 * @param requestId			Request ID
 * @param clientInfo		Client info
 * @param sid				Session ID
 * @param date				Date string
 *
 * @return	Total length
 */
size_t commonHeader(char *dest, size_t maxlen, const char *requestType,
    const char *requestId, const char *clientInfo, const char *sid, time_point date)
{
	static constexpr char templ[] = "HTTP/1.1 200 OK\r\n"
        "Cache-Control: private\r\n"
        "Content-Type: application/mapi-http\r\n"
        "X-RequestType: %s\r\n"
        "X-RequestId: %s\r\n"
        "X-ClientInfo: %s\r\n"
        "X-ResponseCode: 0\r\n"
        "X-PendingPeriod: %lld\r\n"
        "X-ExpirationInfo: %lld\r\n"
        "X-ServerApplication: Exchange/15.00.0847.4040\r\n"
        "Set-Cookie: sid=%s\r\n"
        "Date: %s\r\n";
	using namespace std::chrono;
	char dstring[128];
	rfc1123_dstring(dstring, arsizeof(dstring), gromox::time_point::clock::to_time_t(date));
	return snprintf(dest, maxlen, templ, requestType, requestId, clientInfo,
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

BOOL MhContext::error_responsecode(int response_code) const
{
	char dstring[128], text_buff[512], response_buff[4096];

	auto text_len = sprintf(text_buff,
		"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
		"<html><head>\r\n"
		"<title>MAPI OVER HTTP ERROR</title>\r\n"
		"</head><body>\r\n"
		"<h1>Diagnostic Information</h1>\r\n"
		"<p>%s</p>\r\n"
		"</body></html>\r\n", g_error_text[response_code]);
	rfc1123_dstring(dstring, arsizeof(dstring), time_point::clock::to_time_t(start_time));
	auto response_len = snprintf(response_buff,
		sizeof(response_buff),
		"HTTP/1.1 200 OK\r\n"
		"Cache-Control: private\r\n"
		"Content-Type: text/html\r\n"
		"X-ResponseCode: %d\r\n"
		"Content-Length: %d\r\n"
		"X-ServerApplication: Exchange/15.00.0847.4040\r\n"
		"Date: %s\r\n\r\n%s",
		response_code, text_len, dstring, text_buff);
	return write_response(ID, response_buff, response_len);
}

BOOL MhContext::ping_response() const
{
	char text_buff[256], response_buff[4096];
	auto text_len = render_content(text_buff, tp_now(), start_time);
	auto current_time = tp_now();
	size_t response_len = StringRenderer(response_buff, sizeof(response_buff))
	                      .add(commonHeader, "PING", request_id, client_info, session_string, current_time)
	                      .add("Content-Length: %d\r\n", text_len)
	                      .add(commonContent, text_buff);
	return write_response(ID, response_buff, static_cast<int>(response_len));
}

BOOL MhContext::failure_response(uint32_t status) const
{
	char text_buff[256], seq_string[GUIDSTR_SIZE], response_buff[4096];
	auto current_time = tp_now();
	auto text_len = render_content(text_buff, current_time, start_time)+8;
	sequence_guid.to_str(seq_string, arsizeof(seq_string));
	size_t response_len = StringRenderer(response_buff, sizeof(response_buff))
	                      .add(commonHeader, request_value, request_id, client_info, session_string, current_time)
	                      .add("Content-Length: %d\r\n", text_len)
	                      .add("Set-Cookie: sequence=%s\r\n", seq_string)
	                      .add(commonContent, text_buff)
	                      .add(binStatus, status);
	return write_response(ID, response_buff, static_cast<int>(response_len));
}

BOOL MhContext::normal_response() const
{
	char text_buff[256], seq_string[GUIDSTR_SIZE], chunk_string[32];
	char response_buff[4096];
	auto current_time = tp_now();

	sequence_guid.to_str(seq_string, arsizeof(seq_string));
	size_t response_len = StringRenderer(response_buff, sizeof(response_buff))
	                      .add(commonHeader, request_value, request_id, client_info, session_string, current_time)
	                      .add("Transfer-Encoding: chunked\r\n")
	                      .add("Set-Cookie: sequence=%s\r\n\r\n", seq_string);
	if (!write_response(ID, response_buff, static_cast<int>(response_len)))
		return false;
	auto text_len = render_content(text_buff, current_time, start_time);
	auto tmp_len = sprintf(chunk_string, "%x\r\n", text_len);
	if (!write_response(ID, chunk_string, tmp_len) ||
	    !write_response(ID, text_buff, text_len) ||
	    !write_response(ID, "\r\n", 2))
		return false;
	tmp_len = sprintf(chunk_string, "%x\r\n", epush->m_offset);
	if (!write_response(ID, chunk_string, tmp_len) ||
	    !write_response(ID, epush->m_udata, epush->m_offset) ||
	    !write_response(ID, "\r\n0\r\n\r\n", 7))
		return false;
	return TRUE;
}
