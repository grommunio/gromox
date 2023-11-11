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

bool MhContext::loadHeaders()
{
	user_agent = orig.f_user_agent.c_str();
	const auto &m = orig.f_others;
	auto i = m.find("X-RequestId");
	request_id = i != m.end() ? i->second.c_str() : "";
	i = m.find("X-ClientInfo");
	client_info = i != m.end() ? i->second.c_str() : "";
	i = m.find("X-RequestType");
	gx_strlcpy(request_value, i != m.end() ? i->second.c_str() : "", std::size(request_value));
	i = m.find("X-ClientApplication");
	cl_app = i != m.end() ? i->second.c_str() : "";
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
	rfc1123_dstring(dstring, std::size(dstring), time_point::clock::to_time_t(start));
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
        "Date: {}\r\n";
	using namespace std::chrono;
	char dstring[128];
	rfc1123_dstring(dstring, std::size(dstring), gromox::time_point::clock::to_time_t(date));
	auto rs = fmt::format(templ, requestType, requestId, clientInfo,
	          static_cast<long long>(duration_cast<milliseconds>(response_pending_period).count()),
	          static_cast<long long>(duration_cast<milliseconds>(session_valid_interval).count()),
	          dstring);
	if (*sid != '\0')
		rs += fmt::format("Set-Cookie: sid={}\r\n", sid);
	return rs;
}

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

http_status MhContext::error_responsecode(resp_code response_code) const
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
	rfc1123_dstring(dstring, std::size(dstring), time_point::clock::to_time_t(start_time));
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

http_status MhContext::ping_response() const try
{
	auto current_time = tp_now();
	auto ct = render_content(current_time, start_time);
	auto rs = commonHeader("PING", request_id, client_info, session_string, current_time) +
	          fmt::format("Content-Length: {}\r\n", ct.size()) +
	          "\r\n" + std::move(ct);
	return write_response(ID, rs.c_str(), rs.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1142: ENOMEM");
	return http_status::none;
}

http_status MhContext::failure_response(uint32_t status) const try
{
	char stbuf[8];
	auto current_time = tp_now();
	auto ct = render_content(current_time, start_time);
	auto rs = commonHeader(request_value, request_id, client_info,
	          session_string, current_time) +
	          fmt::format("Content-Length: {}\r\n", ct.size());
	if (sequence_guid != GUID_NONE) {
		char txt[GUIDSTR_SIZE];
		sequence_guid.to_str(txt, std::size(txt));
		rs += fmt::format("Set-Cookie: sequence={}\r\n", txt);
	}
	rs += "\r\n" + std::move(ct) + binStatus(stbuf, status);
	return write_response(ID, rs.c_str(), rs.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1143: ENOMEM");
	return http_status::none;
}

http_status MhContext::normal_response() const try
{
	char chunk_string[32];
	auto current_time = tp_now();
	auto rs = commonHeader(request_value, request_id, client_info,
	          session_string, current_time) +
	          "Transfer-Encoding: chunked\r\n";
	if (sequence_guid != GUID_NONE) {
		char txt[GUIDSTR_SIZE];
		sequence_guid.to_str(txt, std::size(txt));
		rs += fmt::format("Set-Cookie: sequence={}\r\n", txt);
	}
	rs += "\r\n";
	auto wr = write_response(ID, rs.c_str(), rs.size());
	if (wr != http_status::ok)
		return wr;
	auto ct = render_content(current_time, start_time);
	auto tmp_len = sprintf(chunk_string, "%zx\r\n", ct.size());
	wr = write_response(ID, chunk_string, tmp_len);
	if (wr != http_status::ok)
		return wr;
	wr = write_response(ID, ct.c_str(), ct.size());
	if (wr != http_status::ok)
		return wr;
	wr = write_response(ID, "\r\n", 2);
	if (wr != http_status::ok)
		return wr;
	tmp_len = sprintf(chunk_string, "%x\r\n", epush->m_offset);
	wr = write_response(ID, chunk_string, tmp_len);
	if (wr != http_status::ok)
		return wr;
	wr = write_response(ID, epush->m_udata, epush->m_offset);
	if (wr != http_status::ok)
		return wr;
	return write_response(ID, "\r\n0\r\n\r\n", 7);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1144: ENOMEM");
	return http_status::none;
}
