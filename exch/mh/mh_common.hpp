// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#pragma once
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <string>
#include <utility>
#include <libHX/string.h>
#include <gromox/clock.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/hpm_common.h>
#include <gromox/mapidefs.h>

namespace hpm_mh {

static constexpr auto
	response_pending_period = std::chrono::seconds(30),
	session_valid_interval = std::chrono::seconds(900),
	session_valid_extragrace = std::chrono::seconds(60);

struct session_data {
	session_data() = default;
	session_data(const GUID &sesguid, const GUID &seqguid,
	    const char *user, gromox::time_point exptime) :
		session_guid(sesguid), sequence_guid(seqguid), expire_time(exptime)
	{
		gx_strlcpy(username, user, UADDR_SIZE);
		HX_strlower(username);
	}
	NOMOVE(session_data);

	GUID session_guid{}, sequence_guid{};
	char username[UADDR_SIZE]{};
	gromox::time_point expire_time;
};

enum class resp_code {
	success, invalid_verb, invalid_ctx_cookie, missing_header, no_priv,
	invalid_rq_body, missing_cookie, invalid_seq, invalid_rq_type,
};

static constexpr const char *g_error_text[] = {
    "The request was properly formatted and accepted.",
    "The request has an invalid verb.",
    "The request has an invalid session context cookie.",
    "The request has a missing required header.",
    "The client has no privileges to the Session Context.",
    "The request body is invalid.",
    "The request is missing a required cookie.",
    "The request has violated the sequencing requirement"
        " of one request at a time per Session Context.",
    "Invalid request type for this endpoint.",
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern std::string render_content(gromox::time_point, gromox::time_point);
extern std::string commonHeader(const char *rq_type, const char *rq_id, const char *cl_info, const char *sid, gromox::time_point);

struct MhContext
{
	bool loadHeaders();
	bool getHeader(char*, size_t);

	BOOL unauthed() const;
	BOOL error_responsecode(resp_code) const;
	BOOL ping_response() const;
	BOOL failure_response(uint32_t) const;
	BOOL normal_response() const;
	BOOL notification_response() const;
	BOOL notification_response(uint32_t, uint32_t) const;

	int ID = 0;
	HTTP_REQUEST& orig;
	HTTP_AUTH_INFO auth_info{};

	gromox::time_point start_time;
	GUID session_guid{}, sequence_guid{};
	const char *request_id = nullptr, *client_info = nullptr, *cl_app = nullptr;
	char request_value[32]{}, session_string[64]{}, user_agent[128]{};
	size_t push_buff_size = 512 << 10;
	std::unique_ptr<char[]> push_buff;
	session_data *session = nullptr;

protected:
	MhContext(int);
	~MhContext() = default;
	NOMOVE(MhContext);

	EXT_PUSH *epush = nullptr;
};

}
