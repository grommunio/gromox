// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#pragma once
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
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
	session_valid_interval = std::chrono::seconds(900);

struct session_data {
	session_data() = default;
	session_data(const GUID &sesguid, const GUID &seqguid,
	    const char *user, gromox::time_point exptime) :
		session_guid(sesguid), sequence_guid(seqguid), expire_time(exptime)
	{
		gx_strlcpy(username, user, UADDR_SIZE);
		HX_strlower(username);
	}

	GUID session_guid{}, sequence_guid{};
	char username[UADDR_SIZE]{};
	gromox::time_point expire_time;
};

enum {
	RC_SUCCESS = 0,
	RC_UNKNOWN_FAILURE = 1,
	RC_INVALID_VERB = 2,
	RC_INVALID_PATH = 3,
	RC_INVALID_HEADER = 4,
	RC_INVALID_REQUEST_TYPE = 5,
	RC_INVALID_CONTEXT_COOKIE = 6,
	RC_MISSING_HEADER = 7,
	RC_ANONYMOUS_NOT_ALLOWED = 8,
	RC_TOO_LARGE = 9,
	RC_CONTEXT_NOT_FOUND = 10,
	RC_NO_PRIVILEGE = 11,
	RC_INVALID_REQUEST_BODY = 12,
	RC_MISSING_COOKIE = 13,
	RC_RESERVED = 14,
	RC_INVALID_SEQUENCE = 15,
	RC_ENDPOINT_DISABLED = 16,
	RC_INVALID_RESPONSE = 17,
	RC_ENDPOINT_SHUTTING_DOWN = 18,
};

static constexpr const char *g_error_text[] = {
    "The request was properly formatted and accepted.",
    "The request produced an unknown failure.",
    "The request has an invalid verb.",
   	"The request has an invalid path.",
    "The request has an invalid header.",
    "The request has an invalid X-RequestType header.",
    "The request has an invalid session context cookie.",
    "The request has a missing required header.",
    "The request is anonymous, but anonymous requests are not accepted.",
    "The request is too large.",
    "The Session Context is not found.",
    "The client has no privileges to the Session Context.",
    "The request body is invalid.",
    "The request is missing a required cookie.",
    "This value MUST be ignored by the client.",
    "The request has violated the sequencing requirement"
        " of one request at a time per Session Context.",
    "The endpoint is disabled.",
    "The response is invalid.",
    "The endpoint is shutting down."
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern int render_content(char *, gromox::time_point, gromox::time_point);
extern size_t commonHeader(char *, size_t, const char *, const char *, const char *, const char *, gromox::time_point);

struct MhContext
{
	bool loadHeaders();
	bool getHeader(char*, size_t);

	BOOL unauthed() const;
	BOOL error_responsecode(int) const;
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
	char request_id[256]{}, client_info[256]{};
	char request_value[32]{}, session_string[64]{}, push_buff[0x80000];
	session_data *session = nullptr;

protected:
	MhContext(int);
	~MhContext() = default;
	NOMOVE(MhContext);

	EXT_PUSH *epush = nullptr;
};

///////////////////////////////////////////////////////////////////////////////


/**
 * @brief	Utility class to easily generate strings from templates.
 */
class StringRenderer
{
public:
	StringRenderer(char* dest, size_t maxlen) noexcept;

	template<typename...Params, typename... Args>
	StringRenderer& add(size_t(&func)(char*, size_t, Params...), Args&&...);

	StringRenderer& add(const char* format, ...) __attribute__((format(printf, 2, 3)));

	operator size_t() const noexcept;
private:
	char *start, *current, *end;
};


/**
 * @brief	Constructor
 *
 * @param	Destination buffer
 * @param	Size of the destination buffer
 */
inline StringRenderer::StringRenderer(char* dest, size_t maxlen) noexcept
    : start(dest), current(dest), end(dest+maxlen)
{*dest = '\0';}

/**
 * @brief	Append template (printf style)
 *
 * @param	Format string
 *
 * @return Reference to string renderer
 */
inline StringRenderer& StringRenderer::add(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	current += vsnprintf(current, end-current, format, args);
	va_end(args);
	return *this;
}

/**
 * @brief	Append template (generator function)
 *
 * The generator function must take at least the destination buffer and
 * maximum length as arguments and return the number of bytes written
 * to the buffer (excluding the terminating null character).
 *
 * @param	func	Function generating content.
 * @param	args	Arguments forwarded to function
 *
 * @tparam	Sig		Function argument types
 * @tparam	Arg		Argument types (must be compatible with function argument types)
 *
 * @return	Reference to string renderer
 */
template<typename...Params, typename... Args>
inline StringRenderer& StringRenderer::add(size_t(&func)(char*, size_t, Params...), Args&&... args)
{
	current += (*func)(current, end-current, std::forward<Args>(args)...);
	return *this;
}

/**
 * @brief	Convert renderer to number of bytes written (excluding terminating null)
 */
inline StringRenderer::operator size_t() const noexcept
{return current-start;}

}
