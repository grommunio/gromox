#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/mem_file.hpp>

enum {
	FLUSH_WHOLE_MAIL = 0,
	FLUSH_PART_MAIL = 1,
};

enum {
	FLUSH_NONE = 0,
	FLUSH_RESULT_OK = 1,
	FLUSH_TEMP_FAIL = 2,
	FLUSH_PERMANENT_FAIL = 3,
};

enum {
	HT_LMTP = 1 << 0,
	HT_SMTP = 1 << 1,
};

struct STREAM;

struct ENVELOPE_INFO_BASE {
	char parsed_domain[UDOM_SIZE]; /* parsed domain according connection*/
	char hello_domain[UDOM_SIZE]; /* domain name after helo */
	char from[UADDR_SIZE]; /* envelope's from message */
	char username[UADDR_SIZE]; /* user name for login */
	MEM_FILE f_rcpt_to; /* envelope's rcpt to message */
	BOOL        is_login;          /* user is logged in */
};

struct FLUSH_INFO {
    int           flush_action; /* indicate flushing whole or part of mail */
    int           flush_result;
    int           flush_ID;
    void          *flush_ptr;     /* extended data pointer */
};

struct SMTP_CONTEXT;
struct FLUSH_ENTITY final {
	STREAM *pstream = nullptr;
	GENERIC_CONNECTION *pconnection = nullptr;
	FLUSH_INFO *pflusher = nullptr; /* the flusher for saving mail information */
	ENVELOPE_INFO_BASE *penvelope = nullptr;
	BOOL is_spam = false; /* whether the mail is spam */
	int context_ID = 0;
	unsigned int command_protocol = 0;
	SMTP_CONTEXT *pcontext = nullptr;
};

using CANCEL_FUNCTION = void (*)(FLUSH_ENTITY *);

extern "C" { /* dlsym */
extern GX_EXPORT BOOL FLH_LibMain(int reason, void **ptrs);
}
