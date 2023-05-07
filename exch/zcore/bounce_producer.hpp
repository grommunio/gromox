#pragma once
#include <gromox/mapi_types.hpp>

struct MAIL;
struct message_content;

extern BOOL zcore_bouncer_make(const char *username, message_content *brief, const char *bounce_type, MAIL *);
