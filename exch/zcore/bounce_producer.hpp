#pragma once
#include <gromox/mapi_types.hpp>

struct MAIL;
struct MESSAGE_CONTENT;

extern BOOL zcore_bouncer_make(const char *username, MESSAGE_CONTENT *brief, const char *bounce_type, MAIL *);
