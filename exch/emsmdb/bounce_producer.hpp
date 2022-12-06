#pragma once
#include <gromox/mapi_types.hpp>
struct MAIL;
struct MESSAGE_CONTENT;
extern BOOL emsmdb_bouncer_make(const char *username, MESSAGE_CONTENT *pbrief, const char *bounce_type, MAIL *);
