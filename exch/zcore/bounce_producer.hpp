#pragma once
#include <gromox/mapi_types.hpp>

struct MAIL;
struct MESSAGE_CONTENT;

extern int bounce_producer_run(const char *, const char *, const char *);
extern BOOL bounce_producer_make(const char *username, MESSAGE_CONTENT *brief, const char *bounce_type, MAIL *);
