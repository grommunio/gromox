#pragma once
#include <gromox/mail.hpp>

struct MAIL;
struct MESSAGE_CONTENT;

extern int bounce_producer_run(const char *, const char *, const char *);
extern BOOL emsmdb_bouncer_make(const char *username, MESSAGE_CONTENT *pbrief, const char *bounce_type, MAIL *);
