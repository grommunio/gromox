#pragma once
#include <gromox/hook_common.h>

struct MAIL;
extern int mlex_bounce_init(const char *, const char *);
extern bool mlex_bouncer_make(const char *from, const char *rcpt, const vmime::message &orig, const char *bounce_type, MAIL *cur);
