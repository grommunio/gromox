#pragma once
#include <ctime>

struct MAIL;

extern bool exml_bouncer_make(const char *host_id, const char *from, const char *rcpt, MAIL *orig, time_t orig_time, const char *bounce_type, MAIL *cur);
