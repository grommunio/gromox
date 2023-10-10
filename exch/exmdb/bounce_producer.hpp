#pragma once
#include <sqlite3.h>
#include <vmime/message.hpp>

extern BOOL exmdb_bouncer_make_content(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, const char *bounce_type, std::string &subject, std::string &ct);
extern BOOL exmdb_bouncer_make(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, const char *bounce_type, vmime::shared_ptr<vmime::message> &);
