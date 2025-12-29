#pragma once
#include <cstdint>
#include <string>
#include <vmime/message.hpp>

struct db_conn;
extern bool exmdb_bouncer_make_content(const char *from, const char *rcpt, const db_conn &, uint64_t msg_id, const char *bounce_type, std::string &subject, std::string &ct);
extern bool exmdb_bouncer_make(const char *from, const char *rcpt, const db_conn &, uint64_t msg_id, const char *bounce_type, vmime::shared_ptr<vmime::message> &);
