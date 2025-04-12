/*
 * Email Address Kids Lib Header
 */
#pragma once
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <vmime/mailbox.hpp>
#include <vmime/message.hpp>
#include <gromox/mapi_types.hpp>
#define MIME_NAME_LEN 80U
#define MIME_FIELD_LEN (64U * 1024)

struct attachment_list;

/**
 * All fields are always UTF-8 for consistency.
 */
struct GX_EXPORT EMAIL_ADDR {
	EMAIL_ADDR() = default;
	EMAIL_ADDR(const char *x) { parse(x); }
	EMAIL_ADDR(const vmime::mailbox &x) { set(x); }
	void clear();
	void set(const vmime::mailbox &);
	void parse(const char *);
	inline bool has_dispname() const { return *display_name != '\0'; }
	inline bool has_addr() const { return *local_part != '\0' && *domain != '\0'; }
	inline bool has_value() const { return has_dispname() || has_addr(); }

	char display_name[256], local_part[ULCLPART_SIZE], domain[UDOM_SIZE], addr[UADDR_SIZE];
};

struct GX_EXPORT kvpair {
	std::string name, value;
};
using MIME_FIELD = kvpair;

struct GX_EXPORT ENCODE_STRING {
    char encoding[32];
    char charset[32];
    char title[1024];
};

struct MAIL;
extern GX_EXPORT BOOL parse_uri(const char *uri_buff, char *parsed_uri);
extern GX_EXPORT size_t parse_mime_field(const char *, size_t, MIME_FIELD *);
extern GX_EXPORT void parse_field_value(const char *in_buff, long buff_len, char *value, long val_len, std::vector<kvpair> &);
extern GX_EXPORT void parse_mime_encode_string(const char *in, long inlen, ENCODE_STRING *);
extern GX_EXPORT int mutf7_to_utf8(const char *u7, size_t u7len, char *u8, size_t u8len);
extern GX_EXPORT int utf8_to_mutf7(const char *u8, size_t u8len, char *u7, size_t u7len);
extern GX_EXPORT int parse_imap_args(char *cmdline, int cmdlen, char **argv, int argmax);
extern GX_EXPORT BOOL parse_rfc822_timestamp(const char *str_time, time_t *ptime);
extern GX_EXPORT BOOL mime_string_to_utf8(const char *charset, const char *mime_string, char *out_string, size_t out_len);
extern GX_EXPORT void enriched_to_html(const char *enriched_txt,
	char *html, int max_len);
extern GX_EXPORT int html_to_plain(const void *inbuf, size_t inlen, cpid_t, std::string &outbuf);
extern GX_EXPORT char *plain_to_html(const char *rbuf);
extern GX_EXPORT ec_error_t html_init_library();
extern GX_EXPORT ec_error_t html_to_rtf(const void *in, size_t inlen, cpid_t, char **outp, size_t *outlen);
extern GX_EXPORT bool rtf_init_library();
extern GX_EXPORT bool rtf_to_html(const char *in, size_t inlen, const char *charset, std::string &out, attachment_list *);
extern GX_EXPORT bool rtfcp_uncompress(const BINARY *rtf, char *out, size_t *outlen);
extern GX_EXPORT BINARY *rtfcp_compress(const char *in, size_t in_len);
extern GX_EXPORT ssize_t rtfcp_uncompressed_size(const BINARY *);

namespace gromox {

extern GX_EXPORT ec_error_t cu_send_mail(MAIL &, const char *smtp_url, const char *sender, const std::vector<std::string> &rcpt);
extern GX_EXPORT ec_error_t cu_send_vmail(vmime::shared_ptr<vmime::message>, const char *smtp_url, const char *sender, const std::vector<std::string> &rcpt);

}
