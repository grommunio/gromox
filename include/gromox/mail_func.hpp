/*
 * Email Address Kids Lib Header
 */
#pragma once
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <gromox/defs.h>
#include <gromox/mem_file.hpp>
#define MIME_NAME_LEN 80U
#define MIME_FIELD_LEN (64U * 1024)

/**
 * All fields are always UTF-8 for consistency.
 */
struct EMAIL_ADDR {
	inline bool has_dispname() const { return *display_name != '\0'; }
	inline bool has_addr() const { return *local_part != '\0' && *domain != '\0'; }
	inline bool has_value() const { return has_dispname() || has_addr(); }

	char display_name[256], local_part[ULCLPART_SIZE], domain[UDOM_SIZE];
};

struct MIME_FIELD {
	std::string name, value;
};

struct ENCODE_STRING {
    char encoding[32];
    char charset[32];
    char title[1024];
};

struct MAIL;
void parse_email_addr(EMAIL_ADDR *e_addr, const char *email);
void parse_mime_addr(EMAIL_ADDR *e_addr, const char *email);
BOOL parse_uri(const char *uri_buff, char *parsed_uri);
extern GX_EXPORT size_t parse_mime_field(char *, size_t, MIME_FIELD *);
extern GX_EXPORT void parse_field_value(const char *in_buff, long buff_len, char *value, long val_len, MEM_FILE *);
void parse_mime_encode_string(char *in_buff, long buff_len,
	ENCODE_STRING *encode_string);
char* find_url (char *buf, size_t howmuch, int *count);
int utf7_to_utf8 (const char *u7, size_t u7len, char *u8, size_t u8len);
int utf8_to_utf7 (const char *u8, size_t u8len, char *u7, size_t u7len);
int parse_imap_args(char *cmdline, int cmdlen, char **argv, int argmax);
time_t make_gmtime(struct tm *ptm);
void make_gmtm(time_t gm_time, struct tm *ptm);
BOOL parse_rfc822_timestamp(const char *str_time, time_t *ptime);
extern GX_EXPORT BOOL mime_string_to_utf8(const char *charset, const char *mime_string, char *out_string, size_t out_len);
void enriched_to_html(const char *enriched_txt,
	char *html, int max_len);
extern GX_EXPORT int html_to_plain(const void *inbuf, size_t inlen, std::string &outbuf);
extern GX_EXPORT char *plain_to_html(const char *rbuf);

namespace gromox {

extern GX_EXPORT ec_error_t cu_send_mail(MAIL &, const char *smtpprot, const char *smtphost, uint16_t smtpport, const char *sender, const std::vector<std::string> &rcpt);

}
