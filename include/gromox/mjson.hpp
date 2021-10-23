#pragma once
#include <memory>
#include <gromox/simple_tree.hpp>
#include <gromox/lib_buffer.hpp>
#include <gromox/mime_pool.hpp>
#define MJSON_MIME_NONE			0

#define MJSON_MIME_SINGLE		1

#define MJSON_MIME_MULTIPLE		2

struct MJSON_MIME {
	SIMPLE_TREE_NODE node;
	LIB_BUFFER  *ppool;
	int			mime_type;
	char        id[64];
	char 		ctype[256];
	char        encoding[32];
	char        charset[32];
	char        filename[256];
	char        cid[128];
	char        cntl[256];
	char        cntdspn[64];
	size_t      head;
	size_t      begin;
	size_t		length;
};

struct GX_EXPORT MJSON {
	MJSON() = default;
	MJSON(MJSON &&) = delete;
	MJSON(LIB_BUFFER *);
	~MJSON();
	void operator=(MJSON &&) = delete;

	SIMPLE_TREE tree{};
	LIB_BUFFER *ppool = nullptr;
	unsigned int uid = 0;
	int message_fd = -1;
	int read = 0, replied = 0, forwarded = 0, unsent = 0;
	int flag = 0, priority = 0;
	size_t size = 0;
	char path[256]{}, filename[128]{}, charset[32]{}, msgid[1024]{};
	char from[1024]{}, sender[1024]{}, reply[1024]{};
	char to[16*1024]{}, cc[16*1024]{}, inreply[1024]{}, subject[1024]{};
	char received[256]{}, date[256]{}, ref[4096]{};
	char notification[1024]{};
};

using MJSON_MIME_ENUM = void (*)(MJSON_MIME *, void *);

enum {
	MJSON_FLAG_READ,
	MJSON_FLAG_REPLIED,
	MJSON_FLAG_FORWARDED,
	MJSON_FLAG_UNSENT,
	MJSON_FLAG_FLAG
};

enum {
	MJSON_MIME_HEAD,
	MJSON_MIME_CONTENT,
	MJSON_MIME_ENTIRE
};

LIB_BUFFER* mjson_allocator_init(size_t max_size, BOOL thread_safe);
void mjson_allocator_free(LIB_BUFFER *pallocator);
void mjson_clear(MJSON *pjson);
BOOL mjson_retrieve(MJSON *pjson, char *digest_buff,
	int length, const char *path);
int mjson_fetch_structure(MJSON *pjson, const char *charset,
	BOOL b_ext, char *buff, int length);
int mjson_fetch_envelope(MJSON *pjson, const char *charset,
	char *buff, int length);
BOOL mjson_rfc822_check(MJSON *pjson);
extern GX_EXPORT BOOL mjson_rfc822_build(MJSON *, std::shared_ptr<MIME_POOL>, const char *storage_path);
BOOL mjson_rfc822_get(MJSON *pjson_base, MJSON *pjson,
	const char *storage_path, const char *id, char *mjson_id, char *mime_id);
int mjson_rfc822_fetch(MJSON *pjson, const char *storage_path,
	const char *charset, BOOL b_ext, char *buff, int length);
int mjson_seek_fd(MJSON *pjson, const char *id, int whence);
void mjson_enum_mime(MJSON *pjson, MJSON_MIME_ENUM enum_func, void *param);
const char* mjson_get_mail_filename(MJSON *pjson);
const char* mjson_get_mail_received(MJSON *pjson);
const char* mjson_get_mail_messageid(MJSON *pjson);
size_t mjson_get_mail_length(MJSON *pjson);
int mjson_get_mime_mtype(MJSON_MIME *pmime);
const char* mjson_get_mime_ctype(MJSON_MIME *pmime);
const char* mjson_get_mime_charset(MJSON_MIME *pmime);
const char* mjson_get_mime_filename(MJSON_MIME *pmime);
const char* mjson_get_mime_encoding(MJSON_MIME *pmime);
const char* mjson_get_mime_id(MJSON_MIME *pmime);
size_t mjson_get_mime_length(MJSON_MIME *pmime, int param);
size_t mjson_get_mime_offset(MJSON_MIME *pmime, int param);
MJSON_MIME *mjson_get_mime(MJSON *pjson, const char *id);
