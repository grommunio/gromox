#pragma once
#include <gromox/simple_tree.hpp>
#include <gromox/lib_buffer.hpp>
#include <gromox/mime_pool.hpp>
#define MJSON_MIME_NONE			0

#define MJSON_MIME_SINGLE		1

#define MJSON_MIME_MULTIPLE		2

typedef struct _MJSON_MIME {
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
} MJSON_MIME;


typedef struct _MJSON{
	SIMPLE_TREE tree;
	LIB_BUFFER  *ppool;
	unsigned int uid;
	char         path[256];
	int          message_fd;
	char         filename[128];
	char         charset[32];
	char         msgid[1024];
	char         from[1024];
	char         sender[1024];
	char         reply[1024];
	char         to[16*1024];
	char         cc[16*1024];
	char         inreply[1024];
	char         subject[1024];
	char         received[256];
	char         date[256];
	char         ref[4096];
	int          read;
	int          replied;
	int          forwarded;
	int          unsent;
	int          flag;
	int          priority;
	char         notification[1024];
	size_t       size;
} MJSON;

typedef void (*MJSON_MIME_ENUM)(MJSON_MIME*, void*);

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


#ifdef __cplusplus
extern "C" {
#endif

LIB_BUFFER* mjson_allocator_init(size_t max_size, BOOL thread_safe);

void mjson_allocator_free(LIB_BUFFER *pallocator);

void mjson_init(MJSON *pjson, LIB_BUFFER *ppool);

void mjson_clear(MJSON *pjson);

BOOL mjson_retrieve(MJSON *pjson, char *digest_buff,
	int length, const char *path);

void mjson_free(MJSON *pjson);

int mjson_fetch_structure(MJSON *pjson, const char *charset,
	BOOL b_ext, char *buff, int length);

int mjson_fetch_envelope(MJSON *pjson, const char *charset,
	char *buff, int length);

BOOL mjson_rfc822_check(MJSON *pjson);

BOOL mjson_rfc822_build(MJSON *pjson, MIME_POOL *ppool,
	const char *storage_path);

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


#ifdef __cplusplus
}
#endif
