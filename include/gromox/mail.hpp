#pragma once
#include <gromox/mime.hpp>
#include <gromox/stream.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/simple_tree.hpp>
#define	MIME_INSERT_BEFORE	SIMPLE_TREE_INSERT_BEFORE
#define MIME_INSERT_AFTER	SIMPLE_TREE_INSERT_AFTER
#define MIME_ADD_FIRST		SIMPLE_TREE_ADD_FIRST
#define	MIME_ADD_LAST		SIMPLE_TREE_ADD_LAST

typedef void (*MAIL_MIME_ENUM)(MIME*, void*);

typedef struct _MAIL{
	SIMPLE_TREE tree;
	MIME_POOL  *pmime_pool;
	char *buffer;
} MAIL;

#ifdef __cplusplus
extern "C" {
#endif

void mail_init(MAIL *pmail, MIME_POOL *pmime_pool);

void mail_clear(MAIL *pmail);

BOOL mail_retrieve(MAIL *pmail, char *in_buff, size_t length);
BOOL mail_serialize(MAIL *pmail, STREAM *pstream);

BOOL mail_to_file(MAIL *pmail, int fd);

BOOL mail_to_ssl(MAIL *pmail, SSL *ssl);

BOOL mail_check_dot(MAIL *pmail);

BOOL mail_transfer_dot(MAIL *pmail_src, MAIL *pmail_dst);

long mail_get_length(MAIL *pmail);

void mail_free(MAIL *pmail);

MIME* mail_add_head(MAIL *pmail);

MIME* mail_get_head(MAIL *pmail);

BOOL mail_get_charset(MAIL *pmail, char *charset);

int mail_get_digest(MAIL *pmail, size_t *poffset, char *pbuff, int length);
MIME* mail_add_child(MAIL *pmail, MIME *pmime_base, int opt);

void mail_enum_mime(MAIL *pmail, MAIL_MIME_ENUM enum_func, void *param);
BOOL mail_dup(MAIL *pmail_src, MAIL *pmail_dst);

#ifdef __cplusplus
}
#endif
