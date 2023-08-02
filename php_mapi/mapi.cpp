// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2022 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <climits>
#include <cstdint>
#include <cstdio>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/safeint.hpp>
#include <gromox/scope.hpp>
#include <gromox/timezone.hpp>
#include <gromox/util.hpp>
#include <gromox/zcore_client.hpp>
#include <gromox/zcore_rpc.hpp>
#include "php.h"
#include <memory>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"
#include <sys/wait.h>
#include "ext.hpp"
#if PHP_MAJOR_VERSION >= 8
#	include "mapi_arginfo.hpp"
#endif
#include "type_conversion.hpp"
#ifdef ZTS
#	include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(mapi)
	/* this is the global hresult value, used in *every* php mapi function */
	unsigned long hr;
	/* This is a reference to the MAPI exception class */
	zend_class_entry *exception_ce;
	zend_bool exceptions_enabled;
ZEND_END_MODULE_GLOBALS(mapi)

#ifdef ZTS
#	define MAPI_G(v) TSRMG(mapi_globals_id, zend_mapi_globals *, v)
#else
#	define MAPI_G(v) (mapi_globals.v)
#endif
#define PHP_MAPI_EXTNAME "mapi"

#define ZEND_FETCH_RESOURCE(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type) \
	do { \
		rsrc = static_cast<rsrc_type>(zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type)); \
		if (rsrc == nullptr) do { \
			RETURN_FALSE; \
		} while (false); \
	} while (false)
/* PHP macros do not have proper do..while guards on their own */
#define RETVAL_RG(obj, category) \
	do { RETVAL_RES(zend_register_resource(obj, category)); } while (false)
#define pthrow(rv) \
	do { \
		MAPI_G(hr) = (rv); \
		if (MAPI_G(exceptions_enabled)) \
			zend_throw_exception(MAPI_G(exception_ce), mapi_strerror(MAPI_G(hr)), MAPI_G(hr)); \
		RETVAL_FALSE; \
		return; \
	} while (false)

#define ZCL_MEMORY \
	palloc_tls_init(); \
	auto f_memrelease = make_scope_exit(palloc_tls_free);

using namespace gromox;

namespace {

struct MAPI_RESOURCE {
	uint8_t type;
	GUID hsession;
	uint32_t hobject;
};

struct STREAM_OBJECT {
	GUID hsession;
	uint32_t hparent;
	uint32_t proptag;
	uint32_t seek_offset;
	BINARY content_bin;
};

struct ICS_IMPORT_CTX {
	GUID hsession;
	uint32_t hobject;
	uint8_t ics_type;
	zval pztarget_obj;
};

struct ICS_EXPORT_CTX {
	GUID hsession;
	uint32_t hobject;
	uint8_t ics_type;
	zval pztarget_obj;
	zend_bool b_changed;
	uint32_t progress;
	uint32_t sync_steps;
	uint32_t total_steps;
};

}

#if PHP_MAJOR_VERSION < 8
ZEND_BEGIN_ARG_INFO(first_arg_force_ref, 0)
	ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(second_arg_force_ref, 0)
	ZEND_ARG_PASS_INFO(0)
	ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(fourth_arg_force_ref, 0)
	ZEND_ARG_PASS_INFO(0)
	ZEND_ARG_PASS_INFO(0)
	ZEND_ARG_PASS_INFO(0)
	ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO()
#endif

ZEND_DECLARE_MODULE_GLOBALS(mapi)

static void php_mapi_init_globals(zend_mapi_globals *)
{
}

static constexpr GUID GUID_NONE{};
static constexpr char
	name_mapi_session[] = "MAPI Session",
	name_mapi_table[] = "MAPI Table",
	name_mapi_msgstore[] = "MAPI Message Store",
	name_mapi_addressbook[] = "MAPI Addressbook",
	name_mapi_mailuser[] = "MAPI Mail User",
	name_mapi_distlist[] = "MAPI Distribution List",
	name_mapi_abcont[] = "MAPI Addressbook Container",
	name_mapi_folder[] = "MAPI Folder",
	name_mapi_message[] = "MAPI Message",
	name_mapi_attachment[] = "MAPI Attachment",
	name_mapi_property[] = "MAPI Property",
	name_stream[] = "IStream Interface",
	name_mapi_exportchanges[] = "ICS Export Changes",
	name_mapi_advisesink[] = "MAPI Advise sink",
	name_mapi_importhierarchychanges[] = "ICS Import Hierarchy Changes",
	name_mapi_importcontentschanges[] = "ICS Import Contents Changes";

static int le_stream;
static int le_mapi_table;
static int le_mapi_abcont;
static int le_mapi_folder;
static int le_mapi_message;
static int le_mapi_session;
static int le_mapi_addressbook;
static int le_mapi_msgstore;
static int le_mapi_mailuser;
static int le_mapi_distlist;
static int le_mapi_property;
static int le_mapi_advisesink;
static int le_mapi_attachment;
static int le_mapi_exportchanges;
static int le_mapi_importcontentschanges;
static int le_mapi_importhierarchychanges;

static zend_bool stream_object_set_length(
	STREAM_OBJECT *pstream, uint32_t length)
{
	uint8_t *pdata;
	
	/* always leave trail null for string */
	if (NULL == pstream->content_bin.pb) {
		pstream->content_bin.pb = sta_malloc<uint8_t>(length + 1);
		if (pstream->content_bin.pb == nullptr)
			return 0;
		memset(pstream->content_bin.pb, 0, length + 1);
	} else if (length > pstream->content_bin.cb) {
		pdata = sta_realloc<uint8_t>(pstream->content_bin.pb, length + 1);
		if (pdata == nullptr)
			return 0;
		pstream->content_bin.pb = pdata;
		memset(pstream->content_bin.pb
			+ pstream->content_bin.cb, 0,
			length + 1 - pstream->content_bin.cb);
	} else {
		if (pstream->seek_offset > length)
			pstream->seek_offset = length;
		pstream->content_bin.pb[length] = '\0';
	}
	pstream->content_bin.cb = length;
	return 1;
}

static void* stream_object_read(STREAM_OBJECT *pstream,
	uint32_t buf_len, uint32_t *pactual_bytes)
{
	void *paddress;
	uint32_t length;
	
	if (NULL == pstream->content_bin.pb ||
		pstream->content_bin.cb <= pstream->seek_offset) {
		*pactual_bytes = 0;
		return NULL;
	}
	if (pstream->seek_offset + buf_len > pstream->content_bin.cb)
		length = pstream->content_bin.cb - pstream->seek_offset;
	else
		length = buf_len;
	paddress = pstream->content_bin.pb + pstream->seek_offset;
	pstream->seek_offset += length;
	*pactual_bytes = length;
	return paddress;
}

static uint32_t stream_object_write(STREAM_OBJECT *pstream,
	void *pbuff, uint32_t buf_len)
{	
	if (NULL == pstream->content_bin.pb) {
		pstream->content_bin.pb = sta_malloc<uint8_t>(buf_len);
		if (pstream->content_bin.pb == nullptr)
			return 0;
		pstream->seek_offset = 0;
	}
	if (pstream->seek_offset + buf_len > pstream->content_bin.cb &&
	    !stream_object_set_length(pstream, pstream->seek_offset + buf_len))
		return 0;
	memcpy(pstream->content_bin.pb +
		pstream->seek_offset, pbuff, buf_len);
	pstream->seek_offset += buf_len;
	return buf_len;
}

static void stream_object_set_parent(STREAM_OBJECT *pstream,
	GUID hsession, uint32_t hparent, uint32_t proptag)
{
	pstream->hsession = hsession;
	pstream->hparent = hparent;
	pstream->proptag = proptag;
}

static uint32_t stream_object_get_length(STREAM_OBJECT *pstream)
{
	return pstream->content_bin.cb;
}

static zend_bool stream_object_seek(STREAM_OBJECT *pstream,
	uint32_t flags, int32_t offset)
{	
	uint32_t origin;
	switch (flags) {
		case STREAM_SEEK_SET: origin = 0; break;
		case STREAM_SEEK_CUR: origin = pstream->seek_offset; break;
		case STREAM_SEEK_END: origin = pstream->content_bin.cb; break;
		default: return 0;
	}
	auto newoff = safe_add_s(origin, offset);
	if (newoff > pstream->content_bin.cb && !stream_object_set_length(pstream, offset))
		return 0;
	pstream->seek_offset = newoff;
	return 1;
}

static void stream_object_reset(STREAM_OBJECT *pstream)
{
	if (pstream->content_bin.pb != nullptr)
		efree(pstream->content_bin.pb);
	memset(pstream, 0, sizeof(STREAM_OBJECT));
}

static void stream_object_free(STREAM_OBJECT *pstream)
{
	if (pstream->content_bin.pb != nullptr)
		efree(pstream->content_bin.pb);
	efree(pstream);
}

static uint32_t stream_object_commit(STREAM_OBJECT *pstream)
{
	if (pstream->hsession == GUID_NONE || pstream->hparent == 0 || pstream->proptag == 0)
		return ecInvalidParam;
	switch (PROP_TYPE(pstream->proptag)) {
	case PT_BINARY:
		return zclient_setpropval(
			pstream->hsession, pstream->hparent,
			pstream->proptag, &pstream->content_bin);
	case PT_STRING8:
	case PT_UNICODE:
		return zclient_setpropval(pstream->hsession,
			pstream->hparent,
			CHANGE_PROP_TYPE(pstream->proptag, PT_UNICODE),
			pstream->content_bin.pb);
	default:
		return ecInvalidParam;
	}
}

static BINARY* stream_object_get_content(STREAM_OBJECT *pstream)
{
	return &pstream->content_bin;
}

static void notif_sink_free(NOTIF_SINK *psink)
{
	if (NULL != psink->padvise) {
		if (psink->hsession != GUID_NONE)
			for (unsigned int i = 0; i < psink->count; ++i)
				zclient_unadvise(psink->hsession,
					psink->padvise[i].hstore, psink->padvise[i].sub_id);
		efree(psink->padvise);
	}
	efree(psink);
}

static uint32_t notif_sink_timedwait(NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications)
{
	if (0 == psink->count) {
		pnotifications->count = 0;
		pnotifications->ppnotification = NULL;
		return ecSuccess;
	}
	return zclient_notifdequeue(
		psink, timeval, pnotifications);
}

static zend_bool notif_sink_add_subscription(NOTIF_SINK *psink,
	GUID hsession, uint32_t hstore, uint32_t sub_id)
{
	auto padvise = psink->padvise == nullptr ?st_malloc<ADVISE_INFO>() :
	               sta_realloc<ADVISE_INFO>(psink->padvise, psink->count + 1);
	if (padvise == nullptr)
		return 0;
	if (psink->hsession == GUID_NONE)
		psink->hsession = hsession;
	else if (psink->hsession != hsession)
		return 0;
	padvise[psink->count].hstore = hstore;
	padvise[psink->count++].sub_id = sub_id;
	psink->padvise = padvise;
	return 1;
}

static void mapi_resource_dtor(zend_resource *rsrc)
{
	ZCL_MEMORY;
	if (rsrc->ptr == nullptr)
		return;
	auto presource = static_cast<MAPI_RESOURCE *>(rsrc->ptr);
	if (presource->hobject != 0)
		zclient_unloadobject(
			presource->hsession, presource->hobject);
	efree(presource);
}

static void notif_sink_dtor(zend_resource *rsrc)
{
	if (rsrc->ptr != nullptr)
		notif_sink_free(static_cast<NOTIF_SINK *>(rsrc->ptr));
}

static void stream_object_dtor(zend_resource *rsrc)
{
	if (rsrc->ptr != nullptr)
		stream_object_free(static_cast<STREAM_OBJECT *>(rsrc->ptr));
}

static void ics_import_ctx_dtor(zend_resource *rsrc)
{	
	if (rsrc->ptr == nullptr)
		return;
	auto pctx = static_cast<ICS_IMPORT_CTX *>(rsrc->ptr);
	zval_ptr_dtor(&pctx->pztarget_obj);
	if (pctx->hobject != 0)
		zclient_unloadobject(
			pctx->hsession, pctx->hobject);
	efree(pctx);
}

static void ics_export_ctx_dtor(zend_resource *rsrc)
{
	if (rsrc->ptr == nullptr)
		return;
	auto pctx = static_cast<ICS_EXPORT_CTX *>(rsrc->ptr);
	zval_ptr_dtor(&pctx->pztarget_obj);
	if (pctx->hobject != 0)
		zclient_unloadobject(
			pctx->hsession, pctx->hobject);
	efree(pctx);
}

PHP_INI_BEGIN()
	PHP_INI_ENTRY("mapi.zcore_socket", NULL, PHP_INI_PERDIR, NULL)
PHP_INI_END()

static PHP_MINIT_FUNCTION(mapi)
{
	le_mapi_session = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_session, module_number);
	le_mapi_addressbook = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_addressbook, module_number);
	le_mapi_table = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_table, module_number);
	le_mapi_msgstore = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_msgstore, module_number);
	le_mapi_mailuser = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_mailuser, module_number);
	le_mapi_distlist = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_distlist, module_number);
	le_mapi_abcont = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_abcont, module_number);
	le_mapi_folder = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_folder, module_number);
	le_mapi_message = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_message, module_number);
	le_mapi_attachment = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_attachment, module_number);
	le_mapi_property = zend_register_list_destructors_ex(
		mapi_resource_dtor, NULL, name_mapi_property, module_number);
	le_mapi_advisesink = zend_register_list_destructors_ex(
		notif_sink_dtor, NULL, name_mapi_advisesink, module_number);
	le_stream = zend_register_list_destructors_ex(
		stream_object_dtor, NULL, name_stream, module_number);
	le_mapi_exportchanges = zend_register_list_destructors_ex(
		ics_export_ctx_dtor, NULL, name_mapi_exportchanges,
		module_number);
	le_mapi_importhierarchychanges = zend_register_list_destructors_ex(
		ics_import_ctx_dtor, NULL, name_mapi_importhierarchychanges,
		module_number);
	le_mapi_importcontentschanges = zend_register_list_destructors_ex(
		ics_import_ctx_dtor, NULL, name_mapi_importcontentschanges,
		module_number);
	ZEND_INIT_MODULE_GLOBALS(mapi, php_mapi_init_globals, NULL);

	REGISTER_INI_ENTRIES();

	return SUCCESS;
}

static PHP_MINFO_FUNCTION(mapi)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "MAPI Support", "enabled");
	php_info_print_table_row(2, "Version", "1.0");
	php_info_print_table_end();
}

static PHP_MSHUTDOWN_FUNCTION(mapi)
{
	UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}

static PHP_RINIT_FUNCTION(mapi)
{
	zstrplus str_opcache(zend_string_init(ZEND_STRL("zend opcache"), 0));
	if (zend_hash_exists(&module_registry, str_opcache.get())) {
		php_error_docref(nullptr, E_ERROR, "mapi: MAPI cannot execute while opcache is present. You must deactivate opcache in PHP (`phpdismod` command on some systems), or remove opcache entirely with the package manager. <https://docs.grommunio.com/kb/php.html>");
		return FAILURE;
	}

	zstrplus str_server(zend_string_init(ZEND_STRL("_SERVER"), 0));
	zstrplus str_user(zend_string_init(ZEND_STRL("REMOTE_USER"), 0));

	MAPI_G(hr) = 0;
	MAPI_G(exception_ce) = NULL;
	MAPI_G(exceptions_enabled) = 0;
	auto server_vars = zend_hash_find(&EG(symbol_table), str_server.get());
	if (server_vars == nullptr || Z_TYPE_P(server_vars) != IS_ARRAY)
		return SUCCESS;
	auto username = zend_hash_find(Z_ARRVAL_P(server_vars), str_user.get());
	if (username == nullptr || Z_TYPE_P(username) != IS_STRING ||
	    Z_STRLEN_P(username) == 0)
		return SUCCESS;
	add_assoc_stringl(server_vars, "PHP_AUTH_USER", Z_STRVAL_P(username), Z_STRLEN_P(username));
	add_assoc_string(server_vars, "PHP_AUTH_PW", "password");
	return SUCCESS;
}

static PHP_RSHUTDOWN_FUNCTION(mapi)
{
	return SUCCESS;
}

static ZEND_FUNCTION(mapi_load_mapidefs)
{
	zend_long level = 0;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &level) == FAILURE)
		;

	zend_constant c;
	ZEND_CONSTANT_SET_FLAGS(&c, CONST_CS, 0);
	c.name = zend_string_init(ZEND_STRL("MAPIDEFS_LOADED"), 0);
	if (zend_get_constant(c.name) != nullptr) {
		zstr_delete()(c.name);
		return;
	}
	ZVAL_LONG(&c.value, 1);
	zend_register_constant(&c);

#define C(PR_name, PR_val) \
	c.name = zend_string_init(#PR_name, sizeof(#PR_name) - 1, 0); \
	ZVAL_LONG(&c.value, PR_val); \
	zend_register_constant(&c);
#include <mapitags.cpp>
	if (level < 1)
		return;
#include <mapierr.cpp>
#undef C
}

static ZEND_FUNCTION(mapi_last_hresult)
{
	RETURN_LONG(MAPI_G(hr));
}

static ZEND_FUNCTION(mapi_prop_type)
{
	zend_long proptag;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &proptag) == FAILURE) {
		MAPI_G(hr) = ecInvalidParam;
		RETVAL_FALSE;
		return;
	}
	MAPI_G(hr) = ecSuccess;
	RETURN_LONG(PROP_TYPE(proptag));
}

static ZEND_FUNCTION(mapi_prop_id)
{
	zend_long proptag;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &proptag) == FAILURE) {
		MAPI_G(hr) = ecInvalidParam;
		RETVAL_FALSE;
		return;
	}
	MAPI_G(hr) = ecSuccess;
	RETURN_LONG(PROP_ID(proptag));
}

static ZEND_FUNCTION(mapi_is_error)
{
	zend_long errcode;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &errcode) == FAILURE) {
		MAPI_G(hr) = ecInvalidParam;
		RETVAL_FALSE;
		return;
	}
	MAPI_G(hr) = ecSuccess;
	RETURN_BOOL(errcode & 0x80000000);
}

static ZEND_FUNCTION(mapi_make_scode)
{
	zend_long sev, code;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &sev, &code) == FAILURE) {
		MAPI_G(hr) = ecInvalidParam;
		RETVAL_FALSE;
		return;
	}
	uint32_t scode = 0x40000 | static_cast<uint32_t>(code);
	if (sev)
		scode |= 0x80000000;
	MAPI_G(hr) = ecSuccess;
	RETURN_LONG(scode);
}

static ZEND_FUNCTION(mapi_prop_tag)
{
	zend_long propid, proptype;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ll", &proptype, &propid) == FAILURE || propid >
		0xFFFF || proptype > 0xFFFF) {
		MAPI_G(hr) = ecInvalidParam;
		RETVAL_FALSE;
		return;
	}
	MAPI_G(hr) = ecSuccess;
	RETURN_LONG(PROP_TAG(proptype, propid));
}

static ZEND_FUNCTION(mapi_createoneoff)
{
	zend_long flags = 0;
	char *ptype, *paddress, *pdisplayname, empty[1]{};
	size_t type_len = 0, name_len = 0, address_len = 0;
	PUSH_CTX push_ctx;
	ONEOFF_ENTRYID tmp_entry;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"sss|l", &pdisplayname, &name_len, &ptype, &type_len,
		&paddress, &address_len, &flags) == FAILURE ||
		NULL == ptype || '\0' == ptype[0] || NULL == paddress)
		pthrow(ecInvalidParam);
	if (pdisplayname == nullptr)
		pdisplayname = empty;
	tmp_entry.flags = 0;
	tmp_entry.version = 0;
	tmp_entry.ctrl_flags = flags;
	tmp_entry.pdisplay_name = pdisplayname;
	tmp_entry.paddress_type = ptype;
	tmp_entry.pmail_address = paddress;
	if (!push_ctx.init() ||
	    push_ctx.p_oneoff_eid(tmp_entry) != EXT_ERR_SUCCESS)
		pthrow(ecError);
	RETVAL_STRINGL(reinterpret_cast<const char *>(push_ctx.m_vdata), push_ctx.m_offset);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_parseoneoff)
{
	size_t cbentryid = 0;
	char *pentryid;
	EXT_PULL pull_ctx;
	ONEOFF_ENTRYID oneoff_entry;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
		&pentryid, &cbentryid) == FAILURE || NULL == pentryid)
		pthrow(ecInvalidParam);
	pull_ctx.init(pentryid, cbentryid, ext_pack_alloc,
		EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	if (pull_ctx.g_oneoff_eid(&oneoff_entry) != EXT_ERR_SUCCESS)
		pthrow(ecError);
	zarray_init(return_value);
	add_assoc_string(return_value, "name", oneoff_entry.pdisplay_name);
	add_assoc_string(return_value, "type", oneoff_entry.paddress_type);
	add_assoc_string(return_value, "address", oneoff_entry.pmail_address);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_logon_zarafa)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	size_t wa_len = 0, misc_len = 0, username_len = 0, password_len = 0;
	size_t server_len = 0, sslcert_len = 0, sslpass_len = 0;
	char *server, *sslcert, *sslpass, *username, *password;
	char *wa_version, *misc_version;
	MAPI_RESOURCE *presource;
	zstrplus str_server(zend_string_init(ZEND_STRL("_SERVER"), 0));
	zstrplus str_user(zend_string_init(ZEND_STRL("REMOTE_USER"), 0));
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|ssslss",
		&username, &username_len, &password, &password_len, &server,
		&server_len, &sslcert, &sslcert_len, &sslpass, &sslpass_len,
		&flags, &wa_version, &wa_len, &misc_version, &misc_len)
		== FAILURE || NULL == username || '\0' == username[0] ||
		NULL == password)
		pthrow(ecInvalidParam);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	auto result = zclient_logon(username, password, 0, &presource->hsession);
	if (result != ecSuccess)
		pthrow(result);
	presource->type = zs_objtype::session;
	presource->hobject = 0;
	RETVAL_RG(presource, le_mapi_session);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_logon_ex)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	char *username, *password;
	size_t username_len = 0, password_len = 0;
	MAPI_RESOURCE *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssl",
		&username, &username_len, &password, &password_len, &flags)
		== FAILURE || NULL == username || '\0' == username[0] ||
		NULL == password)
		pthrow(ecInvalidParam);
	if ('\0' == password[0]) {
		/* enable empty password only when php is running under cli mode */
		zstrplus str_server(zend_string_init(ZEND_STRL("_SERVER"), 0));
		zstrplus str_reqm(zend_string_init(ZEND_STRL("REQUEST_METHOD"), 0));

		if (PG(auto_globals_jit))
			zend_is_auto_global(str_server.get());

		auto server_vars = zend_hash_find(&EG(symbol_table), str_server.get());
		if (server_vars != nullptr && Z_TYPE_P(server_vars) == IS_ARRAY) {
			auto method = zend_hash_find(Z_ARRVAL_P(server_vars), str_reqm.get());
			if (method != nullptr && Z_TYPE_P(method) == IS_STRING &&
			    Z_STRLEN_P(method) > 0)
				pthrow(ecAccessDenied);
		}
		password = NULL;
	}
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	auto result = zclient_logon(username,
		password, flags, &presource->hsession);
	if (result != ecSuccess)
		pthrow(result);
	presource->type = zs_objtype::session;
	presource->hobject = 0;
	RETVAL_RG(presource, le_mapi_session);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_openentry)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	BINARY entryid;
	size_t eid_size = 0;
	zval *pzresource;
	uint32_t hobject;
	zs_objtype mapi_type;
	MAPI_RESOURCE *psession, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|sl",
	    &pzresource, &entryid.pb, &eid_size, &flags) == FAILURE
		|| NULL == pzresource || NULL == entryid.pb)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	auto result = zclient_openentry(psession->hsession,
					entryid, flags, &mapi_type, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = mapi_type;
	presource->hsession = psession->hsession;
	presource->hobject = hobject;
	switch (mapi_type) {
	case zs_objtype::folder:
		RETVAL_RG(presource, le_mapi_folder);
		break;
	case zs_objtype::message:
		RETVAL_RG(presource, le_mapi_message);
		break;
	default:
		efree(presource);
		pthrow(ecInvalidObject);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_openaddressbook)
{
	ZCL_MEMORY;
	zval *pzresource;
	MAPI_RESOURCE *psession, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::addrbook;
	presource->hsession = psession->hsession;
	presource->hobject = 0;
	RETVAL_RG(presource, le_mapi_addressbook);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_ab_openentry)
{
	zend_long flags = 0;
	BINARY entryid;
	size_t eid_size = 0;
	zval *pzresource;
	uint32_t hobject;
	zs_objtype mapi_type;
	MAPI_RESOURCE *psession, *presource;
	
	entryid.cb = 0;
	entryid.pb = NULL;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|sl",
	    &pzresource, &entryid.pb, &eid_size, &flags) == FAILURE
		|| NULL == pzresource)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_addressbook,
		le_mapi_addressbook);
	if (psession->type != zs_objtype::addrbook)
		pthrow(ecInvalidObject);
	auto result = zclient_openabentry(psession->hsession,
							entryid, &mapi_type, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = mapi_type;
	presource->hsession = psession->hsession;
	presource->hobject = hobject;
	switch (mapi_type) {
	case zs_objtype::mailuser:
	case zs_objtype::oneoff:
		RETVAL_RG(presource, le_mapi_mailuser);
		break;
	case zs_objtype::distlist:
		RETVAL_RG(presource, le_mapi_distlist);
		break;
	case zs_objtype::abcont:
		RETVAL_RG(presource, le_mapi_abcont);
		break;
	default:
		efree(presource);
		pthrow(ecInvalidObject);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_ab_resolvename)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzarray, pzrowset, *pzresource;
	TARRAY_SET cond_set, result_set;
	MAPI_RESOURCE *psession;
	
	ZVAL_NULL(&pzrowset);
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra|l", &pzresource, &pzarray, &flags) == FAILURE
		|| NULL == pzresource || NULL == pzarray)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_addressbook,
		le_mapi_addressbook);
	if (psession->type != zs_objtype::addrbook)
		pthrow(ecInvalidObject);
	auto err = php_to_tarray_set(pzarray, &cond_set);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_resolvename(
		psession->hsession, &cond_set,
		&result_set);
	if (result != ecSuccess)
		pthrow(result);
	err = tarray_set_to_php(&result_set, &pzrowset);
	if (err != ecSuccess)
		pthrow(err);
	RETVAL_ZVAL(&pzrowset, 0, 0);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_ab_getdefaultdir)
{
	ZCL_MEMORY;
	BINARY entryid;
	zval *pzresource;
	MAPI_RESOURCE *psession;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_addressbook,
		le_mapi_addressbook);
	if (psession->type != zs_objtype::addrbook)
		pthrow(ecInvalidObject);
	auto result = zclient_getabgal(psession->hsession, &entryid);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_STRINGL(reinterpret_cast<const char *>(entryid.pb), entryid.cb);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_getmsgstorestable)
{
	ZCL_MEMORY;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *psession, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	auto result = zclient_loadstoretable(psession->hsession, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::table;
	presource->hsession = psession->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_table);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_openmsgstore)
{
	ZCL_MEMORY;
	BINARY entryid;
	size_t eid_size = 0;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *psession, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
	    "rs", &pzresource, &entryid.pb, &eid_size) ==
		FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	auto result = zclient_openstore(
		psession->hsession, entryid,
		&hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::store;
	presource->hsession = psession->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_msgstore);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_openprofilesection)
{
	ZCL_MEMORY;
	size_t uidlen = 0;
	FLATUID *puid;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *psession, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rs", &pzresource, &puid, &uidlen) == FAILURE ||
		NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	if (NULL != puid) {
		if (uidlen == 0)
			puid = NULL;
		else if (uidlen != sizeof(FLATUID))
			pthrow(ecInvalidParam);
	}
	auto result = zclient_openprofilesec(
		psession->hsession, puid, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::profproperty;
	presource->hsession = psession->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_property);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_gethierarchytable)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *probject, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_abcont) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_abcont, le_mapi_abcont);
		if (probject->type != zs_objtype::abcont)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	auto result = zclient_loadhierarchytable(
		probject->hsession, probject->hobject,
		flags, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::table;
	presource->hsession = probject->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_table);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_getcontentstable)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *probject, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_abcont) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_abcont, le_mapi_abcont);
		if (probject->type != zs_objtype::abcont)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_distlist) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE *,
			&pzresource, -1, name_mapi_distlist, le_mapi_distlist);
		if (probject->type != zs_objtype::distlist)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	auto result = zclient_loadcontenttable(
		probject->hsession, probject->hobject,
		flags, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::table;
	presource->hsession = probject->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_table);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_createmessage)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pfolder, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto result = zclient_createmessage(
		pfolder->hsession, pfolder->hobject,
		flags, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::message;
	presource->hsession = pfolder->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_message);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_deletemessages)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzarray, *pzresource;
	MAPI_RESOURCE *pfolder;
	BINARY_ARRAY entryid_array;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra|l", &pzresource, &pzarray, &flags) == FAILURE
		|| NULL == pzresource || NULL == pzarray)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto err = php_to_binary_array(pzarray, &entryid_array);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_deletemessages(
		pfolder->hsession, pfolder->hobject,
		&entryid_array, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_copymessages)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzarray, *pzsrcfolder, *pzdstfolder;
	MAPI_RESOURCE *psrcfolder, *pdstfolder;
	BINARY_ARRAY entryid_array;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rar|l",
		&pzsrcfolder, &pzarray, &pzdstfolder, &flags) == FAILURE ||
		NULL == pzsrcfolder || NULL == pzarray || NULL == pzdstfolder)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(psrcfolder, MAPI_RESOURCE*,
		&pzsrcfolder, -1, name_mapi_folder, le_mapi_folder);
	if (psrcfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	ZEND_FETCH_RESOURCE(pdstfolder, MAPI_RESOURCE*,
		&pzdstfolder, -1, name_mapi_folder, le_mapi_folder);
	if (pdstfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto err = php_to_binary_array(pzarray, &entryid_array);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_copymessages(
		psrcfolder->hsession, psrcfolder->hobject,
		pdstfolder->hobject, &entryid_array, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_setreadflags)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzarray, *pzresource;
	MAPI_RESOURCE *pfolder;
	BINARY_ARRAY entryid_array;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra|l", &pzresource, &pzarray, &flags) == FAILURE
		|| NULL == pzresource || NULL == pzarray)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto err = php_to_binary_array(pzarray, &entryid_array);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_setreadflags(
		pfolder->hsession, pfolder->hobject,
		&entryid_array, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_createfolder)
{
	ZCL_MEMORY;
	size_t name_len = 0, comment_len = 0;
	char *pcomment = nullptr, *pfname;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pfolder, *presource;
	char empty[1]{};
	
	zend_long flags = 0, folder_type = FOLDER_GENERIC;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs|sll",
		&pzresource, &pfname, &name_len, &pcomment, &comment_len,
		&flags, &folder_type) == FAILURE || NULL == pzresource ||
		NULL == pfname || '\0' == pfname[0])
		pthrow(ecInvalidParam);
	if (pcomment == nullptr || comment_len == 0)
		pcomment = empty;
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto result = zclient_createfolder(
		pfolder->hsession, pfolder->hobject,
		folder_type, pfname, pcomment, flags,
		&hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::folder;
	presource->hsession = pfolder->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_folder);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_deletefolder)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	BINARY entryid;
	size_t eid_size = 0;
	zval *pzresource;
	MAPI_RESOURCE *pfolder;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs|l",
	    &pzresource, &entryid.pb, &eid_size, &flags) == FAILURE
		|| NULL == pzresource || NULL == entryid.pb)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto result = zclient_deletefolder(
		pfolder->hsession, pfolder->hobject,
		entryid, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_emptyfolder)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource;
	MAPI_RESOURCE *pfolder;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto result = zclient_emptyfolder(
		pfolder->hsession, pfolder->hobject,
		flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_copyfolder)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	char *pname;
	size_t name_len = 0, eid_size = 0;
	BINARY entryid;
	zval *pzvalsrcfolder, *pzvaldstfolder;
	MAPI_RESOURCE *psrcfolder, *pdstfolder;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rsr|sl",
	    &pzvalsrcfolder, &entryid.pb, &eid_size, &pzvaldstfolder,
		&pname, &name_len, &flags) == FAILURE || NULL == pzvalsrcfolder ||
	    entryid.pb == nullptr || eid_size == 0 || pzvaldstfolder == nullptr)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(psrcfolder, MAPI_RESOURCE*,
		&pzvalsrcfolder, -1, name_mapi_folder, le_mapi_folder);
	if (psrcfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	ZEND_FETCH_RESOURCE(pdstfolder, MAPI_RESOURCE*,
		&pzvaldstfolder, -1, name_mapi_folder, le_mapi_folder);
	if (pdstfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	if (name_len == 0)
		pname = NULL;
	auto result = zclient_copyfolder(psrcfolder->hsession,
		psrcfolder->hobject, entryid, pdstfolder->hobject,
		pname, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_msgstore_createentryid)
{
	ZCL_MEMORY;
	size_t dn_len = 0;
	BINARY entryid;
	char *mailboxdn;
	zval *pzresource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rs", &pzresource, &mailboxdn, &dn_len) == FAILURE
		|| NULL == mailboxdn || '\0' == mailboxdn[0])
		pthrow(ecInvalidParam);
	auto result = zclient_getstoreentryid(mailboxdn, &entryid);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_STRINGL(reinterpret_cast<const char *>(entryid.pb), entryid.cb);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_msgstore_getarchiveentryid)
{
	MAPI_G(hr) = ecNotFound;
	if (MAPI_G(exceptions_enabled))
		zend_throw_exception(MAPI_G(exception_ce),
			"MAPI error ", MAPI_G(hr));
	RETVAL_FALSE;
}

static ZEND_FUNCTION(mapi_msgstore_openentry)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	BINARY entryid{};
	size_t eid_size = 0;
	uint32_t hobject;
	zval *pzresource;
	zs_objtype mapi_type;
	MAPI_RESOURCE *pstore, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
	    "r|sl", &pzresource, &entryid.pb, &eid_size,
		&flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
		pthrow(ecInvalidObject);
	auto result = zclient_openstoreentry(pstore->hsession,
		pstore->hobject, entryid, flags, &mapi_type, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = mapi_type;
	presource->hsession = pstore->hsession;
	presource->hobject = hobject;
	if (mapi_type == zs_objtype::folder)
		RETVAL_RG(presource, le_mapi_folder);
	else if (mapi_type == zs_objtype::message)
		RETVAL_RG(presource, le_mapi_message);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_msgstore_entryidfromsourcekey)
{
	ZCL_MEMORY;
	size_t skey_size = 0, skmsg_size = 0;
	zval *pzresource;
	MAPI_RESOURCE *pstore;
	BINARY entryid, sourcekey_folder{}, sourcekey_message{}, *pmessage_key;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs|s",
	    &pzresource, &sourcekey_folder.pb, &skey_size,
	    &sourcekey_message.pb, &skmsg_size) == FAILURE ||
	    pzresource == nullptr || sourcekey_folder.pb == nullptr ||
	    skey_size == 0)
		pthrow(ecInvalidParam);
	sourcekey_folder.cb = skey_size;
	sourcekey_message.cb = skmsg_size;
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
		pthrow(ecInvalidObject);
	pmessage_key = sourcekey_message.pb == 0 || sourcekey_message.cb == 0 ?
	               nullptr : &sourcekey_message;
	auto result = zclient_entryidfromsourcekey(pstore->hsession,
		pstore->hobject, sourcekey_folder, pmessage_key, &entryid);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_STRINGL(reinterpret_cast<const char *>(entryid.pb), entryid.cb);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_msgstore_advise)
{
	ZCL_MEMORY;
	BINARY entryid, *pentryid;
	size_t eid_size = 0;
	uint32_t sub_id;
	zend_long event_mask;
	zval *pzressink, *pzresource;
	NOTIF_SINK *psink;
	MAPI_RESOURCE *pstore;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
	    "rslr", &pzresource, &entryid.pb, &eid_size,
		&event_mask, &pzressink) == FAILURE || NULL ==
		pzresource)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
		pthrow(ecInvalidObject);
	ZEND_FETCH_RESOURCE(psink, NOTIF_SINK*, &pzressink,
		-1, name_mapi_advisesink, le_mapi_advisesink);
	pentryid = entryid.pb == nullptr || entryid.cb == 0 ? nullptr : &entryid;
	auto result = zclient_storeadvise(
		pstore->hsession, pstore->hobject,
		pentryid, event_mask, &sub_id);
	if (result != ecSuccess)
		pthrow(result);
	if (!notif_sink_add_subscription(psink,
		pstore->hsession, pstore->hobject, sub_id)) {
		zclient_unadvise(pstore->hsession,
			pstore->hobject, sub_id);
		pthrow(ecMAPIOOM);
	}
	RETVAL_LONG(sub_id);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_msgstore_unadvise)
{
	ZCL_MEMORY;
	zend_long sub_id;
	zval *pzresource;
	MAPI_RESOURCE *pstore;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl",
		&pzresource, &sub_id) == FAILURE || NULL == pzresource
		|| 0 == sub_id)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
		pthrow(ecInvalidObject);
	auto result = zclient_unadvise(pstore->hsession,
							pstore->hobject, sub_id);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_sink_create)
{
	auto psink = st_calloc<NOTIF_SINK>();
	if (NULL == psink) {
		MAPI_G(hr) = ecMAPIOOM;
		RETVAL_FALSE;
		if (MAPI_G(exceptions_enabled))
			zend_throw_exception(MAPI_G(exception_ce),
				"MAPI error ", MAPI_G(hr));
	} else {
		MAPI_G(hr) = ecSuccess;
		RETVAL_RG(psink, le_mapi_advisesink);
	}	
}

static ZEND_FUNCTION(mapi_sink_timedwait)
{
	{
	ZCL_MEMORY;
	zend_long tmp_time;
	NOTIF_SINK *psink;
	zval pznotifications, *pzressink;
	ZNOTIFICATION_ARRAY notifications;

	ZVAL_NULL(&pznotifications);
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl",
		&pzressink, &tmp_time) == FAILURE || NULL == pzressink) {
		MAPI_G(hr) = ecInvalidParam;
		goto RETURN_EXCEPTION;
	}
	ZEND_FETCH_RESOURCE(psink, NOTIF_SINK*, &pzressink,
		-1, name_mapi_advisesink, le_mapi_advisesink);
	if (0 == psink->count) {
		usleep(tmp_time*1000);
		notifications.count = 0;
		notifications.ppnotification = NULL;
	} else {
		tmp_time /= 1000;
		if (tmp_time < 1)
			tmp_time = 1;
		auto result = notif_sink_timedwait(psink,
				tmp_time, &notifications);
		if (result != ecSuccess) {
			MAPI_G(hr) = result;
			goto RETURN_EXCEPTION;
		}
	}
	auto err = znotification_array_to_php(&notifications, &pznotifications);
	MAPI_G(hr) = err;
	if (err != ecSuccess)
		goto RETURN_EXCEPTION;
	RETVAL_ZVAL(&pznotifications, 0, 0);
	return;
	}
 RETURN_EXCEPTION:
	sleep(1);
}

static ZEND_FUNCTION(mapi_table_queryallrows)
{
	ZCL_MEMORY;
	zval pzrowset, *pzresource, *pzproptags = nullptr, *pzrestriction = nullptr;
	TARRAY_SET rowset;
	MAPI_RESOURCE *ptable;
	PROPTAG_ARRAY proptags, *pproptags = nullptr;
	RESTRICTION restriction, *prestriction = nullptr;
	
	ZVAL_NULL(&pzrowset);
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|aa",
		&pzresource, &pzproptags, &pzrestriction) == FAILURE ||
		NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	if (NULL != pzrestriction) {
		auto err = php_to_restriction(pzrestriction, &restriction);
		if (err != ecSuccess)
			pthrow(err);
		prestriction = &restriction;
	}
	if (NULL != pzproptags) {
		auto err = php_to_proptag_array(pzproptags, &proptags);
		if (err != ecSuccess)
			pthrow(err);
		pproptags = &proptags;
	}
	auto result = zclient_queryrows(ptable->hsession, ptable->hobject, 0,
	         INT32_MAX, prestriction, pproptags, &rowset);
	if (result != ecSuccess)
		pthrow(result);
	auto err = tarray_set_to_php(&rowset, &pzrowset);
	if (err != ecSuccess)
		pthrow(err);
	RETVAL_ZVAL(&pzrowset, 0, 0);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_queryrows)
{
	ZCL_MEMORY;
	zval pzrowset, *pzresource, *pzproptags;
	TARRAY_SET rowset;
	MAPI_RESOURCE *ptable;
	PROPTAG_ARRAY proptags, *pproptags = nullptr;
	
	ZVAL_NULL(&pzrowset);
	zend_long start = UINT32_MAX, row_count = UINT32_MAX;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|a!ll",
		&pzresource, &pzproptags, &start, &row_count) == FAILURE ||
		NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	if (NULL != pzproptags) {
		auto err = php_to_proptag_array(pzproptags, &proptags);
		if (err != ecSuccess)
			pthrow(err);
		pproptags = &proptags;
	}
	auto result = zclient_queryrows(ptable->hsession,
			ptable->hobject, start, row_count, NULL,
			pproptags, &rowset);
	if (result != ecSuccess)
		pthrow(result);
	auto err = tarray_set_to_php(&rowset, &pzrowset);
	if (err != ecSuccess)
		pthrow(err);
	RETVAL_ZVAL(&pzrowset, 0, 0);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_setcolumns)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource, *pzproptags;
	MAPI_RESOURCE *ptable;
	PROPTAG_ARRAY proptags;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ra|l",
		&pzresource, &pzproptags, &flags) == FAILURE || NULL ==
		pzresource || NULL == pzproptags)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto err = php_to_proptag_array(pzproptags, &proptags);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_setcolumns(
		ptable->hsession, ptable->hobject,
		&proptags, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_seekrow)
{
	ZCL_MEMORY;
	zend_long bookmark = BOOKMARK_BEGINNING, row_count = 0;
	zval *pzresource;
	int32_t rows_sought;
	MAPI_RESOURCE *ptable;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rll",
		&pzresource, &bookmark, &row_count) == FAILURE || NULL
		== pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto result = zclient_seekrow(ptable->hsession,
		ptable->hobject, bookmark, row_count, &rows_sought);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_LONG(rows_sought);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_sort)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource, *pzsortarray;
	MAPI_RESOURCE *ptable;
	SORTORDER_SET sortcriteria;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ra|l",
		&pzresource, &pzsortarray, &flags) == FAILURE || NULL ==
		pzresource || NULL == pzsortarray)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto err = php_to_sortorder_set(pzsortarray, &sortcriteria);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_sorttable(ptable->hsession,
					ptable->hobject, &sortcriteria);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_getrowcount)
{
	ZCL_MEMORY;
	uint32_t count;
	zval *pzresource;
	MAPI_RESOURCE *ptable;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto result = zclient_getrowcount(
		ptable->hsession, ptable->hobject,
		&count);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_LONG(count);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_restrict)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource, *pzrestrictarray;
	MAPI_RESOURCE *ptable;
	RESTRICTION restriction;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ra|l",
		&pzresource, &pzrestrictarray, &flags) == FAILURE ||
		NULL == pzresource || NULL == pzrestrictarray || 0 ==
		zend_hash_num_elements(Z_ARRVAL_P(pzrestrictarray)))
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto err = php_to_restriction(pzrestrictarray, &restriction);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_restricttable(
		ptable->hsession, ptable->hobject,
		&restriction, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_findrow)
{
	ZCL_MEMORY;
	zend_long flags = 0, bookmark = BOOKMARK_BEGINNING;
	uint32_t row_idx;
	zval *pzresource, *pzrestrictarray;
	MAPI_RESOURCE *ptable;
	RESTRICTION restriction;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ra|ll",
		&pzresource, &pzrestrictarray, &bookmark, &flags) == FAILURE
		|| NULL == pzresource || NULL == pzrestrictarray || 0 ==
		zend_hash_num_elements(Z_ARRVAL_P(pzrestrictarray)))
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto err = php_to_restriction(pzrestrictarray, &restriction);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_findrow(ptable->hsession,
			ptable->hobject, bookmark, &restriction,
			flags, &row_idx);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_LONG(row_idx);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_createbookmark)
{
	ZCL_MEMORY;
	zval *pzresource;
	uint32_t bookmark;
	MAPI_RESOURCE *ptable;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r",
		&pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto result = zclient_createbookmark(
		ptable->hsession, ptable->hobject,
		&bookmark);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_LONG(bookmark);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_table_freebookmark)
{
	ZCL_MEMORY;
	zend_long bookmark;
	zval *pzresource;
	MAPI_RESOURCE *ptable;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl",
		&pzresource, &bookmark) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(ptable, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_table, le_mapi_table);
	if (ptable->type != zs_objtype::table)
		pthrow(ecInvalidObject);
	auto result = zclient_freebookmark(
		ptable->hsession, ptable->hobject,
		bookmark);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_msgstore_getreceivefolder)
{
	ZCL_MEMORY;
	BINARY entryid;
	zval *pzresource;
	uint32_t hobject;
	zs_objtype mapi_type;
	MAPI_RESOURCE *pstore, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
		pthrow(ecInvalidObject);
	auto result = zclient_getreceivefolder(
			pstore->hsession, pstore->hobject,
			NULL, &entryid);
	if (result != ecSuccess)
		pthrow(result);
	result = zclient_openstoreentry(
		pstore->hsession, pstore->hobject,
		entryid, 0, &mapi_type, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::folder;
	presource->hsession = pstore->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_folder);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_modifyrecipients)
{
	ZCL_MEMORY;
	zend_long flags = MODRECIP_ADD;
	zval *pzadrlist, *pzresource;
	TARRAY_SET rcpt_list;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rla", &pzresource, &flags, &pzadrlist) == FAILURE
		|| NULL == pzresource || NULL == pzadrlist)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto err = php_to_tarray_set(pzadrlist, &rcpt_list);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_modifyrecipients(
		pmessage->hsession, pmessage->hobject,
		flags, &rcpt_list);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_submitmessage)
{
	ZCL_MEMORY;
	zval *pzresource;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_submitmessage(
		pmessage->hsession, pmessage->hobject);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_getattachmenttable)
{
	ZCL_MEMORY;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pmessage, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_loadattachmenttable(
			pmessage->hsession, pmessage->hobject,
			&hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::table;
	presource->hsession = pmessage->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_table);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_openattach)
{
	ZCL_MEMORY;
	zend_long attach_id;
	zval *pzresource;
	uint32_t hobject;
	MAPI_RESOURCE *pmessage, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl",
		&pzresource, &attach_id) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_openattachment(
		pmessage->hsession, pmessage->hobject,
		attach_id, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::attach;
	presource->hsession = pmessage->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_attachment);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_createattach)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pmessage, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_createattachment(
		pmessage->hsession, pmessage->hobject,
		&hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::attach;
	presource->hsession = pmessage->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_attachment);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_deleteattach)
{	
	ZCL_MEMORY;
	zend_long flags = 0, attach_id;
	zval *pzresource;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl|l",
		&pzresource, &attach_id, &flags) == FAILURE || NULL ==
		pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_deleteattachment(
		pmessage->hsession, pmessage->hobject,
		attach_id);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_read)
{
	ZCL_MEMORY;
	void *pbuff;
	zval *pzresource;
	uint32_t actual_bytes;
	STREAM_OBJECT *pstream;
	zend_long wanted_bytes;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rl", &pzresource, &wanted_bytes) == FAILURE ||
		NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresource, -1, name_stream, le_stream);
	pbuff = stream_object_read(pstream, wanted_bytes, &actual_bytes);
	if (NULL == pbuff)
		pthrow(ecError);
	RETVAL_STRINGL(static_cast<const char *>(pbuff), actual_bytes);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_seek)
{
	ZCL_MEMORY;
	zend_long flags = STREAM_SEEK_CUR, seek_offset;
	zval *pzresource;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl|l",
		&pzresource, &seek_offset, &flags) == FAILURE || NULL ==
		pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresource, -1, name_stream, le_stream);
	if (!stream_object_seek(pstream, flags, seek_offset))
		pthrow(ecError);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_setsize)
{
	ZCL_MEMORY;
	zend_long newsize;
	zval *pzresource;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rl", &pzresource, &newsize) == FAILURE || NULL
		== pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresource, -1, name_stream, le_stream);
	if (!stream_object_set_length(pstream, newsize))
		pthrow(ecError);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_commit)
{
	ZCL_MEMORY;
	uint32_t result;
	zval *pzresource;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresource, -1, name_stream, le_stream);
	result = stream_object_commit(pstream);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_write)
{
	ZCL_MEMORY;
	zval *pzresource;
	size_t dblk_size = 0;
	BINARY data_block;
	uint32_t written_len;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs",
	    &pzresource, &data_block.pb, &dblk_size) == FAILURE
		|| NULL == pzresource)
		pthrow(ecInvalidParam);
	data_block.cb = dblk_size;
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresource, -1, name_stream, le_stream);
	written_len = stream_object_write(pstream,
				data_block.pb, data_block.cb);
	RETVAL_LONG(written_len);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_stat)
{
	ZCL_MEMORY;
	zval *pzresource;
	uint32_t stream_size;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresource, -1, name_stream, le_stream);
	stream_size = stream_object_get_length(pstream);
	zarray_init(return_value);
	add_assoc_long(return_value, "cb", stream_size);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_stream_create)
{
	auto pstream = st_calloc<STREAM_OBJECT>();
	if (NULL == pstream)
		pthrow(ecError);
	RETVAL_RG(pstream, le_stream);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_openpropertytostream)
{
	ZCL_MEMORY;
	zend_long flags = 0, proptag;
	size_t guidlen = 0;
	void *pvalue;
	char *guidstr;
	zval *pzresource;
	MAPI_RESOURCE *probject;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rl|ls", &pzresource, &proptag, &flags, &guidstr,
		&guidlen) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	switch (PROP_TYPE(proptag)) {
	case PT_BINARY:
	case PT_STRING8:
	case PT_UNICODE:
		break;
	default:
		pthrow(ecInvalidParam);
	}
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if(type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_message, le_mapi_message);
		if (probject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_attachment, le_mapi_attachment);
		if (probject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
		if (probject->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_mailuser) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_mailuser, le_mapi_mailuser);
		if (probject->type != zs_objtype::mailuser &&
		    probject->type != zs_objtype::oneoff)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	auto pstream = st_calloc<STREAM_OBJECT>();
	if (NULL == pstream)
		pthrow(ecMAPIOOM);
	stream_object_set_parent(
		pstream, probject->hsession,
		probject->hobject, proptag);
	auto result = zclient_getpropval(probject->hsession,
		probject->hobject, phptag_to_proptag(proptag), &pvalue);
	if (result != ecSuccess)
		pthrow(result);
	if (NULL != pvalue) {
		if (PROP_TYPE(proptag) == PT_BINARY) {
			auto bv = static_cast<BINARY *>(pvalue);
			stream_object_write(pstream, bv->pb, bv->cb);
		} else {
			stream_object_write(pstream, pvalue, strlen(static_cast<const char *>(pvalue)));
		}
		stream_object_seek(pstream, STREAM_SEEK_SET, 0);
	}
	RETVAL_RG(pstream, le_stream);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_getrecipienttable)
{
	ZCL_MEMORY;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pmessage, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_loadrecipienttable(
		pmessage->hsession, pmessage->hobject,
		&hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::table;
	presource->hsession = pmessage->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_table);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_message_setreadflag)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rl",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidObject);
	auto result = zclient_setmessagereadflag(
		pmessage->hsession, pmessage->hobject,
		flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_attach_openobj)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pattach, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pattach, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_attachment,
		le_mapi_attachment);
	if (pattach->type != zs_objtype::attach)
		pthrow(ecInvalidObject);
	auto result = zclient_openembedded(
		pattach->hsession, pattach->hobject,
		flags, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::message;
	presource->hsession = pattach->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_message);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_getidsfromnames)
{
	ZCL_MEMORY;
	zval *pzstore, *pznames, *pzguids;
	PROPID_ARRAY propids;
	MAPI_RESOURCE *pstore;
	PROPNAME_ARRAY propnames;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra|a", &pzstore, &pznames, &pzguids) == FAILURE
		|| NULL == pzstore || NULL == pznames)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzstore, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
		pthrow(ecInvalidObject);
	auto err = php_to_propname_array(pznames, pzguids, &propnames);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_getnamedpropids(
		pstore->hsession, pstore->hobject,
		&propnames, &propids);
	if (result != ecSuccess)
		pthrow(result);
	zarray_init(return_value);
	for (unsigned int i = 0; i < propids.count; ++i)
		add_next_index_long(return_value, PROP_TAG(PT_UNSPECIFIED, propids.ppropid[i]));
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_setprops)
{
	ZCL_MEMORY;
	zval *pzpropvals, *pzresource;
	MAPI_RESOURCE *probject;
	TPROPVAL_ARRAY propvals;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra", &pzresource, &pzpropvals) == FAILURE ||
		NULL == pzresource || NULL == pzpropvals)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if(type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_message, le_mapi_message);
		if (probject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_attachment, le_mapi_attachment);
		if (probject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
		if (probject->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_property) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_property, le_mapi_property);
		if (probject->type != zs_objtype::profproperty)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	auto err = php_to_tpropval_array(pzpropvals, &propvals);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_setpropvals(probject->hsession,
							probject->hobject, &propvals);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_copyto)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzsrc, *pzdst, *pzexcludeiids, *pzexcludeprops;
	MAPI_RESOURCE *psrcobject, *pdstobject;
	PROPTAG_ARRAY exclude_proptags, *pexclude_proptags = nullptr;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "raar|l",
		&pzsrc, &pzexcludeiids, &pzexcludeprops, &pzdst, &flags)
		== FAILURE || NULL == pzsrc || NULL == pzdst)
		pthrow(ecInvalidParam);
	{
	auto type  = Z_RES_TYPE_P(pzsrc);
	auto type1 = Z_RES_TYPE_P(pzdst);
	if (type != type1)
		pthrow(ecInvalidParam);
	if(type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(psrcobject, MAPI_RESOURCE*,
			&pzsrc, -1, name_mapi_message, le_mapi_message);
		if (psrcobject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
		ZEND_FETCH_RESOURCE(pdstobject, MAPI_RESOURCE*,
			&pzdst, -1, name_mapi_message, le_mapi_message);
		if (pdstobject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(psrcobject, MAPI_RESOURCE*,
			&pzsrc, -1, name_mapi_folder, le_mapi_folder);
		if (psrcobject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
		ZEND_FETCH_RESOURCE(pdstobject, MAPI_RESOURCE*,
			&pzdst, -1, name_mapi_folder, le_mapi_folder);
		if (pdstobject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(psrcobject, MAPI_RESOURCE*,
			&pzsrc, -1, name_mapi_attachment, le_mapi_attachment);
		if (psrcobject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
		ZEND_FETCH_RESOURCE(pdstobject, MAPI_RESOURCE*,
			&pzdst, -1, name_mapi_attachment, le_mapi_attachment);
		if (pdstobject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	if (pzexcludeprops != nullptr) {
		auto err = php_to_proptag_array(pzexcludeprops, &exclude_proptags);
		if (err != ecSuccess)
			pthrow(err);
		pexclude_proptags = &exclude_proptags;
	}
	auto result = zclient_copyto(psrcobject->hsession,
				psrcobject->hobject, pexclude_proptags,
				pdstobject->hobject, flags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_savechanges)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource;
	MAPI_RESOURCE *probject;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_message, le_mapi_message);
		if (probject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_attachment, le_mapi_attachment);
		if (probject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
		if (probject->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_property) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_property, le_mapi_property);
		if (probject->type != zs_objtype::profproperty)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	switch (probject->type) {
	case zs_objtype::attach:
	case zs_objtype::message:
		auto result = zclient_savechanges(
			probject->hsession, probject->hobject);
		if (result != ecSuccess)
			pthrow(result);
		break;
	}
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_deleteprops)
{
	ZCL_MEMORY;
	zval *pzresource, *pzproptags;
	PROPTAG_ARRAY proptags;
	MAPI_RESOURCE *probject;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra", &pzresource, &pzproptags) == FAILURE ||
		NULL == pzresource || NULL == pzproptags)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if(type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_message, le_mapi_message);
		if (probject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_attachment, le_mapi_attachment);
		if (probject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
		if (probject->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecInvalidParam);
	}
	}
	auto err = php_to_proptag_array(pzproptags, &proptags);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_deletepropvals(probject->hsession,
								probject->hobject, &proptags);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_openproperty)
{
	ZCL_MEMORY;
	size_t guidlen = 0;
	void *pvalue;
	char *guidstr;
	FLATUID iid_guid;
	uint32_t hobject;
	zval *pzresource;
	PULL_CTX pull_ctx;
	zend_long flags = 0, interfaceflags = 0, proptag;
	MAPI_RESOURCE *probject, *presource;
	ICS_IMPORT_CTX *pimporter;
	ICS_EXPORT_CTX *pexporter;
	
	if (ZEND_NUM_ARGS() == 2) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(),
			"rl", &pzresource, &proptag) == FAILURE || NULL
			== pzresource)
			pthrow(ecInvalidParam);
		iid_guid = IID_IStream;
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(),
			"rlsll", &pzresource, &proptag, &guidstr,
			&guidlen, &interfaceflags, &flags) == FAILURE ||
			NULL == pzresource || NULL == guidstr)
			pthrow(ecInvalidParam);
		pull_ctx.init(guidstr, sizeof(GUID));
		if (pull_ctx.g_guid(&iid_guid) != EXT_ERR_SUCCESS)
			pthrow(ecInvalidParam);
	}
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_message, le_mapi_message);
		if (probject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_attachment, le_mapi_attachment);
		if (probject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
		if (probject->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecNotSupported);
	}
	if (iid_guid == IID_IStream) {
		auto pt = PROP_TYPE(proptag);
		if (pt != PT_BINARY && pt != PT_UNICODE && pt != PT_STRING8)
			pthrow(ecNotSupported);
		auto result = zclient_getpropval(probject->hsession,
			probject->hobject, phptag_to_proptag(proptag), &pvalue); /* memleak(pvalue) */
		if (result != ecSuccess)
			pthrow(result);
		if (ZEND_NUM_ARGS() == 2) {
			if (NULL == pvalue)
				pthrow(ecNotFound);
			if (PROP_TYPE(proptag) == PT_BINARY)
				RETVAL_STRINGL(reinterpret_cast<const char *>(static_cast<BINARY *>(pvalue)->pb), static_cast<BINARY *>(pvalue)->cb);
			else
				RETVAL_STRINGL(static_cast<const char *>(pvalue), strlen(static_cast<const char *>(pvalue)));
		} else {
			auto pstream = st_calloc<STREAM_OBJECT>();
			if (NULL == pstream)
				pthrow(ecMAPIOOM);
			stream_object_set_parent(
				pstream, probject->hsession,
				probject->hobject, proptag);
			if (NULL != pvalue) {
				if (PROP_TYPE(proptag) == PT_BINARY) {
					auto bv = static_cast<BINARY *>(pvalue);
					stream_object_write(pstream, bv->pb, bv->cb);
				} else {
					stream_object_write(pstream,
						pvalue, strlen(static_cast<const char *>(pvalue)));
				}
				stream_object_seek(pstream, STREAM_SEEK_SET, 0);
			}
			RETVAL_RG(pstream, le_stream);
		}
	} else if (iid_guid == IID_IMessage) {
		if (type != le_mapi_attachment || proptag != PR_ATTACH_DATA_OBJ)
			pthrow(ecNotSupported);
		auto result = zclient_openembedded(probject->hsession,
							probject->hobject, flags, &hobject);
		if (result != ecSuccess)
			pthrow(result);
		presource = st_malloc<MAPI_RESOURCE>();
		if (NULL == presource)
			pthrow(ecMAPIOOM);
		presource->type = zs_objtype::message;
		presource->hsession = probject->hsession;
		presource->hobject = hobject;
		RETVAL_RG(presource, le_mapi_message);
	} else if (iid_guid == IID_IExchangeExportChanges) {
		if (type != le_mapi_folder)
			pthrow(ecNotSupported);
		if (PR_CONTENTS_SYNCHRONIZER == proptag) {
			auto result = zclient_contentsync(probject->hsession,
									probject->hobject, &hobject);
			if (result != ecSuccess)
				pthrow(result);
		} else if (PR_HIERARCHY_SYNCHRONIZER == proptag) {
			auto result = zclient_hierarchysync(probject->hsession,
										probject->hobject, &hobject);
			if (result != ecSuccess)
				pthrow(result);
		} else {
			pthrow(ecNotSupported);
		}
		pexporter = st_malloc<ICS_EXPORT_CTX>();
		if (NULL == pexporter)
			pthrow(ecMAPIOOM);
		pexporter->hsession = probject->hsession;
		pexporter->hobject = hobject;
		ZVAL_NULL(&pexporter->pztarget_obj);
		pexporter->ics_type = proptag == PR_CONTENTS_SYNCHRONIZER ?
		                      ICS_TYPE_CONTENTS : ICS_TYPE_HIERARCHY;
		pexporter->progress = 0;
		pexporter->sync_steps = 0;
		pexporter->total_steps = 0;
		RETVAL_RG(pexporter, le_mapi_exportchanges);
	} else if (iid_guid == IID_IExchangeImportHierarchyChanges) {
		if (type != le_mapi_folder)
			pthrow(ecNotSupported);
		if (PR_COLLECTOR != proptag)
			pthrow(ecNotSupported);
		auto result = zclient_hierarchyimport(
			probject->hsession, probject->hobject,
			&hobject);
		if (result != ecSuccess)
			pthrow(result);
		pimporter = st_malloc<ICS_IMPORT_CTX>();
		if (NULL == pimporter)
			pthrow(ecMAPIOOM);
		pimporter->hsession = probject->hsession;
		pimporter->hobject = hobject;
		ZVAL_NULL(&pimporter->pztarget_obj);
		pimporter->ics_type = ICS_TYPE_HIERARCHY;
		RETVAL_RG(pimporter, le_mapi_importhierarchychanges);
	} else if (iid_guid == IID_IExchangeImportContentsChanges) {
		if (type != le_mapi_folder)
			pthrow(ecNotSupported);
		if (PR_COLLECTOR != proptag)
			pthrow(ecNotSupported);
		auto result = zclient_contentimport(
			probject->hsession, probject->hobject,
			&hobject);
		if (result != ecSuccess)
			pthrow(result);
		pimporter = st_malloc<ICS_IMPORT_CTX>();
		if (NULL == pimporter)
			pthrow(ecMAPIOOM);
		pimporter->hsession = probject->hsession;
		pimporter->hobject = hobject;
		ZVAL_NULL(&pimporter->pztarget_obj);
		pimporter->ics_type = ICS_TYPE_CONTENTS;
		RETVAL_RG(pimporter, le_mapi_importcontentschanges);
	} else {
		pthrow(ecNotSupported);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_getprops)
{
	ZCL_MEMORY;
	zval pzpropvals, *pzresource, *pztagarray = nullptr;
	PROPTAG_ARRAY proptags, *pproptags = nullptr;
	TPROPVAL_ARRAY propvals;
	MAPI_RESOURCE *probject;
	
	ZVAL_NULL(&pzpropvals);
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r|a", &pzresource, &pztagarray) == FAILURE ||
		NULL == pzresource)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_message) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
				&pzresource, -1, name_mapi_message,
				le_mapi_message);
		if (probject->type != zs_objtype::message)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
					&pzresource, -1, name_mapi_folder,
					le_mapi_folder);
		if (probject->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_attachment) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
				&pzresource, -1, name_mapi_attachment,
				le_mapi_attachment);
		if (probject->type != zs_objtype::attach)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
				&pzresource, -1, name_mapi_msgstore,
				le_mapi_msgstore);
		if (probject->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_mailuser) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
				&pzresource, -1, name_mapi_mailuser,
				le_mapi_mailuser);
		if (probject->type != zs_objtype::mailuser &&
		    probject->type != zs_objtype::oneoff)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_distlist) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
				&pzresource, -1, name_mapi_distlist,
				le_mapi_distlist);
		if (probject->type != zs_objtype::distlist)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_abcont) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
					&pzresource, -1, name_mapi_abcont,
					le_mapi_abcont);
		if (probject->type != zs_objtype::abcont)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_property) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
				&pzresource, -1, name_mapi_property,
				le_mapi_property);
		if (probject->type != zs_objtype::profproperty)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_addressbook) {
		ZEND_FETCH_RESOURCE(probject, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_addressbook,
			le_mapi_addressbook);
		if (probject->type != zs_objtype::addrbook)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecNotSupported);
	}
	}
	if(NULL != pztagarray) {
		auto err = php_to_proptag_array(pztagarray, &proptags);
		if (err != ecSuccess)
			pthrow(err);
		pproptags = &proptags;
	}
	auto result = zclient_getpropvals(probject->hsession,
				probject->hobject, pproptags, &propvals);
	if (result != ecSuccess)
		pthrow(result);
	auto err = tpropval_array_to_php(&propvals, &pzpropvals);
	if (err != ecSuccess)
		pthrow(err);
	RETVAL_ZVAL(&pzpropvals, 0, 0);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_getnamesfromids)
{
	ZCL_MEMORY;
	zval *pzarray, *pzresource;
	char num_buff[20];
	PROPID_ARRAY propids;
	MAPI_RESOURCE *pstore;
	PROPTAG_ARRAY proptags;
	PROPNAME_ARRAY propnames;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra", &pzresource, &pzarray) == FAILURE || NULL
		== pzresource || NULL == pzarray)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pstore, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
	if (pstore->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	auto err = php_to_proptag_array(pzarray, &proptags);
	if (err != ecSuccess)
		pthrow(err);
	propids.count = proptags.count;
	propids.ppropid = sta_malloc<uint16_t>(proptags.count);
	if (NULL == propids.ppropid)
		pthrow(ecMAPIOOM);
	for (unsigned int i = 0; i < proptags.count; ++i)
		propids.ppropid[i] = PROP_ID(proptags.pproptag[i]);
	auto result = zclient_getpropnames(
		pstore->hsession, pstore->hobject,
		&propids, &propnames);
	if (result != ecSuccess)
		pthrow(result);
	zarray_init(return_value);
	for (unsigned int i = 0; i < propnames.count; ++i) {
		if (propnames.ppropname[i].kind == KIND_NONE)
			continue;
		snprintf(num_buff, 20, "%i", proptag_to_phptag(proptags.pproptag[i]));
		zval prop, *pzprop = &prop;
		zarray_init(pzprop);
		add_assoc_stringl(pzprop, "guid",
			(char*)&propnames.ppropname[i].guid,
			sizeof(GUID));
		if (propnames.ppropname[i].kind == MNID_ID)
			add_assoc_long(pzprop, "id", propnames.ppropname[i].lid);
		else
			add_assoc_string(pzprop, "name",
				propnames.ppropname[i].pname);
		add_assoc_zval(return_value, num_buff, pzprop);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_decompressrtf)
{
	ZCL_MEMORY;
	pid_t pid;
	int status, offset, bufflen, readlen;
	size_t rtflen = 0;
	char *pbuff, *rtfbuffer, *args[2];
	int pipes_in[2] = {-1, -1}, pipes_out[2] = {-1, -1};
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"s", &rtfbuffer, &rtflen) == FAILURE || NULL ==
		rtfbuffer || 0 == rtflen)
		pthrow(ecInvalidParam);
	if (-1 == pipe(pipes_in))
		pthrow(ecError);
	if (-1 == pipe(pipes_out)) {
		close(pipes_in[0]);
		close(pipes_in[1]);
		pthrow(ecError);
	}
	pid = fork();
	switch (pid) {
	case 0:
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(0);
		close(1);
		dup2(pipes_in[0], 0);
		dup2(pipes_out[1], 1);
		close(pipes_in[0]);
		close(pipes_out[1]);
		args[0] = const_cast<char *>("rtf2html");
		args[1] = NULL;
		execv(PKGLIBEXECDIR "/rtf2html", args);
		_exit(-1);
	 case -1:
		close(pipes_in[0]);
		close(pipes_in[1]);
		close(pipes_out[0]);
		close(pipes_out[1]);
		pthrow(ecError);
	default:
		close(pipes_in[0]);
		close(pipes_out[1]);
		break;
	}
	write(pipes_in[1], rtfbuffer, rtflen);
	close(pipes_in[1]);
	offset = 0;
	bufflen = 64*1024;
	pbuff = sta_malloc<char>(bufflen);
	if (NULL == pbuff) {
		close(pipes_out[0]);
		pthrow(ecMAPIOOM);
	}
	while ((readlen = read(pipes_out[0],
		pbuff, bufflen - offset)) > 0) {
		offset += readlen;
		if (offset == bufflen) {
			bufflen *= 2;
			pbuff = sta_realloc<char>(pbuff, bufflen);
			if (NULL == pbuff) {
				close(pipes_out[0]);
				pthrow(ecMAPIOOM);
			}
		}
	}
	waitpid(pid, &status, 0);
	close(pipes_out[0]);
	RETVAL_STRINGL(pbuff, offset);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_getrulestable)
{
	ZCL_MEMORY;
	uint32_t hobject;
	zval *pzresource;
	MAPI_RESOURCE *pfolder, *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto result = zclient_loadruletable(
		pfolder->hsession, pfolder->hobject,
		&hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::table;
	presource->hsession = pfolder->hsession;
	presource->hobject = hobject;
	RETVAL_RG(presource, le_mapi_table);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_getsearchcriteria)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval pzfolderlist, pzrestriction, *pzresource;
	uint32_t search_state;
	MAPI_RESOURCE *pfolder;
	RESTRICTION *prestriction;
	BINARY_ARRAY entryid_array;

	ZVAL_NULL(&pzfolderlist);
	ZVAL_NULL(&pzrestriction);
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l",
		&pzresource, &flags) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto result = zclient_getsearchcriteria(
		pfolder->hsession, pfolder->hobject,
		&entryid_array, &prestriction,
		&search_state);
	if (result != ecSuccess)
		pthrow(result);
	if (prestriction == nullptr)
		ZVAL_NULL(&pzrestriction);
	else if (auto err = restriction_to_php(prestriction, &pzrestriction); err != ecSuccess)
		pthrow(err);
	else if (auto er2 = binary_array_to_php(&entryid_array, &pzfolderlist); er2 != ecSuccess)
		pthrow(er2);
	zarray_init(return_value);
	add_assoc_zval(return_value, "restriction", &pzrestriction);
	add_assoc_zval(return_value, "folderlist", &pzfolderlist);
	add_assoc_long(return_value, "searchstate", search_state);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_setsearchcriteria)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresource, *pzfolderlist, *pzrestriction = nullptr;
	MAPI_RESOURCE *pfolder;
	RESTRICTION restriction, *prestriction = nullptr;
	BINARY_ARRAY entryid_array, *pentryid_array = nullptr;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "raal",
		&pzresource, &pzrestriction, &pzfolderlist, &flags) ==
		FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	if (pzrestriction != nullptr) {
		auto err = php_to_restriction(pzrestriction, &restriction);
		if (err != ecSuccess)
			pthrow(err);
		prestriction = &restriction;
	}
	if (pzfolderlist != nullptr) {
		auto err = php_to_binary_array(pzfolderlist, &entryid_array);
		if (err != ecSuccess)
			pthrow(err);
		pentryid_array = &entryid_array;
	}
	auto result = zclient_setsearchcriteria(
		pfolder->hsession, pfolder->hobject,
		flags, pentryid_array, prestriction);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_folder_modifyrules)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzrows, *pzresource;
	RULE_LIST rule_list;
	MAPI_RESOURCE *pfolder;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra|l", &pzresource, &pzrows, &flags) == FAILURE
		|| NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_folder, le_mapi_folder);
	if (pfolder->type != zs_objtype::folder)
		pthrow(ecInvalidObject);
	auto err = php_to_rule_list(pzrows, &rule_list);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_modifyrules(pfolder->hsession,
					pfolder->hobject, flags, &rule_list);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_zarafa_getpermissionrules)
{
	ZCL_MEMORY;
	zend_long acl_type;
	zval *pzresource;
	PERMISSION_SET perm_set;
	MAPI_RESOURCE *presource;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rl", &pzresource, &acl_type) == FAILURE || NULL
		== pzresource)
		pthrow(ecInvalidParam);
	if (ACCESS_TYPE_GRANT != acl_type)
		pthrow(ecNotSupported);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_msgstore) {
		ZEND_FETCH_RESOURCE(presource, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_msgstore, le_mapi_msgstore);
		if (presource->type != zs_objtype::store)
			pthrow(ecInvalidObject);
	} else if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(presource, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (presource->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecNotSupported);
	}
	}
	auto result = zclient_getpermissions(
		presource->hsession, presource->hobject,
		&perm_set);
	if (result != ecSuccess)
		pthrow(result);
	zarray_init(return_value);
	for (unsigned int i = 0; i < perm_set.count; ++i) {
		zval pzdata_value;
		zarray_init(&pzdata_value);
		add_assoc_stringl(&pzdata_value, "userid",
			reinterpret_cast<const char *>(perm_set.prows[i].entryid.pb),
			perm_set.prows[i].entryid.cb);
		add_assoc_long(&pzdata_value,
			"type", ACCESS_TYPE_GRANT);
		add_assoc_long(&pzdata_value, "rights",
			perm_set.prows[i].member_rights);
		add_assoc_long(&pzdata_value,
			"state", RIGHT_NORMAL);
		add_index_zval(return_value, i, &pzdata_value);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_zarafa_setpermissionrules)
{
	ZCL_MEMORY;
	zval *pzperms, *pzresource;
	HashTable *pdata, *ptarget_hash;
	MAPI_RESOURCE *pfolder;
	PERMISSION_SET perm_set;
	zstrplus str_userid(zend_string_init(ZEND_STRL("userid"), 0));
	zstrplus str_type(zend_string_init(ZEND_STRL("type"), 0));
	zstrplus str_rights(zend_string_init(ZEND_STRL("rights"), 0));
	zstrplus str_state(zend_string_init(ZEND_STRL("state"), 0));

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra", &pzresource, &pzperms) == FAILURE || NULL
		== pzresource || NULL == pzperms)
		pthrow(ecInvalidParam);
	{
	auto type = Z_RES_TYPE_P(pzresource);
	if (type == le_mapi_folder) {
		ZEND_FETCH_RESOURCE(pfolder, MAPI_RESOURCE*,
			&pzresource, -1, name_mapi_folder, le_mapi_folder);
		if (pfolder->type != zs_objtype::folder)
			pthrow(ecInvalidObject);
	} else {
		pthrow(ecNotSupported);
	}
	}
	ZVAL_DEREF(pzperms);
	ptarget_hash = HASH_OF(pzperms);
	if (NULL == ptarget_hash)
		pthrow(ecInvalidParam);
	zend_hash_internal_pointer_reset(ptarget_hash);
	perm_set.count = zend_hash_num_elements(ptarget_hash);
	perm_set.prows = sta_malloc<PERMISSION_ROW>(perm_set.count);
	if (NULL == perm_set.prows)
		pthrow(ecMAPIOOM);

	for (unsigned int i = 0, j = 0; i < perm_set.count; ++i) {
		auto ppzentry = zend_hash_get_current_data(ptarget_hash);
		ZVAL_DEREF(ppzentry);
		pdata = HASH_OF(ppzentry);
		zend_hash_internal_pointer_reset(pdata);
		auto value = zend_hash_find(pdata, str_userid.get());
		if (value == nullptr)
			continue;
		auto ss = zval_get_string(value);
		perm_set.prows[j].entryid.pb = reinterpret_cast<uint8_t *>(ZSTR_VAL(ss));
		perm_set.prows[j].entryid.cb = ZSTR_LEN(ss);
		value = zend_hash_find(pdata, str_type.get());
		if (value == nullptr)
			continue;
		if (zval_get_long(value) != ACCESS_TYPE_GRANT)
			continue;
		value = zend_hash_find(pdata, str_rights.get());
		if (value == nullptr)
			continue;
		perm_set.prows[j].member_rights = zval_get_long(value);
		value = zend_hash_find(pdata, str_state.get());
		perm_set.prows[j].flags = value != nullptr ? zval_get_long(value) :
		                          RIGHT_NEW | RIGHT_AUTOUPDATE_DENIED;
		j ++;
		zend_hash_move_forward(ptarget_hash);
	}
	auto result = zclient_modifypermissions(
		pfolder->hsession, pfolder->hobject,
		&perm_set);
	if (result != ecSuccess)
		pthrow(result);
	MAPI_G(hr) = ecSuccess;
	RETVAL_TRUE;
}

/*
	This function will get user's freebusy data
	
	param session[in]	session object
	param entryid[in]	user's entryid
	param starttime		unix time stamp
	param endtime 		unix time stamp
	return				json string of user's freebusy data,
						json string, empty string means not
						found. fields:
						starttime, endtime, busytype, subject(base64),
						location(base64), rests are all bool(absence
						means false). ismeeting, isrecurring,
						isexception, isreminderset, isprivate
*/
static ZEND_FUNCTION(mapi_getuseravailability)
{
	ZCL_MEMORY;
	zend_long starttime, endtime;
	BINARY entryid;
	size_t eid_size = 0;
	zval *pzresource;
	char *presult_string;
	MAPI_RESOURCE *psession;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rsll",
	    &pzresource, &entryid.pb, &eid_size, &starttime, &endtime) == FAILURE ||
	    pzresource == nullptr || entryid.pb == nullptr || eid_size == 0)
		pthrow(ecInvalidParam);
	entryid.cb = eid_size;
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	auto result = zclient_getuseravailability(
		psession->hsession, entryid, starttime,
		endtime, &presult_string);
	if (result != ecSuccess)
		pthrow(result);
	if (NULL == presult_string) {
		RETVAL_NULL();
		return;
	}
	RETVAL_STRING(presult_string);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_exportchanges_config)
{
	ZCL_MEMORY;
	zend_long flags = 0, buffersize = 0;
	zval *pzrestrict, *pzresstream, *pzincludeprops, *pzexcludeprops;
	zval *pzresimportchanges, *pzresexportchanges;
	ICS_EXPORT_CTX *pctx;
	STREAM_OBJECT *pstream;
	RESTRICTION restriction, *prestriction = nullptr;
	ICS_IMPORT_CTX *pimporter = nullptr;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rrlzzzzl", &pzresexportchanges, &pzresstream, &flags,
		&pzresimportchanges, &pzrestrict, &pzincludeprops,
		&pzexcludeprops, &buffersize) == FAILURE || NULL
		== pzresexportchanges || NULL == pzresstream ||
		NULL == pzresimportchanges)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_EXPORT_CTX*, &pzresexportchanges,
		-1, name_mapi_exportchanges, le_mapi_exportchanges);
	if (Z_TYPE_P(pzresimportchanges) == IS_RESOURCE) {
		auto type = Z_RES_TYPE_P(pzresimportchanges);
		if(type == le_mapi_importcontentschanges) {
			ZEND_FETCH_RESOURCE(pimporter,
				ICS_IMPORT_CTX*, &pzresimportchanges,
				-1, name_mapi_importcontentschanges,
				le_mapi_importcontentschanges);
		} else if(type == le_mapi_importhierarchychanges) {
			ZEND_FETCH_RESOURCE(pimporter,
				ICS_IMPORT_CTX*, &pzresimportchanges,
				-1, name_mapi_importhierarchychanges,
				le_mapi_importhierarchychanges);
		} else {
			pthrow(ecInvalidParam);
		}
	} else {
		pthrow(ecInvalidParam);
	}
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresstream, -1, name_stream, le_stream);
	if (NULL != pzrestrict && Z_TYPE_P(pzrestrict) == IS_ARRAY) {
		auto err = php_to_restriction(pzrestrict, &restriction);
		if (err != ecSuccess)
			pthrow(err);
		prestriction = &restriction;
	}
	zval_ptr_dtor(&pctx->pztarget_obj);
	pctx->sync_steps = buffersize;
	ZVAL_OBJ(&pctx->pztarget_obj, Z_OBJ(pimporter->pztarget_obj));
	Z_ADDREF(pctx->pztarget_obj);
	pctx->ics_type = pimporter->ics_type;
	auto result = zclient_configsync(pctx->hsession, pctx->hobject,
			flags, stream_object_get_content(pstream), prestriction,
			&pctx->b_changed, &pctx->total_steps);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static zend_bool import_message_change(zval *pztarget_obj,
	const TPROPVAL_ARRAY *pproplist, uint32_t flags)
{
	zval pzvalreturn, pzvalargs[3], pzvalfuncname;

	ZVAL_NULL(&pzvalargs[0]);
	ZVAL_LONG(&pzvalargs[1], flags);
	ZVAL_NULL(&pzvalargs[2]);
	auto err = tpropval_array_to_php(pproplist, &pzvalargs[0]);
	if (err != ecSuccess)
		return 0;
	ZVAL_NULL(&pzvalreturn);
	ZVAL_STRING(&pzvalfuncname, "ImportMessageChange");
	uint32_t hresult = call_user_function(NULL, pztarget_obj, &pzvalfuncname,
	                   &pzvalreturn, 3, pzvalargs) == FAILURE ?
	                   ecError : zval_get_long(&pzvalreturn);
	zval_ptr_dtor(&pzvalfuncname);
	zval_ptr_dtor(&pzvalreturn);
	zval_ptr_dtor(&pzvalargs[0]);
	zval_ptr_dtor(&pzvalargs[1]);
	zval_ptr_dtor(&pzvalargs[2]);
	if (hresult != SYNC_E_IGNORE)
		return 0;
	return 1;
}

static zend_bool import_message_deletion(zval *pztarget_obj,
	uint32_t flags, const BINARY_ARRAY *pbins)
{
	zval pzvalreturn, pzvalargs[2], pzvalfuncname;

	ZVAL_NULL(&pzvalfuncname);
	ZVAL_NULL(&pzvalreturn);
	ZVAL_LONG(&pzvalargs[0], flags);
	ZVAL_NULL(&pzvalargs[1]);
	auto err = binary_array_to_php(pbins, &pzvalargs[1]);
	if (err != ecSuccess) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		zval_ptr_dtor(&pzvalargs[0]);
		return 0;
	}
	ZVAL_STRING(&pzvalfuncname, "ImportMessageDeletion");
	if (call_user_function(NULL, pztarget_obj, &pzvalfuncname,
	    &pzvalreturn, 2, pzvalargs) == FAILURE) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		zval_ptr_dtor(&pzvalargs[0]);
		zval_ptr_dtor(&pzvalargs[1]);
		return 0;
	}
	zval_ptr_dtor(&pzvalfuncname);
	zval_ptr_dtor(&pzvalreturn);
	zval_ptr_dtor(&pzvalargs[0]);
	zval_ptr_dtor(&pzvalargs[1]);
	return 1;
}

static zend_bool import_readstate_change(
	zval *pztarget_obj, const STATE_ARRAY *pstates)
{
	zval pzvalargs, pzvalreturn, pzvalfuncname;
    
	ZVAL_NULL(&pzvalfuncname);
	ZVAL_NULL(&pzvalreturn);
	auto err = state_array_to_php(pstates, &pzvalargs);
	if (err != ecSuccess)
		return 0;
	ZVAL_STRING(&pzvalfuncname, "ImportPerUserReadStateChange");
	if (call_user_function(nullptr, pztarget_obj, &pzvalfuncname,
	    &pzvalreturn, 1, &pzvalargs) == FAILURE) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		zval_ptr_dtor(&pzvalargs);
		return 0;
	}
	zval_ptr_dtor(&pzvalfuncname);
	zval_ptr_dtor(&pzvalreturn);
	zval_ptr_dtor(&pzvalargs);
	return 1;
}

static zend_bool import_folder_change(zval *pztarget_obj,
	TPROPVAL_ARRAY *pproplist)
{
	zval pzvalargs, pzvalreturn, pzvalfuncname;

	ZVAL_NULL(&pzvalfuncname);
	ZVAL_NULL(&pzvalreturn);
	auto err = tpropval_array_to_php(pproplist, &pzvalargs);
	if (err != ecSuccess) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		return 0;
	}
	ZVAL_STRING(&pzvalfuncname, "ImportFolderChange");
	if (call_user_function(nullptr, pztarget_obj, &pzvalfuncname,
	    &pzvalreturn, 1, &pzvalargs) == FAILURE) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		zval_ptr_dtor(&pzvalargs);
		return 0;
	}
	zval_ptr_dtor(&pzvalfuncname);
	zval_ptr_dtor(&pzvalreturn);
	zval_ptr_dtor(&pzvalargs);
	return 1;
}

static zend_bool import_folder_deletion(zval *pztarget_obj,
	BINARY_ARRAY *pentryid_array)
{
	zval pzvalreturn, pzvalargs[2], pzvalfuncname;

	ZVAL_NULL(&pzvalfuncname);
	ZVAL_NULL(&pzvalreturn);
	ZVAL_LONG(&pzvalargs[0], 0); /* flags, not used currently */
	auto err = binary_array_to_php(pentryid_array, &pzvalargs[1]);
	if (err != ecSuccess) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		zval_ptr_dtor(&pzvalargs[0]);
		return 0;
	}
	ZVAL_STRING(&pzvalfuncname, "ImportFolderDeletion");
	if (call_user_function(nullptr, pztarget_obj, &pzvalfuncname,
	    &pzvalreturn, 2, pzvalargs) == FAILURE) {
		zval_ptr_dtor(&pzvalfuncname);
		zval_ptr_dtor(&pzvalreturn);
		zval_ptr_dtor(&pzvalargs[0]);
		zval_ptr_dtor(&pzvalargs[1]);
		return 0;
	}
	zval_ptr_dtor(&pzvalfuncname);
	zval_ptr_dtor(&pzvalreturn);
	zval_ptr_dtor(&pzvalargs[0]);
	zval_ptr_dtor(&pzvalargs[1]);
	return 1;
}


static ZEND_FUNCTION(mapi_exportchanges_synchronize)
{
	ZCL_MEMORY;
	uint32_t flags;
	zend_bool b_new;
	zval *pzresource;
	BINARY_ARRAY bins;
	STATE_ARRAY states;
	ICS_EXPORT_CTX *pctx;
	TPROPVAL_ARRAY propvals;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_EXPORT_CTX*, &pzresource,
		-1, name_mapi_exportchanges, le_mapi_exportchanges);
	if (0 == pctx->b_changed) {
		RETVAL_TRUE;
		MAPI_G(hr) = ecSuccess;
		return;
	}
	if (0 == pctx->progress) {
		if (ICS_TYPE_CONTENTS == pctx->ics_type) {
			auto result = zclient_syncdeletions(
				pctx->hsession, pctx->hobject, 0, &bins);
			if (result != ecSuccess)
				pthrow(result);
			if (bins.count > 0 && !import_message_deletion(&pctx->pztarget_obj, 0, &bins))
				pthrow(ecError);
			result = zclient_syncdeletions(pctx->hsession,
						pctx->hobject, SYNC_SOFT_DELETE, &bins);
			if (result != ecSuccess)
				pthrow(result);
			if (bins.count > 0 && !import_message_deletion(&pctx->pztarget_obj, SYNC_SOFT_DELETE, &bins))
				pthrow(ecError);
			result = zclient_syncreadstatechanges(
				pctx->hsession, pctx->hobject, &states);
			if (result != ecSuccess)
				pthrow(result);
			if (states.count > 0 && !import_readstate_change(&pctx->pztarget_obj, &states))
				pthrow(ecError);
		} else {
			auto result = zclient_syncdeletions(
				pctx->hsession, pctx->hobject, 0, &bins);
			if (result != ecSuccess)
				pthrow(result);
			if (bins.count > 0 && !import_folder_deletion(&pctx->pztarget_obj, &bins))
				pthrow(ecError);
		}
	}
	for (size_t i = 0; i < pctx->sync_steps; ++i, ++pctx->progress) {
		if (ICS_TYPE_CONTENTS == pctx->ics_type) {
			auto result = zclient_syncmessagechange(
				pctx->hsession, pctx->hobject, &b_new,
				&propvals);
			if (result == ecNotFound)
				continue;
			if (result != ecSuccess)
				pthrow(result);
			flags = b_new ? SYNC_NEW_MESSAGE : 0;
			if (!import_message_change(&pctx->pztarget_obj,
				&propvals, flags))
				pthrow(ecError);
		} else {
			auto result = zclient_syncfolderchange(
				pctx->hsession, pctx->hobject,
				&propvals);
			if (result == ecNotFound)
				continue;
			if (result != ecSuccess)
				pthrow(result);
			if (!import_folder_change(&pctx->pztarget_obj,
				&propvals))
				pthrow(ecError);
		}
	}
	if (pctx->progress >= pctx->total_steps) {
		RETVAL_TRUE;
	} else {
		zarray_init(return_value);
		add_next_index_long(return_value, pctx->total_steps);
		add_next_index_long(return_value, pctx->progress);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_exportchanges_updatestate)
{
	ZCL_MEMORY;
	BINARY state_bin;
	zval *pzresstream, *pzresexportchanges;
	ICS_EXPORT_CTX *pctx;
	STREAM_OBJECT *pstream;
	
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rr",
		&pzresexportchanges, &pzresstream) == FAILURE || NULL
		== pzresexportchanges || NULL == pzresstream)
		pthrow(ecInvalidParam);
    ZEND_FETCH_RESOURCE(pctx, ICS_EXPORT_CTX*, &pzresexportchanges,
		-1, name_mapi_exportchanges, le_mapi_exportchanges);
    ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresstream, -1, name_stream, le_stream);
	auto result = zclient_statesync(pctx->hsession,
						pctx->hobject, &state_bin);
	if (result != ecSuccess)
		pthrow(result);
	stream_object_reset(pstream);
	stream_object_write(pstream, state_bin.pb, state_bin.cb);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_exportchanges_getchangecount)
{
	ZCL_MEMORY;
	zval *pzresource;
	ICS_EXPORT_CTX *pctx;
	
    if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &pzresource) == FAILURE || NULL == pzresource)
		pthrow(ecInvalidParam);
    ZEND_FETCH_RESOURCE(pctx, ICS_EXPORT_CTX*, &pzresource,
		-1, name_mapi_exportchanges, le_mapi_exportchanges);
	if (pctx->total_steps == 0 && pctx->b_changed != 0) {
		RETVAL_LONG(1);
	} else {
		RETVAL_LONG(pctx->total_steps);
	}
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importcontentschanges_config)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresimport, *pzresstream;
	ICS_IMPORT_CTX *pctx;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rrl",
		&pzresimport, &pzresstream, &flags) == FAILURE || NULL
		== pzresimport || NULL == pzresstream)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importcontentschanges, le_mapi_importcontentschanges);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresstream, -1, name_stream, le_stream);
	auto result = zclient_configimport(pctx->hsession,
					pctx->hobject, ICS_TYPE_CONTENTS,
					stream_object_get_content(pstream));
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importcontentschanges_updatestate)
{
	ZCL_MEMORY;
	BINARY state_bin;
	zval *pzresimport, *pzresstream;
	ICS_IMPORT_CTX *pctx;
	STREAM_OBJECT *pstream;
	
    if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r|r", &pzresimport, &pzresstream) == FAILURE ||
		NULL == pzresimport || NULL == pzresstream)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importcontentschanges, le_mapi_importcontentschanges);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresstream, -1, name_stream, le_stream);
	auto result = zclient_stateimport(pctx->hsession,
							pctx->hobject, &state_bin);
	if (result != ecSuccess)
		pthrow(result);
	stream_object_reset(pstream);
	stream_object_write(pstream, state_bin.pb, state_bin.cb);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importcontentschanges_importmessagechange)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	uint32_t hobject;
	zval *pzresprops, *pzresimport, *pzresmessage;
	ICS_IMPORT_CTX *pctx;
	TPROPVAL_ARRAY propvals;
	MAPI_RESOURCE *presource;
	
    if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ralz", &pzresimport, &pzresprops, &flags,
		&pzresmessage) == FAILURE || NULL == pzresimport
		|| NULL == pzresprops || NULL == pzresmessage)
		pthrow(ecInvalidParam);
    ZEND_FETCH_RESOURCE(pctx, ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importcontentschanges, le_mapi_importcontentschanges);
	auto err = php_to_tpropval_array(pzresprops, &propvals);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_importmessage(pctx->hsession,
			pctx->hobject, flags, &propvals, &hobject);
	if (result != ecSuccess)
		pthrow(result);
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource)
		pthrow(ecMAPIOOM);
	presource->type = zs_objtype::message;
	presource->hsession = pctx->hsession;
	presource->hobject = hobject;
	ZVAL_DEREF(pzresmessage);
	ZVAL_RES(pzresmessage, zend_register_resource(presource, le_mapi_message));
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importcontentschanges_importmessagedeletion)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresimport, *pzresmessages;
	ICS_IMPORT_CTX *pctx;
	BINARY_ARRAY message_bins;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rla",
		&pzresimport, &flags, &pzresmessages) == FAILURE ||
		NULL == pzresimport || NULL == pzresmessages)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx,
		ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importcontentschanges,
		le_mapi_importcontentschanges);
	auto err = php_to_binary_array(pzresmessages, &message_bins);
	if (err != ecSuccess)
		pthrow(err);
	flags = (flags & SYNC_SOFT_DELETE) ? 0 : SYNC_DELETES_FLAG_HARDDELETE;
	auto result = zclient_importdeletion(
			pctx->hsession, pctx->hobject,
			flags, &message_bins);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importcontentschanges_importperuserreadstatechange)
{
	ZCL_MEMORY;
	zval *pzresimport, *pzresreadstates;
	ICS_IMPORT_CTX *pctx;
	STATE_ARRAY message_states;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ra",
		&pzresimport, &pzresreadstates) == FAILURE || NULL ==
		pzresimport || NULL == pzresreadstates)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importcontentschanges, le_mapi_importcontentschanges);
	auto err = php_to_state_array(pzresreadstates, &message_states);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_importreadstates(
				pctx->hsession, pctx->hobject,
				&message_states);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importcontentschanges_importmessagemove)
{
	MAPI_G(hr) = NotImplemented;
	if (MAPI_G(exceptions_enabled))
		zend_throw_exception(MAPI_G(exception_ce),
			"MAPI error ", MAPI_G(hr));
	RETVAL_FALSE;
}

static ZEND_FUNCTION(mapi_importhierarchychanges_config)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresimport, *pzresstream;
	ICS_IMPORT_CTX *pctx;
	STREAM_OBJECT *pstream;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rrl",
		&pzresimport, &pzresstream, &flags) == FAILURE || NULL
		== pzresimport || NULL == pzresstream)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importhierarchychanges, le_mapi_importhierarchychanges);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresstream, -1, name_stream, le_stream);
	auto result = zclient_configimport(pctx->hsession, pctx->hobject,
				ICS_TYPE_HIERARCHY, stream_object_get_content(pstream));
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importhierarchychanges_updatestate)
{
	ZCL_MEMORY;
	BINARY state_bin;
	zval *pzresimport, *pzresstream;
	ICS_IMPORT_CTX *pctx;
	STREAM_OBJECT *pstream;
	
    if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r|r", &pzresimport, &pzresstream) == FAILURE ||
		NULL == pzresimport || NULL == pzresstream)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx,
		ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importhierarchychanges,
		le_mapi_importhierarchychanges);
	ZEND_FETCH_RESOURCE(pstream, STREAM_OBJECT*,
		&pzresstream, -1, name_stream, le_stream);
	auto result = zclient_stateimport(pctx->hsession,
							pctx->hobject, &state_bin);
	if (result != ecSuccess)
		pthrow(result);
	stream_object_reset(pstream);
	stream_object_write(pstream, state_bin.pb, state_bin.cb);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importhierarchychanges_importfolderchange)
{
	ZCL_MEMORY;
	zval *pzresprops, *pzresimport;
	ICS_IMPORT_CTX *pctx;
	TPROPVAL_ARRAY propvals;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ra", &pzresimport, &pzresprops) == FAILURE ||
		NULL == pzresimport || NULL == pzresprops)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx,
		ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importhierarchychanges,
		le_mapi_importhierarchychanges);
	auto err = php_to_tpropval_array(pzresprops, &propvals);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_importfolder(
			pctx->hsession, pctx->hobject,
			&propvals);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_importhierarchychanges_importfolderdeletion)
{
	ZCL_MEMORY;
	zend_long flags = 0;
	zval *pzresimport, *pzresfolders;
	ICS_IMPORT_CTX *pctx;
	BINARY_ARRAY folder_bins;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rla", &pzresimport, &flags, &pzresfolders) == FAILURE
		|| NULL == pzresimport || NULL == pzresfolders)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pctx, ICS_IMPORT_CTX*, &pzresimport, -1,
		name_mapi_importhierarchychanges, le_mapi_importhierarchychanges);
	auto err = php_to_binary_array(pzresfolders, &folder_bins);
	if (err != ecSuccess)
		pthrow(err);
	auto result = zclient_importdeletion(
			pctx->hsession, pctx->hobject,
			flags, &folder_bins);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_wrap_importcontentschanges)
{
	ZCL_MEMORY;
	zval *pzobject;
	ICS_IMPORT_CTX *pctx;

    if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"o", &pzobject) == FAILURE || NULL == pzobject)
		pthrow(ecInvalidParam);
	pctx = st_malloc<ICS_IMPORT_CTX>();
	if (NULL == pctx)
		pthrow(ecMAPIOOM);
	pctx->ics_type = ICS_TYPE_CONTENTS;
	pctx->hobject = 0;
	ZVAL_OBJ(&pctx->pztarget_obj, Z_OBJ_P(pzobject));
	Z_ADDREF(pctx->pztarget_obj);
	RETVAL_RG(pctx, le_mapi_importcontentschanges);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_wrap_importhierarchychanges)
{
	ZCL_MEMORY;
	zval *pzobject;
    ICS_IMPORT_CTX *pctx;

    if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"o", &pzobject) == FAILURE || NULL == pzobject)
		pthrow(ecInvalidParam);
	pctx = st_malloc<ICS_IMPORT_CTX>();
	if (NULL == pctx)
		pthrow(ecMAPIOOM);
	pctx->ics_type = ICS_TYPE_HIERARCHY;
	pctx->hobject = 0;
	ZVAL_OBJ(&pctx->pztarget_obj, Z_OBJ_P(pzobject));
	Z_ADDREF(pctx->pztarget_obj);
	RETVAL_RG(pctx, le_mapi_importhierarchychanges);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_inetmapi_imtoinet)
{
	ZCL_MEMORY;
	BINARY eml_bin;
	zval *pzressession, *pzresmessage, *pzresoptions, *pzresaddrbook;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rrra", &pzressession, &pzresaddrbook, &pzresmessage,
		&pzresoptions) == FAILURE || NULL == pzresmessage)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresmessage, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidParam);
	auto result = zclient_messagetorfc822(
		pmessage->hsession, pmessage->hobject,
		&eml_bin);
	if (result != ecSuccess)
		pthrow(result);
	auto pstream = st_calloc<STREAM_OBJECT>();
	if (NULL == pstream)
		pthrow(ecMAPIOOM);
	stream_object_write(pstream, eml_bin.pb, eml_bin.cb);
	stream_object_seek(pstream, STREAM_SEEK_SET, 0);
	RETVAL_RG(pstream, le_stream);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_inetmapi_imtomapi)
{
	ZCL_MEMORY;
	size_t cbstring = 0;
	char *szstring;
	BINARY eml_bin;
	zval *pzresstore, *pzressession, *pzresmessage, *pzresoptions, *pzresaddrbook;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rrrrsa",
		&pzressession, &pzresstore, &pzresaddrbook, &pzresmessage,
		&szstring, &cbstring, &pzresoptions) == FAILURE || NULL ==
		pzresmessage)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresmessage, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidParam);
	unsigned int mxf_flags = 0;
	auto opthash = HASH_OF(pzresoptions);
	if (opthash != nullptr) {
		zend_string *key = nullptr;
		zend_ulong num __attribute__((unused)) = 0;
		zval *entry __attribute__((unused)) = nullptr;
		ZEND_HASH_FOREACH_KEY_VAL(opthash, num, key, entry) {
			if (key == nullptr)
				php_error_docref(nullptr, E_WARNING, "imtomapi: options array ought to use string keys");
			else if (strcmp(key->val, "parse_smime_signed") == 0)
				mxf_flags |= MXF_UNWRAP_SMIME_CLEARSIGNED;
			else
				php_error_docref(nullptr, E_WARNING, "Unknown imtomapi option: \"%s\"", key->val);
		} ZEND_HASH_FOREACH_END();
	}
	eml_bin.pb = reinterpret_cast<uint8_t *>(szstring);
	eml_bin.cb = cbstring;
	auto result = zclient_rfc822tomessage(pmessage->hsession,
	         pmessage->hobject, mxf_flags, &eml_bin);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}    

static ZEND_FUNCTION(mapi_icaltomapi)
{
	ZCL_MEMORY;
	size_t cbstring = 0;
	char *szstring;
	BINARY ical_bin;
	zval *pzresstore, *pzresmessage, *pzressession, *pzresaddrbook;
	MAPI_RESOURCE *pmessage;
	zend_bool b_norecipients;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rrrrsb",
		&pzressession, &pzresstore, &pzresaddrbook, &pzresmessage,
		&szstring, &cbstring, &b_norecipients) == FAILURE || NULL
		== pzresmessage)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresmessage, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidParam);
	ical_bin.pb = reinterpret_cast<uint8_t *>(szstring);
	ical_bin.cb = cbstring;
	auto result = zclient_icaltomessage(
		pmessage->hsession, pmessage->hobject,
		&ical_bin);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static void imtomapi2_proc(INTERNAL_FUNCTION_PARAMETERS, GUID, LONG_ARRAY &);

/**
 * mapi_icaltomapi2(resource $abook, resource $folder,
 *                  string $ics_data) : array|false|throw;
 *
 * @abook:	address book (has reference to session object in Gromox)
 * @folder:	target folder for event messages (usually the calendar)
 *
 * Returns an array of message resource objects. On error, the function throws.
 * For compatibility reasons, you must check the return value for the value
 * "false" as well.
 */
static ZEND_FUNCTION(mapi_icaltomapi2)
{
	ZCL_MEMORY;
	zval *resabook, *resfolder;
	char *icsdata = nullptr;
	size_t icsdatalen = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rrs", &resabook, &resfolder,
	    &icsdata, &icsdatalen) == FAILURE || resabook == nullptr)
		pthrow(ecInvalidParam);

	MAPI_RESOURCE *fld, *abk;
	ZEND_FETCH_RESOURCE(abk, MAPI_RESOURCE *, &resabook, -1,
		name_mapi_addressbook, le_mapi_addressbook);
	ZEND_FETCH_RESOURCE(fld, MAPI_RESOURCE *, &resfolder, -1,
		name_mapi_folder, le_mapi_folder);
	LONG_ARRAY msg_handles{};
	auto ret = zclient_imtomessage2(abk->hsession, fld->hobject,
	           IMTOMESSAGE_ICAL, icsdata, &msg_handles);
	if (ret != ecSuccess)
		pthrow(ret);
	imtomapi2_proc(INTERNAL_FUNCTION_PARAM_PASSTHRU,
		fld->hsession, msg_handles);
}

static void imtomapi2_proc(INTERNAL_FUNCTION_PARAMETERS,
    GUID session, LONG_ARRAY &msg_handles)
{
	zarray_init(return_value);
	for (size_t i = 0; i < msg_handles.count; ++i) {
		auto res = st_malloc<MAPI_RESOURCE>();
		if (res == nullptr)
			pthrow(ecMAPIOOM);
		res->type = zs_objtype::message;
		res->hsession = session;
		res->hobject = msg_handles.pl[i];
		zval mres;
		ZVAL_RES(&mres, zend_register_resource(res, le_mapi_message));
		add_index_zval(return_value, i, &mres);
	}
	MAPI_G(hr) = ecSuccess;
}

/**
 * mapi_vcftomapi2(resource $folder, string $ics_data) : array|false|throw;
 *
 * @folder:	target folder for event messages
 * 		(usually the private contacts folder)
 *
 * Returns an array of message resource objects. On error, the function throws.
 * For compatibility reasons, you must check the return value for the value
 * "false" as well.
 */
static ZEND_FUNCTION(mapi_vcftomapi2)
{
	ZCL_MEMORY;
	zval *resfolder;
	char *vcdata = nullptr;
	size_t vcdatalen = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &resfolder,
	    &vcdata, &vcdatalen) == FAILURE || resfolder == nullptr)
		pthrow(ecInvalidParam);

	MAPI_RESOURCE *fld;
	ZEND_FETCH_RESOURCE(fld, MAPI_RESOURCE *, &resfolder, -1,
		name_mapi_folder, le_mapi_folder);
	LONG_ARRAY msg_handles{};
	auto ret = zclient_imtomessage2(fld->hsession, fld->hobject,
	           IMTOMESSAGE_VCARD, vcdata, &msg_handles);
	if (ret != ecSuccess)
		pthrow(ret);
	imtomapi2_proc(INTERNAL_FUNCTION_PARAM_PASSTHRU,
		fld->hsession, msg_handles);
}

static ZEND_FUNCTION(mapi_mapitoical)
{
	ZCL_MEMORY;
	BINARY ical_bin;
	zval *pzressession, *pzresmessage, *pzresoptions, *pzresaddrbook;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rrra", &pzressession, &pzresaddrbook, &pzresmessage,
		&pzresoptions) == FAILURE || NULL == pzresmessage)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresmessage, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidParam);
	auto result = zclient_messagetoical(
		pmessage->hsession, pmessage->hobject,
		&ical_bin);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_STRINGL(reinterpret_cast<const char *>(ical_bin.pb), ical_bin.cb);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_vcftomapi)
{
	ZCL_MEMORY;
	size_t cbstring = 0;
	char *szstring;
	BINARY vcf_bin;
	zval *pzresstore, *pzressession, *pzresmessage;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rrrs",
	    &pzressession, &pzresstore, &pzresmessage, &szstring,
	    &cbstring) == FAILURE || NULL == pzresmessage)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresmessage, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidParam);
	vcf_bin.pb = reinterpret_cast<uint8_t *>(szstring);
	vcf_bin.cb = cbstring;
	auto result = zclient_vcftomessage(
		pmessage->hsession, pmessage->hobject,
		&vcf_bin);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_mapitovcf)
{
	ZCL_MEMORY;
	BINARY vcf_bin;
	zval *pzressession, *pzresmessage, *pzresoptions, *pzresaddrbook;
	MAPI_RESOURCE *pmessage;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rrra", &pzressession, &pzresaddrbook, &pzresmessage,
		&pzresoptions) == FAILURE || NULL == pzresmessage)
		pthrow(ecInvalidParam);
	ZEND_FETCH_RESOURCE(pmessage, MAPI_RESOURCE*,
		&pzresmessage, -1, name_mapi_message, le_mapi_message);
	if (pmessage->type != zs_objtype::message)
		pthrow(ecInvalidParam);
	auto result = zclient_messagetovcf(
		pmessage->hsession, pmessage->hobject,
		&vcf_bin);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_STRINGL(reinterpret_cast<const char *>(vcf_bin.pb), vcf_bin.cb);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(mapi_enable_exceptions)
{
	zend_string *clsname;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
	    "S", &clsname) == FAILURE) {
		RETVAL_FALSE;
		return;
	}
	auto ce = *reinterpret_cast<zend_class_entry **>(zend_hash_find(CG(class_table), clsname));
	if (ce != nullptr) {
		MAPI_G(exceptions_enabled) = 1;
		MAPI_G(exception_ce) = ce;
		RETVAL_TRUE;
	} else {
		RETVAL_FALSE;
	}
}

static ZEND_FUNCTION(mapi_feature)
{
	size_t cbfeature = 0;
	const char *szfeature;
	static constexpr const char *features[] =
		{"LOGONFLAGS", "NOTIFICATIONS",
		"INETMAPI_IMTOMAPI", "ST_ONLY_WHEN_OOF"};
	
	RETVAL_FALSE;
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"s", &szfeature, &cbfeature) == FAILURE ||
		NULL == szfeature || 0 == cbfeature) {
		return;
	}
	for (size_t i = 0; i < std::size(features); ++i) {
		if (0 == strcasecmp(features[i], szfeature)) {
			RETVAL_TRUE;
			return;
		}
	}
}

static ZEND_FUNCTION(mapi_msgstore_abortsubmit)
{
	RETVAL_TRUE;
}

static ZEND_FUNCTION(kc_session_save)
{
	zval *pzres, *pzoutstr;
	PUSH_CTX push_ctx;
	MAPI_RESOURCE *psession;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"rz", &pzres, &pzoutstr) == FAILURE || NULL ==
		pzres || NULL == pzoutstr) {
		RETVAL_LONG(ecInvalidParam);
		return;	
	}
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzres, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session) {
		RETVAL_LONG(ecInvalidParam);
		return;	
	}
	if (!push_ctx.init() ||
	    push_ctx.p_guid(psession->hsession) != EXT_ERR_SUCCESS) {
		RETVAL_LONG(ecMAPIOOM);
		return;	
	}
	ZVAL_STRINGL(pzoutstr, reinterpret_cast<const char *>(push_ctx.m_vdata), push_ctx.m_offset);
	RETVAL_LONG(ecSuccess);
}

static ZEND_FUNCTION(kc_session_restore)
{
	zval *pzres, *pzdata;
	GUID hsession;
	BINARY data_bin;
	PULL_CTX pull_ctx;
	MAPI_RESOURCE *presource;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"zz", &pzdata, &pzres) == FAILURE || NULL == pzdata
		|| NULL == pzres || Z_TYPE_P(pzdata) != IS_STRING) {
		RETVAL_LONG(ecInvalidParam);
		return;
	}
	data_bin.pb = reinterpret_cast<uint8_t *>(Z_STRVAL_P(pzdata));
	data_bin.cb = Z_STRLEN_P(pzdata);
	pull_ctx.init(data_bin.pb, data_bin.cb);
	if (pull_ctx.g_guid(&hsession) != EXT_ERR_SUCCESS) {
		RETVAL_LONG(ecInvalidParam);
		return;
	}
	auto result = zclient_checksession(hsession);
	if (result != ecSuccess) {
		RETVAL_LONG(result);
		return;
	}
	presource = st_malloc<MAPI_RESOURCE>();
	if (NULL == presource) {
		RETVAL_LONG(ecMAPIOOM);
		return;
	}
	presource->type = zs_objtype::session;
	presource->hobject = 0;
	presource->hsession = hsession;
	ZVAL_RES(pzres, zend_register_resource(presource, le_mapi_session));
	RETVAL_LONG(ecSuccess);
}


static ZEND_FUNCTION(nsp_getuserinfo)
{
	ZCL_MEMORY;
	char *px500dn, *username, *pdisplay_name;
	BINARY entryid;
	size_t username_len = 0;
	uint32_t privilege_bits;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"s", &username, &username_len) == FAILURE)
		pthrow(ecInvalidParam);
	auto result = zclient_uinfo(username, &entryid,
		&pdisplay_name, &px500dn, &privilege_bits);
	if (result != ecSuccess)
		pthrow(result);
	zarray_init(return_value);
	add_assoc_stringl(return_value, "userid", reinterpret_cast<const char *>(entryid.pb), entryid.cb);
	add_assoc_string(return_value, "username", username);
	add_assoc_string(return_value, "primary_email", username);
	add_assoc_string(return_value, "fullname", pdisplay_name);
	add_assoc_string(return_value, "essdn", px500dn);
	add_assoc_long(return_value, "privilege", privilege_bits);
	MAPI_G(hr) = ecSuccess;
}

static ZEND_FUNCTION(nsp_setuserpasswd)
{
	char *username, *old_passwd, *new_passwd;
	size_t username_len = 0, old_passwd_len = 0, new_passwd_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"sss", &username, &username_len, &old_passwd,
		&old_passwd_len, &new_passwd, &new_passwd_len)
		== FAILURE)
		pthrow(ecInvalidParam);
	auto result = zclient_setpasswd(username, old_passwd, new_passwd);
	if (result != ecSuccess)
		pthrow(result);
	RETVAL_TRUE;
}

static ZEND_FUNCTION(nsp_essdn_to_username)
{
	char *essdn = nullptr, *username = nullptr;
	size_t essdn_size = 0;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &essdn, &essdn_size) == FAILURE)
		pthrow(ecInvalidParam);
	auto ret = zclient_essdn_to_username(essdn, &username);
	if (ret != ecSuccess)
		pthrow(ret);
	RETVAL_STRING(username);
}

static ZEND_FUNCTION(mapi_linkmessage)
{
	ZCL_MEMORY;
	size_t srcheid_size = 0, msgeid_size = 0;
	zval *pzresource;
	BINARY search_entryid, message_entryid;
	MAPI_RESOURCE *psession;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|ss",
	    &pzresource, &search_entryid.pb, &srcheid_size,
	    &message_entryid.pb, &msgeid_size) == FAILURE
		|| NULL == pzresource || NULL == search_entryid.pb ||
		NULL == message_entryid.pb)
		pthrow(ecInvalidParam);
	search_entryid.cb = srcheid_size;
	message_entryid.cb = msgeid_size;
	ZEND_FETCH_RESOURCE(psession, MAPI_RESOURCE*,
		&pzresource, -1, name_mapi_session, le_mapi_session);
	if (psession->type != zs_objtype::session)
		pthrow(ecInvalidObject);
	auto result = zclient_linkmessage(psession->hsession,
						search_entryid, message_entryid);
	if (result != ecSuccess)
		pthrow(result);
	MAPI_G(hr) = ecSuccess;
}

/**
 * mapi_ianatz_to_struct(string $tz) : string|false|throw;
 *
 * @tz:		Timezone name within IANA tzdb
 *
 * Returns a TIMEZONEDEFINITION blob for the timezone. This can be put into
 * PidLidAppointmentTimeZoneDefinition{Start,End}Display.
 */
static ZEND_FUNCTION(mapi_ianatz_to_tzdef)
{
	char *izone = nullptr;
	size_t izone_len;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &izone,
	    &izone_len) == FAILURE || izone == nullptr)
		pthrow(ecInvalidParam);
	auto def = ianatz_to_tzdef(izone);
	if (def == nullptr)
		pthrow(ecNotFound);
	RETVAL_STRINGL(def->data(), def->size());
	MAPI_G(hr) = ecSuccess;
}

/**
 * mapi_strerror : string
 *
 * @code:	error code
 *
 * Returns a textual representation of the error code.
 */
static ZEND_FUNCTION(mapi_strerror)
{
	zend_long code = 0;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &code) == FAILURE) {
		RETVAL_FALSE;
		return;
	}
	auto s = mapi_strerror(code);
	if (s == nullptr)
		RETVAL_FALSE;
	else
		RETVAL_STRING(s);
}

static zend_function_entry mapi_functions[] = {
#if PHP_MAJOR_VERSION >= 8
#	define A(a, s) ZEND_FALIAS(a, s, arginfo_ ## s)
#	define F(s) ZEND_FE(s, arginfo_ ## s)
#	define F7(s, x) ZEND_FE(s, arginfo_ ## s)
#else
#	define A(a, s) ZEND_FALIAS(a, s, nullptr)
#	define F(s) ZEND_FE(s, nullptr)
#	define F7(s, x) ZEND_FE(s, x)
#endif
	F(mapi_load_mapidefs)
	F(mapi_last_hresult)
	F(mapi_prop_type)
	F(mapi_prop_id)
	F(mapi_is_error)
	F(mapi_make_scode)
	F(mapi_prop_tag)
	F(mapi_createoneoff)
	F(mapi_parseoneoff)
	F(mapi_logon_zarafa)
	F(mapi_logon_ex)
	F(mapi_getmsgstorestable)
	F(mapi_openmsgstore)
	F(mapi_openprofilesection)
	F(mapi_openaddressbook)
	F(mapi_openentry)
	F(mapi_ab_openentry)
	F(mapi_ab_resolvename)
	F(mapi_ab_getdefaultdir)
	F(mapi_msgstore_createentryid)
	F(mapi_msgstore_getarchiveentryid)
	F(mapi_msgstore_openentry)
	F(mapi_msgstore_getreceivefolder)
	F(mapi_msgstore_entryidfromsourcekey)
	F(mapi_msgstore_advise)
	F(mapi_msgstore_unadvise)
	F(mapi_msgstore_abortsubmit)
	F(mapi_sink_create)
	F(mapi_sink_timedwait)
	F(mapi_table_queryallrows)
	F(mapi_table_queryrows)
	F(mapi_table_getrowcount)
	F(mapi_table_setcolumns)
	F(mapi_table_seekrow)
	F(mapi_table_sort)
	F(mapi_table_restrict)
	F(mapi_table_findrow)
	F(mapi_table_createbookmark)
	F(mapi_table_freebookmark)
	F(mapi_folder_gethierarchytable)
	F(mapi_folder_getcontentstable)
	F(mapi_folder_getrulestable)
	F(mapi_folder_createmessage)
	F(mapi_folder_createfolder)
	F(mapi_folder_deletemessages)
	F(mapi_folder_copymessages)
	F(mapi_folder_emptyfolder)
	F(mapi_folder_copyfolder)
	F(mapi_folder_deletefolder)
	F(mapi_folder_setreadflags)
	F(mapi_folder_setsearchcriteria)
	F(mapi_folder_getsearchcriteria)
	F(mapi_folder_modifyrules)
	F(mapi_message_getattachmenttable)
	F(mapi_message_getrecipienttable)
	F(mapi_message_openattach)
	F(mapi_message_createattach)
	F(mapi_message_deleteattach)
	F(mapi_message_modifyrecipients)
	F(mapi_message_submitmessage)
	F(mapi_message_setreadflag)
	F(mapi_openpropertytostream)
	F(mapi_stream_write)
	F(mapi_stream_read)
	F(mapi_stream_stat)
	F(mapi_stream_seek)
	F(mapi_stream_commit)
	F(mapi_stream_setsize)
	F(mapi_stream_create)
	F(mapi_attach_openobj)
	F(mapi_savechanges)
	F(mapi_getprops)
	F(mapi_setprops)
	F(mapi_copyto)
	F(mapi_openproperty)
	F(mapi_deleteprops)
	F(mapi_getnamesfromids)
	F(mapi_getidsfromnames)
	F(mapi_decompressrtf)
	F(mapi_zarafa_getpermissionrules)
	F(mapi_zarafa_setpermissionrules)
	F(mapi_getuseravailability)
	F(mapi_exportchanges_config)
	F(mapi_exportchanges_synchronize)
	F(mapi_exportchanges_updatestate)
	F(mapi_exportchanges_getchangecount)
	F(mapi_importcontentschanges_config)
	F(mapi_importcontentschanges_updatestate)
	F7(mapi_importcontentschanges_importmessagechange, fourth_arg_force_ref)
	F(mapi_importcontentschanges_importmessagedeletion)
	F(mapi_importcontentschanges_importperuserreadstatechange)
	F(mapi_importcontentschanges_importmessagemove)
	F(mapi_importhierarchychanges_config)
	F(mapi_importhierarchychanges_updatestate)
	F(mapi_importhierarchychanges_importfolderchange)
	F(mapi_importhierarchychanges_importfolderdeletion)
	F7(mapi_wrap_importcontentschanges, first_arg_force_ref)
	F7(mapi_wrap_importhierarchychanges, first_arg_force_ref)
	F(mapi_inetmapi_imtoinet)
	F(mapi_inetmapi_imtomapi)
	F(mapi_icaltomapi)
	F(mapi_icaltomapi2)
	F(mapi_mapitoical)
	F(mapi_vcftomapi)
	F(mapi_vcftomapi2)
	F(mapi_mapitovcf)
	F(mapi_enable_exceptions)
	F(mapi_feature)
	A(mapi_attach_openbin, mapi_openproperty)
	A(mapi_msgstore_getprops, mapi_getprops)
	A(mapi_folder_getprops, mapi_getprops)
	A(mapi_message_getprops, mapi_getprops)
	A(mapi_message_setprops, mapi_setprops)
	A(mapi_message_openproperty, mapi_openproperty)
	A(mapi_attach_getprops, mapi_getprops)
	A(mapi_attach_openproperty, mapi_openproperty)
	A(mapi_message_savechanges, mapi_savechanges)
	F7(kc_session_save, second_arg_force_ref)
	F7(kc_session_restore, second_arg_force_ref)
	F(nsp_getuserinfo)
	F(nsp_setuserpasswd)
	F(nsp_essdn_to_username)
	F(mapi_linkmessage)
	F(mapi_ianatz_to_tzdef)
	F(mapi_strerror)
	{NULL, NULL, NULL}
#undef A
#undef F
#undef F7
};

static zend_module_entry mapi_module_entry = {
	STANDARD_MODULE_HEADER,
	PHP_MAPI_EXTNAME,
	mapi_functions,
	PHP_MINIT(mapi),
	PHP_MSHUTDOWN(mapi),
	PHP_RINIT(mapi),
	PHP_RSHUTDOWN(mapi),
	PHP_MINFO(mapi),
	PACKAGE_VERSION,
	STANDARD_MODULE_PROPERTIES,
};

BEGIN_EXTERN_C()
	ZEND_DLEXPORT zend_module_entry *get_module();
	ZEND_GET_MODULE(mapi)
END_EXTERN_C()
