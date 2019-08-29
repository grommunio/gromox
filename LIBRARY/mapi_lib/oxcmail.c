#include "dsn.h"
#include "rtf.h"
#include "html.h"
#include "guid.h"
#include "util.h"
#include "tnef.h"
#include "rtfcp.h"
#include "oxvcard.h"
#include "oxcical.h"
#include "oxcmail.h"
#include "rop_util.h"
#include "int_hash.h"
#include "mail_func.h"
#include "tarray_set.h"
#include "ext_buffer.h"
#include "apple_util.h"
#include "tpropval_array.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iconv.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>

/* uncomment below macro if you need system to verify X-MS-TNEF-Correlator */
/* #define VERIFY_TNEF_CORRELATOR */

#define MAXIMUM_SEARCHING_DEPTH					10

/*
	causion!!! if any errors in parsing any sub type, ignore this sub type.
	for example, if an error appears when parsing tnef attachment, treat
	this tnef sub type as normal attachment. there will be no error for
	parsing email object into message object!
*/

typedef struct _FIELD_ENUM_PARAM {
	EXT_BUFFER_ALLOC alloc;
	MESSAGE_CONTENT *pmsg;
	INT_HASH_TABLE *phash;
	uint16_t last_propid;
	const char *charset;
	BOOL b_classified;
	BOOL b_flag_del;
	MAIL *pmail;
} FIELD_ENUM_PARAM;

typedef struct _MIME_ENUM_PARAM {
	BOOL b_result;
	int attach_id;
	const char *charset;
	const char *str_zone;
	GET_PROPIDS get_propids;
	EXT_BUFFER_ALLOC alloc;
	MIME_POOL *pmime_pool;
	MESSAGE_CONTENT *pmsg;
	INT_HASH_TABLE *phash;
	uint16_t last_propid;
	uint64_t nttime_stamp;
	MIME *pplain;
	MIME *phtml;
	MIME *penriched;
	MIME *pcalendar;
	MIME *preport;
} MIME_ENUM_PARAM;

typedef struct _DSN_ENUM_INFO {
	int action_severity;
	TARRAY_SET *prcpts;
	uint64_t submit_time;
} DSN_ENUM_INFO;

typedef struct _DSN_FILEDS_INFO {
	char final_recipient[256];
	int action_severity;
	char remote_mta[128];
	const char *status;
	const char *diagnostic_code;
	const char *x_supplementary_info;
	const char *x_display_name;
} DSN_FILEDS_INFO;

enum {
	MAIL_TYPE_NORMAL,
	MAIL_TYPE_SIGNED,
	MAIL_TYPE_ENCRYPTED,
	MAIL_TYPE_DSN,
	MAIL_TYPE_MDN,
	MAIL_TYPE_CALENDAR,
	MAIL_TYPE_TNEF
};

typedef struct _MIME_SKELETON {
	int mail_type;
	int body_type;
	char *pplain;
	BINARY *phtml;
	BOOL b_inline;
	BINARY rtf_bin;
	BOOL b_attachment;
	const char *charset;
	const char *pmessage_class;
	ATTACHMENT_LIST *pattachments;
} MIME_SKELETON;

static uint8_t MACBINARY_ENCODING[] =
	{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0B, 0x01};
static char g_org_name[128];
static GET_USER_IDS oxcmail_get_user_ids;
static GET_USERNAME oxcmail_get_username;
static LTAG_TO_LCID oxcmail_ltag_to_lcid;
static LCID_TO_LTAG oxcmail_lcid_to_ltag;
static CHARSET_TO_CPID oxcmail_charset_to_cpid;
static CPID_TO_CHARSET oxcmail_cpid_to_charset;
static MIME_TO_EXTENSION oxcmail_mime_to_extension;
static EXTENSION_TO_MIME oxcmail_extension_to_mime;
	
BOOL oxcmail_init_library(const char *org_name,
	GET_USER_IDS get_user_ids, GET_USERNAME get_username,
	LTAG_TO_LCID ltag_to_lcid, LCID_TO_LTAG lcid_to_ltag,
	CHARSET_TO_CPID charset_to_cpid, CPID_TO_CHARSET
	cpid_to_charset, MIME_TO_EXTENSION mime_to_extension,
	EXTENSION_TO_MIME extension_to_mime)
{
	strncpy(g_org_name, org_name, 128);
	oxcmail_get_user_ids = get_user_ids;
	oxcmail_get_username = get_username;
	oxcmail_ltag_to_lcid = ltag_to_lcid;
	oxcmail_lcid_to_ltag = lcid_to_ltag;
	oxcmail_charset_to_cpid = charset_to_cpid;
	oxcmail_cpid_to_charset = cpid_to_charset;
	oxcmail_mime_to_extension = mime_to_extension;
	oxcmail_extension_to_mime = extension_to_mime;
	tnef_init_library(cpid_to_charset);
	if (FALSE == rtf_init_library(cpid_to_charset) ||
		FALSE == html_init_library(cpid_to_charset)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL oxcmail_username_to_essdn(const char *username,
	char *pessdn, int *paddress_type)
{
	int user_id;
	int domain_id;
	char *pdomain;
	int address_type;
	char tmp_name[256];
	char hex_string[16];
	char hex_string2[16];
	
	strncpy(tmp_name, username, 256);
	pdomain = strchr(tmp_name, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	*pdomain = '\0';
	pdomain ++;
	if (FALSE == oxcmail_get_user_ids(username,
		&user_id, &domain_id, &address_type)) {
		return FALSE;
	}
	encode_hex_int(user_id, hex_string);
	encode_hex_int(domain_id, hex_string2);
	snprintf(pessdn, 1024, "/o=%s/ou=Exchange Administrative Group "
			"(FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
			g_org_name, hex_string2, hex_string, tmp_name);
	upper_string(pessdn);
	if (NULL != paddress_type) {
		*paddress_type = address_type;
	}
	return TRUE;
}

static BOOL oxcmail_essdn_to_username(const char *pessdn, char *username)
{
	int tmp_len;
	int user_id;
	char tmp_buff[1024];
	
	tmp_len = sprintf(tmp_buff, "/o=%s/ou=Exchange Administrative"
		" Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=", g_org_name);
	if (0 != strncasecmp(pessdn, tmp_buff, tmp_len)) {
		return FALSE;
	}
	user_id = decode_hex_int(pessdn + tmp_len + 8);
	return oxcmail_get_username(user_id, username);
}

static BOOL oxcmail_entryid_to_username(const BINARY *pbin,
	EXT_BUFFER_ALLOC alloc, char *username)
{
	uint32_t flags;
	EXT_PULL ext_pull;
	uint8_t tmp_uid[16];
	uint8_t provider_uid[16];
	ONEOFF_ENTRYID oneoff_entry;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (pbin->cb < 20) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb, 20, alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		&ext_pull, &flags) || 0 != flags) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_bytes(
		&ext_pull, provider_uid, 16)) {
		return FALSE;
	}
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK, tmp_uid);
	if (0 == memcmp(tmp_uid, provider_uid, 16)) {
		ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
			&ext_pull, &ab_entryid)) {
			return FALSE;
		}
		if (ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER != ab_entryid.type) {
			return FALSE;
		}
		return oxcmail_essdn_to_username(ab_entryid.px500dn, username);
	}
	rop_util_get_provider_uid(PROVIDER_UID_ONE_OFF, tmp_uid);
	if (0 == memcmp(tmp_uid, provider_uid, 16)) {
		ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_oneoff_entryid(
			&ext_pull, &oneoff_entry)) {
			return FALSE;
		}
		if (0 != strcasecmp(oneoff_entry.paddress_type, "SMTP")) {
			return FALSE;
		}
		strncpy(username, oneoff_entry.pmail_address, 256);
		return TRUE;
	}
	return FALSE;
}

static BOOL oxcmail_username_to_oneoff(const char *username,
	const char *pdisplay_name, BINARY *pbin)
{
	int status;
	EXT_PUSH ext_push;
	ONEOFF_ENTRYID tmp_entry;
	
	tmp_entry.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ONE_OFF,
							tmp_entry.provider_uid);
	tmp_entry.version = 0;
	tmp_entry.ctrl_flags = CTRL_FLAG_NORICH | CTRL_FLAG_UNICODE;
	if (NULL != pdisplay_name && '\0' != pdisplay_name[0]) {
		tmp_entry.pdisplay_name = (char*)pdisplay_name;
	} else {
		tmp_entry.pdisplay_name = (char*)username;
	}
	tmp_entry.paddress_type = "SMTP";
	tmp_entry.pmail_address = (char*)username;
	ext_buffer_push_init(&ext_push, pbin->pb, 1280, EXT_FLAG_UTF16);
	status = ext_buffer_push_oneoff_entryid(&ext_push, &tmp_entry);
	if (EXT_ERR_CHARCNV == status) {
		tmp_entry.ctrl_flags = CTRL_FLAG_NORICH;
		status = ext_buffer_push_oneoff_entryid(&ext_push, &tmp_entry);
	}
	if (EXT_ERR_SUCCESS != status) {
		return FALSE;
	}
	pbin->cb = ext_push.offset;
	return TRUE;
}

static BOOL oxcmail_essdn_to_entryid(const char *pessdn, BINARY *pbin)
{
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID tmp_entryid;
	
	tmp_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
							tmp_entryid.provider_uid);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER;
	tmp_entryid.px500dn = (char*)pessdn;
	ext_buffer_push_init(&ext_push, pbin->pb, 1280, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
		&ext_push, &tmp_entryid)) {
		return FALSE;
	}
	pbin->cb = ext_push.offset;
	return TRUE;
}

static BOOL oxcmail_username_to_entryid(const char *username,
	const char *pdisplay_name, BINARY *pbin, int *paddress_type)
{
	char x500dn[1024];

	if (FALSE == oxcmail_username_to_essdn(
		username, x500dn, paddress_type)) {
		if (NULL != paddress_type) {
			*paddress_type = 0;
		}
		return oxcmail_username_to_oneoff(
			username, pdisplay_name, pbin);
	} else {
		return oxcmail_essdn_to_entryid(x500dn, pbin);
	}
}

static BOOL oxcmail_check_ascii(const char *pstring)
{
	int i, len;
	
	len = strlen(pstring);
	for (i=0; i<len; i++) {
		if (0 == isascii(pstring[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_check_crlf(const char *pstring)
{
	int i, len;
	
	len = strlen(pstring);
	for (i=0; i<len; i++) {
		if ('\r' == pstring[i] || '\n' == pstring[i]) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL oxcmail_get_content_param(MIME *pmime,
	const char *tag, char *value, int length)
{
	int tmp_len;
	
	if (FALSE == mime_get_content_param(
		pmime, tag, value, length)) {
		return FALSE;
	}
	tmp_len = strlen(value);
	if (('"' == value[0] && '"' == value[tmp_len - 1]) ||
		('\'' == value[0] && '\'' == value[tmp_len - 1])) {
		value[tmp_len - 1] = '\0';
		memmove(value, value + 1, tmp_len - 1);
	}
	if ('\0' == value[0]) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_get_field_param(char *field,
	const char *tag, char *value, int length)
{
	int i;
	char *pend;
	int tmp_len;
	char *pbegin;
	char *ptoken;
	
	ptoken = strchr(field, ';');
	if (NULL == ptoken) {
		return FALSE;
	}
	ptoken ++;
	pbegin = strcasestr(ptoken, tag);
	if (NULL == pbegin) {
		return FALSE;
	}
	pbegin += strlen(tag);
	if ('=' != *pbegin) {
		return FALSE;
	}
	pbegin ++;
	pend = strchr(pbegin, ';');
	if (NULL == pend) {
		tmp_len = strlen(pbegin);
	} else {
		tmp_len = pend - pbegin;
	}
	if (tmp_len >= length) {
		return FALSE;
	}
	memmove(value, pbegin, tmp_len);
	value[tmp_len] = '\0';
	ltrim_string(value);
	rtrim_string(value);
	tmp_len = strlen(value);
	if (('"' == value[0] && '"' == value[tmp_len - 1]) ||
		('\'' == value[0] && '\'' == value[tmp_len - 1])) {
		value[tmp_len - 1] = '\0';
		memmove(value, value + 1, tmp_len - 1);
	}
	if ('\0' == value[0]) {
		return FALSE;
	}
	return TRUE;
}

static void oxcmail_split_filename(char *file_name, char *extension)
{
	int i;
	int tmp_len;
	char *ptoken;
	
	tmp_len = strlen(file_name);
	for (i=0; i<tmp_len; i++) {
		if ('"' == file_name[i] || '/' == file_name[i] ||
			':' == file_name[i] || '<' == file_name[i] ||
			'>' == file_name[i] || '|' == file_name[i] ||
			'\\' == file_name[i] || (file_name[i] >= 0 &&
			file_name[i] <= 0x1F)) {
			file_name[i] = '_';
		}
	}
	for (i=0; i<tmp_len; i++) {
		if ('.' == file_name[i]) {
			file_name[i] = ' ';
			continue;
		}
		break;
	}
	ltrim_string(file_name);
	tmp_len = strlen(file_name);
	for (i=tmp_len-1; i>=0; i--) {
		if ('.' == file_name[i]) {
			file_name[i] = ' ';
			continue;
		}
		break;
	}
	rtrim_string(file_name);
	ptoken = strrchr(file_name, '.');
	if (NULL == ptoken || strlen(ptoken) >= 16) {
		extension[0] = '\0';
	} else {
		strcpy(extension, ptoken);
	}
}

static BOOL oxcmail_parse_recipient(const char *charset,
	EMAIL_ADDR *paddr, uint32_t rcpt_type, TARRAY_SET *pset)
{
	int tmp_len;
	BINARY tmp_bin;
	char essdn[1024];
	int address_type;
	uint8_t tmp_byte;
	uint32_t tmp_int32;
	char username[256];
	char tmp_buff[1280];
	char utf8_field[512];
	char display_name[256];
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY *pproplist;
	
	if ('\0' != paddr->display_name[0] ||
		('\0' != paddr->local_part[0] &&
		'\0' != paddr->domain[0])) {
		pproplist = tpropval_array_init();
		if (NULL == pproplist) {
			return FALSE;
		}
	} else {
		return TRUE;
	}
	if (FALSE == tarray_set_append_internal(pset, pproplist)) {
		tpropval_array_free(pproplist);
		return FALSE;
	}
	utf8_field[0] = '\0';
	if ('\0' != paddr->display_name[0]) {
		strncpy(display_name, paddr->display_name, 256);
	} else {
		snprintf(display_name, 256, "%s@%s",
			paddr->local_part, paddr->domain);
	}
	if (TRUE == mime_string_to_utf8(charset, display_name, utf8_field)) {
		tmp_len = strlen(utf8_field);
		if (tmp_len > 1 && '"' == utf8_field[0]
			&& '"' == utf8_field[tmp_len - 1]) {
			tmp_len --;
			utf8_field[tmp_len] = '\0';
			memmove(utf8_field, utf8_field + 1, tmp_len);
			tmp_len --;
		}
		if (tmp_len > 1 && '\'' == utf8_field[0]
			&& '\'' == utf8_field[tmp_len - 1]) {
			tmp_len --;
			utf8_field[tmp_len] = '\0';
			memmove(utf8_field, utf8_field + 1, tmp_len);
			tmp_len --;
		}
		propval.proptag = PROP_TAG_DISPLAYNAME;
		if (0 == tmp_len) {
			snprintf(display_name, 256, "%s@%s",
				paddr->local_part, paddr->domain);
			propval.pvalue = display_name;
		} else {
			propval.pvalue = utf8_field;
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
		propval.pvalue = utf8_field;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	} else {
		propval.proptag = PROP_TAG_DISPLAYNAME_STRING8;
		propval.pvalue = display_name;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_TRANSMITTABLEDISPLAYNAME_STRING8;
		propval.pvalue = display_name;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	if ('\0' != paddr->local_part[0] && '\0' != paddr->domain[0]
		&& TRUE == oxcmail_check_ascii(paddr->local_part) &&
		TRUE == oxcmail_check_ascii(paddr->domain)) {
		snprintf(username, 256, "%s@%s", paddr->local_part, paddr->domain);
		if (FALSE == oxcmail_username_to_essdn(
			username, essdn, &address_type)) {
			essdn[0] = '\0';
			address_type = ADDRESS_TYPE_NORMAL;
			tmp_bin.cb = sprintf(tmp_buff, "SMTP:%s", username) + 1;
			upper_string(tmp_buff);
			propval.proptag = PROP_TAG_ADDRESSTYPE;
			propval.pvalue = "SMTP";
			if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_EMAILADDRESS;
			propval.pvalue = username;
			if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
				return FALSE;
			}
		} else {
			tmp_bin.cb = sprintf(tmp_buff, "EX:%s", essdn) + 1;
			propval.proptag = PROP_TAG_ADDRESSTYPE;
			propval.pvalue = "EX";
			if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_EMAILADDRESS;
			propval.pvalue = essdn;
			if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
				return FALSE;
			}
		}
		propval.proptag = PROP_TAG_SMTPADDRESS;
		propval.pvalue = username;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		tmp_bin.pb = tmp_buff;
		propval.proptag = PROP_TAG_SEARCHKEY;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_ENTRYID;
		tmp_bin.cb = 0;
		tmp_bin.pb = tmp_buff;
		propval.pvalue = &tmp_bin;
		if ('\0' == essdn[0]) {
			if (FALSE == oxcmail_username_to_oneoff(
				username, utf8_field, &tmp_bin)) {
				return FALSE;
			}
		} else {
			if (FALSE == oxcmail_essdn_to_entryid(essdn, &tmp_bin)) {
				return FALSE;
			}
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_RECIPIENTENTRYID;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_RECORDKEY;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_OBJECTTYPE;
		propval.pvalue = &tmp_int32;
		if (ADDRESS_TYPE_MLIST == address_type) {
			tmp_int32 = OBJECT_DLIST;
		} else {
			tmp_int32 = OBJECT_USER;
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_DISPLAYTYPE;
		propval.pvalue = &tmp_int32;
		switch (address_type) {
		case ADDRESS_TYPE_MLIST:
			tmp_int32 = DISPLAY_TYPE_DISTLIST;
			break;
		case ADDRESS_TYPE_ROOM:
			tmp_int32 = DISPLAY_TYPE_ROOM;
			break;
		case ADDRESS_TYPE_EQUIPMENT:
			tmp_int32 = DISPLAY_TYPE_EQUIPMENT;
			break;
		default:
			tmp_int32 = DISPLAY_TYPE_MAILUSER;
			break;
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_RECIPIENTFLAGS;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 1;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	tmp_byte = 1;
	propval.proptag = PROP_TAG_RESPONSIBILITY;
	propval.pvalue = &tmp_byte;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	tmp_int32 = 1;
	propval.proptag = PROP_TAG_RECIPIENTFLAGS;
	propval.pvalue = &tmp_int32;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_RECIPIENTTYPE;
	propval.pvalue = &rcpt_type;
	return tpropval_array_set_propval(pproplist, &propval);
}

static BOOL oxcmail_parse_addresses(const char *charset,
	char *field, uint32_t rcpt_type, TARRAY_SET *pset)
{
	int i, len;
	char *ptoken;
	BOOL b_quote;
	char *ptoken_prev;
	EMAIL_ADDR email_addr;
	char temp_address[1024];
	
	len = strlen(field);
	field[len] = ';';
	len ++;
	ptoken_prev = field;
	b_quote = FALSE;
	for (i=0; i<len; i++) {
		if ('"' == field[i]) {
			if (FALSE == b_quote) {
				b_quote = TRUE;
			} else {
				b_quote = FALSE;
			}
		}
		if (',' == field[i] || ';' == field[i]) {
			ptoken = field + i;
			if (ptoken - ptoken_prev >= 1024) {
				ptoken_prev = ptoken + 1;
				continue;
			}
			memcpy(temp_address, ptoken_prev, ptoken - ptoken_prev);
			temp_address[ptoken - ptoken_prev] = '\0';
			parse_mime_addr(&email_addr, temp_address);
			if ('\0' == email_addr.local_part[0] && TRUE == b_quote) {
				continue;
			}
			if (FALSE == oxcmail_parse_recipient(charset,
				&email_addr, rcpt_type, pset)) {
				return FALSE;
			}
			ptoken_prev = ptoken + 1;
			b_quote = FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_parse_address(const char *charset,
	EMAIL_ADDR *paddr, uint32_t proptag1, uint32_t proptag2,
	uint32_t proptag3, uint32_t proptag4, uint32_t proptag5,
	 uint32_t proptag6, TPROPVAL_ARRAY *pproplist)
{
	BINARY tmp_bin;
	char essdn[1024];
	char username[256];
	char tmp_buff[1280];
	char utf8_field[512];
	TAGGED_PROPVAL propval;
	
	if ('\0' != paddr->display_name[0]) {
		if (TRUE == mime_string_to_utf8(charset,
			paddr->display_name, utf8_field)) {
			propval.proptag = proptag1;
			propval.pvalue = utf8_field;
		} else {
			propval.proptag = proptag1&0xFFFF0000|PROPVAL_TYPE_STRING;
			propval.pvalue = paddr->display_name;
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	} else if ('\0' != paddr->local_part[0] && '\0' != paddr->domain[0]) {
		sprintf(username, "%s@%s", paddr->local_part, paddr->domain);
		if (TRUE == oxcmail_check_ascii(username)) {
			propval.proptag = proptag1;
		} else {
			propval.proptag = proptag1&0xFFFF0000|PROPVAL_TYPE_STRING;
		}
		propval.pvalue = username;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	if ('\0' != paddr->local_part[0] && '\0' != paddr->domain[0]
		&& TRUE == oxcmail_check_ascii(paddr->local_part) &&
		TRUE == oxcmail_check_ascii(paddr->domain)) {
		sprintf(username, "%s@%s", paddr->local_part, paddr->domain);
		propval.proptag = proptag2;
		propval.pvalue = "SMTP";
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = proptag3;
		propval.pvalue = username;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = proptag4;
		propval.pvalue = username;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		if (FALSE == oxcmail_username_to_essdn(username, essdn, NULL)) {
			essdn[0] = '\0';
			tmp_bin.cb = sprintf(tmp_buff, "SMTP:%s", username) + 1;
			upper_string(tmp_buff);
		} else {
			tmp_bin.cb = sprintf(tmp_buff, "EX:%s", essdn) + 1;
		}
		tmp_bin.pb = tmp_buff;
		propval.proptag = proptag5;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = proptag6;
		tmp_bin.cb = 0;
		tmp_bin.pb = tmp_buff;
		propval.pvalue = &tmp_bin;
		if ('\0' == essdn[0]) {
			if (FALSE == oxcmail_username_to_oneoff(
				username, utf8_field, &tmp_bin)) {
				return FALSE;
			}
		} else {
			if (FALSE == oxcmail_essdn_to_entryid(essdn, &tmp_bin)) {
				return FALSE;
			}
		}
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_parse_reply_to(const char *charset,
	char *field, TPROPVAL_ARRAY *pproplist)
{
	int i, len;
	int status;
	char *ptoken;
	BOOL b_quote;
	uint32_t count;
	BINARY tmp_bin;
	int str_offset;
	uint32_t bytes;
	uint8_t pad_len;
	uint32_t offset;
	uint32_t offset1;
	uint32_t offset2;
	EXT_PUSH ext_push;
	char *ptoken_prev;
	char tmp_buff[256];
	char utf8_field[512];
	EMAIL_ADDR email_addr;
	TAGGED_PROPVAL propval;
	char temp_address[1024];
	ONEOFF_ENTRYID tmp_entry;
	uint8_t bin_buff[256*1024];
	char str_buff[MIME_FIELD_LEN];
	static uint8_t pad_bytes[3] = {0, 0, 0};
	
	len = strlen(field);
	field[len] = ';';
	len ++;
	ptoken_prev = field;
	count = 0;
	ext_buffer_push_init(&ext_push, bin_buff,
		sizeof(bin_buff), EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
		&ext_push, sizeof(uint32_t))) {
		return FALSE;
	}
	offset = ext_push.offset;
	if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
		&ext_push, sizeof(uint32_t))) {
		return FALSE;
	}
	str_offset = 0;
	tmp_entry.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ONE_OFF,
							tmp_entry.provider_uid);
	tmp_entry.version = 0;
	tmp_entry.pdisplay_name = utf8_field;
	tmp_entry.paddress_type = "SMTP";
	tmp_entry.pmail_address = tmp_buff;
	b_quote = FALSE;
	for (i=0; i<len; i++) {
		if ('"' == field[i]) {
			if (FALSE == b_quote) {
				b_quote = TRUE;
			} else {
				b_quote = FALSE;
			}
		}
		if (',' == field[i] || ';' == field[i]) {
			ptoken = field + i;
			if (ptoken - ptoken_prev >= 1024) {
				ptoken_prev = ptoken + 1;
				continue;
			}
			memcpy(temp_address, ptoken_prev, ptoken - ptoken_prev);
			temp_address[ptoken - ptoken_prev] = '\0';
			parse_mime_addr(&email_addr, temp_address);
			if ('\0' == email_addr.local_part[0] && TRUE == b_quote) {
				continue;
			}
			if ('\0' == email_addr.display_name[0] ||
				FALSE == mime_string_to_utf8(charset,
				email_addr.display_name, utf8_field)) {
				sprintf(utf8_field, "%s@%s",
					email_addr.local_part, email_addr.domain);
			}
			if (0 == str_offset) {
				str_offset = sprintf(str_buff, "%s", utf8_field);
			} else {
				str_offset += snprintf(str_buff + str_offset,
					sizeof(str_buff) - str_offset, ";%s", utf8_field);
			}
			if ('\0' != email_addr.local_part[0] && '\0' != email_addr.domain[0]
				&& TRUE == oxcmail_check_ascii(email_addr.local_part) &&
				TRUE == oxcmail_check_ascii(email_addr.domain)) {
				offset1 = ext_push.offset;
				if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
					&ext_push, sizeof(uint32_t))) {
					return FALSE;
				}
				sprintf(tmp_buff, "%s@%s",
					email_addr.local_part, email_addr.domain);
				tmp_entry.ctrl_flags = CTRL_FLAG_NORICH | CTRL_FLAG_UNICODE;
				status = ext_buffer_push_oneoff_entryid(
								&ext_push, &tmp_entry);
				if (EXT_ERR_CHARCNV == status) {
					ext_push.offset = offset1 + sizeof(uint32_t);
					tmp_entry.ctrl_flags = CTRL_FLAG_NORICH;
					status = ext_buffer_push_oneoff_entryid(
									&ext_push, &tmp_entry);
				}
				if (EXT_ERR_SUCCESS != status) {
					return FALSE;
				}
				offset2 = ext_push.offset;
				bytes = offset2 - (offset1 + sizeof(uint32_t));
				ext_push.offset = offset1;
				if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
					&ext_push, bytes)) {
					return FALSE;
				}
				ext_push.offset = offset2;
				pad_len = ((bytes + 3) & ~3) - bytes;
				if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
					&ext_push, pad_bytes, pad_len)) {
					return FALSE;
				}
				count ++;
			}
			ptoken_prev = ptoken + 1;
			b_quote = FALSE;
		}
	}
	if (0 != count) {
		tmp_bin.cb = ext_push.offset;
		tmp_bin.pb = bin_buff;
		bytes = ext_push.offset - (offset + sizeof(uint32_t));
		ext_push.offset = 0;
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(&ext_push, count)) {
			return FALSE;
		}
		ext_push.offset = offset;
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(&ext_push, bytes)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_REPLYRECIPIENTENTRIES;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	if (str_offset > 0) {
		propval.proptag = PROP_TAG_REPLYRECIPIENTNAMES;
		propval.pvalue = str_buff;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_parse_subject(const char *charset,
	char *field, TPROPVAL_ARRAY *pproplist)
{
	int i;
	int tmp_len;
	char *ptoken;
	int subject_len;
	char tmp_buff1[4096];
	char prefix_buff[32];
	TAGGED_PROPVAL propval;
	char tmp_buff[MIME_FIELD_LEN];
	char utf8_field[MIME_FIELD_LEN];
	static uint8_t seperator[] = {':', 0x00, ' ', 0x00};
	
	if (TRUE == mime_string_to_utf8(
		charset, field, utf8_field)) {
		subject_len = utf8_to_utf16le(utf8_field,
					tmp_buff, sizeof(tmp_buff));
		if (subject_len < 0) {
			utf8_truncate(utf8_field, 255);
			subject_len = utf8_to_utf16le(utf8_field,
					tmp_buff, sizeof(tmp_buff));
			if (subject_len < 0) {
				subject_len = 0;
			}
		}
		if (subject_len > 512) {
			subject_len = 512;
			tmp_buff[510] = '\0';
			tmp_buff[511] = '\0';
		}
		utf16le_to_utf8(tmp_buff, subject_len, tmp_buff1, sizeof(tmp_buff1));
		propval.proptag = PROP_TAG_SUBJECT;
		propval.pvalue = tmp_buff1;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		ptoken = memmem(tmp_buff, subject_len, seperator, 4);
		if (NULL == ptoken) {
			return TRUE;
		}
		tmp_len = ptoken - tmp_buff;
		if (tmp_len < 2 || tmp_len > 6) {
			return TRUE;
		}
		for (i=0; i<tmp_len; i+=2) {
			if ((':' == tmp_buff[i] ||
				' ' == tmp_buff[i] ||
				isdigit(tmp_buff[0])) &&
				'\0' == tmp_buff[i + 1]) {
				return TRUE;
			}
		}
		tmp_len += sizeof(seperator);
		memcpy(tmp_buff1, tmp_buff, tmp_len);
		tmp_buff1[tmp_len] = '\0';
		tmp_buff1[tmp_len + 1] = '\0';
		utf16le_to_utf8(tmp_buff1, tmp_len + 2,
			prefix_buff, sizeof(prefix_buff));
		propval.proptag = PROP_TAG_SUBJECTPREFIX;
		propval.pvalue = prefix_buff;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		utf16le_to_utf8(tmp_buff + tmp_len,
			subject_len - tmp_len, tmp_buff1,
			sizeof(tmp_buff1));
		propval.proptag = PROP_TAG_NORMALIZEDSUBJECT;
		propval.pvalue = tmp_buff1;
		return tpropval_array_set_propval(pproplist, &propval);
	} else {
		propval.proptag = PROP_TAG_SUBJECT_STRING8;
		propval.pvalue = field;
		return tpropval_array_set_propval(pproplist, &propval);
	}
}

static BOOL oxcmail_parse_thread_topic(const char *charset,
	char *field, TPROPVAL_ARRAY *pproplist)
{
	TAGGED_PROPVAL propval;
	char utf8_field[MIME_FIELD_LEN];
	
	if (TRUE == mime_string_to_utf8(
		charset, field, utf8_field)) {
		propval.proptag = PROP_TAG_CONVERSATIONTOPIC;
		propval.pvalue = utf8_field;
		return tpropval_array_set_propval(pproplist, &propval);
	} else {
		propval.proptag = PROP_TAG_CONVERSATIONTOPIC_STRING8;
		propval.pvalue = field;
		return tpropval_array_set_propval(pproplist, &propval);
	}
}

static BOOL oxcmail_parse_thread_index(
	char *field,  TPROPVAL_ARRAY *pproplist)
{
	int i;
	size_t len;
	BINARY tmp_bin;
	TAGGED_PROPVAL propval;
	char tmp_buff[MIME_FIELD_LEN];
	
	/* remove space(s) produced by mime lib */
	len = strlen(field);
	for (i=0; i<len; i++) {
		if (' ' == field[i]) {
			memmove(field + i, field + i + 1, len - i);
			len --;
			i --;
		}
	}
	len = sizeof(tmp_buff);
	if (0 != decode64(field, strlen(field), tmp_buff, &len)) {
		return TRUE;
	}
	tmp_bin.pb = tmp_buff;
	tmp_bin.cb = len;
	propval.proptag = PROP_TAG_CONVERSATIONINDEX;
	propval.pvalue = &tmp_bin;
	return tpropval_array_set_propval(pproplist, &propval);
}

static BOOL oxcmail_parse_keywords(const char *charset,
	char *field, uint16_t propid, TPROPVAL_ARRAY *pproplist)
{
	int i, len;
	BOOL b_start;
	char *ptoken_prev;
	STRING_ARRAY strings;
	TAGGED_PROPVAL propval;
	char* string_buff[1024];
	char tmp_buff[MIME_FIELD_LEN];
	
	propval.proptag = ((uint32_t)propid) << 16;
	if (FALSE == mime_string_to_utf8(
		charset, field, tmp_buff)) {
		propval.proptag |= PROPVAL_TYPE_STRING_ARRAY;
		strcpy(tmp_buff, field);
	} else {
		propval.proptag |= PROPVAL_TYPE_WSTRING_ARRAY;
	}
	strings.count = 0;
	strings.ppstr = string_buff;
	len = strlen(tmp_buff);
	tmp_buff[len] = ';';
	len ++;
	ptoken_prev = tmp_buff;
	b_start = FALSE;
	for (i=0; i<len&&strings.count<1024; i++) {
		if (FALSE == b_start && (' ' == tmp_buff[i]
			|| '\t' == tmp_buff[i])) {
			ptoken_prev = tmp_buff + i + 1;
			continue;
		}
		b_start = TRUE;
		if (',' == tmp_buff[i] || ';' == tmp_buff[i]) {
			tmp_buff[i] = '\0';
			strings.ppstr[strings.count] = ptoken_prev;
			strings.count ++;
			b_start = FALSE;
			ptoken_prev = tmp_buff + i + 1;
		}
	}
	if (0 == strings.count) {
		return TRUE;
	}
	propval.pvalue = &strings;
	return tpropval_array_set_propval(pproplist, &propval);
}

static BOOL oxcmail_parse_response_suppress(
	char *field, TPROPVAL_ARRAY *pproplist)
{
	int i, len;
	BOOL b_start;
	char *ptoken_prev;
	uint32_t tmp_int32;
	TAGGED_PROPVAL propval;
	
	if (0 == strcasecmp(field, "NONE")) {
		return TRUE;
	} else if (0 == strcasecmp(field, "ALL")) {
		tmp_int32 = 0xFFFFFFFF;
		propval.proptag = PROP_TAG_AUTORESPONSESUPPRESS;
		propval.pvalue = &tmp_int32;
		return tpropval_array_set_propval(pproplist, &propval);
	}
	len = strlen(field);
	field[len] = ';';
	len ++;
	ptoken_prev = field;
	b_start = FALSE;
	tmp_int32 = 0;
	for (i=0; i<len; i++) {
		if (FALSE == b_start && (' ' == field[i] || '\t' == field[i])) {
			ptoken_prev = field + i + 1;
			continue;
		}
		b_start = TRUE;
		if (',' == field[i] || ';' == field[i]) {
			field[i] = '\0';
			if (0 == strcasecmp("DR", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_DR;
			} else if (0 == strcasecmp("NDR", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_NDR;
			} else if (0 == strcasecmp("RN", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_RN;
			} else if (0 == strcasecmp("NRN", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_NRN;
			} else if (0 == strcasecmp("OOF", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_OOF;
			} else if (0 == strcasecmp("AutoReply", ptoken_prev)) {
				tmp_int32 |= AUTO_RESPONSE_SUPPRESS_AUTOREPLY;
			}
			b_start = FALSE;
			ptoken_prev = field + i + 1;
		}
	}
	if (0 == tmp_int32) {
		return TRUE;
	}
	propval.proptag = PROP_TAG_AUTORESPONSESUPPRESS;
	propval.pvalue = &tmp_int32;
	return tpropval_array_set_propval(pproplist, &propval);
}

static BOOL oxcmail_parse_content_class(
	char *field, MAIL *pmail, uint16_t *plast_propid,
	INT_HASH_TABLE *phash, TPROPVAL_ARRAY *pproplist)
{
	MIME *pmime;
	char *ptoken;
	GUID tmp_guid;
	char tmp_class[1024];
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	TAGGED_PROPVAL propval1;
	static uint32_t lid_infopathfromname = 0x000085B1;
	
	propval.proptag = PROP_TAG_MESSAGECLASS;
	if (0 == strcasecmp(field, "fax")) {
		pmime = mail_get_head(pmail);
		if (0 != strcasecmp("multipart/mixed",
			mime_get_content_type(pmime))) {
			return TRUE;
		}
		pmime = mime_get_child(pmime);
		if (NULL == pmime) {
			return TRUE;
		}
		if (0 != strcasecmp("text/html",
			mime_get_content_type(pmime))) {
			return TRUE;
		}
		pmime = mime_get_slibling(pmime);
		if (NULL == pmime) {
			return TRUE;
		}
		if (0 != strcasecmp("image/tiff",
			mime_get_content_type(pmime))) {
			return TRUE;
		}
		propval.pvalue = "IPM.Note.Microsoft.Fax";
	} else if (0 == strcasecmp(field, "fax-ca")) {
		propval.pvalue = "IPM.Note.Microsoft.Fax.CA";
	} else if (0 == strcasecmp(field, "missedcall")) {
		pmime = mail_get_head(pmail);
		if (0 != strcasecmp("audio/gsm", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/mp3", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wav", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wma", mime_get_content_type(pmime))) {
			return TRUE;
		}
		propval.pvalue = "IPM.Note.Microsoft.Missed.Voice";
	} else if (0 == strcasecmp(field, "voice-uc")) {
		pmime = mail_get_head(pmail);
		if (0 != strcasecmp("audio/gsm", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/mp3", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wav", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wma", mime_get_content_type(pmime))) {
			return TRUE;
		}
		propval.pvalue = "IPM.Note.Microsoft.Conversation.Voice";
	} else if (0 == strcasecmp(field, "voice-ca")) {
		pmime = mail_get_head(pmail);
		if (0 != strcasecmp("audio/gsm", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/mp3", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wav", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wma", mime_get_content_type(pmime))) {
			return TRUE;
		}
		propval.pvalue = "IPM.Note.Microsoft.Voicemail.UM.CA";
	} else if (0 == strcasecmp(field, "voice")) {
		pmime = mail_get_head(pmail);
		if (0 != strcasecmp("audio/gsm", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/mp3", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wav", mime_get_content_type(pmime)) &&
			0 != strcasecmp("audio/wma", mime_get_content_type(pmime))) {
			return TRUE;
		}
		propval.pvalue = "IPM.Note.Microsoft.Voicemail.UM";
	} if (0 == strncasecmp(field, "urn:content-class:custom.", 25)) {
		sprintf(tmp_class, "IPM.Note.Custom.%s", field + 25);
		propval.pvalue = tmp_class;
	} else if (0 == strncasecmp(field, "InfoPathForm.", 13)) {
		ptoken = strchr(field + 13, '.');
		if (NULL != ptoken) {
			*ptoken = '\0';
			ptoken ++;
			if (TRUE == guid_from_string(&tmp_guid, field + 13)) {
				/* PidLidInfoPathFromName */
				propname.kind = KIND_LID;
				rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
				propname.plid = &lid_infopathfromname;
				if (1 != int_hash_add(phash, *plast_propid, &propname)) {
					return FALSE;
				}
				propval1.proptag = ((uint32_t)(*plast_propid)) << 16;
				if (TRUE == oxcmail_check_ascii(ptoken)) {
					propval1.proptag |= PROPVAL_TYPE_WSTRING;
				} else {
					propval1.proptag |= PROPVAL_TYPE_STRING;
				}
				propval1.pvalue = ptoken;
				if (FALSE == tpropval_array_set_propval(
					pproplist, &propval1)) {
					return FALSE;
				}
				(*plast_propid) ++;
			}
		}
		sprintf(tmp_class, "IPM.InfoPathForm.%s", field + 13);
		propval.pvalue = tmp_class;
	} else {
		/* PidNameContentClass */
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_INTERNET_HEADERS, &propname.guid);
		propname.pname = "Content-Class";
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16;
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag |= PROPVAL_TYPE_WSTRING;
		} else {
			propval1.proptag |= PROPVAL_TYPE_STRING;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			pproplist, &propval)) {
			return FALSE;
		}
		(*plast_propid) ++;
		return TRUE;
	}
	return tpropval_array_set_propval(pproplist, &propval);
}

static BOOL oxcmail_parse_message_flag(
	char *field, uint16_t *plast_propid,
	INT_HASH_TABLE *phash, TPROPVAL_ARRAY *pproplist)
{
	void *pvalue;
	BOOL b_unicode;
	uint8_t tmp_byte;
	double tmp_double;
	uint32_t tmp_int32;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	static uint32_t lid_todo_title = 0x000085A4;
	static uint32_t lid_task_status = 0x00008101;
	static uint32_t lid_flag_request = 0x00008530;
	static uint32_t lid_task_complete = 0x0000811C;
	static uint32_t lid_percent_complete = 0x00008102;
	
	
	/* PidLidFlagRequest */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid_flag_request;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	if (TRUE == oxcmail_check_ascii(field)) {
		propval.proptag |= PROPVAL_TYPE_WSTRING;
	} else {
		propval.proptag |= PROPVAL_TYPE_STRING;
	}
	propval.pvalue = field;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	
	propval.proptag = PROP_TAG_FLAGSTATUS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = FLAG_STATUS_FOLLOWUPFLAGGED;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	
	/* PidLidToDoTitle */
	pvalue = tpropval_array_get_propval(pproplist, PROP_TAG_SUBJECT);
	if (NULL != pvalue) {
		b_unicode = TRUE;
	} else {
		b_unicode = FALSE;
		pvalue = tpropval_array_get_propval(
			pproplist, PROP_TAG_SUBJECT_STRING8);
	}
	if (NULL != pvalue) {
		propname.kind = KIND_LID;
		rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
		propname.plid = &lid_todo_title;
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16;
		if (TRUE == b_unicode) {
			propval.proptag |= PROPVAL_TYPE_WSTRING;
		} else {
			propval.proptag |= PROPVAL_TYPE_STRING;
		}
		propval.pvalue = pvalue;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		(*plast_propid) ++;
	}
	
	/* PidLidTaskStatus */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_TASK, &propname.guid);
	propname.plid = &lid_task_status;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 | PROPVAL_TYPE_LONG;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 0;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	
	/* PidLidTaskComplete */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_TASK, &propname.guid);
	propname.plid = &lid_task_complete;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 | PROPVAL_TYPE_BYTE;
	propval.pvalue = &tmp_byte;
	tmp_byte = 0;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	
	/* PidLidPercentComplete */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_TASK, &propname.guid);
	propname.plid = &lid_percent_complete;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 | PROPVAL_TYPE_DOUBLE;
	propval.pvalue = &tmp_double;
	tmp_double = 0.0;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	
	propval.proptag = PROP_TAG_TODOITEMFLAGS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = TODO_ITEM_RECIPIENTFLAGGED;
	return tpropval_array_set_propval(pproplist, &propval);
}

static BOOL oxcmail_parse_classified(char *field,
	uint16_t *plast_propid, INT_HASH_TABLE *phash,
	TPROPVAL_ARRAY *pproplist)
{
	uint8_t tmp_byte;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	static uint32_t lid_classified = 0x000085B5;
	
	/* PidLidClassified */
	if (0 == strcasecmp(field, "true")) {
		propname.kind = KIND_LID;
		rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
		propname.plid = &lid_classified;
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16 |
											PROPVAL_TYPE_BYTE;
		propval.pvalue = &tmp_byte;
		tmp_byte = 1;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcmail_parse_classkeep(char *field,
	uint16_t *plast_propid, INT_HASH_TABLE *phash,
	TPROPVAL_ARRAY *pproplist)
{
	uint8_t tmp_byte;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	static uint32_t lid_classification_keep = 0x000085BA;
	
	/* PidLidClassificationKeep */
	if (0 == strcasecmp(field, "true") || 0 == strcasecmp(field, "false")) {
		propname.kind = KIND_LID;
		rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
		propname.plid = &lid_classification_keep;
		if (1 != int_hash_add(phash, *plast_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)(*plast_propid)) << 16 |
											PROPVAL_TYPE_BYTE;
		if (0 == strcasecmp(field, "true")) {
			tmp_byte = 1;
		} else if (0 == strcasecmp(field, "false")) {
			tmp_byte = 0;
		}
		propval.pvalue = &tmp_byte;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		(*plast_propid) ++;
	}
	return TRUE;
}

static BOOL oxcmail_parse_classification(char *field,
	uint16_t *plast_propid, INT_HASH_TABLE *phash,
	TPROPVAL_ARRAY *pproplist)
{
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	static uint32_t lid_classification = 0x000085B6;
	
	/* PidLidClassification */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid_classification;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	if (TRUE == oxcmail_check_ascii(field)) {
		propval.proptag |= PROPVAL_TYPE_WSTRING;
	} else {
		propval.proptag |= PROPVAL_TYPE_STRING;
	}
	propval.pvalue = field;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_classdesc(char *field,
	uint16_t *plast_propid, INT_HASH_TABLE *phash,
	TPROPVAL_ARRAY *pproplist)
{
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	static uint32_t lid_classification_description = 0x000085B7;
	
	/* PidLidClassificationDescription */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid_classification_description;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	if (TRUE == oxcmail_check_ascii(field)) {
		propval.proptag |= PROPVAL_TYPE_WSTRING;
	} else {
		propval.proptag |= PROPVAL_TYPE_STRING;
	}
	propval.pvalue = field;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_classid(char *field,
	uint16_t *plast_propid, INT_HASH_TABLE *phash,
	TPROPVAL_ARRAY *pproplist)
{
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	static uint32_t lid_classification_guid = 0x000085B8;
	
	/* PidLidClassificationGuid */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid_classification_guid;
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16;
	if (TRUE == oxcmail_check_ascii(field)) {
		propval.proptag |= PROPVAL_TYPE_WSTRING;
	} else {
		propval.proptag |= PROPVAL_TYPE_STRING;
	}
	propval.pvalue = field;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_enum_mail_head(
	const char *tag, char *field, void *pparam)
{
	void *pvalue;
	time_t tmp_time;
	uint8_t tmp_byte;
	uint64_t tmp_int32;
	uint64_t tmp_int64;
	EMAIL_ADDR email_addr;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	FIELD_ENUM_PARAM *penum_param;
	
	penum_param = (FIELD_ENUM_PARAM*)pparam;
	if (0 == strcasecmp(tag, "From")) {
		parse_mime_addr(&email_addr, field);
		if (FALSE == oxcmail_parse_address(penum_param->charset,
			&email_addr, PROP_TAG_SENTREPRESENTINGNAME,
			PROP_TAG_SENTREPRESENTINGADDRESSTYPE,
			PROP_TAG_SENTREPRESENTINGEMAILADDRESS,
			PROP_TAG_SENTREPRESENTINGSMTPADDRESS,
			PROP_TAG_SENTREPRESENTINGSEARCHKEY,
			PROP_TAG_SENTREPRESENTINGENTRYID,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Sender")) {
		parse_mime_addr(&email_addr, field);
		if (FALSE == oxcmail_parse_address(
			penum_param->charset,
			&email_addr, PROP_TAG_SENDERNAME,
			PROP_TAG_SENDERADDRESSTYPE,
			PROP_TAG_SENDEREMAILADDRESS,
			PROP_TAG_SENDERSMTPADDRESS,
			PROP_TAG_SENDERSEARCHKEY,
			PROP_TAG_SENDERENTRYID,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Reply-To")) {
		if (FALSE == oxcmail_parse_reply_to(
			penum_param->charset, field,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "To")) {
		if (FALSE == oxcmail_parse_addresses(
			penum_param->charset,
			field, RECIPIENT_TYPE_TO,
			penum_param->pmsg->children.prcpts)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Cc")) {
		if (FALSE == oxcmail_parse_addresses(
			penum_param->charset,
			field, RECIPIENT_TYPE_CC,
			penum_param->pmsg->children.prcpts)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Bcc")) {
		if (FALSE == oxcmail_parse_addresses(
			penum_param->charset,
			field, RECIPIENT_TYPE_BCC,
			penum_param->pmsg->children.prcpts)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Return-Receipt-To")) {
		propval.proptag = PROP_TAG_ORIGINATORDELIVERYREPORTREQUESTED;
		propval.pvalue = &tmp_byte;
		tmp_byte = 1;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Disposition-Notification-To")) {
		propval.proptag = PROP_TAG_READRECEIPTREQUESTED;
		propval.pvalue = &tmp_byte;
		tmp_byte = 1;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag =  PROP_TAG_NONRECEIPTNOTIFICATIONREQUESTED;
		propval.pvalue = &tmp_byte;
		tmp_byte = 1;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
		parse_mime_addr(&email_addr, field);
		if (FALSE == oxcmail_parse_address(penum_param->charset,
			&email_addr, PROP_TAG_READRECEIPTNAME,
			PROP_TAG_READRECEIPTADDRESSTYPE,
			PROP_TAG_READRECEIPTEMAILADDRESS,
			PROP_TAG_READRECEIPTSMTPADDRESS,
			PROP_TAG_READRECEIPTSEARCHKEY,
			PROP_TAG_READRECEIPTENTRYID,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Message-ID")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_INTERNETMESSAGEID;
		} else {
			propval.proptag = PROP_TAG_INTERNETMESSAGEID_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Date")) {
		if (TRUE == parse_rfc822_timestamp(field, &tmp_time)) {
			propval.proptag = PROP_TAG_CLIENTSUBMITTIME;
			propval.pvalue = &tmp_int64;
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "References")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_INTERNETREFERENCES;
		} else {
			propval.proptag = PROP_TAG_INTERNETREFERENCES_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Sensitivity")) {
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		if (0 == strcasecmp(field, "Normal")) {
			tmp_int32 = 0;
		} else if (0 == strcasecmp(field, "Personal")) {
			tmp_int32 = 1;
		} else if (0 == strcasecmp(field, "Private")) {
			tmp_int32 = 2;
		} else if (0 == strcasecmp(field, "Company-Confidential")) {
			tmp_int32 = 3;
		} else {
			tmp_int32 = 0;
		}
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Importance") ||
		0 == strcasecmp(tag, "X-MSMail-Priority")) {
		if (0 == strcasecmp(field, "Low")) {
			tmp_int32 = 0;
		} else if (0 == strcasecmp(field, "Normal")) {
			tmp_int32 = 1;
		} else if (0 == strcasecmp(field, "High")) {
			tmp_int32 = 2;
		} else {
			tmp_int32 = 1;
		}
		propval.proptag = PROP_TAG_IMPORTANCE;
		propval.pvalue = &tmp_int32;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Priority")) {
		if (0 == strcasecmp(field, "Non-Urgent")) {
			tmp_int32 = 0;
		} else if (0 == strcasecmp(field, "Normal")) {
			tmp_int32 = 0;
		} else if (0 == strcasecmp(field, "Urgent")) {
			tmp_int32 = 2;
		} else {
			tmp_int32 = 0;
		}
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-Priority")) {
		switch (field[0]) {
		case '5':
		case '4':
			tmp_int32 = 0;
			break;
		case '3':
			tmp_int32 = 1;
			break;
		case '2':
		case '1':
			tmp_int32 = 2;
			break;
		default:
			tmp_int32 = 1;
			break;
		}
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Subject")) {
		if (FALSE == oxcmail_parse_subject(
			penum_param->charset, field,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
		if (NULL == tpropval_array_get_propval(
			&penum_param->pmsg->proplist, PROP_TAG_SUBJECTPREFIX)) {
			propval.proptag = PROP_TAG_SUBJECTPREFIX;
			propval.pvalue = &tmp_byte;
			tmp_byte = '\0';
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
			pvalue = tpropval_array_get_propval(
				&penum_param->pmsg->proplist, PROP_TAG_SUBJECT);
			if (NULL == pvalue) {
				pvalue = tpropval_array_get_propval(
						&penum_param->pmsg->proplist,
						PROP_TAG_SUBJECT_STRING8);
				if (NULL != pvalue) {
					propval.proptag = PROP_TAG_NORMALIZEDSUBJECT_STRING8;
					propval.pvalue = pvalue;
					if (FALSE == tpropval_array_set_propval(
						&penum_param->pmsg->proplist, &propval)) {
						return FALSE;
					}
				}
			} else {
				propval.proptag = PROP_TAG_NORMALIZEDSUBJECT;
				propval.pvalue = pvalue;
				if (FALSE == tpropval_array_set_propval(
					&penum_param->pmsg->proplist, &propval)) {
					return FALSE;
				}
			}
		}
	} else if (0 == strcasecmp(tag, "Thread-Topic")) {
		if (FALSE == oxcmail_parse_thread_topic(
			penum_param->charset, field,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Thread-Index")) {
		if (FALSE == oxcmail_parse_thread_index(
			field, &penum_param->pmsg->proplist)) {
				return FALSE;
			}
	} else if (0 == strcasecmp(tag, "In-Reply-To")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_INREPLYTOID;
		} else {
			propval.proptag = PROP_TAG_INREPLYTOID_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Reply-By")) {
		if (TRUE == parse_rfc822_timestamp(field, &tmp_time)) {
			propval.proptag = PROP_TAG_REPLYTIME;
			propval.pvalue = &tmp_int64;
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "Content-Language")) {
		tmp_int32 = oxcmail_ltag_to_lcid(field);
		if (0 != tmp_int32) {
			propval.proptag = PROP_TAG_MESSAGELOCALEID;
			propval.pvalue = &tmp_int32;
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "Accept-Language") ||
		0 == strcasecmp(tag, "X-Accept-Language")) {
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_INTERNET_HEADERS, &propname.guid);
		propname.pname = "Accept-Language";
		if (1 != int_hash_add(penum_param->phash,
			penum_param->last_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)penum_param->last_propid) << 16;
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag |= PROPVAL_TYPE_WSTRING;
		} else {
			propval.proptag |= PROPVAL_TYPE_STRING;
		}
		propval.pvalue = field;
		penum_param->last_propid ++;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Keywords")) {
		/* PidNameKeywords */
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
		propname.pname = "Keywords";
		if (1 != int_hash_add(penum_param->phash,
			penum_param->last_propid, &propname)) {
			return FALSE;
		}
		if (FALSE == oxcmail_parse_keywords(
			penum_param->charset, field,
			penum_param->last_propid,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
		penum_param->last_propid ++;
	} else if (0 == strcasecmp(tag, "Expires") ||
		0 == strcasecmp(tag, "Expiry-Date")) {
		if (TRUE == parse_rfc822_timestamp(field, &tmp_time)) {
			propval.proptag = PROP_TAG_EXPIRYTIME;
			propval.pvalue = &tmp_int64;
			tmp_int64 = rop_util_unix_to_nttime(tmp_time);
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-Auto-Response-Suppress")) {
		if (FALSE == oxcmail_parse_response_suppress(
			field, &penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Content-Class")) {
		if (FALSE == oxcmail_parse_content_class(field,
			penum_param->pmail, &penum_param->last_propid,
			penum_param->phash, &penum_param->pmsg->proplist)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-Message-Flag")) {
		if (FALSE == oxcmail_parse_message_flag(field,
			&penum_param->last_propid, penum_param->phash,
			&penum_param->pmsg->proplist)) {
			return FALSE;
		}
		penum_param->b_flag_del = TRUE;
	} else if (0 == strcasecmp(tag, "List-Help") ||
		0 == strcasecmp(tag, "X-List-Help")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_LISTHELP;
		} else {
			propval.proptag = PROP_TAG_LISTHELP_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "List-Subscribe") ||
		0 == strcasecmp(tag, "X-List-Subscribe")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_LISTSUBSCRIBE;
		} else {
			propval.proptag = PROP_TAG_LISTSUBSCRIBE_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "List-Unsubscribe") ||
		0 == strcasecmp(tag, "X-List-Unsubscribe")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_LISTUNSUBSCRIBE;
		} else {
			propval.proptag = PROP_TAG_LISTUNSUBSCRIBE_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-Payload-Class")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_ATTACHPAYLOADCLASS;
		} else {
			propval.proptag = PROP_TAG_ATTACHPAYLOADCLASS_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-MS-Exchange-Organization-PRD")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_PURPORTEDSENDERDOMAIN;
		} else {
			propval.proptag = PROP_TAG_PURPORTEDSENDERDOMAIN_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag,
		"X-MS-Exchange-Organization-SenderIdResult")) {
		if (0 == strcasecmp(field, "Neutral")) {
			tmp_int32 = 1;
		} else if (0 == strcasecmp(field, "Pass")) {
			tmp_int32 = 2;
		} else if (0 == strcasecmp(field, "Fail")) {
			tmp_int32 = 3;
		} else if (0 == strcasecmp(field, "SoftFail")) {
			tmp_int32 = 4;
		} else if (0 == strcasecmp(field, "None")) {
			tmp_int32 = 5;
		} else if (0 == strcasecmp(field, "TempError")) {
			tmp_int32 = 6;
		} else if (0 == strcasecmp(field, "PermError")) {
			tmp_int32 = 7;
		} else {
			tmp_int32 = 0;
		}
		if (0 != tmp_int32) {
			propval.proptag = PROP_TAG_SENDERIDSTATUS;
			propval.pvalue = &tmp_int32;
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-MS-Exchange-Organization-SCL")) {
		tmp_int32 = atoi(field);
		propval.proptag = PROP_TAG_CONTENTFILTERSPAMCONFIDENCELEVEL;
		propval.pvalue = &tmp_int32;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-Microsoft-Classified")) {
		if (0 == strcasecmp(field, "true") ||
			0 == strcasecmp(field, "false")) {
			if (FALSE == oxcmail_parse_classified(field,
				&penum_param->last_propid, penum_param->phash,
				&penum_param->pmsg->proplist)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-Microsoft-ClassKeep")) {
		if (TRUE == penum_param->b_classified) {
			if (FALSE == oxcmail_parse_classkeep(field,
				&penum_param->last_propid, penum_param->phash,
				&penum_param->pmsg->proplist)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-Microsoft-Classification")) {
		if (TRUE == penum_param->b_classified) {
			if (FALSE == oxcmail_parse_classification(field,
				&penum_param->last_propid, penum_param->phash,
				&penum_param->pmsg->proplist)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-Microsoft-ClassDesc")) {
		if (TRUE == penum_param->b_classified) {
			if (FALSE == oxcmail_parse_classdesc(field,
				&penum_param->last_propid, penum_param->phash,
				&penum_param->pmsg->proplist)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-Microsoft-ClassID")) {
		if (TRUE == penum_param->b_classified) {
			if (FALSE == oxcmail_parse_classid(field,
				&penum_param->last_propid, penum_param->phash,
				&penum_param->pmsg->proplist)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "X-CallingTelephoneNumber")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_SENDERTELEPHONENUMBER;
		} else {
			propval.proptag = PROP_TAG_SENDERTELEPHONENUMBER_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-VoiceMessageSenderName")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_VOICEMESSAGESENDERNAME;
		} else {
			propval.proptag = PROP_TAG_VOICEMESSAGESENDERNAME_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-AttachmentOrder")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_VOICEMESSAGEATTACHMENTORDER;
		} else {
			propval.proptag = PROP_TAG_VOICEMESSAGEATTACHMENTORDER_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-CallID")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_CALLID;
		} else {
			propval.proptag = PROP_TAG_CALLID_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-VoiceMessageDuration")) {
		propval.proptag = PROP_TAG_VOICEMESSAGEDURATION;
		propval.pvalue = &tmp_int32;
		tmp_int32 = atoi(field);
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-FaxNumverOfPages")) {
		propval.proptag = PROP_TAG_FAXNUMBEROFPAGES;
		propval.pvalue = &tmp_int32;
		tmp_int32 = atoi(field);
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Content-ID")) {
		tmp_int32 = strlen(field);
		if (tmp_int32 > 0) {
			if ('>' == field[tmp_int32 - 1]) {
				field[tmp_int32 - 1] = '\0';
			}
			if ('<' == field[0]) {
				pvalue = field + 1;
			} else {
				pvalue = field;
			}
			if (TRUE == oxcmail_check_ascii(pvalue)) {
				propval.proptag = PROP_TAG_BODYCONTENTID;
			} else {
				propval.proptag = PROP_TAG_BODYCONTENTID_STRING8;
			}
			propval.pvalue = pvalue;
			if (FALSE == tpropval_array_set_propval(
				&penum_param->pmsg->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "Content-Base")) {
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_INTERNET_HEADERS, &propname.guid);
		propname.pname = "Content-Base";
		if (1 != int_hash_add(penum_param->phash,
			penum_param->last_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)penum_param->last_propid) << 16;
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag |= PROPVAL_TYPE_WSTRING;
		} else {
			propval.proptag |= PROPVAL_TYPE_STRING;
		}
		propval.pvalue = field;
		penum_param->last_propid ++;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "Content-Location")) {
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag = PROP_TAG_BODYCONTENTLOCATION;
		} else {
			propval.proptag = PROP_TAG_BODYCONTENTLOCATION_STRING8;
		}
		propval.pvalue = field;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	} else if (0 == strcasecmp(tag, "X-MS-Exchange-Organization-AuthAs") ||
		0 == strcasecmp(tag, "X-MS-Exchange-Organization-AuthDomain") ||
		0 == strcasecmp(tag, "X-MS-Exchange-Organization-AuthMechanism") ||
		0 == strcasecmp(tag, "X-MS-Exchange-Organization-AuthSource") ||
		0 == strcasecmp(tag, "X-Mailer") ||
		0 == strcasecmp(tag, "User-Agent")) {
		propname.kind = KIND_NAME;
		rop_util_get_common_pset(PS_INTERNET_HEADERS, &propname.guid);
		propname.pname = penum_param->alloc(strlen(tag) + 1);
		if (NULL == propname.pname) {
			return FALSE;
		}
		strcpy(propname.pname, tag);
		if (1 != int_hash_add(penum_param->phash,
			penum_param->last_propid, &propname)) {
			return FALSE;
		}
		propval.proptag = ((uint32_t)penum_param->last_propid) << 16;
		if (TRUE == oxcmail_check_ascii(field)) {
			propval.proptag |= PROPVAL_TYPE_WSTRING;
		} else {
			propval.proptag |= PROPVAL_TYPE_STRING;
		}
		propval.pvalue = field;
		penum_param->last_propid ++;
		if (FALSE == tpropval_array_set_propval(
			&penum_param->pmsg->proplist, &propval)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_parse_transport_message_header(
	MIME *pmime, TPROPVAL_ARRAY *pproplist)
{
	size_t tmp_len;
	TAGGED_PROPVAL propval;
	char tmp_buff[1024*1024];
	
	tmp_len = sizeof(tmp_buff) - 1;
	if (TRUE == mime_read_head(pmime, tmp_buff, &tmp_len)) {
		tmp_buff[tmp_len + 1] = '\0';
		if (TRUE == oxcmail_check_ascii(tmp_buff)) {
			propval.proptag = PROP_TAG_TRANSPORTMESSAGEHEADERS;
		} else {
			propval.proptag = PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8;
		}
		propval.pvalue = tmp_buff;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_parse_message_body(const char *charset,
	MIME *pmime, TPROPVAL_ARRAY *pproplist)
{
	size_t length;
	BINARY tmp_bin;
	char *pcontent;
	uint32_t tmp_int32;
	char best_charset[32];
	char temp_charset[32];
	TAGGED_PROPVAL propval;
	const char *content_type;
	
	length = mime_get_length(pmime);
	pcontent = malloc(3*length + 2);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (FALSE == mime_read_content(pmime, pcontent, &length)) {
		free(pcontent);
		return TRUE;
	}
	if (TRUE == oxcmail_get_content_param(
		pmime, "charset", temp_charset, 32)) {
		strcpy(best_charset, temp_charset);
	} else {
		strcpy(best_charset, charset);
	}
	content_type = mime_get_content_type(pmime);
	if (0 == strcasecmp(content_type, "text/html")) {
		propval.proptag = PROP_TAG_INTERNETCODEPAGE;
		propval.pvalue = &tmp_int32;
		tmp_int32 = oxcmail_charset_to_cpid(best_charset);
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			free(pcontent);
			return FALSE;
		}
		tmp_bin.cb = length;
		tmp_bin.pb = pcontent;
		propval.proptag = PROP_TAG_HTML;
		propval.pvalue = &tmp_bin;
	} else if (0 == strcasecmp(content_type, "text/plain")) {
		pcontent[length] = '\0';
		if (TRUE == string_to_utf8(best_charset,
			pcontent, pcontent + length + 1)) {
			propval.proptag = PROP_TAG_BODY;
			propval.pvalue = pcontent + length + 1;
			if (FALSE == utf8_check(propval.pvalue)) {
				utf8_filter(propval.pvalue);
			}
		} else {
			propval.proptag = PROP_TAG_BODY_STRING8;
			propval.pvalue = pcontent;
		}
	} else if (0 == strcasecmp(content_type, "text/enriched")) {
		pcontent[length] = '\0';
		enriched_to_html(pcontent, pcontent + length + 1, 2*length);
		propval.proptag = PROP_TAG_INTERNETCODEPAGE;
		propval.pvalue = &tmp_int32;
		tmp_int32 = oxcmail_charset_to_cpid(best_charset);
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			free(pcontent);
			return FALSE;
		}
		tmp_bin.cb = strlen(pcontent + length + 1);
		tmp_bin.pb = pcontent + length + 1;
		propval.proptag = PROP_TAG_HTML;
		propval.pvalue = &tmp_bin;
	}
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	free(pcontent);
	return TRUE;
}

static void oxcmail_compose_mac_additional(
	uint32_t type, uint32_t creator, BINARY *pbin)
{
	int i, tmp_len;
	uint8_t tmp_buff[16];
	
	tmp_len = 0;
	tmp_buff[tmp_len] = ':';
	tmp_len ++;
	memcpy(tmp_buff + tmp_len, &creator, 4);
	tmp_len += 4;
	tmp_buff[tmp_len] = ':';
	tmp_len ++;
	memcpy(tmp_buff + tmp_len, &type, 4);
	tmp_len += 4;
	tmp_buff[tmp_len] = '\0';
	tmp_len ++;
	pbin->cb = 0;
	for (i=0; i<tmp_len; i++) {
		if (0 == i || 5 == i) {
			pbin->pb[pbin->cb] = ':';
			pbin->cb ++;
			continue;
		}
		if ('\\' == tmp_buff[i] || ':' == tmp_buff[i] || ';' == tmp_buff[i]) {
			pbin->pb[pbin->cb] = '\\';
			pbin->cb ++;
			pbin->pb[pbin->cb] = tmp_buff[i];
			pbin->cb ++;
		} else if (tmp_buff[i] < 32 || tmp_buff[i] > 251 || 127 == tmp_buff[i]) {
			pbin->pb[pbin->cb] = '\\';
			pbin->cb ++;
			sprintf(pbin->pb + pbin->cb, "%03o", (int)tmp_buff[i]);
		} else {
			pbin->pb[pbin->cb] = tmp_buff[i];
			pbin->cb ++;
		}
	}
}

static BOOL oxcmail_set_mac_attachname(TPROPVAL_ARRAY *pproplist,
	BOOL b_description, char *tmp_buff)
{
	char extension[64];
	TAGGED_PROPVAL propval;
	
	oxcmail_split_filename(tmp_buff, extension);
	if (FALSE == b_description) {
		propval.proptag = PROP_TAG_DISPLAYNAME_STRING8;
		propval.pvalue = tmp_buff;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	if ('\0' != extension[0]) {
		propval.proptag = PROP_TAG_ATTACHEXTENSION_STRING8;
		propval.pvalue = extension;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	propval.proptag = PROP_TAG_ATTACHLONGFILENAME_STRING8;
	propval.pvalue = tmp_buff;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_parse_binhex(MIME *pmime,
	ATTACHMENT_CONTENT *pattachment, BOOL b_filename,
	BOOL b_description, uint16_t *plast_propid,
	INT_HASH_TABLE *phash)
{
	BINARY *pbin;
	BINHEX binhex;
	char *pcontent;
	BINARY tmp_bin;
	char tmp_buff[256];
	size_t content_len;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	propval.proptag = PROP_TAG_ATTACHENCODING;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = 9;
	tmp_bin.pb = MACBINARY_ENCODING;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	content_len = mime_get_length(pmime);
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	if (FALSE == binhex_deserialize(&binhex, pcontent, content_len)) {
		free(pcontent);
		return FALSE;
	}
	free(pcontent);
	if (FALSE == b_filename) {
		strcpy(tmp_buff, binhex.file_name);
		if (FALSE == oxcmail_set_mac_attachname(
			&pattachment->proplist, b_description, tmp_buff)) {
			binhex_clear(&binhex);
			return FALSE;
		}
	}
	tmp_bin.cb = 0;
	tmp_bin.pb = tmp_buff;
	oxcmail_compose_mac_additional(binhex.type, binhex.creator, &tmp_bin);
	propval.proptag = PROP_TAG_ATTACHADDITIONALINFORMATION;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		binhex_clear(&binhex);
		return FALSE;
	}
	pbin = apple_util_binhex_to_appledouble(&binhex);
	if (NULL == pbin) {
		binhex_clear(&binhex);
		return FALSE;
	}
	/* PidNameAttachmentMacInfo */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT, &propname.guid);
	propname.pname = "AttachmentMacInfo";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		rop_util_free_binary(pbin);
		binhex_clear(&binhex);
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 |
									PROPVAL_TYPE_BINARY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		rop_util_free_binary(pbin);
		binhex_clear(&binhex);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	(*plast_propid) ++;
	pbin = apple_util_binhex_to_macbinary(&binhex);
	if (NULL == pbin) {
		binhex_clear(&binhex);
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHDATABINARY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		rop_util_free_binary(pbin);
		binhex_clear(&binhex);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	binhex_clear(&binhex);
	return TRUE;
}

static BOOL oxcmail_parse_appledouble(MIME *pmime,
	ATTACHMENT_CONTENT *pattachment, BOOL b_filename,
	BOOL b_description, EXT_BUFFER_ALLOC alloc,
	uint16_t *plast_propid, INT_HASH_TABLE *phash)
{
	int i;
	MIME *psub;
	MIME *phmime;
	MIME *pdmime;
	BINARY *pbin;
	BINARY tmp_bin;
	char *pcontent;
	char *pcontent1;
	EXT_PULL ext_pull;
	char tmp_buff[256];
	size_t content_len;
	size_t content_len1;
	APPLEFILE applefile;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	phmime = NULL;
	pdmime = NULL;
	psub = mime_get_child(pmime);
	if (NULL == psub) {
		return FALSE;
	}
	if (0 == strcasecmp("application/applefile",
		mime_get_content_type(psub))) {
		phmime = psub;
	} else {
		pdmime = psub;
	}
	psub = mime_get_slibling(psub);
	if (NULL == psub) {
		return FALSE;
	}
	if (NULL == phmime) {
		if (0 == strcasecmp("application/applefile",
			mime_get_content_type(psub))) {
			phmime = psub;
		} else {
			return FALSE;
		}
	} else {
		pdmime = psub;
	}
	propval.proptag = PROP_TAG_ATTACHENCODING;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = 9;
	tmp_bin.pb = MACBINARY_ENCODING;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	/* PidNameAttachmentMacContentType */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT, &propname.guid);
	propname.pname = "AttachmentMacContentType";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 |
									PROPVAL_TYPE_WSTRING;
	propval.pvalue = (void*)mime_get_content_type(pdmime);
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	content_len = mime_get_length(phmime);
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (FALSE == mime_read_content(phmime, pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	/* PidNameAttachmentMacInfo */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT, &propname.guid);
	propname.pname = "AttachmentMacInfo";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		free(pcontent);
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 | PROPVAL_TYPE_BINARY;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = content_len;
	tmp_bin.pb = (uint8_t*)pcontent;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	(*plast_propid) ++;
	ext_buffer_pull_init(&ext_pull, pcontent, content_len, alloc, 0);
	if (EXT_ERR_SUCCESS != applefile_pull_file(&ext_pull, &applefile)) {
		free(pcontent);
		return FALSE;
	}
	for (i=0; i<applefile.count; i++) {
		if (FALSE == b_filename && AS_REALNAME ==
			applefile.pentries[i].entry_id) {
			memset(tmp_buff, 0, 256);
			if (((BINARY*)applefile.pentries[i].pentry)->cb > 255) {
				memcpy(tmp_buff,
					((BINARY*)applefile.pentries[i].pentry)->pb, 255);
			} else {
				memcpy(tmp_buff,
					((BINARY*)applefile.pentries[i].pentry)->pb,
					((BINARY*)applefile.pentries[i].pentry)->cb);
			}
			if (FALSE == oxcmail_set_mac_attachname(
				&pattachment->proplist, b_description, tmp_buff)) {
				free(pcontent);
				return FALSE;
			}
		}
		if (AS_FINDERINFO == applefile.pentries[i].entry_id) {
			tmp_bin.cb = 0;
			tmp_bin.pb = tmp_buff;
			oxcmail_compose_mac_additional(
				((ASFINDERINFO*)
				applefile.pentries[i].pentry)->finfo.fd_type,
				((ASFINDERINFO*)
				applefile.pentries[i].pentry)->finfo.fd_creator,
				&tmp_bin);
			propval.proptag = PROP_TAG_ATTACHADDITIONALINFORMATION;
			propval.pvalue = &tmp_bin;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				free(pcontent);
				return FALSE;
			}
		}
	}
	content_len1 = mime_get_length(pdmime);
	pcontent1 = malloc(content_len1);
	if (NULL == pcontent1) {
		free(pcontent);
		return FALSE;
	}
	if (FALSE == mime_read_content(pdmime, pcontent1, &content_len1)) {
		free(pcontent1);
		free(pcontent);
		return FALSE;
	}
	pbin = apple_util_appledouble_to_macbinary(
			&applefile, pcontent1, content_len1);
	if (NULL == pbin) {
		free(pcontent1);
		free(pcontent);
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHDATABINARY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		rop_util_free_binary(pbin);
		free(pcontent1);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	free(pcontent1);
	free(pcontent);
	return TRUE;
}

static BOOL oxcmail_parse_macbinary(MIME *pmime,
	ATTACHMENT_CONTENT *pattachment, BOOL b_filename,
	BOOL b_description, EXT_BUFFER_ALLOC alloc,
	uint16_t *plast_propid, INT_HASH_TABLE *phash)
{	
	int i;
	BINARY *pbin;
	char *pcontent;
	BINARY tmp_bin;
	MACBINARY macbin;
	EXT_PULL ext_pull;
	char tmp_buff[64];
	size_t content_len;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	content_len = mime_get_length(pmime);
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pcontent, content_len, alloc, 0);
	if (EXT_ERR_SUCCESS != macbinary_pull_binary(&ext_pull, &macbin)) {
		free(pcontent);
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHENCODING;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = 9;
	tmp_bin.pb = MACBINARY_ENCODING;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	if (FALSE == b_filename) {
		strcpy(tmp_buff, macbin.header.file_name);
		if (FALSE == oxcmail_set_mac_attachname(
			&pattachment->proplist, b_description, tmp_buff)) {
			free(pcontent);
			return FALSE;
		}
	}
	pbin = apple_util_macbinary_to_appledouble(&macbin);
	if (NULL == pbin) {
		free(pcontent);
		return FALSE;
	}
	/* PidNameAttachmentMacInfo */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT, &propname.guid);
	propname.pname = "AttachmentMacInfo";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 | PROPVAL_TYPE_BINARY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	(*plast_propid) ++;
	tmp_bin.pb = tmp_buff;
	oxcmail_compose_mac_additional(macbin.header.type,
					macbin.header.creator, &tmp_bin);
	propval.proptag = PROP_TAG_ATTACHADDITIONALINFORMATION;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHDATABINARY;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = content_len;
	tmp_bin.pb = pcontent;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	free(pcontent);
	return TRUE;
}

static BOOL oxcmail_parse_applesingle(MIME *pmime,
	ATTACHMENT_CONTENT *pattachment, BOOL b_filename,
	BOOL b_description, EXT_BUFFER_ALLOC alloc,
	uint16_t *plast_propid, INT_HASH_TABLE *phash)
{
	int i;
	BINARY *pbin;
	BINARY tmp_bin;
	char *pcontent;
	EXT_PULL ext_pull;
	char tmp_buff[256];
	size_t content_len;
	APPLEFILE applefile;
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	content_len = mime_get_length(pmime);
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		return FALSE;
	}
	if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
		free(pcontent);
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pcontent, content_len, alloc, 0);
	if (EXT_ERR_SUCCESS != applefile_pull_file(&ext_pull, &applefile)) {
		free(pcontent);
		return oxcmail_parse_macbinary(pmime,
			pattachment, b_filename, b_description,
			alloc, plast_propid, phash);
	}
	propval.proptag = PROP_TAG_ATTACHENCODING;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = 9;
	tmp_bin.pb = MACBINARY_ENCODING;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	/* PidNameAttachmentMacInfo */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT, &propname.guid);
	propname.pname = "AttachmentMacInfo";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		free(pcontent);
		return FALSE;
	}
	pbin = apple_util_applesingle_to_appledouble(&applefile);
	if (NULL == pbin) {
		free(pcontent);
		return FALSE;
	}
	propval.proptag = ((uint32_t)(*plast_propid)) << 16 | PROPVAL_TYPE_BINARY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	(*plast_propid) ++;
	for (i=0; i<applefile.count; i++) {
		if (FALSE == b_filename && AS_REALNAME ==
			applefile.pentries[i].entry_id) {
			memset(tmp_buff, 0, 256);
			if (((BINARY*)applefile.pentries[i].pentry)->cb > 255) {
				memcpy(tmp_buff,
					((BINARY*)applefile.pentries[i].pentry)->pb, 255);
			} else {
				memcpy(tmp_buff,
					((BINARY*)applefile.pentries[i].pentry)->pb,
					((BINARY*)applefile.pentries[i].pentry)->cb);
			}
			if (FALSE == oxcmail_set_mac_attachname(
				&pattachment->proplist, b_description, tmp_buff)) {
				free(pcontent);
				return FALSE;
			}
		}
		if (AS_FINDERINFO == applefile.pentries[i].entry_id) {
			tmp_bin.cb = 0;
			tmp_bin.pb = tmp_buff;
			oxcmail_compose_mac_additional(((ASFINDERINFO*)
				applefile.pentries[i].pentry)->finfo.fd_type, ((ASFINDERINFO*)
				applefile.pentries[i].pentry)->finfo.fd_creator, &tmp_bin);
			propval.proptag = PROP_TAG_ATTACHADDITIONALINFORMATION;
			propval.pvalue = &tmp_bin;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				free(pcontent);
				return FALSE;
			}
		}
	}
	pbin = apple_util_applesingle_to_macbinary(&applefile);
	if (NULL == pbin) {
		free(pcontent);
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHDATABINARY;
	propval.pvalue = pbin;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		rop_util_free_binary(pbin);
		free(pcontent);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	free(pcontent);
	return TRUE;
}

static void oxcmail_enum_attachment(MIME *pmime, void *pparam)
{
	MAIL mail;
	VCARD vcard;
	MIME *pmime1;
	BOOL b_unifn;
	BOOL b_unidp;
	char *ptoken;
	void *pvalue;
	BOOL b_inline;
	BINARY tmp_bin;
	char *pcontent;
	BOOL b_filename;
	time_t tmp_time;
	const char *pext;
	uint64_t tmp_int64;
	uint32_t tmp_int32;
	BOOL b_description;
	size_t content_len;
	char extension[16];
	char mode_buff[32];
	char dir_buff[256];
	char tmp_buff[1024];
	char site_buff[256];
	char file_name[512];
	char date_buff[128];
	char mime_charset[32];
	MESSAGE_CONTENT *pmsg;
	char display_name[512];
	TAGGED_PROPVAL propval;
	MIME_ENUM_PARAM *pmime_enum;
	ATTACHMENT_CONTENT *pattachment;
	
	pmime1 = NULL;
	pmime_enum = pparam;
	if (FALSE == pmime_enum->b_result) {
		return;
	}
	if (pmime == pmime_enum->phtml ||
		pmime == pmime_enum->pplain ||
		pmime == pmime_enum->pcalendar ||
		pmime == pmime_enum->penriched ||
		pmime == pmime_enum->preport) {
		return;
	}
	if (NULL != mime_get_parent(pmime) && 0 == strcasecmp(
		"multipart/appledouble", mime_get_content_type(
		mime_get_parent(pmime)))) {
		return;
	}
	if (MULTIPLE_MIME == mime_get_type(pmime)) {
		if (0 != strcasecmp("multipart/appledouble",
			mime_get_content_type(pmime))) {
			return;
		}
		pmime1 = pmime;
		pmime = mime_get_child(pmime);
		if (NULL == pmime) {
			return;
		}
		if (NULL == mime_get_slibling(pmime)) {
			pmime1 = NULL;
		} else {
			pmime = mime_get_slibling(pmime);
		}
	}
	pattachment = attachment_content_init();
	if (NULL == pattachment) {
		pmime_enum->b_result = FALSE;
		return;
	}
	if (FALSE == attachment_list_append_internal(
		pmime_enum->pmsg->children.pattachments, pattachment)) {
		attachment_content_free(pattachment);
		pmime_enum->b_result = FALSE;
		return;
	}
	propval.proptag = PROP_TAG_ATTACHMIMETAG;
	if (0 == strcasecmp("application/ms-tnef",
		mime_get_content_type(pmime))) {
		propval.pvalue = "application/octet-stream";
	} else {
		propval.pvalue = (void*)mime_get_content_type(pmime);
	}
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		pmime_enum->b_result = FALSE;
		return;
	}
	b_filename = mime_get_filename(pmime, tmp_buff);
	if (TRUE == b_filename) {
		if (TRUE == mime_string_to_utf8(
			pmime_enum->charset, tmp_buff,
			file_name)) {
			b_unifn = TRUE;
		} else {
			b_unifn = FALSE;
			strcpy(file_name, tmp_buff);
		}
		oxcmail_split_filename(file_name, extension);
		if ('\0' == extension[0]) {
			pext = oxcmail_mime_to_extension(
					mime_get_content_type(pmime));
			if ('\0' != pext) {
				sprintf(extension, ".%s", pext);
				strncat(file_name, extension, sizeof(file_name));
			}
		}
	} else {
		b_unifn = TRUE;
		if ('\0' != extension[0]) {
			pext = oxcmail_mime_to_extension(
					mime_get_content_type(pmime));
			if (NULL != pext) {
				sprintf(extension, ".%s", pext);
				strncat(file_name, extension, sizeof(file_name));
			} else {
				strcpy(extension, ".dat");
			}
		}
		pmime_enum->attach_id ++;
		sprintf(file_name, "attachment%d%s",
			pmime_enum->attach_id, extension);
	}
	if ('\0' != extension[0]) {
		propval.proptag = PROP_TAG_ATTACHEXTENSION;
		propval.pvalue = extension;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	if (TRUE == b_unifn) {
		propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
	} else {
		propval.proptag = PROP_TAG_ATTACHLONGFILENAME_STRING8;
	}
	propval.pvalue = file_name;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		pmime_enum->b_result = FALSE;
		return;
	}
	b_description = mime_get_field(pmime,
		"Content-Description", tmp_buff, 256);
	if (TRUE == b_description) {
		if (TRUE == mime_string_to_utf8(
			pmime_enum->charset, tmp_buff,
			display_name)) {
			b_unidp = TRUE;
		} else {
			b_unidp = FALSE;
			strcpy(display_name, tmp_buff);
		}
		if (TRUE == b_unidp) {
			propval.proptag = PROP_TAG_DISPLAYNAME;
		} else {
			propval.proptag = PROP_TAG_DISPLAYNAME_STRING8;
		}
		propval.pvalue = display_name;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	if (TRUE == mime_get_field(pmime,
		"Content-Disposition", tmp_buff, 1024)) {
		if (TRUE == oxcmail_get_field_param(tmp_buff,
			"create-date", date_buff, 128)) {
			if (TRUE == parse_rfc822_timestamp(
				date_buff, &tmp_time)) {
				tmp_int64 = rop_util_unix_to_nttime(tmp_time);
				propval.proptag = PROP_TAG_CREATIONTIME;
				propval.pvalue = &tmp_int64;
				if (FALSE == tpropval_array_set_propval(
					&pattachment->proplist, &propval)) {
					pmime_enum->b_result = FALSE;
					return;
				}
			}
		}
		if (TRUE == oxcmail_get_field_param(tmp_buff,
			"modification-date", date_buff, 128)) {
			if (TRUE == parse_rfc822_timestamp(
				date_buff, &tmp_time)) {
				tmp_int64 = rop_util_unix_to_nttime(tmp_time);
				propval.proptag = PROP_TAG_LASTMODIFICATIONTIME;
				propval.pvalue = &tmp_int64;
				if (FALSE == tpropval_array_set_propval(
					&pattachment->proplist, &propval)) {
					pmime_enum->b_result = FALSE;
					return;
				}
			}
		}
	}
	if (NULL == tpropval_array_get_propval(
		&pattachment->proplist, PROP_TAG_CREATIONTIME)) {
		propval.proptag = PROP_TAG_CREATIONTIME;
		propval.pvalue = &pmime_enum->nttime_stamp;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	if (NULL == tpropval_array_get_propval(
		&pattachment->proplist, PROP_TAG_LASTMODIFICATIONTIME)) {
		propval.proptag = PROP_TAG_LASTMODIFICATIONTIME;
		propval.pvalue = &pmime_enum->nttime_stamp;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	b_inline = FALSE;
	if (TRUE == mime_get_field(pmime, "Content-ID", tmp_buff, 128)) {
		b_inline = TRUE;
		tmp_int32 = strlen(tmp_buff);
		if (tmp_int32 > 0) {
			if ('>' == tmp_buff[tmp_int32 - 1]) {
				tmp_buff[tmp_int32 - 1] = '\0';
			}
			if ('<' == tmp_buff[0]) {
				propval.pvalue = tmp_buff + 1;
			} else {
				propval.pvalue = tmp_buff;
			}
			if (TRUE == oxcmail_check_ascii(propval.pvalue)) {
				propval.proptag = PROP_TAG_ATTACHCONTENTID;
			} else {
				propval.proptag = PROP_TAG_ATTACHCONTENTID_STRING8;
			}
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				pmime_enum->b_result = FALSE;
				return;
			}
		}
	}
	if (TRUE == mime_get_field(pmime, "Content-Location", tmp_buff, 1024)) {
		b_inline = TRUE;
		if (TRUE == oxcmail_check_ascii(tmp_buff)) {
			propval.proptag = PROP_TAG_ATTACHCONTENTLOCATION;
		} else {
			propval.proptag = PROP_TAG_ATTACHCONTENTLOCATION_STRING8;
		}
		propval.pvalue = tmp_buff;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	if (TRUE == mime_get_field(pmime, "Content-Base", tmp_buff, 1024)) {
		if (TRUE == oxcmail_check_ascii(tmp_buff)) {
			propval.proptag = PROP_TAG_ATTACHCONTENTBASE;
		} else {
			propval.proptag = PROP_TAG_ATTACHCONTENTBASE_STRING8;
		}
		propval.pvalue = tmp_buff;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	if (TRUE == b_inline) {
		if (0 != strcasecmp("image/jpeg",
			mime_get_content_type(pmime)) &&
			0 != strcasecmp("image/jpg",
			mime_get_content_type(pmime)) &&
			0 != strcasecmp("image/pjpeg",
			mime_get_content_type(pmime)) &&
			0 != strcasecmp("image/gif",
			mime_get_content_type(pmime)) &&
			0 != strcasecmp("image/bmp",
			mime_get_content_type(pmime)) &&
			0 != strcasecmp("image/png",
			mime_get_content_type(pmime)) &&
			0 != strcasecmp("image/x-png",
			mime_get_content_type(pmime))) {
			b_inline = FALSE;
		}
	}
	if (TRUE == b_inline) {
		if (NULL == mime_get_parent(pmime) ||
			(0 != strcasecmp(mime_get_content_type(
			mime_get_parent(pmime)), "multipart/related") &&
			0 != strcasecmp(mime_get_content_type(
			mime_get_parent(pmime)), "multipart/mixed"))) {
			b_inline = FALSE;
		}
	}
	if (TRUE == b_inline) {
		propval.proptag = PROP_TAG_ATTACHFLAGS;
		propval.pvalue = &tmp_int32;
		tmp_int32 = ATTACH_FLAG_RENDEREDINBODY;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
	}
	/* Content-Type is multipart/appledouble */
	if (NULL != pmime1) {
		propval.proptag = PROP_TAG_ATTACHMETHOD;
		propval.pvalue = &tmp_int32;
		tmp_int32 = ATTACH_METHOD_BY_VALUE;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
		pmime_enum->b_result = oxcmail_parse_appledouble(
			pmime1, pattachment, b_filename, b_description,
			pmime_enum->alloc, &pmime_enum->last_propid,
			pmime_enum->phash);
		return;
	}
	if (0 == strcasecmp("text/directory",  mime_get_content_type(pmime))) {
		content_len = mime_get_length(pmime);
		if (content_len < VCARD_MAX_BUFFER_LEN) {
			pcontent = malloc(3*content_len + 2);
			if (NULL == pcontent) {
				pmime_enum->b_result = FALSE;
				return;
			}
			if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
				free(pcontent);
				pmime_enum->b_result = FALSE;
				return;
			}
			pcontent[content_len] = '\0';
			if (FALSE == oxcmail_get_content_param(
				pmime, "charset", mime_charset, 32)) {
				if (FALSE == utf8_check(pcontent)) {
					strcpy(mime_charset, pmime_enum->charset);
				} else {
					strcpy(mime_charset, "utf-8");
				}
			}
			if (TRUE == string_to_utf8(
				mime_charset, pcontent,
				pcontent + content_len + 1)) {
				if (FALSE == utf8_check(pcontent + content_len + 1)) {
					utf8_filter(pcontent + content_len + 1);
				}
				vcard_init(&vcard);
				if (TRUE == vcard_retrieve(&vcard,
					pcontent + content_len + 1) &&
					NULL != (pmsg = oxvcard_import(
					&vcard, pmime_enum->get_propids))) {
					attachment_content_set_embeded_internal(
										pattachment, pmsg);
					propval.proptag = PROP_TAG_ATTACHMETHOD;
					propval.pvalue = &tmp_int32;
					tmp_int32 = ATTACH_METHOD_EMBEDDED;
					if (FALSE == tpropval_array_set_propval(
						&pattachment->proplist, &propval)) {
						pmime_enum->b_result = FALSE;
					}
					vcard_free(&vcard);
					free(pcontent);
					return;
				}
				vcard_free(&vcard);
			}
			tmp_int32 = ATTACH_METHOD_EMBEDDED;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				pmime_enum->b_result = FALSE;
				free(pcontent);
				return;
			}
			propval.proptag = PROP_TAG_ATTACHDATABINARY;
			propval.pvalue = &tmp_bin;
			tmp_bin.cb = content_len;
			tmp_bin.pb = pcontent;
			pmime_enum->b_result = tpropval_array_set_propval(
							&pattachment->proplist, &propval);
			free(pcontent);
			return;
		}
	}
	if (0 == strcasecmp("message/rfc822", mime_get_content_type(pmime)) ||
		(TRUE == b_filename && 0 == strcasecmp(".eml", extension))) {
		content_len = mime_get_length(pmime);
		pcontent = malloc(content_len);
		if (NULL == pcontent) {
			pmime_enum->b_result = FALSE;
			return;
		}
		if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
			free(pcontent);
			pmime_enum->b_result = FALSE;
			return;
		}
		mail_init(&mail, pmime_enum->pmime_pool);
		if (TRUE == mail_retrieve(&mail, pcontent, content_len)) {
			tpropval_array_remove_propval(&pattachment->proplist,
				PROP_TAG_ATTACHLONGFILENAME);
			tpropval_array_remove_propval(&pattachment->proplist,
				PROP_TAG_ATTACHLONGFILENAME_STRING8);
			tpropval_array_remove_propval(&pattachment->proplist,
				PROP_TAG_ATTACHEXTENSION);
			tpropval_array_remove_propval(&pattachment->proplist,
				PROP_TAG_ATTACHEXTENSION_STRING8);
			if (FALSE == b_description) {
				if (TRUE == mime_get_field(mail_get_head(&mail),
					"Subject", tmp_buff, 256)) {
					if (TRUE == mime_string_to_utf8(
						pmime_enum->charset, tmp_buff, file_name)) {
						propval.proptag = PROP_TAG_DISPLAYNAME;
						propval.pvalue = file_name;
						if (FALSE == tpropval_array_set_propval(
							&pattachment->proplist, &propval)) {
							mail_free(&mail);
							free(pcontent);
							pmime_enum->b_result = FALSE;
							return;
						}
					}
				}
			}
			propval.proptag = PROP_TAG_ATTACHMETHOD;
			propval.pvalue = &tmp_int32;
			tmp_int32 = ATTACH_METHOD_EMBEDDED;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				mail_free(&mail);
				free(pcontent);
				pmime_enum->b_result = FALSE;
				return;
			}
			pmsg = oxcmail_import(pmime_enum->charset,
				pmime_enum->str_zone, &mail,
				pmime_enum->alloc, pmime_enum->get_propids);
			if (NULL == pmsg) {
				mail_free(&mail);
				free(pcontent);
				pmime_enum->b_result = FALSE;
				return;
			}
			mail_free(&mail);
			free(pcontent);
			attachment_content_set_embeded_internal(pattachment, pmsg);
			return;
		}
		mail_free(&mail);
		free(pcontent);
	}
	if (TRUE == b_filename && 0 == strcasecmp(
		"message/external-body", mime_get_content_type(pmime)) &&
		TRUE == oxcmail_get_content_param(pmime, "access-type",
		tmp_buff, 32) && 0 == strcasecmp(tmp_buff, "anon-ftp") &&
		TRUE == oxcmail_get_content_param(
		pmime, "site", site_buff, 256) &&
		TRUE == oxcmail_get_content_param(
		pmime, "directory", dir_buff, 256)) {
		if (FALSE == oxcmail_get_content_param(
			pmime, "mode", mode_buff, 32)) {
			mode_buff[0] = '\0';
		}
		if (0 == strcasecmp(mode_buff, "ascii")) {
			strcpy(mode_buff, ";type=a");
		} else if (0 == strcasecmp(mode_buff, "image")) {
			strcpy(mode_buff, ";type=i");
		}
		tmp_bin.cb = sprintf(tmp_buff, "[InternetShortcut]\r\n"
					"URL=ftp://%s/%s/%s%s", site_buff, dir_buff,
					file_name, mode_buff);
		tmp_bin.pb = mode_buff;
		propval.proptag = PROP_TAG_ATTACHDATABINARY;
		propval.pvalue = &tmp_bin;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
			return;
		}
		ptoken = strrchr(file_name, '.');
		if (NULL != ptoken) {
			strcpy(ptoken + 1, "URL");
		} else {
			strcat(file_name, ".URL");
		}
		if (TRUE == b_unifn) {
			propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
		} else {
			propval.proptag = PROP_TAG_ATTACHLONGFILENAME_STRING8;
		}
		propval.pvalue = file_name;
		if (FALSE == tpropval_array_set_propval(
			&pattachment->proplist, &propval)) {
			pmime_enum->b_result = FALSE;
		}
		return;
	}
	propval.proptag = PROP_TAG_ATTACHMETHOD;
	propval.pvalue = &tmp_int32;
	tmp_int32 = ATTACH_METHOD_BY_VALUE;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		pmime_enum->b_result = FALSE;
		return;
	}
	if (0 == strcasecmp("application/mac-binhex40",
		mime_get_content_type(pmime))) {
		pmime_enum->b_result = oxcmail_parse_binhex(
			pmime, pattachment, b_filename, b_description,
			&pmime_enum->last_propid, pmime_enum->phash);
		return;
	} else if (0 == strcasecmp("application/applefile",
		mime_get_content_type(pmime))) {
		if (TRUE == oxcmail_parse_applesingle(
			pmime, pattachment, b_filename, b_description,
			pmime_enum->alloc, &pmime_enum->last_propid,
			pmime_enum->phash)) {
			return;
		}
	}
	if (0 == strncasecmp(mime_get_content_type(pmime), "text/", 5)) {
		if (TRUE == oxcmail_get_content_param(
			pmime, "charset", tmp_buff, 32)) {
			if (TRUE == oxcmail_check_ascii(tmp_buff)) {
				propval.proptag = PROP_TAG_TEXTATTACHMENTCHARSET;
			} else {
				propval.proptag = PROP_TAG_TEXTATTACHMENTCHARSET_STRING8;
			}
			propval.pvalue = tmp_buff;
			if (FALSE == tpropval_array_set_propval(
				&pattachment->proplist, &propval)) {
				pmime_enum->b_result = FALSE;
				return;
			}
		}
	}
	content_len = mime_get_length(pmime);
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		pmime_enum->b_result = FALSE;
		return;
	}
	if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
		free(pcontent);
		pmime_enum->b_result = FALSE;
		return;
	}
	propval.proptag = PROP_TAG_ATTACHDATABINARY;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = content_len;
	tmp_bin.pb = pcontent;
	pmime_enum->b_result = tpropval_array_set_propval(
					&pattachment->proplist, &propval);
	free(pcontent);
}

static MESSAGE_CONTENT* oxcmail_parse_tnef(MIME *pmime,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	void *pcontent;
	size_t content_len;
	MESSAGE_CONTENT *pmsg;
	
	content_len = mime_get_length(pmime);
	pcontent = malloc(content_len);
	if (NULL == pcontent) {
		return NULL;
	}
	if (FALSE == mime_read_content(pmime, pcontent, &content_len)) {
		free(pcontent);
		return NULL;
	}
	pmsg = tnef_deserialize(pcontent, content_len, alloc,
			get_propids, oxcmail_username_to_entryid);
	free(pcontent);
	return pmsg;
}

static void oxcmail_replace_propid(
	TPROPVAL_ARRAY *pproplist, INT_HASH_TABLE *phash)
{
	int i;
	uint16_t propid;
	uint32_t proptag;
	uint16_t *ppropid;
	
	for (i=0; i<pproplist->count; i++) {
		proptag = pproplist->ppropval[i].proptag;
		propid = proptag >> 16;
		if (0 == (propid & 0x8000)) {
			continue;
		}
		ppropid = int_hash_query(phash, propid);
		if (NULL == ppropid || 0 == *ppropid) {
			tpropval_array_remove_propval(pproplist, proptag);
			i --;
			continue;
		}
		proptag = *ppropid;
		proptag <<= 16;
		pproplist->ppropval[i].proptag &= 0xFFFF;
		pproplist->ppropval[i].proptag |= proptag;
	}
}

static BOOL oxcmail_fetch_propname(MESSAGE_CONTENT *pmsg,
	INT_HASH_TABLE *phash, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids)
{
	int i, tmp_int;
	INT_HASH_ITER *iter;
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	INT_HASH_TABLE *phash1;
	PROPERTY_NAME *ppropname;
	PROPNAME_ARRAY propnames;
	
	propids.count = 0;
	propids.ppropid = alloc(sizeof(uint16_t)*phash->item_num);
	if (NULL == propids.ppropid) {
		return FALSE;
	}
	propnames.count = 0;
	propnames.ppropname = alloc(sizeof(PROPERTY_NAME)*phash->item_num);
	if (NULL == propnames.ppropname) {
		return FALSE;
	}
	iter = int_hash_iter_init(phash);
	for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		ppropname = int_hash_iter_get_value(iter, &tmp_int);
		propids.ppropid[propids.count] = tmp_int;
		propnames.ppropname[propnames.count] = *ppropname;
		propids.count ++;
		propnames.count ++;
	}
	int_hash_iter_free(iter);
	if (FALSE == get_propids(&propnames, &propids1)) {
		return FALSE;
	}
	phash1 = int_hash_init(0x1000, sizeof(uint16_t), NULL);
	if (NULL == phash1) {
		return FALSE;
	}
	for (i=0; i<propids.count; i++) {
		int_hash_add(phash1, propids.ppropid[i], propids1.ppropid + i);
	}
	oxcmail_replace_propid(&pmsg->proplist, phash1);
	if (NULL != pmsg->children.prcpts) {
		for (i=0; i<pmsg->children.prcpts->count; i++) {
			oxcmail_replace_propid(pmsg->children.prcpts->pparray[i], phash1);
		}
	}
	if (NULL != pmsg->children.pattachments) {
		for (i=0; i<pmsg->children.pattachments->count; i++) {
			oxcmail_replace_propid(
				&pmsg->children.pattachments->pplist[i]->proplist, phash1);
		}
	}
	int_hash_free(phash1);
	return TRUE;
}

static void oxcmail_remove_flag_propties(
	MESSAGE_CONTENT *pmsg, GET_PROPIDS get_propids)
{
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[3];
	static uint32_t lid_task_duedate = 0x00008105;
	static uint32_t lid_task_startdate = 0x00008104;
	static uint32_t lid_task_datecompleted = 0x0000810F;
	
	tpropval_array_remove_propval(&pmsg->proplist,
						PROP_TAG_FLAGCOMPLETETIME);
	propnames.count = 3;
	propnames.ppropname = propname_buff;
	/* PidLidTaskDueDate */
	propname_buff[0].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_TASK,
		&propname_buff[0].guid);
	propname_buff[0].plid = &lid_task_duedate;
	/* PidLidTaskStartDate */
	propname_buff[1].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_TASK,
		&propname_buff[1].guid);
	propname_buff[1].plid = &lid_task_startdate;
	/* PidLidTaskDateCompleted */
	propname_buff[2].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_TASK,
		&propname_buff[2].guid);
	propname_buff[2].plid = &lid_task_datecompleted;
	if (FALSE == get_propids(&propnames, &propids)) {
		return;
	}
	tpropval_array_remove_propval(&pmsg->proplist,
		((uint32_t)propids.ppropid[0]) << 16 |
		PROPVAL_TYPE_FILETIME);
	tpropval_array_remove_propval(&pmsg->proplist,
		((uint32_t)propids.ppropid[1]) << 16 |
		PROPVAL_TYPE_FILETIME);
	tpropval_array_remove_propval(&pmsg->proplist,
		((uint32_t)propids.ppropid[2]) << 16 |
		PROPVAL_TYPE_FILETIME);
}

static BOOL oxcmail_copy_message_proplist(
	MESSAGE_CONTENT *pmsg, MESSAGE_CONTENT *pmsg1)
{
	int i;
	
	for (i=0; i<pmsg->proplist.count; i++) {
		if (NULL == tpropval_array_get_propval(&pmsg1->proplist,
			pmsg->proplist.ppropval[i].proptag)) {
			if (FALSE == tpropval_array_set_propval(&pmsg1->proplist,
				&pmsg->proplist.ppropval[i])) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

static BOOL oxcmail_merge_message_attachments(
	MESSAGE_CONTENT *pmsg, MESSAGE_CONTENT *pmsg1)
{
	int i;
	
	if (NULL == pmsg1->children.pattachments) {
		pmsg1->children.pattachments = pmsg->children.pattachments;
		pmsg->children.pattachments = NULL;
		return TRUE;
	}
	while (0 != pmsg->children.pattachments->count) {
		if (FALSE == attachment_list_append_internal(
			pmsg1->children.pattachments,
			pmsg->children.pattachments->pplist[0])) {
			return FALSE;
		}
		pmsg->children.pattachments->count --;
		if (0 == pmsg->children.pattachments->count) {
			return TRUE;
		}
		memmove(pmsg->children.pattachments->pplist,
			pmsg->children.pattachments->pplist + 1,
			sizeof(void*)*pmsg->children.pattachments->count);
	}
	return TRUE;
}

static BOOL oxcmail_enum_dsn_action_field(
	const char *tag, const char *value, void *pparam)
{
	int severity;
	
	if (0 != strcasecmp("Action", tag)) {
		return TRUE;
	}
	if (0 == strcasecmp("delivered", value)) {
		severity = 0;
	} else if (0 == strcasecmp("expanded", value)) {
		severity = 1;
	} else if (0 == strcasecmp("relayed", value)) {
		severity = 2;
	} else if (0 == strcasecmp("delayed", value)) {
		severity = 3;
	} else if (0 == strcasecmp("failed", value)) {
		severity = 4;
	} else {
		return TRUE;
	}
	if (severity > *(int*)pparam) {
		*(int*)pparam = severity;
	}
	return TRUE;
}

static BOOL oxcmail_enum_dsn_action_fields(
	DSN_FIELDS *pfields, void *pparam)
{
	return dsn_enum_fields(pfields,
		oxcmail_enum_dsn_action_field, pparam);
}

static BOOL oxcmail_enum_dsn_rcpt_field(
	const char *tag, const char *value, void *pparam)
{
	DSN_FILEDS_INFO *pinfo;
	
	pinfo = (DSN_FILEDS_INFO*)pparam;
	if (0 == strcasecmp(tag, "Final-Recipient") &&
		0 == strncasecmp(value, "rfc822;", 7)) {
		strncpy(pinfo->final_recipient, value + 7, 256);
		ltrim_string(pinfo->final_recipient);
		rtrim_string(pinfo->final_recipient);
	} else if (0 == strcasecmp(tag, "Action")) {
		if (0 == strcasecmp("delivered", value)) {
			pinfo->action_severity = 0;
		} else if (0 == strcasecmp("expanded", value)) {
			pinfo->action_severity = 1;
		} else if (0 == strcasecmp("relayed", value)) {
			pinfo->action_severity = 2;
		} else if (0 == strcasecmp("delayed", value)) {
			pinfo->action_severity = 3;
		} else if (0 == strcasecmp("failed", value)) {
			pinfo->action_severity = 4;
		}
	} else if (0 == strcasecmp(tag, "Status")) {
		pinfo->status = value;
	} else if (0 == strcasecmp(tag, "Diagnostic-Code")) {
		pinfo->diagnostic_code = value;
	} else if (0 == strcasecmp(tag, "Remote-MTA")) {
		strncpy(pinfo->remote_mta, value, sizeof(pinfo->remote_mta));
	} else if (0 == strcasecmp(tag, "X-Supplementary-Info")) {
		pinfo->x_supplementary_info = value;
	} else if (0 == strcasecmp(tag, "X-Display-Name")) {
		pinfo->x_display_name = value;
	}
	return TRUE;
}

static BOOL oxcmail_enum_dsn_rcpt_fields(
	DSN_FIELDS *pfields, void *pparam)
{
	int kind;
	int detail;
	int subject;
	int tmp_len;
	char *ptoken1;
	char *ptoken2;
	BINARY tmp_bin;
	int address_type;
	char essdn[1280];
	uint32_t tmp_int32;
	char tmp_buff[1280];
	uint32_t status_code;
	DSN_ENUM_INFO *pinfo;
	uint32_t reason_code;
	DSN_FILEDS_INFO f_info;
	TAGGED_PROPVAL propval;
	char display_name[512];
	uint32_t diagnostic_code;
	TPROPVAL_ARRAY *pproplist;
	
	pinfo = (DSN_ENUM_INFO*)pparam;
	f_info.final_recipient[0] = '\0';
	f_info.action_severity = -1;
	f_info.remote_mta[0] = '\0';
	f_info.status = NULL;
	f_info.diagnostic_code = NULL;
	f_info.x_supplementary_info = NULL;
	f_info.x_display_name = NULL;
	dsn_enum_fields(pfields, oxcmail_enum_dsn_rcpt_field, &f_info);
	if (f_info.action_severity < pinfo->action_severity ||
		'\0' == f_info.final_recipient[0] || NULL == f_info.status) {
		return TRUE;
	}
	strncpy(tmp_buff, f_info.status, 1024);
	ptoken1 = strchr(tmp_buff, '.');
	if (NULL == ptoken1) {
		return TRUE;
	}
	*ptoken1 = '\0';
	if (1 != strlen(tmp_buff)) {
		return TRUE;
	}
	if ('2' == tmp_buff[0]) {
		kind = 2;
	} else if ('4' == tmp_buff[0]) {
		kind = 4;
	} else if ('5' == tmp_buff[0]) {
		kind = 5;
	} else {
		return TRUE;
	}
	ptoken1 ++;
	ptoken2 = strchr(ptoken1, '.');
	if (NULL == ptoken2) {
		return TRUE;
	}
	*ptoken2 = '\0';
	tmp_len = strlen(ptoken1);
	if (tmp_len < 1 || tmp_len > 3) {
		return TRUE;
	}
	subject = atoi(ptoken1);
	if (subject > 9 || subject < 0) {
		subject = 0;
	}
	ptoken2 ++;
	tmp_len = strlen(ptoken2);
	if (tmp_len < 1 || tmp_len > 3) {
		return TRUE;
	}
	detail = atoi(ptoken2);
	if (detail > 9 || detail < 0) {
		detail = 0;
	}
	pproplist = tpropval_array_init();
	if (NULL == pproplist) {
		return FALSE;
	}
	if (FALSE == tarray_set_append_internal(
		pinfo->prcpts, pproplist)) {
		tpropval_array_free(pproplist);
		return FALSE;
	}
	propval.proptag = PROP_TAG_RECIPIENTTYPE;
	propval.pvalue = &tmp_int32;
	tmp_int32 = RECIPIENT_TYPE_TO;
	if (FALSE == tpropval_array_set_propval(
		pproplist, &propval)) {
		return FALSE;
	}
	if (NULL != f_info.x_display_name) {
		if (strlen(f_info.x_display_name) < 256 &&
			TRUE == mime_string_to_utf8("utf-8",
			f_info.x_display_name, display_name)) {
			propval.proptag = PROP_TAG_DISPLAYNAME;
			propval.pvalue = display_name;
			if (FALSE == tpropval_array_set_propval(
				pproplist, &propval)) {
				return FALSE;
			}
		}
	}
	if (FALSE == oxcmail_username_to_essdn(
		f_info.final_recipient, essdn, &address_type)) {
		essdn[0] = '\0';
		address_type = ADDRESS_TYPE_NORMAL;
		tmp_bin.cb = sprintf(tmp_buff, "SMTP:%s",
					f_info.final_recipient) + 1;
		upper_string(tmp_buff);
		propval.proptag = PROP_TAG_ADDRESSTYPE;
		propval.pvalue = "SMTP";
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_EMAILADDRESS;
		propval.pvalue = f_info.final_recipient;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	} else {
		tmp_bin.cb = sprintf(tmp_buff, "EX:%s", essdn) + 1;
		propval.proptag = PROP_TAG_ADDRESSTYPE;
		propval.pvalue = "EX";
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_EMAILADDRESS;
		propval.pvalue = essdn;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	propval.proptag = PROP_TAG_SMTPADDRESS;
	propval.pvalue = f_info.final_recipient;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	tmp_bin.pb = tmp_buff;
	propval.proptag = PROP_TAG_SEARCHKEY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ENTRYID;
	tmp_bin.cb = 0;
	tmp_bin.pb = tmp_buff;
	propval.pvalue = &tmp_bin;
	if ('\0' == essdn[0]) {
		if (FALSE == oxcmail_username_to_oneoff(
			f_info.final_recipient, display_name, &tmp_bin)) {
			return FALSE;
		}
	} else {
		if (FALSE == oxcmail_essdn_to_entryid(essdn, &tmp_bin)) {
			return FALSE;
		}
	}
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_RECIPIENTENTRYID;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_RECORDKEY;
	propval.pvalue = &tmp_bin;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_OBJECTTYPE;
	propval.pvalue = &tmp_int32;
	if (ADDRESS_TYPE_MLIST == address_type) {
		tmp_int32 = OBJECT_DLIST;
	} else {
		tmp_int32 = OBJECT_USER;
	}
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_DISPLAYTYPE;
	propval.pvalue = &tmp_int32;
	switch (address_type) {
	case ADDRESS_TYPE_MLIST:
		tmp_int32 = DISPLAY_TYPE_DISTLIST;
		break;
	case ADDRESS_TYPE_ROOM:
		tmp_int32 = DISPLAY_TYPE_ROOM;
		break;
	case ADDRESS_TYPE_EQUIPMENT:
		tmp_int32 = DISPLAY_TYPE_EQUIPMENT;
		break;
	default:
		tmp_int32 = DISPLAY_TYPE_MAILUSER;
		break;
	}
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_RECIPIENTFLAGS;
	propval.pvalue = &tmp_int32;
	tmp_int32 = 1;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	if ('\0' != f_info.remote_mta[0]) {
		propval.proptag = PROP_TAG_REMOTEMESSAGETRANSFERAGENT;
		propval.pvalue = f_info.remote_mta;
		if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
			return FALSE;
		}
	}
	propval.proptag = PROP_TAG_REPORTTIME;
	propval.pvalue = &pinfo->submit_time;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_SUPPLEMENTARYINFO;
	if (NULL != f_info.x_supplementary_info) {
		propval.pvalue = (void*)f_info.x_supplementary_info;
	} else {
		if (NULL == f_info.diagnostic_code) {
			snprintf(tmp_buff, 1024, "<%s #%s>",
				f_info.remote_mta, f_info.status);
		} else {
			snprintf(tmp_buff, 1024, "<%s #%s %s>",
				f_info.remote_mta, f_info.status,
				f_info.diagnostic_code);
		}
		propval.pvalue = tmp_buff;
	}
	status_code = 100*kind + 10*subject + detail;
	propval.proptag = PROP_TAG_NONDELIVERYREPORTSTATUSCODE;
	propval.pvalue = &status_code;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	reason_code = 0;
	diagnostic_code = -1;
	switch (subject) {
	case 1:
		switch (detail) {
		case 1:
			diagnostic_code = 35;
			reason_code = 1;
			break;
		case 2:
			diagnostic_code = 48;
			break;
		case 3:
			diagnostic_code = 32;
			break;
		case 4:
			diagnostic_code = 1;
			break;
		case 6:
			diagnostic_code = 40;
			break;
		default:
			diagnostic_code = 0;
		}
		break;
	case 2:
		switch (detail) {
		case 2:
		case 3:
			diagnostic_code = 13;
			break;
		case 4:
			diagnostic_code = 30;
			break;
		default:
			diagnostic_code = 38;
			break;
		}
		break;
	case 3:
		switch (detail) {
		case 2:
			break;
		case 3:
		case 5:
			diagnostic_code = 18;
			break;
		case 4:
			diagnostic_code = 13;
			break;
		default:
			diagnostic_code = 38;
			break;
		}
		break;
	case 4:
		switch (detail) {
		case 0:
		case 4:
			break;
		case 3:
			reason_code = 6;
			break;
		case 6:
		case 8:
			diagnostic_code = 3;
			break;
		case 7:
			diagnostic_code = 5;
			break;
		default:
			diagnostic_code = 2;
			break;
		}
		break;
	case 5:
		switch (detail) {
		case 3:
			diagnostic_code = 16;
			break;
		case 4:
			diagnostic_code = 11;
			break;
		default:
			diagnostic_code = 17;
			break;
		}
		break;
	case 6:
		switch (detail) {
		case 2:
			diagnostic_code = 9;
			break;
		case 3:
			diagnostic_code = 8;
			break;
		case 4:
			diagnostic_code = 25;
			break;
		case 5:
			reason_code = 2;
			break;
		default:
			diagnostic_code = 15;
			break;
			
		}
		break;
	case 7:
		switch (detail) {
		case 1:
			diagnostic_code = 29;
			break;
		case 2:
			diagnostic_code = 28;
			break;
		case 3:
			diagnostic_code = 26;
			break;
		default:
			diagnostic_code = 46;
			break;
		}
		break;
	}
	propval.proptag = PROP_TAG_NONDELIVERYREPORTDIAGCODE;
	propval.pvalue = &diagnostic_code;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_NONDELIVERYREPORTREASONCODE;
	propval.pvalue = &reason_code;
	if (FALSE == tpropval_array_set_propval(pproplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_enum_dsn_reporting_mta(
	const char *tag, const char *value, void *pparam)
{
	TAGGED_PROPVAL propval;
	
	if (0 == strcasecmp(tag, "Reporting-MTA")) {
		propval.proptag = PROP_TAG_REPORTINGMESSAGETRANSFERAGENT;
		propval.pvalue = (void*)value;
		return tpropval_array_set_propval(
			&((MESSAGE_CONTENT*)pparam)->proplist, &propval);
	}
	return TRUE;
}

static MIME* oxcmail_parse_dsn(MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	DSN dsn;
	MIME *pmime;
	void *pvalue;
	size_t content_len;
	DSN_ENUM_INFO dsn_info;
	TAGGED_PROPVAL propval;
	char tmp_buff[256*1024];
	
	pmime = mail_get_head(pmail);
	pmime = mime_get_child(pmime);
	if (NULL == pmime) {
		return NULL;
	}
	do {
		if (0 == strcasecmp("message/delivery-status",
			mime_get_content_type(pmime))) {
			break;
		}
	} while (pmime = mime_get_slibling(pmime));
	if (NULL == pmime) {
		return NULL;
	}
	if (mime_get_length(pmime) > sizeof(tmp_buff)) {
		return NULL;
	}
	content_len = sizeof(tmp_buff);
	if (FALSE == mime_read_content(pmime, tmp_buff, &content_len)) {
		return NULL;
	}
	dsn_init(&dsn);
	if (FALSE == dsn_retrieve(&dsn, tmp_buff, content_len)) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_info.action_severity = -1;
	dsn_enum_rcpts_fields(&dsn,
		oxcmail_enum_dsn_action_fields,
		&dsn_info.action_severity);
	if (-1 == dsn_info.action_severity) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_info.prcpts = tarray_set_init();
	if (NULL == dsn_info.prcpts) {
		dsn_free(&dsn);
		return NULL;
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_CLIENTSUBMITTIME);
	if (NULL == pvalue) {
		dsn_info.submit_time = rop_util_unix_to_nttime(time(NULL));
	} else {
		dsn_info.submit_time = *(uint64_t*)pvalue;
	}
	if (FALSE == dsn_enum_rcpts_fields(&dsn,
		oxcmail_enum_dsn_rcpt_fields, &dsn_info)) {
		tarray_set_free(dsn_info.prcpts);
		dsn_free(&dsn);
		return NULL;
	}
	message_content_set_rcpts_internal(pmsg, dsn_info.prcpts);
	if (FALSE == dsn_enum_fields(dsn_get_message_fileds(&dsn),
		oxcmail_enum_dsn_reporting_mta, pmsg)) {
		dsn_free(&dsn);
		return NULL;
	}
	switch (dsn_info.action_severity) {
	case 0:
		strcpy(tmp_buff, "REPORT.IPM.Note.DR");
		break;
	case 1:
		strcpy(tmp_buff, "REPORT.IPM.Note.Expanded.DR");
		break;
	case 2:
		strcpy(tmp_buff, "REPORT.IPM.Note.Relayed.DR");
		break;
	case 3:
		strcpy(tmp_buff, "REPORT.IPM.Note.Delayed.DR");
		break;
	case 4:
		strcpy(tmp_buff, "REPORT.IPM.Note.NDR");
		break;
	}
	propval.proptag = PROP_TAG_MESSAGECLASS;
	propval.pvalue = tmp_buff;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_free(&dsn);
	return pmime;
}

static BOOL oxcmail_enum_mdn(const char *tag,
	const char *value, void *pparam)
{
	size_t len;
	char *pvalue;
	char *ptoken;
	BINARY tmp_bin;
	char tmp_buff[1024];
	TAGGED_PROPVAL propval;
	
	if (0 == strcasecmp(tag, "Original-Recipient")) {
		if (0 == strncasecmp(value, "rfc822;", 7)) {
			propval.proptag = PROP_TAG_ORIGINALDISPLAYTO;
			propval.pvalue = (char*)value + 7;
			if (FALSE == tpropval_array_set_propval(
				&((MESSAGE_CONTENT*)pparam)->proplist, &propval)) {
				return FALSE;
			}
		}
	} else if (0 == strcasecmp(tag, "Final-Recipient")) {
		if (0 == strncasecmp(value, "rfc822;", 7)) {
			if (NULL == tpropval_array_get_propval(
				&((MESSAGE_CONTENT*)pparam)->proplist,
				PROP_TAG_ORIGINALDISPLAYTO)) {
				propval.proptag = PROP_TAG_ORIGINALDISPLAYTO;
				propval.pvalue = (char*)value + 7;
				return tpropval_array_set_propval(
					&((MESSAGE_CONTENT*)pparam)->proplist, &propval);
			}
		}
	} else if (0 == strcasecmp(tag, "Disposition")) {
		ptoken = strchr(value, ';');
		if (NULL == ptoken) {
			return TRUE;
		}
		ptoken ++;
		strncpy(tmp_buff, ptoken, 1024);
		ltrim_string(tmp_buff);
		ptoken = strchr(tmp_buff, '/');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		if (0 == strcasecmp(tmp_buff, "displayed") ||
			0 == strcasecmp(tmp_buff, "dispatched") ||
			0 == strcasecmp(tmp_buff, "processed")) {
			strcpy(tmp_buff, "REPORT.IPM.Note.IPNRN");
		} else if (0 == strcasecmp(tmp_buff, "deleted") ||
			0 == strcasecmp(tmp_buff, "denied") ||
			0 == strcasecmp(tmp_buff, "failed")) {
			sprintf(tmp_buff, "REPORT.IPM.Note.IPNNRN");
		} else {
			return TRUE;
		}
		propval.proptag = PROP_TAG_MESSAGECLASS;
		propval.pvalue = tmp_buff;
		if (FALSE == tpropval_array_set_propval(
			&((MESSAGE_CONTENT*)pparam)->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_REPORTTEXT;
		propval.pvalue = (char*)value;
		return tpropval_array_set_propval(
			&((MESSAGE_CONTENT*)pparam)->proplist, &propval);
	} else if (0 == strcasecmp(tag, "X-MSExch-Correlation-Key")) {
		len = strlen(value);
		if (len <= 1024 && 0 == decode64(value, len, tmp_buff, &len)) {
			propval.proptag = PROP_TAG_PARENTKEY;
			propval.pvalue = &tmp_bin;
			tmp_bin.pb = tmp_buff;
			tmp_bin.cb = len;
			return tpropval_array_set_propval(
				&((MESSAGE_CONTENT*)pparam)->proplist, &propval);
		}
	} else if (0 == strcasecmp(tag, "Original-Message-ID")) {
		propval.proptag = PROP_TAG_ORIGINALMESSAGEID;
		propval.pvalue = (char*)value;
		if (FALSE == tpropval_array_set_propval(
			&((MESSAGE_CONTENT*)pparam)->proplist, &propval)) {
			return FALSE;
		}
		propval.proptag = PROP_TAG_INTERNETREFERENCES;
		propval.pvalue = (char*)value;
		return tpropval_array_set_propval(
			&((MESSAGE_CONTENT*)pparam)->proplist, &propval);
	} else if (0 == strcasecmp(tag, "X-Display-Name")) {
		if (TRUE == mime_string_to_utf8("utf-8", value, tmp_buff)) {
			propval.proptag = PROP_TAG_DISPLAYNAME;
			propval.pvalue = tmp_buff;
		} else {
			propval.proptag = PROP_TAG_DISPLAYNAME_STRING8;
			propval.pvalue = (char*)value;
		}
		return tpropval_array_set_propval(
			&((MESSAGE_CONTENT*)pparam)->proplist, &propval);
	}
	return TRUE;
}

static MIME* oxcmail_parse_mdn(MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	int i;
	DSN dsn;
	MIME *pmime;
	void *pvalue;
	size_t content_len;
	TAGGED_PROPVAL propval;
	char tmp_buff[256*1024];
	
	pmime = mail_get_head(pmail);
	if (0 != strcasecmp("message/disposition-notification",
		mime_get_content_type(pmime))) {
		pmime = mime_get_child(pmime);
		if (NULL == pmime) {
			return NULL;
		}
		do {
			if (0 == strcasecmp("message/disposition-notification",
				mime_get_content_type(pmime))) {
				break;
			}
		} while (pmime = mime_get_slibling(pmime));
	}
	if (NULL == pmime) {
		return NULL;
	}
	if (mime_get_length(pmime) > sizeof(tmp_buff)) {
		return NULL;
	}
	content_len = sizeof(tmp_buff);
	if (FALSE == mime_read_content(pmime, tmp_buff, &content_len)) {
		return NULL;
	}
	dsn_init(&dsn);
	if (FALSE == dsn_retrieve(&dsn, tmp_buff, content_len)) {
		dsn_free(&dsn);
		return NULL;
	}
	if (FALSE == dsn_enum_fields(dsn_get_message_fileds(&dsn),
		oxcmail_enum_mdn, pmsg)) {
		dsn_free(&dsn);
		return NULL;
	}
	dsn_free(&dsn);
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_CLIENTSUBMITTIME);
	propval.proptag = PROP_TAG_ORIGINALDELIVERYTIME;
	propval.pvalue = pvalue;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return NULL;
	}
	propval.proptag = PROP_TAG_RECEIPTTIME;
	propval.pvalue = pvalue;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return NULL;
	}
	propval.proptag = PROP_TAG_REPORTTIME;
	propval.pvalue = pvalue;
	for (i=0; i<pmsg->children.prcpts->count; i++) {
		if (FALSE == tpropval_array_set_propval(
			pmsg->children.prcpts->pparray[i], &propval)) {
			return NULL;
		}
	}
	return pmime;
}

static BOOL oxcmail_parse_encrypted(MIME *phead,
	uint16_t *plast_propid, INT_HASH_TABLE *phash,
	MESSAGE_CONTENT *pmsg)
{
	char tmp_buff[1024];
	PROPERTY_NAME propname;
	TAGGED_PROPVAL propval;
	
	if (FALSE == mime_get_field(phead,
		"Content-Type", tmp_buff, 1024)) {
		return FALSE;
	}
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PS_INTERNET_HEADERS, &propname.guid);
	propname.pname = "Content-Type";
	if (1 != int_hash_add(phash, *plast_propid, &propname)) {
		return FALSE;
	}
	propval.proptag = ((uint32_t)*plast_propid) << 16 |
									PROPVAL_TYPE_WSTRING;
	propval.pvalue = tmp_buff;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		return FALSE;
	}
	(*plast_propid) ++;
	return TRUE;
}

static BOOL oxcmail_parse_smime_message(
	MAIL *pmail, MESSAGE_CONTENT *pmsg)
{
	MIME *phead;
	size_t offset;
	char *pcontent;
	BINARY tmp_bin;
	uint32_t tmp_int32;
	size_t content_len;
	TAGGED_PROPVAL propval;
	const char *content_type;
	ATTACHMENT_CONTENT *pattachment;
	
	phead = mail_get_head(pmail);
	if (NULL == phead) {
		return FALSE;
	}
	content_len = mime_get_length(phead);
	pcontent = malloc(content_len + 1024);
	if (NULL == pcontent) {
		return FALSE;
	}
	content_type = mime_get_content_type(phead);
	if (0 == strcasecmp(content_type, "multipart/signed")) {
		memcpy(pcontent, "Content-Type: ", 14);
		offset = 14;
		if (FALSE == mime_get_field(phead, "Content-Type",
			pcontent + offset, 1024 - offset)) {
			free(pcontent);
			return FALSE;
		}
		offset += strlen(pcontent + offset);
		memcpy(pcontent + offset, "\r\n\r\n", 4);
		offset += 4;
		if (FALSE == mime_read_content(phead,
			pcontent + offset, &content_len)) {
			free(pcontent);
			return FALSE;
		}
		offset += content_len;
	} else {
		if (FALSE == mime_read_content(phead,
			pcontent, &content_len)) {
			free(pcontent);
			return FALSE;
		}
		offset = content_len;
	}
	pattachment = attachment_content_init();
	if (NULL == pattachment) {
		free(pcontent);
		return FALSE;
	}
	if (FALSE == attachment_list_append_internal(
		pmsg->children.pattachments, pattachment)) {
		attachment_content_free(pattachment);
		free(pcontent);
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHDATABINARY;
	propval.pvalue = &tmp_bin;
	tmp_bin.cb = offset;
	tmp_bin.pb = pcontent;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		free(pcontent);
		return FALSE;
	}
	free(pcontent);
	propval.proptag = PROP_TAG_ATTACHMETHOD;
	propval.pvalue = &tmp_int32;
	tmp_int32 = ATTACH_METHOD_BY_VALUE;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHMIMETAG;
	propval.pvalue = (void*)content_type;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHEXTENSION;
	propval.pvalue = ".p7m";
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHFILENAME;
	propval.pvalue = "SMIME.p7m";
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_ATTACHLONGFILENAME;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_DISPLAYNAME;
	if (FALSE == tpropval_array_set_propval(
		&pattachment->proplist, &propval)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_try_assign_propval(TPROPVAL_ARRAY *pproplist,
	uint32_t proptag1, uint32_t proptag2)
{
	void *pvalue;
	TAGGED_PROPVAL propval;
	
	if (NULL != tpropval_array_get_propval(pproplist, proptag1)) {
		return TRUE;
	}
	pvalue = tpropval_array_get_propval(pproplist, proptag2);
	if (NULL == pvalue) {
		return TRUE;
	}
	propval.proptag = proptag1;
	propval.pvalue = pvalue;
	return tpropval_array_set_propval(pproplist, &propval);
}

MESSAGE_CONTENT* oxcmail_import(const char *charset,
	const char *str_zone, MAIL *pmail,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids)
{
	int i;
	ICAL ical;
	MIME *phead;
	MIME *pmime;
	MIME *pmime1;
	BOOL b_smime;
	void *pvalue;
	char *pcontent;
	uint8_t tmp_byte;
	BINARY *phtml_bin;
	BINARY *ptnef_key;
	TARRAY_SET *prcpts;
	uint32_t tmp_int32;
	size_t content_len;
	char tmp_buff[256];
	BOOL b_alternative;
	PROPID_ARRAY propids;
	const char *encoding;
	char mime_charset[64];
	INT_HASH_TABLE *phash;
	MESSAGE_CONTENT *pmsg;
	MESSAGE_CONTENT *pmsg1;
	TAGGED_PROPVAL propval;
	PROPERTY_NAME propname;
	PROPNAME_ARRAY propnames;
	char default_charset[64];
	MIME_ENUM_PARAM mime_enum;
	FIELD_ENUM_PARAM field_param;
	ATTACHMENT_LIST *pattachments;
	
	pmsg1 = NULL;
	b_smime = FALSE;
	mime_enum.phtml = NULL;
	mime_enum.pplain = NULL;
	mime_enum.pcalendar = NULL;
	mime_enum.penriched = NULL;
	mime_enum.preport = NULL;
	pmsg = message_content_init();
	if (NULL == pmsg) {
		return NULL;
	}
	/* set default message class */
	propval.proptag = PROP_TAG_MESSAGECLASS;
	propval.pvalue = "IPM.Note";
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		message_content_free(pmsg);
		return NULL;
	}
	prcpts = tarray_set_init();
	if (NULL == prcpts) {
		message_content_free(pmsg);
		return NULL;
	}
	message_content_set_rcpts_internal(pmsg, prcpts);
	phash = int_hash_init(0x1000, sizeof(PROPERTY_NAME), NULL);
	if (NULL == phash) {
		message_content_free(pmsg);
		return NULL;
	}
	if (FALSE == mail_get_charset(pmail, default_charset)) {
		strcpy(default_charset, charset);
	}
	field_param.alloc = alloc;
	field_param.pmail = pmail;
	field_param.pmsg = pmsg;
	field_param.phash = phash;
	field_param.charset = default_charset;
	field_param.last_propid = 0x8000;
	field_param.b_flag_del = FALSE;
	phead = mail_get_head(pmail);
	if (NULL == phead) {
		int_hash_free(phash);
		message_content_free(pmsg);
		return NULL;
	}
	field_param.b_classified = mime_get_field(phead,
		"X-Microsoft-Classified", tmp_buff, 16);
	if (FALSE == mime_enum_field(phead,
		oxcmail_enum_mail_head, &field_param)) {
		int_hash_free(phash);
		message_content_free(pmsg);
		return NULL;
	}
	if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENDERNAME) &&
		NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENDERSMTPADDRESS)) {
		if (FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENDERNAME,
			PROP_TAG_SENTREPRESENTINGNAME) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENDERSMTPADDRESS,
			PROP_TAG_SENTREPRESENTINGSMTPADDRESS) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENDERADDRESSTYPE,
			PROP_TAG_SENTREPRESENTINGADDRESSTYPE) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENDEREMAILADDRESS,
			PROP_TAG_SENTREPRESENTINGEMAILADDRESS) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENDERSEARCHKEY,
			PROP_TAG_SENTREPRESENTINGSEARCHKEY) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENDERENTRYID,
			PROP_TAG_SENTREPRESENTINGENTRYID)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	} else if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENTREPRESENTINGNAME) &&
		NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENTREPRESENTINGSMTPADDRESS)) {
		if (FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENTREPRESENTINGNAME,
			PROP_TAG_SENDERNAME) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENTREPRESENTINGSMTPADDRESS,
			PROP_TAG_SENDERSMTPADDRESS) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENTREPRESENTINGADDRESSTYPE,
			PROP_TAG_SENDERADDRESSTYPE) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENTREPRESENTINGEMAILADDRESS,
			PROP_TAG_SENDEREMAILADDRESS) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENTREPRESENTINGSEARCHKEY,
			PROP_TAG_SENDERSEARCHKEY) ||
			FALSE == oxcmail_try_assign_propval(
			&pmsg->proplist, PROP_TAG_SENTREPRESENTINGENTRYID,
			PROP_TAG_SENDERENTRYID)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}	
	}
	if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_IMPORTANCE)) {
		propval.proptag = PROP_TAG_IMPORTANCE;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 1;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENSITIVITY)) {
		propval.proptag = PROP_TAG_SENSITIVITY;
		propval.pvalue = &tmp_int32;
		tmp_int32 = 0;
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (FALSE == oxcmail_parse_transport_message_header(
		phead, &pmsg->proplist)) {
		int_hash_free(phash);
		message_content_free(pmsg);
		return NULL;
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_CLIENTSUBMITTIME);
	if (NULL == pvalue) {
		propval.proptag = PROP_TAG_CLIENTSUBMITTIME;
		propval.pvalue = &mime_enum.nttime_stamp;
		mime_enum.nttime_stamp = rop_util_unix_to_nttime(time(NULL));
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	} else {
		mime_enum.nttime_stamp = *(uint64_t*)pvalue;
	}
	propval.proptag = PROP_TAG_CREATIONTIME;
	propval.pvalue = &mime_enum.nttime_stamp;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		int_hash_free(phash);
		message_content_free(pmsg);
		return NULL;
	}
	propval.proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval.pvalue = &mime_enum.nttime_stamp;
	if (FALSE == tpropval_array_set_propval(
		&pmsg->proplist, &propval)) {
		int_hash_free(phash);
		message_content_free(pmsg);
		return NULL;
	}
	if (0 == strcasecmp("application/ms-tnef",
		mime_get_content_type(phead))
#ifdef VERIFY_TNEF_CORRELATOR
		&& TRUE == mime_get_field(phead,
		"X-MS-TNEF-Correlator", tmp_buff, 256)
#endif
		&& (pmsg1 = oxcmail_parse_tnef(phead,
		alloc, get_propids))) {
#ifdef VERIFY_TNEF_CORRELATOR
		ptnef_key = tpropval_array_get_propval(
					&pmsg1->proplist,
					PROP_TAG_TNEFCORRELATIONKEY);
		if (NULL == ptnef_key || 0 != strncmp(
			ptnef_key->pb, tmp_buff, ptnef_key->cb)) {
			message_content_free(pmsg1);
		} else {
#endif
			if (FALSE == oxcmail_fetch_propname(
				pmsg, phash, alloc, get_propids)) {
				int_hash_free(phash);
				message_content_free(pmsg);
				message_content_free(pmsg1);
				return NULL;
			}
			int_hash_free(phash);
			if (FALSE == oxcmail_copy_message_proplist(
				pmsg, pmsg1)) {
				message_content_free(pmsg);
				message_content_free(pmsg1);
				return NULL;
			}
			prcpts = pmsg1->children.prcpts;
			pmsg1->children.prcpts =
				pmsg->children.prcpts;
			pmsg->children.prcpts = prcpts;
			message_content_free(pmsg);
			if (TRUE == field_param.b_flag_del) {
				oxcmail_remove_flag_propties(
				pmsg1, get_propids);
			}
			return pmsg1;
#ifdef VERIFY_TNEF_CORRELATOR
		}
#endif
	}
	if (0 == strcasecmp("multipart/report",
		mime_get_content_type(phead)) &&
		TRUE == oxcmail_get_content_param(
		phead, "report-type", tmp_buff, 128) &&
		0 == strcasecmp("delivery-status", tmp_buff)) {
		mime_enum.preport = oxcmail_parse_dsn(pmail, pmsg);
	}
	if ((0 == strcasecmp("multipart/report",
		mime_get_content_type(phead)) &&
		TRUE == oxcmail_get_content_param(
		phead, "report-type", tmp_buff, 128) &&
		0 == strcasecmp("disposition-notification", tmp_buff)) ||
		0 == strcasecmp("message/disposition-notification",
		mime_get_content_type(phead))) {
		mime_enum.preport = oxcmail_parse_mdn(pmail, pmsg);
	}		
	if (0 == strcasecmp("multipart/mixed",
		mime_get_content_type(phead))) {
		if (2 == mime_get_children_num(phead) &&
			(pmime = mime_get_child(phead)) &&
			(pmime1 = mime_get_slibling(pmime)) &&
			0 == strcasecmp("text/plain",
			mime_get_content_type(pmime)) &&
			0 == strcasecmp("application/ms-tnef",
			mime_get_content_type(pmime1))
#ifdef VERIFY_TNEF_CORRELATOR
			&& TRUE == mime_get_field(phead,
			"X-MS-TNEF-Correlator", tmp_buff, 256)
#endif
			&& (pmsg1 = oxcmail_parse_tnef(pmime1,
			alloc, get_propids))) {
#ifdef VERIFY_TNEF_CORRELATOR
			ptnef_key = tpropval_array_get_propval(
						&pmsg1->proplist,
						PROP_TAG_TNEFCORRELATIONKEY);
			if (NULL == ptnef_key || 0 != strncmp(
				ptnef_key->pb, tmp_buff, ptnef_key->cb)) {
				message_content_free(pmsg1);
			} else {
#endif
				if (FALSE == oxcmail_parse_message_body(
					default_charset, pmime, &pmsg->proplist)
					|| FALSE == oxcmail_fetch_propname(
					pmsg, phash, alloc, get_propids)) {
					int_hash_free(phash);
					message_content_free(pmsg);
					message_content_free(pmsg1);
					return NULL;
				}
				int_hash_free(phash);
				if (FALSE == oxcmail_copy_message_proplist(
					pmsg, pmsg1)) {
					message_content_free(pmsg);
					message_content_free(pmsg1);
					return NULL;
				}
				prcpts = pmsg1->children.prcpts;
				pmsg1->children.prcpts =
					pmsg->children.prcpts;
				pmsg->children.prcpts = prcpts;
				message_content_free(pmsg);
				if (TRUE == field_param.b_flag_del) {
					oxcmail_remove_flag_propties(
					pmsg1, get_propids);
				}
				return pmsg1;
#ifdef VERIFY_TNEF_CORRELATOR
			}
#endif
		}
	} else if (0 == strcasecmp("multipart/signed",
		mime_get_content_type(phead))) {
		propval.proptag = PROP_TAG_MESSAGECLASS;
		propval.pvalue = "IPM.Note.SMIME.MultipartSigned";
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
		b_smime = TRUE;
	} else if (0 == strcasecmp("application/pkcs7-mime",
		mime_get_content_type(phead)) ||
		0 == strcasecmp("application/x-pkcs7-mime",
		mime_get_content_type(phead))) {
		propval.proptag = PROP_TAG_MESSAGECLASS;
		propval.pvalue = "IPM.Note.SMIME";
		if (FALSE == tpropval_array_set_propval(
			&pmsg->proplist, &propval)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
		if (FALSE == oxcmail_parse_encrypted(phead,
			&field_param.last_propid, phash, pmsg)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
		b_smime = TRUE;
	}
	mime_enum.b_result = TRUE;
	mime_enum.attach_id = 0;
	mime_enum.charset = default_charset;
	mime_enum.str_zone = str_zone;
	mime_enum.get_propids = get_propids;
	mime_enum.alloc = alloc;
	mime_enum.pmime_pool = pmail->pmime_pool;
	mime_enum.pmsg = pmsg;
	mime_enum.phash = phash;
	pmime = phead;
	for (i=0; i<MAXIMUM_SEARCHING_DEPTH; i++) {
		pmime1 = mime_get_child(pmime);
		if (NULL == pmime1) {
			break;
		}
		pmime = pmime1;
	}
	b_alternative = FALSE;
	pmime1 = mime_get_parent(pmime);
	if (NULL != pmime1 && 0 == strcasecmp(
		"multipart/alternative",
		mime_get_content_type(pmime1))) {
		b_alternative = TRUE;
	}
	do {
		if (0 == strcasecmp("text/plain",
			mime_get_content_type(pmime))) {
			if (NULL == mime_enum.pplain) {
				mime_enum.pplain = pmime;
			}
		}
		if (0 == strcasecmp("text/html",
			mime_get_content_type(pmime))) {
			if (NULL == mime_enum.phtml) {
				mime_enum.phtml = pmime;
			}
		}
		if (0 == strcasecmp("text/enriched",
			mime_get_content_type(pmime))) {
			if (NULL == mime_enum.penriched) {
				mime_enum.penriched = pmime;
			}
		}
		if (0 == strcasecmp("text/calendar",
			mime_get_content_type(pmime))) {
			if (NULL == mime_enum.pcalendar) {
				mime_enum.pcalendar = pmime;
			}
		}
		if (TRUE == b_alternative &&
			MULTIPLE_MIME == mime_get_type(pmime)) {
			pmime1 = mime_get_child(pmime);
			while (NULL != pmime1) {
				if (0 == strcasecmp("text/plain",
					mime_get_content_type(pmime1))) {
					if (NULL == mime_enum.pplain) {
						mime_enum.pplain = pmime1;
					}
				}
				if (0 == strcasecmp("text/html",
					mime_get_content_type(pmime1))) {
					if (NULL == mime_enum.phtml) {
						mime_enum.phtml = pmime1;
					}
				}
				if (0 == strcasecmp("text/enriched",
					mime_get_content_type(pmime1))) {
					if (NULL == mime_enum.penriched) {
						mime_enum.penriched = pmime1;
					}
				}
				if (0 == strcasecmp("text/calendar",
					mime_get_content_type(pmime1))) {
					if (NULL == mime_enum.pcalendar) {
						mime_enum.pcalendar = pmime1;
					}
				}
				pmime1 = mime_get_slibling(pmime1);
			}
		}
	} while (TRUE == b_alternative && NULL !=
		(pmime = mime_get_slibling(pmime)));
	
	if (NULL != mime_enum.pplain) {
		if (FALSE == oxcmail_parse_message_body(default_charset,
			mime_enum.pplain, &pmsg->proplist)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (NULL != mime_enum.phtml) {
		if (FALSE == oxcmail_parse_message_body(default_charset,
			mime_enum.phtml, &pmsg->proplist)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	} else if (NULL != mime_enum.penriched) {
		if (FALSE == oxcmail_parse_message_body(default_charset,
			mime_enum.penriched, &pmsg->proplist)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	}
	if (NULL != mime_enum.pcalendar) {
		content_len = mime_get_length(mime_enum.pcalendar);
		pcontent = malloc(3*content_len + 2);
		if (NULL == pcontent) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
		if (FALSE == mime_read_content(mime_enum.pcalendar,
			pcontent, &content_len)) {
			free(pcontent);
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
		pcontent[content_len] = '\0';
		if (FALSE == oxcmail_get_content_param(
			mime_enum.pcalendar, "charset",
			mime_charset, 32)) {
			if (FALSE == utf8_check(pcontent)) {
				strcpy(mime_charset, default_charset);
			} else {
				strcpy(mime_charset, "utf-8");
			}
		}
		if (FALSE == string_to_utf8(
			mime_charset, pcontent,
			pcontent + content_len + 1)) {
			mime_enum.pcalendar = NULL;
		} else {
			if (FALSE == utf8_check(pcontent + content_len + 1)) {
				utf8_filter(pcontent + content_len + 1);
			}
			ical_init(&ical);
			if (FALSE == ical_retrieve(&ical,
				pcontent + content_len + 1) || 
				NULL == (pmsg1 = oxcical_import(
				str_zone, &ical, alloc, get_propids,
				oxcmail_username_to_entryid))) {
				mime_enum.pcalendar = NULL;
			}
			ical_free(&ical);
		}
		free(pcontent);
	}
	
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		int_hash_free(phash);
		message_content_free(pmsg);
		if (NULL != mime_enum.pcalendar) {
			message_content_free(pmsg1);
		}
		return NULL;
	}
	message_content_set_attachments_internal(pmsg, pattachments);
	if (TRUE == b_smime) {
		if (FALSE == oxcmail_parse_smime_message(pmail, pmsg)) {
			int_hash_free(phash);
			message_content_free(pmsg);
			return NULL;
		}
	} else {
		mime_enum.last_propid = field_param.last_propid;
		mail_enum_mime(pmail, oxcmail_enum_attachment, &mime_enum);
		if (FALSE == mime_enum.b_result) {
			int_hash_free(phash);
			message_content_free(pmsg);
			if (NULL != mime_enum.pcalendar) {
				message_content_free(pmsg1);
			}
			return NULL;
		}
	}
	if (FALSE == oxcmail_fetch_propname(
		pmsg, phash, alloc, get_propids)) {
		int_hash_free(phash);
		message_content_free(pmsg);
		if (NULL != mime_enum.pcalendar) {
			message_content_free(pmsg1);
		}
		return NULL;
	}
	int_hash_free(phash);
	if (NULL != mime_enum.pcalendar) {
		if (NULL == tpropval_array_get_propval(
			&pmsg1->proplist, PROP_TAG_MESSAGECLASS)) {
			/* multiple calendar objects in attachment list */
			if (NULL != pmsg1->children.pattachments) {
				if (FALSE == oxcmail_merge_message_attachments(
					pmsg1, pmsg)) {
					message_content_free(pmsg);
					message_content_free(pmsg1);
					return NULL;
				}
			}
			message_content_free(pmsg1);
		} else {
			if (FALSE == oxcmail_copy_message_proplist(pmsg, pmsg1) ||
				FALSE == oxcmail_merge_message_attachments(pmsg, pmsg1)) {
				message_content_free(pmsg);
				message_content_free(pmsg1);
				return NULL;
			}
			message_content_free(pmsg);
			pmsg = pmsg1;
			/* calendar message object can not be displayed
				correctly without PidTagRtfCompressed convert
				PidTagHtml to PidTagRtfCompressed */
			phtml_bin = tpropval_array_get_propval(
				&pmsg->proplist, PROP_TAG_HTML);
			if (NULL != phtml_bin) {
				pvalue = tpropval_array_get_propval(
					&pmsg->proplist, PROP_TAG_INTERNETCODEPAGE);
				if (NULL == pvalue) {
					tmp_int32 = 65001;
				} else {
					tmp_int32 = *(uint32_t*)pvalue;
				}
				content_len = 2*phtml_bin->cb + 4096;
				pvalue = alloc(content_len);
				if (NULL == pvalue) {
					message_content_free(pmsg);
					return NULL;
				}
				if (TRUE == html_to_rtf(
					phtml_bin->pb, phtml_bin->cb,
					tmp_int32, pvalue, &content_len)) {
					propval.proptag = PROP_TAG_RTFCOMPRESSED;
					propval.pvalue = rtfcp_compress(
								pvalue, content_len);
					if (NULL != propval.pvalue) {
						tpropval_array_set_propval(
							&pmsg->proplist, &propval);
						rop_util_free_binary(propval.pvalue);
					}
				}
			}
		}
	}
	if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_BODY) &&
		NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_BODY_STRING8)) {
		phtml_bin = tpropval_array_get_propval(
				&pmsg->proplist, PROP_TAG_HTML);
		if (NULL != phtml_bin) {
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist,  PROP_TAG_INTERNETCODEPAGE);
			if (NULL == pvalue) {
				tmp_int32 = 65001;
			} else {
				tmp_int32 = *(uint32_t*)pvalue;
			}
			pvalue = alloc(3*phtml_bin->cb + 3);
			if (NULL == pvalue) {
				message_content_free(pmsg);
				return NULL;
			}
			propval.proptag = PROP_TAG_BODY;
			propval.pvalue = pvalue + phtml_bin->cb + 1;
			memcpy(pvalue, phtml_bin->pb, phtml_bin->cb);
			((char*)pvalue)[phtml_bin->cb] = '\0';
			html_to_plain(pvalue, phtml_bin->cb + 1);
			encoding = oxcmail_cpid_to_charset(tmp_int32);
			if (NULL == encoding) {
				encoding = "windows-1252";
			}
			if (TRUE == string_to_utf8(encoding, pvalue,
				propval.pvalue) && TRUE == utf8_check(
				propval.pvalue)) {
				tpropval_array_set_propval(
					&pmsg->proplist, &propval);
			}
		}
	}
	if (NULL == tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_HTML)) {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_BODY);
		if (NULL != pvalue) {
			phtml_bin = alloc(sizeof(BINARY));
			if (NULL == phtml_bin) {
				message_content_free(pmsg);
				return NULL;
			}
			tmp_int32 = strlen(pvalue) + 1024;
			phtml_bin->pb = alloc(tmp_int32);
			if (NULL == phtml_bin->pb) {
				message_content_free(pmsg);
				return NULL;
			}
			strcpy(phtml_bin->pb, pvalue);
			phtml_bin->cb = plain_to_html(phtml_bin->pb, tmp_int32);
			propval.proptag = PROP_TAG_HTML;
			propval.pvalue = phtml_bin;
			tpropval_array_set_propval(
				&pmsg->proplist, &propval);
			propval.proptag = PROP_TAG_INTERNETCODEPAGE;
			propval.pvalue = &tmp_int32;
			tmp_int32 = 65001;
			tpropval_array_set_propval(
				&pmsg->proplist, &propval);
		}
	}
	if (NULL != pmsg->children.pattachments &&
		0 != pmsg->children.pattachments->count) {
		pattachments = pmsg->children.pattachments;
		for (i=0; i<pattachments->count; i++) {
			if (NULL != tpropval_array_get_propval(
				&pattachments->pplist[i]->proplist,
				PROP_TAG_ATTACHCONTENTID)) {
				continue;	
			}
			if (NULL != tpropval_array_get_propval(
				&pattachments->pplist[i]->proplist,
				PROP_TAG_ATTACHCONTENTID_STRING8)) {
				continue;	
			}
			pvalue = tpropval_array_get_propval(
				&pattachments->pplist[i]->proplist,
				PROP_TAG_ATTACHMENTHIDDEN);
			if (NULL != pvalue && 0 != (uint8_t*)pvalue) {
				continue;
			}
			break;
		}
		if (i >= pattachments->count) {
			/* PidLidSmartNoAttach */
			propname.kind = KIND_LID;
			rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
			propname.plid = &tmp_int32;
			tmp_int32 = 0x00008514;
			propnames.count = 1;
			propnames.ppropname = &propname;
			if (FALSE == get_propids(&propnames, &propids)) {
				message_content_free(pmsg);
				return FALSE;
			}
			propval.proptag = propids.ppropid[0];
			propval.proptag <<= 16;
			propval.proptag |= PROPVAL_TYPE_BYTE;
			propval.pvalue = &tmp_byte;
			tmp_byte = 1;
			if (FALSE == tpropval_array_set_propval(
				&pmsg->proplist, &propval)) {
				message_content_free(pmsg);
				return FALSE;	
			}
		}
	}
	if (TRUE == field_param.b_flag_del) {
		oxcmail_remove_flag_propties(pmsg, get_propids);
	}
	return pmsg;
}

static int oxcmail_encode_mime_string(const char *charset,
	const char *pstring, char *pout_string, int max_length)
{
	int offset;
	int string_len;
	size_t base64_len;
	char tmp_buff[MIME_FIELD_LEN];
	
	
	if (FALSE == oxcmail_check_ascii(pstring) ||
		TRUE == oxcmail_check_crlf(pstring)) {
		if (TRUE == string_from_utf8(
			charset, pstring, tmp_buff)) {
			string_len = strlen(tmp_buff);
			offset = snprintf(pout_string,
				max_length, "=?%s?B?", charset);
			if (0 != encode64(tmp_buff, string_len,
				pout_string + offset, max_length - offset,
				&base64_len)) {
				return 0;
			}
		} else {
			string_len = strlen(pstring);
			offset = snprintf(pout_string,
				max_length, "=?utf-8?B?");
			if (0 != encode64(pstring, string_len,
				pout_string + offset, max_length - offset,
				&base64_len)) {
				return 0;
			}
		}
		offset += base64_len;
		if (offset + 3 >= max_length) {
			return 0;
		}
		memcpy(pout_string + offset, "?=", 3);
		return offset + 2;
	} else {
		string_len = strlen(pstring);
		if (string_len >= max_length) {
			return 0;
		}
		memcpy(pout_string, pstring, string_len + 1);
		return string_len;
	}
}

static BOOL oxcmail_get_smtp_address(TPROPVAL_ARRAY *pproplist,
	EXT_BUFFER_ALLOC alloc, uint32_t proptag1, uint32_t proptag2,
	uint32_t proptag3, uint32_t proptag4, char *username)
{
	void *pvalue;

	pvalue = tpropval_array_get_propval(pproplist, proptag1);
	if (NULL == pvalue) {
		pvalue = tpropval_array_get_propval(pproplist, proptag2);
		if (NULL == pvalue) {
FIND_ENTRYID:
			pvalue = tpropval_array_get_propval(pproplist, proptag4);
			if (NULL == pvalue) {
				return FALSE;
			}
			return oxcmail_entryid_to_username(pvalue, alloc, username);
		} else {
			if (0 == strcasecmp(pvalue, "SMTP")) {
				pvalue = tpropval_array_get_propval(pproplist, proptag3);
			} else if (0 == strcasecmp(pvalue, "EX")) {
				pvalue = tpropval_array_get_propval(pproplist, proptag3);
				if (NULL != pvalue) {
					if (TRUE == oxcmail_essdn_to_username(pvalue, username)) {
						return TRUE;	
					}
				}
			} else {
				pvalue = NULL;
			}
			if (NULL == pvalue) {
				goto FIND_ENTRYID;
			}
		}
	}
	strncpy(username, pvalue, 256);
	return TRUE;
}

static BOOL oxcmail_export_addresses(
	const char *charset, TARRAY_SET *prcpts,
	uint32_t rcpt_type, EXT_BUFFER_ALLOC alloc,
	char *field)
{
	int i;
	int offset;
	int tmp_len;
	void *pvalue;
	char username[256];
	char *pdisplay_name;
	TPROPVAL_ARRAY *prcpt;
	
	offset = 0;
	for (i=0; i<prcpts->count; i++) {
		prcpt = prcpts->pparray[i];
		pvalue = tpropval_array_get_propval(
			prcpt, PROP_TAG_RECIPIENTTYPE);
		if (NULL == pvalue || rcpt_type != *(uint32_t*)pvalue) {
			continue;
		}
		if (0 != offset) {
			memcpy(field + offset, ",\r\n\t", 4);
			offset += 4;
			if (offset >= MIME_FIELD_LEN) {
				return FALSE;
			}
		}
		pdisplay_name = tpropval_array_get_propval(
						prcpt, PROP_TAG_DISPLAYNAME);
		if (NULL != pdisplay_name) {
			field[offset] = '"';
			offset ++;
			if (offset >= MIME_FIELD_LEN) {
				return FALSE;
			}
			tmp_len = oxcmail_encode_mime_string(
				charset, pdisplay_name, field + offset,
				MIME_FIELD_LEN - offset);
			if (0 == tmp_len) {
				return FALSE;
			}
			offset += tmp_len;
			field[offset] = '"';
			offset ++;
			if (offset >= MIME_FIELD_LEN) {
				return FALSE;
			}
		}
		if (TRUE == oxcmail_get_smtp_address(prcpt, alloc,
			PROP_TAG_SMTPADDRESS, PROP_TAG_ADDRESSTYPE,
			PROP_TAG_EMAILADDRESS, PROP_TAG_ENTRYID, username)) {
			if (NULL != pdisplay_name) {
				offset += snprintf(field + offset,
						MIME_FIELD_LEN - offset,
						" <%s>", username);
			} else {
				offset += snprintf(field,
					MIME_FIELD_LEN - offset,
					"<%s>", username);
			}
		}
	}
	if (0 == offset || offset >= MIME_FIELD_LEN) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_export_reply_to(MESSAGE_CONTENT *pmsg,
	const char *charset, EXT_BUFFER_ALLOC alloc, char *field)
{
	int i;
	int offset;
	int tmp_len;
	BINARY *pbin;
	EXT_PULL ext_pull;
	STRING_ARRAY *pstrings;
	ONEOFF_ARRAY address_array;
	
	pbin = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_REPLYRECIPIENTENTRIES);
	if (NULL == pbin) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb, pbin->cb, alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_oneoff_array(
		&ext_pull, &address_array)) {
		return FALSE;
	}
	pstrings = tpropval_array_get_propval(&pmsg->proplist,
							PROP_TAG_REPLYRECIPIENTNAMES);
	if (NULL != pstrings && pstrings->count !=
		address_array.count) {
		pstrings = NULL;
	}
	offset = 0;
	for (i=0; i<address_array.count; i++) {
		if (0 != offset) {
			memcpy(field + offset, ", ", 2);
			offset += 2;
			if (offset >= MIME_FIELD_LEN) {
				return FALSE;
			}
		}
		if (NULL != pstrings) {
			field[offset] = '"';
			offset ++;
			if (offset >= MIME_FIELD_LEN) {
				return FALSE;
			}
			tmp_len = oxcmail_encode_mime_string(charset,
					pstrings->ppstr[i], field + offset,
					MIME_FIELD_LEN - offset);
			if (0 == tmp_len) {
				return FALSE;
			}
			offset += tmp_len;
			field[offset] = '"';
			offset ++;
			if (offset >= MIME_FIELD_LEN) {
				return FALSE;
			}
		}
		if (0 != strcasecmp("SMTP", 
			address_array.pentry_id[i].paddress_type)) {
			return FALSE;
		}
		if (NULL != pstrings) {
			offset += snprintf(field, MIME_FIELD_LEN - offset,
				" <%s>", address_array.pentry_id[i].pmail_address);
		} else {
			offset += snprintf(field, MIME_FIELD_LEN - offset,
				"<%s>", address_array.pentry_id[i].pmail_address);
		}
	}
	if (0 == offset || offset >= MIME_FIELD_LEN) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_export_address(MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, uint32_t proptag1, uint32_t proptag2,
	uint32_t proptag3, uint32_t proptag4, uint32_t proptag5,
	const char *charset, char *field)
{
	int offset;
	char *pvalue;
	char address[256];
	char tmp_buff[512];
	
	offset = 0;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag1);
	if (NULL != pvalue) {
		if (strlen(pvalue) >= 256) {
			goto EXPORT_ADDRESS;
		}
		field[offset] = '"';
		offset ++;
		offset += oxcmail_encode_mime_string(charset,
				pvalue, field + offset, 1024 - offset);
		field[offset] = '"';
		offset ++;
		field[offset] = '\0';
	}
EXPORT_ADDRESS:
	if (TRUE == oxcmail_get_smtp_address(&pmsg->proplist, alloc,
		proptag4, proptag2, proptag3, proptag5, address)) {
		if (0 == offset) {
			offset = snprintf(field, 1024, "<%s>", address);
		} else {
			offset += snprintf(field + offset,
				1024 - offset, " <%s>", address);
		}
	}
	if (0 == offset) {
		return FALSE;
	}
	return TRUE;
}

static BOOL oxcmail_export_content_class(
	const char *pmessage_class, char *field)
{
	if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Fax")) {
		strcpy(field, "fax");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Fax.CA")) {
		strcpy(field, "fax-ca");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Missed.Voice")) {
		strcpy(field, "missedcall");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Conversation.Voice")) {
		strcpy(field, "voice-uc");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Voicemail.UM.CA")) {
		strcpy(field, "voice-ca");
	} else if (0 == strcasecmp(pmessage_class,
		"IPM.Note.Microsoft.Voicemail.UM")) {
		strcpy(field, "voice");
	} else if (0 == strncasecmp(pmessage_class,
		"IPM.Note.Custom.", 16)) {
		snprintf(field, 1024,
			"urn:content-class:custom.%s",
			pmessage_class + 16);
	} else {
		return FALSE;
	}
	return TRUE;
}

static int oxcmail_get_mail_type(const char *pmessage_class)
{
	int tmp_len;
	
	tmp_len = strlen(pmessage_class);
	if (0 == strcasecmp( pmessage_class,
		"IPM.Note.SMIME.MultipartSigned")) {
		return MAIL_TYPE_SIGNED;
	}
	if (0 == strncasecmp(pmessage_class, "IPM.InfoPathForm.",
		17) && 0 == strcasecmp(pmessage_class + tmp_len - 22,
		".SMIME.MultipartSigned")) {
		return MAIL_TYPE_SIGNED;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Note.SMIME")) {
		return MAIL_TYPE_ENCRYPTED;
	}
	if (0 == strncasecmp(pmessage_class, "IPM.InfoPathForm.",
		17) && 0 == strcasecmp(pmessage_class + tmp_len - 6,
		".SMIME")) {
		return MAIL_TYPE_ENCRYPTED;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Note") ||
		0 == strncasecmp(pmessage_class, "IPM.Note.", 9) ||
		0 == strncasecmp(pmessage_class, "IPM.InfoPathForm.", 17)) {
		return MAIL_TYPE_NORMAL;
	}
	if (0 == strncasecmp(pmessage_class, "REPORT.", 7) &&
		(0 == strcasecmp(pmessage_class + tmp_len - 3, ".DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 12, ".Expanded.DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 11, ".Relayed.DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 11, ".Delayed.DR") ||
		0 == strcasecmp(pmessage_class + tmp_len - 4, ".NDR"))) {
		return MAIL_TYPE_DSN;
	}
	if (0 == strncasecmp(pmessage_class, "REPORT.", 7) &&
		(0 == strcasecmp(pmessage_class + tmp_len - 6, ".IPNRN") ||
		0 == strcasecmp(pmessage_class + tmp_len - 7, ".IPNNRN"))) {
		return MAIL_TYPE_MDN;
	}
	if (0 == strcasecmp(pmessage_class, "IPM.Appointment") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Request") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Pos") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Tent") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Resp.Neg") ||
		0 == strcasecmp(pmessage_class, "IPM.Schedule.Meeting.Canceled")) {
		return MAIL_TYPE_CALENDAR;
	}
	return MAIL_TYPE_TNEF;
}

static BOOL oxcmail_load_mime_skeleton(
	MESSAGE_CONTENT *pmsg, const char *pcharset,
	BOOL b_tnef, int body_type, MIME_SKELETON *pskeleton)
{
	int i;
	char *pbuff;
	BINARY *prtf;
	size_t rtf_len;
	size_t tmp_len;
	uint32_t *pvalue;
	ATTACHMENT_CONTENT *pattachment;
	memset(pskeleton, 0, sizeof(MIME_SKELETON));
	pskeleton->charset = pcharset;
	pskeleton->pmessage_class = tpropval_array_get_propval(
		(TPROPVAL_ARRAY*)&pmsg->proplist, PROP_TAG_MESSAGECLASS);
	if (NULL == pskeleton->pmessage_class) {
		pskeleton->pmessage_class = tpropval_array_get_propval(
							(TPROPVAL_ARRAY*)&pmsg->proplist,
							PROP_TAG_MESSAGECLASS_STRING8);
	}
	if (NULL == pskeleton->pmessage_class) {
		debug_info("[oxcmail]: missing message class for exporting");
		return FALSE;
	}
	pskeleton->mail_type = oxcmail_get_mail_type(
						pskeleton->pmessage_class);
	if (MAIL_TYPE_SIGNED == pskeleton->mail_type ||
		MAIL_TYPE_ENCRYPTED == pskeleton->mail_type) {
		if (TRUE == b_tnef) {
			b_tnef = FALSE;
		}
	}
	if (TRUE == b_tnef) {
		pskeleton->mail_type = MAIL_TYPE_TNEF;
	}
	pskeleton->body_type = body_type;
	pskeleton->pplain = tpropval_array_get_propval(
					&pmsg->proplist, PROP_TAG_BODY);
	if (MAIL_TYPE_ENCRYPTED == pskeleton->mail_type ||
		MAIL_TYPE_ENCRYPTED == pskeleton->mail_type ||
		MAIL_TYPE_TNEF == pskeleton->mail_type) {
		/* do nothing */
	} else {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_NATIVEBODY);
		if (NULL != pvalue && NATIVE_BODY_RTF == *pvalue &&
			(NULL == (pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_RTFINSYNC)) || 0 == *pvalue)) {
FIND_RTF:
			prtf = tpropval_array_get_propval(&pmsg->proplist,
									PROP_TAG_RTFCOMPRESSED);
			if (NULL != prtf) {
				tmp_len = 8*prtf->cb + 1024*1024;
				rtf_len = tmp_len;
				pbuff = malloc(rtf_len);
				if (NULL == pbuff) {
					return FALSE;
				}
				if (TRUE == rtfcp_uncompress(prtf, pbuff, &rtf_len)) {
					pskeleton->pattachments = attachment_list_init();
					if (NULL == pskeleton->pattachments) {
						free(pbuff);
						return FALSE;
					}
					tmp_len -= rtf_len;
					if (TRUE == rtf_to_html(pbuff, rtf_len,
						pcharset, pbuff + rtf_len, &tmp_len,
						pskeleton->pattachments)) {
						pskeleton->rtf_bin.pb = malloc(tmp_len);
						if (NULL == pskeleton->rtf_bin.pb) {
							free(pbuff);
							return FALSE;
						}
						memcpy(pskeleton->rtf_bin.pb,
							pbuff + rtf_len, tmp_len);
						free(pbuff);
						pskeleton->rtf_bin.cb = tmp_len;
						pskeleton->phtml = &pskeleton->rtf_bin;
						if (0 == pskeleton->pattachments->count) {
							attachment_list_free(pskeleton->pattachments);
							pskeleton->pattachments = NULL;
						} else {
							pskeleton->b_inline = TRUE;
						}
					} else {
						attachment_list_free(pskeleton->pattachments);
						pskeleton->pattachments = NULL;
						free(pbuff);
						pskeleton->mail_type = MAIL_TYPE_TNEF;
					}
				} else {
					free(pbuff);
					pskeleton->mail_type = MAIL_TYPE_TNEF;
				}
			}
		} else {
			pskeleton->phtml = tpropval_array_get_propval(
						&pmsg->proplist, PROP_TAG_HTML);
			if (NULL == pskeleton->phtml) {
				goto FIND_RTF;
			}
		}
	}
	if (NULL == pmsg->children.pattachments) {
		return TRUE;
	}
	for (i=0; i<pmsg->children.pattachments->count; i++) {
		pattachment = pmsg->children.pattachments->pplist[i];
		if (NULL != pattachment->pembedded) {
			pskeleton->b_attachment = TRUE;
			continue;
		}
		pvalue = tpropval_array_get_propval(
					&pattachment->proplist,
					PROP_TAG_ATTACHFLAGS);
		if (NULL != pvalue && (*pvalue & ATTACH_FLAG_RENDEREDINBODY)) {
			if (NULL != tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_ATTACHCONTENTID) ||
				NULL != tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_ATTACHCONTENTLOCATION)) {
				pskeleton->b_inline = TRUE;
				continue;
			}
		}
		pskeleton->b_attachment = TRUE;
	}
	return TRUE;
}

static void oxcmail_free_mime_skeleton(MIME_SKELETON *pskeleton)
{
	if (NULL != pskeleton->pattachments) {
		attachment_list_free(pskeleton->pattachments);
	}
	if (NULL != pskeleton->rtf_bin.pb) {
		free(pskeleton->rtf_bin.pb);
	}
}

static BOOL oxcmail_export_mail_head(MESSAGE_CONTENT *pmsg,
	MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, GET_PROPNAME get_propname,
	MIME *phead)
{
	int i;
	GUID guid;
	int tmp_len;
	uint32_t lid;
	void *pvalue;
	void *pvalue1;
	time_t tmp_time;
	uint16_t propid;
	uint32_t proptag;
	size_t base64_len;
	struct tm time_buff;
	PROPID_ARRAY propids;
	PROPERTY_NAME propname;
	PROPERTY_NAME *ppropname;
	PROPNAME_ARRAY propnames;
	char tmp_buff[MIME_FIELD_LEN];
	char tmp_field[MIME_FIELD_LEN];
	
	
	if (FALSE == mime_set_field(phead, "MIME-Version", "1.0")) {
		return FALSE;
	}
	
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
							PROP_TAG_SENDERSMTPADDRESS);
	pvalue1 = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
	if (NULL != pvalue && NULL != pvalue1) {
		if (0 != strcasecmp(pvalue, pvalue1)) {
			oxcmail_export_address(pmsg, alloc,
				PROP_TAG_SENDERNAME,
				PROP_TAG_SENDERADDRESSTYPE,
				PROP_TAG_SENDEREMAILADDRESS,
				PROP_TAG_SENDERSMTPADDRESS,
				PROP_TAG_SENDERENTRYID,
				pskeleton->charset, tmp_field);
			if (FALSE == mime_set_field(phead,
				"Sender", tmp_field)) {
				return FALSE;
			}
		}
	} else {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
								PROP_TAG_SENDERADDRESSTYPE);
		pvalue1 = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_SENTREPRESENTINGADDRESSTYPE);
		if (NULL != pvalue && NULL != pvalue1 &&
			0 == strcasecmp(pvalue, "SMTP") &&
			0 == strcasecmp(pvalue1, "SMTP")) {
			pvalue = tpropval_array_get_propval(&pmsg->proplist,
									PROP_TAG_SENDEREMAILADDRESS);
			pvalue1 = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
			if (NULL != pvalue && NULL != pvalue1) {
				if (0 != strcasecmp(pvalue, pvalue1)) {
					oxcmail_export_address(pmsg, alloc,
						PROP_TAG_SENDERNAME,
						PROP_TAG_SENDERADDRESSTYPE,
						PROP_TAG_SENDEREMAILADDRESS,
						PROP_TAG_SENDERSMTPADDRESS,
						PROP_TAG_SENDERENTRYID,
						pskeleton->charset, tmp_field);
					if (FALSE == mime_set_field(phead,
						"Sender", tmp_field)) {
						return FALSE;
					}
				}
			}
		}
	}
	if (TRUE == oxcmail_export_address(pmsg, alloc,
		PROP_TAG_SENTREPRESENTINGNAME,
		PROP_TAG_SENTREPRESENTINGADDRESSTYPE,
		PROP_TAG_SENTREPRESENTINGEMAILADDRESS,
		PROP_TAG_SENTREPRESENTINGSMTPADDRESS,
		PROP_TAG_SENTREPRESENTINGENTRYID,
		pskeleton->charset, tmp_field)) {
		if (FALSE == mime_set_field(phead,
			"From", tmp_field)) {
			return FALSE;
		}
	} else {
		if (TRUE == oxcmail_export_address(pmsg, alloc,
			PROP_TAG_SENDERNAME,
			PROP_TAG_SENDERADDRESSTYPE,
			PROP_TAG_SENDEREMAILADDRESS,
			PROP_TAG_SENDERSMTPADDRESS,
			PROP_TAG_SENDERENTRYID,
			pskeleton->charset, tmp_field)) {
			if (FALSE == mime_set_field(phead,
				"Sender", tmp_field)) {
				return FALSE;
			}	
		}
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
			PROP_TAG_ORIGINATORDELIVERYREPORTREQUESTED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		if (TRUE == oxcmail_export_address(pmsg, alloc,
			PROP_TAG_READRECEIPTNAME,
			PROP_TAG_READRECEIPTADDRESSTYPE,
			PROP_TAG_READRECEIPTEMAILADDRESS,
			PROP_TAG_READRECEIPTSMTPADDRESS,
			PROP_TAG_READRECEIPTENTRYID,
			pskeleton->charset, tmp_field) ||
			TRUE == oxcmail_export_address(pmsg, alloc,
			PROP_TAG_SENDERNAME,
			PROP_TAG_SENDERADDRESSTYPE,
			PROP_TAG_SENDEREMAILADDRESS,
			PROP_TAG_SENDERSMTPADDRESS,
			PROP_TAG_SENDERENTRYID,
			pskeleton->charset, tmp_field) ||
			TRUE == oxcmail_export_address(pmsg, alloc,
			PROP_TAG_SENTREPRESENTINGNAME,
			PROP_TAG_SENTREPRESENTINGADDRESSTYPE,
			PROP_TAG_SENTREPRESENTINGEMAILADDRESS,
			PROP_TAG_SENTREPRESENTINGSMTPADDRESS,
			PROP_TAG_SENTREPRESENTINGENTRYID,
			pskeleton->charset, tmp_field)) {
			if (FALSE == mime_set_field(phead,
				"Return-Receipt-To", tmp_field)) {
				return FALSE;
			}	
		}
	}
	
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_READRECEIPTREQUESTED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		if (TRUE == oxcmail_export_address(pmsg, alloc,
			PROP_TAG_READRECEIPTNAME,
			PROP_TAG_READRECEIPTADDRESSTYPE,
			PROP_TAG_READRECEIPTEMAILADDRESS,
			PROP_TAG_READRECEIPTSMTPADDRESS,
			PROP_TAG_READRECEIPTENTRYID,
			pskeleton->charset, tmp_field) ||
			TRUE == oxcmail_export_address(pmsg, alloc,
			PROP_TAG_SENTREPRESENTINGNAME,
			PROP_TAG_SENTREPRESENTINGADDRESSTYPE,
			PROP_TAG_SENTREPRESENTINGEMAILADDRESS,
			PROP_TAG_SENTREPRESENTINGSMTPADDRESS,
			PROP_TAG_SENTREPRESENTINGENTRYID,
			pskeleton->charset, tmp_field)) {
			if (FALSE == mime_set_field(phead,
				"Disposition-Notification-To",
				tmp_field)) {
				return FALSE;
			}
		}
	}
	
	if (TRUE == oxcmail_export_reply_to(pmsg,
		pskeleton->charset, alloc, tmp_field)) {
		if (FALSE == mime_set_field(phead,
			"Reply-To", tmp_field)) {
			return FALSE;
		}
	}
	
	if (NULL == pmsg->children.prcpts) {
		goto EXPORT_CONTENT_CLASS;
	}
	
	if (TRUE == oxcmail_export_addresses(
		pskeleton->charset, pmsg->children.prcpts,
		RECIPIENT_TYPE_TO, alloc, tmp_field)) {
		if (FALSE == mime_set_field(
			phead, "To", tmp_field)) {
			return FALSE;
		}
	}
	
	if (TRUE == oxcmail_export_addresses(
		pskeleton->charset, pmsg->children.prcpts,
		RECIPIENT_TYPE_CC, alloc, tmp_field)) {
		if (FALSE == mime_set_field(
			phead, "Cc", tmp_field)) {
			return FALSE;
		}
	}
	
	if (0 == strncasecmp(pskeleton->pmessage_class,
		"IPM.Schedule.Meeting.", 21) ||
		0 == strcasecmp(pskeleton->pmessage_class,
		"IPM.Task") || 0 == strncasecmp(
		pskeleton->pmessage_class, "IPM.Task.", 9)) {
		if (TRUE == oxcmail_export_addresses(
			pskeleton->charset, pmsg->children.prcpts,
			RECIPIENT_TYPE_BCC, alloc, tmp_field)) {
			if (FALSE == mime_set_field(
				phead, "Bcc", tmp_field)) {
				return FALSE;
			}
		}
	}
	
EXPORT_CONTENT_CLASS:
	if (TRUE == oxcmail_export_content_class(
		pskeleton->pmessage_class, tmp_field)) {
		if (FALSE == mime_set_field(phead,
			"Content-Class", tmp_field)) {
			return FALSE;
		}
	} else if (0 == strncasecmp(
		pskeleton->pmessage_class,
		"IPM.InfoPathForm.", 17)) {
		/* PidLidInfoPathFromName */
		propname.kind = KIND_LID;
		rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
		propname.plid = &lid;
		lid = 0x000085B1;
		propnames.count = 1;
		propnames.ppropname = &propname;
		if (FALSE == get_propids(&propnames, &propids)) {
			return FALSE;
		}
		propid = propids.ppropid[0];
		proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_WSTRING;
		pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
		if (NULL != pvalue) {
			pvalue1 = strrchr(pvalue, '.');
			if (NULL != pvalue1) {
				pvalue = pvalue1 + 1;
			}
			snprintf(tmp_field, 1024, "InfoPathForm.%s", pvalue);
			if (FALSE == mime_set_field(phead,
				"Content-Class", tmp_field)) {
				return FALSE;
			}
		}
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_SENDERTELEPHONENUMBER);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-CallingTelephoneNumber", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_VOICEMESSAGEDURATION);
	if (NULL != pvalue) {
		sprintf(tmp_field, "%d", *(uint32_t*)pvalue);
		if (FALSE == mime_set_field(phead,
			"X-VoiceMessageDuration", tmp_field)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_VOICEMESSAGESENDERNAME);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-VoiceMessageSenderName", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
							PROP_TAG_FAXNUMBEROFPAGES);
	if (NULL != pvalue) {
		sprintf(tmp_field, "%u", *(uint32_t*)pvalue);
		if (FALSE == mime_set_field(phead,
			"X-FaxNumverOfPages", tmp_field)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
				PROP_TAG_VOICEMESSAGEATTACHMENTORDER);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-AttachmentOrder", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_CALLID);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-CallID", pvalue)) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_IMPORTANCE);
	if (NULL != pvalue) {
		switch (*(uint32_t*)pvalue) {
		case 0:
			if (FALSE == mime_set_field(phead,
				"Importance", "Low")) {
				return FALSE;
			}
			break;
		case 1:
			if (FALSE == mime_set_field(phead,
				"Importance", "Normal")) {
				return FALSE;
			}
			break;
		case 2:
			if (FALSE == mime_set_field(phead,
				"Importance", "High")) {
				return FALSE;
			}
			break;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENSITIVITY);
	if (NULL != pvalue) {
		switch (*(uint32_t*)pvalue) {
		case 0:
			if (FALSE == mime_set_field(phead,
				"Sensitivity", "Normal")) {
				return FALSE;
			}
			break;
		case 1:
			if (FALSE == mime_set_field(phead,
				"Sensitivity", "Personal")) {
				return FALSE;
			}
			break;
		case 2:
			if (FALSE == mime_set_field(phead,
				"Sensitivity", "Private")) {
				return FALSE;
			}
			break;
		case 3:
			if (FALSE == mime_set_field(
				phead, "Sensitivity",
				"Company-Confidential")) {
				return FALSE;
			}
			break;
		}
	}
	
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
							PROP_TAG_CLIENTSUBMITTIME);
	if (NULL == pvalue) {
		time(&tmp_time);
	} else {
		tmp_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
	}
	strftime(tmp_field, 128, "%a, %d %b %Y %H:%M:%S %z",
					localtime_r(&tmp_time, &time_buff));
	if (FALSE == mime_set_field(phead, "Date", tmp_field)) {
		return FALSE;
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SUBJECTPREFIX);
	pvalue1 = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_NORMALIZEDSUBJECT);
	if (NULL != pvalue && NULL != pvalue1) {
		snprintf(tmp_buff, MIME_FIELD_LEN, "%s%s", pvalue, pvalue1);
		if (oxcmail_encode_mime_string(pskeleton->charset,
			tmp_buff, tmp_field, sizeof(tmp_field)) > 0) {
			if (FALSE == mime_set_field(phead,
				"Subject", tmp_field)) {
				return FALSE;
			}
		}
	} else {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_SUBJECT);
		if (NULL != pvalue && oxcmail_encode_mime_string(
			pskeleton->charset, pvalue, tmp_field,
			sizeof(tmp_field)) > 0) {
			if (FALSE == mime_set_field(
				phead, "Subject", tmp_field)) {
				return FALSE;
			}
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_CONVERSATIONTOPIC);
	if (NULL != pvalue) {
		if (oxcmail_encode_mime_string(pskeleton->charset,
			pvalue, tmp_field, sizeof(tmp_field)) > 0) {
			if (FALSE == mime_set_field(phead,
				"Thread-Topic", tmp_field)) {
				return FALSE;
			}
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_CONVERSATIONINDEX);
	if (NULL != pvalue) {
		if (0 == encode64(((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, tmp_field,
			1024, &base64_len)) {
			if (FALSE == mime_set_field(phead,
				"Thread-Index", tmp_field)) {
				return FALSE;
			}
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_INTERNETMESSAGEID);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"Message-ID", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_INTERNETREFERENCES);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"References", tmp_field)) {
			return FALSE;
		}
	}
	/* PidNameKeywords */
	propname.kind = KIND_NAME;
	rop_util_get_common_pset(PS_PUBLIC_STRINGS, &propname.guid);
	propname.pname = "Keywords";
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_WSTRING_ARRAY;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		tmp_len = 0;
		for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
			if (0 != tmp_len) {
				memcpy(tmp_field, " ,", 2);
				tmp_len += 2;
			}
			if (tmp_len >= MIME_FIELD_LEN) {
				break;
			}
			tmp_len += oxcmail_encode_mime_string(pskeleton->charset,
					((STRING_ARRAY*)pvalue)->ppstr[i],
					tmp_field + tmp_len, MIME_FIELD_LEN - tmp_len);
		}
		if (tmp_len > 0 && tmp_len < MIME_FIELD_LEN) {
			if (FALSE == mime_set_field(phead, "Keywords", tmp_field)) {
				return FALSE;
			}
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_INREPLYTOID);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"In-Reply-To", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_LISTHELP);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"List-Help", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_LISTSUBSCRIBE);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"List-Subscribe", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_LISTUNSUBSCRIBE);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"List-Unsubscribe", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_MESSAGELOCALEID);
	if (NULL != pvalue) {
		pvalue = (void*)oxcmail_lcid_to_ltag(*(uint32_t*)pvalue);
		if (NULL != pvalue) {
			if (FALSE == mime_set_field(phead,
				"Content-Language", pvalue)) {
				return FALSE;
			}
		}
	}
	/* PidLidClassified */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	lid = 0x000085B5;
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_BYTE;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-Microsoft-Classified", "true")) {
			return FALSE;
		}
	}
	/* PidLidClassificationKeep */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	lid = 0x000085BA;
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_BYTE;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-Microsoft-ClassKeep", "true")) {
			return FALSE;
		}
	}
	/* PidLidClassification */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	lid = 0x000085B6;
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_WSTRING;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-Microsoft-Classification", pvalue)) {
			return FALSE;
		}
	}
	/* PidLidClassificationDescription */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	lid = 0x000085B7;
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_WSTRING;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-Microsoft-ClassDesc", pvalue)) {
			return FALSE;
		}
	}
	/* PidLidClassificationGuid */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	lid = 0x000085B8;
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_WSTRING;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-Microsoft-ClassID", pvalue)) {
			return FALSE;
		}
	}
	
	if ((NULL != pmsg->children.pattachments &&
		pmsg->children.pattachments->count) > 0 ||
		(NULL != pskeleton->pattachments &&
		pskeleton->pattachments->count > 0)) {
		if (FALSE == mime_set_field(phead,
			"X-MS-Has-Attach", "yes")) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_AUTORESPONSESUPPRESS);
	if (NULL != pvalue && 0 != *(uint32_t*)pvalue) {
		if (0xFFFFFFFF == *(uint32_t*)pvalue) {
			if (FALSE == mime_set_field(phead,
				"X-Auto-Response-Suppress", "ALL")) {
				return FALSE;
			}
		} else {
			tmp_len = 0;
			if (*(uint32_t*)pvalue & 0x00000001) {
				if (0 != tmp_len) {
					strcpy(tmp_field + tmp_len, ", ");
					tmp_len += 2;
				}
				strcpy(tmp_field + tmp_len, "DR");
				tmp_len += 2;
			}
			if (*(uint32_t*)pvalue & 0x00000002) {
				if (0 != tmp_len) {
					strcpy(tmp_field + tmp_len, ", ");
					tmp_len += 2;
				}
				strcpy(tmp_field + tmp_len, "NDR");
				tmp_len += 3;
			}
			if (*(uint32_t*)pvalue & 0x00000004) {
				if (0 != tmp_len) {
					strcpy(tmp_field + tmp_len, ", ");
					tmp_len += 2;
				}
				strcpy(tmp_field + tmp_len, "RN");
				tmp_len += 2;
			}
			if (*(uint32_t*)pvalue & 0x00000008) {
				if (0 != tmp_len) {
					strcpy(tmp_field + tmp_len, ", ");
					tmp_len += 2;
				}
				strcpy(tmp_field + tmp_len, "NRN");
				tmp_len += 3;
			}
			if (*(uint32_t*)pvalue & 0x00000010) {
				if (0 != tmp_len) {
					strcpy(tmp_field + tmp_len, ", ");
					tmp_len += 2;
				}
				strcpy(tmp_field + tmp_len, "OOF");
				tmp_len += 3;
			}
			if (*(uint32_t*)pvalue & 0x00000020) {
				if (0 != tmp_len) {
					strcpy(tmp_field + tmp_len, ", ");
					tmp_len += 2;
				}
				strcpy(tmp_field + tmp_len, "AutoReply");
				tmp_len += 9;
			}
		}
		if (0 != tmp_len) {
			if (FALSE == mime_set_field(phead,
				"X-Auto-Response-Suppress", tmp_field)) {
				return FALSE;
			}
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_AUTOFORWARDED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-MS-Exchange-Organization-AutoForwarded", "true")) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENDERIDSTATUS);
	if (NULL != pvalue) {
		switch (*(uint32_t*)pvalue) {
		case 1:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"Neutral")) {
				return FALSE;
			}
			break;
		case 2:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"Pass")) {
				return FALSE;
			}
			break;
		case 3:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"Fail")) {
				return FALSE;
			}
			break;
		case 4:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"SoftFail")) {
				return FALSE;
			}
			break;
		case 5:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"None")) {
				return FALSE;
			}
			break;
		case 6:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"TempError")) {
				return FALSE;
			}
			break;
		case 7:
			if (FALSE == mime_set_field(phead,
				"X-MS-Exchange-Organization-SenderIdResult",
				"PermError")) {
				return FALSE;
			}
			break;
		}
	}
	
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_PURPORTEDSENDERDOMAIN);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-MS-Exchange-Organization-PRD", pvalue)) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
			PROP_TAG_CONTENTFILTERSPAMCONFIDENCELEVEL);
	if (NULL != pvalue) {
		sprintf(tmp_field, "%d", *(int32_t*)pvalue);
		if (FALSE == mime_set_field(phead,
			"X-MS-Exchange-Organization-SCL", tmp_field)) {
			return FALSE;
		}
	}
	
	/* PidLidFlagRequest */
	propname.kind = KIND_LID;
	rop_util_get_common_pset(PSETID_COMMON, &propname.guid);
	propname.plid = &lid;
	lid = 0x00008530;
	propnames.count = 1;
	propnames.ppropname = &propname;
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	propid = propids.ppropid[0];
	proptag = ((uint32_t)propid) << 16 | PROPVAL_TYPE_WSTRING;
	pvalue = tpropval_array_get_propval(&pmsg->proplist, proptag);
	if (NULL != pvalue && '\0' != *(char*)pvalue) {
		if (FALSE == mime_set_field(phead,
			"X-Message-Flag", pvalue)) {
			return FALSE;
		}
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_REPLYTIME);
		if (NULL != pvalue) {
			tmp_time = rop_util_nttime_to_unix(*(uint64_t*)pvalue);
			strftime(tmp_field, 128, "%a, %d %b %Y %H:%M:%S %z",
							localtime_r(&tmp_time, &time_buff));
			if (FALSE == mime_set_field(phead,
				"Reply-By", tmp_field)) {
				return FALSE;
			}
		}
	}
	
	if (MAIL_TYPE_TNEF == pskeleton->mail_type) {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
								PROP_TAG_TNEFCORRELATIONKEY);
		if (NULL == pvalue) {
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist, PROP_TAG_INTERNETMESSAGEID);
			if (NULL != pvalue) {
				strncpy(tmp_field, pvalue, 1024);
			} else {
				tmp_field[0] = '\0';
			}
		} else {
			if (((BINARY*)pvalue)->cb >= 1024) {
				tmp_field[0] = '\0';
			} else {
				memcpy(tmp_field, ((BINARY*)pvalue)->pb, ((BINARY*)pvalue)->cb);
				tmp_field[((BINARY*)pvalue)->cb] = '\0';
			}
		}
		if (FALSE == mime_set_field(phead,
			"X-MS-TNEF-Correlator", tmp_field)) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_BODYCONTENTID);
	if (NULL != pvalue) {
		snprintf(tmp_buff, sizeof(tmp_buff), "<%s>", pvalue);
		if (FALSE == mime_set_field(phead,
			"Content-ID", tmp_buff)) {
			return FALSE;
		}
	}
	
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist,  PROP_TAG_BODYCONTENTLOCATION);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(phead,
			"Content-Location", pvalue)) {
			return FALSE;
		}
	}
	
	rop_util_get_common_pset(PS_INTERNET_HEADERS, &guid);
	for (i=0; i<pmsg->proplist.count; i++) {
		propid = pmsg->proplist.ppropval[i].proptag >> 16;
		if (0 == (propid & 0x8000)) {
			continue;
		}
		if (FALSE == get_propname(propid, &ppropname)) {
			return FALSE;
		}
		if (0 != guid_compare(&ppropname->guid, &guid)) {
			continue;
		}
		if (0 == strcasecmp(ppropname->pname, "Content-Type")) {
			continue;
		}
		if (FALSE == mime_set_field(phead, ppropname->pname,
			pmsg->proplist.ppropval[i].pvalue)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL oxcmail_export_dsn(MESSAGE_CONTENT *pmsg,
	const char *charset, const char *pmessage_class,
	EXT_BUFFER_ALLOC alloc, char *pdsn_content,
	int max_length)
{
	int i;
	DSN dsn;
	int tmp_len;
	void *pvalue;
	char action[16];
	TARRAY_SET *prcpts;
	char tmp_buff[1024];
	DSN_FIELDS *pdsn_fields;
	static const char* status_strings1[] =
		{"5.4.0", "5.1.0", "5.6.5", "5.6.5", "5.2.0", "5.3.0", "4.4.3"};
	static const char* status_strings2[] =
		{"5.1.0", "5.1.4", "4.4.5", "4.4.6", "5.1.0", "4.4.7",
		"5.3.0", "5.6.0", "5.6.3", "5.6.2", "5.6.0", "5.5.4",
		"5.6.0", "5.3.4", "5.6.0", "5.6.1", "5.5.3", "5.5.5",
		"5.3.3", "5.6.2", "5.6.0", "5.6.0", "4.6.4", "4.6.4",
		"4.6.4", "4.6.4", "5.7.3", "4.4.6", "5.7.2", "5.7.1",
		"5.2.4", "5.6.1", "5.1.3", "5.1.0", "5.1.3", "5.1.1",
		"5.1.0", "5.3.0", "5.3.0", "5.1.0", "5.1.6", "5.1.0",
		"5.1.0", "5.1.6", "5.0.0", "5.0.0", "5.7.0", "5.0.0",
		"5.1.2"};
	
	
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	pvalue = tpropval_array_get_propval(
		(TPROPVAL_ARRAY*)&pmsg->proplist,
		PROP_TAG_REPORTINGMESSAGETRANSFERAGENT);
	if (NULL == pvalue) {
		strcpy(tmp_buff, "dns; ");
		gethostname(tmp_buff + 5, 1024);
		if (FALSE == dsn_append_field(pdsn_fields,
			"Reporting-MTA", tmp_buff)) {
			dsn_free(&dsn);
			return FALSE;
		}
	} else {
		if (FALSE == dsn_append_field(pdsn_fields,
			"Reporting-MTA", pvalue)) {
			dsn_free(&dsn);
			return FALSE;
		}
	}
	
	tmp_len = strlen(pmessage_class);
	if (0 == strcasecmp(pmessage_class
		+ tmp_len - 3, ".DR")) {
		strcpy(action, "delivered");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 12, ".Expanded.DR")) {
		strcpy(action, "expanded");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 11, ".Relayed.DR")) {
		strcpy(action, "relayed");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 11, ".Delayed.DR")) {
		strcpy(action, "delayed");
	} else if (0 == strcasecmp(pmessage_class
		+ tmp_len - 4, ".NDR")) {
		strcpy(action, "failed");
	}
	if (NULL == pmsg->children.prcpts) {
		goto SERIALIZE_DSN;
	}
	prcpts = pmsg->children.prcpts;
	for (i=0; i<prcpts->count; i++) {
		pdsn_fields = dsn_new_rcpt_fields(&dsn);
		if (NULL == pdsn_fields) {
			dsn_free(&dsn);
			return FALSE;
		}
		strcpy(tmp_buff, "rfc822;");
		if (FALSE == oxcmail_get_smtp_address(prcpts->pparray[i],
			alloc, PROP_TAG_SMTPADDRESS, PROP_TAG_ADDRESSTYPE,
			PROP_TAG_EMAILADDRESS, PROP_TAG_ENTRYID, tmp_buff + 7)) {
			dsn_free(&dsn);
			return FALSE;
		}
		if (FALSE == dsn_append_field(pdsn_fields,
			"Final-Recipient", tmp_buff) ||
			FALSE == dsn_append_field(pdsn_fields,
			"Action", action)) {
			dsn_free(&dsn);
			return FALSE;
		}
		pvalue = tpropval_array_get_propval(prcpts->pparray[i],
							PROP_TAG_NONDELIVERYREPORTDIAGCODE);
		if (NULL != pvalue) {
			if (0xFFFFFFFF == *(uint32_t*)pvalue) {
				pvalue = tpropval_array_get_propval(prcpts->pparray[i],
								PROP_TAG_NONDELIVERYREPORTREASONCODE);
				if (NULL != pvalue) {
					if (*(uint32_t*)pvalue > 6) {
						strcpy(tmp_buff, "5.4.0");
					} else {
						strcpy(tmp_buff,
							status_strings1[*(uint32_t*)pvalue]);
					}
					if (FALSE == dsn_append_field(
						pdsn_fields, "Status", tmp_buff)) {
						dsn_free(&dsn);
						return FALSE;
					}
				}
			} else {
				pvalue = tpropval_array_get_propval(prcpts->pparray[i],
								PROP_TAG_NONDELIVERYREPORTREASONCODE);
				if (NULL != pvalue) {
					if (*(uint32_t*)pvalue > 48) {
						strcpy(tmp_buff, "5.0.0");
					} else {
						strcpy(tmp_buff,
							status_strings2[*(uint32_t*)pvalue]);
					}
					if (FALSE == dsn_append_field(pdsn_fields,
						"Status", tmp_buff)) {
						dsn_free(&dsn);
						return FALSE;
					}
				}
			}
		}
		pvalue = tpropval_array_get_propval(prcpts->pparray[i],
						PROP_TAG_REMOTEMESSAGETRANSFERAGENT);
		if (NULL != pvalue) {
			if (FALSE == dsn_append_field(
				pdsn_fields, "Remote-MTA", pvalue)) {
				dsn_free(&dsn);
				return FALSE;
			}
		}
		pvalue = tpropval_array_get_propval(
			prcpts->pparray[i], PROP_TAG_SUPPLEMENTARYINFO);
		if (NULL != pvalue) {
			if (FALSE == dsn_append_field(pdsn_fields,
				"X-Supplementary-Info", pvalue)) {
				dsn_free(&dsn);
				return FALSE;
			}
		}
		pvalue = tpropval_array_get_propval(
			prcpts->pparray[i], PROP_TAG_DISPLAYNAME);
		if (NULL != pvalue) {
			if (TRUE == oxcmail_encode_mime_string(
				charset, pvalue, tmp_buff, 256)) {
				if (FALSE == dsn_append_field(pdsn_fields,
					"X-Display-Name", tmp_buff)) {
					dsn_free(&dsn);
					return FALSE;
				}
			}
		}
	}
SERIALIZE_DSN:
	if (FALSE == dsn_serialize(&dsn, pdsn_content, max_length)) {
		dsn_free(&dsn);
		return FALSE;
	}
	dsn_free(&dsn);
	return TRUE;
}

static BOOL oxcmail_export_mdn(MESSAGE_CONTENT *pmsg,
	const char *charset, const char *pmessage_class,
	EXT_BUFFER_ALLOC alloc, char *pmdn_content,
	int max_length)
{
	DSN dsn;
	int tmp_len;
	void *pvalue;
	size_t base64_len;
	char tmp_buff[1024];
	char tmp_address[256];
	DSN_FIELDS *pdsn_fields;
	const char *pdisplay_name;
	
	tmp_address[0] = '\0';
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENDERSMTPADDRESS);
	pdisplay_name = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENDERNAME);
	if (NULL != pvalue) {
		strncpy(tmp_address, pvalue, 256);
	} else {
		pvalue = tpropval_array_get_propval(
			&pmsg->proplist, PROP_TAG_SENDERADDRESSTYPE);
		if (NULL != pvalue && 0 == strcasecmp(pvalue, "SMTP")) {
			pvalue = tpropval_array_get_propval(
				&pmsg->proplist, PROP_TAG_SENDEREMAILADDRESS);
			if (NULL != pvalue) {
				strncpy(tmp_address, pvalue, 256);
			}
		}
	}
	if ('\0' != tmp_address[0]) {
		goto EXPORT_MDN_CONTENT;
	}
	pvalue = tpropval_array_get_propval(&pmsg->proplist,
				PROP_TAG_SENTREPRESENTINGSMTPADDRESS);
	pdisplay_name = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_SENTREPRESENTINGNAME);
	if (NULL != pvalue) {
		strncpy(tmp_address, pvalue, 256);
	} else {
		pvalue = tpropval_array_get_propval(&pmsg->proplist,
					PROP_TAG_SENTREPRESENTINGADDRESSTYPE);
		if (NULL != pvalue && 0 == strcasecmp(pvalue, "SMTP")) {
			pvalue = tpropval_array_get_propval(&pmsg->proplist,
						PROP_TAG_SENTREPRESENTINGEMAILADDRESS);
			if (NULL != pvalue) {
				strncpy(tmp_address, pvalue, 256);
			}
		}
	}
EXPORT_MDN_CONTENT:
	dsn_init(&dsn);
	pdsn_fields = dsn_get_message_fileds(&dsn);
	sprintf(tmp_buff, "rfc822;%s", tmp_address);
	if (FALSE == dsn_append_field(pdsn_fields,
		"Final-Recipient", tmp_buff)) {
		dsn_free(&dsn);
		return FALSE;
	}
	tmp_len = strlen(pmessage_class);
	if (0 == strcasecmp(pmessage_class + tmp_len - 6, ".IPNRN")) {
		strcpy(tmp_buff, "manual-action/MDN-sent-automatically; displayed");
	} else {
		strcpy(tmp_buff, "manual-action/MDN-sent-automatically; deleted");
	}
	if (FALSE == dsn_append_field(pdsn_fields,
		"Disposition", tmp_buff)) {
		dsn_free(&dsn);
		return FALSE;
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_PARENTKEY);
	if (NULL != pvalue) {
		if (0 == encode64(((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, tmp_buff,
			1024, &base64_len)) {
			tmp_buff[base64_len] = '\0';
			if (FALSE == dsn_append_field(pdsn_fields,
				"X-MSExch-Correlation-Key", tmp_buff)) {
				dsn_free(&dsn);
				return FALSE;
			}
		}
	}
	pvalue = tpropval_array_get_propval(
		&pmsg->proplist, PROP_TAG_ORIGINALMESSAGEID);
	if (NULL != pvalue) {
		if (FALSE == dsn_append_field(pdsn_fields,
			"Original-Message-ID", pvalue)) {
			dsn_free(&dsn);
			return FALSE;
		}
	}
	if (NULL != pdisplay_name) {
		if (TRUE == oxcmail_encode_mime_string(
			charset, pdisplay_name, tmp_buff, 256)) {
			if (FALSE == dsn_append_field(pdsn_fields,
				"X-Display-Name", tmp_buff)) {
				dsn_free(&dsn);
				return FALSE;
			}
		}
	}
	if (FALSE == dsn_serialize(&dsn, pmdn_content, max_length)) {
		dsn_free(&dsn);
		return FALSE;
	}
	dsn_free(&dsn);
	return TRUE;
}

static BOOL oxcmail_export_appledouble(MAIL *pmail,
	BOOL b_inline, ATTACHMENT_CONTENT *pattachment,
	MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, MIME *pmime)
{
	int tmp_len;
	BINARY *pbin;
	void *pvalue;
	MIME *pmime1;
	MIME *pmime2;
	MACBINARY macbin;
	uint32_t proptag;
	EXT_PULL ext_pull;
	char tmp_field[1024];
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[2];
	
	pbin = tpropval_array_get_propval(
			&pattachment->proplist,
			PROP_TAG_ATTACHDATABINARY);
	if (NULL == pbin) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull,
		pbin->pb, pbin->cb, alloc, 0);
	if (EXT_ERR_SUCCESS != macbinary_pull_binary(
		&ext_pull, &macbin)) {
		return FALSE;
	}
	propnames.count = 2;
	propnames.ppropname = propname_buff;
	/* PidNameAttachmentMacInfo */
	propname_buff[0].kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT,
		&propname_buff[0].guid);
	propname_buff[0].pname = "AttachmentMacInfo";
	/* PidNameAttachmentMacContentType */
	propname_buff[1].kind = KIND_NAME;
	rop_util_get_common_pset(PSETID_ATTACHMENT,
		&propname_buff[1].guid);
	propname_buff[1].pname = "AttachmentMacContentType";
	if (FALSE == get_propids(&propnames, &propids)) {
		return FALSE;
	}
	proptag = ((uint32_t)propids.ppropid[0]) << 16 |
								PROPVAL_TYPE_BINARY;
	pbin = tpropval_array_get_propval(
		&pattachment->proplist, proptag);
	proptag = ((uint32_t)propids.ppropid[1]) << 16 |
								PROPVAL_TYPE_WSTRING;
	pvalue = tpropval_array_get_propval(
		&pattachment->proplist, proptag);
	if (NULL == pvalue) {
		pvalue = "application/octet-stream";
	} else {
		if (0 == strcasecmp(pvalue, "message/rfc822") ||
			0 == strcasecmp(pvalue, "application/applefile") ||
			0 == strcasecmp(pvalue, "application/mac-binhex40") ||
			0 == strncasecmp(pvalue, "multipart/", 10)) {
			pvalue = "application/octet-stream";
		}
	}
	if (FALSE == mime_set_content_type(
		pmime, "multipart/appledouble")) {
		return FALSE;
	}
	pmime1 = mail_add_child(pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime1) {
		return FALSE;
	}
	if (FALSE == mime_set_content_type(
		pmime1, "application/applefile")) {
		return FALSE;
	}
	pmime2 = mail_add_child(pmail, pmime, MIME_ADD_LAST);
	if (NULL == pmime2) {
		return FALSE;
	}
	if (FALSE == mime_set_content_type(pmime2, pvalue)) {
		return FALSE;
	}
	if (NULL == pbin) {
		pbin = apple_util_macbinary_to_appledouble(&macbin);
		if (NULL == pbin) {
			return FALSE;
		}
		if (FALSE == mime_write_content(pmime1, pbin->pb,
			pbin->cb, MIME_ENCODING_BASE64)) {
			rop_util_free_binary(pbin);
			return FALSE;
		}
		rop_util_free_binary(pbin);
	} else {
		if (FALSE == mime_write_content(pmime1, pbin->pb,
			pbin->cb, MIME_ENCODING_BASE64)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
		&pattachment->proplist, PROP_TAG_ATTACHLONGFILENAME);
	if (NULL == pvalue) {
		pvalue = tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHFILENAME);
	}
	if (NULL != pvalue) {
		tmp_field[0] = '"';
		tmp_len = oxcmail_encode_mime_string(
			pskeleton->charset,	pvalue,
			tmp_field + 1, 512);
		if (tmp_len > 0) {
			memcpy(tmp_field + 1 + tmp_len, "\"", 2);
			if (FALSE == mime_set_content_param(
				pmime2, "name", tmp_field)) {
				return FALSE;
			}
		}
		if (FALSE == b_inline) {
			strcpy(tmp_field, "attachment; filename=\"");
			tmp_len = 22;
		} else {
			strcpy(tmp_field, "inline; filename=\"");
			tmp_len = 18;
		}
		tmp_len += oxcmail_encode_mime_string(
			pskeleton->charset, pvalue,
			tmp_field + tmp_len, 1024 - tmp_len);
		memcpy(tmp_field + tmp_len, "\"", 2);
		if (FALSE == mime_set_field(pmime2,
			"Content-Disposition", tmp_field)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_DISPLAYNAME);
	if (NULL != pvalue) {
		tmp_len = oxcmail_encode_mime_string(
					pskeleton->charset, pvalue,
					tmp_field, 1024);
		if (tmp_len > 0) {
			if (FALSE == mime_set_field(pmime2,
				"Content-Description", tmp_field)) {
				return FALSE;
			}
		}
	}
	return mime_write_content(pmime2, (void*)macbin.pdata,
			macbin.header.data_len, MIME_ENCODING_BASE64);
}

static BOOL oxcmail_export_attachment(
	ATTACHMENT_CONTENT *pattachment, BOOL b_inline,
	MIME_SKELETON *pskeleton, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, GET_PROPNAME get_propname,
	MIME_POOL *ppool, MIME *pmime)
{
	int size;
	void *ptr;
	MAIL imail;
	BOOL b_tnef;
	char *pbuff;
	int tmp_len;
	VCARD vcard;
	void *pvalue;
	BOOL b_vcard;
	size_t offset;
	size_t mail_len;
	time_t tmp_time;
	uint64_t *pctime;
	uint64_t *pmtime;
	STREAM tmp_stream;
	struct tm time_buff;
	char tmp_field[1024];
	const char *pfile_name;
	LIB_BUFFER *pallocator;
	const char *pcontent_type;
	
	
	b_vcard = FALSE;
	if (NULL != pattachment->pembedded) {
		pvalue = tpropval_array_get_propval(
			&pattachment->pembedded->proplist,
			PROP_TAG_MESSAGECLASS);
		if (NULL != pvalue && 0 == strcasecmp(
			pvalue, "IPM.Contact")) {
			b_vcard = TRUE;
		}
	}
	
	pfile_name = NULL;
	if (NULL == pattachment->pembedded) {
		pcontent_type = tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHMIMETAG);
		pfile_name = tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHLONGFILENAME);
		if (NULL == pfile_name) {
			pfile_name = tpropval_array_get_propval(
				&pattachment->proplist, PROP_TAG_ATTACHFILENAME);
		}
		if (NULL == pcontent_type) {
			pvalue = tpropval_array_get_propval(
				&pattachment->proplist, PROP_TAG_ATTACHEXTENSION);
			if (NULL != pvalue) {
				pcontent_type = oxcmail_extension_to_mime(pvalue + 1);
			}
			if (NULL == pcontent_type) {
				pcontent_type = "application/octet-stream";
			}
		}
		if (0 == strncasecmp(pcontent_type, "multipart/", 10)) {
			pcontent_type = "application/octet-stream";
		}
		if (FALSE == mime_set_content_type(pmime, pcontent_type)) {
			return FALSE;
		}
		if (NULL != pfile_name) {
			tmp_field[0] = '"';
			tmp_len = oxcmail_encode_mime_string(
				pskeleton->charset,	pfile_name,
				tmp_field + 1, 512);
			if (tmp_len > 0) {
				memcpy(tmp_field + 1 + tmp_len, "\"", 2);
				if (FALSE == mime_set_content_param(
					pmime, "name", tmp_field)) {
					return FALSE;
				}
			}
		}
	} else {
		if (TRUE == b_vcard) {
			pfile_name = tpropval_array_get_propval(
				&pattachment->proplist, PROP_TAG_ATTACHLONGFILENAME);
			if (NULL == pfile_name) {
				pfile_name = tpropval_array_get_propval(
					&pattachment->proplist, PROP_TAG_ATTACHFILENAME);
			}
			if (FALSE == mime_set_content_type(
				pmime, "text/directory")) {
				return FALSE;
			}
			if (FALSE == mime_set_content_param(
				pmime, "charset", "\"utf-8\"") ||
				FALSE == mime_set_content_param(
				pmime, "profile", "vCard")) {
				return FALSE;
			}
		} else {
			if (FALSE == mime_set_content_type(
				pmime, "message/rfc822")) {
				return FALSE;
			}
		}
	}
	
	pvalue = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_DISPLAYNAME);
	if (NULL != pvalue) {
		tmp_len = oxcmail_encode_mime_string(
					pskeleton->charset, pvalue,
					tmp_field, 1024);
		if (tmp_len > 0) {
			if (FALSE == mime_set_field(pmime,
				"Content-Description", tmp_field)) {
				return FALSE;
			}
		}
	}
	
	pctime = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_CREATIONTIME);
	pmtime = tpropval_array_get_propval(
			&pattachment->proplist,
			PROP_TAG_LASTMODIFICATIONTIME);
	if (TRUE == b_inline) {
		strcpy(tmp_field, "inline; ");
		tmp_len = 8;
	} else {
		strcpy(tmp_field, "attachment; ");
		tmp_len = 12;
	}
	if (NULL != pfile_name) {
		memcpy(tmp_field + tmp_len, "filename=\"", 10);
		tmp_len += 10;
		tmp_len += oxcmail_encode_mime_string(pskeleton->charset,
				pfile_name, tmp_field + tmp_len, 1024 - tmp_len);
		memcpy(tmp_field + tmp_len, "\";\r\n\t", 5);
		tmp_len += 5;
	}
	time(&tmp_time);
	if (NULL != pctime) {
		tmp_time = rop_util_nttime_to_unix(*pctime);
	}
	gmtime_r(&tmp_time, &time_buff);
	tmp_len += strftime(tmp_field + tmp_len, 1024 - tmp_len,
		"creation-date=\"%a, %d %b %Y %H:%M:%S GMT\";\r\n\t",
		&time_buff);
	if (NULL != pmtime) {
		tmp_time = rop_util_nttime_to_unix(*pmtime);
	}
	gmtime_r(&tmp_time, &time_buff);
	tmp_len += strftime(tmp_field + tmp_len, 1024 - tmp_len,
		"modification-date=\"%a, %d %b %Y %H:%M:%S GMT\"",
		&time_buff);
	tmp_field[tmp_len] = '\0';
	if (FALSE == mime_set_field(pmime,
		"Content-Disposition", tmp_field)) {
		return FALSE;
	}
	
	pvalue = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_ATTACHCONTENTID);
	if (NULL != pvalue) {
		snprintf(tmp_field, sizeof(tmp_field), "<%s>", pvalue);
		if (FALSE == mime_set_field(pmime,
			"Content-ID", tmp_field)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_ATTACHCONTENTLOCATION);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(pmime,
			"Content-Location", pvalue)) {
			return FALSE;
		}
	}
	pvalue = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_ATTACHCONTENTBASE);
	if (NULL != pvalue) {
		if (FALSE == mime_set_field(pmime,
			"Content-Base", pvalue)) {
			return FALSE;
		}
	}
	
	if (TRUE == b_vcard) {
		pbuff = NULL;
		if (TRUE == oxvcard_export(
			pattachment->pembedded,
			&vcard, get_propids)) {
			pbuff = malloc(VCARD_MAX_BUFFER_LEN);
			if (NULL != pbuff) {
				if (TRUE == vcard_serialize(&vcard,
					pbuff, VCARD_MAX_BUFFER_LEN)) {
					if (FALSE == mime_write_content(
						pmime, pbuff, strlen(pbuff),
						MIME_ENCODING_BASE64)) {
						free(pbuff);
						vcard_free(&vcard);
						return FALSE;
					}
					free(pbuff);
					vcard_free(&vcard);
					return TRUE;
				}
			}
			vcard_free(&vcard);
		}
		if (NULL != pbuff) {
			free(pbuff);
		}
	}
	
	if (NULL != pattachment->pembedded) {
		if (MAIL_TYPE_TNEF == pskeleton->mail_type) {
			b_tnef = TRUE;
		} else {
			b_tnef = FALSE;
		}
		if (FALSE == oxcmail_export(pattachment->pembedded,
			b_tnef, pskeleton->body_type, ppool, &imail,
			alloc, get_propids, get_propname)) {
			return FALSE;
		}
		mail_len = mail_get_length(&imail);
		pallocator = lib_buffer_init(STREAM_ALLOC_SIZE,
				mail_len / STREAM_BLOCK_SIZE + 1, FALSE);
		if (NULL == pallocator) {
			mail_free(&imail);
			return FALSE;
		}
		stream_init(&tmp_stream, pallocator);
		if (FALSE == mail_serialize(&imail, &tmp_stream)) {
			stream_free(&tmp_stream);
			lib_buffer_free(pallocator);
			mail_free(&imail);
			return FALSE;
		}
		mail_free(&imail);
		pbuff = malloc(mail_len + 128);
		if (NULL == pbuff) {
			stream_free(&tmp_stream);
			lib_buffer_free(pallocator);
			return FALSE;
		}
				
		offset = 0;
		size = STREAM_BLOCK_SIZE;
		while (ptr = stream_getbuffer_for_reading(
			&tmp_stream, &size)) {
			memcpy(pbuff + offset, ptr, size);
			offset += size;
			size = STREAM_BLOCK_SIZE;
		}
		stream_free(&tmp_stream);
		lib_buffer_free(pallocator);
		if (FALSE == mime_write_content(pmime,
			pbuff, mail_len, MIME_ENCODING_NONE)) {
			free(pbuff);
			return FALSE;
		}
		free(pbuff);
		return TRUE;
	}
	pvalue = tpropval_array_get_propval(
				&pattachment->proplist,
				PROP_TAG_ATTACHDATABINARY);
	if (NULL != pvalue && 0 != ((BINARY*)pvalue)->cb) {
		if (FALSE == mime_write_content(pmime, ((BINARY*)pvalue)->pb,
			((BINARY*)pvalue)->cb, MIME_ENCODING_BASE64)) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL oxcmail_export(const MESSAGE_CONTENT *pmsg,
	BOOL b_tnef, int body_type, MIME_POOL *ppool,
	MAIL *pmail, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, GET_PROPNAME get_propname)
{
	int i;
	ICAL ical;
	int tmp_len;
	char *pbuff;
	MIME *phead;
	MIME *phtml;
	MIME *pmime;
	MIME *pplain;
	MIME *pmixed;
	void *pvalue;
	BINARY *pbin;
	BOOL b_inline;
	MIME *prelated;
	MIME *pcalendar;
	ICAL_LINE *piline;
	char tmp_method[32];
	char tmp_charset[32];
	const char *pcharset;
	MIME_FIELD mime_field;
	MIME_SKELETON mime_skeleton;
	ATTACHMENT_CONTENT *pattachment;
	
	
	mail_init(pmail, ppool);
	pvalue = tpropval_array_get_propval(
		(TPROPVAL_ARRAY*)&pmsg->proplist,
		PROP_TAG_INTERNETCODEPAGE);
	if (NULL == pvalue || 1200 == *(uint32_t*)pvalue) {
		pcharset = "utf-8";
	} else {
		pcharset = oxcmail_cpid_to_charset(*(uint32_t*)pvalue);
		if (NULL == pcharset) {
			pcharset = "utf-8";
		}
	}
	if (FALSE == oxcmail_load_mime_skeleton(
		(MESSAGE_CONTENT*)pmsg, pcharset, b_tnef,
		body_type, &mime_skeleton)) {
		mail_free(pmail);
		return FALSE;
	}
	phead = mail_add_head(pmail);
	if (NULL == phead) {
		goto EXPORT_FAILURE;
	}
	pmime = phead;
	pplain = NULL;
	phtml = NULL;
	pmixed = NULL;
	prelated = NULL;
	pcalendar = NULL;
	switch (mime_skeleton.mail_type) {
	case MAIL_TYPE_DSN:
	case MAIL_TYPE_MDN:
	case MAIL_TYPE_NORMAL:
	case MAIL_TYPE_CALENDAR:
		if (MAIL_TYPE_DSN == mime_skeleton.mail_type) {
			pmixed = pmime;
			if (FALSE == mime_set_content_type(
				pmime, "multipart/report") ||
				FALSE == mime_set_content_param(
				pmime, "report-type", "delivery-status") ||
				NULL == (pmime = mail_add_child(
				pmail, pmime, MIME_ADD_LAST))) {
				goto EXPORT_FAILURE;
			}
		} else if (MAIL_TYPE_MDN == mime_skeleton.mail_type) {
			pmixed = pmime;
			if (FALSE == mime_set_content_type(
				pmime, "multipart/report") ||
				FALSE == mime_set_content_param(pmime,
				"report-type", "disposition-notification") ||
				NULL == (pmime = mail_add_child(
				pmail, pmime, MIME_ADD_LAST))) {
				goto EXPORT_FAILURE;
			}
		} else {
			if (TRUE == mime_skeleton.b_attachment) {
				pmixed = pmime;
				if (FALSE == mime_set_content_type(
					pmime, "multipart/mixed") ||
					NULL == (pmime = mail_add_child(
					pmail, pmime, MIME_ADD_LAST))) {
					goto EXPORT_FAILURE;
				}
			}
		}
		if (TRUE == mime_skeleton.b_inline) {
			prelated = pmime;
			if (FALSE == mime_set_content_type(
				pmime, "multipart/related") ||
				NULL == (pmime = mail_add_child(
				pmail, pmime, MIME_ADD_LAST))) {
				goto EXPORT_FAILURE;
			}
		}
		if (OXCMAIL_BODY_PLAIN_AND_HTML == mime_skeleton.body_type &&
			NULL != mime_skeleton.pplain && NULL != mime_skeleton.phtml) {
			if (FALSE == mime_set_content_type(
				pmime, "multipart/alternative")) {
				goto EXPORT_FAILURE;
			}
			pplain = mail_add_child(pmail, pmime, MIME_ADD_LAST);
			phtml = mail_add_child(pmail, pmime, MIME_ADD_LAST);
			if (NULL == pplain || FALSE == mime_set_content_type(
				pplain, "text/plain") || NULL == phtml ||
				FALSE == mime_set_content_type(phtml, "text/html")) {
				goto EXPORT_FAILURE;
			}
			if (MAIL_TYPE_CALENDAR == mime_skeleton.mail_type) {
				pcalendar = mail_add_child(pmail, pmime, MIME_ADD_LAST);
				if (NULL == pcalendar || FALSE == mime_set_content_type(
					pcalendar, "text/calendar")) {
					goto EXPORT_FAILURE;
				}
			}
		} else if (OXCMAIL_BODY_PLAIN_ONLY == mime_skeleton.body_type
			&& NULL != mime_skeleton.pplain) {
PLAIN_ONLY:
			if (MAIL_TYPE_CALENDAR != mime_skeleton.mail_type) {
				if (FALSE ==  mime_set_content_type(
					pmime, "text/plain")) {
					goto EXPORT_FAILURE;
				}
				pplain = pmime;
			} else {
				if (FALSE == mime_set_content_type(
					pmime, "multipart/alternative")) {
					goto EXPORT_FAILURE;
				}
				pplain = mail_add_child(pmail, pmime, MIME_ADD_LAST);
				pcalendar = mail_add_child(pmail, pmime, MIME_ADD_LAST);
				if (NULL == pplain || FALSE == mime_set_content_type(
					pplain, "text/plain") || NULL == pcalendar ||
					FALSE == mime_set_content_type(pcalendar,
					"text/calendar")) {
					goto EXPORT_FAILURE;
				}
			}
		} else if (OXCMAIL_BODY_HTML_ONLY == mime_skeleton.body_type
			&& NULL != mime_skeleton.phtml) {
HTML_ONLY:
			if (MAIL_TYPE_CALENDAR != mime_skeleton.mail_type) {
				if (FALSE ==  mime_set_content_type(
					pmime, "text/html")) {
					goto EXPORT_FAILURE;
				}
				phtml = pmime;
			} else {
				if (FALSE == mime_set_content_type(
					pmime, "multipart/alternative")) {
					goto EXPORT_FAILURE;
				}
				phtml = mail_add_child(pmail, pmime, MIME_ADD_LAST);
				pcalendar = mail_add_child(pmail, pmime, MIME_ADD_LAST);
				if (NULL == phtml || FALSE == mime_set_content_type(
					phtml, "text/html") || NULL == pcalendar ||
					FALSE == mime_set_content_type(pcalendar,
					"text/calendar")) {
					goto EXPORT_FAILURE;
				}
			}
		} else if (NULL != mime_skeleton.phtml) {
			mime_skeleton.body_type = OXCMAIL_BODY_HTML_ONLY;
			goto HTML_ONLY;
		} else {
			mime_skeleton.body_type = OXCMAIL_BODY_PLAIN_ONLY;
			goto PLAIN_ONLY;
		}
		break;
	case MAIL_TYPE_TNEF:
		if (FALSE == mime_set_content_type(
			pmime, "multipart/mixed")) {
			goto EXPORT_FAILURE;
		}
		if (NULL == (pplain = mail_add_child(pmail, pmime,
			MIME_ADD_LAST)) || FALSE == mime_set_content_type(
			pplain, "text/plain")) {
			goto EXPORT_FAILURE;
		}
		break;
	}
	
	if (FALSE == oxcmail_export_mail_head(
		(MESSAGE_CONTENT*)pmsg, &mime_skeleton,
		alloc, get_propids, get_propname, phead)) {
		goto EXPORT_FAILURE;
	}
	
	if (MAIL_TYPE_ENCRYPTED == mime_skeleton.mail_type) {
		if (FALSE == mime_set_content_type(
			pmime, "application/pkcs7-mime")) {
			goto EXPORT_FAILURE;
		}
		if (NULL == pmsg->children.pattachments ||
			1 != pmsg->children.pattachments->count) {
			goto EXPORT_FAILURE;
		}
		pbin = tpropval_array_get_propval(
			&pmsg->children.pattachments->pplist[0]->proplist,
			PROP_TAG_ATTACHDATABINARY);
		if (NULL == pbin) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_write_content(pmime, pbin->pb,
			pbin->cb, MIME_ENCODING_BASE64)) {
			goto EXPORT_FAILURE;
		}
		return TRUE;
	} else if (MAIL_TYPE_SIGNED == mime_skeleton.mail_type) {
		/* make fake "Content-Type" to avoid produce boundary string */
		mime_set_content_type(pmime, "fake-part/signed");
		if (NULL == pmsg->children.pattachments ||
			1 != pmsg->children.pattachments->count) {
			goto EXPORT_FAILURE;
		}
		pbin = tpropval_array_get_propval(
			&pmsg->children.pattachments->pplist[0]->proplist,
			PROP_TAG_ATTACHDATABINARY);
		if (NULL == pbin || 0 == pbin->cb) {
			goto EXPORT_FAILURE;
		}
		tmp_len = parse_mime_field(pbin->pb, pbin->cb, &mime_field);
		if (0 == tmp_len || 0 != strncmp(pbin->pb + tmp_len,
			"\r\n", 2) || 12 != mime_field.field_name_len
			|| 0 != strncasecmp( mime_field.field_name,
			"Content-Type", 12) || mime_field.field_value_len > 1024
			|| mime_field.field_value_len < 16 || 0 != strncasecmp(
			mime_field.field_value, "multipart/signed", 16)) {
			goto EXPORT_FAILURE;
		}
		memcpy(mime_field.field_value, "fake-part/signed", 16);
		mime_field.field_value[mime_field.field_value_len] = '\0';
		if (FALSE == mime_set_field(pmime, "Content-Type",
			mime_field.field_value)) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_write_content(pmime, pbin->pb + tmp_len + 2,
			pbin->cb - tmp_len - 2, MIME_ENCODING_NONE)) {
			return FALSE;
		}
		/* replace "Content-Type" back to the real one */
		strcpy(pmime->content_type, "multipart/signed");
		return TRUE;
	}
	
	if (NULL != pplain) {
		if (NULL == mime_skeleton.pplain ||
			'\0' == mime_skeleton.pplain[0]) {
			if (FALSE == mime_write_content(pplain,
				"\r\n", 2, MIME_ENCODING_BASE64)) {
				goto EXPORT_FAILURE;
			}
		} else {
			pbuff = malloc(4*strlen(mime_skeleton.pplain));
			if (NULL == pbuff) {
				goto EXPORT_FAILURE;
			}
			if (FALSE == string_from_utf8(
				mime_skeleton.charset,
				mime_skeleton.pplain, pbuff)) {
				free(pbuff);
				if (FALSE == mime_write_content(
					pplain, mime_skeleton.pplain,
					strlen(mime_skeleton.pplain),
					MIME_ENCODING_BASE64)) {
					goto EXPORT_FAILURE;
				}
				strcpy(tmp_charset, "\"utf-8\"");
			} else {
				if (FALSE == mime_write_content(
					pplain, pbuff, strlen(pbuff),
					MIME_ENCODING_BASE64)) {
					free(pbuff);
					goto EXPORT_FAILURE;
				}
				free(pbuff);
				sprintf(tmp_charset, "\"%s\"", mime_skeleton.charset);
			}
			if (FALSE == mime_set_content_param(
				pplain, "charset", tmp_charset)) {
				goto EXPORT_FAILURE;
			}
		}
	}
	
	if (MAIL_TYPE_TNEF == mime_skeleton.mail_type) {
		pmime = mail_add_child(pmail, pmime, MIME_ADD_LAST);
		if (NULL == pmime || FALSE == mime_set_content_type(pmime,
			"application/ms-tnef") || NULL == (pbin =
			tnef_serialize(pmsg, alloc, get_propname))) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_write_content(pmime, pbin->pb,
			pbin->cb, MIME_ENCODING_BASE64)) {
			rop_util_free_binary(pbin);
			goto EXPORT_FAILURE;
		}
		rop_util_free_binary(pbin);
		if (FALSE == mime_set_content_param(
			pmime, "name", "\"winmail.dat\"") ||
			FALSE == mime_set_field(pmime, "Content-Disposition",
			"attachment; filename=\"winmail.dat\"")) {
			goto EXPORT_FAILURE;
		}
		oxcmail_free_mime_skeleton(&mime_skeleton);
		return TRUE;
	}
	
	if (NULL != phtml) {
		if (FALSE == mime_write_content(phtml,
			mime_skeleton.phtml->pb,
			mime_skeleton.phtml->cb,
			MIME_ENCODING_BASE64)) {
			goto EXPORT_FAILURE;
		}
		sprintf(tmp_charset, "\"%s\"", mime_skeleton.charset);
		if (FALSE == mime_set_content_param(
			phtml, "charset", tmp_charset)) {
			goto EXPORT_FAILURE;
		}
	}
	
	if (NULL != pcalendar) {
		char tmp_buff[1024*1024];
		
		ical_init(&ical);
		if (FALSE == oxcical_export(pmsg, &ical, alloc,
			get_propids, oxcmail_entryid_to_username,
			oxcmail_essdn_to_username, oxcmail_lcid_to_ltag)) {
			ical_free(&ical);
			goto EXPORT_FAILURE;
		}
		tmp_method[0] = '\0';
		piline = ical_get_line((ICAL_COMPONENT*)&ical, "METHOD");
		if (NULL != piline) {
			pvalue = (void*)ical_get_first_subvalue(piline);
			if (NULL != pvalue) {
				strncpy(tmp_method, pvalue, 32);
			}
		}
		if (FALSE == ical_serialize(&ical,
			tmp_buff, sizeof(tmp_buff))) {
			ical_free(&ical);
			goto EXPORT_FAILURE;
		}
		ical_free(&ical);
		if (FALSE == mime_write_content(pcalendar, tmp_buff,
			strlen(tmp_buff), MIME_ENCODING_BASE64)) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_set_content_param(
			pcalendar, "charset", "\"utf-8\"")) {
			goto EXPORT_FAILURE;
		}
		if ('\0' != tmp_method[0]) {
			mime_set_content_param(pcalendar, "method", tmp_method);
		}
	}
	
	if (MAIL_TYPE_DSN == mime_skeleton.mail_type) {
		char tmp_buff[1024*1024];
		
		pmime = mail_add_child(pmail, phead, MIME_ADD_LAST);
		if (NULL == pmime) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_set_content_type(pmime,
			"message/delivery-status")) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == oxcmail_export_dsn((MESSAGE_CONTENT*)pmsg,
			mime_skeleton.charset, mime_skeleton.pmessage_class,
			alloc, tmp_buff, sizeof(tmp_buff))) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_write_content(pmime, tmp_buff,
			strlen(tmp_buff), MIME_ENCODING_NONE)) {
			goto EXPORT_FAILURE;
		}
	} else if (MAIL_TYPE_MDN == mime_skeleton.mail_type) {
		char tmp_buff[1024*1024];
		
		pmime = mail_add_child(pmail, phead, MIME_ADD_LAST);
		if (NULL == pmime) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_set_content_type(pmime,
			"message/disposition-notification")) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == oxcmail_export_mdn((MESSAGE_CONTENT*)pmsg,
			mime_skeleton.charset, mime_skeleton.pmessage_class,
			alloc, tmp_buff, sizeof(tmp_buff))) {
			goto EXPORT_FAILURE;
		}
		if (FALSE == mime_write_content(pmime, tmp_buff,
			strlen(tmp_buff), MIME_ENCODING_NONE)) {
			goto EXPORT_FAILURE;
		}
	}
	
	if (NULL != mime_skeleton.pattachments) {
		for (i=0; i<mime_skeleton.pattachments->count; i++) {
			pmime = mail_add_child(pmail, prelated, MIME_ADD_LAST);
			if (NULL == pmime) {
				goto EXPORT_FAILURE;
			}
			if (FALSE == oxcmail_export_attachment(
				mime_skeleton.pattachments->pplist[i],
				TRUE, &mime_skeleton, alloc, get_propids,
				get_propname, NULL, pmime)) {
				goto EXPORT_FAILURE;
			}
		}
	}
	
	if (NULL == pmsg->children.pattachments) {
		oxcmail_free_mime_skeleton(&mime_skeleton);
		return TRUE;
	}
	for (i=0; i<pmsg->children.pattachments->count; i++) {
		pattachment = pmsg->children.pattachments->pplist[i];
		if (NULL != pattachment->pembedded) {
			pvalue = tpropval_array_get_propval(
				&pattachment->pembedded->proplist,
				PROP_TAG_MESSAGECLASS);
			if (NULL != pvalue && 0 == strcasecmp(pvalue,
				"IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}")) {
				continue;
			}
		}
		if (NULL == pattachment->pembedded &&
			(pvalue = tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHFLAGS)) &&
			(*(uint32_t*)pvalue & ATTACH_FLAG_RENDEREDINBODY)
			&& (NULL != tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHCONTENTID)
			|| NULL != tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHCONTENTLOCATION))) {
			b_inline = TRUE;
			pmime = mail_add_child(pmail, prelated, MIME_ADD_LAST);
		} else {
			b_inline = FALSE;
			pmime = mail_add_child(pmail, pmixed, MIME_ADD_LAST);
		}
		if (NULL == pmime) {
			goto EXPORT_FAILURE;
		}
		if (NULL == pattachment->pembedded &&
			(pvalue = tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHMETHOD)) &&
			ATTACH_METHOD_BY_VALUE == *(uint32_t*)pvalue &&
			(pvalue = tpropval_array_get_propval(
			&pattachment->proplist, PROP_TAG_ATTACHENCODING)) &&
			9 == ((BINARY*)pvalue)->cb && 0 == memcmp(
			((BINARY*)pvalue)->pb, MACBINARY_ENCODING, 9)) {
			if (TRUE == oxcmail_export_appledouble(pmail,
				b_inline, pattachment, &mime_skeleton,
				alloc, get_propids, pmime)) {
				continue;
			}
		}
		if (FALSE == oxcmail_export_attachment(pattachment,
			b_inline, &mime_skeleton, alloc, get_propids,
			get_propname, ppool, pmime)) {
			goto EXPORT_FAILURE;
		}
	}
	oxcmail_free_mime_skeleton(&mime_skeleton);
	return TRUE;
EXPORT_FAILURE:
	oxcmail_free_mime_skeleton(&mime_skeleton);
	mail_free(pmail);
	return FALSE;
}
