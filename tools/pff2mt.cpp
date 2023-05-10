// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iconv.h>
#include <libpff.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

#define E(a, b) static_assert(static_cast<unsigned int>(LIBPFF_VALUE_TYPE_ ## a) == static_cast<unsigned int>(PT_ ## b));
E(UNSPECIFIED, UNSPECIFIED)
E(INTEGER_16BIT_SIGNED, SHORT)
E(INTEGER_32BIT_SIGNED, LONG)
E(FLOAT_32BIT, FLOAT)
E(DOUBLE_64BIT, DOUBLE)
E(CURRENCY, CURRENCY)
E(FLOATINGTIME, APPTIME)
E(ERROR, ERROR)
E(BOOLEAN, BOOLEAN)
E(OBJECT, OBJECT)
E(INTEGER_64BIT_SIGNED, I8)
E(STRING_ASCII, STRING8)
E(STRING_UNICODE, UNICODE)
E(FILETIME, SYSTIME)
E(GUID, CLSID)
E(SERVER_IDENTIFIER, SVREID)
E(RESTRICTION, SRESTRICTION)
E(RULE_ACTION, ACTIONS)
E(BINARY_DATA, BINARY)
#undef E

namespace {

struct libpff_error_del { void operator()(libpff_error_t *x) const { libpff_error_free(&x); } };
struct libpff_file_del { void operator()(libpff_file_t *x) const { libpff_file_free(&x, nullptr); } };
struct libpff_item_del { void operator()(libpff_item_t *x) const { libpff_item_free(&x, nullptr); } };
struct libpff_record_set_del { void operator()(libpff_record_set_t *x) const { libpff_record_set_free(&x, nullptr); } };
struct libpff_record_entry_del { void operator()(libpff_record_entry_t *x) const { libpff_record_entry_free(&x, nullptr); } };
struct libpff_multi_value_del { void operator()(libpff_multi_value_t *x) const { libpff_multi_value_free(&x, nullptr); } };
struct libpff_noop_del { void operator()(void *x) const { } };

using libpff_error_ptr        = std::unique_ptr<libpff_error_t, libpff_error_del>;
using libpff_file_ptr         = std::unique_ptr<libpff_file_t, libpff_file_del>;
using libpff_item_ptr         = std::unique_ptr<libpff_item_t, libpff_item_del>;
using libpff_record_set_ptr   = std::unique_ptr<libpff_record_set_t, libpff_record_set_del>;
using libpff_record_entry_ptr = std::unique_ptr<libpff_record_entry_t, libpff_record_entry_del>;
using libpff_multi_value_ptr  = std::unique_ptr<libpff_multi_value_t, libpff_multi_value_del>;
using libpff_nti_entry_ptr    = std::unique_ptr<libpff_name_to_id_map_entry_t, libpff_noop_del>;

enum {
	NID_TYPE_HID = 0x0,
	NID_TYPE_INTERNAL = 0x1,
	NID_TYPE_NORMAL_FOLDER = 0x2,
	NID_TYPE_SEARCH_FOLDER = 0x3,
	NID_TYPE_NORMAL_MESSAGE = 0x4,
	NID_TYPE_ATTACHMENT = 0x5,
	NID_TYPE_SEARCH_UPDATE_QUEUE = 0x6,
	NID_TYPE_SEARCH_CRITERIA_OBJECT = 0x7,
	NID_TYPE_ASSOC_MESSAGE = 0x8,
	NID_TYPE_CONTENTS_TABLE_INDEX = 0xA,
	NID_TYPE_RECEIVE_FOLDER_TABLE = 0xB,
	NID_TYPE_OUTGOING_QUEUE_TABLE = 0xC,
	NID_TYPE_HIERARCHY_TABLE = 0xD,
	NID_TYPE_CONTENTS_TABLE = 0xE,
	NID_TYPE_ASSOC_CONTENTS_TABLE = 0xF,
	NID_TYPE_SEARCH_CONTENTS_TABLE = 0x10,
	NID_TYPE_ATTACHMENT_TABLE = 0x11,
	NID_TYPE_RECIPIENT_TABLE = 0x12,
	NID_TYPE_SEARCH_TABLE_INDEX = 0x13,
	NID_TYPE_LTP = 0x1F,
	NID_TYPE_MASK = 0x1F,
};

enum {
	NID_MESSAGE_STORE = 0x20 | NID_TYPE_INTERNAL,
	/* Properties in NID_NAME_TO_ID_MAP are modeled based on OXMSG's __nameid_version1.0 */
	NID_NAME_TO_ID_MAP = 0x60 | NID_TYPE_INTERNAL,
	NID_NORMAL_FOLDER_TEMPLATE = 0xA0 | NID_TYPE_INTERNAL,
	NID_SEARCH_FOLDER_TEMPLATE = 0xC0 | NID_TYPE_INTERNAL,
	NID_ROOT_FOLDER = 0x120 | NID_TYPE_NORMAL_FOLDER,
	NID_SEARCH_MANAGEMENT_QUEUE = 0x1E0 | NID_TYPE_INTERNAL,
	NID_SEARCH_ACTIVITY_LIST = 0x200 | NID_TYPE_INTERNAL,
	NID_SEARCH_DOMAIN_OBJECT = 0x260 | NID_TYPE_INTERNAL,
	NID_SEARCH_GATHERER_QUEUE = 0x280 | NID_TYPE_INTERNAL,
	NID_SEARCH_GATHERER_DESCRIPTOR = 0x2A0 | NID_TYPE_INTERNAL,
	NID_SEARCH_GATHERER_FOLDER_QUEUE = 0x320 | NID_TYPE_INTERNAL,
};

}

using namespace std::string_literals;
using namespace gromox;

static std::vector<uint32_t> g_only_objs;
static gi_folder_map_t g_folder_map;
static unsigned int g_splice;
static int g_with_hidden = -1, g_with_assoc;
static const char *g_ascii_charset;

static void cb_only_obj(const HXoptcb *cb)
{
	g_only_objs.push_back(cb->data_long);
}

static constexpr HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 's', HXTYPE_NONE, &g_splice, nullptr, nullptr, 0, "Splice PFF objects into existing store hierarchy"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"with-assoc", 0, HXTYPE_VAL, &g_with_assoc, nullptr, nullptr, 1, "Do import FAI messages"},
	{"without-assoc", 0, HXTYPE_VAL, &g_with_assoc, nullptr, nullptr, 0, "Skip FAI messages [default]"},
	{"with-hidden", 0, HXTYPE_VAL, &g_with_hidden, nullptr, nullptr, 1, "Do import folders with PR_ATTR_HIDDEN"},
	{"without-hidden", 0, HXTYPE_VAL, &g_with_hidden, nullptr, nullptr, 0, "Skip folders with PR_ATTR_HIDDEN [default: dependent upon -s]"},
	{"only-obj", 0, HXTYPE_ULONG, nullptr, nullptr, cb_only_obj, 0, "Extract specific object only", "NID"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void do_print(unsigned int depth, libpff_item_t *);
static int do_item(unsigned int, const parent_desc &, libpff_item_t *);

static YError az_error(const char *prefix, const libpff_error_ptr &err)
{
	char buf[160];
	buf[0] = '\0';
	libpff_error_sprint(err.get(), buf, arsizeof(buf));
	return YError(std::string(prefix) + ": " + buf);
}

static const char *az_nid_type_to_str(uint8_t t)
{
	thread_local char buf[32];
	switch (t & NID_TYPE_MASK) {
	case NID_TYPE_HID: return "hid";
	case NID_TYPE_INTERNAL: return "int";
	case NID_TYPE_NORMAL_FOLDER: return "folder";
	case NID_TYPE_SEARCH_FOLDER: return "sf";
	case NID_TYPE_ATTACHMENT: return "atx";
	case NID_TYPE_SEARCH_UPDATE_QUEUE: return "srchupdq";
	case NID_TYPE_SEARCH_CRITERIA_OBJECT: return "srchcritobj";
	case NID_TYPE_ASSOC_MESSAGE: return "assoc-msg";
	case NID_TYPE_CONTENTS_TABLE_INDEX: return "conttblidx";
	case NID_TYPE_RECEIVE_FOLDER_TABLE: return "rcvfldtbl";
	case NID_TYPE_OUTGOING_QUEUE_TABLE: return "outgoingq";
	case NID_TYPE_HIERARCHY_TABLE: return "hier";
	case NID_TYPE_CONTENTS_TABLE: return "contents";
	case NID_TYPE_ASSOC_CONTENTS_TABLE: return "assoccnttbl";
	case NID_TYPE_SEARCH_CONTENTS_TABLE: return "srchconttbl";
	case NID_TYPE_ATTACHMENT_TABLE: return "atxtbl";
	case NID_TYPE_RECIPIENT_TABLE: return "rcpttbl";
	case NID_TYPE_SEARCH_TABLE_INDEX: return "srchtblidx";
	case NID_TYPE_LTP: return "ltp";
	default: snprintf(buf, sizeof(buf), "unknown-%xh", t & NID_TYPE_MASK); return buf;
	}
}

static const char *az_pffitem_type_to_str(uint8_t t)
{
	thread_local char buf[32];
	switch (t) {
	case LIBPFF_ITEM_TYPE_ACTIVITY: return "activity";
	case LIBPFF_ITEM_TYPE_APPOINTMENT: return "appointment";
	case LIBPFF_ITEM_TYPE_ATTACHMENT: return "attachment";
	case LIBPFF_ITEM_TYPE_CONTACT: return "contact";
	case LIBPFF_ITEM_TYPE_DISTRIBUTION_LIST: return "dlist";
	case LIBPFF_ITEM_TYPE_DOCUMENT: return "document";
	case LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE: return "conflict-message";
	case LIBPFF_ITEM_TYPE_EMAIL: return "email";
	case LIBPFF_ITEM_TYPE_EMAIL_SMIME: return "email(smime)";
	case LIBPFF_ITEM_TYPE_FOLDER: return "folder";
	case LIBPFF_ITEM_TYPE_MEETING: return "meeting";
	case LIBPFF_ITEM_TYPE_NOTE: return "note";
	case LIBPFF_ITEM_TYPE_RSS_FEED: return "rss";
	case LIBPFF_ITEM_TYPE_TASK: return "task";
	case LIBPFF_ITEM_TYPE_RECIPIENTS: return "rcpts";
	case LIBPFF_ITEM_TYPE_UNDEFINED: return "undef";
	default: snprintf(buf, sizeof(buf), "unknown-%u", t); return buf;
	}
}

static const char *az_special_ident(uint32_t nid)
{
#define E(s) case s: return #s;
	switch (nid) {
	E(NID_MESSAGE_STORE)
	E(NID_NAME_TO_ID_MAP)
	E(NID_NORMAL_FOLDER_TEMPLATE)
	E(NID_SEARCH_FOLDER_TEMPLATE)
	E(NID_ROOT_FOLDER)
	E(NID_SEARCH_MANAGEMENT_QUEUE)
	E(NID_SEARCH_ACTIVITY_LIST)
	E(NID_SEARCH_DOMAIN_OBJECT)
	E(NID_SEARCH_GATHERER_QUEUE)
	E(NID_SEARCH_GATHERER_DESCRIPTOR)
	E(NID_SEARCH_GATHERER_FOLDER_QUEUE)
	}
	return "";
}

/* Lookup the pff record entry for the given propid */
static bool az_item_get_propv(libpff_item_t *item, uint32_t proptag,
    libpff_record_entry_t **rent)
{
	libpff_record_set_ptr rset;
	auto ret = libpff_item_get_record_set_by_index(item, 0, &unique_tie(rset), nullptr);
	if (ret <= 0)
		return false;
	uint8_t flags = PROP_TYPE(proptag) == PT_UNSPECIFIED ?
	                LIBPFF_ENTRY_VALUE_FLAG_MATCH_ANY_VALUE_TYPE : 0;
	libpff_error_ptr err;
	ret = libpff_record_set_get_entry_by_type(rset.get(), PROP_ID(proptag),
	      PROP_TYPE(proptag), rent, flags, &unique_tie(err));
	if (ret < 0)
		throw az_error("PF-1001", err);
	else if (ret == 0)
		return false;
	return true;
}

static bool is_mapi_message(uint32_t nid)
{
	/*
	 * libpff_internal_item_determine_type just yolos it on the
	 * presence of PR_MESSAGE_CLASS. Until someone starts having
	 * a folder with PR_MESSAGE_CLASS, then that falls apart.
	 */
	nid &= NID_TYPE_MASK;
	return nid == NID_TYPE_NORMAL_MESSAGE || nid == NID_TYPE_ASSOC_MESSAGE;
}

static int do_attach2(unsigned int depth, ATTACHMENT_CONTENT *atc, libpff_item_t *atx)
{
	int atype = LIBPFF_ATTACHMENT_TYPE_UNDEFINED;
	uint64_t asize = 0;
	libpff_error_ptr err;

	if (libpff_attachment_get_type(atx, &atype, &unique_tie(err)) < 1 &&
	    atype != LIBPFF_ATTACHMENT_TYPE_UNDEFINED)
		fprintf(stderr, "%s\n", az_error("PF-1012: Attachment is not fully recognized", err).what());
	tree(depth);
	if (atype == LIBPFF_ATTACHMENT_TYPE_DATA) {
		if (libpff_attachment_get_data_size(atx, &asize, &~unique_tie(err)) < 1) {
			fprintf(stderr, "%s\n", az_error("PF-1013: Attachment is corrupted", err).what());
			return 0;
		}
		/*
		 * Data is in PR_ATTACH_DATA_BIN, and so was
		 * already spooled into atc->proplist by the caller.
		 */
		tlog("[attachment type=%c size=%llu]\n", atype,
		     static_cast<unsigned long long>(asize));
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_ITEM) {
		libpff_item_ptr emb_item;
		if (libpff_attachment_get_item(atx, &unique_tie(emb_item),
		    &~unique_tie(err)) < 1) {
			fprintf(stderr, "%s\n", az_error("PF-1014: Attachment is corrupted", err).what());
			return 0;
		}
		tlog("[attachment type=%c embedded_msg]\n", atype);
		auto ret = do_item(depth + 1, parent_desc::as_attach(atc), emb_item.get());
		if (ret < 0)
			return ret;
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_REFERENCE) {
		tlog("[attachment type=%c]\n", atype);
		throw YError("PF-1005: EOPNOTSUPP");
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_UNDEFINED) {
		tlog("[attachment type=0]\n");
	} else {
		tlog("[attachment type=unknown]\n");
		throw YError("PF-1006: EOPNOTSUPP");
	}
	return 0;
}

/**
 * Check whether PR_SUBJECT has a \x01 marker at the front, and if so, adjust
 * @pv to contain the actual subject text set the corrected PR_SUBJECT, and set
 * PR_SUBJECT_PREFIX too.
 */
static bool tpropval_subject_handler(TPROPVAL_ARRAY *ar, const TAGGED_PROPVAL &pv)
{
	/* MS-PST v9 §2.5.3.1.1.1 */
	auto buf = reinterpret_cast<const uint8_t *>(pv.pvalue);
	auto s = reinterpret_cast<const char *>(pv.pvalue);
	if (buf[0] != 0x01 || buf[1] == 0x00 || strnlen(s, buf[1]) < buf[1])
		return false;
	TAGGED_PROPVAL pv2 = {pv.proptag, deconst(buf) + buf[1] + 1};
	if (ar->set(pv2) != 0)
		throw std::bad_alloc();
	if (buf[1] == 0x01)
		return true;
	std::string prefix(s + 2, buf[1] - 1);
	TAGGED_PROPVAL pv3 = {PR_SUBJECT_PREFIX, deconst(prefix.c_str())};
	if (ar->set(pv3) != 0)
		throw std::bad_alloc();
	return true;
}

static char *u16convert(const uint8_t *data, size_t inbytes)
{
	size_t bytes = inbytes * 3 / 2 + 1;
	auto outbuf = me_alloc<char>(bytes);
	if (outbuf == nullptr)
		return nullptr;
	auto cd = iconv_open("UTF-8", "UTF-16LE");
	if (cd == iconv_t(-1)) {
		free(outbuf);
		return nullptr;
	}
	auto icv_in = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
	auto icv_out = outbuf;
	auto icv_obytes = bytes;
	iconv(cd, &icv_in, &inbytes, &icv_out, &icv_obytes);
	iconv_close(cd);
	if (icv_obytes > 0)
		*icv_out = '\0';
	else
		outbuf[bytes-1] = '\0';
	return outbuf;
}

static std::unique_ptr<TPROPVAL_ARRAY, gi_delete>
mv_decode_str(uint32_t proptag, const uint8_t *data, size_t dsize)
{
	if (dsize < 4)
		return nullptr;
	std::unique_ptr<TPROPVAL_ARRAY, gi_delete> tp(me_alloc<TPROPVAL_ARRAY>());
	if (tp == nullptr)
		throw std::bad_alloc();
	auto pv = me_alloc<TAGGED_PROPVAL>();
	tp->count = 1;
	tp->ppropval = pv;
	if (tp->ppropval == nullptr)
		throw std::bad_alloc();
	auto ba = me_alloc<STRING_ARRAY>();
	if (ba == nullptr)
		throw std::bad_alloc();
	pv->proptag = proptag;
	pv->pvalue = ba;
	/* PST v9 §2.3.3.4.2 */
	auto nelem = le32p_to_cpu(data);
	ba->count = 0;
	ba->ppstr = static_cast<char **>(calloc(nelem, sizeof(char *)));
	if (ba->ppstr == nullptr)
		throw std::bad_alloc();
	for (; ba->count < nelem; ++ba->count) {
		auto i = ba->count;
		uint32_t ofs = 4 * (i + 1), next_ofs = 4 * (i + 2);
		if (dsize < next_ofs) {
			fprintf(stderr, "PF-1070: broken MV data\n");
			break;
		}
		ofs = le32p_to_cpu(&data[ofs]);
		if (dsize < ofs) {
			fprintf(stderr, "PF-1071: broken MV data\n");
			break;
		}
		if (i == nelem - 1) {
			next_ofs = dsize;
		} else if (dsize < next_ofs + 4) {
			fprintf(stderr, "PF-1072: broken MV data\n");
			break;
		} else {
			next_ofs = le32p_to_cpu(&data[next_ofs]);
		}
		if (dsize < next_ofs) {
			fprintf(stderr, "PF-1073: broken MV data\n");
			break;
		}
		if (next_ofs < ofs) {
			fprintf(stderr, "PF-1069: broken MV data\n");
			break;
		}
		if (PROP_TYPE(proptag) == PT_MV_STRING8)
			ba->ppstr[i] = strndup(reinterpret_cast<const char *>(&data[ofs]), next_ofs - ofs);
		else
			ba->ppstr[i] = u16convert(&data[ofs], next_ofs - ofs);
		if (ba->ppstr[i] == nullptr)
			throw std::bad_alloc();
	}
	return tp;
}

static std::unique_ptr<TPROPVAL_ARRAY, gi_delete>
mv_decode_bin(uint32_t proptag, const uint8_t *data, size_t dsize)
{
	if (dsize < 4)
		return nullptr;
	std::unique_ptr<TPROPVAL_ARRAY, gi_delete> tp(me_alloc<TPROPVAL_ARRAY>());
	if (tp == nullptr)
		throw std::bad_alloc();
	auto pv = me_alloc<TAGGED_PROPVAL>();
	tp->count = 1;
	tp->ppropval = pv;
	if (tp->ppropval == nullptr)
		throw std::bad_alloc();
	auto ba = me_alloc<BINARY_ARRAY>();
	if (ba == nullptr)
		throw std::bad_alloc();
	pv->proptag = proptag;
	pv->pvalue = ba;
	auto nelem = le32p_to_cpu(data);
	ba->count = 0;
	ba->pbin = static_cast<BINARY *>(calloc(nelem, sizeof(BINARY)));
	if (ba->pbin == nullptr)
		throw std::bad_alloc();
	for (; ba->count < nelem; ++ba->count) {
		auto i = ba->count;
		uint32_t ofs = 4 * (i + 1), next_ofs = 4 * (i + 2);
		if (dsize < next_ofs) {
			fprintf(stderr, "PF-1074: broken MV data\n");
			break;
		}
		ofs = le32p_to_cpu(&data[ofs]);
		if (dsize < ofs) {
			fprintf(stderr, "PF-1075: broken MV data\n");
			break;
		}
		if (i == nelem - 1) {
			next_ofs = dsize;
		} else if (dsize < next_ofs + 4) {
			fprintf(stderr, "PF-1076: broken MV data\n");
			break;
		} else {
			next_ofs = le32p_to_cpu(&data[next_ofs]);
		}
		if (dsize < next_ofs) {
			fprintf(stderr, "PF-1077: broken MV data\n");
			break;
		}
		if (next_ofs < ofs) {
			fprintf(stderr, "PF-1068: broken MV data\n");
			break;
		}
		ba->pbin[i].cb = next_ofs - ofs;
		ba->pbin[i].pv = malloc(ba->pbin[i].cb);
		if (ba->pbin[i].pv == nullptr)
			throw std::bad_alloc();
		memcpy(ba->pbin[i].pv, &data[ofs], ba->pbin[i].cb);
	}
	return tp;
}

static void recordent_to_tpropval(libpff_record_entry_t *rent, TPROPVAL_ARRAY *ar)
{
	libpff_error_ptr err, e2, e3;
	unsigned int etype = 0, vtype = 0;
	size_t dsize = 0;

	auto r1 = libpff_record_entry_get_entry_type(rent, &etype, &unique_tie(err));
	auto r2 = libpff_record_entry_get_value_type(rent, &vtype, &unique_tie(e2));
	/*
	 * It may become necessary to filter some (or perhaps all) properties that
	 * are in the so-called non-transmittable range(s) (cf. mapidefs.h).
	 */
	auto r3 = libpff_record_entry_get_data_size(rent, &dsize, &unique_tie(e3));
	if (r1 < 0)
		throw az_error("PF-1061", err);
	if (r2 < 0)
		throw az_error("PF-1062", e2);
	if (r3 < 0)
		throw az_error("PF-1063", e3);
	if (r1 == 0 || r2 == 0 || r3 == 0) {
		if (g_show_props)
			fprintf(stderr, "PF-1064: Encountered PFF record entry with no proptag\n");
		return;
	}

	auto buf = std::make_unique<uint8_t[]>(dsize + 1);
	if (dsize == 0)
		buf[0] = '\0';
	else if (libpff_record_entry_get_data(rent, buf.get(), dsize + 1, &~unique_tie(err)) < 1)
		throw az_error("PF-1033", err);

	union {
		BINARY bin;
		GUID guid;
		struct {
			BINARY svbin;
			SVREID svreid;
		};
		SHORT_ARRAY sa;
		LONG_ARRAY la;
		LONGLONG_ARRAY lla;
		FLOAT_ARRAY fa;
		DOUBLE_ARRAY da;
		GUID_ARRAY ga;
	} u;
	std::unique_ptr<TPROPVAL_ARRAY, gi_delete> uextra;
	TAGGED_PROPVAL pv;
	pv.proptag = PROP_TAG(vtype, etype);
	pv.pvalue = buf.get();
	switch (vtype) {
	case PT_SHORT:
		if (dsize == sizeof(uint16_t))
			break;
		throw YError("PF-1015: Datasize mismatch on %xh\n", pv.proptag);
	case PT_LONG:
		if (dsize == sizeof(uint32_t))
			break;
		throw YError("PF-1016: Datasize mismatch on %xh\n", pv.proptag);
	case PT_I8:
	case PT_SYSTIME:
	case PT_CURRENCY:
		if (dsize == sizeof(uint64_t))
			break;
		throw YError("PF-1019: Datasize mismatch on %xh\n", pv.proptag);
	case PT_FLOAT:
		if (dsize == sizeof(float))
			break;
		throw YError("PF-1020: Datasize mismatch on %xh\n", pv.proptag);
	case PT_DOUBLE:
	case PT_APPTIME:
		if (dsize == sizeof(double))
			break;
		throw YError("PF-1021: Datasize mismatch on %xh\n", pv.proptag);
	case PT_BOOLEAN:
		if (dsize == sizeof(uint8_t))
			break;
		throw YError("PF-1024: Datasize mismatch on %xh\n", pv.proptag);
	case PT_STRING8:
	case PT_UNICODE: {
		size_t dsize2 = 0;
		if (libpff_record_entry_get_data_as_utf8_string_size(rent, &dsize2, &unique_tie(err)) >= 1) {
			++dsize2;
			buf = std::make_unique<uint8_t[]>(dsize2);
			if (libpff_record_entry_get_data_as_utf8_string(rent,
			    buf.get(), dsize2, &~unique_tie(err)) < 1)
				throw az_error("PF-1036", err);
		} else if (vtype == PT_UNICODE) {
			fprintf(stderr, "PF-1041: Garbage in string which cannot be represented in UTF-8\n");
			auto s = iconvtext(reinterpret_cast<char *>(buf.get()), dsize,
			         "UTF-16", "UTF-8//IGNORE");
			dsize = s.size() + 1;
			buf = std::make_unique<uint8_t[]>(dsize);
			memcpy(buf.get(), s.data(), dsize);
		} else if (vtype == PT_STRING8) {
			fprintf(stderr, "PF-1041: Garbage in string which cannot be represented in UTF-8\n");
			auto s = iconvtext(reinterpret_cast<char *>(buf.get()), dsize,
			         g_ascii_charset, "UTF-8//IGNORE");
			dsize = s.size() * 3 + 1;
			buf = std::make_unique<uint8_t[]>(dsize);
			memcpy(buf.get(), s.data(), dsize);
		}
		pv.proptag = CHANGE_PROP_TYPE(pv.proptag, PT_UNICODE);
		pv.pvalue = buf.get();
		break;
	}
	case PT_BINARY:
		u.bin.cb = dsize;
		u.bin.pv = buf.get();
		pv.pvalue = &u.bin;
		break;
	case PT_CLSID:
		if (dsize != sizeof(u.guid)) {
			fprintf(stderr, "PF-1040: Encountered property %xh with icorrect GUID size (%zu)\n",
			        pv.proptag, dsize);
			return;
		}
		memcpy(&u.guid, buf.get(), sizeof(u.guid));
		pv.pvalue = &u.guid;
		break;
	case PT_SVREID:
		pv.pvalue = &u.svreid;
		u.svbin.cb = dsize;
		u.svbin.pv = buf.get();
		u.svreid.pbin = &u.svbin;
		u.svreid.folder_id = 0;
		u.svreid.message_id = 0;
		u.svreid.instance = 0;
		break;
	case PT_MV_SHORT:
		u.sa.count = dsize / sizeof(uint16_t);
		u.sa.ps = reinterpret_cast<uint16_t *>(buf.get());
		pv.pvalue = &u.sa;
		break;
	case PT_MV_LONG:
		u.la.count = dsize / sizeof(uint32_t);
		u.la.pl = reinterpret_cast<uint32_t *>(buf.get());
		pv.pvalue = &u.la;
		break;
	case PT_MV_FLOAT:
		u.fa.count = dsize / sizeof(float);
		u.fa.mval = reinterpret_cast<float *>(buf.get());
		pv.pvalue = &u.fa;
		break;
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		u.da.count = dsize / sizeof(double);
		u.da.mval = reinterpret_cast<double *>(buf.get());
		pv.pvalue = &u.da;
		break;
	case PT_MV_I8:
	case PT_MV_SYSTIME:
	case PT_MV_CURRENCY:
		u.lla.count = dsize / sizeof(uint64_t);
		u.lla.pll = reinterpret_cast<uint64_t *>(buf.get());
		pv.pvalue = &u.lla;
		break;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		uextra = mv_decode_str(pv.proptag, buf.get(), dsize);
		pv.pvalue = uextra != nullptr ? uextra->ppropval[0].pvalue : nullptr;
		break;
	case PT_MV_BINARY:
		uextra = mv_decode_bin(pv.proptag, buf.get(), dsize);
		pv.pvalue = uextra != nullptr ? uextra->ppropval[0].pvalue : nullptr;
		break;
	case PT_MV_CLSID:
		u.ga.count = dsize / sizeof(GUID);
		u.ga.pguid = reinterpret_cast<GUID *>(buf.get());
		pv.pvalue = &u.guid;
		break;
	case PT_OBJECT:
		if (pv.proptag == PR_ATTACH_DATA_OBJ)
			return; /* Embedded message, which separately handled. */
		throw YError("PF-1039: Unsupported proptag %xh (datasize %zu). Implement me!\n",
		        pv.proptag, dsize);
	default:
		throw YError("PF-1042: Unsupported proptype %xh (datasize %zu). Implement me!\n",
		        pv.proptag, dsize);
	}
	bool done = false;
	if (pv.proptag == PR_SUBJECT)
		done = tpropval_subject_handler(ar, pv);
	if (!done && ar->set(pv) != 0)
		throw std::bad_alloc();
}

static void recordset_to_tpropval_a(libpff_record_set_t *rset, TPROPVAL_ARRAY *props)
{
	int nent = 0;
	libpff_error_ptr err;
	if (libpff_record_set_get_number_of_entries(rset, &nent, &unique_tie(err)) < 1)
		throw az_error("PF-1028", err);
	for (int i = 0; i < nent; ++i) {
		libpff_record_entry_ptr rent;
		if (libpff_record_set_get_entry_by_index(rset, i,
		    &unique_tie(rent), &~unique_tie(err)) < 1)
			throw az_error("PF-1029", err);
		recordent_to_tpropval(rent.get(), props);
	}
}

/* Collect all recordsets' properties into one TPROPVAL_ARRAY */
static tpropval_array_ptr item_to_tpropval_a(libpff_item_t *item)
{
	tpropval_array_ptr props(tpropval_array_init());
	if (props == nullptr)
		throw std::bad_alloc();
	int nsets = 0;
	libpff_error_ptr err;
	if (libpff_item_get_number_of_record_sets(item, &nsets, &unique_tie(err)) < 1 ||
	    nsets == 0)
		return props;
	for (int n = 0; n < nsets; ++n) {
		libpff_record_set_ptr rset;
		if (libpff_item_get_record_set_by_index(item, n,
		    &unique_tie(rset), &~unique_tie(err)) < 1)
			throw az_error("PF-1022", err);
		recordset_to_tpropval_a(rset.get(), props.get());
	}
	return props;
}

/* Collect each recordset as its own TPROPVAL_ARRAY */
static tarray_set_ptr item_to_tarray_set(libpff_item_t *item)
{
	tarray_set_ptr tset(tarray_set_init());
	if (tset == nullptr)
		throw std::bad_alloc();
	int nsets = 0;
	libpff_error_ptr err;
	if (libpff_item_get_number_of_record_sets(item, &nsets, &unique_tie(err)) < 1 ||
	    nsets == 0)
		return tset;
	for (int n = 0; n < nsets; ++n) {
		libpff_record_set_ptr rset;
		if (libpff_item_get_record_set_by_index(item, n,
		    &unique_tie(rset), &~unique_tie(err)) < 1)
			throw az_error("PF-1043", err);
		tpropval_array_ptr tprops(tpropval_array_init());
		if (tprops == nullptr)
			throw std::bad_alloc();
		recordset_to_tpropval_a(rset.get(), tprops.get());
		auto ret = tset->append_move(std::move(tprops));
		if (ret == ENOMEM)
			throw std::bad_alloc();
	}
	return tset;
}

static int do_folder(unsigned int depth, const parent_desc &parent,
    libpff_item_t *item)
{
	auto props = item_to_tpropval_a(item);
	if (g_show_tree) {
		auto tset = item_to_tarray_set(item);
		gi_dump_tarray_set(depth, *tset);
	} else {
		auto name = props->get<char>(PR_DISPLAY_NAME);
		if (name != nullptr)
			fprintf(stderr, "pff: Processing \"%s\"...\n", name);
		/*
		 * There are a bunch of folders with no dispname property at all.
		 * Probably not worth mentioning in the low-verbosity level here.
		 */
	}
	uint32_t ident = 0;
	if (libpff_item_get_identifier(item, &ident, nullptr) < 1)
		throw YError("PF-1051");
	if (!g_wet_run)
		return 0;
	auto hidden_flag = props->get<const uint8_t>(PR_ATTR_HIDDEN);
	if (hidden_flag != nullptr && *hidden_flag != 0 && !g_with_hidden) {
		fprintf(stderr, " - skipped due to PR_ATTR_HIDDEN=1\n");
		return 1;
	}

	bool b_create = false;
	auto iter = g_folder_map.find(ident);
	if (iter == g_folder_map.end() && parent.type == MAPI_FOLDER) {
		/* PST folder with name -> new folder in store. Create. */
		b_create = true;
	} else if (iter == g_folder_map.end()) {
		/* No @parent for writing the item anywhere, and no hints in map => do not create. */
	} else if (!iter->second.create) {
		/* Splice request (e.g. PST wastebox -> Store wastebox) */
		b_create = true;
	} else {
		/* Create request (e.g. PST root without name -> new folder in store with name) */
		b_create = true;
	}

	if (!b_create)
		return 0;
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	ep.p_uint32(static_cast<uint32_t>(MAPI_FOLDER));
	ep.p_uint32(ident);
	ep.p_uint32(static_cast<uint32_t>(parent.type));
	ep.p_uint64(parent.folder_id);
	ep.p_tpropval_a(*props);
	ep.p_uint64(0); /* ACL count */
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	auto ret = HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize));
	if (ret < 0)
		throw YError("PF-1124: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	if (ret < 0)
		throw YError("PF-1126: %s", strerror(errno));
	return 0;
}

static message_content_ptr extract_message(unsigned int depth,
    const parent_desc &parent, libpff_item_t *item)
{
	auto props = item_to_tpropval_a(item);
	message_content_ptr ctnt(message_content_init());
	if (ctnt == nullptr)
		throw std::bad_alloc();
	ctnt->children.pattachments = attachment_list_init();
	if (ctnt->children.pattachments == nullptr)
		throw std::bad_alloc();
	ctnt->children.prcpts = tarray_set_init();
	if (ctnt->children.prcpts == nullptr)
		throw std::bad_alloc();
	std::swap(ctnt->proplist.count, props->count);
	std::swap(ctnt->proplist.ppropval, props->ppropval);
	libpff_item_ptr recip_set;
	if (libpff_message_get_recipients(item, &unique_tie(recip_set), nullptr) >= 1) {
		auto ret = do_item(depth, parent_desc::as_msg(ctnt.get()), recip_set.get());
		if (ret < 0)
			throw YError("PF-1052: %s", strerror(-ret));
	}
	int atnum = 0;
	if (libpff_message_get_number_of_attachments(item, &atnum, nullptr) >= 1) {
		for (int atidx = 0; atidx < atnum; ++atidx) {
			libpff_item_ptr atx;
			libpff_error_ptr err;
			if (libpff_message_get_attachment(item, atidx,
			    &unique_tie(atx), &unique_tie(err)) < 1)
				throw az_error("PF-1017", err);
			auto ret = do_item(depth, parent_desc::as_msg(ctnt.get()), atx.get());
			if (ret < 0)
				throw YError("PF-1053: %s", strerror(-ret));
		}
	}
	return ctnt;
}

static int do_message(unsigned int depth, const parent_desc &parent,
    libpff_item_t *item, uint32_t ident)
{
	auto ctnt = extract_message(depth, parent, item);
	if (parent.type == MAPI_ATTACH)
		parent.attach->set_embedded_internal(ctnt.release());
	if (parent.type != MAPI_FOLDER)
		return 0;

	/* Normal message, not embedded */
	if (g_show_tree)
		gi_dump_msgctnt(depth, *ctnt);
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(ident) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(static_cast<uint32_t>(parent.type)) != EXT_ERR_SUCCESS ||
	    ep.p_uint64(parent.folder_id) != EXT_ERR_SUCCESS ||
	    ep.p_msgctnt(*ctnt) != EXT_ERR_SUCCESS)
		throw YError("PF-1058");
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	auto ret = HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize));
	if (ret < 0)
		throw YError("PF-1128: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	if (ret < 0)
		throw YError("PF-1130: %s", strerror(errno));
	return 0;
}

static int do_recips(unsigned int depth, const parent_desc &parent, libpff_item_t *item)
{
	int nsets = 0;
	libpff_error_ptr err;
	assert(parent.type == MAPI_MESSAGE);
	if (libpff_item_get_number_of_record_sets(item, &nsets, &unique_tie(err)) < 1)
		return 0;
	for (int s = 0; s < nsets; ++s) {
		libpff_record_set_ptr rset;
		if (libpff_item_get_record_set_by_index(item, s, &unique_tie(rset), nullptr) < 1)
			throw YError("PF-1049");
		tpropval_array_ptr props(tpropval_array_init());
		if (props == nullptr)
			throw std::bad_alloc();
		recordset_to_tpropval_a(rset.get(), props.get());
		if (parent.message->children.prcpts->append_move(std::move(props)) == ENOMEM)
			throw std::bad_alloc();
	}
	return 0;
}

static int do_attach(unsigned int depth, const parent_desc &parent, libpff_item_t *item)
{
	attachment_content_ptr atc(attachment_content_init());
	if (atc == nullptr)
		throw std::bad_alloc();
	auto props = item_to_tpropval_a(item);
	std::swap(atc->proplist.count, props->count);
	std::swap(atc->proplist.ppropval, props->ppropval);
	do_print(depth++, item);
	auto ret = do_attach2(depth, atc.get(), item);
	if (ret < 0)
		return ret;
	if (parent.type == MAPI_MESSAGE) {
		if (!parent.message->children.pattachments->append_internal(atc.get()))
			throw std::bad_alloc();
		atc.release();
	}
	return 0;
}

static void do_print(unsigned int depth, libpff_item_t *item)
{
	uint32_t ident = 0, nent = 0;
	uint8_t item_type = LIBPFF_ITEM_TYPE_UNDEFINED;
	int nsets = 0;
	libpff_error_ptr err;

	libpff_item_get_identifier(item, &ident, nullptr);
	libpff_item_get_type(item, &item_type, nullptr);
	libpff_item_get_number_of_record_sets(item, &nsets, nullptr);
	libpff_item_get_number_of_entries(item, &nent, nullptr);
	tree(depth);
	auto sp_nid = az_special_ident(ident);
	tlog("[id=%lxh%s%s ntyp=%s type=%s nset=%d nent=%lu]\n",
		static_cast<unsigned long>(ident),
		*sp_nid != '\0' ? " " : "", sp_nid,
		az_nid_type_to_str(ident),
		az_pffitem_type_to_str(item_type),
		nsets, static_cast<unsigned long>(nent));
}

static int do_item(unsigned int depth, const parent_desc &parent, libpff_item_t *item)
{
	uint32_t ident = 0;
	uint8_t item_type = LIBPFF_ITEM_TYPE_UNDEFINED;
	int ret = 0;
	libpff_error_ptr err;

	libpff_item_get_identifier(item, &ident, nullptr);
	libpff_item_get_type(item, &item_type, nullptr);
	auto new_parent = parent;
	if (item_type == LIBPFF_ITEM_TYPE_FOLDER) {
		if (g_show_tree)
			do_print(depth++, item);
		ret = do_folder(depth, parent, item);
		new_parent.type = MAPI_FOLDER;
		new_parent.folder_id = ident;
	} else if (is_mapi_message(ident)) {
		if (g_show_tree)
			do_print(depth++, item);
		if (g_with_assoc ||
		    (ident & NID_TYPE_MASK) != NID_TYPE_ASSOC_MESSAGE)
			return do_message(depth, parent, item, ident);
		return 0;
	} else if (item_type == LIBPFF_ITEM_TYPE_RECIPIENTS) {
		ret = do_recips(depth, parent, item);
	} else if (item_type == LIBPFF_ITEM_TYPE_ATTACHMENT) {
		ret = do_attach(depth, parent, item);
	} else if (g_show_tree && ident != 0) {
		/*
		 * The root entry is not very interesting (always
		 * nset=0,nent=0), it would just indent the remaining tree by
		 * one level.
		 */
		do_print(depth++, item);
		auto tset = item_to_tarray_set(item);
		gi_dump_tarray_set(depth, *tset);
	}

	if (ret < 0)
		return ret;
	if (ret == 1)
		return 0;
	int nsub = 0;
	if (libpff_item_get_number_of_sub_items(item, &nsub, &~unique_tie(err)) < 1)
		throw az_error("PF-1003", err);
	for (int i = 0; i < nsub; ++i) {
		libpff_item_ptr subitem;
		if (libpff_item_get_sub_item(item, i, &unique_tie(subitem), &~unique_tie(err)) < 1)
			throw az_error("PF-1004", err);
		ret = do_item(depth, new_parent, subitem.get());
		if (ret < 0)
			return ret;
	}
	return 0;
}

static uint32_t az_nid_from_mst(libpff_item_t *item, uint32_t proptag)
{
	libpff_record_entry_ptr rent;
	if (az_item_get_propv(item, proptag, &~unique_tie(rent)) < 1)
		return 0;
	char eid[24];
	if (libpff_record_entry_get_data(rent.get(),
	    reinterpret_cast<uint8_t *>(eid), arsizeof(eid), nullptr) < 1)
		return 0;
	return le32p_to_cpu(&eid[20]);
}

static void az_fmap_standard(libpff_file_t *file, const char *filename)
{
	char timebuf[64];
	time_t now = time(nullptr);
	auto tm = localtime(&now);
	strftime(timebuf, arsizeof(timebuf), " @%FT%T", tm);
	g_folder_map.emplace(NID_ROOT_FOLDER, tgt_folder{true, PRIVATE_FID_IPMSUBTREE,
		"Import of "s + HX_basename(filename) + timebuf});
}

/**
 * Analyze message store properties to discover special folders.
 */
static void az_fmap_splice_mst(libpff_file_t *file)
{
	g_folder_map.emplace(NID_ROOT_FOLDER, tgt_folder{false, PRIVATE_FID_ROOT, "FID_ROOT"});

	libpff_item_ptr mst;
	if (libpff_file_get_message_store(file, &~unique_tie(mst), nullptr) < 1)
		return;
	auto nid = az_nid_from_mst(mst.get(), PR_IPM_SUBTREE_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_IPMSUBTREE, "FID_IPMSUBTREE"});
	nid = az_nid_from_mst(mst.get(), PR_IPM_OUTBOX_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_OUTBOX, "FID_OUTBOX"});
	nid = az_nid_from_mst(mst.get(), PR_IPM_WASTEBASKET_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_DELETED_ITEMS, "FID_DELETED_ITEMS"});
	nid = az_nid_from_mst(mst.get(), PR_IPM_SENTMAIL_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_SENT_ITEMS, "FID_SENT_ITEMS"});
	nid = az_nid_from_mst(mst.get(), PR_FINDER_ENTRYID);
	if (nid != 0)
		g_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_FINDER, "FID_FINDER"});
}

/**
 * Analyze the Receive Folder Table to discover the inbox special folder.
 */
static void az_fmap_splice_rft2(const tarray_set &tset)
{
	unsigned int goodmatch = 0;
	uint32_t nid = 0;
	for (size_t i = 0; i < tset.count; ++i) {
		auto props = tset.pparray[i];
		if (props == nullptr)
			continue;
		auto msgcls = props->get<char>(PR_MESSAGE_CLASS);
		auto tgtfld = props->get<uint32_t>(PR_PST_RECEIVE_FOLDER_NID);
		if (msgcls == nullptr || tgtfld == nullptr)
			continue;
		/*
		 * In PST, the receive folder with msgcls="" is of no
		 * use because it points to the PST root.
		 */
		if (strcmp(msgcls, "IPM") == 0 && goodmatch < 2) {
			goodmatch = 2;
			nid = *tgtfld;
		} else if (strcmp(msgcls, "IPM.Note") == 0 && goodmatch < 3) {
			goodmatch = 3;
			nid = *tgtfld;
		}
	}
	if (goodmatch > 0)
		g_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_INBOX, "FID_INBOX"});
}

static void az_fmap_splice_rft(libpff_file_t *file)
{
	libpff_error_ptr err;
	libpff_item_ptr root;
	if (libpff_file_get_root_item(file, &unique_tie(root), &~unique_tie(err)) < 1)
		throw az_error("PF-1002", err);
	int nsub = 0;
	if (libpff_item_get_number_of_sub_items(root.get(), &nsub, &~unique_tie(err)) < 1)
		throw az_error("PF-1007", err);
	for (int i = 0; i < nsub; ++i) {
		libpff_item_ptr subitem;
		unsigned int ident = 0;

		if (libpff_item_get_sub_item(root.get(), i, &unique_tie(subitem), &~unique_tie(err)) < 1)
			throw az_error("PF-1008", err);
		if (libpff_item_get_identifier(subitem.get(), &ident, &~unique_tie(err)) < 1)
			throw az_error("PF-1009", err);
		if ((ident & NID_TYPE_MASK) == NID_TYPE_RECEIVE_FOLDER_TABLE)
			az_fmap_splice_rft2(*item_to_tarray_set(subitem.get()));
	}
}

static void npg_ent(gi_name_map &map, libpff_record_entry_t *rent)
{
	libpff_nti_entry_ptr nti_entry;
	uint32_t etype = 0, vtype = 0;
	uint8_t nti_type = 0;

	if (libpff_record_entry_get_entry_type(rent, &etype, nullptr) < 1 ||
	    etype < 0x8000 ||
	    libpff_record_entry_get_value_type(rent, &vtype, nullptr) < 1)
		return;
	if (libpff_record_entry_get_name_to_id_map_entry(rent, &unique_tie(nti_entry), nullptr) < 1)
		return;
	if (libpff_name_to_id_map_entry_get_type(nti_entry.get(), &nti_type, nullptr) < 1)
		return;
	std::unique_ptr<char[], stdlib_delete> pnstr;
	PROPERTY_NAME pn_req{};
	if (libpff_name_to_id_map_entry_get_guid(nti_entry.get(),
	    reinterpret_cast<uint8_t *>(&pn_req.guid), sizeof(pn_req.guid), nullptr) < 1)
		return;
	if (nti_type == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_NUMERIC) {
		if (libpff_name_to_id_map_entry_get_number(nti_entry.get(), &pn_req.lid, nullptr) < 1)
			return;
		pn_req.kind = MNID_ID;
	} else if (nti_type == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_STRING) {
		size_t dsize = 0;
		if (libpff_name_to_id_map_entry_get_utf8_string_size(nti_entry.get(), &dsize, nullptr) < 1)
			return;
		/* malloc: match up with allocator used by ext_buffer.cpp etc. */
		pnstr.reset(me_alloc<char>(dsize + 1));
		if (libpff_name_to_id_map_entry_get_utf8_string(nti_entry.get(), reinterpret_cast<uint8_t *>(pnstr.get()), dsize + 1, nullptr) < 1)
			return;
		pn_req.kind = MNID_STRING;
		pn_req.pname = pnstr.get();
	}
	map.emplace(PROP_TAG(vtype, etype), std::move(pn_req));
}

static void npg_set(gi_name_map &map, libpff_record_set_t *rset)
{
	int nent = 0;
	if (libpff_record_set_get_number_of_entries(rset, &nent, nullptr) < 1)
		return;
	for (int i = 0; i < nent; ++i) {
		libpff_record_entry_ptr rent;
		if (libpff_record_set_get_entry_by_index(rset, i,
		    &unique_tie(rent), nullptr) > 0)
			npg_ent(map, rent.get());
	}
}

static void npg_item(gi_name_map &map, libpff_item_t *item)
{
	uint32_t ident = 0;
	libpff_item_get_identifier(item, &ident, nullptr);
	int nsets = 0;
	if (libpff_item_get_number_of_record_sets(item, &nsets, nullptr) > 0) {
		for (int n = 0; n < nsets; ++n) {
			libpff_record_set_ptr rset;
			if (libpff_item_get_record_set_by_index(item, n,
			    &unique_tie(rset), nullptr) > 0)
				npg_set(map, rset.get());
		}
	}

	int nsub = 0, atype = 0;
	if (libpff_item_get_number_of_sub_items(item, &nsub, nullptr) > 0) {
		for (int i = 0; i < nsub; ++i) {
			libpff_item_ptr subitem;
			if (libpff_item_get_sub_item(item, i, &unique_tie(subitem), nullptr) > 0)
				npg_item(map, subitem.get());
		}
	}
	nsub = 0;
	if (libpff_message_get_number_of_attachments(item, &nsub, nullptr) > 0) {
		for (int i = 0; i < nsub; ++i) {
			libpff_item_ptr subitem;
			if (libpff_message_get_attachment(item, i, &unique_tie(subitem), nullptr) > 0)
				npg_item(map, subitem.get());
		}
	}
	if (libpff_attachment_get_type(item, &atype, nullptr) > 0 &&
	    atype == LIBPFF_ATTACHMENT_TYPE_ITEM) {
		libpff_item_ptr subitem;
		if (libpff_attachment_get_item(item, &unique_tie(subitem), nullptr) > 0)
			npg_item(map, subitem.get());
	}
	libpff_item_ptr subitem;
	if (libpff_message_get_recipients(item, &unique_tie(subitem), nullptr) > 0)
		npg_item(map, subitem.get());
}

static errno_t do_file(const char *filename) try
{
	libpff_error_ptr err;
	libpff_file_ptr file;
	if (libpff_file_initialize(&unique_tie(file), &unique_tie(err)) < 1) {
		fprintf(stderr, "%s\n", az_error("PF-1023", err).what());
		return EIO;
	}
	fprintf(stderr, "pff: Reading %s...\n", filename);
	errno = 0;
	if (libpff_file_open(file.get(), filename, LIBPFF_OPEN_READ,
	    &~unique_tie(err)) < 1) {
		auto se = errno;
		char buf[160];
		buf[0] = '\0';
		libpff_error_sprint(err.get(), buf, std::size(buf));
		if (*buf != '\0')
			fprintf(stderr, "pff: %s\n", buf);
		if (se != 0)
			fprintf(stderr, "pff: Could not open \"%s\": %s\n", filename, strerror(se));
		else
			fprintf(stderr, "pff: \"%s\" not recognized as PFF\n", filename);
		return ECANCELED;
	}
	int cpid = CP_ACP;
	if (libpff_file_get_ascii_codepage(file.get(), &cpid, &~unique_tie(err)) < 1)
		/* ignore */;
	if (cpid == CP_ACP)
		g_ascii_charset = "cp850"; /* make encoding problems visible */
	else if (cpid != CP_ACP)
		g_ascii_charset = cpid_to_cset(static_cast<cpid_t>(cpid));
	if (g_ascii_charset == nullptr) {
		fprintf(stderr, "pff: no charset for cpid %d\n", cpid);
		return ECANCELED;
	}

	uint8_t xsplice = g_splice;
	auto ret = HXio_fullwrite(STDOUT_FILENO, "GXMT0002", 8);
	if (ret < 0)
		throw YError("PF-1132: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, &xsplice, sizeof(xsplice));
	if (ret < 0)
		throw YError("PF-1133: %s", strerror(errno));
	/*
	 * There seems to be no way to export a public store hierarchy from
	 * EXC2019; you can only ever export individual "public folders"
	 * (folders within IPM_SUBTREE) via Outlook - but these have no special
	 * hierarchy anymore that is worth thinking about.
	 */
	xsplice = false; /* <=> not public store. */
	ret = HXio_fullwrite(STDOUT_FILENO, &xsplice, sizeof(xsplice));
	if (ret < 0)
		throw YError("PF-1134: %s", strerror(errno));
	g_folder_map.clear();
	if (g_splice) {
		az_fmap_splice_mst(file.get());
		az_fmap_splice_rft(file.get());
	} else {
		az_fmap_standard(file.get(), filename);
	}
	gi_dump_folder_map(g_folder_map);
	gi_folder_map_write(g_folder_map);

	libpff_item_ptr root;
	if (libpff_file_get_root_item(file.get(), &~unique_tie(root), &~unique_tie(err)) < 1)
		throw az_error("PF-1025", err);
	fprintf(stderr, "pff: Building list of named properties...\n");
	gi_name_map name_map;
	npg_item(name_map, root.get());
	gi_dump_name_map(name_map);
	gi_name_map_write(name_map);

	if (g_show_tree)
		fprintf(stderr, "Object tree:\n");
	if (g_only_objs.size() == 0)
		return do_item(0, {}, root.get());

	auto pd = parent_desc::as_folder(~0ULL);
	for (const auto nid : g_only_objs) {
		if (libpff_file_get_item_by_identifier(file.get(), nid,
		    &~unique_tie(root), &~unique_tie(err)) < 1)
			throw az_error("PF-1026", err);
		ret = do_item(0, pd, root.get());
		if (ret < 0)
			return ret;
	}
	return 0;
} catch (const char *e) {
	fprintf(stderr, "pff: Exception: %s\n", e);
	return ECANCELED;
} catch (const std::string &e) {
	fprintf(stderr, "pff: Exception: %s\n", e.c_str());
	return ECANCELED;
} catch (const std::exception &e) {
	fprintf(stderr, "pff: Exception: %s\n", e.what());
	return ECANCELED;
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-pff2mt [-pst] input.pst | gromox-mt2.... \n");
	fprintf(stderr, "Option overview: gromox-pff2mt -?\n");
	fprintf(stderr, "Documentation: man gromox-pff2mt\n");
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_with_hidden < 0)
		g_with_hidden = !g_splice;
	if (argc != 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);
	auto ret = do_file(argv[1]);
	if (ret != 0) {
		fprintf(stderr, "pff: Import unsuccessful.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
