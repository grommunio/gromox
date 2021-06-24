// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <libpff.h>
#include <mysql.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/tarray_set.hpp>
#include <gromox/tie.hpp>
#include <gromox/tpropval_array.hpp>
#include <gromox/util.hpp>

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
E(RESTRICTION, SRESTRICT)
E(RULE_ACTION, ACTIONS)
E(BINARY_DATA, BINARY)
#undef E

namespace {

struct afree {
	void operator()(ATTACHMENT_CONTENT *x) const { attachment_content_free(x); }
	void operator()(BINARY *x) const { rop_util_free_binary(x); }
	void operator()(MESSAGE_CONTENT *x) const { message_content_free(x); }
	void operator()(PCL *x) const { pcl_free(x); }
	void operator()(TPROPVAL_ARRAY *x) const { tpropval_array_free(x); }
};

struct libpff_error_del { void operator()(libpff_error_t *x) { libpff_error_free(&x); } };
struct libpff_file_del { void operator()(libpff_file_t *x) { libpff_file_free(&x, nullptr); } };
struct libpff_item_del { void operator()(libpff_item_t *x) { libpff_item_free(&x, nullptr); } };
struct libpff_record_set_del { void operator()(libpff_record_set_t *x) { libpff_record_set_free(&x, nullptr); } };
struct libpff_record_entry_del { void operator()(libpff_record_entry_t *x) { libpff_record_entry_free(&x, nullptr); } };
struct libpff_multi_value_del { void operator()(libpff_multi_value_t *x) { libpff_multi_value_free(&x, nullptr); } };
struct libpff_noop_del { void operator()(void *x) { } };

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

struct parent_desc {
	enum mapi_object_type type = MAPI_STORE; /* here: pseudo-value for "unset" */
	union {
		void *unknown = nullptr;
		uint64_t folder_id;
		MESSAGE_CONTENT *message;
		ATTACHMENT_CONTENT *attach;
	};

	static inline parent_desc as_msg(MESSAGE_CONTENT *m)
	{
		parent_desc d{MAPI_MESSAGE};
		d.message = m;
		return d;
	}
	static inline parent_desc as_attach(ATTACHMENT_CONTENT *a)
	{
		parent_desc d{MAPI_ATTACH};
		d.attach = a;
		return d;
	}
	static inline parent_desc as_folder(uint64_t id)
	{
		parent_desc d{MAPI_FOLDER};
		d.folder_id = id;
		return d;
	}
};

struct tgt_folder {
	bool create = false;
	uint64_t fid_to = 0;
	std::string create_name;
};

}

using namespace std::string_literals;
using namespace gromox;
namespace exmdb_client = exmdb_client_remote;
using libpff_error_ptr        = std::unique_ptr<libpff_error_t, libpff_error_del>;
using libpff_file_ptr         = std::unique_ptr<libpff_file_t, libpff_file_del>;
using libpff_item_ptr         = std::unique_ptr<libpff_item_t, libpff_item_del>;
using libpff_record_set_ptr   = std::unique_ptr<libpff_record_set_t, libpff_record_set_del>;
using libpff_record_entry_ptr = std::unique_ptr<libpff_record_entry_t, libpff_record_entry_del>;
using libpff_multi_value_ptr  = std::unique_ptr<libpff_multi_value_t, libpff_multi_value_del>;
using libpff_nti_entry_ptr    = std::unique_ptr<libpff_name_to_id_map_entry_t, libpff_noop_del>;

static std::unordered_map<uint32_t, tgt_folder> g_folder_map;
static std::unordered_map<uint16_t, uint16_t> g_propname_cache;
static char *g_username;
static std::string g_storedir_s;
static const char *g_storedir;
static unsigned int g_wet_run = 1, g_show_tree, g_user_id, g_show_props;
static const struct HXoption g_options_table[] = {
	{nullptr, 'n', HXTYPE_VAL, &g_wet_run, nullptr, nullptr, 0, "Dry run"},
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static int do_item(unsigned int, const parent_desc &, libpff_item_t *);

static int g_socket = -1;

static void tree(unsigned int depth)
{
	if (!g_show_tree)
		return;
	printf("%-*s \\_ ", depth * 4, "");
}

static void tlog(const char *fmt, ...)
{
	if (!g_show_tree)
		return;
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static int az_error(const char *prefix, const libpff_error_ptr &err)
{
	char buf[160];
	buf[0] = '\0';
	libpff_error_sprint(err.get(), buf, arsizeof(buf));
	fprintf(stderr, "%s: %s\n", prefix, buf);
	return 0;
}

static const char *az_item_type_to_str(uint8_t t)
{
	thread_local char buf[32];
	switch (t) {
	case LIBPFF_ITEM_TYPE_ACTIVITY: return "activity";
	case LIBPFF_ITEM_TYPE_APPOINTMENT: return "appointment";
	case LIBPFF_ITEM_TYPE_ATTACHMENT: return "atx";
	case LIBPFF_ITEM_TYPE_CONTACT: return "contact";
	case LIBPFF_ITEM_TYPE_DISTRIBUTION_LIST: return "dlist";
	case LIBPFF_ITEM_TYPE_DOCUMENT: return "document";
	case LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE: return "conflict message";
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
    libpff_record_set_t **rset, libpff_record_entry_t **rent)
{
	auto ret = libpff_item_get_record_set_by_index(item, 0, rset, nullptr);
	if (ret <= 0)
		return false;
	uint8_t flags = PROP_TYPE(proptag) == PT_UNSPECIFIED ?
	                LIBPFF_ENTRY_VALUE_FLAG_MATCH_ANY_VALUE_TYPE : 0;
	ret = libpff_record_set_get_entry_by_type(*rset, PROP_ID(proptag),
	      PROP_TYPE(proptag), rent, flags, nullptr);
	if (ret < 0)
		throw "PF-1001";
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

/* Obtain a string value from a libpff item's property */
static std::string az_item_get_str(libpff_item_t *item, uint32_t proptag)
{
	libpff_record_set_ptr rset;
	libpff_record_entry_ptr rent;

	auto ret = az_item_get_propv(item, CHANGE_PROP_TYPE(proptag, PT_UNSPECIFIED),
	           &unique_tie(rset), &unique_tie(rent));
	if (ret == 0)
		return {};
	size_t dsize = 0;
	if (libpff_record_entry_get_data_as_utf8_string_size(rent.get(), &dsize, nullptr) < 1)
		throw "PF-1026";
	++dsize;
	auto buf = std::make_unique<uint8_t[]>(dsize);
	if (libpff_record_entry_get_data_as_utf8_string(rent.get(), buf.get(), dsize, nullptr) < 1)
		throw "PF-1002";
	return reinterpret_cast<char *>(buf.get());
}

/* Pretty-print a libpff record entry (property) */
static void az_recordent(unsigned int depth, libpff_record_entry_t *rent)
{
	uint32_t etype = 0, vtype = 0;
	size_t size = 0;

	if (libpff_record_entry_get_entry_type(rent, &etype, nullptr) < 1)
		throw "PF-1005";
	if (libpff_record_entry_get_value_type(rent, &vtype, nullptr) < 1)
		throw "PF-1006";
	if (libpff_record_entry_get_data_size(rent, &size, nullptr) < 1)
		throw "PF-1007";
	if (g_show_props)
		tree(depth);
	tlog("%08xh:", static_cast<unsigned int>((etype << 16) | vtype));
	switch (vtype) {
	case LIBPFF_VALUE_TYPE_INTEGER_32BIT_SIGNED: {
		uint32_t v;
		if (libpff_record_entry_get_data_as_32bit_integer(rent, &v, nullptr) < 1)
			throw "PF-1008";
		tlog("%u", v);
		break;
	}
	case LIBPFF_VALUE_TYPE_BOOLEAN: {
		uint8_t v = 0;
		if (libpff_record_entry_get_data_as_boolean(rent, &v, nullptr) < 1)
			throw "PF-1009";
		tlog("%u", v);
		break;
	}
	case LIBPFF_VALUE_TYPE_STRING_ASCII: {
		size_t dsize = 0;
		if (g_show_props &&
		    libpff_record_entry_get_data_as_utf8_string_size(rent, &dsize, nullptr) >= 1) {
			++dsize;
			auto buf = std::make_unique<uint8_t[]>(dsize);
			if (libpff_record_entry_get_data_as_utf8_string(rent, buf.get(), dsize, nullptr) >= 1)
				tlog("astr(%zu)=\"%s\"", size, buf.get());
		} else {
			tlog("astr(%zu)", size);
		}
		break;
	}
	case LIBPFF_VALUE_TYPE_STRING_UNICODE: {
		size_t dsize = 0;
		if (g_show_props &&
		    libpff_record_entry_get_data_as_utf8_string_size(rent, &dsize, nullptr) >= 1) {
			++dsize;
			auto buf = std::make_unique<uint8_t[]>(dsize);
			if (libpff_record_entry_get_data_as_utf8_string(rent, buf.get(), dsize, nullptr) >= 1)
				tlog("wstr(%zu)=\"%s\"", size / 2, buf.get());
		} else {
			tlog("wstr(%zu)", size / 2);
		}
		break;
	}
	case LIBPFF_VALUE_TYPE_BINARY_DATA: {
		auto buf = std::make_unique<uint8_t[]>(size);
		if (g_show_props &&
		    libpff_record_entry_get_data(rent, buf.get(), size, nullptr) >= 1)
			tlog("bin(%zu)=%s", size, bin2hex(buf.get(), size).c_str());
		else
			tlog("bin(%zu)", size);
		break;
	}
	case LIBPFF_VALUE_TYPE_MULTI_VALUE_INTEGER_16BIT_SIGNED ... LIBPFF_VALUE_TYPE_MULTI_VALUE_BINARY_DATA: {
		libpff_multi_value_ptr mv;
		int numv = 0;
		if (libpff_record_entry_get_multi_value(rent, &unique_tie(mv), nullptr) < 1)
			throw "PF-1038";
		if (libpff_multi_value_get_number_of_values(mv.get(), &numv, nullptr) < 1)
			throw "PF-1039";
		auto buf = std::make_unique<uint8_t[]>(size);
		if (g_show_props &&
		    libpff_record_entry_get_data(rent, buf.get(), size, nullptr) >= 1)
			tlog("mv[%d]-arb(%zu)=%s", numv, size, bin2hex(buf.get(), size).c_str());
		else
			tlog("mv[%d]-arb(%zu)", numv, size);
		break;
	}
	default:
		break;
	}
	tlog(g_show_props ? "\n" : ", ");
}

/* Pretty-print a libpff record set (property set) */
static void az_recordset(unsigned int depth, libpff_record_set_t *rset)
{
	int nent = 0;
	if (libpff_record_set_get_number_of_entries(rset, &nent, nullptr) < 1)
		throw "PF-1010";
	tree(depth);
	tlog("props(%d):", nent);
	tlog(g_show_props ? "\n" : " {");
	for (int i = 0; i < nent; ++i) {
		libpff_record_entry_ptr rent;

		if (libpff_record_set_get_entry_by_index(rset, i, &unique_tie(rent), nullptr) < 1)
			throw "PF-1011";
		az_recordent(depth + 1, rent.get());
	}
	if (!g_show_props)
		tlog("}\n");
}

static int do_attach(unsigned int depth, ATTACHMENT_CONTENT *atc, libpff_item_t *atx)
{
	int atype = 0;
	uint64_t asize = 0;
	libpff_error_ptr err;

	if (libpff_attachment_get_type(atx, &atype, &unique_tie(err)) < 1)
		return az_error("PF-1012: Attachment is corrupted", err);
	tree(depth);
	if (atype == LIBPFF_ATTACHMENT_TYPE_DATA) {
		if (libpff_attachment_get_data_size(atx, &asize, &unique_tie(err)) < 1)
			return az_error("PF-1013: Attachment is corrupted", err);
		/*
		 * Data is in PR_ATTACH_DATA_BIN, and so was
		 * already spooled into atc->proplist by the caller.
		 */
		tlog("[attachment type=%c size=%zu]\n", atype, asize);
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_ITEM) {
		libpff_item_ptr emb_item;
		if (libpff_attachment_get_item(atx, &unique_tie(emb_item),
		    &unique_tie(err)) < 1)
			return az_error("PF-1014: Attachment is corrupted", err);
		tlog("[attachment type=%c embedded_msg]\n", atype);
		auto ret = do_item(depth + 1, parent_desc::as_attach(atc), emb_item.get());
		if (ret < 0)
			return ret;
	} else if (atype == LIBPFF_ATTACHMENT_TYPE_REFERENCE) {
		tlog("[attachment type=%c]\n", atype);
		return -EOPNOTSUPP;
	} else {
		tlog("[attachment type=unknown]\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

static std::string sql_escape(MYSQL *sqh, const char *in)
{
	std::string out;
	out.resize(strlen(in) * 2 + 1);
	auto ret = mysql_real_escape_string(sqh, out.data(), in, strlen(in));
	out.resize(ret);
	return out;
}

static MYSQL *sql_login()
{
	auto cfg = config_file_initd("mysql_adaptor.cfg", PKGSYSCONFDIR);
	if (cfg == nullptr) {
		fprintf(stderr, "No mysql_adaptor.cfg: %s\n", strerror(errno));
		return nullptr;
	}
	auto sql_host = config_file_get_value(cfg, "mysql_host");
	auto v = config_file_get_value(cfg, "mysql_port");
	auto sql_port = v != nullptr ? strtoul(v, nullptr, 0) : 0;
	auto sql_user = config_file_get_value(cfg, "mysql_username");
	if (sql_user == nullptr)
		sql_user = "root";
	auto sql_pass = config_file_get_value(cfg, "mysql_password");
	auto sql_dbname = config_file_get_value(cfg, "mysql_dbname");
	if (sql_dbname == nullptr)
		sql_dbname = "email";
	auto conn = mysql_init(nullptr);
	if (conn == nullptr) {
		fprintf(stderr, "mysql_init failed\n");
		return nullptr;
	}
	mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	if (mysql_real_connect(conn, sql_host, sql_user, sql_pass, sql_dbname,
	    sql_port, nullptr, 0) != nullptr)
		return conn;
	fprintf(stderr, "Failed to connect to SQL %s@%s: %s\n",
	        sql_user, sql_host, mysql_error(conn));
	mysql_close(conn);
	return nullptr;
}

static int sql_meta(MYSQL *sqh, const char *username, unsigned int *user_id,
    std::string &storedir) try
{
	auto query = "SELECT id, maildir FROM users WHERE username='" +
	             sql_escape(sqh, username) + "'";
	if (mysql_real_query(sqh, query.c_str(), query.size()) != 0) {
		fprintf(stderr, "mysql_query: %s\n", mysql_error(sqh));
		return -EINVAL;
	}
	DB_RESULT result = mysql_store_result(sqh);
	if (result == nullptr) {
		fprintf(stderr, "mysql_store: %s\n", mysql_error(sqh));
		return -ENOENT;
	}
	auto row = result.fetch_row();
	if (row == nullptr)
		return -ENOENT;
	*user_id = strtoul(row[0], nullptr, 0);
	storedir = row[1] != nullptr ? row[1] : "";
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

static BOOL exm_dorpc(const char *dir, const EXMDB_REQUEST *prequest, EXMDB_RESPONSE *presponse)
{
	BINARY tb;
	if (exmdb_ext_push_request(prequest, &tb) != EXT_ERR_SUCCESS)
		return FALSE;
	if (!exmdb_client_write_socket(g_socket, &tb)) {
		free(tb.pb);
		return FALSE;
	}
	free(tb.pb);
	if (!exmdb_client_read_socket(g_socket, &tb))
		return FALSE;
	auto cl_0 = make_scope_exit([&]() { free(tb.pb); });
	if (tb.cb < 5 || tb.pb[0] != exmdb_response::SUCCESS)
		return FALSE;
	presponse->call_id = prequest->call_id;
	BINARY tb2 = tb;
	tb2.cb -= 5;
	tb2.pb += 5;
	return exmdb_ext_pull_response(&tb2, presponse) == EXT_ERR_SUCCESS ? TRUE : false;
}

static int exm_connect(const char *dir)
{
	std::vector<EXMDB_ITEM> exmlist;
	auto ret = list_file_read_exmdb("exmdb_list.txt", PKGSYSCONFDIR, exmlist);
	if (ret < 0) {
		fprintf(stderr, "[exmdb_client]: list_file_read_exmdb: %s\n", strerror(-ret));
		return ret;
	}
	auto xn = std::find_if(exmlist.begin(), exmlist.end(),
	          [&](const EXMDB_ITEM &s) { return strncmp(s.prefix.c_str(), dir, s.prefix.size()) == 0; });
	if (xn == exmlist.end()) {
		fprintf(stderr, "No target for %s\n", dir);
		return -ENOENT;
	}
	wrapfd fd(gx_inet_connect(xn->host.c_str(), xn->port, 0));
	if (fd.get() < 0) {
		fprintf(stderr, "gx_inet_connect pffimport@[%s]:%hu: %s\n",
		        xn->host.c_str(), xn->port, strerror(-fd.get()));
		return -errno;
	}
	exmdb_rpc_exec = exm_dorpc;

	char rid[64];
	snprintf(rid, GX_ARRAY_SIZE(rid), "pffimport:%ld", static_cast<long>(getpid()));
	EXMDB_REQUEST rq;
	rq.call_id = exmdb_callid::CONNECT;
	rq.payload.connect.prefix    = deconst(xn->prefix.c_str());
	rq.payload.connect.remote_id = rid;
	rq.payload.connect.b_private = TRUE;
	BINARY tb{};
	if (exmdb_ext_push_request(&rq, &tb) != EXT_ERR_SUCCESS ||
	    !exmdb_client_write_socket(fd.get(), &tb)) {
		fprintf(stderr, "Protocol failure\n");
		return -1;
	}
	free(tb.pb);
	if (!exmdb_client_read_socket(fd.get(), &tb)) {
		fprintf(stderr, "Protocol failure\n");
		return -1;
	}
	auto cl_0 = make_scope_exit([&]() { free(tb.pb); });
	auto response_code = tb.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (tb.cb != 5) {
			fprintf(stderr, "response format error during connect to "
				"[%s]:%hu/%s\n", xn->host.c_str(),
				xn->port, xn->prefix.c_str());
			return -1;
		}
		return fd.release();
	}
	fprintf(stderr, "Failed to connect to [%s]:%hu/%s: %s\n",
	        xn->host.c_str(), xn->port, xn->prefix.c_str(), exmdb_rpc_strerror(response_code));
	return -1;
}

static int az_resolve_inplace(libpff_record_entry_t *rent, uint32_t &proptag)
{
	if (!g_wet_run)
		return 0;
	auto it = g_propname_cache.find(proptag);
	if (it != g_propname_cache.end()) {
		proptag = PROP_TAG(PROP_TYPE(proptag), it->second);
		return 0;
	}

	libpff_nti_entry_ptr nti_entry;
	uint8_t nti_type = 0;
	if (libpff_record_entry_get_name_to_id_map_entry(rent, &unique_tie(nti_entry), nullptr) < 1)
		return 0;
	if (libpff_name_to_id_map_entry_get_type(nti_entry.get(), &nti_type, nullptr) < 1)
		return 0;

	std::unique_ptr<char[]> pnstr;
	PROPERTY_NAME pn_req{};
	PROPNAME_ARRAY pna_req;
	pna_req.count = 1;
	pna_req.ppropname = &pn_req;

	if (libpff_name_to_id_map_entry_get_guid(nti_entry.get(),
	    reinterpret_cast<uint8_t *>(&pn_req.guid), sizeof(pn_req.guid), nullptr) < 1)
		return 0;

	if (nti_type == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_NUMERIC) {
		if (libpff_name_to_id_map_entry_get_number(nti_entry.get(), &pn_req.lid, nullptr) < 1)
			return -EIO;
		pn_req.kind = MNID_ID;
	} else if (nti_type == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_STRING) {
		size_t dsize = 0;
		if (libpff_name_to_id_map_entry_get_utf8_string_size(nti_entry.get(), &dsize, nullptr) < 1)
			return 0;
		try {
			pnstr = std::make_unique<char[]>(dsize + 1);
		} catch (const std::bad_alloc &) {
			return -ENOMEM;
		}
		if (libpff_name_to_id_map_entry_get_utf8_string(nti_entry.get(), reinterpret_cast<uint8_t *>(pnstr.get()), dsize + 1, nullptr) < 1)
			return -EIO;
		pn_req.kind = MNID_STRING;
		pn_req.pname = pnstr.get();
	} else {
		fprintf(stderr, "PF-1046: unable to handle libpff propname type %xh\n", nti_type);
		return -EOPNOTSUPP;
	}

	PROPID_ARRAY pid_rsp{};
	if (!exmdb_client::get_named_propids(g_storedir, TRUE, &pna_req, &pid_rsp)) {
		fprintf(stderr, "PF-1047: request to server for propname mapping failed\n");
		return -EIO;
	}
	if (pid_rsp.count != 1) {
		fprintf(stderr, "PF-1048\n");
		return -EIO;
	}
	try {
		g_propname_cache.emplace(PROP_ID(proptag), pid_rsp.ppropid[0]);
	} catch (const std::bad_alloc &) {
		return -ENOMEM;
	}
	proptag = PROP_TAG(PROP_TYPE(proptag), pid_rsp.ppropid[0]);
	return 0;
}

static int recordent_to_tpropval(libpff_record_entry_t *rent, TPROPVAL_ARRAY *ar)
{
	libpff_multi_value_ptr mv;
	unsigned int etype = 0, vtype = 0;
	size_t dsize = 0;
	int mvnum = 0;

	if (libpff_record_entry_get_entry_type(rent, &etype, nullptr) < 1)
		throw "PF-1030";
	if (libpff_record_entry_get_value_type(rent, &vtype, nullptr) < 1)
		throw "PF-1031";
	if (libpff_record_entry_get_data_size(rent, &dsize, nullptr) < 1)
		throw "PF-1032";

	TAGGED_PROPVAL pv;
	pv.proptag = PROP_TAG(vtype, etype);
	auto ret = az_resolve_inplace(rent, pv.proptag);
	if (ret < 0)
		return ret;
	auto buf = std::make_unique<uint8_t[]>(dsize + 1);
	if (dsize == 0)
		buf[0] = '\0';
	else if (libpff_record_entry_get_data(rent, buf.get(), dsize + 1, nullptr) < 1)
		throw "PF-1033";
	if (vtype & LIBPFF_VALUE_TYPE_MULTI_VALUE_FLAG) {
		if (libpff_record_entry_get_multi_value(rent, &unique_tie(mv), nullptr) < 1)
			throw "PF-1034";
		if (libpff_multi_value_get_number_of_values(mv.get(), &mvnum, nullptr) < 1)
			throw "PF-1035";
		if (dsize > 4 && mvnum == 0) {
			/* See also MS-PST 2.3.3.4.2 */
			fprintf(stderr, "Broken PFF file: Multivalue property %xh with 0 items, but still with size %zu.\n",
			        pv.proptag, dsize);
			return 0;
		}
	}

	union {
		GUID guid;
		BINARY bin;
		SHORT_ARRAY sa;
		LONG_ARRAY la;
		LONGLONG_ARRAY lla;
	} u;
	pv.pvalue = buf.get();
	switch (vtype) {
	case PT_SHORT:
		if (dsize == sizeof(uint16_t))
			break;
		fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
		return -EINVAL;
	case PT_LONG:
		if (dsize == sizeof(uint32_t))
			break;
		fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
		return -EINVAL;
	case PT_I8:
	case PT_SYSTIME:
		if (dsize == sizeof(uint64_t))
			break;
		fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
		return -EINVAL;
	case PT_FLOAT:
		if (dsize == sizeof(float))
			break;
		fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
		return -EINVAL;
	case PT_DOUBLE:
	case PT_APPTIME:
		if (dsize == sizeof(double))
			break;
		fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
		return -EINVAL;
	case PT_BOOLEAN:
		if (dsize == sizeof(uint8_t))
			break;
		fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
		return -EINVAL;
	case PT_STRING8:
	case PT_UNICODE: {
		libpff_error_ptr err;
		size_t dsize2 = 0;
		if (libpff_record_entry_get_data_as_utf8_string_size(rent, &dsize2, &unique_tie(err)) >= 1) {
			++dsize2;
			buf = std::make_unique<uint8_t[]>(dsize2);
			if (libpff_record_entry_get_data_as_utf8_string(rent, buf.get(), dsize2, nullptr) < 1)
				throw "PF-1036";
		} else {
			fprintf(stderr, "PF-1041: Garbage in Unicode string\n");
			auto s = iconvtext(reinterpret_cast<char *>(buf.get()), dsize, "UTF-16", "UTF-8//IGNORE");
			dsize = s.size() + 1;
			buf = std::make_unique<uint8_t[]>(dsize);
			memcpy(buf.get(), s.data(), dsize);
		}
		pv.pvalue = buf.get();
		break;
	}
	case PT_BINARY:
		u.bin.cb = dsize;
		u.bin.pv = buf.get();
		pv.pvalue = &u.bin;
		break;
	case PT_CLSID:
		if (dsize != sizeof(u.guid))
			throw "PF-1040: GUID size incorrect " + std::to_string(dsize);
		memcpy(&u.guid, buf.get(), sizeof(u.guid));
		pv.pvalue = &u.guid;
		break;
	case PT_MV_SHORT:
		if (dsize != mvnum * sizeof(uint16_t)) {
			fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
			return -EINVAL;
		}
		u.sa.count = mvnum;
		u.sa.ps = reinterpret_cast<uint16_t *>(buf.get());
		pv.pvalue = &u.sa;
		break;
	case PT_MV_LONG:
		if (dsize != mvnum * sizeof(uint32_t)) {
			fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
			return -EINVAL;
		}
		u.la.count = mvnum;
		u.la.pl = reinterpret_cast<uint32_t *>(buf.get());
		pv.pvalue = &u.la;
		break;
	case PT_MV_I8:
	case PT_MV_SYSTIME:
		if (dsize != mvnum * sizeof(uint64_t)) {
			fprintf(stderr, "Datasize mismatch on %xh\n", pv.proptag);
			return -EINVAL;
		}
		u.lla.count = mvnum;
		u.lla.pll = reinterpret_cast<uint64_t *>(buf.get());
		pv.pvalue = &u.lla;
		break;
	case PT_OBJECT:
		if (pv.proptag == PR_ATTACH_DATA_OBJ)
			return 0; /* Embedded message, which separately handled. */
		fprintf(stderr, "Unsupported proptag %xh (datasize %zu). Implement me!\n",
		        pv.proptag, dsize);
		return -EOPNOTSUPP;
	default:
		fprintf(stderr, "Unsupported proptype %xh (datasize %zu). Implement me!\n",
		        pv.proptag, dsize);
		return -EOPNOTSUPP;
	}
	if (!tpropval_array_set_propval(ar, &pv))
		return -ENOMEM;
	return 0;
}

static int recordset_to_tpropval_a(libpff_record_set_t *rset, TPROPVAL_ARRAY *props)
{
	int nent = 0;
	if (libpff_record_set_get_number_of_entries(rset, &nent, nullptr) < 1)
		throw "PF-1028";
	for (int i = 0; i < nent; ++i) {
		libpff_record_entry_ptr rent;

		if (libpff_record_set_get_entry_by_index(rset, i, &unique_tie(rent), nullptr) < 1)
			throw "PF-1029";
		auto ret = recordent_to_tpropval(rent.get(), props);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int exm_create_folder(unsigned int depth, uint64_t parent_fld,
    TPROPVAL_ARRAY *props, uint64_t *new_fld_id)
{
	uint64_t change_num = 0;
	if (!exmdb_client::allocate_cn(g_storedir, &change_num)) {
		fprintf(stderr, "allocate_cn RPC failed\n");
		return -EIO;
	}
	SIZED_XID zxid;
	char tmp_buff[22];
	BINARY bxid;
	zxid.size = 22;
	zxid.xid.guid = rop_util_make_user_guid(g_user_id);
	rop_util_value_to_gc(change_num, zxid.xid.local_id);
	EXT_PUSH ep;
	if (!ep.init(tmp_buff, sizeof(tmp_buff), 0) ||
	    ep.p_xid(22, &zxid.xid) != EXT_ERR_SUCCESS) {
		fprintf(stderr, "ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.offset;
	std::unique_ptr<PCL, afree> pcl(pcl_init());
	if (pcl == nullptr) {
		fprintf(stderr, "pcl_init: ENOMEM\n");
		return -ENOMEM;
	}
	if (!pcl_append(pcl.get(), &zxid)) {
		fprintf(stderr, "pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, afree> pclbin(pcl_serialize(pcl.get()));
	if (pclbin == nullptr){
		fprintf(stderr, "pcl_serialize: ENOMEM\n");
		return -ENOMEM;
	}
	if (!tpropval_array_set_propval(props, PROP_TAG_PARENTFOLDERID, &parent_fld) ||
	    !tpropval_array_set_propval(props, PROP_TAG_CHANGENUMBER, &change_num) ||
	    !tpropval_array_set_propval(props, PR_CHANGE_KEY, &bxid) ||
	    !tpropval_array_set_propval(props, PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) {
		fprintf(stderr, "tpropval: ENOMEM\n");
		return -ENOMEM;
	}
	if (!exmdb_client::create_folder_by_properties(g_storedir, 0, props, new_fld_id)) {
		fprintf(stderr, "create_folder_by_properties RPC failed\n");
		return -EIO;
	}
	if (*new_fld_id == 0) {
		auto dn = tpropval_array_get_propval(props, PR_DISPLAY_NAME);
		fprintf(stderr, "createfolder: folder \"%s\" already existed\n",
		       dn != nullptr ? static_cast<char *>(dn) : "<ERROR>");
		return -EEXIST;
	}
	return 0;
}

static int exm_create_msg(uint64_t parent_fld, MESSAGE_CONTENT *ctnt)
{
	uint64_t msg_id = 0, change_num = 0;
	if (!exmdb_client::allocate_message_id(g_storedir, parent_fld, &msg_id)) {
		fprintf(stderr, "allocate_message_id RPC failed (timeout?)\n");
		return -EIO;
	} else if (!exmdb_client::allocate_cn(g_storedir, &change_num)) {
		fprintf(stderr, "allocate_cn RPC failed\n");
		return -EIO;
	}

	SIZED_XID zxid;
	char tmp_buff[22];
	BINARY bxid;
	zxid.size = 22;
	zxid.xid.guid = rop_util_make_user_guid(g_user_id);
	rop_util_value_to_gc(change_num, zxid.xid.local_id);
	EXT_PUSH ep;
	if (!ep.init(tmp_buff, sizeof(tmp_buff), 0) ||
	    ep.p_xid(22, &zxid.xid) != EXT_ERR_SUCCESS) {
		fprintf(stderr, "ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.offset;
	std::unique_ptr<PCL, afree> pcl(pcl_init());
	if (pcl == nullptr) {
		fprintf(stderr, "pcl_init: ENOMEM\n");
		return -ENOMEM;
	}
	if (!pcl_append(pcl.get(), &zxid)) {
		fprintf(stderr, "pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, afree> pclbin(pcl_serialize(pcl.get()));
	if (pclbin == nullptr){
		fprintf(stderr, "pcl_serialize: ENOMEM\n");
		return -ENOMEM;
	}
	auto props = &ctnt->proplist;
	if (!tpropval_array_set_propval(props, PROP_TAG_MID, &msg_id) ||
	    !tpropval_array_set_propval(props, PROP_TAG_CHANGENUMBER, &change_num) ||
	    !tpropval_array_set_propval(props, PR_CHANGE_KEY, &bxid) ||
	    !tpropval_array_set_propval(props, PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) {
		fprintf(stderr, "tpropval: ENOMEM\n");
		return -ENOMEM;
	}
	gxerr_t e_result = GXERR_SUCCESS;
	if (!exmdb_client::write_message(g_storedir, g_username, 65001,
	    parent_fld, ctnt, &e_result)) {
		fprintf(stderr, "write_message RPC failed\n");
		return -EIO;
	} else if (e_result != 0) {
		fprintf(stderr, "write_message: gxerr %d\n", e_result);
		return -EIO;
	}
	return 0;
}

/* Process an arbitrary PFF item (folder, message, recipient table, attachment, ...) */
static int do_item2(unsigned int depth, const parent_desc &parent,
    libpff_item_t *item, unsigned int item_type, uint32_t ident, int nsets,
    uint64_t *new_fld_id)
{
	std::unique_ptr<TPROPVAL_ARRAY, afree> props(tpropval_array_init());
	if (props == nullptr) {
		fprintf(stderr, "tpropval_array_init: ENOMEM\n");
		return -ENOMEM;
	}

	for (int s = 0; s < nsets; ++s) {
		libpff_record_set_ptr rset;

		if (libpff_item_get_record_set_by_index(item, s, &unique_tie(rset), nullptr) < 1)
			throw "PF-1022";
		if (g_show_tree)
			az_recordset(depth, rset.get());
		auto ret = recordset_to_tpropval_a(rset.get(), props.get());
		if (ret < 0)
			return ret;
		if (item_type != LIBPFF_ITEM_TYPE_RECIPIENTS)
			/* For folders, messages, attachments, etc. keep properties in @props. */
			continue;

		/* Turn this property set into a "recipient". */
		assert(parent.type == MAPI_MESSAGE);
		if (!tarray_set_append_internal(parent.message->children.prcpts, props.get())) {
			fprintf(stderr, "tarray_set_append: ENOMEM\n");
			return -ENOMEM;
		}
		props.release();
		props.reset(tpropval_array_init());
		if (props == nullptr) {
			fprintf(stderr, "tpropval_array_init: ENOMEM\n");
			return -ENOMEM;
		}
	}

	if (g_wet_run && item_type == LIBPFF_ITEM_TYPE_FOLDER) {
		auto iter = g_folder_map.find(ident);
		if (iter == g_folder_map.end() && parent.type == MAPI_FOLDER) {
			/* PST folder with name -> new folder in store */
			auto ret = exm_create_folder(depth, parent.folder_id, props.get(), new_fld_id);
			if (ret < 0)
				return ret;
		} else if (iter == g_folder_map.end()) {
			/* No @parent for writing the item anywhere, and no hints in map => do not create. */
		} else if (!iter->second.create) {
			/* Splice request (e.g. PST wastebox -> Store wastebox) */
			*new_fld_id = iter->second.fid_to;
		} else {
			/* Create request (e.g. PST root without name -> new folder in store with name) */
			if (!tpropval_array_set_propval(props.get(), PR_DISPLAY_NAME,
			    iter->second.create_name.c_str())) {
				fprintf(stderr, "tpropval: ENOMEM\n");
				return -ENOMEM;
			}
			auto ret = exm_create_folder(depth, iter->second.fid_to,
			           props.get(), new_fld_id);
			if (ret < 0)
				return ret;
		}
	} else if (item_type == LIBPFF_ITEM_TYPE_ATTACHMENT) {
		std::unique_ptr<ATTACHMENT_CONTENT, afree> atc(attachment_content_init());
		if (atc == nullptr) {
			fprintf(stderr, "attachment_content_init: ENOMEM\n");
			return -ENOMEM;
		}
		std::swap(atc->proplist.count, props->count);
		std::swap(atc->proplist.ppropval, props->ppropval);
		auto ret = do_attach(depth, atc.get(), item);
		if (ret < 0)
			return ret;
		if (parent.type == MAPI_MESSAGE) {
			if (!attachment_list_append_internal(parent.message->children.pattachments, atc.get())) {
				fprintf(stderr, "attachment_list_append_internal: ENOMEM\n");
				return -ENOMEM;
			}
			atc.release();
		}
	}

	/*
	 * Unconditionally parse recipients/attachments into @ctnt. If it is
	 * not a message, it just gets freed without being sent to the server.
	 */
	std::unique_ptr<MESSAGE_CONTENT, afree> ctnt(message_content_init());
	if (ctnt == nullptr) {
		fprintf(stderr, "message_content_init: ENOMEM\n");
		return -ENOMEM;
	}
	ctnt->children.pattachments = attachment_list_init();
	if (ctnt->children.pattachments == nullptr) {
		fprintf(stderr, "attachment_list_init: ENOMEM\n");
		return -ENOMEM;
	}
	ctnt->children.prcpts = tarray_set_init();
	if (ctnt->children.prcpts == nullptr) {
		fprintf(stderr, "tarray_set_init: ENOMEM\n");
		return -ENOMEM;
	}
	std::swap(ctnt->proplist.count, props->count);
	std::swap(ctnt->proplist.ppropval, props->ppropval);

	libpff_item_ptr recip_set;
	if (libpff_message_get_recipients(item, &unique_tie(recip_set), nullptr) >= 1) {
		auto ret = do_item(depth + 1, parent_desc::as_msg(ctnt.get()), recip_set.get());
		if (ret < 0)
			return ret;
	}

	int atnum = 0;
	if (libpff_message_get_number_of_attachments(item, &atnum, nullptr) >= 1) {
		for (int atidx = 0; atidx < atnum; ++atidx) {
			libpff_item_ptr atx;
			if (libpff_message_get_attachment(item, atidx, &unique_tie(atx), nullptr) < 1)
				throw "PF-1017";
			auto ret = do_item(depth, parent_desc::as_msg(ctnt.get()), atx.get());
			if (ret < 0)
				return ret;
		}
	}

	auto name = az_item_get_str(item, PR_DISPLAY_NAME);
	if (g_show_tree) {
		if (!name.empty()) {
			tree(depth);
			tlog("display_name=\"%s\"\n", name.c_str());
		}
		name = az_item_get_str(item, PR_SUBJECT);
		if (!name.empty()) {
			tree(depth);
			tlog("subject=\"%s\"\n", name.c_str());
		}
		name = az_item_get_str(item, PR_ATTACH_LONG_FILENAME);
		if (!name.empty()) {
			tree(depth);
			tlog("filename=\"%s\"\n", name.c_str());
		}
	} else if (item_type == LIBPFF_ITEM_TYPE_FOLDER &&
	    (parent.type == MAPI_FOLDER || *new_fld_id != 0)) {
		printf("Processing folder \"%s\"...\n", name.c_str());
	}

	if (!is_mapi_message(ident))
		return 0;
	if (g_wet_run && parent.type == MAPI_FOLDER)
		return exm_create_msg(parent.folder_id, ctnt.get());
	if (parent.type == MAPI_ATTACH)
		attachment_content_set_embedded_internal(parent.attach, ctnt.release());
	return 0;
}

/* General look at an (arbitrary) PFF item */
static int do_item(unsigned int depth, const parent_desc &parent, libpff_item_t *item)
{
	uint32_t ident = 0, nent = 0;
	uint8_t item_type = LIBPFF_ITEM_TYPE_UNDEFINED;
	int nsets = 0;

	if (libpff_item_get_identifier(item, &ident, nullptr) < 1)
		throw "PF-1018";
	libpff_item_get_type(item, &item_type, nullptr);
	libpff_item_get_number_of_record_sets(item, &nsets, nullptr);
	if (g_show_tree) {
		libpff_item_get_number_of_entries(item, &nent, nullptr);
		tree(depth);
		auto sp_nid = az_special_ident(ident);
		tlog("[id=%lxh%s%s type=%s nent=%lu nset=%d]\n",
		        static_cast<unsigned long>(ident),
		        *sp_nid != '\0' ? " " : "", sp_nid,
		        az_item_type_to_str(item_type),
		        static_cast<unsigned long>(nent), nsets);
	}

	++depth;
	/*
	 * If folder: collect props and create.
	 * If message: collect props and recurse into recipient sets & attachments...
	 */
	uint64_t new_fld_id = 0;
	auto ret = do_item2(depth, parent, item, item_type, ident, nsets, &new_fld_id);
	if (ret < 0)
		return ret;
	auto new_parent = parent;
	if (new_fld_id != 0) {
		new_parent.type = MAPI_FOLDER;
		new_parent.folder_id = new_fld_id;
	}

	/*
	 * Subitems usually consist exclusively of messages (<=> attachments
	 * are not subitems, even if they are nested (sub) within a message).
	 */
	int nsub = 0;
	if (libpff_item_get_number_of_sub_items(item, &nsub, nullptr) < 1)
		throw "PF-1003";
	for (int i = 0; i < nsub; ++i) {
		libpff_item_ptr subitem;
		if (libpff_item_get_sub_item(item, i, &unique_tie(subitem), nullptr) < 1)
			throw "PF-1004";
		ret = do_item(depth, new_parent, subitem.get());
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int do_file(const char *filename) try
{
	libpff_error_ptr err;
	libpff_file_ptr file;
	if (libpff_file_initialize(&unique_tie(file), &unique_tie(err)) < 1) {
		az_error("PF-1023", err);
		return -EIO;
	}
	fprintf(stderr, "Reading %s...\n", filename);
	if (libpff_file_open(file.get(), filename, LIBPFF_OPEN_READ, nullptr) < 1) {
		int s = errno;
		fprintf(stderr, "Could not open \"%s\": %s\n", filename, strerror(s));
		return -(errno = s);
	}

	g_propname_cache.clear();
	if (g_wet_run)
		fprintf(stderr, "Transferring objects...\n");

	char timebuf[64];
	time_t now = time(nullptr);
	auto tm = localtime(&now);
	strftime(timebuf, GX_ARRAY_SIZE(timebuf), " @%FT%T", tm);

	g_folder_map.clear();
	g_folder_map.emplace(NID_ROOT_FOLDER, tgt_folder{true, rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE),
		"Import of "s + HX_basename(filename) + timebuf});

	libpff_item_ptr root;
	if (libpff_file_get_root_item(file.get(), &~unique_tie(root), nullptr) < 1)
		throw "PF-1025";
	return do_item(0, {}, root.get());
} catch (const char *e) {
	fprintf(stderr, "Exception: %s\n", e);
	return -ECANCELED;
} catch (const std::string &e) {
	fprintf(stderr, "Exception: %s\n", e.c_str());
	return -ECANCELED;
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_wet_run && g_username == nullptr) {
		fprintf(stderr, "When -N is absent, the -u option is mandatory.\n");
		return EXIT_FAILURE;
	}
	if (argc < 2) {
		fprintf(stderr, "Usage: pffimport [-t] username pstfilename...\n");
		return EXIT_FAILURE;
	}
	if (g_username != nullptr) {
		auto sqh = sql_login();
		if (sqh == nullptr)
			return EXIT_FAILURE;
		auto ret = sql_meta(sqh, g_username, &g_user_id, g_storedir_s);
		mysql_close(sqh);
		if (ret == -ENOENT) {
			fprintf(stderr, "No such user \"%s\"\n", g_username);
			return EXIT_FAILURE;
		} else if (ret < 0) {
			fprintf(stderr, "sql_meta(\"%s\"): %s\n", g_username, strerror(-ret));
			return EXIT_FAILURE;
		}
		g_storedir = g_storedir_s.c_str();
		g_socket = exm_connect(g_storedir);
		if (g_socket < 0)
			return false;
	}
	int ret = EXIT_SUCCESS;
	while (--argc > 0) {
		auto r2 = do_file(*++argv);
		if (r2 < 0) {
			ret = EXIT_FAILURE;
			break;
		}
	}
	if (ret == EXIT_FAILURE)
		fprintf(stderr, "Import unsuccessful.\n");
	return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
