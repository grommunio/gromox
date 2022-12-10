// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <mysql.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <zlib.h>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <fmt/core.h>
#include <gromox/database_mysql.hpp>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

using namespace std::string_literals;
using namespace gromox;

namespace {

union UPV {
	uint16_t i;
	uint32_t l;
	uint64_t ll;
	float flt;
	double dbl;
	bool b;
	char *str;
	void *ptr;
	BINARY bin;
};

enum {
	/* KC does not have MSGFLAG_READ really */
	KC_MSGFLAG_EVERREAD = 1U << 1,
	KC_MSGFLAG_DELETED = 1U << 10,
};

enum propcol {
	PCOL_TAG, PCOL_TYPE, PCOL_ULONG, PCOL_STRING, PCOL_BINARY, PCOL_DOUBLE,
	PCOL_LONGINT, PCOL_HI, PCOL_LO,
};

enum class aclconv {
	automatic = -1, noextract, extract, convert,
};

struct kdb_item;

struct driver final {
	driver() = default;
	~driver();
	NOMOVE(driver);

	int open_by_guid_1(const char *);
	int open_by_guid(const char *);
	int open_by_user(const char *);
	DB_RESULT query(const char *);
	uint32_t hid_from_eid(const BINARY &);
	uint32_t hid_from_mst(kdb_item &, uint32_t);
	uint32_t hid_from_ren(kdb_item &, unsigned int);
	std::unique_ptr<kdb_item> get_store_item();
	std::unique_ptr<kdb_item> get_root_folder();
	void fmap_setup_standard(const char *title);
	void fmap_setup_splice();
	void fmap_setup_splice_public();

	void do_database(const char *title);

	MYSQL *m_conn = nullptr;
	std::string server_guid;
	uint32_t m_user_id = 0, m_store_hid = 0, m_root_hid = 0;
	unsigned int schema_vers = 0;
	bool m_public_store = false;
	gi_folder_map_t m_folder_map;
};

struct ace_list final {
	ace_list();
	errno_t emplace(std::string &&, uint32_t);
	inline size_t size() const { return m_rows.size(); }
	inline const std::vector<PERMISSION_DATA> &get_perms() const { return m_rows; }
	auto begin() const { return m_rows.cbegin(); }
	auto end() const { return m_rows.cend(); }

	private:
	std::list<std::string> m_strs;
	tarray_set_ptr m_rdata;
	std::vector<PERMISSION_DATA> m_rows;
};

struct kdb_item final {
	kdb_item(driver &drv) : m_drv(drv) {}
	static std::unique_ptr<kdb_item> load_hid_base(driver &, uint32_t hid);
	tpropval_array_ptr &get_props();
	size_t get_sub_count() { return m_sub_hids.size(); }
	std::unique_ptr<kdb_item> get_sub_item(size_t idx);

	using hidxtype = std::pair<uint32_t, unsigned int>;

	driver &m_drv;
	uint32_t m_hid = 0;
	enum mapi_object_type m_mapitype{};
	tpropval_array_ptr m_props;
	std::vector<hidxtype> m_sub_hids;
	ace_list m_acl;
};

struct sql_login_param {
	std::string host, user, pass, dbname;
	uint16_t port = 0;
};

}

static int do_item(driver &, unsigned int, const parent_desc &, kdb_item &);

static char *g_sqlhost, *g_sqlport, *g_sqldb, *g_sqluser, *g_atxdir;
static char *g_srcguid, *g_srcmbox, *g_acl_map_file, *g_user_map_file;
static unsigned int g_splice, g_level1_fan = 10, g_level2_fan = 20, g_verbose;
static enum aclconv g_acl_conv = aclconv::automatic;
static int g_with_hidden = -1;
static std::vector<uint32_t> g_only_objs;
static std::unordered_map<std::string, std::string> g_acl_map;
static uint32_t g_proptag_stubbed;

static void cb_only_obj(const HXoptcb *cb) {
		g_only_objs.push_back(cb->data_long);
}

static void acl_cb(const struct HXoptcb *i)
{
	auto s = i->data;
	if (strcasecmp(s, "no") == 0 || strcasecmp(s, "noextract") == 0) {
		g_acl_conv = aclconv::noextract;
	} else if (strcasecmp(s, "ex") == 0 || strcasecmp(s, "extract") == 0) {
		g_acl_conv = aclconv::extract;
	} else if (strcasecmp(s, "convert") == 0) {
		g_acl_conv = aclconv::convert;
	} else if (strcasecmp(s, "auto") == 0) {
		g_acl_conv = aclconv::automatic;
	} else {
		fprintf(stderr, "Unrecognized --acl option value \"%s\"\n", s);
		exit(EXIT_FAILURE);
	}
}

static constexpr HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 's', HXTYPE_NONE, &g_splice, nullptr, nullptr, 0, "Map folders of a private store (see manpage for detail)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the source archive"},
	{nullptr, 'v', HXTYPE_NONE | HXOPT_INC, &g_verbose, nullptr, nullptr, 0, "More detailed progress reports"},
	{"acl", 0, HXTYPE_STRING, nullptr, nullptr, acl_cb, 0, "Conversion for ACLs (auto, no/noextract, extract, convert)", "MODE"},
	{"l1", 0, HXTYPE_UINT, &g_level1_fan, nullptr, nullptr, 0, "L1 fan number for attachment directories of type files_v1 (default: 10)", "N"},
	{"l2", 0, HXTYPE_UINT, &g_level1_fan, nullptr, nullptr, 0, "L2 fan number for attachment directories of type files_v1 (default: 20)", "N"},
	{"mbox-guid", 0, HXTYPE_STRING, &g_srcguid, nullptr, nullptr, 0, "Lookup source mailbox by GUID", "GUID"},
	{"mbox-mro", 0, HXTYPE_STRING, &g_srcmbox, nullptr, nullptr, 0, "Lookup source mailbox by MRO", "NAME"},
	{"sql-host", 0, HXTYPE_STRING, &g_sqlhost, nullptr, nullptr, 0, "Hostname for SQL connection (default: localhost)", "HOST"},
	{"sql-port", 0, HXTYPE_STRING, &g_sqlport, nullptr, nullptr, 0, "Port for SQL connection (default: auto)", "PORT"},
	{"sql-db", 0, HXTYPE_STRING, &g_sqldb, nullptr, nullptr, 0, "Database name (default: kopano)", "NAME"},
	{"sql-user", 0, HXTYPE_STRING, &g_sqluser, nullptr, nullptr, 0, "Username for SQL connection (default: root)", "USER"},
	{"src-host", 0, HXTYPE_STRING, &g_sqlhost, nullptr, nullptr, 0, "Old name and alias for --sql-host", "HOST"},
	{"src-port", 0, HXTYPE_STRING, &g_sqlport, nullptr, nullptr, 0, "Old name and alias for --sql-port", "PORT"},
	{"src-db", 0, HXTYPE_STRING, &g_sqldb, nullptr, nullptr, 0, "Old name and alias for --sql-db", "NAME"},
	{"src-user", 0, HXTYPE_STRING, &g_sqluser, nullptr, nullptr, 0, "Old name and alias for --sql-user", "USER"},
	{"src-attach", 0, HXTYPE_STRING, &g_atxdir, nullptr, nullptr, 0, "Attachment directory", "DIR"},
	{"src-guid", 0, HXTYPE_STRING, &g_srcguid, nullptr, nullptr, 0, "Old name and alias for --mbox-guid", "GUID"},
	{"src-mbox", 0, HXTYPE_STRING, &g_srcmbox, nullptr, nullptr, 0, "Old name and alias for --mbox-mro", "NAME"},
	{"only-obj", 0, HXTYPE_ULONG, nullptr, nullptr, cb_only_obj, 0, "Extract specific object only", "OBJID"},
	{"user-map", 0, HXTYPE_STRING, &g_user_map_file, nullptr, nullptr, 0, "User resolution map", "FILE"},
	{"with-hidden", 0, HXTYPE_VAL, &g_with_hidden, nullptr, nullptr, 1, "Do import folders with PR_ATTR_HIDDEN"},
	{"without-hidden", 0, HXTYPE_VAL, &g_with_hidden, nullptr, nullptr, 0, "Do skip folders with PR_ATTR_HIDDEN [default: dependent upon -s]"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::string sql_escape(MYSQL *sqh, const char *in)
{
	std::string out;
	out.resize(strlen(in) * 2 + 1);
	auto ret = mysql_real_escape_string(sqh, out.data(), in, strlen(in));
	out.resize(ret);
	return out;
}

static bool skip_property(const TAGGED_PROPVAL &p)
{
	switch (PROP_ID(p.proptag)) {
	/*
	 * Skip importing IMAP data; midb rebuilds this anyway, and has its own
	 * database for this so as to not clutter the store with what is
	 * effectively computable data.
	 *
	 * emsmdb32.dll's ICS also fails to cope with properties in the
	 * non-transmittable range with a certain size. It seems that the
	 * property may only be as large as there is remaining space in the rop
	 * packet, though at least 8K. Since the fill status of the packet can
	 * be anywhere from 0 to 32K, the behavior is exceptionally erratic.
	 */
	case PROP_ID(PR_EC_IMAP_ID):
	case PROP_ID(PR_EC_IMAP_SUBSCRIBED):
	case PROP_ID(PR_EC_IMAP_MAX_ID):
	case PROP_ID(PR_EC_IMAP_EMAIL_SIZE):
	case PROP_ID(PR_EC_IMAP_BODY):
	case PROP_ID(PR_EC_IMAP_BODYSTRUCTURE):
		return true;
	/* Contains entryids and so on, pretty useless after import. */
	/* Some objects need entryids (even if nonresolvable), recipients might be one category. */
	case PROP_ID(PR_ACL_DATA):
	case PROP_ID(PR_RULES_DATA):
	case PROP_ID(PR_RW_RULES_STREAM):
	case PROP_ID(PR_EC_WEBACCESS_SETTINGS_JSON):
	case PROP_ID(PR_IPM_SUBTREE_ENTRYID):
	case PROP_ID(PR_IPM_OUTBOX_ENTRYID):
	case PROP_ID(PR_IPM_WASTEBASKET_ENTRYID):
	case PROP_ID(PR_IPM_SENTMAIL_ENTRYID):
	case PROP_ID(PR_VIEWS_ENTRYID):
	case PROP_ID(PR_COMMON_VIEWS_ENTRYID):
	case PROP_ID(PR_DEFAULT_VIEW_ENTRYID):
	case PROP_ID(PR_FINDER_ENTRYID):
	case PROP_ID(PR_IPM_APPOINTMENT_ENTRYID):
	case PROP_ID(PR_IPM_CONTACT_ENTRYID):
	case PROP_ID(PR_IPM_JOURNAL_ENTRYID):
	case PROP_ID(PR_IPM_NOTE_ENTRYID):
	case PROP_ID(PR_IPM_TASK_ENTRYID):
	case PROP_ID(PR_REM_ONLINE_ENTRYID):
	case PROP_ID(PR_REM_OFFLINE_ENTRYID):
	case PROP_ID(PR_IPM_DRAFTS_ENTRYID):
	case PROP_ID(PR_ADDITIONAL_REN_ENTRYIDS):
	case PROP_ID(PR_ADDITIONAL_REN_ENTRYIDS_EX):
	case PROP_ID(PR_FREEBUSY_ENTRYIDS):
	case PROP_ID(PR_CONFLICT_ENTRYID):
	case PROP_ID(PR_SCHEDULE_FOLDER_ENTRYID):
	case PROP_ID(PR_IPM_DAF_ENTRYID):
	case PROP_ID(PR_NON_IPM_SUBTREE_ENTRYID):
	case PROP_ID(PR_EFORMS_REGISTRY_ENTRYID):
	case PROP_ID(PR_SPLUS_FREE_BUSY_ENTRYID):
	case PROP_ID(PR_IPM_FAVORITES_ENTRYID):
	case PROP_ID(PR_IPM_PUBLIC_FOLDERS_ENTRYID):
		return true;
	/* In Gromox, these are computed properties */
	case PROP_ID(PR_PARENT_DISPLAY):
		return true;
	default:
		return false;
	}
}

ace_list::ace_list() : m_rdata(tarray_set_init())
{}

errno_t ace_list::emplace(std::string &&s, uint32_t r)
{
	tpropval_array_ptr props(tpropval_array_init());
	if (props == nullptr)
		return ENOMEM;
	m_strs.push_back(std::move(s));
	auto ret = props->set(PR_SMTP_ADDRESS, m_strs.back().c_str());
	if (ret != 0) {
		fprintf(stderr, "error ACL: %d\n", ret);
		return ret;
	}
	ret = props->set(PR_MEMBER_RIGHTS, &r);
	if (ret != 0) {
		fprintf(stderr, "error ACL: %d\n", ret);
		return ret;
	}
	PERMISSION_DATA d = {ROW_ADD, {2, props->ppropval}};
	ret = m_rdata->append_move(std::move(props));
	if (ret != 0)
		return ret;
	m_rows.emplace_back(d);
	return 0;
}

static void hid_to_tpropval_1(driver &drv, const char *qstr, TPROPVAL_ARRAY *ar)
{
	auto res = drv.query(qstr);
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr) {
		auto xtag = strtoul(znul(row[PCOL_TAG]), nullptr, 0);
		auto xtype = strtoul(znul(row[PCOL_TYPE]), nullptr, 0);
		auto rowlen = res.row_lengths();
		UPV upv{};
		TAGGED_PROPVAL pv{};
		pv.pvalue = &upv;

		switch (xtype) {
		case PT_SHORT: upv.i = strtoul(znul(row[PCOL_ULONG]), nullptr, 0); break;
		case PT_LONG: [[fallthrough]];
		case PT_ERROR: upv.l = strtoul(znul(row[PCOL_ULONG]), nullptr, 0); break;
		case PT_FLOAT: upv.flt = strtod(znul(row[PCOL_DOUBLE]), nullptr); break;
		case PT_DOUBLE: upv.dbl = strtod(znul(row[PCOL_DOUBLE]), nullptr); break;
		case PT_BOOLEAN: upv.b = strtoul(znul(row[PCOL_ULONG]), nullptr, 0); break;
		case PT_I8: upv.ll = strtoll(znul(row[PCOL_LONGINT]), nullptr, 0); break;
		case PT_CURRENCY:
		case PT_SYSTIME:
			upv.ll = (static_cast<uint64_t>(strtol(znul(row[PCOL_HI]), nullptr, 0)) << 32) |
			         strtoul(znul(row[PCOL_LO]), nullptr, 0);
			break;
		case PT_STRING8:
			xtype = PT_UNICODE;
			[[fallthrough]];
		case PT_UNICODE: pv.pvalue = row[PCOL_STRING]; break;
		case PT_CLSID: [[fallthrough]];
		case PT_BINARY:
			upv.bin.cb = rowlen[PCOL_BINARY];
			upv.bin.pv = row[PCOL_BINARY];
			pv.pvalue = &upv.bin;
			break;
		default:
			throw YError("PK-1007: proptype %xh not supported. Implement me!", pv.proptag);
		}
		pv.proptag = PROP_TAG(xtype, xtag);
		if (ar->set(pv) != 0)
			throw std::bad_alloc();
	}
}

static void hid_to_tpropval_mv(driver &drv, const char *qstr, TPROPVAL_ARRAY *ar)
{
	auto res = drv.query(qstr);
	struct UPW {
		std::vector<uint32_t> mvl;
		std::vector<uint64_t> mvll;
		std::vector<float> mvflt;
		std::vector<double> mvdbl;
		std::vector<std::string> mvstr;
	};
	std::unordered_map<uint32_t, UPW> collect;
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr) {
		if (row[PCOL_TAG] == nullptr || row[PCOL_TYPE] == nullptr)
			continue;
		auto xtag  = strtoul(row[PCOL_TAG], nullptr, 0);
		auto xtype = strtoul(row[PCOL_TYPE], nullptr, 0);
		auto proptag = PROP_TAG(xtype, xtag);
		auto colen = res.row_lengths();
		switch (xtype) {
		case PT_MV_SHORT:
		case PT_MV_LONG:
			if (row[PCOL_ULONG] == nullptr)
				continue;
			collect[proptag].mvl.emplace_back(strtoul(row[PCOL_ULONG], nullptr, 0));
			break;
		case PT_MV_I8:
			if (row[PCOL_LONGINT] == nullptr)
				continue;
			collect[proptag].mvll.emplace_back(strtoul(row[PCOL_LONGINT], nullptr, 0));
			break;
		case PT_MV_CURRENCY:
		case PT_MV_SYSTIME:
			if (row[PCOL_HI] == nullptr || row[PCOL_LO] == nullptr)
				continue;
			collect[proptag].mvll.emplace_back(
				(static_cast<uint64_t>(strtol(znul(row[PCOL_HI]), nullptr, 0)) << 32) |
			         strtoul(znul(row[PCOL_LO]), nullptr, 0));
			break;
		case PT_MV_FLOAT:
			if (row[PCOL_DOUBLE] == nullptr)
				continue;
			collect[proptag].mvflt.emplace_back(strtoul(row[PCOL_DOUBLE], nullptr, 0));
			break;
		case PT_MV_DOUBLE:
		case PT_MV_APPTIME:
			if (row[PCOL_DOUBLE] == nullptr)
				continue;
			collect[proptag].mvdbl.emplace_back(strtoul(row[PCOL_DOUBLE], nullptr, 0));
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			if (row[PCOL_STRING] == nullptr)
				continue;
			collect[proptag].mvstr.emplace_back(row[PCOL_STRING]);
			break;
		case PT_MV_CLSID:
		case PT_MV_BINARY:
			if (row[PCOL_BINARY] == nullptr)
				continue;
			collect[proptag].mvstr.emplace_back(row[PCOL_BINARY], colen[PCOL_BINARY]);
			break;
		default:
			throw YError("PK-1010: Proptype %lxh not supported. Implement me!", static_cast<unsigned long>(proptag));
		}
	}

	for (auto &&[proptag, xpair] : collect) {
		switch (PROP_TYPE(proptag)) {
		case PT_MV_LONG: {
			LONG_ARRAY la;
			la.count = xpair.mvl.size();
			la.pl = xpair.mvl.data();
			if (ar->set(proptag, &la) != 0)
				throw std::bad_alloc();
			break;
		}
		case PT_MV_CURRENCY:
		case PT_MV_I8:
		case PT_MV_SYSTIME: {
			LONGLONG_ARRAY la;
			la.count = xpair.mvll.size();
			la.pll = xpair.mvll.data();
			if (ar->set(proptag, &la) != 0)
				throw std::bad_alloc();
			break;
		}
		case PT_MV_FLOAT: {
			FLOAT_ARRAY la;
			la.count = xpair.mvflt.size();
			la.mval = xpair.mvflt.data();
			if (ar->set(proptag, &la) != 0)
				throw std::bad_alloc();
			break;
		}
		case PT_MV_DOUBLE:
		case PT_MV_APPTIME: {
			DOUBLE_ARRAY la;
			la.count = xpair.mvdbl.size();
			la.mval = xpair.mvdbl.data();
			if (ar->set(proptag, &la) != 0)
				throw std::bad_alloc();
			break;
		}
		case PT_MV_STRING8:
		case PT_MV_UNICODE: {
			std::vector<char *> ptrs(xpair.mvstr.size());
			STRING_ARRAY sa;
			sa.count = xpair.mvstr.size();
			for (size_t i = 0; i < sa.count; ++i)
				ptrs[i] = xpair.mvstr[i].data();
			sa.ppstr = ptrs.data();
			if (ar->set(CHANGE_PROP_TYPE(proptag, PT_MV_UNICODE), &sa) != 0)
				throw std::bad_alloc();
			break;
		}
		case PT_MV_CLSID:
		case PT_MV_BINARY: {
			std::vector<BINARY> bins(xpair.mvstr.size());
			BINARY_ARRAY ba;
			ba.count = xpair.mvstr.size();
			for (size_t i = 0; i < ba.count; ++i) {
				bins[i].pv = xpair.mvstr[i].data();
				bins[i].cb = xpair.mvstr[i].size();
			}
			ba.pbin = bins.data();
			if (ar->set(proptag, &ba) != 0)
				throw std::bad_alloc();
			break;
		}
		}
	}
}

static tpropval_array_ptr hid_to_propval_a(driver &drv, uint32_t hid)
{
	tpropval_array_ptr props(tpropval_array_init());
	if (props == nullptr)
		throw std::bad_alloc();
	char qstr[256];
	snprintf(qstr, arsizeof(qstr),
		"SELECT tag, type, val_ulong, val_string, val_binary, val_double, val_longint, val_hi, val_lo "
		"FROM properties WHERE hierarchyid=%u", hid);
	hid_to_tpropval_1(drv, qstr, props.get());
	snprintf(qstr, arsizeof(qstr),
		"SELECT tag, type, val_ulong, val_string, val_binary, val_double, val_longint, val_hi, val_lo "
		"FROM mvproperties WHERE hierarchyid=%u ORDER BY tag, type, orderid", hid);
	hid_to_tpropval_mv(drv, qstr, props.get());
	return props;
}

static const char *kp_item_type_to_str(enum mapi_object_type t)
{
	thread_local char buf[32];
	switch (t) {
	case MAPI_STORE: return "store";
	case MAPI_FOLDER: return "folder";
	case MAPI_MESSAGE: return "message";
	case MAPI_MAILUSER: return "mailuser";
	case MAPI_ATTACH: return "attach";
	case MAPI_DISTLIST: return "distlist";
	default: snprintf(buf, arsizeof(buf), "other-%u", t); return buf;
	}
}

static void do_print(unsigned int depth, kdb_item &item)
{
	tree(depth);
	tlog("[hid=%lu type=%s]\n", static_cast<unsigned long>(item.m_hid),
	     kp_item_type_to_str(item.m_mapitype));
}

int driver::open_by_guid_1(const char *guid)
{
	auto drv = this;
	if (hex2bin(guid).size() != 16)
		throw YError("PK-1011: invalid GUID passed");

	/* user_id available from n61 */
	auto qstr = fmt::format("SELECT hierarchy_id, user_id, type FROM stores WHERE guid=0x{}", guid);
	auto res = drv->query(qstr.c_str());
	auto row = res.fetch_row();
	if (row == nullptr || row[0] == nullptr || row[1] == nullptr)
		throw YError("PK-1014: no store by that GUID");
	drv->m_user_id = strtoul(row[1], nullptr, 0);
	drv->m_store_hid = strtoul(row[0], nullptr, 0);
	drv->m_public_store = row[2] != nullptr && strtoul(row[2], nullptr, 0) == 1;
	return 0;
}

static int setup_charset(MYSQL *m)
{
	auto ret = mysql_set_character_set(m, "utf8mb4");
	if (ret == 0)
		return 0;
	ret = mysql_set_character_set(m, "utf8");
	if (ret == 0)
		return 0;
	/* Restore previous error state. */
	return mysql_set_character_set(m, "utf8mb4");
}

static std::unique_ptr<driver> make_driver(const sql_login_param &sqp)
{
	auto drv = std::make_unique<driver>();
	drv->m_conn = mysql_init(nullptr);
	if (drv->m_conn == nullptr)
		throw std::bad_alloc();
	if (mysql_real_connect(drv->m_conn, snul(sqp.host), sqp.user.c_str(),
	    sqp.pass.c_str(), sqp.dbname.c_str(), sqp.port, nullptr, 0) == nullptr)
		throw YError("PK-1018: mysql_connect %s@%s: %s",
		      sqp.user.c_str(), sqp.host.c_str(), mysql_error(drv->m_conn));
	if (setup_charset(drv->m_conn) != 0)
		throw YError("PK-1021: charset utf8mb4/utf8mb3 not available: %s",
		      mysql_error(drv->m_conn));

	auto qstr = fmt::format("SELECT value FROM settings WHERE name='server_guid'");
	DB_RESULT res = drv->query(qstr.c_str());
	if (res == nullptr)
		throw YError("PG-1133: unable to request server_guid");
	auto row = res.fetch_row();
	if (row == nullptr)
		throw YError("PG-1134: unable to request server_guid");
	auto rowlen = res.row_lengths();
	if (row[0] == nullptr || rowlen[0] != sizeof(GUID))
		throw YError("PG-1135: unable to request server_guid");
	drv->server_guid = bin2hex(row[0], rowlen[0]);
	fmt::print(stderr, "kdb Server GUID: {}\n", drv->server_guid);

	qstr = fmt::format("SELECT value FROM settings WHERE name='attachment_storage'");
	res = drv->query(qstr.c_str());
	if (res == nullptr)
		throw YError("PG-1136: unable to request settings.attachment_storage");
	row = res.fetch_row();
	if (row != nullptr && row[0] != nullptr &&
	    strncasecmp(row[0], "files", 5) != 0)
		throw YError("PG-1137: kdb2mt does not support attachment_storage type other than files (v1, v2, etc.) at this time");

	qstr = "SELECT MAX(databaserevision) FROM versions";
	try {
		res = drv->query(qstr.c_str());
		row = res.fetch_row();
		if (row == nullptr || row[0] == nullptr)
			throw YError("PK-1002: Database has no version information and is too old");
	} catch (const YError &e) {
		fprintf(stderr, "PK-1003: Database has no version information and is too old.\n");
		throw;
	}
	drv->schema_vers = strtoul(row[0], nullptr, 0);
	if (drv->schema_vers < 61)
		throw YError("PK-1004: Database schema kdb-%u is not supported.\n", drv->schema_vers);
	fprintf(stderr, "Database schema is kdb-%u\n", drv->schema_vers);

	return drv;
}

int driver::open_by_guid(const char *guid)
{
	fmt::print(stderr, "Store GUID: {}\n", guid);
	return open_by_guid_1(guid);
}

static void present_stores(const char *storeuser, DB_RESULT &res)
{
	DB_ROW row;
	if (*storeuser != '\0')
		fmt::print(stderr, "The search for \"{}\" has turned up multiple candidate stores:\n\n", storeuser);
	fprintf(stderr, "GUID                              user_id   size  most_recent_owner\n");
	fprintf(stderr, "====================================================================\n");
	while ((row = res.fetch_row()) != nullptr) {
		auto colen = res.row_lengths();
		char mbsize[32]{};
		if (row[4] != nullptr)
			HX_unit_size_cu(mbsize, std::size(mbsize), strtoull(row[4], nullptr, 0), 0);
		fprintf(stderr, "%s  %7lu  %5s  %s\n", bin2hex(row[0], colen[0]).c_str(),
		        strtoul(row[1], nullptr, 0), mbsize, znul(row[2]));
	}
	fprintf(stderr, "============================================================\n");
}

int driver::open_by_user(const char *storeuser)
{
	auto drv = this;
	std::string qstr = "SELECT s.guid, s.user_id, s.user_name, s.type, "
	                   "p.val_longint FROM stores AS s "
	                   "LEFT JOIN properties AS p "
	                   "ON s.hierarchy_id=p.hierarchyid AND p.tag=0xE08";
	if (*storeuser != '\0') {
		fmt::print(stderr, "PK-1008: Warning: The search by MRO name "
			"(--mbox-mro) is only a heuristic and not guaranteed "
			"to produce the correct result, "
			"lest it would require the full original user database, "
			"a requirement this tool does not want to impose.\n");
		qstr += " WHERE s.user_name='" +
		        sql_escape(drv->m_conn, storeuser) + "'";
	}
	auto res = drv->query(qstr.c_str());
	if (*storeuser == '\0' || mysql_num_rows(res.get()) > 1) {
		present_stores(storeuser, res);
		throw YError("PK-1013: \"%s\" was ambiguous.\n", storeuser);
	}
	auto row = res.fetch_row();
	if (row == nullptr || row[0] == nullptr)
		throw YError("PK-1022: no store for that user");
	auto rowlen = res.row_lengths();
	auto guid = bin2hex(row[0], rowlen[0]);
	fmt::print(stderr, "Store GUID for MRO \"{}\": {}\n", storeuser, guid);
	return open_by_guid_1(guid.c_str());
}

driver::~driver()
{
	if (m_conn != nullptr)
		mysql_close(m_conn);
}

DB_RESULT driver::query(const char *qstr)
{
	auto ret = mysql_query(m_conn, qstr);
	if (ret != 0)
		throw YError("PK-1000: mysql_query \"%s\": %s", qstr, mysql_error(m_conn));
	DB_RESULT res = mysql_store_result(m_conn);
	if (res == nullptr)
		throw YError("PK-1001: mysql_store: %s", mysql_error(m_conn));
	return res;
}

uint32_t driver::hid_from_eid(const BINARY &eid)
{
	if (eid.cb == 0)
		return 0;
	char qstr[184];
	snprintf(qstr, arsizeof(qstr), "SELECT hierarchyid FROM indexedproperties "
		"WHERE tag=0x0FFF AND val_binary=0x%.96s LIMIT 1", bin2hex(eid.pv, eid.cb).c_str());
	auto res = query(qstr);
	auto row = res.fetch_row();
	if (row == nullptr || row[0] == nullptr)
		return 0;
	return strtoul(row[0], nullptr, 0);
}

uint32_t driver::hid_from_mst(kdb_item &item, uint32_t proptag)
{
	auto &props = item.get_props();
	auto eid = props->get<BINARY>(proptag);
	if (eid == nullptr)
		return 0;
	return hid_from_eid(*eid);
}

uint32_t driver::hid_from_ren(kdb_item &item, unsigned int idx)
{
	auto &props = item.get_props();
	auto ba = props->get<BINARY_ARRAY>(PR_ADDITIONAL_REN_ENTRYIDS);
	if (ba == nullptr || idx >= ba->count)
		return 0;
	return hid_from_eid(ba->pbin[idx]);
}

void driver::fmap_setup_splice()
{
	m_folder_map.clear();
	auto store = get_store_item();
	auto root = get_root_folder();
	m_folder_map.emplace(root->m_hid, tgt_folder{false, PRIVATE_FID_ROOT, "FID_ROOT"});
	auto nid = hid_from_mst(*store, PR_IPM_SUBTREE_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_IPMSUBTREE, "FID_IPMSUBTREE"});
	nid = hid_from_mst(*store, PR_IPM_OUTBOX_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_OUTBOX, "FID_OUTBOX"});
	nid = hid_from_mst(*store, PR_IPM_WASTEBASKET_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_DELETED_ITEMS, "FID_DELETED_ITEMS"});
	nid = hid_from_mst(*store, PR_IPM_SENTMAIL_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_SENT_ITEMS, "FID_SENT_ITEMS"});
	nid = hid_from_mst(*store, PR_FINDER_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_FINDER, "FID_FINDER"});
	nid = hid_from_mst(*store, PR_SCHEDULE_FOLDER_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_SCHEDULE, "FID_SCHEDULE"});

	nid = hid_from_mst(*root, PR_IPM_APPOINTMENT_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_CALENDAR, "FID_CALENDAR"});
	nid = hid_from_mst(*root, PR_IPM_CONTACT_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_CONTACTS, "FID_CONTACTS"});
	nid = hid_from_mst(*root, PR_IPM_JOURNAL_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_JOURNAL, "FID_JOURNAL"});
	nid = hid_from_mst(*root, PR_IPM_NOTE_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_NOTES, "FID_NOTES"});
	nid = hid_from_mst(*root, PR_IPM_TASK_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_TASKS, "FID_TASKS"});
	nid = hid_from_mst(*root, PR_IPM_DRAFTS_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_DRAFT, "FID_DRAFT"});

	/*
	 * This here is just for classification of sync folders.
	 * Ignoring sync folder contents should be done elsewhere.
	 * (If we did not classify these folders here, they would get imported
	 * as regular folders rather than the special folder.)
	 * Skeletor returns next week with more useful hints.
	 */
	nid = hid_from_ren(*root, sfConflicts);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_CONFLICTS, "FID_CONFLICTS"});
	nid = hid_from_ren(*root, sfSyncFailures);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_SYNC_ISSUES, "FID_SYNC_ISSUES"});
	nid = hid_from_ren(*root, sfLocalFailures);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_LOCAL_FAILURES, "FID_LOCAL_FAIL"});
	nid = hid_from_ren(*root, sfServerFailures);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_SERVER_FAILURES, "FID_SERVER_FAIL"});
	nid = hid_from_ren(*root, sfJunkEmail);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_JUNK, "FID_JUNK"});

	char qstr[71];
	snprintf(qstr, arsizeof(qstr), "SELECT objid, messageclass FROM receivefolder WHERE storeid=%u", m_store_hid);
	auto res = query(qstr);
	DB_ROW row;
	unsigned int goodmatch = 0;
	while ((row = res.fetch_row()) != nullptr) {
		auto xobjid = strtoul(znul(row[0]), nullptr, 0);
		auto xmsgcl = znul(row[1]);
		if (strcmp(xmsgcl, "") == 0 && goodmatch < 1) {
			goodmatch = 1;
			nid = xobjid;
		} else if (strcmp(xmsgcl, "IPM") == 0 && goodmatch < 2) {
			goodmatch = 2;
			nid = xobjid;
		} else if (strcmp(xmsgcl, "IPM.Note") == 0 && goodmatch < 3) {
			goodmatch = 3;
			nid = xobjid;
		}
	}
	if (goodmatch > 0)
		m_folder_map.emplace(nid, tgt_folder{false, PRIVATE_FID_INBOX, "FID_INBOX"});
}

void driver::fmap_setup_splice_public()
{
	m_folder_map.clear();
	auto store = get_store_item();
	auto root = get_root_folder();
	m_folder_map.emplace(root->m_hid, tgt_folder{false, PUBLIC_FID_ROOT, "FID_ROOT"});
	auto nid = hid_from_mst(*store, PR_IPM_SUBTREE_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PUBLIC_FID_IPMSUBTREE, "FID_IPM"});
	nid = hid_from_mst(*store, PR_NON_IPM_SUBTREE_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PUBLIC_FID_NONIPMSUBTREE, "FID_NONIPM"});
	nid = hid_from_mst(*store, PR_EFORMS_REGISTRY_ENTRYID);
	if (nid != 0)
		m_folder_map.emplace(nid, tgt_folder{false, PUBLIC_FID_EFORMSREGISTRY, "FID_EFORMS"});
}

void driver::fmap_setup_standard(const char *title)
{
	char timebuf[64];
	time_t now = time(nullptr);
	auto tm = localtime(&now);
	strftime(timebuf, arsizeof(timebuf), " @%FT%T", tm);
	m_folder_map.clear();
	auto root = get_root_folder();
	m_folder_map.emplace(root->m_hid, tgt_folder{true, PRIVATE_FID_IPMSUBTREE,
		"Import of "s + title + timebuf});
}

std::unique_ptr<kdb_item> driver::get_store_item()
{
	return kdb_item::load_hid_base(*this, m_store_hid);
}

std::unique_ptr<kdb_item> driver::get_root_folder()
{
	if (m_root_hid == 0) {
		char qstr[80];
		snprintf(qstr, arsizeof(qstr), "SELECT id FROM hierarchy WHERE parent=%u AND type=3 LIMIT 1", m_store_hid);
		auto res = query(qstr);
		auto row = res.fetch_row();
		if (row == nullptr || row[0] == nullptr)
			throw YError("PK-1017: no root folder for store");
		m_root_hid = strtoul(row[0], nullptr, 0);
	}
	return kdb_item::load_hid_base(*this, m_root_hid);
}

/**
 * Lookup a specific hierarchy ID and return all kinds of info:
 * - own type
 * - children object IDs
 */
std::unique_ptr<kdb_item> kdb_item::load_hid_base(driver &drv, uint32_t hid)
{
	auto qstr = fmt::format("SELECT id, type, flags FROM hierarchy WHERE (id={} OR parent={})", hid, hid);
	auto res = drv.query(qstr.c_str());
	auto yi = std::make_unique<kdb_item>(drv);
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr) {
		auto xid   = strtoul(row[0], nullptr, 0);
		auto xtype = strtoul(row[1], nullptr, 0);
		auto xflag = strtoul(row[2], nullptr, 0);
		if (xid == hid) {
			/* Own existence validated */
			yi->m_hid = xid;
			yi->m_mapitype = static_cast<enum mapi_object_type>(xtype);
			continue;
		}
		if (xtype == MAPI_FOLDER && xflag == FOLDER_SEARCH)
			/* Skip over search folders */
			continue;
		if (xflag & KC_MSGFLAG_DELETED)
			/* Skip over softdeletes */
			continue;
		yi->m_sub_hids.push_back({xid, xtype});
	}
	if (yi->m_hid != hid)
		return nullptr;
	/*
	 * Put messages before folders, so genimport processes a folder's
	 * message before the folder's subfolders. (Harmonizes better with
	 * genimport's status printouts.)
	 */
	std::sort(yi->m_sub_hids.begin(), yi->m_sub_hids.end(),
		[](const hidxtype &a, const hidxtype &b) /* operator< */
		{
			if (a.second == MAPI_MESSAGE && b.second == MAPI_FOLDER)
				return true;
			if (a.second == MAPI_FOLDER && b.second == MAPI_MESSAGE)
				return false;
			return a < b;
		});
	/* Gromox ACL tables are only specified for folders at this time. */
	if (yi->m_mapitype != MAPI_FOLDER)
		return yi;
	if (g_acl_conv == aclconv::noextract)
		return yi;
	/*
	 * ECSecurity.cpp ECSecurity::GetObjectPermission never evaluates type=1
	 * (ACCESS_TYPE_DENIED); but only 2 (ACCESS_TYPE_GRANT).
	 */
	qstr = fmt::format("SELECT id, rights FROM acl WHERE hierarchy_id={} AND type=2", hid);
	res = drv.query(qstr.c_str());
	while ((row = res.fetch_row()) != nullptr) {
		uint32_t ben_id = strtoul(row[0], nullptr, 0);
		uint32_t rights = strtoul(row[1], nullptr, 0);
		rights &= ~(frightsGromoxSendAs | frightsGromoxStoreOwner);
		auto synthid = std::to_string(ben_id) + "@" + drv.server_guid + ".kopano.invalid";
		auto it = g_acl_map.find(synthid);
		if (it != g_acl_map.end())
			synthid = it->second;
		auto ret = yi->m_acl.emplace(std::move(synthid), rights);
		if (ret == ENOMEM)
			throw std::bad_alloc();
		else if (ret != 0)
			throw YError("PK-1023: %d", static_cast<int>(ret));
	}
	return yi;
}

tpropval_array_ptr &kdb_item::get_props()
{
	if (m_props == nullptr)
		m_props = hid_to_propval_a(m_drv, m_hid);
	return m_props;
}

std::unique_ptr<kdb_item> kdb_item::get_sub_item(size_t idx)
{
	if (idx >= m_sub_hids.size())
		return nullptr;
	return load_hid_base(m_drv, m_sub_hids[idx].first);
}

static void do_namemap_table(driver &drv, gi_name_map &map)
{
	auto res = drv.query("SELECT id, guid, nameid, namestring FROM names");
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr) {
		auto rowlen = res.row_lengths();
		std::unique_ptr<char[]> pnstr;
		PROPERTY_NAME pn_req{};

		if (rowlen[1] != sizeof(GUID))
			continue;
		memcpy(&pn_req.guid, row[1], sizeof(GUID));
		if (row[2] != nullptr) {
			pn_req.kind = MNID_ID;
			pn_req.lid  = strtoul(row[2], nullptr, 0);
		} else {
			pn_req.kind = MNID_STRING;
			pnstr.reset(me_alloc<char>(rowlen[3] + 1));
			memcpy(pnstr.get(), row[3], rowlen[3] + 1);
			pn_req.pname = pnstr.get();
		}
		map.emplace(PROP_TAG(PT_UNSPECIFIED, 0x8501 + strtoul(row[0], nullptr, 0)), std::move(pn_req));
		pnstr.release();
		pn_req.pname = nullptr;
	}

	for (const auto &[tag, mn] : map)
		if (mn.kind == MNID_STRING && mn.guid == PSETID_KCARCHIVE &&
		    strcasecmp(mn.name.c_str(), "stubbed") == 0)
			g_proptag_stubbed = CHANGE_PROP_TYPE(tag, PT_BOOLEAN);
}

static gi_name_map do_namemap(driver &drv)
{
	gi_name_map map;
	static constexpr struct {
		const GUID &guid;
		unsigned int lid_min, lid_max, base;
	} hardmapped_nprops[] = {
		{PSETID_ADDRESS,          0x8000, 0x80EF, 0x80B0},
		{PSETID_TASK,             0x8100, 0x813F, 0x8070},
		{PSETID_APPOINTMENT,      0x8200, 0x826F, 0x8000},
		{PSETID_COMMON,           0x8500, 0x85FF, 0x81A0},
		{PSETID_LOG,              0x8700, 0x871F, 0x82A0},
		{PSETID_BUSINESSCARDVIEW, 0x8800, 0x881F, 0x82C0},
		{PSETID_NOTE,             0x8B00, 0x8B1F, 0x82E0},
		{PSETID_REPORT,           0x8D00, 0x8D1F, 0x8300},
		{PSETID_REMOTE,           0x8F00, 0x8F1F, 0x8320},
		{PSETID_MEETING,          0x0000, 0x003F, 0x8340},
		{PSETID_KC,               0x0002, 0x0002, 0x8380},
	};
	PROPERTY_NAME pn;

	for (const auto &row : hardmapped_nprops) {
		pn.kind = MNID_ID;
		pn.guid = row.guid;
		for (pn.lid = row.lid_min; pn.lid < row.lid_max; ++pn.lid)
			map.emplace(PROP_TAG(PT_UNSPECIFIED, pn.lid - row.lid_min + row.base), pn);
	}
	do_namemap_table(drv, map);
	return map;
}

static void gi_dump_acl(unsigned int depth, const ace_list &acl)
{
	for (const auto &pd : acl) {
		auto id = znul(pd.propvals.get<char>(PR_SMTP_ADDRESS));
		auto ri = pd.propvals.get<uint32_t>(PR_MEMBER_RIGHTS);
		if (id == nullptr || ri == nullptr)
			continue;
		if (g_show_props)
			tree(depth);
		tlog("ACE: %s: %xh\n", id, static_cast<unsigned int>(*ri));
	}
}

static int do_folder(driver &drv, unsigned int depth, const parent_desc &parent, kdb_item &item)
{
	auto props = std::move(item.get_props());
	props->erase_if(skip_property);
	if (g_show_tree) {
		gi_dump_acl(depth, item.m_acl);
		gi_dump_tpropval_a(depth, *props);
	} else {
		auto dn = props->get<const char>(PR_DISPLAY_NAME);
		fprintf(stderr, "Processing folder \"%s\" (%zu elements)...\n",
		        znul(dn), item.m_sub_hids.size());
	}
	auto hidden_flag = props->get<const uint8_t>(PR_ATTR_HIDDEN);
	if (hidden_flag != nullptr && *hidden_flag != 0 && !g_with_hidden) {
		fprintf(stderr, " - skipped due to PR_ATTR_HIDDEN=1\n");
		return 1;
	}

	bool b_create = false;
	auto iter = drv.m_folder_map.find(item.m_hid);
	if (iter == drv.m_folder_map.end() && parent.type == MAPI_FOLDER) {
		/* PST folder with name -> new folder in store. Create. */
		b_create = true;
	} else if (iter == drv.m_folder_map.end()) {
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
	ep.p_uint32(MAPI_FOLDER);
	ep.p_uint32(item.m_hid);
	ep.p_uint32(parent.type);
	ep.p_uint64(parent.folder_id);
	ep.p_tpropval_a(*props);
	ep.p_uint64(item.m_acl.size());
	for (const auto &ace : item.m_acl.get_perms())
		ep.p_permission_data(ace);
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	auto ret = HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize));
	if (ret < 0)
		throw YError("PK-1024: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	if (ret < 0)
		throw YError("PK-1026: %s", strerror(errno));
	return 0;
}

static message_content_ptr build_message(driver &drv, unsigned int depth,
    kdb_item &item)
{
	auto &props = item.get_props();
	message_content_ptr ctnt(message_content_init());
	if (ctnt == nullptr)
		throw std::bad_alloc();
	ctnt->children.pattachments = attachment_list_init();
	if (ctnt->children.pattachments == nullptr)
		throw std::bad_alloc();
	ctnt->children.prcpts = tarray_set_init();
	if (ctnt->children.prcpts == nullptr)
		throw std::bad_alloc();
	std::swap(ctnt->proplist, *props);

	/* Subitems can be recipients, attachments... */
	auto parent = parent_desc::as_msg(ctnt.get());
	for (size_t i = 0; i < item.m_sub_hids.size(); ++i) {
		auto subitem = item.get_sub_item(i);
		auto ret = do_item(drv, depth, parent, *subitem);
		if (ret < 0)
			throw YError("PK-1015: %s", strerror(-ret));
	}
	return ctnt;
}

static bool skip_message(const TPROPVAL_ARRAY &props)
{
	auto flags = props.get<const uint32_t>(PR_MESSAGE_FLAGS);
	auto mcls  = props.get<const char>(PR_MESSAGE_CLASS);
	if (flags != nullptr && mcls != nullptr && *flags & MSGFLAG_ASSOCIATED &&
	    strcmp(mcls, "IPM.Microsoft.FolderDesign.NamedView") == 0)
		return true;
	if (g_proptag_stubbed != 0) {
		auto flag = props.get<uint8_t>(g_proptag_stubbed);
		if (flag != nullptr && *flag != 0)
			return true;
	}
	return false;
}

static int do_message(driver &drv, unsigned int depth, const parent_desc &parent, kdb_item &item)
{
	auto ctnt = build_message(drv, depth, item);
	if (skip_message(ctnt->proplist))
		return 0;
	ctnt->proplist.erase_if(skip_property);
	if (parent.type == MAPI_ATTACH)
		attachment_content_set_embedded_internal(parent.attach, ctnt.release());
	if (parent.type != MAPI_FOLDER)
		return 0;

	if (g_show_tree)
		gi_dump_msgctnt(depth, *ctnt);
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	if (ep.p_uint32(MAPI_MESSAGE) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(item.m_hid) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(parent.type) != EXT_ERR_SUCCESS ||
	    ep.p_uint64(parent.folder_id) != EXT_ERR_SUCCESS ||
	    ep.p_msgctnt(*ctnt) != EXT_ERR_SUCCESS)
		throw YError("PF-1058");
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	auto ret = HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize));
	if (ret < 0)
		throw YError("PK-1028: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	if (ret < 0)
		throw YError("PK-1030: %s", strerror(errno));
	return 0;
}

static int do_recip(driver &drv, unsigned int depth, const parent_desc &parent, kdb_item &item)
{
	tpropval_array_ptr props = std::move(item.get_props());
	props->erase_if(skip_property);
	if (parent.message->children.prcpts->append_move(std::move(props)) == ENOMEM)
		throw std::bad_alloc();
	return 0;
}

static std::string slurp_file_gz(const char *file)
{
	std::string file_gz, outstr;
	gzFile fp = gzopen(file, "rb");
	if (fp == nullptr && errno == ENOENT) {
		file_gz = file + ".gz"s;
		file = file_gz.c_str();
		fp = gzopen(file, "rb");
	}
	if (fp == nullptr) {
		fprintf(stderr, "gzopen %s: %s\n", file, strerror(errno));
		return outstr;
	}
	auto cl_0 = make_scope_exit([&]() { gzclose(fp); });
	char buf[4096];
	while (!gzeof(fp)) {
		auto rd = gzread(fp, buf, arsizeof(buf));
		/* save errno because gzread might just fail save-restoring it */
		int saved_errno = errno, zerror;
		const char *zerrstr = gzerror(fp, &zerror);
		if (rd < 0 && zerror == Z_ERRNO) {
			fprintf(stderr, "gzread %s: %s (%d): %s\n", file, zerrstr, zerror, strerror(saved_errno));
			break;
		} else if (rd < 0) {
			fprintf(stderr, "gzread %s: %s (%d)\n", file, zerrstr, zerror);
			break;
		}
		if (rd == 0)
			break;
		outstr.append(buf, rd);
	}
	return outstr;
}

static void do_attach_byval(driver &drv, unsigned int depth, unsigned int hid,
    TPROPVAL_ARRAY *props, bool is_optional)
{
	char qstr[96];
	snprintf(qstr, arsizeof(qstr), drv.schema_vers >= 71 ?
	         "SELECT instanceid, filename FROM singleinstances WHERE hierarchyid=%u LIMIT 1" :
	         "SELECT instanceid FROM singleinstances WHERE hierarchyid=%u LIMIT 1", hid);
	auto res = drv.query(qstr);
	auto row = res.fetch_row();
	if (row == nullptr || row[0] == nullptr) {
		if (!is_optional)
			fprintf(stderr, "PK-1012: attachment %u is missing from \"singleinstances\" table and is lost\n", hid);
		return;
	}
	std::string filename;
	auto siid = strtoul(row[0], nullptr, 0);
	if (drv.schema_vers >= 71 && row[1] != nullptr && row[1][0] != '\0')
		filename = g_atxdir + "/"s + row[1] + "/content";
	else
		filename = g_atxdir + "/"s + std::to_string(siid % g_level1_fan) +
		           "/" + std::to_string(siid / g_level1_fan % g_level2_fan) +
		           "/" + std::to_string(siid);
	if (g_show_tree) {
		tree(depth);
		fprintf(stderr, "Attachment source: %s\n", filename.c_str());
	}
	std::string contents = slurp_file_gz(filename.c_str());
	BINARY bin;
	bin.cb = contents.size();
	bin.pv = contents.data();
	if (props->set(PR_ATTACH_DATA_BIN, &bin) != 0)
		throw std::bad_alloc();
}

static int do_attach(driver &drv, unsigned int depth, const parent_desc &parent, kdb_item &item)
{
	attachment_content_ptr atc(attachment_content_init());
	if (atc == nullptr)
		throw std::bad_alloc();
	auto &props = item.get_props();
	auto mode = props->get<uint32_t>(PR_ATTACH_METHOD);

	/*
	 * Scrape all attachments that are in the database, irrespective
	 * of PR_ATTACH_METHOD. Because we can.
	 */
	if ((mode == nullptr || *mode == ATTACH_BY_VALUE) && *g_atxdir != '\0')
		do_attach_byval(drv, depth, item.m_hid, props.get(), mode == nullptr);

	auto saved_show_tree = g_show_tree;
	g_show_tree = false;
	auto new_parent = parent_desc::as_attach(atc.get());
	for (size_t i = 0; i < item.m_sub_hids.size(); ++i) {
		auto subitem = item.get_sub_item(i);
		auto ret = do_item(drv, depth + 1, new_parent, *subitem);
		if (ret < 0) {
			g_show_tree = saved_show_tree;
			return ret;
		}
	}
	g_show_tree = saved_show_tree;

	std::swap(atc->proplist, *props);
	atc->proplist.erase_if(skip_property);
	if (parent.type == MAPI_MESSAGE) {
		if (!attachment_list_append_internal(parent.message->children.pattachments, atc.get()))
			throw std::bad_alloc();
		atc.release();
	}
	return 0;
}

static int do_item(driver &drv, unsigned int depth, const parent_desc &parent, kdb_item &item)
{
	auto new_parent = parent;
	int ret = 0;
	if (g_show_tree)
		do_print(depth++, item);
	if (item.m_mapitype == MAPI_FOLDER) {
		ret = do_folder(drv, depth, parent, item);
		new_parent.type = MAPI_FOLDER;
		new_parent.folder_id = item.m_hid;
	} else if (item.m_mapitype == MAPI_MESSAGE) {
		return do_message(drv, depth, parent, item);
	} else if (item.m_mapitype == MAPI_MAILUSER) {
		ret = do_recip(drv, depth, parent, item);
	} else if (item.m_mapitype == MAPI_ATTACH) {
		ret = do_attach(drv, depth, parent, item);
	} else {
		auto &props = item.get_props();
		if (g_show_tree)
			gi_dump_tpropval_a(depth, *props);
	}
	if (ret < 0)
		return ret;
	if (ret == 1)
		return 0; /* skip item */

	auto istty = isatty(STDERR_FILENO);
	auto last_ts = std::chrono::steady_clock::now();
	unsigned int verb = (new_parent.type == MAPI_STORE ||
	                    new_parent.type == MAPI_FOLDER) &&
	                    !g_show_tree && g_verbose;

	for (size_t i = 0; i < item.m_sub_hids.size(); ++i) {
		auto subitem = item.get_sub_item(i);
		ret = do_item(drv, depth, new_parent, *subitem);
		if (ret < 0)
			return ret;
		auto now_ts = decltype(last_ts)::clock::now();
		auto tsdiff = now_ts - last_ts;
		if (verb > 0 && tsdiff > std::chrono::seconds(1)) {
			fprintf(stderr, " %zu/%zu (%.0f%%)%c", i, item.m_sub_hids.size(),
			        i * 100.0 / item.m_sub_hids.size(), istty ? '\r' : '\n');
			last_ts = now_ts;
			verb = 2;
		}
	}
	if (verb > 0 && istty)
		fprintf(stderr, "\e[2K");
	return 0;
}

static int do_database(std::unique_ptr<driver> &&drv, const char *title)
{
	uint8_t xsplice = g_splice;
	auto ret = HXio_fullwrite(STDOUT_FILENO, "GXMT0002", 8);
	if (ret < 0)
		throw YError("PK-1032: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, &xsplice, sizeof(xsplice));
	if (ret < 0)
		throw YError("PK-1034: %s", strerror(errno));
	xsplice = drv->m_public_store;
	ret = HXio_fullwrite(STDOUT_FILENO, &xsplice, sizeof(xsplice));
	if (ret < 0)
		throw YError("PK-1036: %s", strerror(errno));
	if (g_splice && drv->m_public_store)
		drv->fmap_setup_splice_public();
	else if (g_splice)
		drv->fmap_setup_splice();
	else
		drv->fmap_setup_standard(title);
	gi_dump_folder_map(drv->m_folder_map);
	gi_folder_map_write(drv->m_folder_map);

	auto name_map = do_namemap(*drv);
	gi_dump_name_map(name_map);
	gi_name_map_write(name_map);

	if (g_show_tree)
		fprintf(stderr, "Object tree:\n");
	if (g_only_objs.size() == 0)
		return do_item(*drv, 0, {}, *drv->get_store_item());

	auto pd = parent_desc::as_folder(~0ULL);
	for (const auto hid : g_only_objs) {
		auto item = kdb_item::load_hid_base(*drv, hid);
		ret = do_item(*drv, 0, pd, *item);
		if (ret < 0)
			throw YError("PK-1015: %s", strerror(-ret));
	}
	return 0;
}

static int usermap_read(const char *file, std::unordered_map<std::string, std::string> &map)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Could not read %s: %s\n", file, strerror(errno));
		return EXIT_FAILURE;
	}
	Json::Value jval;
	if (!json_from_str({slurp_data.get(), slurp_len}, jval) ||
	    !jval.isArray()) {
		fprintf(stderr, "%s: parse error\n", file);
		return EXIT_FAILURE;
	}
	for (unsigned int i = 0; i < jval.size(); ++i) {
		auto &row = jval[i];
		if (row["id"].isNull() || row["sv"].isNull())
			continue;
		auto srv_guid = row["sv"].asString();
		HX_strlower(srv_guid.data());
		if (g_acl_conv == aclconv::convert && !row["to"].isNull() &&
		    strchr(row["to"].asCString(), '@') != nullptr)
			map.emplace(row["id"].asString() + "@" + srv_guid + ".kopano.invalid",
				row["to"].asString());
	}
	if (g_acl_conv == aclconv::convert)
		fprintf(stderr, "%s: read %zu entries\n", file, map.size());
	return 0;
}

static void terse_help()
{
	fprintf(stderr, "Usage: SQLPASS=sqlpass gromox-kdb2mt --sql-host kdb.lan "
	        "--src-attach /tmp/at --mbox-guid 0123456789ABCDEFFEDCBA9876543210 jdoe\n");
	fprintf(stderr, "Option overview: gromox-kdb2mt -?\n");
	fprintf(stderr, "Documentation: man gromox-kdb2mt\n");
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	if (g_acl_map_file != nullptr) {
		fprintf(stderr, "The --acl-map option is no longer valid.\n");
		fprintf(stderr, "Use --user-map from now on; this is a new file format. See manpage for details.\n");
		return EXIT_FAILURE;
	}
	if (g_acl_conv == aclconv::convert && g_user_map_file == nullptr) {
		fprintf(stderr, "--acl=convert requires --user-map\n");
		exit(EXIT_FAILURE);
	} else if (g_acl_conv == aclconv::automatic) {
		if (g_user_map_file == nullptr) {
			g_acl_conv = aclconv::noextract;
			fprintf(stderr, "No ACLs will be extracted\n");
		} else {
			g_acl_conv = aclconv::convert;
			fprintf(stderr, "ACLs will be extracted and converted\n");
		}
	}
	if (g_user_map_file != nullptr) {
		int ret = usermap_read(g_user_map_file, g_acl_map);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	if (g_with_hidden < 0)
		g_with_hidden = !g_splice;
	if ((g_srcguid != nullptr) == (g_srcmbox != nullptr)) {
		fprintf(stderr, "Exactly one of --mbox-guid or --mbox-mro must be specified.\n");
		terse_help();
		return EXIT_FAILURE;
	} else if (g_atxdir == nullptr) {
		fprintf(stderr, "You need to specify the --src-at option.\n");
		fprintf(stderr, "(To skip importing file-based attachments, use --src-at \"\".)\n");
		terse_help();
		return EXIT_FAILURE;
	}
	if (argc != 1) {
		terse_help();
		return EXIT_FAILURE;
	}

	int ret = EXIT_SUCCESS;
	sql_login_param sqp;
	if (g_sqlhost != nullptr)
		sqp.host = g_sqlhost;
	if (g_sqlport != nullptr)
		sqp.port = strtoul(g_sqlport, nullptr, 0);
	sqp.dbname = g_sqldb != nullptr ? g_sqldb : "kopano";
	sqp.user = g_sqluser != nullptr ? g_sqluser : "root";
	auto s = getenv("SQLPASS");
	if (s != nullptr) {
		sqp.pass = s;
	} else {
		s = getenv("SRCPASS");
		if (s != nullptr)
			sqp.pass = s;
	}

	try {
		auto drv = make_driver(sqp);
		int ret = 0;
		if (g_srcguid != nullptr)
			ret = drv->open_by_guid(g_srcguid);
		else if (g_srcmbox != nullptr)
			ret = drv->open_by_user(g_srcmbox);
		if (ret != 0) {
			fprintf(stderr, "Problem?!\n");
			return EXIT_FAILURE;
		}
		if (isatty(STDOUT_FILENO)) {
			fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
				"You probably wanted to redirect output into a file or pipe.\n");
			return EXIT_FAILURE;
		}
		ret = do_database(std::move(drv), g_srcguid != nullptr ? g_srcguid : g_srcmbox);
	} catch (const char *e) {
		fprintf(stderr, "kdb2mt: Exception: %s\n", e);
		return -ECANCELED;
	} catch (const std::string &e) {
		fprintf(stderr, "kdb2mt: Exception: %s\n", e.c_str());
		return -ECANCELED;
	} catch (const std::exception &e) {
		fprintf(stderr, "kdb2mt: Exception: %s\n", e.what());
		return -ECANCELED;
	}
	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
