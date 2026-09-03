// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2026 grommunio GmbH
// This file is part of Gromox.
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <unordered_map>
#include <libHX/ctype_helper.h>
#include <libHX/option.h>
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

static char s_unit[] = "MB";
static unsigned long long UNIT = 1048576;
static constexpr int BLOCKUNIT = 512;

namespace {

struct deleter {
	void operator()(sqlite3 *x) const { sqlite3_close_v2(x); }
};

struct ustat {
	ustat() = default;
	ustat(unsigned long long a, unsigned long long b) : size(a), pad(b) {}
	ustat(const struct stat &o) : size(o.st_size), pad(o.st_blocks * BLOCKUNIT) {}
	ustat operator+(const ustat &o) const { return {size + o.size, pad + o.pad}; }
	ustat &operator+=(const ustat &o)
	{
		size += o.size;
		pad += o.pad;
		return *this;
	}
	unsigned long long units() const { return size / UNIT; }
	unsigned long long punits() const { return pad / UNIT; }

	unsigned long long size = 0, pad = 0;
};

struct rfc_stat {
	rfc_stat &operator+=(const rfc_stat &o)
	{
		recv  += o.recv;
		sent  += o.sent;
		dirs  += o.dirs;
		total += o.total;
		return *this;
	}
	ustat recv, sent, dirs, total;
};

/**
 * Information about a file
 * @refs: referenced by this many MAPI objects (i.e. deduplication factor)
 */
struct object_stat {
	size_t refs = 0;
	unsigned long long ifc = 0;
	ustat du;
	proptag_t proptag{};
	int8_t format = -1;
};

struct ifc_stat {
	unsigned long long ifco = 0, dedup = 0;
	ustat du;
	size_t lost = 0, lost_pad = 0;
};

}

using dir_ptr = std::unique_ptr<DIR, file_deleter>;
using db_handle = std::unique_ptr<sqlite3, deleter>;
using object_map = std::unordered_map<std::string, object_stat>;
using stat_map = std::unordered_map<std::string, struct stat>;

static unsigned int g_show_orphans;
static constexpr HXoption g_options_table[] = {
	{{}, 'B', HXTYPE_STRING, {}, {}, {}, {}, "Report byte values in this unit (-BK, -BM, -BG, -B4K, -B512)"},
	{"orphans", 0, HXTYPE_NONE, &g_show_orphans, {}, {}, {}, "Show orphaned files"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static double ratio(double a, double b) { return b == 0 ? NAN : a / b; }

static double ratio_sav(double old, double nu)
{
	if (old == nu)
		return 0;
	else if (old == 0)
		return -INFINITY;
	return 100 * (1 - nu / old);
}

static bool looks_like_midb_generated(const char *name)
{
	auto dot = strchr(name, '.');
	if (dot == nullptr)
		return false;
	if (dot[1] == 'm' && strtoul(&dot[2], nullptr, 10) != 0)
		return true;
	if (class_match_suffix(name, ".midb") == 0)
		return true;
	return false;
}

static db_handle db_open(const std::string &path)
{
	sqlite3 *dbx = nullptr;
	auto ret = sqlite3_open_v2(path.c_str(), &dbx,
	           SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
	db_handle db(std::move(dbx));
	dbx = nullptr;
	if (ret != SQLITE_OK) {
		fprintf(stderr, "open %s: %s\n", path.c_str(), sqlite3_errstr(ret));
		return nullptr;
	}
	return db;
}

static unsigned long long db_read_nts(sqlite3 *db)
{
	auto stm = gx_sql_prep(db, "SELECT propval FROM store_properties WHERE proptag=0xe080014");
	return stm != nullptr && stm.step() == SQLITE_ROW ? stm.col_uint64(0) : 0;
}

/**
 * Scan exchange.sqlite3 for CID file references and yield an associative
 * container that indicates how often each content object was referenced.
 *
 * @db:   opened exchange.sqlite3
 * @type: property set which to examine; either %MAPI_MESSAGE or %MAPI_ATTACH.
 */
static object_map db_read_cid_refs(sqlite3 *db, mapi_object_type type)
{
	xstmt stm;
	if (type == MAPI_ATTACH)
		stm = gx_sql_prep(db, "SELECT proptag, propval FROM attachment_properties AS ap "
		      "WHERE ap.proptag=0x37010102");
	else if (type == MAPI_MESSAGE)
		stm = gx_sql_prep(db, "SELECT proptag, propval FROM message_properties AS mp "
		      "WHERE mp.proptag IN (0x1000001e,0x1000001f,0x10090102,0x10130102,0x7d001e,0x7d001f)");
	else
		throw EXIT_FAILURE;
	if (stm == nullptr)
		throw EXIT_FAILURE;

	/* The columns in question are references to filename rather than the actual content */
	object_map m;
	while (stm.step() == SQLITE_ROW) {
		auto &entry = m[stm.col_text(1)];
		++entry.refs;
		entry.proptag = stm.col_uint64(0);
	}
	return m;
}

static bool digits_only(const char *s)
{
	for (; *s != '\0'; ++s)
		if (!HX_isdigit(*s))
			return false;
	return true;
}

/**
 * Resolve a CID filename reference and determine/record more information, such as:
 * - Gromox header/compression type
 * - actual disk usage of the content object in fs blocks (record fs overhead)
 */
static void cid_more_detail(const char *dir, const std::string &obj_id,
    object_stat &info)
{
	auto cid = dir + "/cid/"s;
	struct stat sb;
	auto path = cid + obj_id;

	if (digits_only(obj_id.c_str())) {
		/* #codepoints marker in classic PT_UNICODE files (v0/v1z only) */
		bool strip = info.proptag == PR_BODY ||
		             info.proptag == PR_TRANSPORT_MESSAGE_HEADERS;

		if (stat(path.c_str(), &sb) == 0) {
			info.format = 0;
			info.du     = sb;
			info.ifc    = info.du.size;
			if (strip && info.ifc >= 4)
				info.ifc -= 4;
		}
		path += ".v1z";
		if (stat(path.c_str(), &sb) == 0) {
			info.format = 1;
			info.du     = sb;
			info.ifc    = gx_decompressed_size(path.c_str());
			if (strip && info.ifc >= 4)
				info.ifc -= 4;
		}
		memcpy(&path[path.size()-3], "zst", 3);
		if (stat(path.c_str(), &sb) == 0) {
			info.format = 2;
			info.du     = sb;
			info.ifc    = gx_decompressed_size(path.c_str());
		}
	} else if ((obj_id[0] == 'S' || obj_id[0] == 'Y') && obj_id[1] == '-' &&
	    HX_isxdigit(obj_id[2]) && HX_isxdigit(obj_id[3]) && obj_id[4] == '/' &&
	    stat(path.c_str(), &sb) == 0) {
		info.format = 3;
		info.du     = sb;
		info.ifc    = gx_decompressed_size(path.c_str());
	}
}

/**
 * Reads an object map (populated with deduplication info) and updates it with more
 * per-object info. In particular, it
 * Sums are built and returned.
 */
static ifc_stat cid_analyze(const char *dir, object_map &map)
{
	ifc_stat st;
	for (auto &[obj_id, info] : map) {
		cid_more_detail(dir, obj_id, info);
		if (info.format < 0) {
			st.lost += info.refs;
			++st.lost_pad;
			continue;
		}
		st.ifco   += info.refs * info.ifc;
		st.dedup  += info.ifc;
		st.du     += info.du;
	}
	return st;
}

/**
 * Scan a sqlite3 file for EML file references and yield an associative
 * container that indicates how often each content object was referenced.
 *
 * @db: opened exchange.sqlite3 or midb.sqlite3
 *      (both share the same table column name)
 * @m:  output
 */
static int db_read_eml_refs(sqlite3 *db, object_map &m)
{
	auto stm = gx_sql_prep(db, "SELECT mid_string FROM messages");
	if (stm == nullptr)
		return -1;
	while (stm.step() == SQLITE_ROW)
		++m[stm.col_text(0)].refs;
	return 0;
}

static rfc_stat eml_analyze(const char *maildir, const object_map &map)
{
	rfc_stat out;
	dir_ptr dh_eml(opendir((maildir + "/eml"s).c_str()));
	dir_ptr dh_ext(opendir((maildir + "/ext"s).c_str()));
	auto dfd_eml = dh_eml != nullptr ? dirfd(dh_eml.get()) : -1;
	auto dfd_ext = dh_ext != nullptr ? dirfd(dh_ext.get()) : -1;

	for (const auto &[key, info] : map) {
		struct stat sb;
		bool maybe_midb = looks_like_midb_generated(key.c_str());
		if (fstatat(dfd_eml, key.c_str(), &sb, 0) == 0 && S_ISREG(sb.st_mode)) {
			if (maybe_midb)
				out.sent += sb;
			else
				out.recv += sb;
			out.total += sb;
		}
		if (fstatat(dfd_ext, key.c_str(), &sb, 0) == 0 && S_ISREG(sb.st_mode)) {
			if (maybe_midb)
				out.sent += sb;
			else
				out.recv += sb;
			out.total += sb;
		}
	}
	return out;
}

static void ifc_dump(const ifc_stat &s)
{
	printf("%-30s  %9zu     %9zu\n", "Missing items", s.lost, s.lost_pad);
	printf("%-30s  %9llu %-2s          -\n", "Informational content", s.ifco / UNIT, s_unit);
	printf("%-30s  %9llu %-2s          -\n", "After deduplication", s.dedup / UNIT, s_unit);
	printf("%-30s  %9.3f x           -\n", "Dedup ratio", ratio(s.ifco, s.dedup));
	printf("%-30s  %9.1f %%           -\n", "Dedup savings", ratio_sav(s.ifco, s.dedup));
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "After compression", s.du.units(), s_unit, s.du.punits(), s_unit);
	printf("%-30s  %9.3f x   %9.3f x\n", "File compression ratio",
		ratio(s.dedup, s.du.size), ratio(s.dedup, s.du.pad));
	printf("%-30s  %9.1f %%   %9.1f %%\n", "Savings over dedup",
		ratio_sav(s.dedup, s.du.size), ratio_sav(s.dedup, s.du.pad));
	printf("%-30s  %9.3f x   %9.3f x\n", "IFC compression ratio",
		ratio(s.ifco, s.du.size), ratio(s.ifco, s.du.pad));
	printf("%-30s  %9.1f %%   %9.1f %%\n", "Savings over IFC",
		ratio_sav(s.ifco, s.du.size), ratio_sav(s.ifco, s.du.pad));
}

static ustat count_dirs(const std::string &path)
{
	ustat out;
	struct stat sb;
	dir_ptr dh(opendir(path.c_str()));
	if (dh == nullptr)
		return out;
	auto dfd = dirfd(dh.get());
	if (fstat(dfd, &sb) == 0)
		out += sb;
	const struct dirent *de;
	while ((de = readdir(dh.get())) != nullptr) {
		auto name = de->d_name;
		if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
			continue;
		if (fstatat(dfd, name, &sb, 0) != 0 || !S_ISDIR(sb.st_mode))
			continue;
		out += sb;
		out += count_dirs(path + "/" + name);
	}
	return out;
}

/**
 * Simply find all filenames (recursive entrypoint with directory fd)
 *
 * @prefix: prefix for dh
 * @dh:     directory to scan
 * @outmap: collected filenames
 */
static int sm_find_files(const std::string &prefix, DIR *dh, stat_map &outmap)
{
	const struct dirent *de;
	auto dfd = dirfd(dh);
	while ((de = readdir(dh)) != nullptr) {
		auto name = de->d_name;
		if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
			continue;
		struct stat sb;
		if (fstatat(dfd, name, &sb, 0) != 0)
			continue;
		auto de_full = prefix + "/" + name;
		outmap.emplace(de_full, sb);
		if (!S_ISDIR(sb.st_mode))
			continue;
		dir_ptr sub_dh(opendir(de_full.c_str()));
		if (sub_dh == nullptr) {
			fprintf(stderr, "opendir %s: %s\n", de_full.c_str(), strerror(errno));
			continue;
		}
		auto err = sm_find_files(de_full, sub_dh.get(), outmap);
		if (err < 0)
			return err;
	}
	return 0;
}

/**
 * Make a record of all files recursively, and collect their stat() results.
 *
 * @path:   directory to scan
 * @outmap: collected filenames
 */
static stat_map sm_find_files(const std::string &path)
{
	stat_map outmap;
	struct stat sb;
	dir_ptr dh(opendir(path.c_str()));
	if (dh == nullptr) {
		fprintf(stderr, "opendir %s: %s\n", path.c_str(), strerror(errno));
		return {};
	}
	if (fstatat(dirfd(dh.get()), ".", &sb, 0) != 0)
		return {};
	outmap.emplace(path, sb);
	if (sm_find_files(path, dh.get(), outmap) < 0)
		return {};
	return outmap;
}

/**
 * @map:    complete set of filenames in the maildir
 * @omap:   a set of well-referenced file objects
 * @prefix: directory prefix for keys in omap
 */
static size_t sm_prune_files(stat_map &smap, const object_map &omap,
    const std::string &prefix)
{
	size_t z = 0;
	for (const auto &[om_key, om_info] : omap) {
		if (om_key.empty())
			continue;
		std::string fn;
		if (prefix.empty())
			fn = om_key;
		else
			fn = prefix + "/" + om_key;
		z += smap.erase(fn);
		z += smap.erase(fn + ".v1z");
		z += smap.erase(fn + ".zst");
	}
	return z;
}

static ustat sm_cumulate(const stat_map &smap, unsigned int type)
{
	ustat out{};
	for (const auto &[key, sb] : smap) {
		bool include = false;
		if (type == S_IFDIR && S_ISDIR(sb.st_mode))
			include = true;
		else if (type == 0 && !S_ISDIR(sb.st_mode))
			include = true;
		if (include)
			out += sb;
	}
	return out;
}

static uint64_t subabs(uint64_t a, uint64_t b)
{
	return a >= b ? a - b : b - a;
}

int main(int argc, char **argv) try
{
	HXopt6_auto_result result{};
	if (HX_getopt6(g_options_table, argc, argv, &result,
	    HXOPT_USAGEONERR | HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	for (int i = 0; i < result.nopts; ++i) {
		if (result.desc[i]->sh == 'B') {
			switch (toupper(result.oarg[i][0])) {
			case 'B':
				UNIT = 1; strcpy(s_unit, "B"); break;
			case 'K':
				UNIT = 1ULL << 10; strcpy(s_unit, "KB"); break;
			case 'M':
				UNIT = 1ULL << 20; strcpy(s_unit, "MB"); break;
			case 'G':
				UNIT = 1ULL << 30; strcpy(s_unit, "GB"); break;
			case 'T':
				UNIT = 1ULL << 40; strcpy(s_unit, "TB"); break;
			default:
				fprintf(stderr, "Unrecognized syntax for -B: \"%s\"\n", result.oarg[i]);
				return EXIT_FAILURE;
			}
		}
	}
	if (result.nargs < 1) {
		fprintf(stderr, "Usage: mbsize <directory>\n");
		return EXIT_FAILURE;
	}

	printf("                                 Apparent         On FS \n");
	printf("                                ------------  ------------\n");

	auto db_path = result.uarg[0] + "/exmdb/exchange.sqlite3"s;
	db_handle db, midb;
	ustat sqlite_sb, midb_sb;
	struct stat sb;
	if (stat(db_path.c_str(), &sb) == 0) {
		sqlite_sb = sb;
		db = db_open(db_path.c_str());
		if (db == nullptr)
			return EXIT_FAILURE;
	}
	auto midb_path = result.uarg[0] + "/exmdb/midb.sqlite3"s;
	if (stat(midb_path.c_str(), &sb) == 0) {
		midb_sb = sb;
		midb = db_open(midb_path.c_str());
	}

	auto nts = db_read_nts(db.get());
	auto allfiles = sm_find_files(result.uarg[0]);
	if (allfiles.empty())
		return EXIT_FAILURE;
	/* Prune well-known files */
	ustat wellknown;
	for (const auto &fn : {"exmdb/exchange.sqlite3", "exmdb/exchange.sqlite3-shm", "exmdb/exchange.sqlite3-wal",
	                       "exmdb/midb.sqlite3", "exmdb/midb.sqlite3-shm", "exmdb/midb.sqlite3-wal",
	                       "tables.sqlite3", "tables.sqlite3-shm", "tables.sqlite3-wal",
	                       "config/autoreply.cfg", "config/external-reply", "config/internal-reply",
	                       "config/portrait.jpg", "config/sendas.txt", "config/delegates.txt"}) {
		auto path = result.uarg[0] + "/"s + fn;
		if (stat(path.c_str(), &sb) == 0)
			wellknown += sb;
		allfiles.erase(path);
	}

	auto msg_refs = db_read_cid_refs(db.get(), MAPI_MESSAGE);
	sm_prune_files(allfiles, msg_refs, result.uarg[0] + "/cid"s);
	auto atx_refs = db_read_cid_refs(db.get(), MAPI_ATTACH);
	sm_prune_files(allfiles, atx_refs, result.uarg[0] + "/cid"s);
	auto msg_ic = cid_analyze(result.uarg[0], msg_refs);
	auto atx_ic = cid_analyze(result.uarg[0], atx_refs);
	msg_refs.clear();
	atx_refs.clear();
	object_map eml_refs;
	if (db_read_eml_refs(db.get(), eml_refs) < 0)
		return EXIT_FAILURE;
	if (midb != nullptr && db_read_eml_refs(midb.get(), eml_refs) < 0)
		return EXIT_FAILURE;
	sm_prune_files(allfiles, eml_refs, result.uarg[0] + "/eml"s);
	sm_prune_files(allfiles, eml_refs, result.uarg[0] + "/ext"s);
	auto rfc = eml_analyze(result.uarg[0], eml_refs);
	auto rfc1 = rfc;
	auto dirmeta = sm_cumulate(allfiles, S_IFDIR);
	auto orphans = sm_cumulate(allfiles, 0);

	printf("== RFC5322/Mbox representation ==\n");
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Tracked files in EML/EXT", rfc1.total.units(), s_unit, rfc1.total.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... Received", rfc.recv.units(), s_unit, rfc.recv.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... Sent", rfc.sent.units(), s_unit, rfc.sent.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "midb.sqlite3", midb_sb.units(), s_unit, midb_sb.punits(), s_unit);
	rfc.total += midb_sb;
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Files combined (no dirs)", rfc.total.units(), s_unit, rfc.total.punits(), s_unit);

	printf("\n== FS: Body compression analysis ==\n");
	ifc_dump(msg_ic);

	printf("\n== FS: Attachment compression analysis ==\n");
	ifc_dump(atx_ic);

	printf("\n== MAPI Reported Sizes / Network Transfer Size ==\n");
	printf("%-30s  %9llu %-2s          -\n", "Store size", nts / UNIT, s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... Bodies", msg_ic.ifco / UNIT, s_unit, msg_ic.du.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... Attachments", atx_ic.ifco / UNIT, s_unit, atx_ic.du.punits(), s_unit);
	printf("%-30s  %9llu %-2s          -\n", "... Other properties", (nts - msg_ic.ifco - atx_ic.ifco) / UNIT, s_unit);

	printf("\n== MAPI on-disk ==\n");
	auto du = sqlite_sb + msg_ic.du + atx_ic.du;
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Sum of MAPI data", du.units(), s_unit, du.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... exchange.sqlite3", sqlite_sb.units(), s_unit, sqlite_sb.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... Bodies", msg_ic.du.units(), s_unit, msg_ic.du.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "... Attachments", atx_ic.du.units(), s_unit, atx_ic.du.punits(), s_unit);
	printf("%-30s  %9.1f %%   %9.1f %%\n", "NTS deviation",
		100 * ratio(subabs(nts, du.size), du.size),
		100 * ratio(subabs(nts, du.pad), du.pad));

	printf("\n== General on-disk overview ==\n");
	du = rfc1.total + msg_ic.du + atx_ic.du + wellknown + dirmeta + orphans;
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Tracked files in eml/,ext/", rfc1.total.units(), s_unit, rfc1.total.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Tracked bodies in cid/", msg_ic.du.units(), s_unit, msg_ic.du.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Tracked attachments in cid/", atx_ic.du.units(), s_unit, atx_ic.du.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Databases & user config", wellknown.units(), s_unit, wellknown.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "FS directories", dirmeta.units(), s_unit, dirmeta.punits(), s_unit);
	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Orphaned/Unrecognized files", orphans.units(), s_unit, orphans.punits(), s_unit);
	if (g_show_orphans)
		for (const auto &[key, sb] : allfiles)
			if (!S_ISDIR(sb.st_mode))
				printf("\t%s\n", key.c_str());

	printf("%-30s  %9llu %-2s  %9llu %-2s\n", "Total", du.units(), s_unit, du.punits(), s_unit);
	printf("%-30s  %9.3f x   %9.3f x\n", "Provisioning factor over NTS",
		ratio(du.size, nts), ratio(du.pad, nts));

	return 0;
} catch (int xit) {
	return xit;
}
