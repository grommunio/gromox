// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
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
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

static constexpr int MB = 1048576, BLOCKUNIT = 512;

namespace {

struct deleter {
	void operator()(sqlite3 *x) const { sqlite3_close(x); }
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
	unsigned long long mb() const { return size / MB; }
	unsigned long long pmb() const { return pad / MB; }

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

struct object_stat {
	size_t refs = 0;
	unsigned int format = 0;
	unsigned long long ifc = 0;
	ustat du;
};

struct ifc_stat {
	unsigned long long ifco = 0, dedup = 0;
	ustat du;
	size_t lost = 0, lost_pad = 0;
};

}

using db_handle = std::unique_ptr<sqlite3, deleter>;
using object_map = std::unordered_map<std::string, object_stat>;

static double ratio(double a, double b) { return a / b; }

static double ratio_sav(double old, double nu)
{
	auto x = 1 - nu / old;
	return x * 100;
}

static struct rfc_stat rfc_count(const std::string &dirname)
{
	struct rfc_stat out;
	struct stat sb;
	std::unique_ptr<DIR, file_deleter> dh(opendir(dirname.c_str()));
	if (dh == nullptr)
		return out;
	auto dfd = dirfd(dh.get());
	if (fstat(dfd, &sb) == 0)
		out.dirs = sb;

	const struct dirent *de;
	while ((de = readdir(dh.get())) != nullptr) {
		auto name = de->d_name;
		if (*name == '.')
			continue;
		if (fstatat(dfd, name, &sb, 0) != 0 ||
		    !S_ISREG(sb.st_mode))
			continue;
		if (class_match_suffix(name, ".midb") == 0)
			out.sent += sb;
		else
			out.recv += sb;
	}
	out.total = out.recv + out.sent + out.dirs;
	return out;
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

static object_map db_read_usecount(sqlite3 *db, mapi_object_type type)
{
	xstmt stm;
	if (type == MAPI_ATTACH)
		stm = gx_sql_prep(db, "SELECT propval FROM attachment_properties AS ap "
		      "WHERE ap.proptag=0x37010102");
	else if (type == MAPI_MESSAGE)
		stm = gx_sql_prep(db, "SELECT propval FROM message_properties AS mp "
		      "WHERE mp.proptag IN (0x1000001f,0x10090102,0x10130102,0x7d001f)");
	else
		throw EXIT_FAILURE;
	if (stm == nullptr)
		throw EXIT_FAILURE;
	object_map m;
	while (stm.step() == SQLITE_ROW)
		++m[stm.col_text(0)].refs;
	return m;
}

static object_stat file_detail(const char *dir, const std::string &obj_id)
{
	object_stat info;
	auto cid = dir + "/cid/"s;
	struct stat sb;
	auto path = cid + obj_id;
	if (std::all_of(obj_id.cbegin(), obj_id.cend(), HX_isdigit)) {
		if (stat(path.c_str(), &sb) == 0) {
			info.format = 0;
			info.refs   = 1;
			info.du     = sb;
			info.ifc    = info.du.size;
			if (info.ifc >= 4)
				info.ifc -= 4;
			return info;
		}
		path += ".v1z";
		if (stat(path.c_str(), &sb) == 0) {
			info.format = 1;
			info.refs   = 1;
			info.du     = sb;
			info.ifc    = gx_decompressed_size(path.c_str());
			if (info.ifc >= 4)
				info.ifc -= 4;
			return info;
		}
		memcpy(&path[path.size()-3], "zst", 3);
		if (stat(path.c_str(), &sb) == 0) {
			info.format = 2;
			info.refs   = 1;
			info.du     = sb;
			info.ifc    = gx_decompressed_size(path.c_str());
		}
	} else if ((obj_id[0] == 'S' || obj_id[0] == 'Y') && obj_id[1] == '-' &&
	    HX_isxdigit(obj_id[2]) && HX_isxdigit(obj_id[3]) && obj_id[4] == '/' &&
	    stat(path.c_str(), &sb) == 0) {
		info.format = 3;
		info.refs   = 1;
		info.du     = sb;
		info.ifc    = gx_decompressed_size(path.c_str());
	}
	return info;
}

/**
 * Read the object map and update it with more per-object info.
 * Sums are built and returned.
 */
static ifc_stat usecount_analyze(const char *dir, object_map &map)
{
	ifc_stat st;
	for (auto &[obj_id, info] : map) {
		auto new_info = file_detail(dir, obj_id);
		if (new_info.refs == 0) {
			st.lost += info.refs;
			++st.lost_pad;
			continue;
		}
		new_info.refs = info.refs;
		info          = std::move(new_info);
		st.ifco   += info.refs * info.ifc;
		st.dedup  += info.ifc;
		st.du     += info.du;
	}
	return st;
}

static void ifc_dump(const ifc_stat &s)
{
	printf("%-30s  %6zu     %6zu\n", "Missing items", s.lost, s.lost_pad);
	printf("%-30s  %6llu MB       -\n", "Informational content", s.ifco / MB);
	printf("%-30s  %6llu MB       -\n", "After deduplication", s.dedup / MB);
	printf("%-30s  %6.3f x        -\n", "Dedup ratio", ratio(s.ifco, s.dedup));
	printf("%-30s  %6.1f %%        -\n", "Dedup savings", ratio_sav(s.ifco, s.dedup));
	printf("%-30s  %6llu MB  %6llu MB\n", "After compression", s.du.mb(), s.du.pmb());
	printf("%-30s  %6.3f x   %6.3f x\n", "File compression ratio",
		ratio(s.dedup, s.du.size), ratio(s.dedup, s.du.pad));
	printf("%-30s  %6.1f %%   %6.1f %%\n", "Savings over dedup",
		ratio_sav(s.dedup, s.du.size), ratio_sav(s.dedup, s.du.pad));
	printf("%-30s  %6.3f x   %6.3f x\n", "IFC compression ratio",
		ratio(s.ifco, s.du.size), ratio(s.ifco, s.du.pad));
	printf("%-30s  %6.1f %%   %6.1f %%\n", "Savings over IFC",
		ratio_sav(s.ifco, s.du.size), ratio_sav(s.ifco, s.du.pad));
}

static ustat count_dirs(const std::string &path)
{
	ustat out;
	struct stat sb;
	std::unique_ptr<DIR, file_deleter> dh(opendir(path.c_str()));
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

int main(int argc, char **argv) try
{
	if (argc < 2) {
		fprintf(stderr, "Usage: mbsize <directory>\n");
		return EXIT_FAILURE;
	}

	printf("                                 Apparent    On FS \n");
	printf("                                ---------  ---------\n");

	auto db_path = argv[1] + "/exmdb/exchange.sqlite3"s;
	ustat sqlite_sb, midb_sb;
	struct stat sb;
	if (stat(db_path.c_str(), &sb) == 0)
		sqlite_sb = sb;
	if (stat((argv[1] + "/exmdb/midb.sqlite3"s).c_str(), &sb) == 0)
		midb_sb = sb;

	auto db = db_open(db_path.c_str());
	if (db == nullptr)
		return EXIT_FAILURE;
	auto nts = db_read_nts(db.get());

	auto msg_uc = db_read_usecount(db.get(), MAPI_MESSAGE);
	auto atx_uc = db_read_usecount(db.get(), MAPI_ATTACH);
	auto msg_ic = usecount_analyze(argv[1], msg_uc);
	auto atx_ic = usecount_analyze(argv[1], atx_uc);

	auto rfc = rfc_count(argv[1] + "/eml"s);
	rfc += rfc_count(argv[1] + "/ext"s);
	printf("== RFC5322/Mbox representation ==\n");
	printf("%-30s  %6llu MB  %6llu MB\n", "Received", rfc.recv.mb(), rfc.recv.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "Sent", rfc.sent.mb(), rfc.sent.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "FS directories", rfc.dirs.mb(), rfc.dirs.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "midb.sqlite3", midb_sb.mb(), midb_sb.pmb());
	rfc.total += midb_sb;
	printf("%-30s  %6llu MB  %6llu MB\n", "Total", rfc.total.mb(), rfc.total.pmb());

	printf("\n== FS: Body analysis ==\n");
	ifc_dump(msg_ic);

	printf("\n== FS: Attachment analysis ==\n");
	ifc_dump(atx_ic);

	printf("\n== MAPI Reported Sizes / Network Transfer Size ==\n");
	printf("%-30s  %6llu MB       -\n", "Store size", nts / MB);
	printf("%-30s  %6llu MB  %6llu MB\n", "... Bodies", msg_ic.ifco / MB, msg_ic.du.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "... Attachments", atx_ic.ifco / MB, atx_ic.du.pmb());
	printf("%-30s  %6llu MB       -\n", "... Other", (nts - msg_ic.ifco - atx_ic.ifco) / MB);

	printf("\n== On-disk sizes ==\n");
	auto cid_dirs = count_dirs(argv[1] + "/cid"s);
	auto du = sqlite_sb + msg_ic.du + atx_ic.du + cid_dirs;
	printf("%-30s  %6llu MB  %6llu MB\n", "Sum of MAPI data", du.mb(), du.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "... exchange.sqlite3", sqlite_sb.mb(), sqlite_sb.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "... Bodies", msg_ic.du.mb(), msg_ic.du.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "... Attachments", atx_ic.du.mb(), atx_ic.du.pmb());
	printf("%-30s  %6llu MB  %6llu MB\n", "... FS directories", cid_dirs.mb(), cid_dirs.pmb());
	printf("%-30s  %6.1f %%   %6.1f %%\n\n", "NTS deviation",
		100 * ratio(nts - du.size, du.size),
		100 * ratio(nts - du.pad, du.pad));

	du += rfc.total;
	printf("%-30s  %6llu MB   %6llu MB\n", "Total MAPI+RFC", du.mb(), du.pmb());
	printf("%-30s  %6.3f x   %6.3f x\n", "Provisioning factor over NTS",
		ratio(du.size, nts), ratio(du.pad, nts));

	return 0;
} catch (int xit) {
	return xit;
}
