// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mysql.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/scope.hpp>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

using namespace std::string_literals;
using namespace gromox;
using namespace gi_dump;
using LLU = unsigned long long;

std::string g_dstuser, g_storedir_s;
const char *g_storedir;
unsigned int g_user_id, g_wet_run = 1;
unsigned int g_public_folder, g_verbose_create;
static thread_local alloc_context g_alloc_mgr;
ec_error_t (*exmdb_local_rules_execute)(const char *, const char *, const char *, eid_t, eid_t, unsigned int);

YError::YError(const std::string &s) : m_str(s)
{}

YError::YError(std::string &&s) : m_str(std::move(s))
{}

YError::YError(const char *fmt, ...)
{
	if (strchr(fmt, '%') == nullptr) {
		m_str = fmt;
		return;
	}
	va_list args;
	va_start(args, fmt);
	std::unique_ptr<char[], gi_delete> strp;
	auto ret = vasprintf(&unique_tie(strp), fmt, args);
	va_end(args);
	m_str = ret >= 0 && strp != nullptr ? strp.get() : "vasprintf";
}

void gi_dump_folder_map(const gi_folder_map_t &map)
{
	if (!g_show_props)
		return;
	fprintf(stderr, "Folder map (%zu entries):\n", map.size());
	fprintf(stderr, "\t# HierID (hex) -> Target name\n");
	for (const auto &[nid, tgt] : map)
		fprintf(stderr, "\t%xh -> %s (%s %llxh)\n", nid, tgt.create_name.c_str(),
		        tgt.create ? "create under" : "splice into", LLU{tgt.fid_to});
}

void gi_dump_name_map(const gi_name_map &map)
{
	if (!g_show_props)
		return;
	fprintf(stderr, "Preamble's named property map (%zu entries):\n", map.size());
	fprintf(stderr, "\t# proptag (hex) -> MAPINAMEID definition:\n");
	for (const auto &[proptag, propname] : map) {
		char g[40];
		propname.guid.to_str(g, std::size(g), 38);
		if (propname.kind == MNID_ID)
			fprintf(stderr, "\t%08xh -> {MNID_ID, %s, %xh}\n",
				proptag, g, static_cast<unsigned int>(propname.lid));
		else if (propname.kind == MNID_STRING)
			fprintf(stderr, "\t%08xh -> {MNID_STRING, %s, %s}\n",
				proptag, g, propname.name.c_str());
	}
}

void gi_folder_map_read(const void *buf, size_t bufsize, gi_folder_map_t &map)
{
	EXT_PULL ep;
	ep.init(buf, bufsize, zalloc, EXT_FLAG_WCOUNT);
	uint64_t max = 0;
	if (ep.g_uint64(&max) != pack_result::ok)
		throw YError("PG-1100");
	for (size_t n = 0; n < max; ++n) {
		uint32_t nid;
		uint8_t create;
		uint64_t fidto;
		std::unique_ptr<char[], gi_delete> name;
		if (ep.g_uint32(&nid) != pack_result::ok ||
		    ep.g_uint8(&create) != pack_result::ok ||
		    ep.g_uint64(&fidto) != pack_result::ok ||
		    ep.g_str(&unique_tie(name)) != pack_result::ok)
			throw YError("PG-1101");
		map.insert_or_assign(nid, tgt_folder{static_cast<bool>(create), fidto, name != nullptr ? name.get() : ""});
	}
}

void gi_folder_map_write(const gi_folder_map_t &map)
{
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	if (ep.p_uint64(map.size()) != pack_result::ok)
		throw YError("PG-1102");
	for (const auto &[nid, tgt] : map)
		if (ep.p_uint32(nid) != pack_result::ok ||
		    ep.p_uint8(!!tgt.create) != pack_result::ok ||
		    ep.p_uint64(tgt.fid_to) != pack_result::ok ||
		    ep.p_str(tgt.create_name.c_str()) != pack_result::ok)
			throw YError("PG-1103");
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
		throw YError("PG-1104: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
		throw YError("PG-1106: %s", strerror(errno));
}

void gi_name_map_read(const void *buf, size_t bufsize, gi_name_map &map)
{
	EXT_PULL ep;
	ep.init(buf, bufsize, zalloc, EXT_FLAG_WCOUNT);
	uint64_t max = 0;
	if (ep.g_uint64(&max) != pack_result::ok)
		throw YError("PG-1108");
	for (size_t n = 0; n < max; ++n) {
		proptag_t proptag;
		PROPERTY_NAME propname{};
		if (ep.g_uint32(&proptag) != pack_result::ok ||
		    ep.g_propname(&propname) != pack_result::ok)
			throw YError("PG-1109");
		try {
			map.insert_or_assign(proptag, propname);
		} catch (const std::bad_alloc &) {
			free(propname.pname);
			throw;
		}
		free(propname.pname);
	}
}

void gi_name_map_write(const gi_name_map &map)
{
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	if (ep.p_uint64(map.size()) != pack_result::ok)
		throw YError("PG-1110");
	for (const auto &[proptag, xn] : map) {
		static_assert(sizeof(gi_name_map::key_type) == sizeof(uint32_t),
			"Something is fishy with the definition of gi_name_map");
		if (ep.p_uint32(proptag) != pack_result::ok ||
		    ep.p_propname(static_cast<PROPERTY_NAME>(xn)) != pack_result::ok)
			throw YError("PG-1111");
	}
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
		throw YError("PG-1112: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
		throw YError("PG-1114: %s", strerror(errno));
}

uint16_t gi_resolve_namedprop(const PROPERTY_XNAME &xpn_req)
{
	PROPERTY_NAME pn_req(xpn_req);
	PROPNAME_ARRAY pna_req;
	pna_req.count = 1;
	pna_req.ppropname = &pn_req;

	PROPID_ARRAY pid_rsp{};
	if (!exmdb_client->get_named_propids(g_storedir, TRUE, &pna_req, &pid_rsp))
		throw YError("PF-1047: request to server for propname mapping failed");
	if (pid_rsp.size() != 1)
		throw YError("PF-1048");
	return pid_rsp[0];
}

int exm_set_change_keys(TPROPVAL_ARRAY *props, eid_t change_num,
    const BINARY *oldpcl)
{
	/* Set the change key and initial PCL for the object */
	XID zxid{g_public_folder ? rop_util_make_domain_guid(g_user_id) :
	         rop_util_make_user_guid(g_user_id), change_num};
	char tmp_buff[22];
	BINARY bxid;
	EXT_PUSH ep;
	if (!ep.init(tmp_buff, std::size(tmp_buff), 0) ||
	    ep.p_xid(zxid) != pack_result::ok) {
		fprintf(stderr, "exm: ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.m_offset;
	PCL pcl;
	if (oldpcl != nullptr)
		pcl.deserialize(oldpcl);
	if (!pcl.replace(zxid)) {
		fprintf(stderr, "exm: pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, gi_delete> pclbin(pcl.serialize());
	if (pclbin == nullptr) {
		fprintf(stderr, "exm: pcl_serialize: ENOMEM\n");
		return -ENOMEM;
	}
	ec_error_t ret;
	if ((ret = props->set(PidTagChangeNumber, &change_num)) != ecSuccess ||
	    (ret = props->set(PR_CHANGE_KEY, &bxid)) != ecSuccess ||
	    (ret = props->set(PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) != ecSuccess) {
		fprintf(stderr, "%s: %s\n", __func__, mapi_strerror(ret));
		return ece2nerrno(ret);
	}
	return 0;
}

int exm_permissions(eid_t fid, const std::vector<PERMISSION_DATA> &perms)
{
	if (perms.size() == 0)
		return 0;
	if (!exmdb_client->update_folder_permission(g_storedir, fid, false,
	    perms.size(), perms.data())) {
		fprintf(stderr, "exm: update_folder_perm(%llxh) RPC failed\n", LLU{fid});
		return -EIO;
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

static std::unique_ptr<MYSQL, mysql_delete> sql_login()
{
	auto cfg = config_file_initd("mysql_adaptor.cfg", PKGSYSCONFDIR, nullptr);
	if (cfg == nullptr) {
		fprintf(stderr, "exm: No mysql_adaptor.cfg: %s\n", strerror(errno));
		return nullptr;
	}
	auto sql_host = cfg->get_value("mysql_host");
	auto v = cfg->get_value("mysql_port");
	auto sql_port = v != nullptr ? strtoul(v, nullptr, 0) : 0;
	auto sql_user = cfg->get_value("mysql_username");
	if (sql_user == nullptr)
		sql_user = "root";
	auto sql_pass = cfg->get_value("mysql_password");
	auto sql_dbname = cfg->get_value("mysql_dbname");
	if (sql_dbname == nullptr)
		sql_dbname = "email";
	std::unique_ptr<MYSQL, mysql_delete> conn(mysql_init(nullptr));
	if (conn == nullptr) {
		fprintf(stderr, "exm: mysql_init failed\n");
		return nullptr;
	}
	if (mysql_real_connect(conn.get(), sql_host, sql_user, sql_pass,
	    sql_dbname, sql_port, nullptr, 0) == nullptr) {
		fprintf(stderr, "exm: Failed to connect to SQL %s@%s: %s\n",
		        sql_user, sql_host, mysql_error(conn.get()));
		return nullptr;
	}
	if (mysql_set_character_set(conn.get(), "utf8mb4") != 0) {
		fprintf(stderr, "mysql: \"utf8mb4\" not available: %s\n",
		        mysql_error(conn.get()));
		return nullptr;
	}
	return conn;
}

static int sql_meta(MYSQL *sqh, const char *username, bool is_domain,
    unsigned int *user_id, std::string &storedir) try
{
	std::string query = is_domain ?
		("SELECT `id`, `homedir` FROM `domains` WHERE `domainname`='"s + sql_escape(sqh, username) + "'") :
		("SELECT `id`, `maildir` FROM `users` WHERE `username`='"s + sql_escape(sqh, username) + "'");
	if (mysql_real_query(sqh, query.c_str(), query.size()) != 0) {
		fprintf(stderr, "exm: mysql_query: %s\n", mysql_error(sqh));
		return -EINVAL;
	}
	DB_RESULT result = mysql_store_result(sqh);
	if (result == nullptr) {
		fprintf(stderr, "exm: mysql_store: %s\n", mysql_error(sqh));
		return -ENOENT;
	}
	auto row = result.fetch_row();
	if (row == nullptr)
		return -ENOENT;
	*user_id = strtoul(row[0], nullptr, 0);
	storedir = znul(row[1]);
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

static int sql_dir_to_user(MYSQL *sqh, const char *dir,
    unsigned int &user_id, std::string &username) try
{
	auto query = "SELECT `id`, `username` FROM `users` WHERE `maildir`='"s + sql_escape(sqh, dir) + "'";
	if (mysql_real_query(sqh, query.c_str(), query.size()) != 0) {
		fprintf(stderr, "exm: mysql_query: %s\n", mysql_error(sqh));
		return -EINVAL;
	}
	DB_RESULT result = mysql_store_result(sqh);
	if (result == nullptr) {
		fprintf(stderr, "exm: mysql_store: %s\n", mysql_error(sqh));
		return -ENOENT;
	}
	auto row = result.fetch_row();
	if (row == nullptr || row[0] == nullptr || row[1] == nullptr)
		return -ENOENT;
	user_id = strtoul(row[0], nullptr, 0);
	username = row[1];
	return 0;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

static void *gi_alloc(size_t z) { return g_alloc_mgr.alloc(z); }
static void gi_free(void *) {}

int gi_setup_from_dir(const char *dir)
{
	auto sqh = sql_login();
	if (sqh == nullptr)
		return EXIT_FAILURE;
	g_storedir_s = dir;
	for (auto z = g_storedir_s.size(); z > 1 && g_storedir_s[z-1] == '/'; --z)
		g_storedir_s[z-1] = '\0';
	g_storedir = g_storedir_s.c_str();
	auto ret = sql_dir_to_user(sqh.get(), g_storedir, g_user_id, g_dstuser);
	if (ret == -ENOENT) {
		fprintf(stderr, "exm: No user with homedir \"%s\"\n", g_storedir);
		fprintf(stderr, "exm: (No attempt was made to locate a domain mailbox)\n");
		return EXIT_FAILURE;
	} else if (ret < 0) {
		fprintf(stderr, "get_id_from_maildir(\"%s\"): %s\n",
		        g_storedir, strerror(-ret));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int gi_setup_from_user(const char *username)
{
	if (*username == '@') {
		g_public_folder = true;
		++username;
	}
	g_dstuser = username;
	auto sqh = sql_login();
	if (sqh == nullptr)
		return EXIT_FAILURE;
	auto ret = sql_meta(sqh.get(), g_dstuser.c_str(), g_public_folder,
	           &g_user_id, g_storedir_s);
	sqh.reset();
	if (ret == -ENOENT) {
		fprintf(stderr, "exm: No such %s \"%s\"\n",
		        g_public_folder ? "domain" : "username", g_dstuser.c_str());
		return EXIT_FAILURE;
	} else if (ret < 0) {
		fprintf(stderr, "exm: sql_meta(\"%s\"): %s\n",
		        g_dstuser.c_str(), strerror(-ret));
		return EXIT_FAILURE;
	}
	g_storedir = g_storedir_s.c_str();
	return EXIT_SUCCESS;
}

namespace {

static constexpr std::pair<const char *, uint8_t> fld_special_names[] = {
	{"", PRIVATE_FID_ROOT},
	{"CALENDAR", PRIVATE_FID_CALENDAR},
	{"COMMON_VIEWS", PRIVATE_FID_COMMON_VIEWS},
	{"CONFLICTS", PRIVATE_FID_CONFLICTS},
	{"CONTACTS", PRIVATE_FID_CONTACTS},
	{"DEFERRED_ACTION", PRIVATE_FID_DEFERRED_ACTION},
	{"DELETED", PRIVATE_FID_DELETED_ITEMS},
	{"DRAFT", PRIVATE_FID_DRAFT},
	{"FINDER", PRIVATE_FID_FINDER},
	{"INBOX", PRIVATE_FID_INBOX},
	{"IPM_SUBTREE", PRIVATE_FID_IPMSUBTREE},
	{"JOURNAL", PRIVATE_FID_JOURNAL},
	{"JUNK", PRIVATE_FID_JUNK},
	{"LOCAL_FAILURES", PRIVATE_FID_LOCAL_FAILURES},
	{"NOTES", PRIVATE_FID_NOTES},
	{"OUTBOX", PRIVATE_FID_OUTBOX},
	{"SENT", PRIVATE_FID_SENT_ITEMS},
	{"SERVER_FAILURES", PRIVATE_FID_SERVER_FAILURES},
	{"SHORTCUTS", PRIVATE_FID_SHORTCUTS},
	{"SYNC_ISSUES", PRIVATE_FID_SYNC_ISSUES},
	{"TASKS", PRIVATE_FID_TASKS},
	{"TRASH", PRIVATE_FID_DELETED_ITEMS},
	{"VIEWS", PRIVATE_FID_VIEWS},
	{"WASTEBASKET", PRIVATE_FID_DELETED_ITEMS},
};

}

eid_t gi_lookup_eid_by_name(const char *dir, const char *name)
{
	char *end = nullptr;
	auto pure_id = strtoull(name, &end, 0);
	if (end != name && *znul(end) == '\0')
		return rop_util_make_eid_ex(1, pure_id);

	const char *sep = strpbrk(name, "/\\"); /* CONST-STRCHR-MARKER */
	if (sep == nullptr)
		sep = "/";
	auto pathcomp = gx_split(name, *sep);
	if (pathcomp.size() == 0)
		return 0;
	auto ptr = std::lower_bound(std::begin(fld_special_names), std::end(fld_special_names),
	           pathcomp[0].c_str(), [](const std::pair<const char *, uint8_t> &pair, const char *x) {
	           	return strcasecmp(pair.first, x) < 0;
	           });
	if (ptr == std::end(fld_special_names) ||
	    strcasecmp(ptr->first, pathcomp[0].c_str()) != 0)
		return 0;

	eid_t fid = rop_util_make_eid_ex(1, ptr->second);
	for (size_t i = 1; i < pathcomp.size(); ++i) {
		if (pathcomp[i].empty())
			continue;
		RESTRICTION_CONTENT rst_4 = {FL_IGNORECASE, PR_DISPLAY_NAME, {PR_DISPLAY_NAME, deconst(pathcomp[i].c_str())}};
		RESTRICTION_EXIST rst_3   = {PR_DISPLAY_NAME};
		RESTRICTION rst_2[2]      = {{RES_EXIST, {&rst_3}}, {RES_CONTENT, {&rst_4}}};
		RESTRICTION_AND_OR rst_1  = {std::size(rst_2), rst_2};
		RESTRICTION rst           = {RES_AND, {&rst_1}};
		uint32_t table_id = 0, rowcount = 0;
		if (!exmdb_client->load_hierarchy_table(dir, fid, nullptr,
		    0, &rst, &table_id, &rowcount)) {
			mlog(LV_ERR, "load_hierarchy_table RPC rejected");
			return 0;
		}
		auto cl_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(dir, table_id); });

		static constexpr proptag_t qtags[] = {PidTagFolderId};
		static constexpr PROPTAG_ARRAY qtaginfo = {std::size(qtags), deconst(qtags)};
		tarray_set rowset;
		if (!exmdb_client->query_table(dir, nullptr, CP_ACP, table_id,
		    &qtaginfo, 0, rowcount, &rowset)) {
			mlog(LV_ERR, "query_table RPC rejected");
			return 0;
		}
		if (rowset.count == 0) {
			return 0;
		} else if (rowset.count > 1) {
			mlog(LV_ERR, "\"%s\" is ambiguous.", pathcomp[i].c_str());
			return 0;
		}
		auto newfid = rowset.pparray[0]->get<const eid_t>(PidTagFolderId);
		if (newfid == nullptr)
			return 0;
		fid = *newfid;
	}
	return fid;
}

int gi_startup_client(unsigned int maxconn)
{
	exmdb_local_rules_execute = reinterpret_cast<decltype(exmdb_local_rules_execute)>(service_query("rules_execute",
	                            "system", typeid(*exmdb_local_rules_execute)));
	exmdb_rpc_alloc = gi_alloc;
	exmdb_rpc_free = gi_free;
	exmdb_client.emplace(maxconn, 0);
	return exmdb_client_run(PKGSYSCONFDIR);
}

void gi_shutdown()
{
	g_alloc_mgr.clear();
	exmdb_client.reset();
	service_release("rules_execute", "system");
}

/**
 * @idx:	zero-based index for selecting attachment
 */
errno_t gi_decapsulate_attachment(message_content_ptr &ctnt, unsigned int idx)
{
	auto &atxlist = *ctnt->children.pattachments;
	if (idx >= atxlist.count || atxlist.pplist[idx])
		return ENOENT;
	auto &ebptr = atxlist.pplist[idx]->pembedded;
	if (ebptr == nullptr)
		return ENOENT;
	auto embed = std::move(ebptr);
	ebptr = nullptr;
	ctnt.reset(embed);
	return 0;
}
