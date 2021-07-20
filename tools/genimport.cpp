// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mysql.h>
#include <string>
#include <unordered_map>
#include <vector>
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
#include <gromox/tpropval_array.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static std::string g_dstuser;
static int g_socket = -1;
static unsigned int g_user_id;
static std::string g_storedir_s;
const char *g_storedir;
unsigned int g_show_tree, g_show_props, g_wet_run = 1;
std::unordered_map<uint16_t, uint16_t> g_propname_cache;
std::unordered_map<uint32_t, tgt_folder> g_folder_map;

void tree(unsigned int depth)
{
	if (!g_show_tree)
		return;
	printf("%-*s \\_ ", depth * 4, "");
}

void tlog(const char *fmt, ...)
{
	if (!g_show_tree)
		return;
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static void gi_dump_tpropval(unsigned int depth, TAGGED_PROPVAL &tp)
{
	if (g_show_props)
		tree(depth);
	tlog("%08xh:", tp.proptag);

	switch (PROP_TYPE(tp.proptag)) {
	case PT_LONG:
		tlog("%u", *static_cast<uint32_t *>(tp.pvalue));
		break;
	case PT_BOOLEAN:
		tlog("%u", *static_cast<uint8_t *>(tp.pvalue));
		break;
	case PT_STRING8:
	case PT_UNICODE: {
		auto s = static_cast<const char *>(tp.pvalue);
		char u = PROP_TYPE(tp.proptag) == PT_UNICODE ? 'w' : 'a';
		auto z = strlen(s);
		if (g_show_props)
			tlog("%cstr(%zu)=\"%s\"", u, z, s);
		else
			tlog("%cstr(%zu)", u, z);
		break;
	}
	case PT_BINARY: {
		auto &b = *static_cast<BINARY *>(tp.pvalue);
		if (g_show_props)
			tlog("bin(%zu)=%s", b.cb, bin2hex(b.pv, b.cb).c_str());
		else
			tlog("bin(%zu)", b.cb);
		break;
	}
	case PT_MV_LONG: {
		auto &sl = *static_cast<LONG_ARRAY *>(tp.pvalue);
		tlog("mvlong[%zu]", sl.count);
		if (!g_show_props)
			break;
		tlog("={", sl.count);
		for (size_t i = 0; i < sl.count; ++i)
			tlog("%u,", sl.pl[i]);
		tlog("}");
		break;
	}
	case PT_MV_BINARY: {
		auto &sb = *static_cast<BINARY_ARRAY *>(tp.pvalue);
		tlog("mvbin[%zu]", sb.count);
		if (!g_show_props)
			break;
		tlog("={", sb.count);
		for (size_t i = 0; i < sb.count; ++i)
			tlog("%s,", bin2hex(sb.pbin[i].pv, sb.pbin[i].cb).c_str());
		tlog("}");
		break;
	}
	case PT_MV_UNICODE: {
		auto &ss = *static_cast<STRING_ARRAY *>(tp.pvalue);
		tlog("mvstr[%zu]", ss.count);
		if (!g_show_props)
			break;
		tlog("={", ss.count);
		for (size_t i = 0; i < ss.count; ++i)
			tlog("\"%s\",", ss.ppstr[i]);
		tlog("}");
		break;
	}
	default:
		break;
	}
	tlog(g_show_props ? "\n" : ", ");
}

void gi_dump_tpropval_a(unsigned int depth, TPROPVAL_ARRAY &props)
{
	if (props.count == 0)
		return;
	tree(depth);
	tlog("props(%d):", props.count);
	tlog(g_show_props ? "\n" : " {");
	for (size_t i = 0; i < props.count; ++i)
		gi_dump_tpropval(depth + 1, props.ppropval[i]);
	if (!g_show_props)
		tlog("}\n");
}

static BOOL exm_dorpc(const char *dir, const EXMDB_REQUEST *prequest, EXMDB_RESPONSE *presponse)
{
	BINARY tb;
	if (exmdb_ext_push_request(prequest, &tb) != EXT_ERR_SUCCESS)
		return false;
	if (!exmdb_client_write_socket(g_socket, &tb)) {
		free(tb.pb);
		return false;
	}
	free(tb.pb);
	if (!exmdb_client_read_socket(g_socket, &tb))
		return false;
	auto cl_0 = make_scope_exit([&]() { free(tb.pb); });
	if (tb.cb < 5 || tb.pb[0] != exmdb_response::SUCCESS)
		return false;
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
		fprintf(stderr, "gx_inet_connect genimport@[%s]:%hu: %s\n",
		        xn->host.c_str(), xn->port, strerror(-fd.get()));
		return -errno;
	}
	exmdb_rpc_exec = exm_dorpc;

	char rid[64];
	snprintf(rid, arsizeof(rid), "genimport:%ld", static_cast<long>(getpid()));
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

int exm_create_folder(uint64_t parent_fld, TPROPVAL_ARRAY *props, bool o_excl,
    uint64_t *new_fld_id)
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
	if (!ep.init(tmp_buff, arsizeof(tmp_buff), 0) ||
	    ep.p_xid(22, &zxid.xid) != EXT_ERR_SUCCESS) {
		fprintf(stderr, "ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.m_offset;
	std::unique_ptr<PCL, gi_delete> pcl(pcl_init());
	if (pcl == nullptr) {
		fprintf(stderr, "pcl_init: ENOMEM\n");
		return -ENOMEM;
	}
	if (!pcl_append(pcl.get(), &zxid)) {
		fprintf(stderr, "pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, gi_delete> pclbin(pcl_serialize(pcl.get()));
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
	auto dn = static_cast<const char *>(tpropval_array_get_propval(props, PR_DISPLAY_NAME));
	if (!o_excl && dn != nullptr) {
		if (!exmdb_client::get_folder_by_name(g_storedir,
		    parent_fld, dn, new_fld_id)) {
			fprintf(stderr, "get_folder_by_name \"%s\" RPC/network failed\n", dn);
			return -EIO;
		}
		if (*new_fld_id != 0)
			return 0;
	}
	if (dn == nullptr)
		dn = "";
	if (!exmdb_client::create_folder_by_properties(g_storedir, 0, props, new_fld_id)) {
		fprintf(stderr, "create_folder_by_properties \"%s\" RPC failed\n", dn);
		return -EIO;
	}
	if (*new_fld_id == 0) {
		fprintf(stderr, "createfolder: folder \"%s\" already existed or some other problem\n", dn);
		return -EEXIST;
	}
	return 0;
}

int exm_create_msg(uint64_t parent_fld, MESSAGE_CONTENT *ctnt)
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
	if (!ep.init(tmp_buff, arsizeof(tmp_buff), 0) ||
	    ep.p_xid(22, &zxid.xid) != EXT_ERR_SUCCESS) {
		fprintf(stderr, "ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.m_offset;
	std::unique_ptr<PCL, gi_delete> pcl(pcl_init());
	if (pcl == nullptr) {
		fprintf(stderr, "pcl_init: ENOMEM\n");
		return -ENOMEM;
	}
	if (!pcl_append(pcl.get(), &zxid)) {
		fprintf(stderr, "pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, gi_delete> pclbin(pcl_serialize(pcl.get()));
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
	if (!exmdb_client::write_message(g_storedir, g_dstuser.c_str(), 65001,
	    parent_fld, ctnt, &e_result)) {
		fprintf(stderr, "write_message RPC failed\n");
		return -EIO;
	} else if (e_result != 0) {
		fprintf(stderr, "write_message: gxerr %d\n", e_result);
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

int gi_setup(const char *username)
{
	auto sqh = sql_login();
	if (sqh == nullptr)
		return EXIT_FAILURE;
	auto ret = sql_meta(sqh, username, &g_user_id, g_storedir_s);
	mysql_close(sqh);
	if (ret == -ENOENT) {
		fprintf(stderr, "No such user \"%s\"\n", username);
		return EXIT_FAILURE;
	} else if (ret < 0) {
		fprintf(stderr, "sql_meta(\"%s\"): %s\n", username, strerror(-ret));
		return EXIT_FAILURE;
	}
	g_dstuser = username;
	g_storedir = g_storedir_s.c_str();
	g_socket = exm_connect(g_storedir);
	if (g_socket < 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
