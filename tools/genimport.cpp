// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1
#include <algorithm>
#include <cerrno>
#include <cstdarg>
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
#include <gromox/tie.hpp>
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

gi_name_map::~gi_name_map()
{
	for (auto &e : *this)
		if (e.second.kind == MNID_STRING)
			free(e.second.pname);
}

void tree(unsigned int depth)
{
	if (!g_show_tree)
		return;
	fprintf(stderr, "%-*s \\_ ", depth * 4, "");
}

void tlog(const char *fmt, ...)
{
	if (!g_show_tree)
		return;
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static void gi_dump_tpropval(unsigned int depth, const TAGGED_PROPVAL &tp)
{
	if (g_show_props)
		tree(depth);
	tlog("%08xh:", tp.proptag);

	switch (PROP_TYPE(tp.proptag)) {
	case PT_LONG: {
		unsigned long v = *static_cast<uint32_t *>(tp.pvalue);
		tlog("%lu/%lxh", v, v);
		break;
	}
	case PT_I8: {
		unsigned long long v = *static_cast<uint64_t *>(tp.pvalue);
		tlog("%llu/%llxh", v, v);
		break;
	}
	case PT_CURRENCY: {
		unsigned long long v = *static_cast<uint64_t *>(tp.pvalue);
		tlog("%llu.%04llu", v / 1000, v % 1000);
		break;
	}
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
	case PT_SYSTIME: {
		unsigned long long v = *static_cast<uint64_t *>(tp.pvalue);
		time_t ut = rop_util_nttime_to_unix(v);
		char buf[80]{};
		auto tm = localtime(&ut);
		if (tm != nullptr)
			strftime(buf, arsizeof(buf), "%FT%T", tm);
		tlog("%s (raw %llxh)", buf, v);
		break;
	}
	case PT_BINARY: {
		auto &b = *static_cast<BINARY *>(tp.pvalue);
		if (g_show_props)
			tlog("bin(%zu)=%s", static_cast<size_t>(b.cb), bin2hex(b.pv, b.cb).c_str());
		else
			tlog("bin(%zu)", static_cast<size_t>(b.cb));
		break;
	}
	case PT_MV_LONG: {
		auto &sl = *static_cast<LONG_ARRAY *>(tp.pvalue);
		tlog("mvlong[%zu]", static_cast<size_t>(sl.count));
		if (!g_show_props)
			break;
		tlog("={");
		for (size_t i = 0; i < sl.count; ++i)
			tlog("%u,", sl.pl[i]);
		tlog("}");
		break;
	}
	case PT_MV_BINARY: {
		auto &sb = *static_cast<BINARY_ARRAY *>(tp.pvalue);
		tlog("mvbin[%zu]", static_cast<size_t>(sb.count));
		if (!g_show_props)
			break;
		tlog("={");
		for (size_t i = 0; i < sb.count; ++i)
			tlog("%s,", bin2hex(sb.pbin[i].pv, sb.pbin[i].cb).c_str());
		tlog("}");
		break;
	}
	case PT_MV_UNICODE: {
		auto &ss = *static_cast<STRING_ARRAY *>(tp.pvalue);
		tlog("mvstr[%zu]", static_cast<size_t>(ss.count));
		if (!g_show_props)
			break;
		tlog("={");
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

void gi_dump_tpropval_a(unsigned int depth, const TPROPVAL_ARRAY &props)
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
	auto p = static_cast<const char *>(tpropval_array_get_propval(&props, PR_DISPLAY_NAME));
	if (p != nullptr) {
		tree(depth);
		tlog("display_name=\"%s\"\n", p);
	}
	p = static_cast<const char *>(tpropval_array_get_propval(&props, PR_SUBJECT));
	if (p != nullptr) {
		tree(depth);
		tlog("subject=\"%s\"\n", p);
	}
	p = static_cast<const char *>(tpropval_array_get_propval(&props, PR_ATTACH_LONG_FILENAME));
	if (p != nullptr) {
		tree(depth);
		tlog("filename=\"%s\"\n", p);
	}
}

void gi_dump_msgctnt(unsigned int depth, const MESSAGE_CONTENT &ctnt)
{
	gi_dump_tpropval_a(depth, ctnt.proplist);
	auto &r = ctnt.children.prcpts;
	if (r != nullptr) {
		for (size_t n = 0; n < r->count; ++n) {
			tree(depth);
			tlog("Recipient #%zu\n", n);
			if (r->pparray[n] != nullptr)
				gi_dump_tpropval_a(depth + 1, *r->pparray[n]);
		}
	}
	auto &a = ctnt.children.pattachments;
	if (a != nullptr) {
		for (size_t n = 0; n < a->count; ++n) {
			tree(depth);
			tlog("Attachment #%zu\n", n);
			auto atc = a->pplist[n];
			if (atc == nullptr)
				continue;
			gi_dump_tpropval_a(depth + 1, atc->proplist);
			if (atc->pembedded == nullptr)
				continue;
			tree(depth + 1);
			tlog("Embedded message\n");
			gi_dump_msgctnt(depth + 2, *atc->pembedded);
		}
	}
}

void gi_dump_folder_map(const gi_folder_map_t &map)
{
	if (!g_show_props)
		return;
	fprintf(stderr, "Folder map (%zu entries):\n", map.size());
	fprintf(stderr, "\t# HierID (hex) -> Target name\n");
	for (const auto &[nid, tgt] : map)
		fprintf(stderr, "\t%xh -> %s%s\n", nid, tgt.create_name.c_str(),
		        tgt.create ? " (create)" : "");
}

void gi_dump_name_map(const gi_name_map &map)
{
	if (!g_show_props)
		return;
	fprintf(stderr, "Named properties (%zu entries):\n", map.size());
	fprintf(stderr, "\t# PROPID (hex) <-> MAPINAMEID definition:\n");
	for (const auto &[propid, propname] : map) {
		if (propname.kind == MNID_ID)
			fprintf(stderr, "\t%08xh <-> {MNID_ID, %s, %xh}\n",
				propid, bin2hex(propname.guid).c_str(),
				static_cast<unsigned int>(propname.lid));
		else if (propname.kind == MNID_STRING)
			fprintf(stderr, "\t%08xh <-> {MNID_STRING, %s, %s}\n",
				propid, bin2hex(propname.guid).c_str(), propname.pname);
	}
}

static void *zalloc(size_t z) { return calloc(1, z); }

void gi_folder_map_read(const void *buf, size_t bufsize, gi_folder_map_t &map)
{
	EXT_PULL ep;
	ep.init(buf, bufsize, zalloc, EXT_FLAG_WCOUNT);
	uint64_t max = 0;
	if (ep.g_uint64(&max) != EXT_ERR_SUCCESS)
		throw YError("PG-1100");
	for (size_t n = 0; n < max; ++n) {
		uint32_t nid;
		uint8_t create;
		uint64_t fidto;
		std::unique_ptr<char[], gi_delete> name;
		if (ep.g_uint32(&nid) != EXT_ERR_SUCCESS ||
		    ep.g_uint8(&create) != EXT_ERR_SUCCESS ||
		    ep.g_uint64(&fidto) != EXT_ERR_SUCCESS ||
		    ep.g_str(&unique_tie(name)) != EXT_ERR_SUCCESS)
			throw YError("PG-1101");
		map.insert_or_assign(nid, tgt_folder{static_cast<bool>(create), fidto, name != nullptr ? name.get() : ""});
	}
}

void gi_folder_map_write(const gi_folder_map_t &map)
{
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	if (ep.p_uint64(map.size()) != EXT_ERR_SUCCESS)
		throw YError("PG-1102");
	for (const auto &[nid, tgt] : map)
		if (ep.p_uint32(nid) != EXT_ERR_SUCCESS ||
		    ep.p_uint8(!!tgt.create) != EXT_ERR_SUCCESS ||
		    ep.p_uint64(tgt.fid_to) != EXT_ERR_SUCCESS ||
		    ep.p_str(tgt.create_name.c_str()) != EXT_ERR_SUCCESS)
			throw YError("PG-1103");
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	auto ret = write(STDOUT_FILENO, &xsize, sizeof(xsize));
	if (ret < 0)
		throw YError("PG-1104: %s", strerror(errno));
	else if (ret != sizeof(xsize))
		throw YError("PG-1105");
	ret = write(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	if (ret < 0)
		throw YError("PG-1106: %s", strerror(errno));
	else if (ret != ep.m_offset)
		throw YError("PG-1107");
}

void gi_name_map_read(const void *buf, size_t bufsize, gi_name_map &map)
{
	EXT_PULL ep;
	ep.init(buf, bufsize, zalloc, EXT_FLAG_WCOUNT);
	uint64_t max = 0;
	if (ep.g_uint64(&max) != EXT_ERR_SUCCESS)
		throw YError("PG-1108");
	for (size_t n = 0; n < max; ++n) {
		uint32_t proptag;
		PROPERTY_NAME propname;
		if (ep.g_uint32(&proptag) != EXT_ERR_SUCCESS ||
		    ep.g_propname(&propname) != EXT_ERR_SUCCESS)
			throw YError("PG-1109");
		try {
			map.insert_or_assign(proptag, std::move(propname));
		} catch (const std::bad_alloc &) {
			free(propname.pname);
			throw;
		}
	}
}

void gi_name_map_write(const gi_name_map &map)
{
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw std::bad_alloc();
	if (ep.p_uint64(map.size()) != EXT_ERR_SUCCESS)
		throw YError("PG-1110");
	for (const auto &[propid, propname] : map)
		if (ep.p_uint32(propid) != EXT_ERR_SUCCESS ||
		    ep.p_propname(&propname) != EXT_ERR_SUCCESS)
			throw YError("PG-1111");
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	auto ret = write(STDOUT_FILENO, &xsize, sizeof(xsize));
	if (ret < 0)
		throw YError("PG-1112: %s", strerror(errno));
	else if (ret != sizeof(xsize))
		throw YError("PG-1113");
	ret = write(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	if (ret < 0)
		throw YError("PG-1114: %s", strerror(errno));
	else if (ret != ep.m_offset)
		throw YError("PG-1115");
}

uint16_t gi_resolve_namedprop(const PROPERTY_NAME *pn_req)
{
	PROPNAME_ARRAY pna_req;
	pna_req.count = 1;
	pna_req.ppropname = deconst(pn_req);

	PROPID_ARRAY pid_rsp{};
	if (!exmdb_client::get_named_propids(g_storedir, TRUE, &pna_req, &pid_rsp))
		throw YError("PF-1047: request to server for propname mapping failed");
	if (pid_rsp.count != 1)
		throw YError("PF-1048");
	return pid_rsp.ppropid[0];
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
		fprintf(stderr, "exm: list_file_read_exmdb: %s\n", strerror(-ret));
		return ret;
	}
	auto xn = std::find_if(exmlist.begin(), exmlist.end(),
	          [&](const EXMDB_ITEM &s) { return strncmp(s.prefix.c_str(), dir, s.prefix.size()) == 0; });
	if (xn == exmlist.end()) {
		fprintf(stderr, "exm: No target for %s\n", dir);
		return -ENOENT;
	}
	wrapfd fd(gx_inet_connect(xn->host.c_str(), xn->port, 0));
	if (fd.get() < 0) {
		fprintf(stderr, "exm: gx_inet_connect genimport@[%s]:%hu: %s\n",
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
		fprintf(stderr, "exm: Protocol failure\n");
		return -1;
	}
	free(tb.pb);
	if (!exmdb_client_read_socket(fd.get(), &tb)) {
		fprintf(stderr, "exm: Protocol failure\n");
		return -1;
	}
	auto cl_0 = make_scope_exit([&]() { free(tb.pb); });
	auto response_code = tb.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (tb.cb != 5) {
			fprintf(stderr, "exm: response format error during connect to "
				"[%s]:%hu/%s\n", xn->host.c_str(),
				xn->port, xn->prefix.c_str());
			return -1;
		}
		return fd.release();
	}
	fprintf(stderr, "exm: Failed to connect to [%s]:%hu/%s: %s\n",
	        xn->host.c_str(), xn->port, xn->prefix.c_str(), exmdb_rpc_strerror(response_code));
	return -1;
}

int exm_create_folder(uint64_t parent_fld, TPROPVAL_ARRAY *props, bool o_excl,
    uint64_t *new_fld_id)
{
	uint64_t change_num = 0;
	if (!exmdb_client::allocate_cn(g_storedir, &change_num)) {
		fprintf(stderr, "exm: allocate_cn(fld) RPC failed\n");
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
		fprintf(stderr, "exm: ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.m_offset;
	std::unique_ptr<PCL, gi_delete> pcl(pcl_init());
	if (pcl == nullptr) {
		fprintf(stderr, "exm: pcl_init: ENOMEM\n");
		return -ENOMEM;
	}
	if (!pcl_append(pcl.get(), &zxid)) {
		fprintf(stderr, "exm: pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, gi_delete> pclbin(pcl_serialize(pcl.get()));
	if (pclbin == nullptr){
		fprintf(stderr, "exm: pcl_serialize: ENOMEM\n");
		return -ENOMEM;
	}
	if (tpropval_array_get_propval(props, PR_LAST_MODIFICATION_TIME) == nullptr) {
		auto last_time = rop_util_current_nttime();
		if (!tpropval_array_set_propval(props, PR_LAST_MODIFICATION_TIME, &last_time))
			return -ENOMEM;
	}
	if (!tpropval_array_set_propval(props, PROP_TAG_PARENTFOLDERID, &parent_fld) ||
	    !tpropval_array_set_propval(props, PROP_TAG_CHANGENUMBER, &change_num) ||
	    !tpropval_array_set_propval(props, PR_CHANGE_KEY, &bxid) ||
	    !tpropval_array_set_propval(props, PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) {
		fprintf(stderr, "exm: tpropval: ENOMEM\n");
		return -ENOMEM;
	}
	auto dn = static_cast<const char *>(tpropval_array_get_propval(props, PR_DISPLAY_NAME));
	if (!o_excl && dn != nullptr) {
		if (!exmdb_client::get_folder_by_name(g_storedir,
		    parent_fld, dn, new_fld_id)) {
			fprintf(stderr, "exm: get_folder_by_name \"%s\" RPC/network failed\n", dn);
			return -EIO;
		}
		if (*new_fld_id != 0)
			return 0;
	}
	if (dn == nullptr)
		dn = "";
	if (!exmdb_client::create_folder_by_properties(g_storedir, 0, props, new_fld_id)) {
		fprintf(stderr, "exm: create_folder_by_properties \"%s\" RPC failed\n", dn);
		return -EIO;
	}
	if (*new_fld_id == 0) {
		fprintf(stderr, "exm: Could not create folder \"%s\". "
			"Either it already existed or some there was some other unspecified problem.\n", dn);
		return -EEXIST;
	}
	return 0;
}

int exm_create_msg(uint64_t parent_fld, MESSAGE_CONTENT *ctnt)
{
	uint64_t msg_id = 0, change_num = 0;
	if (!exmdb_client::allocate_message_id(g_storedir, parent_fld, &msg_id)) {
		fprintf(stderr, "exm: allocate_message_id RPC failed (timeout?)\n");
		return -EIO;
	} else if (!exmdb_client::allocate_cn(g_storedir, &change_num)) {
		fprintf(stderr, "exm: allocate_cn(msg) RPC failed\n");
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
		fprintf(stderr, "exm: ext_push: ENOMEM\n");
		return -ENOMEM;
	}
	bxid.pv = tmp_buff;
	bxid.cb = ep.m_offset;
	std::unique_ptr<PCL, gi_delete> pcl(pcl_init());
	if (pcl == nullptr) {
		fprintf(stderr, "exm: pcl_init: ENOMEM\n");
		return -ENOMEM;
	}
	if (!pcl_append(pcl.get(), &zxid)) {
		fprintf(stderr, "exm: pcl_append: ENOMEM\n");
		return -ENOMEM;
	}
	std::unique_ptr<BINARY, gi_delete> pclbin(pcl_serialize(pcl.get()));
	if (pclbin == nullptr){
		fprintf(stderr, "exm: pcl_serialize: ENOMEM\n");
		return -ENOMEM;
	}
	auto props = &ctnt->proplist;
	if (tpropval_array_get_propval(props, PR_LAST_MODIFICATION_TIME) == nullptr) {
		auto last_time = rop_util_current_nttime();
		if (!tpropval_array_set_propval(props, PR_LAST_MODIFICATION_TIME, &last_time))
			return -ENOMEM;
	}
	if (!tpropval_array_set_propval(props, PROP_TAG_MID, &msg_id) ||
	    !tpropval_array_set_propval(props, PROP_TAG_CHANGENUMBER, &change_num) ||
	    !tpropval_array_set_propval(props, PR_CHANGE_KEY, &bxid) ||
	    !tpropval_array_set_propval(props, PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) {
		fprintf(stderr, "exm: tpropval: ENOMEM\n");
		return -ENOMEM;
	}
	gxerr_t e_result = GXERR_SUCCESS;
	if (!exmdb_client::write_message(g_storedir, g_dstuser.c_str(), 65001,
	    parent_fld, ctnt, &e_result)) {
		fprintf(stderr, "exm: write_message RPC failed\n");
		return -EIO;
	} else if (e_result != 0) {
		fprintf(stderr, "exm: write_message: gxerr %d\n", e_result);
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
	auto conn = mysql_init(nullptr);
	if (conn == nullptr) {
		fprintf(stderr, "exm: mysql_init failed\n");
		return nullptr;
	}
	mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	if (mysql_real_connect(conn, sql_host, sql_user, sql_pass, sql_dbname,
	    sql_port, nullptr, 0) != nullptr)
		return conn;
	fprintf(stderr, "exm: Failed to connect to SQL %s@%s: %s\n",
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
		fprintf(stderr, "exm: No such user \"%s\"\n", username);
		return EXIT_FAILURE;
	} else if (ret < 0) {
		fprintf(stderr, "exm: sql_meta(\"%s\"): %s\n", username, strerror(-ret));
		return EXIT_FAILURE;
	}
	g_dstuser = username;
	g_storedir = g_storedir_s.c_str();
	g_socket = exm_connect(g_storedir);
	if (g_socket < 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
