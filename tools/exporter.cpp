// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/ical.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tnef.hpp>
#include <gromox/vcard.hpp>
#include "genimport.hpp"
#include "staticnpmap.cpp"

using namespace gromox;
using namespace gi_dump;

enum {
	EXPORT_MAIL,
	EXPORT_ICAL,
	EXPORT_VCARD,
	EXPORT_GXMT,
	EXPORT_TNEF,
};

static std::shared_ptr<config_file> g_config_file;
static const char *g_username;
static unsigned int g_export_mode = EXPORT_MAIL, g_mlog_level = MLOG_DEFAULT_LEVEL;
static int g_allday_mode = -1;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'Y', HXTYPE_INT, &g_allday_mode, nullptr, nullptr, 0, "Allday emission mode (default=-1, YMDHMS=0, YMD=1)"},
	{nullptr, 'p', HXTYPE_NONE | HXOPT_INC, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{nullptr, 'u', HXTYPE_STRING, {}, {}, {}, 0, "Username of store to export from", "EMAILADDR"},
	{"ical", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_ICAL, "Export as calendar object"},
	{"loglevel", 0, HXTYPE_UINT, &g_mlog_level, {}, {}, {}, "Basic loglevel of the program", "N"},
	{"mail", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_MAIL, "Export as RFC5322 mail"},
	{"mt", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_GXMT, "Export as Gromox mailbox transfer format"},
	{"tnef", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_TNEF, "Export as TNEF object"},
	{"vcard", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_VCARD, "Export as vCard object"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static BOOL cu_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	return exmdb_client_remote::get_named_propids(g_storedir,
	       false, names, ids);
}

static BOOL cu_get_propname(propid_t propid, PROPERTY_NAME **name) try
{
	PROPNAME_ARRAY names = {};
	if (!exmdb_client_remote::get_named_propnames(g_storedir,
	    {propid}, &names) || names.size() != 1)
		return false;
	*name = &names.ppropname[0];
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2238: ENOMEM");
	return false;
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-exm2eml -u source@mbox.de msgid >dump.eml\n");
	fprintf(stderr, "       gromox-exm2mt -u source@mbox.de msgid >dump.mt\n");
}

static constexpr generic_module g_dfl_svc_plugins[] =
	{{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}};

static constexpr cfg_directive exm2eml_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR},
	{"data_path", PKGDATADIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static int fetch_as_instance(const char *idstr, std::string &log_id,
    uint64_t &msg_id, MESSAGE_CONTENT *&ctnt)
{
	char *sep = nullptr;
	auto folder_id = strtoull(idstr, &sep, 0);
	if (sep == nullptr || *sep != ':') {
		fprintf(stderr, "Unparsable: \"%s\"\n", idstr);
		return -1;
	}
	log_id = idstr;
	msg_id = strtoull(sep + 1, nullptr, 0);
	uint32_t inst_id = 0;
	ctnt = message_content_init();
	if (ctnt == nullptr)
		throw std::bad_alloc();
	if (!exmdb_client_remote::load_message_instance(g_storedir,
	    nullptr, CP_UTF8, false, rop_util_make_eid_ex(1, folder_id),
	    rop_util_make_eid_ex(1, msg_id), &inst_id)) {
		fprintf(stderr, "RPC load_message_instance rejected; probably message not found.\n");
		return -1;
	}
	auto cl_6 = HX::make_scope_exit([&]() { exmdb_client_remote::unload_instance(g_storedir, inst_id); });
	if (!exmdb_client_remote::read_message_instance(g_storedir,
	    inst_id, ctnt)) {
		fprintf(stderr, "The RPC was rejected for an unspecified reason.\n");
		return -1;
	}
	return 0;
}

static int fetch_message(const char *idstr, std::string &log_id,
    uint64_t &msg_id, MESSAGE_CONTENT *&ctnt)
{
	msg_id = strtoull(idstr, nullptr, 0);
	log_id = g_storedir_s + ":m" + std::to_string(msg_id);
	if (!exmdb_client_remote::read_message(g_storedir, nullptr, CP_UTF8,
	    rop_util_make_eid_ex(1, msg_id), &ctnt)) {
		fprintf(stderr, "The RPC was rejected for an unspecified reason.\n");
		return -1;
	}
	if (ctnt == nullptr) {
		fprintf(stderr, "A message by the id %llxh was not found\n",
			static_cast<unsigned long long>(msg_id));
		return -1;
	}
	return 0;
}

static int emit_message_im(const message_content &ctnt, const std::string &log_id)
{
	MAIL imail;
	if (!oxcmail_export(&ctnt, log_id.c_str(), false, oxcmail_body::plain_and_html,
	    &imail, zalloc, cu_get_propids,
	    cu_get_propname)) {
		fprintf(stderr, "oxcmail_export failed for an unspecified reason.\n");
		return -1;
	}
	auto err = imail.to_fd(STDOUT_FILENO);
	if (err == EPIPE) {
		perror("pipe");
		return -1;
	} else if (err != 0) {
		fprintf(stderr, "Writeout failed for an unspecified reason. %s\n", strerror(err));
		return -1;
	}
	return 0;
}

static int emit_header_gxmt()
{
	if (HXio_fullwrite(STDOUT_FILENO, "GXMT0004", 8) < 0)
		throw YError("PG-1014: %s", strerror(errno));
	uint8_t flag = false;
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* splice flag */
		throw YError("PG-1015: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* public store flag */
		throw YError("PG-1016: %s", strerror(errno));
	gi_dump_name_map(static_namedprop_map.fwd);
	gi_name_map_write(static_namedprop_map.fwd);
	return 0;
}

static int emit_message_gxmt(const message_content &ctnt, eid_t msg_id)
{
	std::vector<propid_t> tags;
	for (const auto &p : ctnt.proplist)
		if (is_nameprop_id(PROP_ID(p.proptag)))
			tags.push_back(PROP_ID(p.proptag));
	PROPNAME_ARRAY propnames{};
	if (tags.size() > 0 &&
	    (!exmdb_client_remote::get_named_propnames(g_storedir, tags, &propnames) ||
	    propnames.size() != tags.size())) {
		fprintf(stderr, "get_all_named_propids failed\n");
		return -1;
	}
	for (size_t i = 0; i < tags.size() && i < propnames.count; ++i) {
		const auto &p = propnames.ppropname[i];
		if (p.kind > MNID_STRING)
			continue;
		if (!static_namedprop_map.emplace_2(tags[i], p).second)
			continue; /* alreay added previously */

		EXT_PUSH ep;
		if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
			throw YError("ENOMEM");
		auto proptag = PROP_TAG(PT_UNSPECIFIED, tags[i]);
		if (ep.p_uint32(GXMT_NAMEDPROP) != pack_result::success ||
		    ep.p_uint32(proptag) != pack_result::success ||
		    ep.p_uint32(0) != pack_result::success ||
		    ep.p_uint64(0) != pack_result::success ||
		    ep.p_propname(p) != pack_result::success)
			throw YError("PG-1143");
		uint64_t xsize = cpu_to_le64(ep.m_offset);
		if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
			throw YError("PG-1144: %s", strerror(errno));
		if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
			throw YError("PG-1145: %s", strerror(errno));

		/* Emit report */
		if (!g_show_props)
			continue;
		char g[40];
		p.guid.to_str(g, std::size(g), 38);
		if (p.kind == MNID_ID)
			fprintf(stderr, "Recorded namedprop: %08xh -> {MNID_ID, %s, %xh}\n",
				proptag, g, static_cast<unsigned int>(p.lid));
		else if (p.kind == MNID_STRING)
			fprintf(stderr, "Recorded namedprop: %08xh -> {MNID_STRING, %s, %s}\n",
				proptag, g, p.pname);
	}
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
		throw YError("ENOMEM");
	if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != pack_result::ok ||
	    ep.p_uint32(msg_id.m_value) != pack_result::ok ||
	    ep.p_uint32(static_cast<uint32_t>(0)) != pack_result::ok ||
	    ep.p_uint64(MAILBOX_FID_UNANCHORED) != pack_result::ok ||
	    ep.p_msgctnt(ctnt) != pack_result::ok ||
	    ep.p_str("") != pack_result::ok ||
	    ep.p_str("") != pack_result::ok) {
		fprintf(stderr, "E-2005\n");
		return -1;
	}
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
		throw YError("PG-1017: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
		throw YError("PG-1018: %s", strerror(errno));
	return 0;
}

static int emit_message_ical(const message_content &ctnt, const std::string &log_id)
{
	ical ic;
	if (!oxcical_export(&ctnt, log_id.c_str(), ic,
	    g_config_file->get_value("x500_org_name"),
	    zalloc, cu_get_propids, mysql_adaptor_userid_to_name)) {
		fprintf(stderr, "oxcical_export failed for an unspecified reason.\n");
		return -1;
	}
	std::string buf;
	auto err = ic.serialize(buf);
	if (err != ecSuccess) {
		fprintf(stderr, "ical::serialize: %s\n", mapi_strerror(err));
		return -1;
	}
	fputs(buf.c_str(), stdout);
	return 0;
}

static int emit_message_vcard(const message_content &ctnt, const std::string &log_id)
{
	vcard vc;
	if (!oxvcard_export(&ctnt, log_id.c_str(), vc, cu_get_propids)) {
		fprintf(stderr, "oxvcard_export %s failed for an unspecified reason.\n", log_id.c_str());
		return -1;
	}
	std::string buf;
	if (!vc.serialize(buf)) {
		fprintf(stderr, "vcard::serialize %s failed for an unspecified reason.\n", log_id.c_str());
		return -1;
	}
	fwrite(buf.c_str(), buf.size(), 1, stdout);
	return 0;
}

static int emit_message_tnef(const message_content &ctnt, const std::string &log_id)
{
	auto bin = tnef_serialize(&ctnt, log_id.c_str(), zalloc, cu_get_propname);
	if (bin == nullptr) {
		fprintf(stderr, "tnef_serialize failed for an unspecified reason.\n");
		return -1;
	}
	auto ret = write(STDOUT_FILENO, bin->pv, bin->cb);
	if (ret < 0 || static_cast<size_t>(ret) != bin->cb) {
		fprintf(stderr, "write: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int do_message(const char *idstr, int msgcounter)
{
	std::string log_id;
	MESSAGE_CONTENT *ctnt = nullptr;
	uint64_t msg_id = 0;
	auto ret = strchr(idstr, ':') != nullptr ?
	           fetch_as_instance(idstr, log_id, msg_id, ctnt) :
	           fetch_message(idstr, log_id, msg_id, ctnt);
	if (ret != 0)
		return EXIT_FAILURE;
	if (g_show_tree) {
		fprintf(stderr, "Message %d\n", msgcounter);
		gi_print(0, *ctnt);
	}

	if (g_export_mode == EXPORT_MAIL)
		return emit_message_im(*ctnt, log_id);
	else if (g_export_mode == EXPORT_GXMT)
		return emit_message_gxmt(*ctnt, msgcounter);
	else if (g_export_mode == EXPORT_ICAL)
		return emit_message_ical(*ctnt, log_id);
	else if (g_export_mode == EXPORT_VCARD)
		return emit_message_vcard(*ctnt, log_id);
	else if (g_export_mode == EXPORT_TNEF)
		return emit_message_tnef(*ctnt, log_id);
	return 0;
}

int main(int argc, char **argv) try
{
	auto bn = HX_basename(argv[0]);
	if (strcmp(bn, "gromox-export") == 0) {
		g_export_mode = EXPORT_GXMT;
	} else if (strcmp(bn, "gromox-exm2eml") == 0) {
		g_export_mode = EXPORT_MAIL;
	} else if (strcmp(bn, "gromox-exm2mt") == 0) {
		g_export_mode = EXPORT_GXMT;
	} else if (strcmp(bn, "gromox-exm2ical") == 0) {
		g_export_mode = EXPORT_ICAL;
	} else if (strcmp(bn, "gromox-exm2vcf") == 0) {
		g_export_mode = EXPORT_VCARD;
	} else if (strcmp(bn, "gromox-exm2tnef") == 0) {
		g_export_mode = EXPORT_TNEF;
	} else {
		fprintf(stderr, "Invocation of this utility as \"%s\" not recognized\n", argv[0]);
		return EXIT_FAILURE;
	}

	HXopt6_auto_result argp;
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_OA) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argp.nargs > 1 && g_export_mode != EXPORT_GXMT) {
		fprintf(stderr, "Attempted to export more than one object, which is only supported with GXMT format.\n");
		return EXIT_FAILURE;
	}
	for (int i = 0; i < argp.nopts; ++i)
		if (argp.desc[i]->sh == 'u')
			g_username = argp.oarg[i];
	if (g_username == nullptr || argp.nargs < 1) {
		terse_help();
		return EXIT_FAILURE;
	}
	if ((g_export_mode == EXPORT_GXMT || g_export_mode == EXPORT_TNEF) &&
	    isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output binary streams to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}
	if (g_allday_mode >= 0)
		g_oxcical_allday_ymd = g_allday_mode;
	mlog_init(nullptr, nullptr, g_mlog_level, nullptr);
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);
	g_config_file = config_file_prg(nullptr, "midb.cfg",
	                exm2eml_cfg_defaults);
	if (g_config_file == nullptr) {
		fprintf(stderr, "Something went wrong with config files (e.g. permission denied)\n");
		return EXIT_FAILURE;
	}
	service_init({g_config_file, g_dfl_svc_plugins, 1});
	auto cl_1 = HX::make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    mysql_adaptor_userid_to_name)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	MAIL imail;

	if (gi_setup_from_user(g_username) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	if (gi_startup_client() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	auto cl_5 = HX::make_scope_exit(gi_shutdown);

	if (g_export_mode == EXPORT_GXMT)
		if (emit_header_gxmt() != 0)
			return EXIT_FAILURE;
	for (int i = 0; i < argp.nargs; ++i) {
		auto err = do_message(argp.uarg[i], i + 1);
		if (err != 0)
			return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "gromox-export: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
