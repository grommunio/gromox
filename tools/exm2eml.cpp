// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
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
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/endian.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ical.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/vcard.hpp>
#include "genimport.hpp"
#include "exch/midb/system_services.hpp"

enum {
	EXPORT_MAIL,
	EXPORT_ICAL,
	EXPORT_VCARD,
	EXPORT_GXMT,
};

using namespace gromox;
decltype(system_services_get_username_from_id) system_services_get_username_from_id;
decltype(system_services_get_user_ids) system_services_get_user_ids;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *g_username;
static unsigned int g_export_mode = EXPORT_MAIL;
static int g_allday_mode = -1;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'Y', HXTYPE_INT, &g_allday_mode, nullptr, nullptr, 0, "Allday emission mode (default=-1, YMDHMS=0, YMD=1)"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	{"ical", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_ICAL, "Export as calendar object"},
	{"mail", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_MAIL, "Export as RFC5322 mail"},
	{"mt", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_GXMT, "Export as Gromox mailbox transfer format"},
	{"vcard", 0, HXTYPE_VAL, &g_export_mode, nullptr, nullptr, EXPORT_VCARD, "Export as vCard object"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static BOOL cu_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	return exmdb_client_remote::get_named_propids(g_storedir,
	       false, names, ids);
}

static BOOL cu_get_propname(uint16_t propid, PROPERTY_NAME **name)
{
	PROPID_ARRAY ids = {1, &propid};
	PROPNAME_ARRAY names = {};
	if (!exmdb_client_remote::get_named_propnames(g_storedir, &ids, &names))
		return false;
	*name = names.count != 0 ? &names.ppropname[0] : nullptr;
	return TRUE;
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-exm2eml -u source@mbox.de msgid >dump.eml\n");
}

static std::vector<std::string> g_svc_plugins =
	{"libgxs_mysql_adaptor.so"};

static constexpr cfg_directive exm2eml_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR},
	{"data_path", PKGDATADIR},
	{"state_path", PKGSTATEDIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

int main(int argc, const char **argv) try
{
	auto bn = HX_basename(argv[0]);
	if (strcmp(bn, "gromox-exm2eml") == 0) {
		g_export_mode = EXPORT_MAIL;
	} else if (strcmp(bn, "gromox-exm2mt") == 0) {
		g_export_mode = EXPORT_GXMT;
	} else if (strcmp(bn, "gromox-exm2ical") == 0) {
		g_export_mode = EXPORT_ICAL;
	} else if (strcmp(bn, "gromox-exm2vcf") == 0) {
		g_export_mode = EXPORT_VCARD;
	} else {
		fprintf(stderr, "Invocation of this utility as \"%s\" not recognized\n", argv[0]);
		return EXIT_FAILURE;
	}

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_username == nullptr || argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	if (g_export_mode == EXPORT_GXMT && isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}
	if (g_allday_mode >= 0)
		g_oxcical_allday_ymd = g_allday_mode;
	g_config_file = config_file_prg(nullptr, "midb.cfg",
	                exm2eml_cfg_defaults);
	if (g_config_file == nullptr) {
		fprintf(stderr, "Something went wrong with config files\n");
		return EXIT_FAILURE;
	}
	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_path"),
		g_config_file->get_value("state_path"),
		std::move(g_svc_plugins), 1});
	auto cl_0 = make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}

#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)
	E(system_services_get_username_from_id, "get_username_from_id");
	auto cl_2 = make_scope_exit([]() { service_release("get_username_from_id", "system"); });
	E(system_services_get_user_ids, "get_user_ids");
	auto cl_3 = make_scope_exit([]() { service_release("get_user_ids", "system"); });
#undef E

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    system_services_get_user_ids, system_services_get_username_from_id)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	MAIL imail;

	gi_setup_early(g_username);
	if (gi_setup() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	auto cl_1 = make_scope_exit(gi_shutdown);

	MESSAGE_CONTENT *ctnt = nullptr;
	uint64_t msg_id = 0;
	if (strchr(argv[1], ':') != nullptr) {
		char *sep = nullptr;
		auto folder_id = strtoull(argv[1], &sep, 0);
		if (sep == nullptr || *sep != ':') {
			fprintf(stderr, "Unparsable: \"%s\"\n", argv[1]);
			return EXIT_FAILURE;
		}
		msg_id = strtoull(sep + 1, nullptr, 0);
		uint32_t inst_id = 0;
		ctnt = message_content_init();
		if (!exmdb_client_remote::load_message_instance(g_storedir,
		    nullptr, CP_UTF8, false, rop_util_make_eid_ex(1, folder_id),
		    rop_util_make_eid_ex(1, msg_id), &inst_id)) {
			fprintf(stderr, "RPC load_message_instance rejected; probably message not found.\n");
			return EXIT_FAILURE;
		}
		auto cl_4 = make_scope_exit([&]() { exmdb_client_remote::unload_instance(g_storedir, inst_id); });
		if (!exmdb_client_remote::read_message_instance(g_storedir,
		    inst_id, ctnt)) {
			fprintf(stderr, "The RPC was rejected for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
	} else {
		msg_id = strtoull(argv[1], nullptr, 0);
		if (!exmdb_client_remote::read_message(g_storedir, nullptr, CP_UTF8,
		    rop_util_make_eid_ex(1, msg_id), &ctnt)) {
			fprintf(stderr, "The RPC was rejected for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		if (ctnt == nullptr) {
			fprintf(stderr, "A message by the id %llxh was not found\n",
			        static_cast<unsigned long long>(msg_id));
			return EXIT_FAILURE;
		}
	}
	if (g_export_mode == EXPORT_MAIL) {
		if (!oxcmail_export(ctnt, false, oxcmail_body::plain_and_html,
		    &imail, zalloc, cu_get_propids,
		    cu_get_propname)) {
			fprintf(stderr, "oxcmail_export failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		if (!imail.to_file(STDOUT_FILENO)) {
			fprintf(stderr, "Writeout failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
	} else if (g_export_mode == EXPORT_GXMT) {
		std::vector<uint16_t> tags;
		for (const auto &p : ctnt->proplist)
			tags.push_back(PROP_ID(p.proptag));
		const PROPID_ARRAY propids = {static_cast<uint16_t>(tags.size()), deconst(tags.data())};
		PROPNAME_ARRAY propnames{};
		if (!exmdb_client_remote::get_named_propnames(g_storedir, &propids, &propnames)) {
			fprintf(stderr, "get_all_named_propids failed\n");
			return EXIT_FAILURE;
		}
		gi_name_map name_map;
		for (size_t i = 0; i < tags.size() && i < propnames.count; ++i) {
			const auto &p = propnames.ppropname[i];
			if (p.kind <= MNID_STRING)
				name_map.emplace(PROP_TAG(PT_UNSPECIFIED, tags[i]), p);
		}
		if (HXio_fullwrite(STDOUT_FILENO, "GXMT0003", 8) < 0)
			throw YError("PG-1014: %s", strerror(errno));
		uint8_t flag = false;
		if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* splice flag */
			throw YError("PG-1015: %s", strerror(errno));
		if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* public store flag */
			throw YError("PG-1016: %s", strerror(errno));
		gi_folder_map_write({});
		gi_name_map_write(name_map);
		EXT_PUSH ep;
		if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT))
			throw YError("ENOMEM");
		if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(msg_id) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(static_cast<uint32_t>(0)) != EXT_ERR_SUCCESS ||
		    ep.p_uint64(~0ULL) != EXT_ERR_SUCCESS ||
		    ep.p_msgctnt(*ctnt) != EXT_ERR_SUCCESS) {
			fprintf(stderr, "E-2021\n");
			return EXIT_FAILURE;
		}
		uint64_t xsize = cpu_to_le64(ep.m_offset);
		if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
			throw YError("PG-1017: %s", strerror(errno));
		if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
			throw YError("PG-1018: %s", strerror(errno));
	} else if (g_export_mode == EXPORT_ICAL) {
		ical ic;
		if (!oxcical_export(ctnt, ic, g_config_file->get_value("x500_org_name"),
		    zalloc, cu_get_propids, oxcmail_id2user)) {
			fprintf(stderr, "oxcical_export failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		std::string buf;
		auto err = ic.serialize(buf);
		if (err != ecSuccess) {
			fprintf(stderr, "ical::serialize: %s\n", mapi_strerror(err));
			return EXIT_FAILURE;
		}
		fputs(buf.c_str(), stdout);
	} else if (g_export_mode == EXPORT_VCARD) {
		vcard vc;
		if (!oxvcard_export(ctnt, vc, cu_get_propids)) {
			fprintf(stderr, "oxvcard_export failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		auto buf = std::make_unique<char[]>(VCARD_MAX_BUFFER_LEN);
		if (!vc.serialize(buf.get(), VCARD_MAX_BUFFER_LEN)) {
			fprintf(stderr, "vcard::serialize failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		fputs(buf.get(), stdout);
	}
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "exm2eml: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
