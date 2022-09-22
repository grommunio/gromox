// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
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
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ical.hpp>
#include <gromox/mime_pool.hpp>
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

	auto mimepool = MIME_POOL::create(4096, 8, "mime_pool");
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
	auto msg_id = strtoull(argv[1], nullptr, 0);
	if (!exmdb_client_remote::read_message(g_storedir, nullptr, 65001,
	    rop_util_make_eid_ex(1, msg_id), &ctnt)) {
		fprintf(stderr, "The RPC was rejected for an unspecified reason.\n");
		return EXIT_FAILURE;
	}
	if (ctnt == nullptr) {
		fprintf(stderr, "A message by the id %llxh was not found\n",
		        static_cast<unsigned long long>(msg_id));
		return EXIT_FAILURE;
	}
	if (g_export_mode == EXPORT_MAIL) {
		if (!oxcmail_export(ctnt, false, oxcmail_body::plain_and_html, mimepool,
		    &imail, malloc, cu_get_propids, cu_get_propname)) {
			fprintf(stderr, "oxcmail_export failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		if (!imail.to_file(STDOUT_FILENO)) {
			fprintf(stderr, "Writeout failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
	} else if (g_export_mode == EXPORT_ICAL) {
		ical ic;
		if (!oxcical_export(ctnt, ic, malloc, cu_get_propids,
		    oxcmail_entryid_to_username, oxcmail_essdn_to_username)) {
			fprintf(stderr, "oxcical_export failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		auto buf = std::make_unique<char[]>(1048576);
		if (!ic.serialize(buf.get(), 1048576)) {
			fprintf(stderr, "vcard::serialize failed for an unspecified reason.\n");
			return EXIT_FAILURE;
		}
		fputs(buf.get(), stdout);
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
