// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/option.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include "genimport.hpp"
#include "exch/midb/system_services.hpp"

using namespace gromox;
decltype(system_services_get_username_from_id) system_services_get_username_from_id;
decltype(system_services_get_user_ids) system_services_get_user_ids;
decltype(system_services_cpid_to_charset) system_services_cpid_to_charset;
decltype(system_services_charset_to_cpid) system_services_charset_to_cpid;
decltype(system_services_lcid_to_ltag) system_services_lcid_to_ltag;
decltype(system_services_ltag_to_lcid) system_services_ltag_to_lcid;
decltype(system_services_mime_to_extension) system_services_mime_to_extension;
decltype(system_services_extension_to_mime) system_services_extension_to_mime;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *g_username;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
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
	{"libgxs_mysql_adaptor.so", "libgxs_textmaps.so"};

static constexpr cfg_directive exm2eml_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR},
	{"data_path", PKGDATADIR},
	{"service_plugin_path", PKGLIBDIR},
	{"state_path", PKGSTATEDIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

int main(int argc, const char **argv) try
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_username == nullptr || argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}

	g_config_file = config_file_prg(nullptr, "midb.cfg",
	                exm2eml_cfg_defaults);
	if (g_config_file == nullptr) {
		fprintf(stderr, "Something went wrong with config files\n");
		return EXIT_FAILURE;
	}
	service_init({g_config_file->get_value("service_plugin_path"),
		g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_path"),
		g_config_file->get_value("state_path"),
		std::move(g_svc_plugins), false, 1});
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
	E(system_services_get_user_ids, "get_user_ids");
	E(system_services_cpid_to_charset, "cpid_to_charset");
	E(system_services_charset_to_cpid, "charset_to_cpid");
	E(system_services_lcid_to_ltag, "lcid_to_ltag");
	E(system_services_ltag_to_lcid, "ltag_to_lcid");
	E(system_services_mime_to_extension, "mime_to_extension");
	E(system_services_extension_to_mime, "extension_to_mime");
#undef E

	auto mimepool = MIME_POOL::create(4096, 8, "mime_pool");
	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    system_services_get_user_ids, system_services_get_username_from_id,
	    system_services_ltag_to_lcid, system_services_lcid_to_ltag,
	    system_services_charset_to_cpid, system_services_cpid_to_charset,
	    system_services_mime_to_extension, system_services_extension_to_mime)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	MAIL imail;

	gi_setup_early(g_username);
	if (gi_setup() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	auto cl_1 = make_scope_exit(gi_shutdown);

	MESSAGE_CONTENT *ctnt = nullptr;
	if (!exmdb_client_remote::read_message(g_storedir, nullptr, 65001,
	    rop_util_make_eid_ex(1, strtoull(argv[1], nullptr, 0)), &ctnt)) {
		fprintf(stderr, "The RPC was rejected for an unspecified reason.\n");
		return EXIT_FAILURE;
	}
	if (!oxcmail_export(ctnt, false, oxcmail_body::plain_and_html, mimepool,
	    &imail, malloc, cu_get_propids, cu_get_propname)) {
		fprintf(stderr, "oxcmail_export failed for an unspecified reason.\n");
		return EXIT_FAILURE;
	}
	if (!imail.to_file(STDOUT_FILENO)) {
		fprintf(stderr, "Writeout failed for an unspecified reason.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "exm2eml: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
