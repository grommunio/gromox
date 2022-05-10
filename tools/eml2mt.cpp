// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/option.h>
#include <gromox/config_file.hpp>
#include <gromox/endian.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include "genimport.hpp"
#include "exch/midb/system_services.h"
#include "../exch/midb/service.h"

using namespace gromox;

static unsigned int g_oneoff;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"oneoff", 0, HXTYPE_NONE, &g_oneoff, nullptr, nullptr, 0, "Resolve addresses to ONEOFF rather than EX addresses"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr const char *g_svc_plugins[] =
	{"libgxs_mysql_adaptor.so", "libgxs_textmaps.so", nullptr};

static constexpr cfg_directive eml2mt_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR},
	{"data_path", PKGDATADIR},
	{"service_plugin_path", PKGLIBEXECDIR},
	{"state_path", PKGSTATEDIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

decltype(system_services_get_username_from_id) system_services_get_username_from_id;
decltype(system_services_get_user_ids) system_services_get_user_ids;
decltype(system_services_cpid_to_charset) system_services_cpid_to_charset;
decltype(system_services_charset_to_cpid) system_services_charset_to_cpid;
decltype(system_services_lcid_to_ltag) system_services_lcid_to_ltag;
decltype(system_services_ltag_to_lcid) system_services_ltag_to_lcid;
decltype(system_services_mime_to_extension) system_services_mime_to_extension;
decltype(system_services_extension_to_mime) system_services_extension_to_mime;
decltype(system_services_lang_to_charset) system_services_lang_to_charset;
std::shared_ptr<CONFIG_FILE> g_config_file;
static const char g_default_timezone[] = "UTC";
static gi_name_map name_map;
static std::unordered_map<std::string, uint16_t> name_rev_map;
static uint16_t name_id = 0x8000;

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-eml2mt file.eml[...] | gromox-mt2 ...\n");
	fprintf(stderr, "Documentation: man gromox-eml2mt\n");
}

static BOOL ee_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	ids->ppropid = me_alloc<uint16_t>(names->count);
	if (ids->ppropid == nullptr)
		return false;
	ids->count = names->count;
	for (size_t i = 0; i < names->count; ++i) {
		auto &name = names->ppropname[i];
		char guid[GUIDSTR_SIZE], txt[NP_STRBUF_SIZE];
		name.guid.to_str(guid, arsizeof(guid));
		if (name.kind == MNID_ID)
			snprintf(txt, arsizeof(txt), "GUID=%s,LID=%u", guid, name.lid);
		else
			snprintf(txt, arsizeof(txt), "GUID=%s,NAME=%s", guid, name.pname);
		auto [iter, added] = name_rev_map.emplace(std::move(txt), name_id);
		if (!added) {
			ids->ppropid[i] = iter->second;
			continue;
		} else if (name_id == 0xffff) {
			ids->ppropid[i] = 0;
			continue;
		}
		name_map.emplace(PROP_TAG(PT_UNSPECIFIED, name_id), name);
		ids->ppropid[i] = name_id++;
	}
	return TRUE;
}

static std::unique_ptr<MESSAGE_CONTENT, gi_delete>
do_mail(const char *file, std::shared_ptr<MIME_POOL> mime_pool)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(strcmp(file, "-") == 0 ?
		HX_slurp_fd(STDIN_FILENO, &slurp_len) : HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
		return nullptr;
	}

	MAIL imail(std::move(mime_pool));
	if (!imail.retrieve(slurp_data.get(), slurp_len)) {
		fprintf(stderr, "Unable to parse %s\n", file);
		return nullptr;
	}
	std::unique_ptr<MESSAGE_CONTENT, gi_delete> msg(oxcmail_import("utf-8",
		"UTC", &imail, malloc, ee_get_propids));
	if (msg == nullptr)
		fprintf(stderr, "Failed to convert IM %s to MAPI\n", file);
	return msg;
}

int main(int argc, const char **argv) try
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	g_config_file = config_file_prg(nullptr, "midb.cfg", eml2mt_cfg_defaults);
	if (g_config_file == nullptr) {
		fprintf(stderr, "Something went wrong with config files\n");
		return EXIT_FAILURE;
	}
	service_init({g_config_file->get_value("service_plugin_path"),
		g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_path"),
		g_config_file->get_value("state_path"),
		g_svc_plugins, false, 1});
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
	auto cl_1 = make_scope_exit([]() { service_release("get_username_from_id", "system"); });
	E(system_services_get_user_ids, "get_user_ids");
	if (g_oneoff)
		system_services_get_user_ids = [](const char *, int *, int *, display_type *) -> BOOL { return false; };
	auto cl_2 = make_scope_exit([]() { service_release("get_user_ids", "system"); });
	E(system_services_cpid_to_charset, "cpid_to_charset");
	auto cl_3 = make_scope_exit([]() { service_release("cpid_to_charset", "system"); });
	E(system_services_charset_to_cpid, "charset_to_cpid");
	auto cl_4 = make_scope_exit([]() { service_release("charset_to_cpid", "system"); });
	E(system_services_lcid_to_ltag, "lcid_to_ltag");
	auto cl_5 = make_scope_exit([]() { service_release("lcid_to_ltag", "system"); });
	E(system_services_ltag_to_lcid, "ltag_to_lcid");
	auto cl_6 = make_scope_exit([]() { service_release("ltag_to_lcid", "system"); });
	E(system_services_mime_to_extension, "mime_to_extension");
	auto cl_7 = make_scope_exit([]() { service_release("mime_to_extension", "system"); });
	E(system_services_extension_to_mime, "extension_to_mime");
	auto cl_8 = make_scope_exit([]() { service_release("extension_to_mime", "system"); });
	E(system_services_lang_to_charset, "lang_to_charset");
	auto cl_9 = make_scope_exit([]() { service_release("lang_to_charset", "system"); });
#undef E

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    system_services_get_user_ids, system_services_get_username_from_id,
	    system_services_ltag_to_lcid, system_services_lcid_to_ltag,
	    system_services_charset_to_cpid, system_services_cpid_to_charset,
	    system_services_mime_to_extension, system_services_extension_to_mime)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}

	auto mime_pool = MIME_POOL::create(4096, 8);	
	std::vector<std::unique_ptr<MESSAGE_CONTENT, gi_delete>> msgs;

	for (int i = 1; i < argc; ++i) {
		auto msg = do_mail(argv[i], mime_pool);
		if (msg == nullptr)
			continue;
		msgs.push_back(std::move(msg));
	}

	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}

	write(STDOUT_FILENO, "GXMT0002", 8);
	uint8_t flag = false;
	write(STDOUT_FILENO, &flag, sizeof(flag)); /* splice */
	write(STDOUT_FILENO, &flag, sizeof(flag)); /* public store */
	gi_folder_map_write({});
	gi_dump_name_map(name_map);
	gi_name_map_write(name_map);

	auto parent = parent_desc::as_folder(~0ULL);
	for (size_t i = 0; i < msgs.size(); ++i) {
		if (g_show_tree) {
			fprintf(stderr, "Message %zu\n", i + 1);
			gi_dump_msgctnt(0, *msgs[i]);
		}
		EXT_PUSH ep;
		if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT)) {
			fprintf(stderr, "E-2020: ENOMEM\n");
			return EXIT_FAILURE;
		}
		if (ep.p_uint32(MAPI_MESSAGE) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(i + 1) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(parent.type) != EXT_ERR_SUCCESS ||
		    ep.p_uint64(parent.folder_id) != EXT_ERR_SUCCESS ||
		    ep.p_msgctnt(*msgs[i]) != EXT_ERR_SUCCESS) {
			fprintf(stderr, "E-2021\n");
			return EXIT_FAILURE;
		}
		uint64_t xsize = cpu_to_le64(ep.m_offset);
		write(STDOUT_FILENO, &xsize, sizeof(xsize));
		write(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
	}
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "eml2mt: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
