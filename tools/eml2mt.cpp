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
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/endian.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mime_pool.hpp>
#include <gromox/oxcical.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/oxvcard.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "exch/midb/system_services.hpp"

using namespace gromox;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

enum {
	IMPORT_MAIL,
	IMPORT_ICAL,
	IMPORT_VCARD,
};

static unsigned int g_import_mode = IMPORT_MAIL;
static unsigned int g_oneoff;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'P', HXTYPE_NONE, &g_oxvcard_pedantic, nullptr, nullptr, 0, "Enable pedantic import mode"},
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"ical", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_ICAL, "Treat input as iCalendar"},
	{"mail", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_MAIL, "Treat input as Internet Mail"},
	{"oneoff", 0, HXTYPE_NONE, &g_oneoff, nullptr, nullptr, 0, "Resolve addresses to ONEOFF rather than EX addresses"},
	{"vcard", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_VCARD, "Treat input as vCard"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_svc_plugins =
	{"libgxs_mysql_adaptor.so"};

static constexpr cfg_directive eml2mt_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR},
	{"data_path", PKGDATADIR},
	{"state_path", PKGSTATEDIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

decltype(system_services_get_username_from_id) system_services_get_username_from_id;
decltype(system_services_get_user_ids) system_services_get_user_ids;
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

static std::unique_ptr<MESSAGE_CONTENT, mc_delete>
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
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> msg(oxcmail_import("utf-8",
		"UTC", &imail, malloc, ee_get_propids));
	if (msg == nullptr)
		fprintf(stderr, "Failed to convert IM %s to MAPI\n", file);
	return msg;
}

static errno_t do_ical(const char *file, std::vector<message_ptr> &mv)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(strcmp(file, "-") == 0 ?
		HX_slurp_fd(STDIN_FILENO, &slurp_len) : HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
		return errno;
	}
	ICAL ical;
	auto ret = ical.init();
	if (ret < 0) {
		fprintf(stderr, "ical_init: %s\n", strerror(-ret));
		return -ret;
	} else if (!ical.retrieve(slurp_data.get())) {
		fprintf(stderr, "ical_parse %s unsuccessful\n", file);
		return EIO;
	}
	auto err = oxcical_import_multi("UTC", &ical, malloc, ee_get_propids,
	           oxcmail_username_to_entryid, mv);
	if (err == ecNotFound) {
		fprintf(stderr, "%s: Not an iCalendar object, or an incomplete one.\n", file);
		return EIO;
	} else if (err != ecSuccess) {
		fprintf(stderr, "%s: Import rejected for an unspecified reason (usually a too-strict parser).\n", file);
		return EIO;
	}
	return 0;
}

static errno_t do_vcard(const char *file, std::vector<message_ptr> &mv)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(strcmp(file, "-") == 0 ?
		HX_slurp_fd(STDIN_FILENO, &slurp_len) : HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
		return errno;
	}
	std::vector<vcard> cardvec;
	auto ret = vcard_retrieve_multi(slurp_data.get(), cardvec);
	if (ret != ecSuccess) {
		fprintf(stderr, "vcard_parse %s unsuccessful (ecode=%xh)\n", file, ret);
		return EIO;
	}
	mv.reserve(mv.size() + cardvec.size());
	for (const auto &card : cardvec) {
		message_ptr mc(oxvcard_import(&card, ee_get_propids));
		if (mc == nullptr) {
			fprintf(stderr, "Failed to convert IM %s to MAPI\n", file);
			return EIO;
		}
		mv.push_back(std::move(mc));
	}
	return 0;
}

int main(int argc, const char **argv) try
{
	auto bn = HX_basename(argv[0]);
	if (strcmp(bn, "gromox-eml2mt") == 0) {
		g_import_mode = IMPORT_MAIL;
	} else if (strcmp(bn, "gromox-ical2mt") == 0) {
		g_import_mode = IMPORT_ICAL;
	} else if (strcmp(bn, "gromox-vcf2mt") == 0) {
		g_import_mode = IMPORT_VCARD;
	} else {
		fprintf(stderr, "Invocation of this utilit as \"%s\" not recognized\n", argv[0]);
		return EXIT_FAILURE;
	}
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	g_config_file = config_file_prg(nullptr, "midb.cfg", eml2mt_cfg_defaults);
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
	auto cl_1 = make_scope_exit([]() { service_release("get_username_from_id", "system"); });
	E(system_services_get_user_ids, "get_user_ids");
	if (g_oneoff)
		system_services_get_user_ids = [](const char *, int *, int *, display_type *) -> BOOL { return false; };
	auto cl_2 = make_scope_exit([]() { service_release("get_user_ids", "system"); });
#undef E

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    system_services_get_user_ids, system_services_get_username_from_id)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}

	auto mime_pool = MIME_POOL::create(4096, 8, "mime_pool");
	std::vector<message_ptr> msgs;

	for (int i = 1; i < argc; ++i) {
		if (g_import_mode == IMPORT_MAIL) {
			auto msg = do_mail(argv[i], mime_pool);
			if (msg == nullptr)
				continue;
			msgs.push_back(std::move(msg));
		} else if (g_import_mode == IMPORT_ICAL) {
			if (do_ical(argv[i], msgs) != 0)
				continue;
		} else if (g_import_mode == IMPORT_VCARD) {
			if (do_vcard(argv[i], msgs) != 0)
				continue;
		}
	}

	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}

	auto ret = HXio_fullwrite(STDOUT_FILENO, "GXMT0002", 8);
	if (ret < 0)
		throw YError("PG-1014: %s", strerror(errno));
	uint8_t flag = false;
	ret = HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)); /* splice */
	if (ret < 0)
		throw YError("PG-1015: %s", strerror(errno));
	ret = HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)); /* public store */
	if (ret < 0)
		throw YError("PG-1016: %s", strerror(errno));
	gi_folder_map_t fmap;
	if (g_import_mode == IMPORT_ICAL)
		fmap.emplace(~0ULL, tgt_folder{false, PRIVATE_FID_CALENDAR, ""});
	else if (g_import_mode == IMPORT_VCARD)
		fmap.emplace(~0ULL, tgt_folder{false, PRIVATE_FID_CONTACTS, ""});
	gi_folder_map_write(fmap);
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
		ret = HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize));
		if (ret < 0)
			throw YError("PG-1017: %s", strerror(errno));
		ret = HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset);
		if (ret < 0)
			throw YError("PG-1018: %s", strerror(errno));
	}
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "eml2mt: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
