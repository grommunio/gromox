// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
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
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include "genimport.hpp"
#include "exch/midb/system_services.hpp"

using namespace std::string_literals;
using namespace gromox;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

enum {
	IMPORT_MAIL,
	IMPORT_ICAL,
	IMPORT_VCARD,
	IMPORT_MBOX,
};

static unsigned int g_import_mode = IMPORT_MAIL;
static unsigned int g_oneoff;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'P', HXTYPE_NONE, &g_oxvcard_pedantic, nullptr, nullptr, 0, "Enable pedantic import mode"},
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"ical", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_ICAL, "Treat input as iCalendar"},
	{"mail", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_MAIL, "Treat input as Internet Mail"},
	{"mbox", 0, HXTYPE_VAL, &g_import_mode, {}, {}, IMPORT_MBOX, "Treat input as Unix mbox"},
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
		name.guid.to_str(guid, std::size(guid));
		if (name.kind == MNID_ID)
			snprintf(txt, std::size(txt), "GUID=%s,LID=%u", guid, name.lid);
		else
			snprintf(txt, std::size(txt), "GUID=%s,NAME=%s", guid, name.pname);
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
do_mail(const char *file, char *data, size_t dsize)
{
	MAIL imail;
	if (!imail.load_from_str_move(data, dsize)) {
		fprintf(stderr, "Unable to parse %s\n", file);
		return nullptr;
	}
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> msg(oxcmail_import("utf-8",
		"UTC", &imail, zalloc, ee_get_propids));
	if (msg == nullptr)
		fprintf(stderr, "Failed to convert IM %s to MAPI\n", file);
	return msg;
}

static std::unique_ptr<MESSAGE_CONTENT, mc_delete> do_eml(const char *file)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(strcmp(file, "-") == 0 ?
		HX_slurp_fd(STDIN_FILENO, &slurp_len) : HX_slurp_file(file, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
		return nullptr;
	}
	return do_mail(file, slurp_data.get(), slurp_len);
}

enum class mbox_rid { start, envelope_from, msghdr, msgbody, emit };

struct mbox_rdstate {
	std::vector<message_ptr> &msgvec;
	std::string filename;
	size_t fncut = 0;
	unsigned int mail_count = 0;
	enum mbox_rid rid = mbox_rid::start;
	bool alpine_pseudo_msg = false;
	std::string cbuf;
};

static void mbox_line(mbox_rdstate &rs, const char *line)
{
	switch (rs.rid) {
	case mbox_rid::start:
		if (line[0] == '\n' || (line[0] == '\r' && line[1] == '\n'))
			return;
		rs.rid = mbox_rid::envelope_from;
		[[fallthrough]];
	case mbox_rid::envelope_from:
		rs.rid = mbox_rid::msghdr;
		if (strncmp(line, "From ", 5) == 0)
			return;
		[[fallthrough]];
	case mbox_rid::msghdr:
		rs.cbuf += line;
		if (line[0] == '\n' || (line[0] == '\r' && line[1] == '\n')) {
			rs.rid = mbox_rid::msgbody;
			return;
		}
		if (strncmp(line, "X-IMAP: ", 8) == 0)
			rs.alpine_pseudo_msg = true;
		return;
	case mbox_rid::msgbody:
		if (strncmp(line, "From ", 5) != 0) {
			rs.cbuf += line;
			return;
		}
		[[fallthrough]];
	case mbox_rid::emit: {
		if (rs.alpine_pseudo_msg) {
			/* discard Alpine MAILER-DAEMON/X-IMAP pseudo message */
			rs.alpine_pseudo_msg = false;
			rs.cbuf = std::string();
			rs.rid  = mbox_rid::msghdr;
			return;
		}
		rs.filename.erase(rs.fncut);
		rs.filename += std::to_string(++rs.mail_count);
		auto mo = do_mail(rs.filename.c_str(), rs.cbuf.data(), rs.cbuf.size());
		if (mo == nullptr)
			throw std::bad_alloc();
		rs.msgvec.push_back(std::move(mo));
		rs.cbuf = std::string();
		rs.rid  = mbox_rid::msghdr;
		return;
	}
	default:
		return;
	}
}

static errno_t do_mbox(const char *file, std::vector<message_ptr> &msgvec)
{
	std::unique_ptr<FILE, stdlib_delete> extra_fp;
	FILE *fp = nullptr;
	if (strcmp(file, "-") == 0) {
		fp = stdin;
	} else {
		extra_fp.reset(fopen(file, "r"));
		if (extra_fp == nullptr) {
			int se = errno;
			fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
			return se;
		}
		fp = extra_fp.get();
	}
	hxmc_t *line = nullptr;
	auto cl_0 = make_scope_exit([&]() { HXmc_free(line); });
	mbox_rdstate rs{msgvec};
	rs.filename = file;
	rs.filename += ":";
	rs.fncut    = rs.filename.size();
	while (HX_getl(&line, fp) != nullptr)
		mbox_line(rs, line);
	rs.rid = mbox_rid::emit;
	mbox_line(rs, nullptr);
	return 0;
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
	if (!ical.load_from_str_move(slurp_data.get())) {
		fprintf(stderr, "ical_parse %s unsuccessful\n", file);
		return EIO;
	}
	auto err = oxcical_import_multi("UTC", ical, zalloc, ee_get_propids,
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
	auto ret = vcard_load_multi_from_str_move(slurp_data.get(), cardvec);
	if (ret != ecSuccess) {
		fprintf(stderr, "vcard_parse %s unsuccessful (ecode=%xh)\n", file, ret);
		return EIO;
	}
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

static constexpr cfg_directive delivery_cfg_defaults[] = {
	CFG_TABLE_END,
};

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
		fprintf(stderr, "Invocation of this utility as \"%s\" not recognized\n", argv[0]);
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
		system_services_get_user_ids = [](const char *, unsigned int *, unsigned int *, display_type *) -> BOOL { return false; };
	auto cl_2 = make_scope_exit([]() { service_release("get_user_ids", "system"); });
#undef E

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    system_services_get_user_ids, system_services_get_username_from_id)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}

	auto cfg = config_file_prg(nullptr, "delivery.cfg", delivery_cfg_defaults);
	std::vector<message_ptr> msgs;

	for (int i = 1; i < argc; ++i) {
		if (g_import_mode == IMPORT_MAIL) {
			auto msg = do_eml(argv[i]);
			if (msg == nullptr)
				continue;
			msgs.push_back(std::move(msg));
		} else if (g_import_mode == IMPORT_MBOX) {
			if (do_mbox(argv[i], msgs) != 0)
				continue;
		} else if (g_import_mode == IMPORT_ICAL) {
			if (do_ical(argv[i], msgs) != 0)
				continue;
		} else if (g_import_mode == IMPORT_VCARD) {
			if (do_vcard(argv[i], msgs) != 0)
				continue;
		}
	}

	if (HXio_fullwrite(STDOUT_FILENO, "GXMT0003", 8) < 0)
		throw YError("PG-1014: %s", strerror(errno));
	uint8_t flag = false;
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* splice flag */
		throw YError("PG-1015: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* public store flag */
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
		if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(i + 1) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(static_cast<uint32_t>(parent.type)) != EXT_ERR_SUCCESS ||
		    ep.p_uint64(parent.folder_id) != EXT_ERR_SUCCESS ||
		    ep.p_msgctnt(*msgs[i]) != EXT_ERR_SUCCESS) {
			fprintf(stderr, "E-2021\n");
			return EXIT_FAILURE;
		}
		uint64_t xsize = cpu_to_le64(ep.m_offset);
		if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
			throw YError("PG-1017: %s", strerror(errno));
		if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
			throw YError("PG-1018: %s", strerror(errno));
	}
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "eml2mt: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
