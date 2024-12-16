// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
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
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tnef.hpp>
#include <gromox/util.hpp>
#include <gromox/vcard.hpp>
#include "genimport.hpp"
#include "staticnpmap.cpp"

using namespace std::string_literals;
using namespace gromox;
using namespace gi_dump;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

enum {
	IMPORT_MAIL,
	IMPORT_ICAL,
	IMPORT_VCARD,
	IMPORT_MBOX,
	IMPORT_TNEF,
};

static unsigned int g_import_mode = IMPORT_MAIL;
static unsigned int g_oneoff;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'P', HXTYPE_NONE, &g_oxvcard_pedantic, nullptr, nullptr, 0, "Enable pedantic import mode"},
	{nullptr, 'p', HXTYPE_NONE | HXOPT_INC, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"ical", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_ICAL, "Treat input as iCalendar"},
	{"mail", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_MAIL, "Treat input as Internet Mail"},
	{"mbox", 0, HXTYPE_VAL, &g_import_mode, {}, {}, IMPORT_MBOX, "Treat input as Unix mbox"},
	{"oneoff", 0, HXTYPE_NONE, &g_oneoff, nullptr, nullptr, 0, "Resolve addresses to ONEOFF rather than EX addresses"},
	{"tnef", 0, HXTYPE_VAL, &g_import_mode, {}, {}, IMPORT_TNEF, "Treat input as TNEF"},
	{"vcard", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_VCARD, "Treat input as vCard"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr static_module g_dfl_svc_plugins[] =
	{{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}};

static constexpr cfg_directive eml2mt_cfg_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR},
	{"data_path", PKGDATADIR},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

GET_USER_IDS system_services_get_user_ids;
GET_DOMAIN_IDS system_services_get_domain_ids;
std::shared_ptr<CONFIG_FILE> g_config_file;

static thread_local alloc_context g_alloc_mgr;
static void *gi_alloc(size_t z) { return g_alloc_mgr.alloc(z); }

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-eml2mt file.eml[...] | gromox-mt2 ...\n");
	fprintf(stderr, "Documentation: man gromox-eml2mt\n");
}

static std::unique_ptr<MESSAGE_CONTENT, mc_delete>
do_mail(const char *file, char *data, size_t dsize)
{
	MAIL imail;
	if (!imail.load_from_str_move(data, dsize)) {
		fprintf(stderr, "Unable to parse %s\n", file);
		return nullptr;
	}
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> msg(oxcmail_import(nullptr,
		"UTC", &imail, gi_alloc, ee_get_propids));
	if (msg == nullptr)
		fprintf(stderr, "Failed to convert IM %s to MAPI\n", file);
	return msg;
}

static std::unique_ptr<MESSAGE_CONTENT, mc_delete> do_eml(const char *file)
{
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(strcmp(file, "-") == 0 ?
		HX_slurp_fd(STDIN_FILENO, &slurp_len) : HX_slurp_file(file, &slurp_len));
	static constexpr uint64_t olecf_sig = 0xd0cf11e0a1b11ae1, olecf_beta = 0x0e11fc0dd0cf110e;
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
		return nullptr;
	} else if (slurp_len >= 8 &&
	    (be64p_to_cpu(slurp_data.get()) == olecf_sig ||
	    be64p_to_cpu(slurp_data.get()) == olecf_beta)) {
		fprintf(stderr, "Input file %s looks like an OLECF file; "
			"you should use gromox-oxm2mt, not gromox-eml2mt "
			"(which is for Internet/RFC5322 mail).\n", file);
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
	ical ical;
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

static errno_t do_tnef(const char *file, std::vector<message_ptr> &mv)
{
	size_t slurp_size = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(file, &slurp_size));
	if (slurp_data == nullptr) {
		fprintf(stderr, "tnef: could not open \"%s\": %s\n",
		        file, strerror(errno));
		return EIO;
	}
	message_content_ptr mc(tnef_deserialize(slurp_data.get(), slurp_size,
		zalloc, ee_get_propids, oxcmail_username_to_entryid));
	if (mc == nullptr) {
		fprintf(stderr, "tnef: %s: import rejected\n", file);
		return EIO;
	}
	mv.emplace_back(std::move(mc));
	return 0;
}

static constexpr cfg_directive delivery_cfg_defaults[] = {
	CFG_TABLE_END,
};

int main(int argc, char **argv) try
{
	auto bn = HX_basename(argv[0]);
	if (strcmp(bn, "gromox-eml2mt") == 0) {
		g_import_mode = IMPORT_MAIL;
	} else if (strcmp(bn, "gromox-ical2mt") == 0) {
		g_import_mode = IMPORT_ICAL;
	} else if (strcmp(bn, "gromox-vcf2mt") == 0) {
		g_import_mode = IMPORT_VCARD;
	} else if (strcmp(bn, "gromox-tnef2mt") == 0) {
		g_import_mode = IMPORT_TNEF;
	} else {
		fprintf(stderr, "Invocation of this utility as \"%s\" not recognized\n", argv[0]);
		return EXIT_FAILURE;
	}
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = make_scope_exit([=]() { HX_zvecfree(argv); });
	if (argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);
	g_config_file = config_file_prg(nullptr, "midb.cfg", eml2mt_cfg_defaults);
	if (g_config_file == nullptr) {
		fprintf(stderr, "Something went wrong with config files\n");
		return EXIT_FAILURE;
	}
	service_init({g_config_file, g_dfl_svc_plugins, 1});
	auto cl_0 = make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}

	if (g_oneoff) {
		system_services_get_user_ids = [](const char *, unsigned int *, unsigned int *, display_type *) -> BOOL { return false; };
		system_services_get_domain_ids = [](const char *, unsigned int *, unsigned int *) -> BOOL { return false; };
	} else {
		system_services_get_user_ids   = mysql_adaptor_get_user_ids;
		system_services_get_domain_ids = mysql_adaptor_get_domain_ids;
	}

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    mysql_adaptor_get_username_from_id)) {
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
		} else if (g_import_mode == IMPORT_TNEF) {
			if (do_tnef(argv[i], msgs) != 0)
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
		fmap.emplace(MAILBOX_FID_UNANCHORED, tgt_folder{false, PRIVATE_FID_CALENDAR, ""});
	else if (g_import_mode == IMPORT_VCARD)
		fmap.emplace(MAILBOX_FID_UNANCHORED, tgt_folder{false, PRIVATE_FID_CONTACTS, ""});
	gi_folder_map_write(fmap);
	gi_dump_name_map(static_namedprop_map.fwd);
	gi_name_map_write(static_namedprop_map.fwd);

	auto parent = parent_desc::as_folder(MAILBOX_FID_UNANCHORED);
	for (size_t i = 0; i < msgs.size(); ++i) {
		if (g_show_tree) {
			fprintf(stderr, "Message %zu\n", i + 1);
			gi_print(0, *msgs[i], ee_get_propname);
		}
		EXT_PUSH ep;
		if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT)) {
			fprintf(stderr, "E-2013: ENOMEM\n");
			return EXIT_FAILURE;
		}
		if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(i + 1) != EXT_ERR_SUCCESS ||
		    ep.p_uint32(static_cast<uint32_t>(parent.type)) != EXT_ERR_SUCCESS ||
		    ep.p_uint64(parent.folder_id) != EXT_ERR_SUCCESS ||
		    ep.p_msgctnt(*msgs[i]) != EXT_ERR_SUCCESS) {
			fprintf(stderr, "E-2004\n");
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
