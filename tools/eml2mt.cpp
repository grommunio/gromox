// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
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

/**
 * @content: MAPI representation with broken-down fields
 * @im_std:  Original RFC5322, stored in a std::string
 * @im_raw:  Original RFC5322, stored in a malloc buffer
 */
struct fat_message {
	message_ptr content;
	std::string im_std;
	std::unique_ptr<char[], stdlib_delete> im_raw;
	size_t im_len = 0;
};

enum {
	IMPORT_MAIL,
	IMPORT_ICAL,
	IMPORT_VCARD,
	IMPORT_MBOX,
	IMPORT_TNEF,
};

static unsigned int g_import_mode = IMPORT_MAIL;
static unsigned int g_oneoff, g_attach_decap, g_mlog_level = MLOG_DEFAULT_LEVEL;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'P', HXTYPE_NONE, &g_oxvcard_pedantic, nullptr, nullptr, 0, "Enable pedantic import mode"},
	{nullptr, 'p', HXTYPE_NONE | HXOPT_INC, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"decap", 0, HXTYPE_UINT, &g_attach_decap, {}, {}, {}, "Decapsulate embedded message (1-based index)", "IDX"},
	{"ical", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_ICAL, "Treat input as iCalendar"},
	{"loglevel", 0, HXTYPE_UINT, &g_mlog_level, {}, {}, {}, "Basic loglevel of the program", "N"},
	{"mail", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_MAIL, "Treat input as Internet Mail"},
	{"mbox", 0, HXTYPE_VAL, &g_import_mode, {}, {}, IMPORT_MBOX, "Treat input as Unix mbox"},
	{"oneoff", 0, HXTYPE_NONE, &g_oneoff, nullptr, nullptr, 0, "Resolve addresses to ONEOFF rather than EX addresses"},
	{"tnef", 0, HXTYPE_VAL, &g_import_mode, {}, {}, IMPORT_TNEF, "Treat input as TNEF"},
	{"vcard", 0, HXTYPE_VAL, &g_import_mode, nullptr, nullptr, IMPORT_VCARD, "Treat input as vCard"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr generic_module g_dfl_svc_plugins[] =
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

static message_ptr do_mail(const char *file, const char *data, size_t dsize)
{
	MAIL imail;
	if (!imail.refonly_parse(data, dsize)) {
		fprintf(stderr, "Unable to parse %s\n", file);
		return nullptr;
	}
	auto msg = oxcmail_import(&imail, gi_alloc, ee_get_propids);
	if (msg == nullptr)
		fprintf(stderr, "Failed to convert IM %s to MAPI\n", file);
	return msg;
}

static fat_message do_eml(const char *file)
{
	static constexpr uint64_t olecf_sig = 0xd0cf11e0a1b11ae1, olecf_beta = 0x0e11fc0dd0cf110e;
	fat_message mo;

	mo.im_raw.reset(strcmp(file, "-") == 0 ? HX_slurp_fd(STDIN_FILENO, &mo.im_len) :
		HX_slurp_file(file, &mo.im_len));
	auto raw = mo.im_raw.get();
	if (raw == nullptr) {
		fprintf(stderr, "Unable to read from %s: %s\n", file, strerror(errno));
		return {};
	} else if (mo.im_len >= 8 && (be64p_to_cpu(raw) == olecf_sig ||
	    be64p_to_cpu(raw) == olecf_beta)) {
		fprintf(stderr, "Input file %s looks like an OLECF file; "
			"you should use gromox-oxm2mt, not gromox-eml2mt "
			"(which is for Internet/RFC5322 mail).\n", file);
	}
	mo.content = do_mail(file, raw, mo.im_len);
	return mo;
}

enum class mbox_rid { start, envelope_from, msghdr, msgbody, emit };

struct mbox_rdstate {
	std::vector<fat_message> &msgvec;
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

		fat_message mo;
		mo.im_std  = std::move(rs.cbuf);
		mo.content = do_mail(rs.filename.c_str(), mo.im_std.data(), mo.im_std.size());
		if (mo.content == nullptr)
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

static errno_t do_mbox(const char *file, std::vector<fat_message> &msgvec)
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
	auto cl_0 = HX::make_scope_exit([&]() { HXmc_free(line); });
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
	auto err = oxcical_import_multi(ical, zalloc, ee_get_propids,
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
		fprintf(stderr, "vcard_parse %s unsuccessful (ecode=%xh)\n",
			file, static_cast<unsigned int>(ret));
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

	HXopt6_auto_result argp;
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_ARGS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argp.nargs < 1) {
		terse_help();
		return EXIT_FAILURE;
	}
	mlog_init(nullptr, nullptr, g_mlog_level, nullptr);
	setup_utf8_locale();
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init();
	g_config_file = config_file_prg(nullptr, "midb.cfg", eml2mt_cfg_defaults);
	if (g_config_file == nullptr) {
		fprintf(stderr, "Something went wrong with config files (e.g. permission denied)\n");
		return EXIT_FAILURE;
	}
	service_init({g_config_file, g_dfl_svc_plugins, 1});
	auto cl_0 = HX::make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}

	if (g_oneoff) {
		system_services_get_user_ids = [](const char *, unsigned int *, unsigned int *, display_type *) -> bool { return false; };
		system_services_get_domain_ids = [](const char *, unsigned int *, unsigned int *) -> bool { return false; };
	} else {
		system_services_get_user_ids   = mysql_adaptor_get_user_ids;
		system_services_get_domain_ids = mysql_adaptor_get_domain_ids;
	}

	if (!oxcmail_init_library(g_config_file->get_value("x500_org_name"),
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    mysql_adaptor_userid_to_name)) {
		fprintf(stderr, "oxcmail_init: unspecified error\n");
		return EXIT_FAILURE;
	}
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}

	auto cfg = config_file_prg(nullptr, "delivery.cfg", delivery_cfg_defaults);
	if (cfg == nullptr)
		return EXIT_FAILURE;

	std::vector<fat_message> msgs;
	for (int i = 0; i < argp.nargs; ++i) {
		auto le_file = argp.uarg[i];
		if (g_import_mode == IMPORT_MAIL) {
			auto mo = do_eml(le_file);
			if (mo.content == nullptr)
				continue;
			msgs.push_back(std::move(mo));
		} else if (g_import_mode == IMPORT_MBOX) {
			if (do_mbox(le_file, msgs) != 0)
				continue;
		} else if (g_import_mode == IMPORT_ICAL) {
			std::vector<message_ptr> content_vec;
			if (do_ical(le_file, content_vec) != 0)
				continue;
			for (auto &&ct : std::move(content_vec))
				msgs.emplace_back(std::move(ct));
		} else if (g_import_mode == IMPORT_VCARD) {
			std::vector<message_ptr> content_vec;
			if (do_vcard(le_file, content_vec) != 0)
				continue;
			for (auto &&ct : std::move(content_vec))
				msgs.emplace_back(std::move(ct));
		} else if (g_import_mode == IMPORT_TNEF) {
			std::vector<message_ptr> content_vec;
			if (do_tnef(le_file, content_vec) != 0)
				continue;
			for (auto &&ct : std::move(content_vec))
				msgs.emplace_back(std::move(ct));
		}
	}
	if (g_attach_decap > 0) {
		auto osize = msgs.size();
		for (auto &msg : msgs) {
			auto ret = gi_decapsulate_attachment(msg.content, g_attach_decap - 1);
			if (ret != 0)
				msg.content.reset();
		}
		std::erase_if(msgs, [](const fat_message &mo) { return mo.content == nullptr; });
		fprintf(stderr, "Attachment decapsulation filter: %zu MAPI message(s) have been turned into %zu\n",
			osize, msgs.size());
	}

	if (HXio_fullwrite(STDOUT_FILENO, "GXMT0005", 8) < 0)
		throw YError("PG-1014: %s", strerror(errno));
	uint8_t flag = false;
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* splice flag */
		throw YError("PG-1015: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* public store flag */
		throw YError("PG-1016: %s", strerror(errno));
	gi_folder_map_t fmap;
	gi_folder_map_write(fmap);
	gi_dump_name_map(static_namedprop_map.fwd);
	gi_name_map_write(static_namedprop_map.fwd);

	auto parent = parent_desc::as_folder(MAILBOX_FID_UNANCHORED);
	for (size_t i = 0; i < msgs.size(); ++i) {
		if (g_show_tree) {
			fprintf(stderr, "Message %zu\n", i + 1);
			gi_print(0, *msgs[i].content, ee_get_propname);
		}
		EXT_PUSH ep;
		if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT)) {
			fprintf(stderr, "E-2013: ENOMEM\n");
			return EXIT_FAILURE;
		}
		if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != pack_result::ok ||
		    ep.p_uint64(i + 1) != pack_result::ok ||
		    ep.p_uint32(static_cast<uint32_t>(parent.type)) != pack_result::ok ||
		    ep.p_uint64(parent.folder_id) != pack_result::ok ||
		    ep.p_msgctnt(*msgs[i].content) != pack_result::ok) {
			fprintf(stderr, "E-2004\n");
			return EXIT_FAILURE;
		}
		pack_result pr2 =
			msgs[i].im_std.size() > 0 ? ep.p_str(msgs[i].im_std) :
			msgs[i].im_raw != nullptr ? ep.p_str(msgs[i].im_raw.get()) :
			ep.p_str("");
		if (pr2 != pack_result::ok || ep.p_str("") != pack_result::ok) {
			fprintf(stderr, "E-2014\n");
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
