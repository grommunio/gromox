// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <utility>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/paths.h>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "staticnpmap.cpp"

using namespace gromox;
using namespace gi_dump;

namespace {

struct ob_desc {
	enum mapi_object_type mapitype = MAPI_STORE;
	uint32_t nid = 0;
	parent_desc parent;
};

}

using propididmap_t = std::unordered_map<uint16_t, uint16_t>;

static char *g_username, *g_anchor_folder_str;
static gi_folder_map_t g_folder_map;
static gi_name_map g_src_name_map;
static propididmap_t g_thru_name_map;
static uint8_t g_splice;
static uint64_t g_anchor_folder; /* GCV */
static unsigned int g_oexcl = 1, g_repeat_iter = 1;
static unsigned int g_do_delivery, g_skip_notif, g_skip_rules, g_twostep;
static unsigned int g_continuous_mode, g_mrautoproc, g_mlog_level = MLOG_DEFAULT_LEVEL;

static constexpr static_module g_dfl_svc_plugins[] = {
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgxs_ruleproc.so", SVC_ruleproc},
};

static const char *strerror_eof(int e)
{
	return e != 0 ? strerror(e) : "EOF";
}

static constexpr HXoption g_options_table[] = {
	{nullptr, 'B', HXTYPE_STRING, &g_anchor_folder_str, nullptr, nullptr, 0, "Placement position for unanchored messages", "NAME"},
	{nullptr, 'D', HXTYPE_NONE, &g_do_delivery, nullptr, nullptr, 0, "Use delivery mode"},
	{nullptr, 'c', HXTYPE_NONE, &g_continuous_mode, {}, {}, 0, "Continuous operation mode (do not stop on errors)"},
	{nullptr, 'p', HXTYPE_NONE | HXOPT_INC, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	{nullptr, 'v', HXTYPE_NONE | HXOPT_INC, &g_verbose_create, nullptr, nullptr, 0, "Be more verbose"},
	{nullptr, 'x', HXTYPE_VAL, &g_oexcl, nullptr, nullptr, 0, "Disable O_EXCL like behavior for non-spliced folders"},
	{"loglevel", 0, HXTYPE_UINT, &g_mlog_level, {}, {}, {}, "Basic loglevel of the program", "N"},
	{"repeat", 0, HXTYPE_UINT, &g_repeat_iter, {}, {}, 0, "For testing purposes, import each message N times", "N"},
	{"skip-notif", 0, HXTYPE_NONE, &g_skip_notif, nullptr, nullptr, 0, "Skip emission of notifications (if -D)"},
	{"skip-rules", 0, HXTYPE_NONE, &g_skip_rules, nullptr, nullptr, 0, "Skip execution of rules (if -D)"},
	{"twostep", '2', HXTYPE_NONE, &g_twostep, nullptr, nullptr, 0, "TWOSTEP rule executor (implies -D; development)"},
	{"autoproc", 0, HXTYPE_NONE, &g_mrautoproc, {}, {}, 0, "Perform meeting request processing (development)"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void filter_folder_map(gi_folder_map_t &fmap)
{
	if (!g_public_folder)
		fmap.emplace(MAILBOX_FID_UNANCHORED, tgt_folder{false, g_anchor_folder != 0 ?
			g_anchor_folder : PRIVATE_FID_DRAFT, ""});
	else
		fmap.emplace(MAILBOX_FID_UNANCHORED, tgt_folder{false, PUBLIC_FID_IPMSUBTREE, ""});
	for (auto &p : fmap)
		p.second.fid_to = rop_util_make_eid_ex(1, p.second.fid_to);
}

static int exm_read_base_maps()
{
	errno = 0;
	char magic[8];
	auto ret = HXio_fullread(STDIN_FILENO, magic, std::size(magic));
	if (ret == 0)
		return 0;
	if (ret < 0 || static_cast<size_t>(ret) != std::size(magic))
		throw YError("PG-1126: %s", strerror_eof(errno));
	if (memcmp(magic, "GXMT0003", 8) != 0)
		throw YError("PG-1127: Unrecognized input format");
	ret = HXio_fullread(STDIN_FILENO, &g_splice, sizeof(g_splice));
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(g_splice))
		throw YError("PG-1120: %s", strerror_eof(errno));
	ret = HXio_fullread(STDIN_FILENO, &magic[0], 1);
	if (ret < 0 || static_cast<size_t>(ret) != 1)
		throw YError("PG-1124: %s", strerror_eof(errno));
	if (g_splice && g_public_folder && magic[0] != 1)
		throw YError("PG-1125: Cannot satisfy splice request. The target is a public store, but input is from a private store."
			" Remove the -s option from your kdb2mt/pff2mt command and retry.");
	else if (g_splice && !g_public_folder && magic[0] != 0)
		throw YError("PG-1128: Cannot satisfy splice request. The target is a private store, but input is from a public store."
			" Remove the -s option from your kdb2mt/pff2mt command and retry.");

	uint64_t xsize = 0;
	errno = 0;
	ret = HXio_fullread(STDIN_FILENO, &xsize, sizeof(xsize));
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(xsize))
		throw YError("PG-1001: %s", strerror_eof(errno));
	xsize = le64_to_cpu(xsize);
	auto buf = std::make_unique<char[]>(xsize);
	errno = 0;
	ret = HXio_fullread(STDIN_FILENO, buf.get(), xsize);
	if (ret < 0 || static_cast<size_t>(ret) != xsize)
		throw YError("PG-1002: %s", strerror_eof(errno));
	gi_folder_map_read(buf.get(), xsize, g_folder_map);
	gi_dump_folder_map(g_folder_map);
	filter_folder_map(g_folder_map);
	if (g_show_props)
		fprintf(stderr, "Folder map adjusted (for a %s store):\n", g_public_folder ? "public" : "private");
	gi_dump_folder_map(g_folder_map);

	errno = 0;
	ret = HXio_fullread(STDIN_FILENO, &xsize, sizeof(xsize));
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(xsize))
		throw YError("PG-1003: %s", strerror_eof(errno));
	xsize = std::min(le64_to_cpu(xsize), static_cast<uint64_t>(UINT64_MAX));
	buf = std::make_unique<char[]>(xsize);
	ret = HXio_fullread(STDIN_FILENO, buf.get(), xsize);
	if (ret < 0 || static_cast<size_t>(ret) != xsize)
		throw YError("PG-1004: %s", strerror_eof(errno));
	gi_name_map_read(buf.get(), xsize, g_src_name_map);
	gi_dump_name_map(g_src_name_map);
	return 1;
}

static void exm_adjust_staticprops(TPROPVAL_ARRAY &props)
{
	/*
	 * The WRITE_MESSAGE RPC applies certain constraints (cf.
	 * exmdb_provider:common_util_set_properties). Apply substitutions that
	 * exmdb_server_set_instance_properties would do.
	 */
	auto mfp = props.get<uint32_t>(PR_MESSAGE_FLAGS);
	uint32_t mf = mfp != nullptr ? *mfp : 0;
	static constexpr uint8_t a_one = 1;
	static constexpr std::pair<unsigned int, unsigned int> xmap[] = {
		{MSGFLAG_READ, PR_READ},
		{MSGFLAG_ASSOCIATED, PR_ASSOCIATED},
		{MSGFLAG_RN_PENDING, PR_READ_RECEIPT_REQUESTED},
		{MSGFLAG_NRN_PENDING, PR_NON_RECEIPT_NOTIFICATION_REQUESTED},
	};
	for (const auto &e : xmap)
		if (mf & e.first && props.set(e.second, &a_one) == ecServerOOM)
			throw std::bad_alloc();
}

static void exm_adjust_namedprops(TPROPVAL_ARRAY &props)
{
	for (size_t i = 0; i < props.count; ++i) {
		auto old_tag = props.ppropval[i].proptag;
		if (!is_nameprop_id(PROP_ID(old_tag)))
			continue;
		auto thru_iter = g_thru_name_map.find(PROP_ID(old_tag));
		if (thru_iter != g_thru_name_map.end()) {
			props.ppropval[i].proptag = PROP_TAG(PROP_TYPE(old_tag), thru_iter->second);
			continue;
		}
		auto name_iter = g_src_name_map.find(old_tag);
		if (name_iter == g_src_name_map.end())
			name_iter = g_src_name_map.find(CHANGE_PROP_TYPE(old_tag, PT_UNSPECIFIED));
		if (name_iter == g_src_name_map.end()) {
			fprintf(stderr, "mt2exm: broken input stream does not specify namedpropinfo for tag %xh.\n", old_tag);
			continue;
		}
		auto new_id = gi_resolve_namedprop(name_iter->second);
		props.ppropval[i].proptag = PROP_TAG(PROP_TYPE(old_tag), new_id);
		g_thru_name_map.emplace(PROP_ID(old_tag), new_id);
	}
}

static void exm_adjust_propids(MESSAGE_CONTENT &);
static void exm_adjust_propids(ATTACHMENT_CONTENT &ac)
{
	exm_adjust_staticprops(ac.proplist);
	exm_adjust_namedprops(ac.proplist);
	if (ac.pembedded != nullptr)
		exm_adjust_propids(*ac.pembedded);
}

static void exm_adjust_propids(MESSAGE_CONTENT &mc)
{
	exm_adjust_staticprops(mc.proplist);
	exm_adjust_namedprops(mc.proplist);
	if (mc.children.prcpts != nullptr)
		for (auto &rcpt : *mc.children.prcpts) {
			exm_adjust_staticprops(rcpt);
			exm_adjust_namedprops(rcpt);
		}
	if (mc.children.pattachments != nullptr)
		for (auto &at : *mc.children.pattachments)
			exm_adjust_propids(at);
}

static void exm_folder_adjust(TPROPVAL_ARRAY &props)
{
	/*
	 * exmdb_server_create_folder only allows two types,
	 * upgrade everything else for best import.
	 */
	auto ft = props.get<uint32_t>(PR_FOLDER_TYPE);
	if (ft != nullptr && *ft != FOLDER_GENERIC && *ft != FOLDER_SEARCH)
		*ft = FOLDER_GENERIC;
	exm_adjust_staticprops(props);
	exm_adjust_namedprops(props);
}

static int exm_folder(const ob_desc &obd, TPROPVAL_ARRAY &props,
    const std::vector<PERMISSION_DATA> &perms)
{
	if (g_show_tree) {
		printf("exm: Folder %lxh (parent=%llxh)\n",
			static_cast<unsigned long>(obd.nid),
			static_cast<unsigned long long>(obd.parent.folder_id));
		if (g_show_props)
			gi_print(0, props, ee_get_propname);
	}
	exm_folder_adjust(props);

	auto current_it  = g_folder_map.find(obd.nid);
	auto parent_it   = g_folder_map.find(obd.parent.folder_id);
	uint64_t new_fid = 0;

	if (current_it != g_folder_map.end() && current_it->second.create) {
		/*
		 * #1. Instruction to create folder beneath @fid_to
		 * such as {NID_ROOT_FOLDER, {true, IPMSUBTREE, "Import of ..."}}
		 */
		if (props.set(PR_DISPLAY_NAME, current_it->second.create_name.c_str()) == ecServerOOM)
			throw std::bad_alloc();
		auto ret = exm_create_folder(current_it->second.fid_to,
			   &props, g_oexcl, &new_fid);
		if (ret < 0) {
			fprintf(stderr, "exm: folder for input object %lxh could not be created\n",
			        static_cast<unsigned long>(obd.nid));
			return ret;
		}
		if (new_fid != 0) {
			if (g_show_tree)
				fprintf(stderr, "Updated mapping {%lxh -> %llxh}\n",
				        static_cast<unsigned long>(obd.nid),
				        static_cast<unsigned long long>(new_fid));
			current_it->second.create = false;
			current_it->second.fid_to = new_fid;
		}
		return exm_permissions(new_fid, perms);
	} else if (current_it != g_folder_map.end() && !current_it->second.create) {
		/*
		 * #2. Instruction to splice @nid onto @fid_to (preexisting folder)
		 * such as {0x8062, {false, WASTEBASKET}}.
		 *
		 * Nothing needs to be done.
		 * Subobjects will enter case #3.
		 */
		//new_fid = current_it->second.fid_to;
		return exm_permissions(current_it->second.fid_to, perms);
	} else if (parent_it != g_folder_map.end()) {
		/*
		 * #3. The parent appears in the folder map.
		 * Create or reuse (depending on splice) "subfolder of e.g. wastebasket".
		 */
		auto ret = exm_create_folder(parent_it->second.fid_to,
			   &props, !g_splice && g_oexcl, &new_fid);
		if (ret < 0) {
			fprintf(stderr, "exm: folder for input object %lxh could not be created\n",
			        static_cast<unsigned long>(obd.nid));
			return ret;
		}
		if (new_fid != 0) {
			/* Make subobjects (seen later) to take exm_folder case #3/exm_messages case #n. */
			if (g_show_tree)
				fprintf(stderr, "exm: Learned new folder {%lxh -> %llxh}\n",
				        static_cast<unsigned long>(obd.nid),
				        static_cast<unsigned long long>(new_fid));
			g_folder_map.try_emplace(obd.nid, tgt_folder{false, new_fid});
		}
		return exm_permissions(new_fid, perms);
	}
	fprintf(stderr, "exm: No known placement method for NID %lxh, skipping.\n",
	        static_cast<unsigned long>(obd.nid));
	return 0;
}

static int exm_message(const ob_desc &obd, MESSAGE_CONTENT &ctnt)
{
	if (g_show_tree)
		printf("exm: Message %lxh (parent=%llxh)\n",
			static_cast<unsigned long>(obd.nid),
			static_cast<unsigned long long>(obd.parent.folder_id));
	if (g_show_tree && g_show_props)
		gi_print(0, ctnt, ee_get_propname);
	auto folder_it = g_folder_map.find(obd.parent.folder_id);
	if (!g_do_delivery && folder_it == g_folder_map.end()) {
		fprintf(stderr, "PF-1123: unknown parent folder %llxh\n",
		        static_cast<unsigned long long>(obd.parent.folder_id));
		return 0;
	}
	exm_adjust_propids(ctnt);
	if (g_show_tree && g_show_props) {
		tree(0);
		tlog("adjusted properties:\n");
		gi_print(0, ctnt, ee_get_propname);
	}
	if (!g_do_delivery) {
		for (auto i = 0U; i < g_repeat_iter; ++i) {
			if (i > 0 && i % 1024 == 0)
				fprintf(stderr, "mt2exm repeat %u/%u\n", i, g_repeat_iter);
			auto ret = exm_create_msg(folder_it->second.fid_to, &ctnt);
			if (ret != EXIT_SUCCESS)
				return ret;
		}
		return EXIT_SUCCESS;
	}
	unsigned int mode = 0;
	if (!g_skip_rules)
		mode |= DELIVERY_DO_RULES;
	if (!g_skip_notif)
		mode |= DELIVERY_DO_NOTIF;
	if (g_twostep) {
		mode |= DELIVERY_TWOSTEP;
		mode &= ~(DELIVERY_DO_RULES | DELIVERY_DO_NOTIF);
	}
	if (g_mrautoproc)
		mode |= DELIVERY_MRAUTOPROC;
	for (auto i = 0U; i < g_repeat_iter; ++i) {
		if (i > 0 && i % 1024 == 0)
			fprintf(stderr, "mt2exm repeat %u/%u\n", i, g_repeat_iter);
		auto ret = exm_deliver_msg(g_username, &ctnt, mode);
		if (ret != EXIT_SUCCESS)
			return ret;
	}
	return EXIT_SUCCESS;
}

static int exm_packet(const void *buf, size_t bufsize)
{
	EXT_PULL ep;
	ep.init(buf, bufsize, zalloc, EXT_FLAG_WCOUNT);
	ob_desc obd;
	uint32_t type = 0, parent_type = 0;
	if (ep.g_uint32(&type) != pack_result::ok ||
	    ep.g_uint32(&obd.nid) != pack_result::ok)
		throw YError("PG-1121");
	if (ep.g_uint32(&parent_type) != pack_result::success ||
	    ep.g_uint64(&obd.parent.folder_id) != pack_result::ok)
		throw YError("PG-1116");
	if (type == GXMT_NAMEDPROP) {
		PROPERTY_NAME propname{};
		if (ep.g_propname(&propname) != pack_result::success)
			throw YError("PG-1138");
		try {
			g_src_name_map.insert_or_assign(obd.nid, propname);
		} catch (const std::bad_alloc &) {
			free(propname.pname);
			throw;
		}
		free(propname.pname);
		return 0;
	}
	obd.mapitype = static_cast<enum mapi_object_type>(type);
	obd.parent.type = static_cast<enum mapi_object_type>(parent_type);
	if (obd.mapitype == MAPI_FOLDER && g_do_delivery) {
		return 0;
	} else if (obd.mapitype == MAPI_FOLDER) {
		TPROPVAL_ARRAY props{};
		auto cl_0 = HX::make_scope_exit([&]() { tpropval_array_free_internal(&props); });
		if (ep.g_tpropval_a(&props) != pack_result::ok)
			throw YError("PG-1118");
		uint64_t acl_items = 0;
		if (ep.g_uint64(&acl_items) != pack_result::ok)
			throw YError("PG-1132");
		std::vector<PERMISSION_DATA> perms;
		for (uint64_t i = 0; i < acl_items; ++i) {
			PERMISSION_DATA d;
			if (ep.g_permission_data(&d) != pack_result::ok)
				throw YError("PG-1129");
			if (d.flags == ROW_ADD)
				perms.push_back(std::move(d));
			else
				fprintf(stderr, "ACE not of type ROW_ADD, ignoring\n");
		}
		auto ret = exm_folder(obd, props, perms);
		if (ret < 0)
			throw YError("PG-1122: %s", strerror(-ret));
		return 0;
	} else if (obd.mapitype == MAPI_MESSAGE) {
		MESSAGE_CONTENT ctnt{};
		auto cl_0 = HX::make_scope_exit([&]() { message_content_free_internal(&ctnt); });
		if (ep.g_msgctnt(&ctnt) != pack_result::ok)
			throw YError("PG-1119");
		return exm_message(obd, ctnt);
	}
	throw YError("PG-1117: unknown obd.mapitype %u", static_cast<unsigned int>(obd.mapitype));
}

static void gi_dump_thru_map(const propididmap_t &map)
{
	if (!g_show_props)
		return;
	fprintf(stderr, "propid-to-propid map (%zu entries):\n", map.size());
	fprintf(stderr, "\t# src propid <-> dst propid:\n");
	for (const auto &[from, to] : map)
		fprintf(stderr, "\t%04xh <-> %04xh\n", from, to);
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-mt2exm -u target@mbox.de <stream.dump\n");
	fprintf(stderr, "Option overview: gromox-mt2exm -?\n");
	fprintf(stderr, "Documentation: man gromox-mt2exm\n");
}

int main(int argc, char **argv) try
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt5(g_options_table, argv, &argc, &argv,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0a = HX::make_scope_exit([=]() { HX_zvecfree(argv); });
	if (g_username == nullptr) {
		terse_help();
		return EXIT_FAILURE;
	}
	mlog_init(nullptr, nullptr, g_mlog_level, nullptr);
	if (g_continuous_mode)
		fprintf(stderr, "Continuous mode has been selcted: On errors, the import will NOT abort\n");
	if (g_twostep)
		g_do_delivery = true;
	if (g_do_delivery && g_anchor_folder != 0)
		fprintf(stderr, "mt2exm: -B option has no effect when -D is used\n");
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	service_init({nullptr, g_dfl_svc_plugins, 1});
	auto cl_1 = HX::make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}
	textmaps_init(PKGDATADIR);
	if (gi_setup_from_user(g_username) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	if (gi_startup_client() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	auto cl_0 = HX::make_scope_exit(gi_shutdown);
	if (g_anchor_folder_str == nullptr) {
		g_anchor_folder = PRIVATE_FID_DRAFT;
	} else {
		g_anchor_folder = rop_util_get_gc_value(gi_lookup_eid_by_name(g_storedir, g_anchor_folder_str));
		if (g_anchor_folder == 0) {
			fprintf(stderr, "Folder not recognized/found: \"%s\"\n", g_anchor_folder_str);
			return EXIT_FAILURE;
		}
	}
	if (exm_read_base_maps() == 0)
		return EXIT_SUCCESS;
	int iret = EXIT_SUCCESS;
	while (true) {
		uint64_t xsize = 0;
		errno = 0;
		auto ret = HXio_fullread(STDIN_FILENO, &xsize, sizeof(xsize));
		if (ret == 0)
			break;
		else if (ret < 0 || static_cast<size_t>(ret) != sizeof(xsize))
			throw YError("PG-1005: %s", strerror_eof(errno));
		xsize = le64_to_cpu(xsize);
		auto buf = std::make_unique<char[]>(xsize);
		errno = 0;
		ret = HXio_fullread(STDIN_FILENO, buf.get(), xsize);
		if (ret < 0 || static_cast<size_t>(ret) != xsize)
			throw YError("PG-1006: %s", strerror_eof(errno));
		auto pkret = exm_packet(buf.get(), xsize);
		if (pkret != EXIT_SUCCESS && !g_continuous_mode) {
			iret = pkret;
			break;
		}
	}
	gi_dump_thru_map(g_thru_name_map);
	return iret;
} catch (const std::exception &e) {
	fprintf(stderr, "mt2exm: Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
