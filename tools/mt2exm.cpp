// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <utility>
#include <libHX/option.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/scope.hpp>
#include <gromox/tie.hpp>
#include "genimport.hpp"

using namespace gromox;

namespace {

struct ob_desc {
	enum mapi_object_type mapitype = MAPI_STORE;
	uint32_t nid = 0;
	parent_desc parent;
};

}

using gi_thru_map = std::unordered_map<uint16_t, uint16_t>;

static char *g_username;
static gi_folder_map_t g_folder_map;
static gi_name_map g_src_name_map;
static gi_thru_map g_thru_name_map;
static uint8_t g_splice, ignore_mkdir_fail;
static const struct HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{nullptr, 'u', HXTYPE_STRING, &g_username, nullptr, nullptr, 0, "Username of store to import to", "EMAILADDR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void *zalloc(size_t z) { return calloc(1, z); }

static ssize_t fullread(int fd, void *vbuf, size_t size)
{
	char *buf = static_cast<char *>(vbuf);
	size_t read_total = 0;
	if (size > SSIZE_MAX)
		size = SSIZE_MAX;

	while (read_total < size) {
		ssize_t ret = read(fd, buf, size - read_total);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			break;
		read_total += ret;
		buf += ret;
	}
	return read_total;
}

static void exm_read_base_maps()
{
	errno = 0;
	char magic[8];
	auto ret = fullread(STDIN_FILENO, magic, arsizeof(magic));
	if (ret < 0 || static_cast<size_t>(ret) != arsizeof(magic))
		throw YError("PG-1126: %s", strerror(errno));
	if (memcmp(magic, "GXMT0000", 8) != 0)
		throw YError("PG-1127: Unrecognized input format");
	ret = fullread(STDIN_FILENO, &g_splice, sizeof(g_splice));
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(g_splice))
		throw YError("PG-1120: %s", strerror(errno));

	uint64_t xsize = 0;
	errno = 0;
	ret = fullread(STDIN_FILENO, &xsize, sizeof(xsize));
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(xsize))
		throw YError("PG-1001: %s", strerror(errno));
	xsize = le64_to_cpu(xsize);
	auto buf = std::make_unique<char[]>(xsize);
	errno = 0;
	ret = fullread(STDIN_FILENO, buf.get(), xsize);
	if (ret < 0 || static_cast<size_t>(ret) != xsize)
		throw YError("PG-1002: %s", strerror(errno));
	gi_folder_map_read(buf.get(), xsize, g_folder_map);
	g_folder_map.emplace(~0ULL, tgt_folder{false, rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT), ""});
	gi_dump_folder_map(g_folder_map);

	errno = 0;
	ret = fullread(STDIN_FILENO, &xsize, sizeof(xsize));
	if (ret < 0 || static_cast<size_t>(ret) != sizeof(xsize))
		throw YError("PG-1003: %s", strerror(errno));
	xsize = le64_to_cpu(xsize);
	buf = std::make_unique<char[]>(xsize);
	ret = fullread(STDIN_FILENO, buf.get(), xsize);
	if (ret < 0 || static_cast<size_t>(ret) != xsize)
		throw YError("PG-1004: %s", strerror(errno));
	gi_name_map_read(buf.get(), xsize, g_src_name_map);
	gi_dump_name_map(g_src_name_map);
}

static void exm_adjust_staticprops(TPROPVAL_ARRAY &props)
{
	/*
	 * The WRITE_MESSAGE RPC applies certain constraints (cf.
	 * exmdb_provider:common_util_set_properties). Apply substitutions that
	 * exmdb_server_set_instance_properties would do.
	 */
	auto mfp = static_cast<uint32_t *>(tpropval_array_get_propval(&props, PR_MESSAGE_FLAGS));
	uint32_t mf = mfp != nullptr ? *mfp : 0;
	uint8_t a_one = 1;
	TAGGED_PROPVAL tp;
	tp.pvalue = &a_one;

	if (mf & MSGFLAG_READ) {
		tp.proptag = PR_READ;
		tpropval_array_set_propval(&props, &tp);
	}
	if (mf & MSGFLAG_ASSOCIATED) {
		tp.proptag = PR_ASSOCIATED;
		tpropval_array_set_propval(&props, &tp);
	}
	if (mf & MSGFLAG_RN_PENDING) {
		tp.proptag = PR_READ_RECEIPT_REQUESTED;
		tpropval_array_set_propval(&props, &tp);
	}
	if (mf & MSGFLAG_NRN_PENDING) {
		tp.proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
		tpropval_array_set_propval(&props, &tp);
	}
}

static void exm_adjust_namedprops(TPROPVAL_ARRAY &props)
{
	for (size_t i = 0; i < props.count; ++i) {
		auto old_tag = props.ppropval[i].proptag;
		if (PROP_ID(old_tag) < 0x8000)
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
			fprintf(stderr, "Database corruption: No named property entry for proptag %xh.\n", old_tag);
			continue;
		}
		auto new_id = gi_resolve_namedprop(&name_iter->second);
		props.ppropval[i].proptag = PROP_TAG(PROP_TYPE(old_tag), new_id);
		g_thru_name_map.emplace(PROP_ID(old_tag), new_id);
	}
}

static void exm_folder_adjust(TPROPVAL_ARRAY &props)
{
	/*
	 * exmdb_server_create_folder_by_properties only takes two types,
	 * upgrade everything else for best import.
	 */
	auto ftp = tpropval_array_get_propval(&props, PR_FOLDER_TYPE);
	if (ftp != nullptr) {
		auto &ft = *static_cast<uint32_t *>(ftp);
		if (ft != FOLDER_GENERIC && ft != FOLDER_SEARCH)
			ft = FOLDER_GENERIC;
	}
}

static int exm_folder(const ob_desc &obd, TPROPVAL_ARRAY &props)
{
	if (g_show_tree) {
		printf("exm: Folder %lxh (parent=%llxh)\n",
			static_cast<unsigned long>(obd.nid),
			static_cast<unsigned long long>(obd.parent.folder_id));
		if (g_show_props)
			gi_dump_tpropval_a(0, props);
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
		if (!tpropval_array_set_propval(&props, PR_DISPLAY_NAME,
		    current_it->second.create_name.c_str()))
			throw std::bad_alloc();
		auto ret = exm_create_folder(current_it->second.fid_to,
			   &props, true /* O_EXCL */, &new_fid);
		if (ret < 0 && ignore_mkdir_fail)
			return 0;
		if (ret < 0)
			return ret;
		if (new_fid != 0) {
			if (g_show_tree)
				fprintf(stderr, "Updated mapping {%lxh -> %llxh}\n",
				        static_cast<unsigned long>(obd.nid),
				        static_cast<unsigned long long>(new_fid));
			current_it->second.create = false;
			current_it->second.fid_to = new_fid;
		}
		return 0;
	} else if (current_it != g_folder_map.end() && !current_it->second.create) {
		/*
		 * #2. Instruction to splice @nid onto @fid_to (preexisting folder)
		 * such as {0x8062, {false, WASTEBASKET}}.
		 *
		 * Nothing needs to be done.
		 * Subobjects will enter case #3.
		 */
		//new_fid = current_it->second.fid_to;
		return 0;
	} else if (parent_it != g_folder_map.end()) {
		/*
		 * #3. The parent appears in the folder map.
		 * Create or reuse (depending on splice) "subfolder of e.g. wastebasket".
		 */
		auto ret = exm_create_folder(parent_it->second.fid_to,
			   &props, !g_splice, &new_fid);
		if (ret < 0 && ignore_mkdir_fail)
			return 0;
		if (ret < 0)
			return ret;
		if (new_fid != 0) {
			/* Make subobjects (seen later) to take exm_folder case #3/exm_messages case #n. */
			if (g_show_tree)
				fprintf(stderr, "exm: Learned new folder {%lxh -> %llxh}\n",
				        static_cast<unsigned long>(obd.nid),
				        static_cast<unsigned long long>(new_fid));
			g_folder_map.try_emplace(obd.nid, tgt_folder{false, new_fid});
		}
		return 0;
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
		gi_dump_msgctnt(0, ctnt);
	auto folder_it = g_folder_map.find(obd.parent.folder_id);
	if (folder_it == g_folder_map.end()) {
		fprintf(stderr, "PF-1123: unknown parent folder %llxh\n",
		        static_cast<unsigned long long>(obd.parent.folder_id));
		return 0;
	}
	exm_adjust_staticprops(ctnt.proplist);
	exm_adjust_namedprops(ctnt.proplist);
	if (g_show_tree && g_show_props) {
		tree(0);
		tlog("adjusted properties:\n");
		gi_dump_msgctnt(0, ctnt);
	}
	return exm_create_msg(folder_it->second.fid_to, &ctnt);
}

static int exm_packet(const void *buf, size_t bufsize)
{
	EXT_PULL ep;
	ep.init(buf, bufsize, zalloc, EXT_FLAG_WCOUNT);
	ob_desc obd;
	uint32_t type = 0;
	if (ep.g_uint32(&type) != EXT_ERR_SUCCESS ||
	    ep.g_uint32(&obd.nid) != EXT_ERR_SUCCESS)
		throw YError("PG-1121");
	obd.mapitype = static_cast<enum mapi_object_type>(type);
	if (ep.g_uint32(&type) != EXT_ERR_SUCCESS ||
	    ep.g_uint64(&obd.parent.folder_id) != EXT_ERR_SUCCESS)
		throw YError("PG-1116");
	obd.parent.type = static_cast<enum mapi_object_type>(type);
	if (obd.mapitype == MAPI_FOLDER) {
		TPROPVAL_ARRAY props{};
		auto cl_0 = make_scope_exit([&]() { tpropval_array_free_internal(&props); });
		if (ep.g_tpropval_a(&props) != EXT_ERR_SUCCESS)
			throw YError("PG-1118");
		auto ret = exm_folder(obd, props);
		if (ret < 0)
			throw YError("PG-1122: %s", strerror(errno));
		return 0;
	} else if (obd.mapitype == MAPI_MESSAGE) {
		MESSAGE_CONTENT ctnt{};
		auto cl_0 = make_scope_exit([&]() { message_content_free_internal(&ctnt); });
		if (ep.g_msgctnt(&ctnt) != EXT_ERR_SUCCESS)
			throw YError("PG-1119");
		return exm_message(obd, ctnt);
	}
	throw YError("PG-1117: unknown obd.mapitype %u", obd.mapitype);
}

static void gi_dump_thru_map(const gi_thru_map &map)
{
	if (!g_show_props)
		return;
	fprintf(stderr, "Named properties, thru-map (%zu entries):\n", map.size());
	for (const auto &[from, to] : map)
		fprintf(stderr, "\t%04xh <-> %04xh\n", from, to);
}

int main(int argc, const char **argv) try
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_username == nullptr) {
		fprintf(stderr, "Usage: gromox-mt2exm -u username\n");
		return EXIT_FAILURE;
	}

	exm_read_base_maps();
	if (gi_setup(g_username) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	while (true) {
		uint64_t xsize = 0;
		errno = 0;
		auto ret = fullread(STDIN_FILENO, &xsize, sizeof(xsize));
		if (ret == 0)
			break;
		if (ret < 0 || static_cast<size_t>(ret) != sizeof(xsize))
			throw YError("PG-1005: %s", strerror(errno));
		xsize = le64_to_cpu(xsize);
		auto buf = std::make_unique<char[]>(xsize);
		errno = 0;
		ret = fullread(STDIN_FILENO, buf.get(), xsize);
		if (ret < 0 || static_cast<size_t>(ret) != xsize)
			throw YError("PG-1006: %s", strerror(errno));
		exm_packet(buf.get(), xsize);
	}
	gi_dump_thru_map(g_thru_name_map);
	return EXIT_SUCCESS;
} catch (const std::exception &e) {
	fprintf(stderr, "Exception: %s\n", e.what());
	return EXIT_FAILURE;
}
