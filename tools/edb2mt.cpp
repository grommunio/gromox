// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <libesedb.h>
#include <map>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/option.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/paths.h>
#include <gromox/propval.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "edb_pack.hpp"
#include "genimport.hpp"
#define TOCU8(s) reinterpret_cast<const uint8_t *>(s)
#define TOU8(s) reinterpret_cast<uint8_t *>(s)

using namespace gromox;

namespace {

struct bin_del { void operator()(BINARY *x) const { rop_util_free_binary(x); } };
struct ese_column_del { void operator()(libesedb_column_t *x) const { libesedb_column_free(&x, nullptr); } };
struct ese_error_del { void operator()(libesedb_error_t *x) const { libesedb_error_free(&x); } };
struct ese_file_del { void operator()(libesedb_file_t *x) const { libesedb_file_free(&x, nullptr); } };
struct ese_lval_del { void operator()(libesedb_long_value_t *x) const { libesedb_long_value_free(&x, nullptr); } };
struct ese_record_del { void operator()(libesedb_record_t *x) const { libesedb_record_free(&x, nullptr); } };
struct ese_table_del { void operator()(libesedb_table_t *x) const { libesedb_table_free(&x, nullptr); } };
struct edb_folder;

using ese_column_ptr = std::unique_ptr<libesedb_column_t, ese_column_del>;
using ese_error_ptr  = std::unique_ptr<libesedb_error_t, ese_error_del>;
using ese_file_ptr   = std::unique_ptr<libesedb_file_t, ese_file_del>;
using ese_lval_ptr   = std::unique_ptr<libesedb_long_value_t, ese_lval_del>;
using ese_record_ptr = std::unique_ptr<libesedb_record_t, ese_record_del>;
using ese_table_ptr  = std::unique_ptr<libesedb_table_t, ese_table_del>;
using bin_ptr        = std::unique_ptr<BINARY, bin_del>;
using colmap_t       = std::vector<std::string>; /* index to name */
using valmap_t       = std::map<std::string, std::string>; /* colname to value */
using hiermap_t      = std::map<std::string, edb_folder>;
using assigner_t     = void(const std::string &, std::string &&);
using LLU            = unsigned long long;

struct mbox {
	unsigned int id = 0, lcid = 0;
	GUID mb_guid{}, owner_guid{}, inst_guid{};
	GUID mapping_guid{}, local_id_guid{};
	std::string owner_name;
};

struct mbox_state {
	ese_file_ptr file;
	hiermap_t hier;
	int mbid = 0;
	unsigned int depth = 0;
};

struct edb_folder {
	edb_folder() = default;
	edb_folder(edb_folder &&) = delete;
	~edb_folder();
	void operator<<(edb_folder &&);

	std::string fid, parent;
	std::vector<std::string> children;
	TPROPVAL_ARRAY props{};
	std::map<unsigned int, std::string> separated_props;
};

}

static unsigned int g_list_mbox;
static char *g_extract_mbox;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'l', HXTYPE_NONE, &g_list_mbox, nullptr, nullptr, 0, "Show available mailboxes in database"},
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{nullptr, 'x', HXTYPE_STRING, &g_extract_mbox, nullptr, nullptr, 0, "Extract the given mailbox", "ID/RK/GUID"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

edb_folder::~edb_folder()
{
	while (props.count > 0)
		props.erase(props.ppropval[0].proptag);
	free(props.ppropval);
}

void edb_folder::operator<<(edb_folder &&o)
{
	fid = std::move(o.fid);
	parent = std::move(o.parent);
	children.insert(children.end(), std::make_move_iterator(o.children.begin()),
		std::make_move_iterator(o.children.end()));
	props = std::move(o.props);
	o.props = {};
	o.children.clear();
}

static YError az_error(const char *prefix, const ese_error_ptr &err)
{
	char buf[160];
	buf[0] = '\0';
	libesedb_error_sprint(err.get(), buf, std::size(buf));
	return YError(std::string(prefix) + ": " + buf);
}

static colmap_t get_column_map(libesedb_table_t *tbl)
{
	ese_error_ptr err;
	int ncols = 0;

	if (libesedb_table_get_number_of_columns(tbl, &ncols, 0, &unique_tie(err)) < 1)
		throw az_error("EE-1001", err);
	colmap_t map(ncols);
	for (int x = 0; x < ncols; ++x) {
		ese_column_ptr col;
		if (libesedb_table_get_column(tbl, x, &unique_tie(col), 0, &~unique_tie(err)) < 1)
			throw az_error("EE-1002", err);
		size_t cnsize = 0;
		if (libesedb_column_get_utf8_name_size(col.get(), &cnsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1003", err);
		/* cnsize includes space for NUL */
		if (cnsize <= 1)
			continue;
		std::string colname;
		colname.resize(cnsize);
		if (libesedb_column_get_utf8_name(col.get(),
		    reinterpret_cast<uint8_t *>(colname.data()),
		    cnsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1004", err);
		colname.pop_back(); /* remove extra NUL added by esedb */
		map[x] = std::move(colname);
	}
	return map;
}

static void read_col(libesedb_record_t *row, unsigned int x,
    const std::string &colname, std::function<assigner_t> cb)
{
	ese_error_ptr err;
	uint32_t coltype = 0;
	uint8_t flags = 0;

	if (libesedb_record_get_column_type(row, x, &coltype, &unique_tie(err)) < 1)
		throw az_error("EE-1007", err);
	if (libesedb_record_get_value_data_flags(row, x, &flags, &~unique_tie(err)) < 1)
		throw az_error("EE-1008", err);

	bool is_simple = (flags & (LIBESEDB_VALUE_FLAG_LONG_VALUE | LIBESEDB_VALUE_FLAG_MULTI_VALUE)) == 0;
	bool is_text = coltype == LIBESEDB_COLUMN_TYPE_LARGE_TEXT ||
	               coltype == LIBESEDB_COLUMN_TYPE_TEXT;
	bool is_bin  = coltype == LIBESEDB_COLUMN_TYPE_LARGE_BINARY_DATA ||
	               coltype == LIBESEDB_COLUMN_TYPE_BINARY_DATA;
	bool is_lval = (flags & (LIBESEDB_VALUE_FLAG_LONG_VALUE |
	               LIBESEDB_VALUE_FLAG_MULTI_VALUE)) == LIBESEDB_VALUE_FLAG_LONG_VALUE;
	size_t dsize = 0;
	std::string udata;

	if (is_text && is_simple) {
		auto ret = libesedb_record_get_value_utf8_string_size(row, x, &dsize, &~unique_tie(err));
		if (ret < 0)
			throw az_error("EE-1043", err);
		else if (ret == 0 || dsize == 0)
			return;
		udata.resize(dsize);
		if (libesedb_record_get_value_utf8_string(row, x,
		    TOU8(udata.data()), dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1021", err);
		udata.pop_back(); /* extra NUL emitted by libesedb */
	} else if (is_text && is_lval) {
		ese_lval_ptr lv;
		if (libesedb_record_get_long_value(row, x, &unique_tie(lv), &~unique_tie(err)) < 1)
			throw az_error("EE-1042", err);
		if (libesedb_long_value_get_utf8_string_size(lv.get(), &dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1041", err);
		if (dsize == 0)
			return;
		udata.resize(dsize);
		if (libesedb_long_value_get_utf8_string(lv.get(),
		    TOU8(udata.data()), dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1038", err);
		udata.pop_back();
	} else if (is_bin && is_simple) {
		if (libesedb_record_get_value_binary_data_size(row, x, &dsize, &~unique_tie(err)) < 1)
			return;
		if (dsize == 0)
			return;
		udata.resize(dsize);
		if (libesedb_record_get_value_binary_data(row, x,
		    TOU8(udata.data()), dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1014", err);
	} else if (is_lval) {
		ese_lval_ptr lv;
		uint64_t dsize64 = 0;
		if (libesedb_record_get_long_value(row, x, &unique_tie(lv), &~unique_tie(err)) < 1)
			throw az_error("EE-1018", err);
		if (libesedb_long_value_get_data_size(lv.get(), &dsize64, &~unique_tie(err)) < 1)
			throw az_error("EE-1019", err);
		if (dsize64 == 0)
			return;
		dsize = std::max(dsize64, static_cast<uint64_t>(UINT32_MAX));
		udata.resize(dsize);
		if (libesedb_long_value_get_data(lv.get(),
		    TOU8(udata.data()), dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1020", err);
	} else if ((flags & ~LIBESEDB_VALUE_FLAG_VARIABLE_SIZE) == 0) {
		if (libesedb_record_get_value_data_size(row, x, &dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1009", err);
		if (dsize == 0)
			return;
		udata.resize(dsize);
		if (libesedb_record_get_value_data(row, x,
		    TOU8(udata.data()), dsize, &~unique_tie(err)) < 1)
			throw az_error("EE-1010", err);
	} else {
		fprintf(stderr, "unhandled: coltype %d (%xh), flags %xh\n",
			coltype, coltype, flags);
		return;
	}
	cb(colname, std::move(udata));
}

static void foreach_col(libesedb_table_t *tbl, unsigned int y, colmap_t &ix2na,
    std::function<assigner_t> cb)
{
	ese_error_ptr err;
	ese_record_ptr row;

	if (libesedb_table_get_record(tbl, y, &unique_tie(row), &unique_tie(err)) < 1)
		throw az_error("EE-1005", err);
	int nvals = 0;
	if (libesedb_record_get_number_of_values(row.get(), &nvals, &~unique_tie(err)) < 1)
		throw az_error("EE-1006", err);
	for (int x = 0; x < nvals; ++x) {
		if (ix2na[x].empty())
			continue;
		read_col(row.get(), x, ix2na[x], cb);
	}
}

/**
 * Obtain a trivial overview list of the mailboxes contained in a EDB file for
 * further processing.
 */
static std::map<unsigned int, mbox> get_mbox_list(libesedb_file_t *file)
{
	std::map<unsigned int, mbox> mbox_list;
	ese_error_ptr err;
	ese_table_ptr table;

	if (libesedb_file_get_table_by_utf8_name(file,
	    reinterpret_cast<const uint8_t *>("Mailbox"), 8,
	    &unique_tie(table), &unique_tie(err)) < 1) {
		fprintf(stderr, "No such table \"Mailbox\"\n");
		throw ECANCELED;
	}

	auto ix2na = get_column_map(table.get());
	int nrows = 0;
	if (libesedb_table_get_number_of_records(table.get(), &nrows, &~unique_tie(err)) < 1)
		throw az_error("EE-1015", err);
	for (int y = 0; y < nrows; ++y) {
		struct mbox mb;
		foreach_col(table.get(), y, ix2na, [&](const std::string &key, std::string &&val) {
			if (val.size() == 4 && key == "MailboxNumber")
				mb.id = le32p_to_cpu(val.data());
			else if (val.size() == 16 && key == "MailboxGuid")
				memcpy(&mb.mb_guid, val.data(), 16);
			else if (val.size() == 16 && key == "OwnerADGuid")
				memcpy(&mb.owner_guid, val.data(), 16);
			else if (val.size() == 16 && key == "MailboxInstanceGuid")
				memcpy(&mb.inst_guid, val.data(), 16);
			else if (val.size() == 16 && key == "MappingSignatureGuid")
				memcpy(&mb.mapping_guid, val.data(), 16);
			else if (key == "MailboxOwnerDisplayName")
				mb.owner_name = std::move(val);
		});
		mbox_list.emplace(mb.id, std::move(mb));
	}

	if (libesedb_file_get_table_by_utf8_name(file,
	    reinterpret_cast<const uint8_t *>("MailboxIdentity"), 16,
	    &~unique_tie(table), &~unique_tie(err)) < 1) {
		fprintf(stderr, "No such table \"MailboxIdentity\"");
		throw ECANCELED;
	}
	ix2na = get_column_map(table.get());
	if (libesedb_table_get_number_of_records(table.get(), &nrows, &~unique_tie(err)) < 1)
		throw az_error("EE-1016", err);
	for (int y = 0; y < nrows; ++y) {
		int mbid = 0;
		GUID lguid{};
		foreach_col(table.get(), y, ix2na, [&](const std::string &key, std::string &&val) {
			if (val.size() == 4 && key == "MailboxNumber")
				mbid = le32p_to_cpu(val.data());
			else if (val.size() == 16 && key == "LocalIdGuid")
				memcpy(&lguid, val.data(), 16);
		});
		auto mbptr = mbox_list.find(mbid);
		if (mbptr == mbox_list.end())
			continue;
		mbptr->second.local_id_guid = std::move(lguid);
	}

	return mbox_list;
}

/**
 * Read the named properties list of the given mailbox and return a
 * genimport_namemap object for it.
 */
static gi_name_map do_namedprops(mbox_state &mbs)
{
	gi_name_map map;
	ese_error_ptr err;
	ese_table_ptr table;
	std::string tbl_name = "ExtendedPropertyNameMapping_" + std::to_string(mbs.mbid);

	if (libesedb_file_get_table_by_utf8_name(mbs.file.get(),
	    reinterpret_cast<const uint8_t *>(tbl_name.c_str()), tbl_name.size(),
	    &unique_tie(table), &unique_tie(err)) < 1) {
		fprintf(stderr, "Table \"%s\" is unexpectedly absent\n", tbl_name.c_str());
		throw ECANCELED;
	}
	auto ix2na = get_column_map(table.get());
	int nrows = 0;
	if (libesedb_table_get_number_of_records(table.get(), &nrows, &~unique_tie(err)) < 1)
		throw az_error("EE-1039", err);
	for (int y = 0; y < nrows; ++y) {
		PROPERTY_XNAME pn_req{};
		uint16_t propid = 0;
		foreach_col(table.get(), y, ix2na, [&](const std::string &key, std::string &&val) {
			if (key == "PropNumber") {
				propid = le32p_to_cpu(val.data());
			} else if (key == "PropGuid" && val.size() == 16) {
				memcpy(&pn_req.guid, val.data(), val.size());
			} else if (key == "PropName" && val.size() > 0) {
				pn_req.kind = MNID_STRING;
				pn_req.name = std::move(val);
			} else if (key == "PropDispId") {
				pn_req.lid = le32p_to_cpu(val.data());
				if (pn_req.lid != 0)
					pn_req.kind = MNID_ID;
			}
		});
		if (propid != 0)
			map.emplace(PROP_TAG(PT_UNSPECIFIED, propid), std::move(pn_req));
	}
	return map;
}

/**
 * Analyze a PropertyBlob
 */
static void do_propblob(TPROPVAL_ARRAY &props, const std::string &blob)
{
	if (blob.size() < 6 || memcmp(&blob[0], "ProP\x00\x04", 6) != 0) {
		fprintf(stderr, "Unrecognized propblob content: %s\n", bin2hex(blob.data(), blob.size()).c_str());
		return;
	}
	TPROPVAL_ARRAY new_props;
	auto cl_0 = make_scope_exit([&]() { free(new_props.ppropval); });
	edb_pull ep;
	ep.init(blob.data(), blob.size(), malloc, EXT_FLAG_UTF16);
	if (ep.g_edb_propval_a(&new_props) != pack_result::success)
		;
	if (props.count == 0)
		std::swap(new_props, props);
	while (new_props.count > 0) {
		props.set(new_props.ppropval[0].proptag, new_props.ppropval[0].pvalue);
		new_props.erase(new_props.ppropval[0].proptag);
	}
}

static const std::pair<const char *, uint32_t> folder_col_to_tag[] = {
	{"ChangeKey", PR_CHANGE_KEY},
	{"Comment", PR_COMMENT},
	{"ContainerClass", PR_CONTAINER_CLASS},
	{"ConversationCount", pidTagConversationContentCount}, // unsure
	{"CreatorSid", PR_CREATOR_SID},
	{"DisplayName", PR_DISPLAY_NAME},
	{"DisplayType", PR_DISPLAY_TYPE},
	{"FolderCount", PR_FOLDER_CHILD_COUNT},
	{"HiddenItemAttachCount", 0}, // needs verification
	{"HiddenItemCount", PR_ASSOC_CONTENT_COUNT},
	{"HiddenItemHasAttachCount", PR_ASSOC_MSG_W_ATTACH_COUNT}, // needs verification
	{"HiddenItemSize", PR_ASSOC_MESSAGE_SIZE_EXTENDED},
	{"LastModificationTime", PR_LAST_MODIFICATION_TIME},
	{"LastModifierSid", PR_LAST_MODIFIER_SID},
	{"LocalCommitTimeMax", PR_LOCAL_COMMIT_TIME_MAX},
	{"MessageAttachCount", 0}, // needs verification
	{"MessageCount", PR_CONTENT_COUNT}, // needs verification
	{"MessageHasAttachCount", PR_NORMAL_MSG_W_ATTACH_COUNT}, // needs verification
	{"MessageSize", PR_MESSAGE_SIZE_EXTENDED},
	{"NextArticleNumber", PR_INTERNET_ARTICLE_NUMBER_NEXT},
	{"ReservedMessageCnGlobCntCurrent", 0},
	{"ReservedMessageCnGlobCntMax", pidTagReservedCnCounterRangeUpperLimit}, // unsure
	{"ReservedMessageIdGlobCntCurrent", 0},
	{"ReservedMessageIdGlobCntMax", pidTagReservedIdCounterRangeUpperLimit}, // unsure
	{"SourceKey", PR_SOURCE_KEY},
	{"TotalDeletedCount", PR_DELETED_MSG_COUNT},
	{"UnreadHiddenItemCount", 0},
	{"UnreadMessageCount", PR_CONTENT_UNREAD},
	//{"MidsetDeleted", MetaTagIdsetDeleted}, // needs verification
};

static void folder_prop_handler(edb_folder &f, const std::string &key,
    std::string &&val)
{
	if (key == "FolderId") {
		f.fid = std::move(val); /* datbase_guid + FID */
		return;
	} else if (key == "ParentFolderId") {
		f.parent = std::move(val);
		return;
	} else if (key == "PropertyBlob" || key == "PropertyBlobDelta") {
		/* LargePropertyValueBlob, ExtensionBlob too? */
		do_propblob(f.props, val);
		return;
	} else if (strncmp(key.c_str(), "SeparatedProperty", 17) == 0 &&
	    key.size() == 19) {
		f.separated_props.emplace(strtoul(&key[17], nullptr, 10), std::move(val));
		return;
	}
	/*
	 * key == QueryCriteria, SearchState, SetSearchCriteriaFlags:
	 * not normally transported via tags.
	 */
	auto iter = std::lower_bound(std::begin(folder_col_to_tag),
	            std::end(folder_col_to_tag), key.c_str(),
	            [](const std::pair<const char *, uint32_t> &p, const char *key) {
	            	return strcasecmp(p.first, key) < 0;
	            });
	if (iter == std::end(folder_col_to_tag) ||
	    strcasecmp(iter->first, key.c_str()) != 0)
		return;
	auto proptag = iter->second;
	switch (PROP_TYPE(proptag)) {
	case PT_UNSPECIFIED:
	case PT_NULL:
		return;
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_APPTIME:
	case PT_I8:
	case PT_SYSTIME:
	case PT_STRING8:
	case PT_UNICODE:
		f.props.set(proptag, val.c_str());
		return;
	case PT_BINARY: {
		BINARY bv;
		bv.pv = val.data();
		bv.cb = val.size();
		f.props.set(proptag, &bv);
		return;
	}
	default:
		fprintf(stderr, "unimplemented conversion for proptag %xh\n", proptag);
		return;
	}
}

/**
 * Read the folder list from an EDB mailbox. Those folders seem to have
 * no particular order, so they need to be collected first to establish
 * the depth order.
 */
static const std::string hierarchy_root_anchor(26, '\0');
static hiermap_t read_hierarchy(mbox_state &mbs)
{
	hiermap_t fmap;
	ese_error_ptr err;
	ese_table_ptr table;
	std::string tbl_name = "Folder_" + std::to_string(mbs.mbid);

	if (libesedb_file_get_table_by_utf8_name(mbs.file.get(),
	    reinterpret_cast<const uint8_t *>(tbl_name.c_str()), tbl_name.size(),
	    &unique_tie(table), &unique_tie(err)) < 1) {
		fprintf(stderr, "Table \"%s\" is unexpectedly absent\n", tbl_name.c_str());
		throw ECANCELED;
	}
	auto ix2na = get_column_map(table.get());
	int nrows = 0;
	if (libesedb_table_get_number_of_records(table.get(), &nrows, &~unique_tie(err)) < 1)
		throw az_error("EE-1040", err);
	for (int y = 0; y < nrows; ++y) {
		edb_folder folder;
		foreach_col(table.get(), y, ix2na, [&](const std::string &key, std::string &&val) {
			folder_prop_handler(folder, key, std::move(val));
		});
		if (folder.fid.size() == 0)
			continue;
		fmap[folder.parent].children.emplace_back(folder.fid);
		auto fid_copy = folder.fid;
		fmap[std::move(fid_copy)] << std::move(folder);
	}
	auto r = fmap.find(hierarchy_root_anchor);
	if (r != fmap.end())
		r->second.fid = hierarchy_root_anchor;
	return fmap;
}

static void do_folder(mbox_state &mbs, const edb_folder &folder)
{
	tree(mbs.depth);
	if (g_show_tree)
		tlog("[fld=%s]\n", bin2hex(folder.fid.data(), folder.fid.size()).c_str());
	++mbs.depth;
	gi_dump_tpropval_a(mbs.depth, folder.props);
	for (const auto &child_id : folder.children)
		do_folder(mbs, mbs.hier[child_id]);
	--mbs.depth;
}

/**
 * Process an entire mailbox.
 */
static errno_t do_mbox(mbox_state &mbs)
{
	if (HXio_fullwrite(STDOUT_FILENO, "GXMT0003", 8) < 0)
		throw YError("PG-1014: %s", strerror(errno));
	uint8_t flag = false;
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* splice flag */
		throw YError("PG-1015: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* public store flag */
		throw YError("PG-1016: %s", strerror(errno));
	gi_folder_map_write({});

	auto name_map = do_namedprops(mbs);
	gi_dump_name_map(name_map);
	gi_name_map_write(name_map);

	mbs.hier = read_hierarchy(mbs);
	auto zero_base = mbs.hier.find(hierarchy_root_anchor);
	if (zero_base == mbs.hier.end())
		return ecSuccess;
	do_folder(mbs, zero_base->second);
	return 0;
}

/**
 * Process an entire EDB file.
 */
static errno_t do_file(const char *filename) try
{
	struct mbox_state mbs;
	ese_error_ptr err;
	if (libesedb_file_initialize(&unique_tie(mbs.file), &unique_tie(err)) < 1) {
		fprintf(stderr, "%s\n", az_error("EE-1017", err).what());
		return EIO;
	}
	fprintf(stderr, "edb2mt: Reading %s...\n", filename);
	errno = 0;
	if (libesedb_file_open(mbs.file.get(), filename,
	    LIBESEDB_OPEN_READ, &unique_tie(err)) < 1) {
		if (errno != 0)
			fprintf(stderr, "edb: Could not open \"%s\": %s\n",
			        filename, strerror(errno));
		else
			fprintf(stderr, "edb: \"%s\" not recognized as Extensible Storage Engine database\n", filename);
		return ECANCELED;
	}

	auto mbox_list = get_mbox_list(mbs.file.get());
	if (g_list_mbox) {
		for (const auto &[mbid, mb] : mbox_list)
			fprintf(stderr, "%4u  Name:         %s\n      MailboxGuid:  %s\n"
			        "      InstanceGuid: %s\n      LocalIdGuid:  %s\n\n",
			        mbid, mb.owner_name.c_str(),
			        bin2hex(mb.mb_guid).c_str(),
			        bin2hex(mb.inst_guid).c_str(),
			        bin2hex(mb.local_id_guid).c_str());
		return 0;
	}

	char *end = nullptr;
	mbs.mbid = strtoul(g_extract_mbox, &end, 0);
	if (end != nullptr && end != g_extract_mbox && *end == '\0') {
		/* Produce MT stream for exactly one mailbox. */
		auto mbptr = mbox_list.find(mbs.mbid);
		if (mbptr != mbox_list.end())
			return do_mbox(mbs);
		fprintf(stderr, "No such mailbox: %s\n", g_extract_mbox);
		return ECANCELED;
	}
	/* Try a wider match by GUID. */
	for (const auto &[mbid, mb] : mbox_list) {
		if (bin2hex(mb.mb_guid) == g_extract_mbox ||
		    bin2hex(mb.inst_guid) == g_extract_mbox ||
		    bin2hex(mb.local_id_guid) == g_extract_mbox) {
			mbs.mbid = mb.id;
			return do_mbox(mbs);
		}
	}
	fprintf(stderr, "No such mailbox: %s\n", g_extract_mbox);
	return ECANCELED;
#if 0

	auto parent = parent_desc::as_folder(~0ULL);
	if (g_show_tree)
		gi_dump_msgctnt(0, *ctnt);
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT)) {
		fprintf(stderr, "E-2020: ENOMEM\n");
		return EXIT_FAILURE;
	}
	if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(1) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(static_cast<uint32_t>(parent.type)) != EXT_ERR_SUCCESS ||
	    ep.p_uint64(parent.folder_id) != EXT_ERR_SUCCESS ||
	    ep.p_msgctnt(*ctnt) != EXT_ERR_SUCCESS) {
		fprintf(stderr, "E-2021\n");
		return EXIT_FAILURE;
	}
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
		throw YError("PG-1017: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
		throw YError("PG-1018: %s", strerror(errno));
#endif
	return 0;
} catch (const char *e) {
	fprintf(stderr, "edb: Exception: %s\n", e);
	return ECANCELED;
} catch (const std::string &e) {
	fprintf(stderr, "edb: Exception: %s\n", e.c_str());
	return ECANCELED;
} catch (const std::exception &e) {
	fprintf(stderr, "edb: Exception: %s\n", e.what());
	return ECANCELED;
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-edb2mt -l mdb01.edb\n");
	fprintf(stderr, "Usage: gromox-edb2mt -x GUID mdb01.edb | gromox-mt2....\n");
	fprintf(stderr, "Option overview: gromox-edb2mt -?\n");
	fprintf(stderr, "Documentation: man gromox-edb2mt\n");
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc != 2) {
		terse_help();
		return EXIT_FAILURE;
	}
#if 0
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}
#endif
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);

	auto ret = do_file(argv[1]);
	if (ret != 0) {
		fprintf(stderr, "edb2mt: Import unsuccessful.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
