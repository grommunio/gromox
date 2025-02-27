// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sqlite3.h>
#include <vector>
#include <fmt/core.h>
#include <libHX/option.h>
#include <gromox/database.h>
#include <gromox/mapi_types.hpp>
#include <gromox/scope.hpp>

using namespace gromox;
using LLU = unsigned long long;

static unsigned int g_do_repair;

static ssize_t ck_allocated_eids(sqlite3 *db)
{
	auto xt = gx_sql_begin(db, g_do_repair ? txn_mode::write : txn_mode::read);
	std::vector<uint64_t> eids;

	auto stm = gx_sql_prep(db, "SELECT f.folder_id "
		"FROM folders AS f LEFT JOIN allocated_eids AS a "
		"ON a.range_begin <= f.folder_id AND f.folder_id < a.range_end "
		"WHERE f.folder_id > 0 AND a.range_begin IS NULL");
	if (stm == nullptr)
		return -1;
	ssize_t probs = 0;
	printf("%s:", __func__);
	for (; stm.step() == SQLITE_ROW; ++probs) {
		auto objid = stm.col_int64(0);
		printf(" f%llu", LLU(objid));
		if (g_do_repair)
			eids.push_back(objid);
	}

	stm = gx_sql_prep(db, "SELECT m.message_id FROM messages AS m "
		"LEFT JOIN allocated_eids AS a ON a.range_begin <= m.message_id "
		"AND m.message_id < a.range_end WHERE m.message_id > 0 "
		"AND a.range_begin IS NULL");
	if (stm == nullptr)
		return -1;
	for (; stm.step() == SQLITE_ROW; ++probs) {
		auto objid = stm.col_int64(0);
		printf(" m%llu", LLU(objid));
		if (g_do_repair)
			eids.push_back(objid);
	}
	printf(" [%zu issues]", probs);
	if (!g_do_repair) {
		printf("\n");
		return probs;
	}

	stm = gx_sql_prep(db, "INSERT INTO allocated_eids (range_begin,range_end,allocate_time,is_system) VALUES (?,?,0,1)");
	if (stm == nullptr)
		return -1;
	for (auto objid : eids) {
		stm.bind_int64(1, objid);
		stm.bind_int64(2, objid + 1);
		auto ret = stm.step();
		if (ret != SQLITE_DONE)
			return -1;
		stm.reset();
	}
	if (eids.size() > 0)
		printf(" [fixed]");
	printf("\n");
	if (xt.commit() != SQLITE_OK)
		return -1;
	return probs;
}

static ssize_t ck_indices_present(sqlite3 *db)
{
	static constexpr const char *names[] = {
		"allocated_eids.time_index",
		"attachments_properties.attachment_property_index6",
		"attachments_properties.attid_properties_index6",
		"attachments.mid_attachments_index",
		"autoreply_ts.sqlite_autoindex_autoreply_ts_1",
		"folder_properties.folder_property_index3",
		"folder_properties.fid_properties_index3",
		"folders.search_index10",
		"folders.sqlite_autoindex_folders_1",
		"message_changes.mid_changes_index",
		"message_properties.proptag_propval_index4",
		"message_properties.message_property_index4",
		"message_properties.mid_properties_index4",
		"messages.parent_read_assoc_index8",
		"messages.parent_assoc_index8",
		"messages.assoc_index8",
		"messages.attid_messages_index8",
		"messages.pid_messages_index8",
		"messages.sqlite_autoindex_messages_2",
		"messages.sqlite_autoindex_messages_1",
		"named_properties.namedprop_unique",
		"permissions.folder_username_index",
		"permissions.fid_permissions_index",
		"receive_table.fid_receive_index",
		"receive_table.sqlite_autoindex_receive_table_1",
		"recipients.mid_recipients_index",
		"recipients_properties.recipient_property_index5",
		"recipients_properties.rid_properties_index5",
		"replguidmap.replguidmap_guid",
		"rules.fid_rules_index",
		"search_result.search_message_index",
		"search_result.mid_result_index",
		"search_result.fid_result_index",
		"search_scopes.included_scope_index",
		"search_scopes.fid_scope_index",
		"store_properties.sqlite_autoindex_store_properties_1",
		"zz",
	};
	auto xt = gx_sql_begin(db, g_do_repair ? txn_mode::write : txn_mode::read);
	ssize_t pr = 0;
	printf("%s:", __func__);
	for (const auto e : names) {
		const char *e2 = strchr(e, '.'); /* CONST-STRCHR-MARKER */
		if (e2 == nullptr)
			e2 = e;
		auto stm = gx_sql_prep(db, fmt::format("PRAGMA index_list({})", ++e2).c_str());
		if (stm == nullptr) {
			printf(" %s", e);
			++pr;
		}
	}
	if (pr > 0) {
		printf(" [%zu problems]", pr);
		if (g_do_repair)
			printf(" [repair_not_implemented]");
	}
	printf("\n");
	if (xt.commit() != SQLITE_OK)
		return -1;
	return pr;
}

static ssize_t check_one_db(sqlite3 *db)
{
	auto ret = ck_allocated_eids(db);
	if (ret < 0)
		return ret;
	auto pr = ret;
	ret = ck_indices_present(db);
	if (ret < 0)
		return ret;
	pr += ret;
	return pr;
}

static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE, &g_do_repair, nullptr, nullptr, 0, "Perform repairs"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc < 2) {
		fprintf(stderr, "Usage: mbck [-p] sqlitefile\n");
		return EXIT_FAILURE;
	}
	while (*++argv != nullptr) {
		sqlite3 *db = nullptr;
		auto ret = sqlite3_open_v2(*argv, &db, SQLITE_OPEN_READWRITE, nullptr);
		if (ret != SQLITE_OK) {
			fprintf(stderr, "sqlite3_open_v2 %s: %s\n", *argv, sqlite3_errstr(ret));
			return EXIT_FAILURE;
		}
		printf("== %s ==\n", *argv);
		auto cl_0 = make_scope_exit([&]() { sqlite3_close(db); });
		if (gx_sql_exec(db, "PRAGMA foreign_keys=ON") != SQLITE_OK ||
		    gx_sql_exec(db, "PRAGMA journal_mode=WAL") != SQLITE_OK ||
		    sqlite3_busy_timeout(db, 60000) != SQLITE_OK)
			return EXIT_FAILURE;
		auto pr = check_one_db(db);
		if (pr < 0)
			return EXIT_FAILURE;
		else if (pr > 0)
			printf("%s: %zu problems total\n", *argv, pr);
	}
	return EXIT_SUCCESS;
}
