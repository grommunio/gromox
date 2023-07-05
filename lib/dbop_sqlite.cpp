// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <climits>
#include <cstdio>
#include <memory>
#include <fmt/core.h>
#include <gromox/database.h>
#include <gromox/dbop.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

/*
 * INDEX names should be suffixed by the schema number, to facilitate
 * dbop_sqlite_upgrade (old table+index exists simultaneously with new table).
 */
#define TABLE_END {}

namespace gromox {

namespace {

struct tbl_init {
	const char *name, *command;
};

struct tblite_upgradefn {
	unsigned int v;
	const char *command, *tbl_name, *q_create, *q_move;
};

}

static constexpr char tbl_config_0[] =
"CREATE TABLE configurations ("
"  config_id INTEGER PRIMARY KEY,"
"  config_value NONE NOT NULL)";

static constexpr char tbl_config_1[] =
"CREATE TABLE configurations ("
"  config_id INTEGER PRIMARY KEY,"
"  config_value BLOB NOT NULL)";

static constexpr char tbl_config_move1[] =
"INSERT INTO configurations SELECT config_id, config_value FROM u0";

static constexpr char tbl_alloc_eids_0[] =
"CREATE TABLE allocated_eids ("
"  range_begin INTEGER NOT NULL,"
"  range_end INTEGER NOT NULL,"
"  allocate_time INTEGER NOT NULL,"
"  is_system INTEGER DEFAULT NULL);"
"CREATE INDEX time_index ON allocated_eids(allocate_time);";

static constexpr char tbl_namedprops_0[] =
"CREATE TABLE named_properties ("
"  propid INTEGER PRIMARY KEY AUTOINCREMENT,"
"  name_string TEXT COLLATE NOCASE NOT NULL)";

static constexpr char tbl_storeprops_0[] =
"CREATE TABLE store_properties ("
"  proptag INTEGER UNIQUE NOT NULL,"
"  propval NONE NOT NULL)";

static constexpr char tbl_storeprops_2[] =
"CREATE TABLE store_properties ("
"  proptag INTEGER UNIQUE NOT NULL,"
"  propval BLOB NOT NULL)";

static constexpr char tbl_storeprops_move2[] =
"INSERT INTO store_properties SELECT proptag, propval FROM u0";

static constexpr char tbl_fldprops_0[] =
"CREATE TABLE folder_properties ("
"  folder_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval NONE NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_properties_index ON folder_properties(folder_id);"
"CREATE UNIQUE INDEX folder_property_index ON folder_properties(folder_id, proptag);";

static constexpr char tbl_fldprops_3[] =
"CREATE TABLE folder_properties ("
"  folder_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval BLOB NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_properties_index3 ON folder_properties(folder_id);"
"CREATE UNIQUE INDEX folder_property_index3 ON folder_properties(folder_id, proptag);";

static constexpr char tbl_fldprops_move3[] =
"INSERT INTO folder_properties SELECT folder_id, proptag, propval FROM u0";

static constexpr char tbl_perms_0[] =
"CREATE TABLE permissions ("
"  member_id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  folder_id INTEGER NOT NULL,"
"  username TEXT COLLATE NOCASE NOT NULL,"
"  permission INTEGER NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_permissions_index ON permissions(folder_id);"
"CREATE UNIQUE INDEX folder_username_index ON permissions(folder_id, username);";

static constexpr char tbl_rules_0[] =
"CREATE TABLE rules ("
"  rule_id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  name TEXT COLLATE NOCASE,"
"  provider TEXT COLLATE NOCASE NOT NULL,"
"  sequence INTEGER NOT NULL,"
"  state INTEGER NOT NULL,"
"  level INTEGER,"
"  user_flags INTEGER,"
"  provider_data BLOB,"
"  condition BLOB NOT NULL,"
"  actions BLOB NOT NULL,"
"  folder_id INTEGER NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_rules_index on rules(folder_id);";

static constexpr char tbl_msgprops_0[] =
"CREATE TABLE message_properties ("
"  message_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval NONE NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_properties_index ON message_properties(message_id);"
"CREATE UNIQUE INDEX message_property_index ON message_properties(message_id, proptag);"
"CREATE INDEX proptag_propval_index ON message_properties(proptag, propval);";

static constexpr char tbl_msgprops_4[] =
"CREATE TABLE message_properties ("
"  message_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval BLOB NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_properties_index4 ON message_properties(message_id);"
"CREATE UNIQUE INDEX message_property_index4 ON message_properties(message_id, proptag);"
"CREATE INDEX proptag_propval_index4 ON message_properties(proptag, propval);";

static constexpr char tbl_msgprops_move4[] =
"INSERT INTO message_properties SELECT message_id, proptag, propval FROM u0";

static constexpr char tbl_msgchgs_0[] =
"CREATE TABLE message_changes ("
"  message_id INTEGER NOT NULL,"
"  change_number INTEGER NOT NULL,"
"  indices BLOB NOT NULL,"
"  proptags BLOB NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_changes_index ON message_changes(message_id);";

static constexpr char tbl_rcpts_0[] =
"CREATE TABLE recipients ("
"  recipient_id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  message_id INTEGER NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_recipients_index ON recipients(message_id);";

static constexpr char tbl_rcptprops_0[] =
"CREATE TABLE recipients_properties ("
"  recipient_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval NONE NOT NULL,"
"  FOREIGN KEY (recipient_id) REFERENCES recipients (recipient_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX rid_properties_index ON recipients_properties(recipient_id);"
"CREATE UNIQUE INDEX recipient_property_index ON recipients_properties(recipient_id, proptag);";

static constexpr char tbl_rcptprops_5[] =
"CREATE TABLE recipients_properties ("
"  recipient_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval BLOB NOT NULL,"
"  FOREIGN KEY (recipient_id) REFERENCES recipients (recipient_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX rid_properties_index5 ON recipients_properties(recipient_id);"
"CREATE UNIQUE INDEX recipient_property_index5 ON recipients_properties(recipient_id, proptag);";

static constexpr char tbl_rcptprops_move5[] =
"INSERT INTO recipients_properties SELECT recipient_id, proptag, propval FROM u0";

static constexpr char tbl_attach_0[] =
"CREATE TABLE attachments ("
"  attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  message_id INTEGER NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_attachments_index ON attachments(message_id);";

static constexpr char tbl_atxprops_0[] =
"CREATE TABLE attachment_properties ("
"  attachment_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval NONE NOT NULL,"
"  FOREIGN KEY (attachment_id) REFERENCES attachments (attachment_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX attid_properties_index ON attachment_properties(attachment_id);"
"CREATE UNIQUE INDEX attachment_property_index ON attachment_properties(attachment_id, proptag);";

static constexpr char tbl_atxprops_6[] =
"CREATE TABLE attachment_properties ("
"  attachment_id INTEGER NOT NULL,"
"  proptag INTEGER NOT NULL,"
"  propval BLOB NOT NULL,"
"  FOREIGN KEY (attachment_id) REFERENCES attachments (attachment_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX attid_properties_index6 ON attachment_properties(attachment_id);"
"CREATE UNIQUE INDEX attachment_property_index6 ON attachment_properties(attachment_id, proptag);";

static constexpr char tbl_atxprops_move6[] =
"INSERT INTO attachment_properties SELECT attachment_id, proptag, propval FROM u0";

static constexpr char tbl_pvt_folders_0[] =
"CREATE TABLE folders ("
"  folder_id INTEGER PRIMARY KEY,"
"  parent_id INTEGER,"
"  change_number INTEGER UNIQUE NOT NULL,"
"  is_search INTEGER DEFAULT 0,"
"  search_flags INTEGER DEFAULT NULL,"
"  search_criteria BLOB DEFAULT NULL,"
"  cur_eid INTEGER NOT NULL,"
"  max_eid INTEGER NOT NULL,"
"  FOREIGN KEY (parent_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX search_index ON folders(is_search);";

static constexpr char tbl_pvt_folders_10[] =
"CREATE TABLE folders ("
"  folder_id INTEGER PRIMARY KEY,"
"  parent_id INTEGER,"
"  change_number INTEGER UNIQUE NOT NULL,"
"  is_search INTEGER DEFAULT 0,"
"  search_flags INTEGER DEFAULT NULL,"
"  search_criteria BLOB DEFAULT NULL,"
"  cur_eid INTEGER NOT NULL,"
"  max_eid INTEGER NOT NULL,"
"  `is_deleted` INTEGER DEFAULT 0,"
"  FOREIGN KEY (parent_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX search_index10 ON folders(is_search);";

static constexpr char tbl_pvt_folders_move10[] =
"INSERT INTO folders SELECT folder_id, parent_id, change_number, is_search, search_flags, search_criteria, cur_eid, max_eid, 0 AS is_deleted FROM u0";

static constexpr char tbl_pvt_msgs_0[] =
"CREATE TABLE messages ("
"  message_id INTEGER PRIMARY KEY,"
"  parent_fid INTEGER,"
"  parent_attid INTEGER,"
"  is_associated INTEGER,"
"  change_number INTEGER UNIQUE NOT NULL,"
"  read_cn INTEGER UNIQUE DEFAULT NULL,"
"  read_state INTEGER DEFAULT 0,"
"  message_size INTEGER NOT NULL,"
"  group_id INTEGER DEFAULT NULL,"
"  timer_id INTEGER DEFAULT NULL,"
"  mid_string TEXT DEFAULT NULL,"
"  FOREIGN KEY (parent_fid) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE,"
"  FOREIGN KEY (parent_attid) REFERENCES attachments (attachment_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX pid_messages_index ON messages(parent_fid);"
"CREATE INDEX attid_messages_index ON messages(parent_attid);"
"CREATE INDEX assoc_index ON messages(is_associated);"
"CREATE INDEX parent_assoc_index ON messages(parent_fid, is_associated);"
"CREATE INDEX parent_read_assoc_index ON messages(parent_fid, read_state, is_associated);";

static constexpr char tbl_pvt_msgs_8[] =
"CREATE TABLE messages ("
"  message_id INTEGER PRIMARY KEY,"
"  parent_fid INTEGER,"
"  parent_attid INTEGER,"
"  is_deleted INTEGER DEFAULT 0,"
"  is_associated INTEGER,"
"  change_number INTEGER UNIQUE NOT NULL,"
"  read_cn INTEGER UNIQUE DEFAULT NULL,"
"  read_state INTEGER DEFAULT 0,"
"  message_size INTEGER NOT NULL,"
"  group_id INTEGER DEFAULT NULL,"
"  timer_id INTEGER DEFAULT NULL,"
"  mid_string TEXT DEFAULT NULL,"
"  FOREIGN KEY (parent_fid) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE,"
"  FOREIGN KEY (parent_attid) REFERENCES attachments (attachment_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX pid_messages_index8 ON messages(parent_fid);"
"CREATE INDEX attid_messages_index8 ON messages(parent_attid);"
"CREATE INDEX assoc_index8 ON messages(is_associated);"
"CREATE INDEX parent_assoc_index8 ON messages(parent_fid, is_associated);"
"CREATE INDEX parent_read_assoc_index8 ON messages(parent_fid, read_state, is_associated);";

static constexpr char tbl_pvt_msgs_move8[] =
"INSERT INTO messages SELECT message_id, parent_fid, parent_attid, 0 AS is_deleted, is_associated, change_number, read_cn, read_state, message_size, group_id, timer_id, mid_string FROM u0";

static constexpr char tbl_pvt_recvfld_0[] =
"CREATE TABLE receive_table ("
"  class TEXT COLLATE NOCASE UNIQUE NOT NULL,"
"  folder_id INTEGER NOT NULL,"
"  modified_time INTEGER NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_receive_index ON receive_table(folder_id);";

static constexpr char tbl_pvt_searchscopes_0[] =
"CREATE TABLE search_scopes ("
"  folder_id INTEGER NOT NULL,"
"  included_fid INTEGER NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE,"
"  FOREIGN KEY (included_fid) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_scope_index ON search_scopes(folder_id);"
"CREATE INDEX included_scope_index ON search_scopes(included_fid);";

static constexpr char tbl_pvt_searchresult_0[] =
"CREATE TABLE search_result ("
"  folder_id INTEGER NOT NULL,"
"  message_id INTEGER NOT NULL,"
"  FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX fid_result_index ON search_result(folder_id);"
"CREATE INDEX mid_result_index ON search_result(message_id);"
"CREATE UNIQUE INDEX search_message_index ON search_result(folder_id, message_id);";

static constexpr char tbl_pub_folders_0[] =
"CREATE TABLE folders ("
"  folder_id INTEGER PRIMARY KEY,"
"  parent_id INTEGER,"
"  change_number INTEGER UNIQUE NOT NULL,"
"  is_deleted INTEGER DEFAULT 0,"
"  cur_eid INTEGER NOT NULL,"
"  max_eid INTEGER NOT NULL,"
"  FOREIGN KEY (parent_id) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX folder_delete_index ON folders(parent_id, is_deleted);";

static constexpr char tbl_pub_msgs_0[] =
"CREATE TABLE messages ("
"  message_id INTEGER PRIMARY KEY,"
"  parent_fid INTEGER,"
"  parent_attid INTEGER,"
"  is_deleted INTEGER DEFAULT 0,"
"  is_associated INTEGER,"
"  change_number INTEGER UNIQUE NOT NULL,"
"  message_size INTEGER NOT NULL,"
"  group_id INTEGER DEFAULT NULL,"
"  FOREIGN KEY (parent_fid) REFERENCES folders (folder_id) ON DELETE CASCADE ON UPDATE CASCADE,"
"  FOREIGN KEY (parent_attid) REFERENCES attachments (attachment_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX pid_messages_index ON messages(parent_fid);"
"CREATE INDEX attid_messages_index ON messages(parent_attid);"
"CREATE INDEX assoc_index ON messages(is_associated);"
"CREATE INDEX parent_assoc_delete_index ON messages(parent_fid, is_associated, is_deleted);";

static constexpr char tbl_pub_readst_0[] =
"CREATE TABLE read_states ("
"  message_id INTEGER NOT NULL,"
"  username TEXT COLLATE NOCASE NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_states_index ON read_states(message_id);"
"CREATE UNIQUE INDEX state_username_index ON read_states(message_id, username);";

static constexpr char tbl_pub_readcn_0[] =
"CREATE TABLE read_cns ("
"  message_id INTEGER NOT NULL,"
"  username TEXT COLLATE NOCASE NOT NULL,"
"  read_cn INTEGER UNIQUE NOT NULL,"
"  FOREIGN KEY (message_id) REFERENCES messages (message_id) ON DELETE CASCADE ON UPDATE CASCADE);"
"CREATE INDEX mid_readcn_index ON read_cns(message_id);"
"CREATE UNIQUE INDEX readcn_username_index ON read_cns(message_id, username);";

static constexpr char tbl_pub_replmap_0[] =
"CREATE TABLE replca_mapping ("
"  replid INTEGER PRIMARY KEY AUTOINCREMENT,"
"  replguid TEXT COLLATE NOCASE UNIQUE NOT NULL)";

static constexpr tbl_init tbl_pvt_init_0[] = {
	{"configurations", tbl_config_0},
	{"allocated_eids", tbl_alloc_eids_0},
	{"named_properties", tbl_namedprops_0},
	{"store_properties", tbl_storeprops_0},
	{"folder_properties", tbl_fldprops_0},
	{"permissions", tbl_perms_0},
	{"rules", tbl_rules_0},
	{"message_properties", tbl_msgprops_0},
	{"message_changes", tbl_msgchgs_0},
	{"recipients", tbl_rcpts_0},
	{"recipients_properties", tbl_rcptprops_0},
	{"attachments", tbl_attach_0},
	{"attachment_properties", tbl_atxprops_0},
	{"folders", tbl_pvt_folders_0},
	{"messages", tbl_pvt_msgs_0},
	{"receive_table", tbl_pvt_recvfld_0},
	{"search_scopes", tbl_pvt_searchscopes_0},
	{"search_result", tbl_pvt_searchresult_0},
	TABLE_END,
};

static constexpr tbl_init tbl_pvt_init_top[] = {
	{"configurations", tbl_config_1},
	{"allocated_eids", tbl_alloc_eids_0},
	{"named_properties", tbl_namedprops_0},
	{"store_properties", tbl_storeprops_2},
	{"folder_properties", tbl_fldprops_3},
	{"permissions", tbl_perms_0},
	{"rules", tbl_rules_0},
	{"message_properties", tbl_msgprops_4},
	{"message_changes", tbl_msgchgs_0},
	{"recipients", tbl_rcpts_0},
	{"recipients_properties", tbl_rcptprops_5},
	{"attachments", tbl_attach_0},
	{"attachment_properties", tbl_atxprops_6},
	{"folders", tbl_pvt_folders_10},
	{"messages", tbl_pvt_msgs_8},
	{"receive_table", tbl_pvt_recvfld_0},
	{"search_scopes", tbl_pvt_searchscopes_0},
	{"search_result", tbl_pvt_searchresult_0},
	TABLE_END,
};

static constexpr tbl_init tbl_pub_init_0[] = {
	{"configurations", tbl_config_0},
	{"allocated_eids", tbl_alloc_eids_0},
	{"named_properties", tbl_namedprops_0},
	{"store_properties", tbl_storeprops_0},
	{"folder_properties", tbl_fldprops_0},
	{"permissions", tbl_perms_0},
	{"rules", tbl_rules_0},
	{"message_properties", tbl_msgprops_0},
	{"message_changes", tbl_msgchgs_0},
	{"recipients", tbl_rcpts_0},
	{"recipients_properties", tbl_rcptprops_0},
	{"attachments", tbl_attach_0},
	{"attachment_properties", tbl_atxprops_0},
	{"folders", tbl_pub_folders_0},
	{"messages", tbl_pub_msgs_0},
	{"read_states", tbl_pub_readst_0},
	{"read_cns", tbl_pub_readcn_0},
	{"replca_mapping", tbl_pub_replmap_0},
	TABLE_END,
};

static constexpr tbl_init tbl_pub_init_top[] = {
	{"configurations", tbl_config_1},
	{"allocated_eids", tbl_alloc_eids_0},
	{"named_properties", tbl_namedprops_0},
	{"store_properties", tbl_storeprops_2},
	{"folder_properties", tbl_fldprops_3},
	{"permissions", tbl_perms_0},
	{"rules", tbl_rules_0},
	{"message_properties", tbl_msgprops_4},
	{"message_changes", tbl_msgchgs_0},
	{"recipients", tbl_rcpts_0},
	{"recipients_properties", tbl_rcptprops_5},
	{"attachments", tbl_attach_0},
	{"attachment_properties", tbl_atxprops_6},
	{"folders", tbl_pub_folders_0},
	{"messages", tbl_pub_msgs_0},
	{"read_states", tbl_pub_readst_0},
	{"read_cns", tbl_pub_readcn_0},
	{"replca_mapping", tbl_pub_replmap_0},
	TABLE_END,
};

static constexpr char tbl_midb_folders_0[] =
"CREATE TABLE folders ("
"  folder_id INTEGER PRIMARY KEY,"
"  parent_fid INTEGER NOT NULL,"
"  commit_max INTEGER NOT NULL,"
"  name TEXT NOT NULL UNIQUE,"
"  uidnext INTEGER DEFAULT 0,"
"  unsub INTEGER DEFAULT 0,"
"  sort_field INTEGER DEFAULT 0);"
"CREATE INDEX parent_fid_index ON folders(parent_fid);";

static constexpr char tbl_midb_msgs_0[] =
"CREATE TABLE messages ("
"  message_id INTEGER PRIMARY KEY,"
"  folder_id INTEGER NOT NULL,"
"  mid_string TEXT NOT NULL UNIQUE,"
"  idx INTEGER DEFAULT NULL,"
"  mod_time INTEGER DEFAULT 0,"
"  uid INTEGER NOT NULL,"
"  unsent INTEGER DEFAULT 0,"
"  recent INTEGER DEFAULT 1,"
"  read INTEGER DEFAULT 0,"
"  flagged INTEGER DEFAULT 0,"
"  replied INTEGER DEFAULT 0,"
"  forwarded INTEGER DEFAULT 0,"
"  deleted INTEGER DEFAULT 0,"
"  subject TEXT NOT NULL,"
"  sender TEXT NOT NULL,"
"  rcpt TEXT NOT NULL,"
"  size INTEGER NOT NULL,"
"  ext TEXT DEFAULT NULL," /* unused */
"  received INTEGER NOT NULL,"
"  FOREIGN KEY (folder_id)"
"  	REFERENCES folders (folder_id)"
"  	ON DELETE CASCADE"
"  	ON UPDATE CASCADE);"
"CREATE INDEX folder_id_index ON messages(folder_id);"
"CREATE INDEX fid_idx_index ON messages(folder_id, idx);"
"CREATE INDEX fid_recent_index ON messages(folder_id, recent);"
"CREATE INDEX fid_read_index ON messages(folder_id, read);"
"CREATE INDEX fid_received_index ON messages(folder_id, received);"
"CREATE INDEX fid_uid_index ON messages(folder_id, uid);"
"CREATE INDEX fid_flagged_index ON messages(folder_id, flagged);"
"CREATE INDEX fid_subject_index ON messages(folder_id, subject);"
"CREATE INDEX fid_from_index ON messages(folder_id, sender);"
"CREATE INDEX fid_rcpt_index ON messages(folder_id, rcpt);"
"CREATE INDEX fid_size_index ON messages(folder_id, size);";

static constexpr char tbl_midb_mapping_0[] =
"CREATE TABLE mapping ("
"  message_id INTEGER PRIMARY KEY,"
"  mid_string TEXT NOT NULL,"
"  flag_string TEXT)";

static constexpr tbl_init tbl_midb_init_0[] = {
	{"configurations", tbl_config_0},
	{"folders", tbl_midb_folders_0},
	{"messages", tbl_midb_msgs_0},
	{"mapping", tbl_midb_mapping_0},
	TABLE_END,
};

static constexpr tbl_init tbl_midb_init_top[] = {
	{"configurations", tbl_config_1},
	{"folders", tbl_midb_folders_0},
	{"messages", tbl_midb_msgs_0},
	{"mapping", tbl_midb_mapping_0},
	TABLE_END,
};

/*
 * Because sqlite does not support ALTER TABLE CHANGE COLUMN statements, we are
 * but left with recreating the entire table and issuing a move(copy) command.
 */
static constexpr tblite_upgradefn tbl_pvt_upgrade_list[] = {
	{1, nullptr, "configurations", tbl_config_1, tbl_config_move1},
	{2, nullptr, "store_properties", tbl_storeprops_2, tbl_storeprops_move2},
	{3, nullptr, "folder_properties", tbl_fldprops_3, tbl_fldprops_move3},
	{4, nullptr, "message_properties", tbl_msgprops_4, tbl_msgprops_move4},
	{5, nullptr, "recipients_properties", tbl_rcptprops_5, tbl_rcptprops_move5},
	{6, nullptr, "attachment_properties", tbl_atxprops_6, tbl_atxprops_move6},
	/*
	 * Some AAPI versions generated schema 0 databases with a
	 * messages.is_deleted and/or folders.is_deleted column. Some
	 * dbop_sqlite versions generated schema 7 databases without a
	 * messages.is_deleted column. Make it right.
	 */
	{8, nullptr, "messages", tbl_pvt_msgs_8, tbl_pvt_msgs_move8},
	{10, nullptr, "folders", tbl_pvt_folders_10, tbl_pvt_folders_move10},
	TABLE_END,
};

static constexpr tblite_upgradefn tbl_pub_upgrade_list[] = {
	{1, nullptr, "configurations", tbl_config_1, tbl_config_move1},
	{2, nullptr, "store_properties", tbl_storeprops_2, tbl_storeprops_move2},
	{3, nullptr, "folder_properties", tbl_fldprops_3, tbl_fldprops_move3},
	{4, nullptr, "message_properties", tbl_msgprops_4, tbl_msgprops_move4},
	{5, nullptr, "recipients_properties", tbl_rcptprops_5, tbl_rcptprops_move5},
	{6, nullptr, "attachment_properties", tbl_atxprops_6, tbl_atxprops_move6},
	TABLE_END,
};

static constexpr tblite_upgradefn tbl_midb_upgrade_list[] = {
	{1, nullptr, "configurations", tbl_config_1, tbl_config_move1},
	TABLE_END,
};

static char kind_to_char(sqlite_kind k)
{
	switch (k) {
	case sqlite_kind::pvt: return 'V';
	case sqlite_kind::pub: return 'B';
	case sqlite_kind::midb: return 'M';
	default: return 0;
	}
}

static int dbop_sqlite_bump(sqlite3 *db, unsigned int version) try
{
	auto qstr = fmt::format("REPLACE INTO `configurations` "
	            "(`config_id`,`config_value`) VALUES (10,{})", version);
	return gx_sql_exec(db, qstr.c_str()) == SQLITE_OK ? 0 : -EINVAL;
} catch (const std::bad_alloc &) {
	return -ENOMEM;
}

static int dbop_sqlite_create_int(sqlite3 *db, const struct tbl_init *entry,
    unsigned int flags)
{
	for (; entry->name != nullptr; ++entry) {
		if (flags & DBOP_VERBOSE)
			mlog(LV_NOTICE, "dbop_sqlite: Creating table \"%s\"", entry->name);
		auto ret = gx_sql_exec(db, entry->command);
		if (ret != SQLITE_OK)
			return -1;
	}
	return 0;
}

int dbop_sqlite_create(sqlite3 *db, sqlite_kind k, unsigned int flags)
{
	bool s0 = flags & DBOP_SCHEMA_0;
	const tbl_init *tbl = nullptr;
	switch (k) {
	case sqlite_kind::pvt:
		tbl = s0 ? tbl_pvt_init_0 : tbl_pvt_init_top;
		break;
	case sqlite_kind::pub:
		tbl = s0 ? tbl_pub_init_0 : tbl_pub_init_top;
		break;
	case sqlite_kind::midb:
		tbl = s0 ? tbl_midb_init_0 : tbl_midb_init_top;
		break;
	default:
		return -EINVAL;
	}
	auto ret = dbop_sqlite_create_int(db, tbl, flags);
	if (ret != 0)
		return ret;
	return dbop_sqlite_bump(db, s0 ? 0 : dbop_sqlite_recentversion(k));
}

int dbop_sqlite_recentversion(sqlite_kind k)
{
	switch (k) {
	case sqlite_kind::pvt: return tbl_pvt_upgrade_list[std::size(tbl_pvt_upgrade_list)-2].v;
	case sqlite_kind::pub: return tbl_pub_upgrade_list[std::size(tbl_pub_upgrade_list)-2].v;
	case sqlite_kind::midb: return tbl_midb_upgrade_list[std::size(tbl_midb_upgrade_list)-2].v;
	default: return 0;
	}
}

int dbop_sqlite_schemaversion(sqlite3 *db, sqlite_kind)
{
	const char q[] = "SELECT `config_value` FROM `configurations` "
	                 "WHERE `config_id`=10"; /* CONFIG_ID_SCHEMAVERSION */
	auto stm = gx_sql_prep(db, q);
	if (stm == nullptr)
		return -1;
	auto ret = stm.step();
	if (ret == SQLITE_DONE)
		return 0; /* first version */
	else if (ret != SQLITE_ROW)
		return -1;
	return stm.col_uint64(0);
}

static int dbop_sqlite_chcol(sqlite3 *db, const tblite_upgradefn *entry)
{
	auto qstr = fmt::format("ALTER TABLE `{}` RENAME TO `u0`", entry->tbl_name);
	if (gx_sql_exec(db, qstr.c_str()) != SQLITE_OK ||
	    gx_sql_exec(db, entry->q_create) != SQLITE_OK ||
	    gx_sql_exec(db, entry->q_move) != SQLITE_OK ||
	    gx_sql_exec(db, "DROP TABLE `u0`") != SQLITE_OK)
		return -EIO;
	return 0;
}

ssize_t dbop_sqlite_integcheck(sqlite3 *db, int loglevel)
{
	auto stm = gx_sql_prep(db, "PRAGMA integrity_check");
	if (stm == nullptr)
		return -1;
	ssize_t errors = 0;
	int ret;
	while ((ret = stm.step()) == SQLITE_ROW) {
		if (errors < SSIZE_MAX)
			++errors;
		if (errors == 1 && strcmp(stm.col_text(0), "ok") == 0)
			errors = 0;
		else if (loglevel >= 0)
			mlog(loglevel, "%s", stm.col_text(0));
	}
	return errors;
}

int dbop_sqlite_upgrade(sqlite3 *db, const char *filedesc,
    sqlite_kind kind, unsigned int flags)
{
	bool did_chcol = false;
	auto current = dbop_sqlite_schemaversion(db, kind);
	if (current < 0)
		return -EIO;
	const tblite_upgradefn *entry = nullptr;
	switch (kind) {
	case sqlite_kind::pub: entry = tbl_pub_upgrade_list; break;
	case sqlite_kind::pvt: entry = tbl_pvt_upgrade_list; break;
	case sqlite_kind::midb: entry = tbl_midb_upgrade_list; break;
	default: return -EINVAL;
	}
	while (entry->v <= static_cast<unsigned int>(current) && entry->v != 0)
		++entry;
	if (entry->v == 0)
		/* Already recent */
		return 0;
	auto errors = dbop_sqlite_integcheck(db, LV_ERR);
	if (errors != 0) {
		mlog(LV_ERR, "Upgrade of %s not started because of %zd integrity problems"
			" <https://docs.grommunio.com/kb/sqlite.html>",
			filedesc, errors);
		return -EIO;
	}

	if (gx_sql_exec(db, "PRAGMA foreign_keys=OFF") != SQLITE_OK ||
	    gx_sql_exec(db, "PRAGMA legacy_alter_table=ON") != SQLITE_OK)
		return -EIO;
	for (; entry->v != 0; ++entry) {
		if (flags & DBOP_VERBOSE)
			mlog(LV_NOTICE, "dbop_sqlite: upgrading %s to schema E%c-%u",
			        filedesc, kind_to_char(kind), entry->v);
		auto tx = gx_sql_begin_trans(db);
		if (!tx)
			return -EIO;
		if (entry->command != nullptr && entry->tbl_name == nullptr &&
		    entry->q_create == nullptr && entry->q_move == nullptr) {
			auto ret = gx_sql_exec(db, entry->command);
			if (ret != SQLITE_OK)
				return -EIO;
		} else if (entry->command == nullptr &&
		    entry->tbl_name != nullptr && entry->q_create != nullptr &&
		    entry->q_move != nullptr) {
			auto ret = dbop_sqlite_chcol(db, entry);
			if (ret < 0)
				return ret;
			did_chcol = true;
		} else {
			mlog(LV_ERR, "dbop_sqlite: malformed entry in upgrade table, sv %u", entry->v);
			return -EINVAL;
		}
		if (dbop_sqlite_bump(db, entry->v) != 0 || tx.commit() != 0)
			return -EIO;
	}
	/* Reclaim some diskspace */
	if (did_chcol && gx_sql_exec(db, "VACUUM") != SQLITE_OK)
		/* ignore */;

	if (gx_sql_exec(db, "PRAGMA foreign_keys=ON") != SQLITE_OK ||
	    gx_sql_exec(db, "PRAGMA legacy_alter_table=OFF") != SQLITE_OK)
		return -EIO;
	return 0;
}

}
