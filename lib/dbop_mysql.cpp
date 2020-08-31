/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mysql.h>
#include <gromox/database.h>
#include <gromox/dbop.h>

using namespace gromox;

struct tbl_init {
	const char *name, *command;
};

struct tbl_upgradefn {
	unsigned int v;
	const char *command;
};

/* Initialization to create schema 0 */
static const char tbl_alias_0[] =
"CREATE TABLE `aliases` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `aliasname` varchar(128) NOT NULL,"
"  `mainname` varchar(128) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `aliasname` (`aliasname`),"
"  KEY `mainname` (`mainname`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_assoc_0[] =
"CREATE TABLE `associations` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `list_id_2` (`list_id`,`username`),"
"  KEY `username` (`username`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_classes_0[] =
"CREATE TABLE `classes` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `classname` varchar(128) NOT NULL,"
"  `listname` varchar(128) DEFAULT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `listname` (`listname`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `group_id` (`group_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_domains_0[] =
"CREATE TABLE `domains` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `org_id` int(10) unsigned NOT NULL DEFAULT 0,"
"  `domainname` varchar(64) NOT NULL,"
"  `password` varchar(40) NOT NULL DEFAULT '',"
"  `homedir` varchar(128) NOT NULL DEFAULT '',"
"  `media` varchar(64) NOT NULL DEFAULT '',"
"  `max_size` int(10) unsigned NOT NULL,"
"  `max_user` int(10) unsigned NOT NULL,"
"  `title` varchar(128) NOT NULL DEFAULT '',"
"  `address` varchar(128) NOT NULL DEFAULT '',"
"  `admin_name` varchar(32) NOT NULL DEFAULT '',"
"  `tel` varchar(64) NOT NULL DEFAULT '',"
"  `create_day` date NOT NULL,"
"  `end_day` date NOT NULL,"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `domain_status` tinyint(4) NOT NULL DEFAULT 0,"
"  `domain_type` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `domainname` (`domainname`),"
"  KEY `homedir` (`homedir`,`domain_type`),"
"  KEY `org_id` (`org_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_forwards_0[] =
"CREATE TABLE `forwards` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `forward_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `destination` varchar(128) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_groups_0[] =
"CREATE TABLE `groups` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `groupname` varchar(128) NOT NULL,"
"  `password` varchar(40) NOT NULL DEFAULT '',"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `max_size` int(10) unsigned NOT NULL,"
"  `max_user` int(10) unsigned NOT NULL,"
"  `title` varchar(128) NOT NULL,"
"  `create_day` date NOT NULL,"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `group_status` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `groupname` (`groupname`),"
"  KEY `domain_id` (`domain_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_hierarchy_0[] =
"CREATE TABLE `hierarchy` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `class_id` int(10) unsigned NOT NULL,"
"  `child_id` int(10) unsigned NOT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `class_id` (`class_id`),"
"  KEY `child_id` (`child_id`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `group_id` (`group_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_members_0[] =
"CREATE TABLE `members` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `class_id` int(10) unsigned NOT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `class_id_2` (`class_id`,`username`),"
"  KEY `username` (`username`),"
"  KEY `class_id` (`class_id`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `group_id` (`group_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_mlists_0[] =
"CREATE TABLE `mlists` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `listname` varchar(128) NOT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `list_type` tinyint(4) NOT NULL,"
"  `list_privilege` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `listname` (`listname`),"
"  KEY `domain_id` (`domain_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_orgs_0[] =
"CREATE TABLE `orgs` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `memo` varchar(128) NOT NULL DEFAULT '',"
"  PRIMARY KEY (`id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_specifieds_0[] =
"CREATE TABLE `specifieds` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_users_0[] =
"CREATE TABLE `users` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `password` varchar(40) NOT NULL DEFAULT '',"
"  `real_name` varchar(32) NOT NULL DEFAULT '',"
"  `title` varchar(128) NOT NULL DEFAULT '',"
"  `memo` varchar(128) NOT NULL DEFAULT '',"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  `maildir` varchar(128) NOT NULL DEFAULT '',"
"  `max_size` int(10) unsigned NOT NULL,"
"  `max_file` int(10) unsigned NOT NULL,"
"  `create_day` date NOT NULL,"
"  `lang` varchar(32) NOT NULL DEFAULT '',"
"  `timezone` varchar(64) NOT NULL DEFAULT '',"
"  `mobile_phone` varchar(20) NOT NULL DEFAULT '',"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `sub_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `address_status` tinyint(4) NOT NULL DEFAULT 0,"
"  `address_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `cell` varchar(20) NOT NULL DEFAULT '',"
"  `tel` varchar(20) NOT NULL DEFAULT '',"
"  `nickname` varchar(32) NOT NULL DEFAULT '',"
"  `homeaddress` varchar(128) NOT NULL DEFAULT '',"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`),"
"  UNIQUE KEY `domain_id_2` (`domain_id`,`username`),"
"  UNIQUE KEY `group_id_2` (`group_id`,`username`),"
"  KEY `group_id` (`group_id`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `maildir` (`maildir`,`address_type`)"
") DEFAULT CHARSET=utf8mb4";

static const struct tbl_init tbl_init_0[] = {
	{"aliases", tbl_alias_0},
	{"associations", tbl_assoc_0},
	{"classes", tbl_classes_0},
	{"domains", tbl_domains_0},
	{"forwards", tbl_forwards_0},
	{"groups", tbl_groups_0},
	{"hierarchy", tbl_hierarchy_0},
	{"members", tbl_members_0},
	{"mlists", tbl_mlists_0},
	{"orgs", tbl_orgs_0},
	{"specifieds", tbl_specifieds_0},
	{"users", tbl_users_0},
	{nullptr},
};

static int dbop_mysql_create_int(MYSQL *conn, const struct tbl_init *entry)
{
	for (; entry->name != nullptr; ++entry) {
		printf("Creating %s", entry->name);
		auto ret = mysql_real_query(conn, entry->command, strlen(entry->command));
		if (ret != 0) {
			printf(": %s\n", mysql_error(conn));
			return EXIT_FAILURE;
		}
		printf("\n");
	}
	return EXIT_SUCCESS;
}

int dbop_mysql_create_0(MYSQL *conn)
{
	return dbop_mysql_create_int(conn, tbl_init_0);
}

/* Initialization to create most recent schema */
static const char tbl_alias_top[] =
"CREATE TABLE `aliases` ("
"  `aliasname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `mainname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`aliasname`),"
"  KEY `mainname` (`mainname`)"
"  CONSTRAINT `aliases_ibfk_1` FOREIGN KEY (`mainname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_assoc_top[] =
"CREATE TABLE `associations` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `list_id_2` (`list_id`,`username`),"
"  KEY `username` (`username`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_classes_top[] =
"CREATE TABLE `classes` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `classname` varchar(128) NOT NULL,"
"  `listname` varchar(320) CHARACTER SET ascii DEFAULT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `listname` (`listname`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `group_id` (`group_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_domains_top[] =
"CREATE TABLE `domains` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `org_id` int(10) unsigned NOT NULL DEFAULT 0,"
"  `domainname` varchar(255) CHARACTER SET ascii NOT NULL,"
"  `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT '',"
"  `homedir` varchar(128) NOT NULL DEFAULT '',"
"  `media` varchar(64) NOT NULL DEFAULT '',"
"  `max_size` int(10) unsigned NOT NULL,"
"  `max_user` int(10) unsigned NOT NULL,"
"  `title` varchar(128) NOT NULL DEFAULT '',"
"  `address` varchar(128) NOT NULL DEFAULT '',"
"  `admin_name` varchar(32) NOT NULL DEFAULT '',"
"  `tel` varchar(64) NOT NULL DEFAULT '',"
"  `create_day` date NOT NULL,"
"  `end_day` date NOT NULL,"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `domain_status` tinyint(4) NOT NULL DEFAULT 0,"
"  `domain_type` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `domainname` (`domainname`),"
"  KEY `homedir` (`homedir`,`domain_type`),"
"  KEY `org_id` (`org_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_forwards_top[] =
"CREATE TABLE `forwards` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `forward_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `destination` varchar(320) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_groups_top[] =
"CREATE TABLE `groups` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `groupname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT '',"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `max_size` int(10) unsigned NOT NULL,"
"  `max_user` int(10) unsigned NOT NULL,"
"  `title` varchar(128) NOT NULL,"
"  `create_day` date NOT NULL,"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `group_status` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `groupname` (`groupname`),"
"  KEY `domain_id` (`domain_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_members_top[] =
"CREATE TABLE `members` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `class_id` int(10) unsigned NOT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `class_id_2` (`class_id`,`username`),"
"  KEY `username` (`username`),"
"  KEY `class_id` (`class_id`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `group_id` (`group_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_mlists_top[] =
"CREATE TABLE `mlists` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `listname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `list_type` tinyint(4) NOT NULL,"
"  `list_privilege` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `listname` (`listname`),"
"  KEY `domain_id` (`domain_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_specifieds_top[] =
"CREATE TABLE `specifieds` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static const char tbl_users_top[] =
"CREATE TABLE `users` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT '',"
"  `real_name` varchar(32) NOT NULL DEFAULT '',"
"  `title` varchar(128) NOT NULL DEFAULT '',"
"  `memo` varchar(128) NOT NULL DEFAULT '',"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
"  `maildir` varchar(128) NOT NULL DEFAULT '',"
"  `max_size` int(10) unsigned NOT NULL,"
"  `max_file` int(10) unsigned NOT NULL,"
"  `create_day` date NOT NULL,"
"  `lang` varchar(32) NOT NULL DEFAULT '',"
"  `timezone` varchar(64) NOT NULL DEFAULT '',"
"  `mobile_phone` varchar(20) NOT NULL DEFAULT '',"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `sub_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `address_status` tinyint(4) NOT NULL DEFAULT 0,"
"  `address_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `cell` varchar(20) NOT NULL DEFAULT '',"
"  `tel` varchar(20) NOT NULL DEFAULT '',"
"  `nickname` varchar(32) NOT NULL DEFAULT '',"
"  `homeaddress` varchar(128) NOT NULL DEFAULT '',"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`),"
"  UNIQUE KEY `domain_id_2` (`domain_id`,`username`),"
"  UNIQUE KEY `group_id_2` (`group_id`,`username`),"
"  KEY `group_id` (`group_id`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `maildir` (`maildir`,`address_type`)"
") DEFAULT CHARSET=utf8mb4";

static const struct tbl_init tbl_init_top[] = {
	{"associations", tbl_assoc_top},
	{"classes", tbl_classes_top},
	{"domains", tbl_domains_top},
	{"forwards", tbl_forwards_top},
	{"groups", tbl_groups_top},
	{"hierarchy", tbl_hierarchy_0},
	{"members", tbl_members_top},
	{"mlists", tbl_mlists_top},
	{"orgs", tbl_orgs_0},
	{"specifieds", tbl_specifieds_top},
	{"users", tbl_users_top},
	{"aliases", tbl_alias_top},
	{nullptr},
};

int dbop_mysql_create_top(MYSQL *conn)
{
	return dbop_mysql_create_int(conn, tbl_init_top);
}

/* Upgrade phases */
unsigned int dbop_mysql_schemaversion(MYSQL *conn)
{
	const char q[] = "SELECT `value` FROM `options` WHERE `key`='schemaversion'";
	if (mysql_real_query(conn, q, strlen(q)) != 0)
		return 0;
	DB_RESULT res(conn, mysql_store_result(conn));
	if (res == nullptr)
		abort();
	auto row = res.fetch_row();
	if (row == nullptr)
		return 0;
	return strtoul(row[0], nullptr, 0);
}

static const struct tbl_upgradefn tbl_upgrade_list[] = {
	{1, "CREATE TABLE `options` (`key` varchar(32) CHARACTER SET ascii NOT NULL,"
	    " `value` varchar(255) DEFAULT NULL, PRIMARY KEY (`key`)) DEFAULT CHARSET=utf8mb4"},
	{2, "ALTER TABLE `aliases` CHANGE COLUMN `aliasname` `aliasname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{3, "ALTER TABLE `aliases` CHANGE COLUMN `mainname` `mainname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{4, "ALTER TABLE `associations` CHANGE COLUMN `username` `username` varchar(320) CHARACTER SET ascii NOT NULL"},
	{6, "ALTER TABLE `classes` CHANGE COLUMN `listname` `listname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{7, "ALTER TABLE `domains` CHANGE COLUMN `domainname` `domainname` varchar(255) CHARACTER SET ascii NOT NULL"},
	{8, "ALTER TABLE `forwards` CHANGE COLUMN `username` `username` varchar(320) CHARACTER SET ascii NOT NULL"},
	{9, "ALTER TABLE `forwards` CHANGE COLUMN `destination` `destination` varchar(320) CHARACTER SET ascii NOT NULL"},
	{10, "ALTER TABLE `groups` CHANGE COLUMN `groupname` `groupname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{11, "ALTER TABLE `members` CHANGE COLUMN `username` `username` varchar(320) CHARACTER SET ascii NOT NULL"},
	{12, "ALTER TABLE `mlists` CHANGE COLUMN `listname` `listname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{13, "ALTER TABLE `specifieds` CHANGE COLUMN `username` `username` varchar(320) CHARACTER SET ascii NOT NULL"},
	{14, "ALTER TABLE `users` CHANGE COLUMN `username` `username` varchar(320) CHARACTER SET ascii NOT NULL"},
	{15, "ALTER TABLE `domains` CHANGE COLUMN `password` `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT ''"},
	{16, "ALTER TABLE `groups` CHANGE COLUMN `password` `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT ''"},
	{17, "ALTER TABLE `users` CHANGE COLUMN `password` `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT ''"},
	{18, "ALTER TABLE `aliases` DROP COLUMN `id`"},
	{19, "ALTER TABLE `aliases` ADD PRIMARY KEY (`aliasname`)"},
	{20, "ALTER TABLE `aliases` DROP INDEX `aliasname`"},
	{21, "ALTER TABLE `aliases` ADD CONSTRAINT `aliases_ibfk_1` FOREIGN KEY (`mainname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"},
	{0, nullptr},
};

int dbop_mysql_upgrade(MYSQL *conn)
{
	unsigned int current = dbop_mysql_schemaversion(conn);
	printf("Current schema n%u\n", current);

	auto *entry = tbl_upgrade_list;
	while (entry->v <= current && entry->v != 0)
		++entry;

	for (; entry->v != 0; ++entry) {
		printf("Upgrading schema to n%u\n", entry->v);
		auto ret = mysql_real_query(conn, entry->command, strlen(entry->command));
		if (ret != 0) {
			printf("\"%s\": %s\n", entry->command, mysql_error(conn));
			return EXIT_FAILURE;
		}
		char uq[72];
		if (entry->v == 1)
			snprintf(uq, sizeof(uq), "INSERT INTO `options` VALUES ('schemaversion', %u)", entry->v);
		else
			snprintf(uq, sizeof(uq), "UPDATE `options` SET `value`=%u WHERE `key`='schemaversion'", entry->v);
		ret = mysql_real_query(conn, uq, strlen(uq));
		if (ret != 0) {
			printf("\"%s\": %s\n", uq, mysql_error(conn));
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}
