// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mysql.h>
#include <gromox/database_mysql.hpp>
#include <gromox/dbop.h>
#include <gromox/util.hpp>
/*
 * Notes:
 *  - In case of new tables, edit ``tbl_init_top`` as well
 *    and run ``gromox-dbop -C``.
 */
using namespace gromox;

namespace {

struct tbl_init {
	const char *name, *command;
};

struct tbl_upgradefn {
	unsigned int v;
	const char *command;
};

}

namespace gromox {

/* If you are thinking about changing any tbl_XXX_N, with N=number, then you should rather add tbl_XXX_top. */
static constexpr char tbl_options_1[] =
"CREATE TABLE `options` ("
"  `key` varchar(32) CHARACTER SET ascii NOT NULL,"
"  `value` varchar(255) DEFAULT NULL,"
"  PRIMARY KEY (`key`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_uprops_25[] =
"CREATE TABLE `user_properties` ("
"  `user_id` int(10) unsigned NOT NULL,"
"  `proptag` int(10) unsigned NOT NULL,"
"  `propval_bin` varbinary(4096) DEFAULT NULL,"
"  `propval_str` varchar(4096) DEFAULT NULL,"
"  PRIMARY KEY (`user_id`,`proptag`),"
"  CONSTRAINT `user_properties_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_admroles_41[] =
"CREATE TABLE `admin_roles` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `name` varchar(32) NOT NULL,"
"  `description` varchar(256) DEFAULT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `name` (`name`)"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_admroleperm_42[] =
"CREATE TABLE `admin_role_permission_relation` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `role_id` int(10) unsigned NOT NULL,"
"  `permission` varchar(64) NOT NULL,"
"  `parameters` text,"
"  PRIMARY KEY (`id`),"
"  KEY `role_id` (`role_id`),"
"  CONSTRAINT `admin_role_permission_relation_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `admin_roles` (`id`)"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_admuserrole_43[] =
"CREATE TABLE `admin_user_role_relation` ("
"  `user_id` int(10) unsigned NOT NULL,"
"  `role_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`user_id`,`role_id`),"
"  CONSTRAINT `admin_user_role_relation_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,"
"  CONSTRAINT `admin_user_role_relation_ibfk_2` FOREIGN KEY (`role_id`) REFERENCES `admin_roles` (`id`)"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

/* Initialization to create schema 0 */
static constexpr char tbl_alias_0[] =
"CREATE TABLE `aliases` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `aliasname` varchar(128) NOT NULL,"
"  `mainname` varchar(128) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `aliasname` (`aliasname`),"
"  KEY `mainname` (`mainname`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_assoc_0[] =
"CREATE TABLE `associations` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `list_id_2` (`list_id`,`username`),"
"  KEY `username` (`username`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_classes_0[] =
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

static constexpr char tbl_configs_71[] =
"CREATE TABLE `configs` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `service` varchar(200) NOT NULL,"
"  `file` varchar(200) NOT NULL,"
"  `key` varchar(200) NOT NULL,"
"  `value` varchar(255) NOT NULL DEFAULT '',"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `path` (`service`,`file`,`key`),"
"  KEY `service` (`service`),"
"  KEY `file` (`file`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_domains_0[] =
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

static constexpr char tbl_fetchmail_75[] =
"CREATE TABLE `fetchmail` ("
"  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,"
"  `user_id` int(10) unsigned NOT NULL,"
"  `mailbox` varchar(320) NOT NULL,"
"  `active` tinyint(1) unsigned NOT NULL DEFAULT '1',"
"  `src_server` varchar(255) NOT NULL,"
"  `src_auth` enum('password','kerberos_v5','kerberos','kerberos_v4','gssapi','cram-md5','otp','ntlm','msn','ssh','any') NOT NULL DEFAULT 'password',"
"  `src_user` varchar(255) NOT NULL,"
"  `src_password` varchar(255) NOT NULL,"
"  `src_folder` varchar(255) NOT NULL,"
"  `fetchall` tinyint(1) unsigned NOT NULL DEFAULT '0',"
"  `keep` tinyint(1) unsigned NOT NULL DEFAULT '1',"
"  `protocol` enum('POP3','IMAP','POP2','ETRN','AUTO') NOT NULL DEFAULT 'IMAP',"
"  `usessl` tinyint(1) unsigned NOT NULL DEFAULT '1',"
"  `sslcertck` tinyint(1) unsigned NOT NULL DEFAULT '0',"
"  `sslcertpath` varchar(255) CHARACTER SET utf8 DEFAULT NULL,"
"  `sslfingerprint` varchar(255) CHARACTER SET latin1 DEFAULT NULL,"
"  `extra_options` text,"
"  `date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
"  PRIMARY KEY (`id`),"
"  KEY `fetchmail_ibfk_1` (`user_id`),"
"  CONSTRAINT `fetchmail_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
")";

static constexpr char tbl_forwards_0[] =
"CREATE TABLE `forwards` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `forward_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `destination` varchar(128) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_groups_0[] =
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

static constexpr char tbl_hierarchy_0[] =
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

static constexpr char tbl_members_0[] =
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

static constexpr char tbl_mlists_0[] =
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

static constexpr char tbl_orgs_0[] =
"CREATE TABLE `orgs` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `memo` varchar(128) NOT NULL DEFAULT '',"
"  PRIMARY KEY (`id`)"
") DEFAULT CHARSET=utf8mb4";

/*
 * A table to facilitate faster lookup for Autodiscover. When an OXDISCO
 * request is made for primary@example.com, we want to know all the extra
 * (secondary) stores for which primary@ has (exact: _may_ have) permission.
 *
 * In other words, secondary_store_hints is the *reverse* of sqlite3 permission
 * tables.
 *
 * All secondary stores so found still need to be tested for actual permissions
 * before OXDISCO is allowed to return them.
 */
static constexpr char tbl_scndstore_91[] =
"CREATE TABLE `secondary_store_hints` ("
"  `primary` int(10) unsigned NOT NULL,"
"  `secondary` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`primary`,`secondary`),"
"  CONSTRAINT `users_ibfk_1` FOREIGN KEY (`primary`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,"
"  CONSTRAINT `users_ibfk_2` FOREIGN KEY (`secondary`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_specifieds_0[] =
"CREATE TABLE `specifieds` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(128) NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_users_0[] =
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

static constexpr char tbl_userdev_92[] =
"CREATE TABLE `user_devices` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `user_id` int(10) unsigned NOT NULL,"
"  `device_id` varchar(64) NOT NULL,"
"  `status` int(10) unsigned NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `user_device` (`user_id`,`device_id`),"
"  CONSTRAINT `user_devices_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_userdevhist_93[] =
"CREATE TABLE `user_device_history` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `user_device_id` int(10) unsigned NOT NULL,"
"  `time` timestamp NOT NULL DEFAULT current_timestamp(),"
"  `remote_ip` varchar(64) NOT NULL,"
"  `status` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `user_device_history_ibfk_1` (`user_device_id`),"
"  CONSTRAINT `user_device_history_ibfk_1` FOREIGN KEY (`user_device_id`) REFERENCES `user_devices` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_taskqueue_102[] =
"CREATE TABLE `tasq` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `command` varchar(16) NOT NULL,"
"  `state` tinyint(3) unsigned NOT NULL DEFAULT '0',"
"  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,"
"  `updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,"
"  `message` varchar(160) NOT NULL DEFAULT '',"
"  `access` text,"
"  `params` text,"
"  PRIMARY KEY (`id`),"
"  KEY `state` (`state`),"
"  KEY `updated` (`updated`)"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_servers_103[] =
"CREATE TABLE `servers` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `hostname` varchar(255) CHARACTER SET ascii NOT NULL,"
"  `extname` varchar(255) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`id`)"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_orgparam_109[] =
"CREATE TABLE `orgparam` ("
"  `org_id` int(10) unsigned NOT NULL,"
"  `key` varchar(32) CHARACTER SET ascii NOT NULL,"
"  `value` varchar(255),"
"  PRIMARY KEY (`org_id`, `key`),"
"  CONSTRAINT `orgparam_ibfk_1` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_altnames_129[] =
"CREATE TABLE `altnames` ("
"  `user_id` int(10) unsigned NOT NULL,"
"  `altname` varchar(320) NOT NULL,"
"  `magic` int(10) unsigned NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`user_id`, `altname`),"
"  UNIQUE KEY `altname` (`altname`),"
"  CONSTRAINT `altnames_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static constexpr struct tbl_init tbl_init_0[] = {
	{"aliases", tbl_alias_0},
	{"associations", tbl_assoc_0},
	{"classes", tbl_classes_0},
	{"domains", tbl_domains_0},
	{"forwards", tbl_forwards_0},
	{"groups", tbl_groups_0},
	{"hierarchy", tbl_hierarchy_0},
	{"members", tbl_members_0},
	{"orgs", tbl_orgs_0},
	{"specifieds", tbl_specifieds_0},
	{"users", tbl_users_0},
	{"mlists", tbl_mlists_0},
	{nullptr},
};

static int dbop_mysql_create_int(MYSQL *conn, const struct tbl_init *entry)
{
	for (; entry->name != nullptr; ++entry) {
		mlog(LV_NOTICE, "dbop: Creating %s", entry->name);
		auto ret = mysql_real_query(conn, entry->command, strlen(entry->command));
		if (ret != 0) {
			mlog(LV_ERR, "dbop: Query \"%s\":", entry->command);
			mlog(LV_ERR, "dbop: %s", mysql_error(conn));
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int dbop_mysql_create_0(MYSQL *conn)
{
	return dbop_mysql_create_int(conn, tbl_init_0);
}

/* Initialization to create most recent schema */
static constexpr char tbl_alias_top[] =
"CREATE TABLE `aliases` ("
"  `aliasname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `mainname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`aliasname`),"
"  KEY `mainname` (`mainname`),"
"  CONSTRAINT `aliases_ibfk_1` FOREIGN KEY (`mainname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_assoc_top[] =
"CREATE TABLE `associations` ("
"  `list_id` int(10) NOT NULL,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`list_id`,`username`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_classes_top[] =
"CREATE TABLE `classes` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `classname` varchar(128) NOT NULL,"
"  `listname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `filters` TEXT,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `listname` (`listname`),"
"  CONSTRAINT `classes_ibfk_2` FOREIGN KEY (`listname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE,"
"  FOREIGN KEY (`domain_id`) REFERENCES domains (`id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_domains_top[] =
"CREATE TABLE `domains` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `org_id` int(10) unsigned NOT NULL DEFAULT 0,"
"  `domainname` varchar(255) CHARACTER SET ascii NOT NULL,"
"  `homeserver` tinyint(5) NOT NULL DEFAULT 0,"
"  `homedir` varchar(128) NOT NULL DEFAULT '',"
"  `max_user` int(10) unsigned NOT NULL,"
"  `title` varchar(128) NOT NULL DEFAULT '',"
"  `address` varchar(128) NOT NULL DEFAULT '',"
"  `admin_name` varchar(32) NOT NULL DEFAULT '',"
"  `tel` varchar(64) NOT NULL DEFAULT '',"
"  `end_day` date NOT NULL,"
"  `domain_status` tinyint(4) NOT NULL DEFAULT 0,"
"  `sync_policy` text CHARACTER SET ascii DEFAULT NULL,"
"  `chat_id` varchar(26) DEFAULT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `domainname` (`domainname`),"
"  KEY `homedir` (`homedir`),"
"  KEY `org_id` (`org_id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_forwards_top[] =
"CREATE TABLE `forwards` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `forward_type` tinyint(4) NOT NULL DEFAULT 0,"
"  `destination` varchar(320) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_groups_top[] =
"CREATE TABLE `groups` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `groupname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT '',"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `title` varchar(128) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `groupname` (`groupname`),"
"  KEY `domain_id` (`domain_id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_mlists_top[] =
"CREATE TABLE `mlists` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `listname` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `list_type` tinyint(4) NOT NULL,"
"  `list_privilege` tinyint(4) NOT NULL DEFAULT 0,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `listname` (`listname`),"
"  KEY `domain_id` (`domain_id`),"
"  CONSTRAINT `mlists_ibfk_1` FOREIGN KEY (`listname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_orgs_top[] =
"CREATE TABLE `orgs` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `name` varchar(32) NOT NULL,"
"  `description` varchar(128),"
"  PRIMARY KEY (`id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_servers_top[] =
"CREATE TABLE `servers` ("
"  `id` tinyint(5) unsigned NOT NULL AUTO_INCREMENT,"
"  `hostname` varchar(255) CHARACTER SET ascii NOT NULL,"
"  `extname` varchar(255) CHARACTER SET ascii NOT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `hostname` (`hostname`)"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_specifieds_top[] =
"CREATE TABLE `specifieds` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `list_id` int(10) NOT NULL,"
"  PRIMARY KEY (`id`),"
"  KEY `list_id` (`list_id`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_users_top[] =
"CREATE TABLE `users` ("
"  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,"
"  `username` varchar(320) CHARACTER SET ascii NOT NULL,"
"  `primary_email` varchar(320) CHARACTER SET ascii," // unused as of schema 110
"  `altname` varchar(64)," // unused as of schema 129
"  `password` varchar(136) CHARACTER SET ascii NOT NULL DEFAULT '',"
"  `domain_id` int(10) unsigned NOT NULL,"
"  `group_id` int(10) unsigned NOT NULL,"
   /*
    * exthost/inthost are unconstrained on purposes; don't want to lose the
    * association on so many users when the server entry disappears by accident
    */
"  `homeserver` tinyint(5) unsigned NOT NULL DEFAULT 0,"
"  `maildir` varchar(128) NOT NULL DEFAULT '',"
"  `lang` varchar(32) NOT NULL DEFAULT '',"
"  `timezone` varchar(64) NOT NULL DEFAULT '',"
"  `privilege_bits` int(10) unsigned NOT NULL,"
"  `address_status` tinyint(4) NOT NULL DEFAULT 0,"
"  `externid` varbinary(64) DEFAULT NULL,"
"  `sync_policy` text CHARACTER SET ascii DEFAULT NULL,"
"  `chat_id` varchar(26) DEFAULT NULL,"
"  PRIMARY KEY (`id`),"
"  UNIQUE KEY `username` (`username`),"
"  UNIQUE KEY `domain_id_2` (`domain_id`,`username`),"
"  UNIQUE KEY `group_id_2` (`group_id`,`username`),"
"  UNIQUE KEY `altname` (`altname`),"
"  KEY `group_id` (`group_id`),"
"  KEY `domain_id` (`domain_id`),"
"  KEY `maildir` (`maildir`)"
") DEFAULT CHARSET=utf8mb4";

static constexpr char tbl_uprops_top[] =
"CREATE TABLE `user_properties` ("
"  `user_id` int(10) unsigned NOT NULL,"
"  `proptag` int(10) unsigned NOT NULL,"
"  `order_id` int(10) unsigned DEFAULT 1,"
"  `propval_bin` varbinary(4096) DEFAULT NULL,"
"  `propval_str` varchar(4096) DEFAULT NULL,"
"  PRIMARY KEY (`user_id`,`proptag`,`order_id`),"
"  CONSTRAINT `user_properties_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE"
") DEFAULT CHARSET=utf8mb4";

static constexpr struct tbl_init tbl_init_top[] = {
	{"admin_roles", tbl_admroles_41},
	{"associations", tbl_assoc_top},
	{"configs", tbl_configs_71},
	{"domains", tbl_domains_top},
	{"forwards", tbl_forwards_top},
	{"groups", tbl_groups_top},
	{"options", tbl_options_1},
	{"orgs", tbl_orgs_top},
	{"specifieds", tbl_specifieds_top},
	{"users", tbl_users_top},
	{"aliases", tbl_alias_top},
	{"mlists", tbl_mlists_top},
	{"user_properties", tbl_uprops_top},
	{"admin_role_permission_relation", tbl_admroleperm_42},
	{"admin_user_role_relation", tbl_admuserrole_43},
	{"classes", tbl_classes_top},
	{"fetchmail", tbl_fetchmail_75},
	{"secondary_store_hints", tbl_scndstore_91},
	{"user_devices", tbl_userdev_92},
	{"user_device_history", tbl_userdevhist_93},
	{"task_queue", tbl_taskqueue_102},
	{"servers", tbl_servers_top},
	{"orgparam", tbl_orgparam_109},
	{"altnames", tbl_altnames_129},
	{nullptr},
};

int dbop_mysql_create_top(MYSQL *conn)
{
	auto ret = dbop_mysql_create_int(conn, tbl_init_top);
	if (ret != 0)
		return ret;
	char uq[80];
	snprintf(uq, sizeof(uq), "INSERT INTO `options` (`key`, `value`) VALUES ('schemaversion', %u)",
	         dbop_mysql_recentversion());
	ret = mysql_real_query(conn, uq, strlen(uq));
	if (ret != 0) {
		mlog(LV_ERR, "dbop: Query \"%s\":", uq);
		mlog(LV_ERR, "%s", mysql_error(conn));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/* Upgrade phases */
int dbop_mysql_schemaversion(MYSQL *conn)
{
	const char q[] = "SELECT `value` FROM `options` WHERE `key`='schemaversion'";
	if (mysql_real_query(conn, q, strlen(q)) != 0)
		/* Not an error - table did not exist in schema 0 yet. */
		return 0;
	DB_RESULT res(mysql_store_result(conn));
	if (res == nullptr)
		return -1;
	auto row = res.fetch_row();
	if (row == nullptr || row[0] == nullptr)
		return 0;
	return strtoul(row[0], nullptr, 0);
}

static constexpr tbl_upgradefn tbl_upgrade_list[] = {
	{1, "CREATE TABLE IF NOT EXISTS `options` (`key` varchar(32) CHARACTER SET ascii NOT NULL,"
	    " `value` varchar(255) DEFAULT NULL, PRIMARY KEY (`key`)) DEFAULT CHARSET=utf8mb4"},
	{2, "ALTER TABLE `aliases` CHANGE COLUMN `aliasname` `aliasname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{3, "ALTER TABLE `aliases` CHANGE COLUMN `mainname` `mainname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{4, "ALTER TABLE `associations` CHANGE COLUMN `username` `username` varchar(320) CHARACTER SET ascii NOT NULL"},
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
	{19, "ALTER TABLE `aliases` DROP INDEX `aliasname`"},
	{20, "ALTER TABLE `aliases` ADD PRIMARY KEY (`aliasname`)"},
	{21, "ALTER TABLE `aliases` ADD CONSTRAINT `aliases_ibfk_1` FOREIGN KEY (`mainname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"},
	/*
	 * n22: Domain-level aliases are no longer supported; just insert
	 * according user-level aliases entries into `aliases`. (This is also
	 * how it is done with LDAP-based DITs elsewhere.)
	 */
	{22, "DELETE FROM `domains` WHERE domain_type=1"},
	/*
	 * n23: Authentication through user-level aliases is no longer desired.
	 * (In LDAP DITs, such is not always supported either.)
	 */
	{23, "DELETE FROM `users` WHERE address_type=1"},
	/* Domain aliases, with no @, might have been stored in this table too(?) */
	{24, "DELETE FROM `aliases` WHERE aliasname NOT LIKE '%@%'"},
	{25, tbl_uprops_25},
	{26, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 979173407, `homeaddress` FROM `users` WHERE `homeaddress`!=''"}, /* PidTagHomeAddressStreet */
	{27, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 978255903, `nickname` FROM `users` WHERE `nickname`!=''"}, /* PidTagNickname */
	{28, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 973602847, `tel` FROM `users` WHERE `tel`!=''"}, /* PidTagBusinessTelephoneNumber */
	{29, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 974782495, `tel` FROM `users` WHERE `tel`!=''"}, /* PidTagPrimaryTelephoneNumber */
	{30, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 974913567, `cell` FROM `users` WHERE `cell`!=''"}, /* PidTagMobileTelephoneNumber */
	{31, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 805568543, `memo` FROM `users` WHERE `memo`!=''"}, /* PidTagComment */
	{32, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 974585887, `title` FROM `users` WHERE `title`!=''"}, /* PidTagTitle */
	{33, "INSERT INTO `user_properties` (`user_id`, `proptag`, `propval_str`) SELECT `id`, 805371935, `real_name` FROM `users` WHERE `real_name`!=''"}, /* PidTagDisplayName */
	{34, "ALTER TABLE `users` DROP COLUMN `homeaddress`"},
	{35, "ALTER TABLE `users` DROP COLUMN `nickname`"},
	{36, "ALTER TABLE `users` DROP COLUMN `tel`"},
	{37, "ALTER TABLE `users` DROP COLUMN `cell`"},
	{38, "ALTER TABLE `users` DROP COLUMN `memo`"},
	{39, "ALTER TABLE `users` DROP COLUMN `title`"},
	{40, "ALTER TABLE `users` DROP COLUMN `real_name`"},
	{41, tbl_admroles_41},
	{42, tbl_admroleperm_42},
	{43, tbl_admuserrole_43},
	{44, "ALTER TABLE `users` DROP COLUMN `mobile_phone`"}, /* was never used (cf. cell) */
	{45, "ALTER TABLE `users` DROP COLUMN `create_day`"},
	{46, "ALTER TABLE `domains` DROP COLUMN `create_day`"},
	{47, "ALTER TABLE `groups` DROP COLUMN `create_day`"},
	{48, "DELETE FROM `domains` WHERE domain_type!=0"},
	{49, "ALTER TABLE `domains` DROP COLUMN `domain_type`"},
	{50, "ALTER TABLE `domains` DROP COLUMN `password`"},
	{51, "ALTER TABLE `domains` DROP COLUMN `media`"},
	{52, "ALTER TABLE `domains` DROP COLUMN `max_size`"},
	{53, "ALTER TABLE `domains` DROP COLUMN `privilege_bits`"},
	{54, "ALTER TABLE `users` DROP COLUMN `max_file`"},
	{55, "ALTER TABLE `users` ADD COLUMN `externid` varbinary(64) DEFAULT NULL"},
	{56, "ALTER TABLE user_properties DROP CONSTRAINT user_properties_ibfk_1"},
	{57, "ALTER TABLE user_properties ADD CONSTRAINT user_properties_ibfk_1 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE"},
	{58, "ALTER TABLE `groups` DROP COLUMN `group_status`"},
	{59, "ALTER TABLE `groups` DROP COLUMN `privilege_bits`"},
	{60, "ALTER TABLE `groups` DROP COLUMN `max_user`"},
	{61, "ALTER TABLE `groups` DROP COLUMN `max_size`"},
	{62, "ALTER TABLE `hierarchy` DROP COLUMN `domain_id`"},
	{63, "ALTER TABLE `classes` DROP COLUMN `domain_id`"},
	{64, "ALTER TABLE `classes` DROP COLUMN `group_id`"},
	{65, "ALTER TABLE `members` DROP COLUMN `domain_id`"},
	{66, "ALTER TABLE `members` DROP COLUMN `group_id`"},
	{67, "ALTER TABLE `classes` ADD COLUMN `filters` TEXT"},
	{68, "TRUNCATE `classes`"},
	{69, "ALTER TABLE `classes` ADD COLUMN `domain_id` int(10) unsigned NOT NULL"},
	{70, "ALTER TABLE `classes` ADD CONSTRAINT FOREIGN KEY (`domain_id`) REFERENCES domains (`id`)"},
	{71, tbl_configs_71},
	{72, "ALTER TABLE `orgs` DROP COLUMN `memo`"},
	{73, "ALTER TABLE `orgs` ADD COLUMN `name` varchar(32) NOT NULL"},
	{74, "ALTER TABLE `orgs` ADD COLUMN `description` varchar(128)"},
	{75, tbl_fetchmail_75},
	{76, "ALTER TABLE `users` ADD COLUMN `sync_policy` text CHARACTER SET ascii DEFAULT NULL"},
	{77, "ALTER TABLE `domains` ADD COLUMN `sync_policy` text CHARACTER SET ascii DEFAULT NULL"},
	{78, "ALTER TABLE `users` ADD COLUMN `chat_id` varchar(26)"},
	{79, "ALTER TABLE `domains` ADD COLUMN `chat_id` varchar(26)"},
	{80, "ALTER TABLE `user_properties` ADD COLUMN `order_id` int(10) unsigned DEFAULT 1 AFTER `proptag`"},
	{81, "ALTER TABLE `user_properties` DROP PRIMARY KEY, ADD PRIMARY KEY (`user_id`, `proptag`, `order_id`)"},
	/* Upgrade addr_type to PR_DISPLAY_TYPE_EX=DT_xxx */
	{82, "INSERT IGNORE INTO user_properties (user_id, proptag, propval_str) SELECT u.id AS user_id, 956628995 AS proptag, 0 AS propval_str FROM users AS u WHERE u.address_type=0 AND u.sub_type=0"},
	{83, "INSERT IGNORE INTO user_properties (user_id, proptag, propval_str) SELECT u.id AS user_id, 956628995 AS proptag, 7 AS propval_str FROM users AS u WHERE u.address_type=0 AND u.sub_type=1"},
	{84, "INSERT IGNORE INTO user_properties (user_id, proptag, propval_str) SELECT u.id AS user_id, 956628995 AS proptag, 8 AS propval_str FROM users AS u WHERE u.address_type=0 AND u.sub_type=2"},
	{85, "INSERT IGNORE INTO user_properties (user_id, proptag, propval_str) SELECT u.id AS user_id, 956628995 AS proptag, 1 AS propval_str FROM users AS u WHERE u.address_type=2"},
	{86, "ALTER TABLE users DROP COLUMN sub_type"},
	{87, "ALTER TABLE users DROP COLUMN address_type"},
	{88, "ALTER TABLE `users` ADD COLUMN `primary_email` varchar(320) CHARACTER SET ascii AFTER `username`"},
	{89, "ALTER TABLE `users` ADD CONSTRAINT UNIQUE `primary_email` (`primary_email`)"},
	{90, "UPDATE `users` SET `primary_email`=`username`"},
	{91, tbl_scndstore_91},
	{92, tbl_userdev_92},
	{93, tbl_userdevhist_93},
	{94, "UPDATE `users` SET lang=\"zh_TW\" where lang=\"cn\""},
	{95, "UPDATE `users` SET lang=\"cs\" where lang=\"cz\""},
	{96, "UPDATE `users` SET lang=\"da\" where lang=\"dk\""},
	{97, "UPDATE `users` SET lang=\"ja\" where lang=\"jp\""},
	{98, "UPDATE `users` SET lang=\"nb\" where lang=\"no\""},
	{99, "UPDATE `users` SET lang=\"pt_BR\" where lang=\"pt\""},
	{100, "UPDATE `users` SET lang=\"sl\" where lang=\"si\""},
	{101, "UPDATE `users` SET lang=\"zh_CN\" where lang=\"zh\""},
	{102, tbl_taskqueue_102},
	{103, tbl_servers_103},
	{104, "ALTER TABLE `users` ADD COLUMN `homeserver` tinyint(5) unsigned NOT NULL DEFAULT 0 AFTER `group_id`"},
	{105, "ALTER TABLE `domains` ADD COLUMN `homeserver` tinyint(5) unsigned NOT NULL DEFAULT 0 AFTER `domainname`"},
	{106, "ALTER TABLE `servers` ADD CONSTRAINT UNIQUE `hostname` (`hostname`)"},
	{107, "ALTER TABLE `servers` CHANGE COLUMN `id` `id` tinyint(5) unsigned NOT NULL AUTO_INCREMENT"},
	/* 108: Fix up previous 107 (was: "DEFAULT 0") */
	{108, "ALTER TABLE `servers` CHANGE COLUMN `id` `id` tinyint(5) unsigned NOT NULL AUTO_INCREMENT"},
	{109, tbl_orgparam_109},
	{110, "ALTER TABLE `users` ADD COLUMN `altname` varchar(64) AFTER `primary_email`"},
	{111, "ALTER TABLE `users` ADD CONSTRAINT UNIQUE `altname` (`altname`)"},
	{112, "ALTER TABLE `users` DROP COLUMN `max_size`"},
	/* 113: Enforce constraint for 114 */
	{113, "DELETE `mlists` FROM `mlists` LEFT JOIN `users` ON `mlists`.`listname`=`users`.`username` WHERE `users`.`username` IS NULL"},
	{114, "ALTER TABLE `mlists` ADD CONSTRAINT `mlists_ibfk_1` FOREIGN KEY (`listname`) REFERENCES `users` (`username`)"},
	{115, "DROP TABLE `members`"},
	{117, "DROP TABLE `hierarchy`"},
	{118, "DELETE `classes` FROM `classes` LEFT JOIN `users` ON `classes`.`listname`=`users`.`username` WHERE `users`.`username` IS NULL"},
	{119, "ALTER TABLE `classes` CHANGE COLUMN `listname` `listname` varchar(320) CHARACTER SET ascii NOT NULL"},
	{120, "ALTER TABLE `classes` ADD CONSTRAINT `classes_ibfk_2` FOREIGN KEY (`listname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"},
	{121, "ALTER TABLE `mlists` DROP CONSTRAINT `mlists_ibfk_1`"},
	{122, "ALTER TABLE `mlists` ADD CONSTRAINT `mlists_ibfk_1` FOREIGN KEY (`listname`) REFERENCES `users` (`username`) ON DELETE CASCADE ON UPDATE CASCADE"},
	{123, "ALTER TABLE `associations` DROP INDEX `list_id`"},
	{124, "ALTER TABLE `associations` DROP INDEX `username`"},
	{125, "ALTER TABLE `associations` DROP COLUMN `id`"},
	{126, "ALTER TABLE `associations` MODIFY COLUMN `list_id` int(10) NOT NULL FIRST"},
	{127, "ALTER TABLE `associations` ADD PRIMARY KEY (`list_id`,`username`)"},
	{128, "ALTER TABLE `associations` DROP INDEX `list_id_2`"},
	{129, tbl_altnames_129},
	{130, "INSERT INTO altnames (SELECT id AS user_id, altname, 0 AS magic FROM users WHERE altname IS NOT NULL)"},
	{131, "UPDATE users SET altname=NULL"},
	{0, nullptr},
};

int dbop_mysql_recentversion()
{
	return tbl_upgrade_list[std::size(tbl_upgrade_list)-2].v;
}

int dbop_mysql_upgrade(MYSQL *conn)
{
	auto current = dbop_mysql_schemaversion(conn);
	mlog(LV_NOTICE, "dbop: Current database schema: gx-%d", current);
	if (current < 0)
		return EXIT_FAILURE;

	auto *entry = tbl_upgrade_list;
	while (entry->v <= static_cast<unsigned int>(current) && entry->v != 0)
		++entry;

	for (; entry->v != 0; ++entry) {
		mlog(LV_NOTICE, "dbop: Upgrading schema to GX-%u", entry->v);
		auto ret = mysql_real_query(conn, entry->command, strlen(entry->command));
		if (ret != 0) {
			mlog(LV_ERR, "dbop: \"%s\": %s", entry->command, mysql_error(conn));
			return EXIT_FAILURE;
		}
		char uq[72];
		if (entry->v == 1)
			snprintf(uq, sizeof(uq), "INSERT INTO `options` VALUES ('schemaversion', %u)", entry->v);
		else
			snprintf(uq, sizeof(uq), "UPDATE `options` SET `value`=%u WHERE `key`='schemaversion'", entry->v);
		ret = mysql_real_query(conn, uq, strlen(uq));
		if (ret != 0) {
			mlog(LV_ERR, "dbop: \"%s\": %s", uq, mysql_error(conn));
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

}
