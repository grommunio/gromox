#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include "log_flusher.h"
#include "log_analyzer.h"
#include "message.h"
#include "domain_cleaner.h"
#include "media_migrator.h"
#include "password_cleaner.h"
#include "data_source.h"
#include <gromox/locker_client.h>
#include <gromox/system_log.h>
#include "keyword_cleaning.h"
#include "file_operation.h"
#include "smtp_sender.h"
#include "midb_client.h"
#include "auto_backup.h"
#include "config_file.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	char *str_value;
	time_t now_time;
	CONFIG_FILE *pconfig;
	char console_path[256];
	char data_path[256];
	char mount_path[256];
	char log_path[256];
	char logo_link[256];
	char logo_path[256];
	char area_path[256];
	char midb_path[256];
	char background_path[256];
	char resource_path[256];
	char admin_mailbox[256];
	char default_domain[256];
	char system_backup_path[256];
	char group_path[256];
	char kstatisitic_path[256];
	char statistic_path[256];
	char temp_buff[128];
	char locker_ip[16];
	int locker_port;
	int max_interval;
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	time(&now_time);	
	char *dflcfgpath = config_default_path("synchronizer.cfg");
	pconfig = config_file_init2(opt_config_file, dflcfgpath);
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 1;
	}
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATASADIR, sizeof(data_path));
		config_file_set_value(pconfig, "DATA_FILE_PATH", data_path);
	} else {
		strcpy(data_path, str_value);
	}
	printf("[system]: data path is %s\n", data_path);
	
	str_value = config_file_get_value(pconfig, "LOGO_LINK");
	if (NULL == str_value) {
		strcpy(logo_link, DFL_LOGOLINK);
	} else {
		strcpy(logo_link, str_value);
	}
	
	sprintf(logo_path, "%s/picture/logo_bb.gif", data_path);
	sprintf(background_path, "%s/picture/di1.gif", data_path);
	sprintf(resource_path, "%s/daemon", data_path);
	
	str_value = config_file_get_value(pconfig, "GATEWAY_MOUNT_PATH");
	if (NULL == str_value) {
		strcpy(mount_path, PKGSTATEGATEWAYDIR);
		config_file_set_value(pconfig, "GATEWAY_MOUNT_PATH", mount_path);
	} else {
		strcpy(mount_path, str_value);
	}
	printf("[system]: gateway mount path is %s\n", mount_path);
	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(log_path, PKGLOGDIR "/sa.log", sizeof(log_path));
		config_file_set_value(pconfig, "LOG_FILE_PATH", log_path);
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "SYSTEM_BACKUP_PATH");
	if (NULL == str_value) {
		strcpy(system_backup_path, "../sys_backup");
	} else {
		strcpy(system_backup_path, str_value);
	}
	printf("[system]: system backup path is %s\n", system_backup_path);

	str_value = config_file_get_value(pconfig, "ADMIN_MAILBOX");
	if (NULL == str_value) {
		strcpy(admin_mailbox, "admin@gridware.com.cn");
		config_file_set_value(pconfig, "ADMIN_MAILBOX", "admin@gridware.com.cn");
	} else {
		strcpy(admin_mailbox, str_value);
	}
	printf("[system]: administrator mailbox is %s\n", admin_mailbox);
	
	str_value = config_file_get_value(pconfig, "DEFAULT_DOMAIN");
	if (NULL == str_value) {
		strcpy(default_domain, "herculiz.com");
		config_file_set_value(pconfig, "DEFAULT_DOMAIN", "herculiz.com");
	} else {
		strcpy(default_domain, str_value);
	}
	printf("[system]: default domain is %s\n", default_domain);
	
	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
		config_file_set_value(pconfig, "MYSQL_HOST", "localhost");
	} else {
		strcpy(mysql_host, str_value);
	}
	printf("[system]: mysql host is %s\n", mysql_host);

	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
		config_file_set_value(pconfig, "MYSQL_PORT", "3306");
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
			config_file_set_value(pconfig, "MYSQL_PORT", "3306");
		}
	}
	printf("[system]: mysql port is %d\n", mysql_port);

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		mysql_user[0] = '\0';
		printf("[system]: cannot find mysql username in config "
			"file, use current unix login name\n");
	} else {
		strcpy(mysql_user, str_value);
		printf("[system]: mysql username is %s\n", mysql_user);
	}

	mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	if (NULL == mysql_passwd) {
		printf("[system]: use empty password as mysql password\n");
	} else {
		if ('\0' == mysql_passwd[0]) {
			printf("[system]: use empty password as mysql password\n");
		} else {
			printf("[system]: mysql password is ********\n");
		}
	}

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
		config_file_set_value(pconfig, "MYSQL_DBNAME", "email");
	} else {
		strcpy(db_name, str_value);
	}
	printf("[system]: mysql database name is %s\n", db_name);

	str_value = config_file_get_value(pconfig, "LOCKER_LISTEN_IP");
	if (NULL == str_value) {
		strcpy(locker_ip, "127.0.0.1");
		config_file_set_value(pconfig, "LOCKER_LISTEN_IP", "127.0.0.1");
	} else {
		strncpy(locker_ip, str_value, 16);
	}
	printf("[system]: locker listen ipaddr is %s\n", locker_ip);

	str_value = config_file_get_value(pconfig, "LOCKER_LISTEN_PORT");
	if (NULL == str_value) {
		locker_port = 7777;
		config_file_set_value(pconfig, "LOCKER_LISTEN_PORT", "7777");
	} else {
		locker_port = atoi(str_value);
		if (locker_port <= 0) {
			locker_port = 7777;
			config_file_set_value(pconfig, "LOCKER_LISTEN_PORT", "7777");
		}
	}
	printf("[system]: locker listen port is %d\n", locker_port);

	str_value = config_file_get_value(pconfig, "LOCKER_MAXIMUM_INTERVAL");
	if (NULL == str_value) {
		max_interval = 180;
		config_file_set_value(pconfig, "LOCKER_MAXIMUM_INTERVAL", "3minutes");
	} else {
		max_interval = atoitvl(str_value);
		if (max_interval <= 0) {
			max_interval = 180;
			config_file_set_value(pconfig, "LOCKER_MAXIMUM_INTERVAL",
				"3minutes");
		}
	}
	itvltoa(max_interval, temp_buff);
	printf("[system]: locker maximum interval is %s\n", temp_buff);
	
	config_file_free(pconfig);
	sprintf(area_path, "%s/area_list.txt", data_path);
	sprintf(midb_path, "%s/midb_list.txt", data_path);
	sprintf(statistic_path, "%s/mail_statistic.txt", data_path);
	sprintf(console_path, "%s/console_table.txt", data_path);
	sprintf(group_path, "%s/keyword_group.txt", data_path);
	sprintf(kstatisitic_path, "%s/keyword_statistic.txt", data_path);
	system_log_init(log_path);
	file_operation_init();
	smtp_sender_init();
	midb_client_init(midb_path);
	log_flusher_init(console_path);
	message_init(background_path, logo_path, logo_link, resource_path);
	locker_client_init(locker_ip, locker_port, max_interval);
	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);
	log_analyzer_init(now_time, statistic_path, mount_path);
	keyword_cleaning_init(now_time, group_path, console_path, kstatisitic_path);
	auto_backup_init(opt_config_file != nullptr ? opt_config_file : dflcfgpath,
		data_path, system_backup_path, admin_mailbox, default_domain);
	domain_cleaner_init(now_time);
	password_cleaner_init(now_time);
	media_migrator_init(area_path);
	if (0 != system_log_run()) {
		printf("[system]: failed to run system log\n");
		return 1;
	}
	if (0 != file_operation_run()) {
		printf("[system]: failed to run file operation\n");
		return 2;
	}
	if (0 != smtp_sender_run()) {
		printf("[system]: failed to run smtp sender\n");
		return 3;
	}
	if (0 != midb_client_run()) {
		printf("[system]: failed to run midb client\n");
		return 4;
	}
	if (0 != log_flusher_run()) {
		printf("[system]: failed to run log flusher\n");
		return 5;
	}
	if (0 != message_run()) {
		printf("[system]: failed to run message\n");
		return 6;
	}
	if (0 != locker_client_run()) {
		printf("[system]: failed to run locker client\n");
		return 7;
	}
	if (0 != data_source_run()) {
		printf("[system]: failed to run data source\n");
		return 8;
	}
	if (0 != log_analyzer_run()) {
		printf("[system]: failed to run domain classifier\n");
		return 9;
	}
	if (0 != keyword_cleaning_run()) {
		printf("[system]: failed to run keyword cleaning\n");
		return 10;
	}
	if (0 != auto_backup_run()) {
		printf("[system]: failed to run config backup\n");
		return 11;
	}
	if (0 != domain_cleaner_run()) {
		printf("[system]: failed to run domain cleaner\n");
		return 12;
	}
	if (0 != media_migrator_run()) {
		printf("[system]: failed to run media migrator\n");
		return 13;
	}
	if (0 != password_cleaner_run()) {
		printf("[system]: failed to run password cleaner\n");
		return 14;
	}

	password_cleaner_stop();
	media_migrator_stop();
	domain_cleaner_stop();
	auto_backup_stop();
	keyword_cleaning_stop();
	log_analyzer_stop();
	data_source_stop();
	locker_client_stop();
	message_stop();
	log_flusher_stop();
	midb_client_stop();
	smtp_sender_stop();
	file_operation_stop();
	system_log_stop();

	password_cleaner_free();
	media_migrator_free();
	domain_cleaner_free();
	auto_backup_free();
	keyword_cleaning_free();
	log_analyzer_free();
	data_source_free();
	locker_client_free();
	message_free();
	log_flusher_free();
	midb_client_free();
	smtp_sender_free();
	file_operation_free();
	system_log_free();
	printf("[system]: DAEMON run OK\n");
	return 0;
}
