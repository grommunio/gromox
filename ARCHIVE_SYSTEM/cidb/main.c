#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include "util.h"
#include "listener.h"
#include "mysql_pool.h"
#include "cmd_parser.h"
#include <gromox/system_log.h>
#include "config_file.h"
#include "classify_engine.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#define SOCKET_TIMEOUT		60

static BOOL g_notify_stop;
static char *opt_config_file = NULL;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

int main(int argc, const char **argv)
{
	int conn_num;
	struct tm *ptm;
	int valid_days;
	int mysql_port;
	int sphinx_port;
	int listen_port;
	int threads_num;
	char *str_value;
	time_t now_time;
	long tmptbl_size;
	struct tm tmp_tm;
	int scan_interval;
	char *mysql_passwd;
	char tmp_size[64];
	char db_name[128];
	char log_path[256];
	char listen_ip[16];
	char temp_buff[256];
	char list_path[256];
	char mysql_host[128];
	char sphinx_host[128];
	char mysql_user[128];
	CONFIG_FILE *pconfig;
	char storage_path[128];

	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	pconfig = config_file_init2(opt_config_file, config_default_path("cidb.cfg"));
	if (opt_config_file != NULL && pconfig == NULL) {
		printf("[system]: config_file_init %s: %s\n",
			opt_config_file, strerror(errno));
		return 2;
	}

	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(log_path, PKGLOGDIR "/titan_log.txt", sizeof(log_path));
		config_file_set_value(pconfig, "LOG_FILE_PATH", log_path);
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(list_path, PKGDATAARCHIVEDIR "/cidb_acl.txt", sizeof(list_path));
	} else {
		snprintf(list_path, 255, "%s/cidb_acl.txt", str_value);
	}
	printf("[system]: acl file path is %s\n", list_path);
	
	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		strcpy(mysql_host, str_value);
	}

	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
		}
	}

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		mysql_user[0] = '\0';
	} else {
		strcpy(mysql_user, str_value);
	}

	mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "archive");
	} else {
		strcpy(db_name, str_value);
	}
	
	str_value = config_file_get_value(pconfig, "MYSQL_CONNECTION_NUM");
	if (NULL == str_value) {
		conn_num = 20;
		config_file_set_value(pconfig, "MYSQL_CONNECTION_NUM", "20");
	} else {
		conn_num = atoi(str_value);
		if (conn_num < 0) {
			conn_num = 20;
			config_file_set_value(pconfig, "MYSQL_CONNECTION_NUM", "20");
		}
	}
	printf("[system]: mysql connection number is %d\n", conn_num);

	str_value = config_file_get_value(pconfig, "MYSQL_SCAN_INTERVAL");
	if (NULL == str_value) {
		scan_interval = 60;
		config_file_set_value(pconfig, "MYSQL_SCAN_INTERVAL", "1minute");
	} else {
		scan_interval = atoitvl(str_value);
		if (scan_interval <= 0) {
			scan_interval = 60;
			config_file_set_value(pconfig, "MYSQL_SCAN_INTERVAL", "1minute");
		}
	}
	itvltoa(scan_interval, temp_buff);
	printf("[system]: reconnecting thread scanning interval is %s\n",
		temp_buff);

	str_value = config_file_get_value(pconfig, "CIDB_LISTEN_IP");
	if (NULL == str_value) {
		listen_ip[0] = '\0';
		printf("[system]: listen ipaddr is ANY\n");
	} else {
		strncpy(listen_ip, str_value, 16);
		printf("[system]: listen ipaddr is %s\n", listen_ip);
	}

	str_value = config_file_get_value(pconfig, "CIDB_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 5556;
		config_file_set_value(pconfig, "CIDB_LISTEN_PORT", "5556");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 5556;
			config_file_set_value(pconfig, "CIDB_LISTEN_PORT", "5556");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);

	str_value = config_file_get_value(pconfig, "CIDB_THREADS_NUM");
	if (NULL == str_value) {
		threads_num = 50;
		config_file_set_value(pconfig, "CIDB_THREADS_NUM", "50");
	} else {
		threads_num = atoi(str_value);
		if (threads_num < 20) {
			threads_num = 20;
			config_file_set_value(pconfig, "CIDB_THREADS_NUM", "20");
		} else if (threads_num > 400) {
			threads_num = 400;
			config_file_set_value(pconfig, "CIDB_THREADS_NUM", "400");
		}
	}
	printf("[system]: connection threads number is %d\n", threads_num);

	str_value = config_file_get_value(pconfig, "MYSQL_TMP_TABLE_SIZE");
	if (NULL == str_value) {
		tmptbl_size = 1UL << 30;
		config_file_set_value(pconfig, "MYSQL_TMP_TABLE_SIZE", "1G");
	} else {
		tmptbl_size = atobyte(str_value);
		if (tmptbl_size < 16*1024*1024 || tmptbl_size > 4096*1024*1024UL) {
			tmptbl_size = 16*1024*1024;
			config_file_set_value(pconfig, "MYSQL_TMP_TABLE_SIZE", "16M");
		}
	}
	bytetoa(tmptbl_size, tmp_size);
	printf("[system]: mysql tm table size is %s\n", tmp_size);
	
	str_value = config_file_get_value(pconfig, "STORAGE_PATH");
	if (NULL == str_value) {
		printf("[system]: cannot find STORAGE_PATH in config file!\n");
		config_file_free(pconfig);
		return 2;
	}
	strcpy(storage_path, str_value);
	if ('\0' == storage_path[0]) {
		printf("[system]: STORAGE_PATH empty in config file!\n");
		config_file_free(pconfig);
		return 2;
	}
	printf("[system]: storage path of archived mails is %s\n", storage_path);
	
	str_value = config_file_get_value(pconfig, "VALID_DAYS");
	if (NULL == str_value) {
		valid_days = 365;
	} else {
		valid_days = atoi(str_value);
		if (valid_days < 0) {
			valid_days = 0;
		}
	}
	
	if (0 == valid_days) {
		printf("[system]: achived mails will never be deleted\n");
	} else {
		printf("[system]: archived mails will be deleted after %d days\n",
			valid_days);
	}
	
	str_value = config_file_get_value(pconfig, "SPHINX_HOST");
	if (NULL == str_value) {
		strcpy(sphinx_host, "localhost");
	} else {
		strcpy(sphinx_host, str_value);
	}
	
	str_value = config_file_get_value(pconfig, "SPHINX_PORT");
	if (NULL == str_value) {
		sphinx_port = 9312;
	} else {
		sphinx_port = atoi(str_value);
		if (sphinx_port <= 0) {
			sphinx_port = 9312;
		}
	}
	
	mysql_pool_init(conn_num, scan_interval, mysql_host, mysql_port,
		mysql_user, mysql_passwd, db_name, 0);
	config_file_free(pconfig);
	system_log_init(log_path);

	listener_init(listen_ip, listen_port, list_path);

	classify_engine_init(storage_path, valid_days,
		sphinx_host, sphinx_port, tmptbl_size);

	cmd_parser_init(threads_num, SOCKET_TIMEOUT);


	if (0 != system_log_run()) {
		printf("[system]: fail to run system log\n");
		return 3;
	}
	

	if (0 != listener_run()) {
		printf("[system]: fail to run listener\n");
		return 4;
	}

	if (0 != cmd_parser_run()) {
		listener_stop();
		printf("[system]: fail to run command parser\n");
		return 5;
	}
	
	if (0 != mysql_pool_run()) {
		cmd_parser_stop();
		listener_stop();
		printf("[system]: fail to run mysql pool\n");
		return 6;
	}

	if (0 != classify_engine_run()) {
		mysql_pool_stop();
		cmd_parser_stop();
		listener_stop();
		printf("[system]: fail to run classify engine\n");
		return 7;
	}

	if (0 != listener_trigger_accept()) {
		classify_engine_stop();
		cmd_parser_stop();
		listener_stop();
		printf("[system]: fail to trigger listener\n");
		return 8;
	}
	
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: CIDB is now running\n");
	while (FALSE == g_notify_stop) {
		time(&now_time);
		ptm = localtime_r(&now_time, &tmp_tm);
		if (0 == ptm->tm_hour && 0 == ptm->tm_min) {
			classify_engine_clean(now_time);
			sleep(60);
		}
		sleep(1);	
	}

	listener_stop();
	cmd_parser_stop();
	classify_engine_stop();
	mysql_pool_stop();
	return 0;
}



