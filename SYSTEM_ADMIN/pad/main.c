#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <libHX/option.h>
#include "util.h"
#include "config_file.h"
#include "communicator.h"
#include "exec_sched.h"
#include "data_source.h"
#include "midb_client.h"
#include "sensor_client.h"
#include <gromox/system_log.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

static BOOL g_notify_stop;
static char *opt_config_file;
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

	int listen_port;
	int sensor_port;
	int comm_thr_num;
	int proc_thr_num;
	int pop_interval;
	char log_path[256];
	char acl_path[256];
	char list_path[256];
	char midb_path[256];
	char temp_buff[32];
	char listen_ip[16];
	char sensor_ip[16];
	char *str_value;
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	CONFIG_FILE *pconfig;

	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	if (opt_config_file == NULL) {
		printf("You need to specify the -c option.\n");
		return EXIT_FAILURE;
	}
	umask(0);	
	signal(SIGPIPE, SIG_IGN);
	pconfig = config_file_init(opt_config_file);
	if (NULL == pconfig) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	str_value = config_file_get_value(pconfig, "LOG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(log_path, "../logs/athena_log.txt");
		config_file_set_value(pconfig, "LOG_FILE_PATH",
			"../logs/athena_log.txt");
	} else {
		strcpy(log_path, str_value);
	}
	printf("[system]: log path is %s\n", log_path);

	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(acl_path, "../data/pad_acl.txt");
		strcpy(list_path, "../data/pad.txt");
		strcpy(midb_path, "../data/midb_list.txt");
	} else {
		snprintf(acl_path, 255, "%s/pad_acl.txt", str_value);
		snprintf(list_path, 255, "%s/pad.txt", str_value);
		snprintf(midb_path, 255, "%s/midb_list.txt", str_value);
	}
	printf("[system]: acl list path is %s\n", acl_path);
	printf("[system]: user list path is %s\n", list_path);
	printf("[system]: midb list path is %s\n", midb_path);


	str_value = config_file_get_value(pconfig, "PAD_LISTEN_IP");
	if (NULL == str_value) {
		listen_ip[0] = '\0';
		printf("[system]: listen ip is ANY\n");
	} else {
		strncpy(listen_ip, str_value, 16);
		printf("[system]: listen ip is %s\n", listen_ip);
	}

	str_value = config_file_get_value(pconfig, "PAD_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 22222;
		config_file_set_value(pconfig, "PAD_LISTEN_PORT", "22222");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 22222;
			config_file_set_value(pconfig, "PAD_LISTEN_PORT", "22222");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);

	str_value = config_file_get_value(pconfig, "PAD_COMM_THREADS_NUM");
	if (NULL == str_value) {
		comm_thr_num = 5;
		config_file_set_value(pconfig, "PAD_COMM_THREADS_NUM", "5");
	} else {
		comm_thr_num = atoi(str_value);
		if (comm_thr_num < 1) {
			comm_thr_num = 5;
			config_file_set_value(pconfig, "PAD_COMM_THREADS_NUM", "5");
		}
		if (comm_thr_num > 50) {
			comm_thr_num = 50;
			config_file_set_value(pconfig, "PAD_COMM_THREADS_NUM", "50");
		}
	}
	printf("[system]: communication threads number is %d\n", comm_thr_num);

	communicator_init(listen_ip, listen_port, acl_path, comm_thr_num);

	str_value = config_file_get_value(pconfig, "PAD_POP_INTERVAL");
	if (NULL == str_value) {
		pop_interval = 600;
		config_file_set_value(pconfig, "PAD_POP_INTERVAL", "10minutes");
	} else {
		pop_interval = atoitvl(str_value);
		if (pop_interval < 60) {
			pop_interval = 60;
			config_file_set_value(pconfig, "PAD_POP_INTERVAL", "1minute");
		}
	}
	itvltoa(pop_interval, temp_buff);
	printf("[system]: pop interval is %s\n", temp_buff);

	str_value = config_file_get_value(pconfig, "PAD_PROC_THREADS_NUM");
	if (NULL == str_value) {
		proc_thr_num = 10;
		config_file_set_value(pconfig, "PAD_PROC_THREADS_NUM", "10");
	} else {
		proc_thr_num = atoi(str_value);
		if (proc_thr_num < 1) {
			proc_thr_num = 10;
			config_file_set_value(pconfig, "PAD_PROC_THREADS_NUM", "10");
		}
		if (proc_thr_num > 500) {
			proc_thr_num = 500;
			config_file_set_value(pconfig, "PAD_PROC_THREADS_NUM", "500");
		}
	}
	printf("[system]: process threads number is %d\n", proc_thr_num);

	exec_sched_init(list_path, pop_interval, proc_thr_num);

	midb_client_init(midb_path);

	str_value = config_file_get_value(pconfig, "SENSOR_LISTEN_IP");
	if (NULL == str_value) {
		strcpy(sensor_ip, "127.0.0.1");
	} else {
		strncpy(sensor_ip, str_value, 16);
		printf("[system]: sensor ip is %s\n", sensor_ip);
	}

	str_value = config_file_get_value(pconfig, "SENSOR_LISTEN_PORT");
	if (NULL == str_value) {
		sensor_port = 11111;
		config_file_set_value(pconfig, "SENSOR_LISTEN_PORT", "11111");
	} else {
		sensor_port = atoi(str_value);
		if (sensor_port <= 0) {
			sensor_port = 11111;
			config_file_set_value(pconfig, "SENSOR_LISTEN_PORT", "11111");
		}
	}
	printf("[system]: sensor port is %d\n", sensor_port);

	sensor_client_init(sensor_ip, sensor_port);
	
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

	data_source_init(mysql_host, mysql_port, mysql_user, mysql_passwd, db_name);


	config_file_save(pconfig);
	config_file_free(pconfig);

	system_log_init(log_path);



	if (0 != system_log_run()) {
		printf("[system]: fail to run system log\n");
		return 3;
	}

	if (0 != midb_client_run()) {
		system_log_stop();
		printf("[system]: fail to run midb client\n");
		return 4;
	}

	if (0 != data_source_run()) {
		midb_client_stop();
		system_log_stop();
		printf("[system]: fail to run data source\n");
		return 5;
	}

	if (0 != sensor_client_run()) {
		data_source_stop();
		midb_client_stop();
		system_log_stop();
		printf("[system]: fail to run command parser\n");
		return 5;
	}

	if (0 != exec_sched_run()) {
		sensor_client_stop();
		data_source_stop();
		midb_client_stop();
		system_log_stop();
		printf("[system]: fail to run exec sched\n");
		return 6;
	}

	if (0 != communicator_run()) {
		exec_sched_stop();
		sensor_client_stop();
		data_source_stop();
		midb_client_stop();
		system_log_stop();
		printf("[system]: fail to communicator\n");
		return 7;
	}
	
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: PAD is now rinning\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}

	communicator_stop();
	exec_sched_stop();
	sensor_client_stop();
	data_source_stop();
	midb_client_stop();
	system_log_stop();
	return 0;
}



