#include "processing_engine.h"
#include "url_downloader.h"
#include "file_operation.h"
#include "gateway_control.h"
#include "list_file.h"
#include "config_file.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <pthread.h>

#define INDEX_ROOT_PASSWORD		0
#define INDEX_DEFAULT_DOMAIN	1
#define INDEX_ADMIN_MAILBOX		2
#define INDEX_HUGE_DOMAIN		3
#define INDEX_SESSION_NUM		4
#define INDEX_RCPT_NUM			5
#define INDEX_MAIL_LENGTH		6
#define INDEX_TIME_OUT			7
#define INDEX_SCANNING_SIZE		8
#define INDEX_CONN_FREQ			9
#define INDEX_DISPARCH_FREQ		10
#define INDEX_LOG_DAYS			11
#define INDEX_LOCAL_DOMAIN		12
#define INDEX_BACKEND_LIST		13
#define INDEX_DNS_TABLE			14
#define INDEX_FORWARD_TABLE		15
#define INDEX_FROM_REPLACE		16
#define INDEX_DOMAIN_MAILBOX	17

#define TOKEN_SESSION               1
#define TOKEN_CONTROL               100
#define CTRL_RESTART_WEBADAPTOR     3

#define ACL_CAPACITY				1024

static BOOL g_noop;
static BOOL g_notify_stop;
static char g_master_ip[16];
static char g_data_path[256];
static char g_control_path[256];
static char g_shm_path[256];
static char g_config_path[256];
static char g_mask_string[20];
static pthread_t g_thread_id;

static void* thread_work_func(void *param);

static void processing_engine_clear_sessions();

static void processing_engine_restart_web_adaptor();

static void processing_engine_transfer_backend_table(char *src_file, char *dst_file);

static void processing_engine_transfer_dns_table(char *src_file, char *dst_file);

static void processing_engine_transfer_forward_table(char *src_file, char *dst_file);

static void processing_engine_transfer_backup_list(char *src_file, char *dst_file);

static void processing_engine_transfer_from_replace(char *src_file, char *dst_file);

static void processing_engine_transfer_domain_mailbox(char *src_file, char *dst_file);


void processing_engine_init(const char *master_ip, const char *data_path,
	const char *config_path, const char *control_path, const char *shm_path,
	const char *mask_string, BOOL b_noop)
{
	g_noop = b_noop;
	strcpy(g_master_ip, master_ip);
	strcpy(g_data_path, data_path);
	strcpy(g_config_path, config_path);
	strcpy(g_control_path, control_path);
	strcpy(g_shm_path, shm_path);
	memset(g_mask_string, '0', sizeof(g_mask_string));
	strcpy(g_mask_string, mask_string);
	g_notify_stop = TRUE;
}

int processing_engine_run()
{
	if (FALSE == g_noop) {
		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
			g_notify_stop = TRUE;
			printf("[processing_engine]: fail to create fresh thread\n");
			return -1;
		}
	}
	return 0;
}

int processing_engine_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	return 0;
}

void processing_engine_free()
{
	g_master_ip[0] = '\0';
}

static void* thread_work_func(void *param)
{
	char *str_master;
	char *str_master1;
	char *str_master2;
	char *str_slave;
	char *str_slave1;
	char *str_slave2;
	char temp_url[1024];
	char temp_path[256];
	char temp_path1[256];
	char command_string[1024];
	int times, num, unit, local_type;
	BOOL b_master, b_slave;
	CONFIG_FILE *pconfig_master;
	CONFIG_FILE *pconfig_slave;
	
	while (FALSE == g_notify_stop) {
		sleep(3);
		sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?athena.cfg",
			g_master_ip);
		sprintf(temp_path, "%s.tmp", g_config_path);
		if (FALSE == url_downloader_get(temp_url, temp_path)) {
			continue;
		}
		pconfig_master = config_file_init(temp_path);
		if (NULL == pconfig_master) {
			continue;
		}
		pconfig_slave = config_file_init(g_config_path);
		if (NULL == pconfig_slave) {
			continue;
		}
		if (NULL == pconfig_slave) {
			config_file_free(pconfig_master);
			continue;
		}
		if ('1' == g_mask_string[INDEX_ROOT_PASSWORD]) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?system_users.txt", g_master_ip);
			sprintf(temp_path, "%s/system_users.txt", g_data_path);
			sprintf(temp_path1, "%s/system_users.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				processing_engine_clear_sessions();
			}
		}
		if ('1' == g_mask_string[INDEX_DEFAULT_DOMAIN]) {
			str_master = config_file_get_value(pconfig_master, "DEFAULT_DOMAIN");
			str_slave = config_file_get_value(pconfig_slave, "DEFAULT_DOMAIN");
			if (NULL != str_master && (NULL == str_slave ||
				0 != strcasecmp(str_master, str_slave))) {
				config_file_set_value(pconfig_slave, "DEFAULT_DOMAIN", str_master);
				sprintf(command_string, "system set default-domain %s", str_master);
				gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
			}
		}
		if ('1' == g_mask_string[INDEX_ADMIN_MAILBOX]) {
			str_master = config_file_get_value(pconfig_master, "ADMIN_MAILBOX");
			str_slave = config_file_get_value(pconfig_slave, "ADMIN_MAILBOX");
			if (NULL != str_master && (NULL == str_slave ||
				0 != strcasecmp(str_master, str_slave))) {
				config_file_set_value(pconfig_slave, "ADMIN_MAILBOX", str_master);
				sprintf(command_string, "system set admin-mailbox %s", str_master);
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}
		if ('1' == g_mask_string[INDEX_HUGE_DOMAIN]) {
			str_master = config_file_get_value(pconfig_master, "HASH_HUGE");
			str_slave = config_file_get_value(pconfig_slave, "HASH_HUGE");
			b_master = TRUE;
			b_slave = TRUE;
			if (NULL != str_master && 0 == strcasecmp(str_master, "FALSE")) {
				b_master = FALSE;
			}
			if (NULL != str_slave && 0 == strcasecmp(str_slave, "FALSE")) {
				b_slave = FALSE;
			}
			if (b_master != b_slave) {
				if (TRUE == b_master) {
					config_file_set_value(pconfig_slave, "HASH_HUGE", "TRUE");
					sprintf(command_string, "mail_backup.hook set hash-huge TRUE");
				} else {
					config_file_set_value(pconfig_slave, "HASH_HUGE", "FALSE");
					sprintf(command_string, "mail_backup.hook set hash-huge FALSE");
				}
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}
		if ('1' == g_mask_string[INDEX_SESSION_NUM]) {
			str_master = config_file_get_value(pconfig_master, "SMTP_SESSION_MAIL_NUM");
			str_slave = config_file_get_value(pconfig_slave, "SMTP_SESSION_MAIL_NUM");
			if (NULL != str_master && (NULL == str_slave ||
				0 != strcasecmp(str_master, str_slave))) {
				config_file_set_value(pconfig_slave, "SMTP_SESSION_MAIL_NUM", str_master);
				sprintf(command_string, "smtp set max-mails %s", str_master);
				gateway_control_notify(command_string, NOTIFY_SMTP);
			}
		}
		if ('1' == g_mask_string[INDEX_RCPT_NUM]) {
			str_master = config_file_get_value(pconfig_master, "SMTP_MAX_RCPT_NUM");
			str_slave = config_file_get_value(pconfig_slave, "SMTP_MAX_RCPT_NUM");
			if (NULL != str_master && (NULL == str_slave ||
				0 != strcasecmp(str_master, str_slave))) {
				config_file_set_value(pconfig_slave, "SMTP_MAX_RCPT_NUM", str_master);
				sprintf(command_string, "rcpt_limit.pas set max-rcpt %s", str_master);
				gateway_control_notify(command_string, NOTIFY_SMTP);
			}
		}
		if ('1' == g_mask_string[INDEX_MAIL_LENGTH]) {
			str_master = config_file_get_value(pconfig_master, "SMTP_MAIL_LEN_NUM");
			str_slave = config_file_get_value(pconfig_slave, "SMTP_MAIL_LEN_NUM");
			str_master1 = config_file_get_value(pconfig_master, "SMTP_MAIL_LEN_UNIT");
			str_slave1 = config_file_get_value(pconfig_slave, "SMTP_MAIL_LEN_UNIT");
			if (NULL != str_master && NULL != str_master1 &&
				(NULL == str_slave || NULL == str_slave1 ||
				0 != strcmp(str_master, str_slave) ||
				0 != strcmp(str_master1, str_slave1))) {
				num = atoi(str_master);
				unit = atoi(str_master1);
				if (num > 0 && (2 == unit || 3 == unit)) {
					config_file_set_value(pconfig_slave, "SMTP_MAIL_LEN_NUM", str_master);
					config_file_set_value(pconfig_slave, "SMTP_MAIL_LEN_UNIT", str_master1);
					switch (unit) {
					case 2:
						sprintf(command_string, "smtp set mail-length %dK", num);
						break;
					case 3:
						sprintf(command_string, "smtp set mail-length %dM", num);
						break;
					}
					gateway_control_notify(command_string, NOTIFY_SMTP);
				}
			}
		}
		if ('1' == g_mask_string[INDEX_TIME_OUT]) {
			str_master = config_file_get_value(pconfig_master, "SMTP_TIMEOUT_NUM");
			str_slave = config_file_get_value(pconfig_slave, "SMTP_TIMEOUT_NUM");
			str_master1 = config_file_get_value(pconfig_master, "SMTP_TIMEOUT_UNIT");
			str_slave1 = config_file_get_value(pconfig_slave, "SMTP_TIMEOUT_UNIT");
			if (NULL != str_master && NULL != str_master1 &&
				(NULL == str_slave || NULL == str_slave1 ||
				0 != strcmp(str_master, str_slave) ||
				0 != strcmp(str_master1, str_slave1))) {
				num = atoi(str_master);
				unit = atoi(str_master1);
				if (num > 0 && (1 == unit || 2 == unit)) {
					config_file_set_value(pconfig_slave, "SMTP_TIMEOUT_NUM", str_master);
					config_file_set_value(pconfig_slave, "SMTP_TIMEOUT_UNIT", str_master1);
					switch (unit) {
					case 1:
						sprintf(command_string, "smtp set time-out %dseconds", num);
						break;
					case 2:
						sprintf(command_string, "smtp set time-out %dminutes", num);
						break;
					}
					gateway_control_notify(command_string, NOTIFY_SMTP);
				}
			}
		}
		if ('1' == g_mask_string[INDEX_SCANNING_SIZE]) {
			str_master = config_file_get_value(pconfig_master, "VIRUS_SCANNING_NUM");
			str_slave = config_file_get_value(pconfig_slave, "VIRUS_SCANNING_NUM");
			str_master1 = config_file_get_value(pconfig_master, "VIRUS_SCANNING_UNIT");
			str_slave1 = config_file_get_value(pconfig_slave, "VIRUS_SCANNING_UNIT");
			if (NULL != str_master && NULL != str_master1 &&
				(NULL == str_slave || NULL == str_slave1 ||
				0 != strcmp(str_master, str_slave) ||
				0 != strcmp(str_master1, str_slave1))) {
				num = atoi(str_master);
				unit = atoi(str_master1);
				if (num > 0 && unit >= 1 && unit <= 3) {
					config_file_set_value(pconfig_slave, "VIRUS_SCANNING_NUM", str_master);
					config_file_set_value(pconfig_slave, "VIRUS_SCANNING_UNIT", str_master1);
					switch (unit) {
					case 1:
						sprintf(command_string, "flusher set scanning-size %d", num);
						break;
					case 2:
						sprintf(command_string, "flusher set scanning-size %dK", num);
						break;
					case 3:
						sprintf(command_string, "flusher set scanning-size %dM", num);
						break;
					}
					gateway_control_notify(command_string, NOTIFY_SMTP);
				}
			}
		}
		if ('1' == g_mask_string[INDEX_CONN_FREQ]) {
			str_master = config_file_get_value(pconfig_master, "CONNECTION_TIMES");
			str_slave = config_file_get_value(pconfig_slave, "CONNECTION_TIMES");
			str_master1 = config_file_get_value(pconfig_master, "CONNECTION_INTERVAL_NUM");
			str_slave1 = config_file_get_value(pconfig_slave, "CONNECTION_INTERVAL_NUM");
			str_master2 = config_file_get_value(pconfig_master, "CONNECTION_INTERVAL_UNIT");
			str_slave2 = config_file_get_value(pconfig_slave, "CONNECTION_INTERVAL_UNIT");
			if (NULL != str_master && NULL != str_master1 &&
				NULL != str_master2 && (NULL == str_slave ||
				NULL == str_slave1 || NULL == str_slave2 ||
				0 != strcmp(str_master, str_slave) ||
				0 != strcmp(str_master1, str_slave1) ||
				0 != strcmp(str_master2, str_slave2))) {
				times = atoi(str_master);
				num = atoi(str_master1);
				unit = atoi(str_master2);
				if (times > 0 && unit > 0 && (1 == unit || 2 == unit)) {
					config_file_set_value(pconfig_slave, "CONNECTION_TIMES", str_master);
					config_file_set_value(pconfig_slave, "CONNECTION_INTERVAL_NUM", str_master1);
					config_file_set_value(pconfig_slave, "CONNECTION_INTERVAL_UNIT", str_master2);
					switch (unit) {
					case 1:
						sprintf(command_string, "ip_filter.svc audit set %d/%d", times, num);
						break;
					case 2:
						sprintf(command_string, "ip_filter.svc audit set %d/%dminutes", times, num);
						break;
					}
					gateway_control_notify(command_string, NOTIFY_SMTP);
				}
			}
		}
		if ('1' == g_mask_string[INDEX_DISPARCH_FREQ]) {
			str_master = config_file_get_value(pconfig_master, "DISPATCH_RETRING_TIMES");
			str_slave = config_file_get_value(pconfig_slave, "DISPATCH_RETRING_TIMES");
			str_master1 = config_file_get_value(pconfig_master, "DISPATCH_RETRING_INTERVAL_NUM");
			str_slave1 = config_file_get_value(pconfig_slave, "DISPATCH_RETRING_INTERVAL_NUM");
			str_master2 = config_file_get_value(pconfig_master, "DISPATCH_RETRING_INTERVAL_UNIT");
			str_slave2 = config_file_get_value(pconfig_slave, "DISPATCH_RETRING_INTERVAL_UNIT");
			if (NULL != str_master && NULL != str_master1 &&
				NULL != str_master2 && (NULL == str_slave ||
				NULL == str_slave1 || NULL == str_slave2 ||
				0 != strcmp(str_master, str_slave) ||
				0 != strcmp(str_master1, str_slave1) ||
				0 != strcmp(str_master2, str_slave2))) {
				times = atoi(str_master);
				num = atoi(str_master1);
				unit = atoi(str_master2);
				if (times > 0 && unit > 0 && unit >= 1 && unit <= 3) {
					config_file_set_value(pconfig_slave, "DISPATCH_RETRING_TIMES", str_master);
					config_file_set_value(pconfig_slave, "DISPATCH_RETRING_INTERVAL_NUM", str_master1);
					config_file_set_value(pconfig_slave, "DISPATCH_RETRING_INTERVAL_UNIT", str_master2);
					sprintf(command_string, "gateway_dispatch.hook set retrying-times %d", times);
					gateway_control_notify(command_string, NOTIFY_DELIVERY);
					switch (unit) {
					case 1:
						 sprintf(command_string, "gateway_dispatch.hook set cache-scan %d", num);
						 break;
					case 2:
						 sprintf(command_string, "gateway_dispatch.hook set cache-scan %dminutes", num);
						 break;
					case 3:
						 sprintf(command_string, "gateway_dispatch.hook set cache-scan %dhours", num);
						 break;
					}
					gateway_control_notify(command_string, NOTIFY_DELIVERY);
				}
			}
		}
		if ('1' == g_mask_string[INDEX_LOG_DAYS]) {
			str_master = config_file_get_value(pconfig_master, "LOG_VALID_DAYS");
			str_slave = config_file_get_value(pconfig_slave, "LOG_VALID_DAYS");
			if (NULL != str_master && (NULL == str_slave ||
				0 != strcmp(str_master, str_slave))) {
				config_file_set_value(pconfig_slave, "LOG_VALID_DAYS", str_master);
				sprintf(command_string, "log_plugin.svc set valid-days %s", str_master);
				gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
			}
		}
		if ('1' == g_mask_string[INDEX_LOCAL_DOMAIN]) {
			str_master = config_file_get_value(pconfig_master, "LOCAL_SETUP_TYPE");
			str_slave = config_file_get_value(pconfig_slave, "LOCAL_SETUP_TYPE");
			if (NULL != str_master && (NULL == str_slave ||
				0 != strcmp(str_master, str_slave))) {
				config_file_set_value(pconfig_slave, "LOCAL_SETUP_TYPE", str_master);
				num = atoi(str_master);
				switch (num) {
				case 0:
					config_file_set_value(pconfig_slave, "LOCAL_SETUP_TYPE", "0");
					sprintf(command_string, "system set domain-list FALSE");
					gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
					break;
				case 1:
					config_file_set_value(pconfig_slave, "LOCAL_SETUP_TYPE", "1");
					str_master = config_file_get_value(pconfig_master, "DOMAINLIST_URL_PATH");
					config_file_set_value(pconfig_slave, "DOMAINLIST_URL_PATH", str_master);
					sprintf(command_string, "system set domain-list TRUE");
					gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
					break;
				case 2:
					config_file_set_value(pconfig_slave, "LOCAL_SETUP_TYPE", "2");
					sprintf(command_string, "system set domain-list TRUE");
					gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
					break;
				}
				config_file_save(pconfig_slave);
				processing_engine_restart_web_adaptor();	
			}
		}
		str_slave = config_file_get_value(pconfig_slave, "LOCAL_SETUP_TYPE");
		if (NULL != str_slave) {
			local_type = atoi(str_slave);
		} else {
			local_type = -1;
		}
		config_file_save(pconfig_slave);
		config_file_free(pconfig_master);
		config_file_free(pconfig_slave);

		sprintf(temp_path, "%s.tmp", g_config_path);
		remove(temp_path);

		
		if ('1' == g_mask_string[INDEX_LOCAL_DOMAIN] && 0 == local_type) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?local_setup.txt", g_master_ip);
			sprintf(temp_path, "%s/local_setup.txt", g_data_path);
			sprintf(temp_path1, "%s/local_setup.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				file_operation_broadcast(temp_path, "data/delivery/inbound_ips.txt");
				sprintf(command_string, "dns_adaptor.svc reload inbound-ips");
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}
		
		if ('1' == g_mask_string[INDEX_LOCAL_DOMAIN] && 2 == local_type) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?domain_list.txt", g_master_ip);
			sprintf(temp_path, "%s/domain_list.txt", g_data_path);
			sprintf(temp_path1, "%s/domain_list.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				file_operation_broadcast(temp_path, "data/smtp/domain_list.txt");
				file_operation_broadcast(temp_path, "data/delivery/domain_list.txt");
				sprintf(command_string, "domain_list.svc reload");
				gateway_control_notify(command_string, NOTIFY_SMTP|NOTIFY_DELIVERY);
			}
		}
		
		if ('1' == g_mask_string[INDEX_BACKEND_LIST]) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?backend_table.txt", g_master_ip);
			sprintf(temp_path, "%s/backend_table.txt", g_data_path);
			sprintf(temp_path1, "%s/backend_table.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				processing_engine_transfer_backend_table(temp_path, temp_path1);
				file_operation_broadcast(temp_path1, "data/delivery/gateway_dispatch.txt");
				sprintf(command_string, "gateway_dispatch.hook backends reload");
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}

		if ('1' == g_mask_string[INDEX_DNS_TABLE]) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?dns_table.txt", g_master_ip);
			sprintf(temp_path, "%s/dns_table.txt", g_data_path);
			sprintf(temp_path1, "%s/dns_table.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				processing_engine_transfer_dns_table(temp_path, temp_path1);
				file_operation_broadcast(temp_path1, "data/delivery/dns_adaptor.txt");
				sprintf(command_string, "dns_adaptor.svc reload fixed");
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}
		
		if ('1' == g_mask_string[INDEX_FORWARD_TABLE]) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?forward_table.txt", g_master_ip);
			sprintf(temp_path, "%s/forward_table.txt", g_data_path);
			sprintf(temp_path1, "%s/forward_table.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				processing_engine_transfer_forward_table(temp_path, temp_path1);
				file_operation_broadcast(temp_path1, "data/delivery/mail_forwarder.txt");
				sprintf(command_string, "mail_forwarder.hook reload");
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}

		if ('1' == g_mask_string[INDEX_FROM_REPLACE]) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?from_replace.txt", g_master_ip);
			sprintf(temp_path, "%s/from_replace.txt", g_data_path);
			sprintf(temp_path1, "%s/from_replace.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				processing_engine_transfer_from_replace(temp_path, temp_path1);
				file_operation_broadcast(temp_path1, "data/delivery/from_replace.txt");
				sprintf(command_string, "from_replace.hook reload");
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}

		if ('1' == g_mask_string[INDEX_DOMAIN_MAILBOX]) {
			sprintf(temp_url, "http://%s/cgi-bin/synchronization_rpc?domain_mailbox.txt", g_master_ip);
			sprintf(temp_path, "%s/domain_mailbox.txt", g_data_path);
			sprintf(temp_path1, "%s/domain_mailbox.txt.tmp", g_data_path);
			if (TRUE == url_downloader_get(temp_url, temp_path1) &&
				FILE_COMPARE_DIFFERENT == file_operation_compare(
				temp_path, temp_path1)) {
				remove(temp_path);
				link(temp_path1, temp_path);
				remove(temp_path1);
				processing_engine_transfer_domain_mailbox(temp_path, temp_path1);
				file_operation_broadcast(temp_path1, "data/delivery/domain_mailbox.txt");
				sprintf(command_string, "domain_mailbox.hook reload");
				gateway_control_notify(command_string, NOTIFY_DELIVERY);
			}
		}
	}
}

static void processing_engine_clear_sessions()
{
	key_t k_shm;
	int i, shm_id;
	int j, item_num;
	char *pitem;
	char *shm_begin;
	char list_path[256];
	LIST_FILE *pfile;

	k_shm = ftok(g_shm_path, TOKEN_SESSION);
	if (-1 == k_shm) {
		return;
	}
	shm_id = shmget(k_shm, ACL_CAPACITY*(32+sizeof(time_t)+16+256), 0666);
	if (-1 == shm_id) {
		return;
	}
	shm_begin = shmat(shm_id, NULL, 0);
	if (NULL == shm_begin) {
		return;
	}
	sprintf(list_path, "%s/system_users.txt", g_data_path);
	pfile = list_file_init(list_path, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		shmdt(shm_begin);
		return;
	}
	pitem = list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	for (i=0; i<ACL_CAPACITY; i++) {
		for (j=0; j<item_num; j++) {
			if (0 == strcasecmp(pitem + 3*256*j, shm_begin + i * (32 + 
				sizeof(time_t) + 16 + 256) + 32 + sizeof(time_t) + 16)) {
				break;
			}
			if (j == item_num) {
				*(shm_begin + i * (32 + sizeof(time_t) + 16 + 256)) = '\0';
			}
		}
	}
	shmdt(shm_begin);
	list_file_free(pfile);
}

static void processing_engine_restart_web_adaptor()
{
	int ctrl_id;
	key_t k_ctrl;
	long ctrl_type;

	k_ctrl = ftok(g_control_path, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		return;
	}
	ctrl_id = msgget(k_ctrl, 0666);
	if (-1 == ctrl_id) {
		return;
	}
	ctrl_type = CTRL_RESTART_WEBADAPTOR;
	msgsnd(ctrl_id, &ctrl_type, 0, IPC_NOWAIT);
}

static void processing_engine_transfer_backend_table(char *src_file, char *dst_file)
{
	char *pitem;
	char temp_line[256];
	LIST_FILE *pfile;
	int i, fd, len, item_num;
	
	pfile = list_file_init(src_file, "%s:16%s:256%d");
	if (NULL == pfile) {
		return;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s:%d\n",
				pitem + i * (16 + 256 + sizeof(int)),
				*(int*)(pitem + i * (16 + 256 + sizeof(int)) + 16 + 256));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
}

static void processing_engine_transfer_dns_table(char *src_file, char *dst_file)
{
	char *pitem;
	char temp_line[1024];
	LIST_FILE *pfile;
	int i, fd, len, item_num;
	
	pfile = list_file_init(src_file, "%s:256%s:8%s:256");
	if (NULL == pfile) {
		return;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t%s\t%s\n",
				pitem + i * (2 * 256 + 8) + 256,
				pitem + i * (2 * 256 + 8),
				pitem + i * (2 * 256 + 8) + 256 + 8);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
}

static void processing_engine_transfer_forward_table(char *src_file, char *dst_file)
{
	char *pitem;
	char temp_line[1024];
	LIST_FILE *pfile;
	int i, fd, len, item_num;
	
	pfile = list_file_init(src_file, "%s:256%s:12%s:256");
	if (NULL == pfile) {
		return;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "F_%s\t%s\t%s\n",
				pitem + i * (2 * 256 + 12) + 256,
				pitem + i * (2 * 256 + 12),
				pitem + i * (2 * 256 + 12) + 256 + 12);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
}

static void processing_engine_transfer_backup_list(char *src_file, char *dst_file)
{
	char *pitem;
	char temp_line[1024];
	LIST_FILE *pfile;
	int i, fd, len, item_num;
	
	pfile = list_file_init(src_file, "%s:256%d");
	if (NULL == pfile) {
		return;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\n", pitem + i * (256 + sizeof(int)));
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
}

static void processing_engine_transfer_from_replace(char *src_file, char *dst_file)
{
	char *pitem;
	char temp_line[1024];
	LIST_FILE *pfile;
	int i, fd, len, item_num;
	
	pfile = list_file_init(src_file, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t%s\n",
				pitem + 3*256*i, pitem + 3*256*i + 256);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
}

static void processing_engine_transfer_domain_mailbox(char *src_file, char *dst_file)
{
	char *pitem;
	char temp_line[1024];
	LIST_FILE *pfile;
	int i, fd, len, item_num;
	
	pfile = list_file_init(src_file, "%s:256%s:256%s:256");
	if (NULL == pfile) {
		return;
	}
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
	if (-1 == fd) {
		return;
	}
	item_num = list_file_get_item_num(pfile);
	pitem = list_file_get_list(pfile);
	for (i=0; i<item_num; i++) {
		len = sprintf(temp_line, "%s\t%s\n",
				pitem + 3*256*i, pitem + 3*256*i + 256);
		write(fd, temp_line, len);
	}
	close(fd);
	list_file_free(pfile);
}

