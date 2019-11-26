#include <unistd.h>
#include "config_file.h"
#include "multiple_retrying.h"
#include "retrying_table.h"
#include "proxy_retrying.h"
#include "stub_retrying.h"
#include "util.h"
#include <stdio.h>

static char g_config_path[256];

void multiple_retrying_init(const char *config_path, const char *list_path,
	int table_size, int min_interval, int valid_interval, int port,
	int time_out, int ping_interval, int channel_num)
{
	strcpy(g_config_path, config_path);
	retrying_table_init(table_size, min_interval, valid_interval);
	proxy_retrying_init(list_path, port, time_out, ping_interval, channel_num);
	stub_retrying_init(list_path, port, time_out, channel_num);
}

int multiple_retrying_run()
{
	if (0 != retrying_table_run()) {
		printf("[multiple_retrying]: fail to run the module retrying table\n");
		return -1;
	}
	if (0 != stub_retrying_run()) {
		printf("[multiple_retrying]: fail to run the module stub retrying\n");
		return -2;
	}
	if (0 != proxy_retrying_run()) {
		printf("[multiple_retrying]: fail to run the module proxy retrying\n");
		return -3;
	}
	return 0;
}

int multiple_retrying_stop()
{
	retrying_table_stop();
	stub_retrying_stop();
	proxy_retrying_stop();
	return 0;
}

void multiple_retrying_free()
{
	retrying_table_free();
	stub_retrying_free();
	proxy_retrying_free();
}

BOOL multiple_retrying_writeline_timeout(int sockd, const char *buff,
	int time_out)
{
	int write_len;
	int offset, length;
	time_t first_time;
	time_t last_time;
	char temp_line[1024];
	
	offset = 0;
	length = strlen(buff);
	if (length > 1000) {
		return FALSE;
	}
	memcpy(temp_line, buff, length);
	temp_line[length ++] = '\r';
	temp_line[length ++] = '\n';
	time(&first_time);
	
	while (TRUE) {
		write_len = write(sockd, temp_line + offset, length - offset);
		if (-1 == write_len) {
			write_len = 0;
		}
		offset += write_len;
		if (offset == length) {
			return TRUE;
		}
		time(&last_time);
		if (last_time - first_time > time_out) {
			return FALSE;
		}
		usleep(5000);
	}
}

BOOL multiple_retrying_readline_timeout(int sockd, char *buff, int length,
	int time_out)
{
	int offset;
	int temp_len;
	int i, read_len;
	time_t first_time;
	time_t last_time;
	char temp_line[1024];

	offset = 0;
	time(&first_time);
	while (TRUE) {
		read_len = read(sockd, temp_line, 1024 - offset);
		if (-1 == read_len) {
			read_len = 0;
		}
		offset += read_len;
		for (i=0; i<offset; i++) {
			if ('\r' == temp_line[i] && '\n' == temp_line[i + 1]) {
				temp_len = (i < length - 1) ? i : length - 1;
				memcpy(buff, temp_line, temp_len);
				buff[temp_len] = '\0';
				return TRUE;
			}
		}
		time(&last_time);
		if (last_time - first_time > time_out || 1024 == offset) {
			return FALSE;
		}
		usleep(5000);
	}
}


/*
 *  retrying table's console talk
 *  @param
 *      argc            arguments number
 *      argv [in]       arguments value
 *      result [out]    buffer for retrieving result
 *      length          result buffer length
 */
void multiple_retrying_console_talk(int argc, char **argv,
	char *result, int length)
{
	CONFIG_FILE *pfile;
	int len, interval;
	char help_string[] = "250 retrying table help information:\r\n"
			             "\t%s info\r\n"
						 "\t    --print the retrying table information\r\n"
						 "\t%s set min-interval <interval>\r\n"
						 "\t    --set minimum interval of retying table\r\n"
						 "\t%s set valid-interval <interval>\r\n"
						 "\t    --set valid interval of retrying table\r\n"
						 "\t%s set time-out <interval>\r\n"
						 "\t    --set time-out of connection\r\n"
						 "\t%s set ping-interval <interval>\r\n"
						 "\t    --set ping interval of connection";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
			argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		len = snprintf(result, length,
			"250 retrying table information:\r\n"
			"\ttable capacity      %d\r\n"
			"\tcurrent used        %d\r\n"
			"\tminimum interval    ",
			retrying_table_get_param(RETRYING_TABLE_TABLE_SIZE),
			retrying_table_get_valid());
		itvltoa(retrying_table_get_param(RETRYING_TABLE_MIN_INTERVAL),
			result + len);
		len += strlen(result + len);
		memcpy(result + len, "\r\n\tvalid interval      ", 23);
		len += 23;
		itvltoa(retrying_table_get_param(RETRYING_TABLE_MAX_INTERVAL),
			result + len);
		len += strlen(result + len);
		memcpy(result + len, "\r\n\ttime-out            ", 23);
		len += 23;
		itvltoa(proxy_retrying_get_param(PROXY_RETRYING_TIME_OUT),
			result + len);
		len += strlen(result + len);
		memcpy(result + len, "\r\n\tping interval       ", 23);
		len += 23;
		itvltoa(proxy_retrying_get_param(PROXY_RETRYING_PING_INTERVAL),
			result + len);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("min-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
			return;
		}
		if (interval > retrying_table_get_param(RETRYING_TABLE_MAX_INTERVAL)) {
			snprintf(result, length, "550 %s is larger than valid "
				"interval", argv[3]);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 fail to open config file", length);
			return;
		}
		config_file_set_value(pfile, "MINIMUM_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		retrying_table_set_param(RETRYING_TABLE_MIN_INTERVAL, interval);
		strncpy(result, "250 minimum interval set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("valid-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
			return;
		}
		if (interval < retrying_table_get_param(RETRYING_TABLE_MIN_INTERVAL)) {
			snprintf(result, length, "550 %s is less than valid "
				"interval", argv[3]);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 fail to open config file", length);
			return;
		}
		config_file_set_value(pfile, "VALID_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		retrying_table_set_param(RETRYING_TABLE_MAX_INTERVAL, interval);
		strncpy(result, "250 valid interval set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("time-out", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
			return;
		}
		if (interval <= proxy_retrying_get_param(
			PROXY_RETRYING_PING_INTERVAL)) {
			len = snprintf(result, length, "550 time-out value must be larger "
					"than ping interval ");
			itvltoa(proxy_retrying_get_param(PROXY_RETRYING_PING_INTERVAL),
				result + len);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 fail to open config file", length);
			return;
		}
		config_file_set_value(pfile, "TIME_OUT", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		proxy_retrying_set_param(PROXY_RETRYING_TIME_OUT, interval);
		if (interval > proxy_retrying_get_param(PROXY_RETRYING_UNIT_NUM) *
			proxy_retrying_get_param(PROXY_RETRYING_CHANNEL_NUM)) {
			stub_retrying_set_param(STUB_RETRYING_WAIT_INTERVAL, interval);
		} else {
			stub_retrying_set_param(STUB_RETRYING_WAIT_INTERVAL,
				proxy_retrying_get_param(PROXY_RETRYING_UNIT_NUM) *
				proxy_retrying_get_param(PROXY_RETRYING_CHANNEL_NUM));
		}
		strncpy(result, "250 time-out set OK", length);
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("ping-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			snprintf(result, length, "550 %s is illegal", argv[3]);
			return;
		}
		if (interval >= proxy_retrying_get_param(PROXY_RETRYING_TIME_OUT)) {
			len = snprintf(result, length, "550 ping interval must be less "
					"than time-out ");
			itvltoa(proxy_retrying_get_param(PROXY_RETRYING_TIME_OUT),
				result + len);
			return;
		}
		pfile = config_file_init(g_config_path);
		if (NULL == pfile) {
			strncpy(result, "550 fail to open config file", length);
			return;
		}
		config_file_set_value(pfile, "PING_INTERVAL", argv[3]);
		if (FALSE == config_file_save(pfile)) {
			strncpy(result, "550 fail to save config file", length);
			config_file_free(pfile);
			return;
		}
		config_file_free(pfile);
		proxy_retrying_set_param(PROXY_RETRYING_PING_INTERVAL, interval);
		strncpy(result, "250 ping interval set OK", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

