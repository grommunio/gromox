/*
 *  Connection filter which take the ip and check if it is exist in the 
 *  white or black list, otherwise we let it pass the audit filter sub 
 *  module that assure the connection will not connect too many times
 *  within the specified interval
 *
 */
#include <libHX/string.h>
#include <gromox/fileio.h>
#include "common_types.h"
#include "config_file.h"
#include "ip_filter.h"
#include "audit_filter.h"
#include "grey_list.h"
#include "temp_list.h"
#include "util.h"
#include "mail_func.h"
#include <stdio.h>
#include <stdarg.h>

enum{
	IP_FILTER_TEMP_DENY,
	IP_FILTER_GREY_ALLOW,
	IP_FILTER_GREY_DENY,
	IP_FILTER_AUDIT_DENY,
	IP_FILTER_NOT_HIT
};

static int ip_filter_search(char* ip); 

static char g_module_name[256];
static char g_config_path[256];

/*
 *  ip filter's construction function, it includes two parts 
 *  --- blacklist and auditing list
 *
 *  @param 
 *		config_path [in]    config file path
 *      audit_num           number of ip addresses to audit
 *      audit_interval      allowing interval for an IP
 *      audit_times         during the interval, times of IP
 *      temp_list_size		size of temp list
 *      list_path [in]			grey list file path
 */
void ip_filter_init(const char *module_name, const char *config_path,
	int audit_num, int audit_interval, int audit_times, int temp_list_size,
	const char *list_path, int growing_num) 
{
	strcpy(g_module_name, module_name);
	strcpy(g_config_path, config_path);
    audit_filter_init(audit_num, audit_interval, audit_times);
    grey_list_init(list_path, growing_num);
    temp_list_init(temp_list_size);
}


/*
 *  connections filter's destruction function
 */
void ip_filter_free()
{
    grey_list_free();
    audit_filter_free();
    temp_list_free();
}

/*
 *  make connection filter effect
 *
 *  @return  
 *      0       success
 *      <>0     fail
 */
int ip_filter_run()
{
    if (0 != grey_list_run()) {
		ip_filter_echo("failed to run grey list");
        return -1;
    }
    
    /* initialize the audit-list filter */
    if (0 != audit_filter_run()) {
		ip_filter_echo("failed to run audit");
        grey_list_stop();
        return -2;
    }
    if (0 != temp_list_run()) {
		ip_filter_echo("failed to run temporary list");
        grey_list_stop();
        audit_filter_stop();
        return -3;
    }

    return 0;
}

/*
 *  stop the connection filter
 *
 *  @return  
 *      0       success
 *      <>0     fail
 *
 */
int ip_filter_stop() 
{
    grey_list_stop();
    audit_filter_stop();
    temp_list_stop();
   
    return 0;
}


/*
 *  judge if ip can pass
 *  @param
 *		ip				ip address
 *  @return  
 *		TRUE			OK, pass
 *		FALSE			NO, can not pass
 */                                                                                        
BOOL ip_filter_judge(char* ip) 
{
	
    if (TRUE == temp_list_query(ip)) {
        return FALSE;
    }
    switch (grey_list_query(ip, TRUE)) {
    case GREY_LIST_ALLOW:
        return TRUE;
    case GREY_LIST_DENY:
        return FALSE;
    case GREY_LIST_NOT_FOUND:
		if (TRUE == audit_filter_judge(ip)) {
			return TRUE;
		} else {
			return FALSE;
		}
    }
    return TRUE;
}

/*
 *  query if ipaddr is in, do not audit IP address
 *  @param
 *		ip				ip address
 *  @return  
 *		TRUE			ipaddr is in filter
 *		FALSE			ipaddr is not in filter
 */                                                                                        
BOOL ip_filter_query(char* ip) 
{
    if (TRUE == temp_list_query(ip)) {
        return TRUE;
    }

    switch (grey_list_query(ip, FALSE)) {
    case GREY_LIST_ALLOW:
        return FALSE;
    case GREY_LIST_DENY:
        return TRUE;
    case GREY_LIST_NOT_FOUND:
		return audit_filter_query(ip);
    }
    return FALSE;
}

/*
 *  search ipaddr in filter
 *  @param
 *      ip             ip address
 *  @return
 *      IP_FILTER_TEMP_DENY
 *      IP_FILTER_GREY_ALLOW
 *      IP_FILTER_GREY_DENY
 *      IP_FILTER_AUDIT_DENY
 *      IP_FILTER_NOT_HIT
 */
static int ip_filter_search(char* ip)
{
	if (TRUE == temp_list_query(ip)) {
		return IP_FILTER_TEMP_DENY;
	}
	switch (grey_list_query(ip, FALSE)) {
	case GREY_LIST_ALLOW:
		return IP_FILTER_GREY_ALLOW;
	case GREY_LIST_DENY:
		return IP_FILTER_GREY_DENY;
	}
	if (TRUE == audit_filter_query(ip)) {
		return IP_FILTER_AUDIT_DENY;
	}
	return IP_FILTER_NOT_HIT;
}

/*
 *  add one ipaddr into temporary ip table
 *  @param
 *		ip [in]		ip address
 *		interval	interval
 *	@return
 *		TRUE		OK
 *		FALSE		fail
 */
BOOL ip_filter_add_ip_into_temp_list(char *ip, int interval)
{
    return temp_list_add_ip(ip, interval);
}

/*
 *	console talk for ip filter service plugin
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments array
 *		result [out]	buffer for retriving result
 *		length			result buffer length
 */
void ip_filter_console_talk(int argc, char **argv, char *result, int length)
{
	int audit_times, audit_interval, audit_capability;
	int grey_times, grey_interval;
	int temp_interval, offset;
	struct tm time_buff;
	time_t first_access, last_access;
	time_t until_time;
	char temp_ip[16];
	char first_time[64];
	char last_time[64];
	char *pslash;
	CONFIG_FILE *pconfig;
	char help_string[] = "250 ip filter help information:\r\n"
						 "\t%s search <ipaddr>\r\n"
						 "\t    --search ipaddr in ipaddr filter\r\n"
						 "\t%s audit info\r\n"
						 "\t    --print the audit information\r\n"
		                 "\t%s audit set <times/interval>\r\n"
		                 "\t    --set the audit parameters\r\n"
						 "\t%s audit remove <ipaddr>\r\n"
						 "\t    --remove ip from audit\r\n"
		                 "\t%s audit echo <ipaddr>\r\n"
		                 "\t    --print ipaddr information in audit\r\n"
		                 "\t%s audit dump <path>\r\n"
		                 "\t    --dump ips in audit to file\r\n"
		                 "\t%s grey-list reload\r\n"
		                 "\t    --reload the grey list table\r\n"
		                 "\t%s grey-list add <ipaddr> <times/interval>\r\n"
		                 "\t    --add ipaddr into grey list\r\n"
		                 "\t%s grey-list remove <ipaddr>\r\n"
		                 "\t    --remove ip from grey list\r\n"
		                 "\t%s grey-list echo <ipaddr>\r\n"
		                 "\t    --printf ipaddr information in grey list\r\n"
		                 "\t%s grey-list dump <path>\r\n"
		                 "\t    --dump ips in grey list to file\r\n"
						 "\t%s temp-list add <ipaddr> <interval>\r\n"
						 "\t    --add ipaddr into temporary list\r\n"
		                 "\t%s temp-list remove <ipaddr>\r\n"
		                 "\t    --remove ip from temporary list\r\n"
		                 "\t%s temp-list echo <ipaddr>\r\n"
		                 "\t    --print ipaddr information in temporary list\r\n"
		                 "\t%s temp-list dump <path>\r\n"
		                 "\t    --dump ips in temporary list to file";
	
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0],
				argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
				argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}
	if (3 == argc && 0 == strcmp("search", argv[1])) {
		if (NULL == extract_ip(argv[2], temp_ip)) {
			snprintf(result, length, "550 %s is not ip address", argv[2]);
			return;
		}
		switch (ip_filter_search(temp_ip)) {
		case IP_FILTER_TEMP_DENY:
			snprintf(result, length, "250 %s is found in temporary list",
				temp_ip);
			return;
		case IP_FILTER_GREY_ALLOW:
			snprintf(result, length, "250 %s is allowed by grey list",
				temp_ip);
			return;
		case IP_FILTER_GREY_DENY:
			snprintf(result, length, "250 %s is denied by grey list",
				temp_ip);
			return;
		case IP_FILTER_AUDIT_DENY:
			snprintf(result, length, "250 %s is found in audit",
				temp_ip);
			return;
		case IP_FILTER_NOT_HIT:
			snprintf(result, length, "550 cannot find %s in ip filter",
				temp_ip);
			return;
		}
	}
	if (0 == strcmp("audit", argv[1])) {
		if (3 == argc && 0 == strcmp("info", argv[2])) {
			audit_times      = audit_filter_get_param(AUDIT_TIMES);
			audit_interval   = audit_filter_get_param(AUDIT_INTERVAL);
			audit_capability = audit_filter_get_param(AUDIT_CAPABILITY);
			offset = gx_snprintf(result, length,
					"250 %s audit information:\r\n"
			        "\ttable capacity    %d\r\n"
			        "\ttimes             %d\r\n"
			        "\tinterval          ",
			        argv[0], audit_capability, audit_times);
			itvltoa(audit_interval, result + offset);
			return;
		}
		if (4 == argc && 0 == strcmp("remove", argv[2])) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			if (TRUE == audit_filter_remove_ip(temp_ip)) {
				snprintf(result, length, "250 %s is remove from audit",
					temp_ip);
			} else {
				snprintf(result, length,"550 fail to remove %s from audit",
					temp_ip);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("set", argv[2])) {
			HX_strrtrim(argv[3]);
			HX_strltrim(argv[3]);
			if (NULL == (pslash = strchr(argv[3], '/'))) {
				snprintf(result, length, "550 invalid argument %s should be "
						"times/interval", argv[3]);
				return;
			}
			*pslash = '\0';
			audit_times = atoi(argv[3]);
			audit_interval = atoitvl(pslash + 1);
			if (audit_interval <= 0) {
				snprintf(result, length,"550 %s is illegal", pslash + 1);
			}
			pconfig = config_file_init2(NULL, g_config_path);
			if (NULL == pconfig) {
				strncpy(result, "550 Failed to open config file", length);
				return;
			}
			config_file_set_value(pconfig, "AUDIT_TIMES", argv[3]);
			config_file_set_value(pconfig, "AUDIT_INTERVAL", pslash + 1);
			if (FALSE == config_file_save(pconfig)) {
				strncpy(result, "550 fail to save config file", length);
				config_file_free(pconfig);
				return;
			}
			config_file_free(pconfig);
			audit_filter_set_param(AUDIT_TIMES, audit_times);
			audit_filter_set_param(AUDIT_INTERVAL, audit_interval);
			strncpy(result, "250 audit set OK", length);
			return;
		}
		if (4 == argc && 0 == strcmp("echo", argv[2])) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			if (FALSE == audit_filter_echo(temp_ip, &first_access,
				&last_access, &audit_times)) {
				snprintf(result, length, "550 %s is not in audit", temp_ip);	
			} else {
				strftime(first_time, 64, "%Y/%m/%d %H:%M:%S",
					localtime_r(&first_access, &time_buff));
				strftime(last_time, 64, "%Y/%m/%d %H:%M:%S",
					localtime_r(&last_access, &time_buff));
				snprintf(result, length, "250 %s is in audit, first access time"
					" is %s, last access time is %s, access audit %d times",
					temp_ip, first_time, last_time, audit_times);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("dump", argv[2])) {
			if (FALSE == audit_filter_dump(argv[3])) {
				snprintf(result, length, "550 fail to dump audit");
			} else {
				snprintf(result, length, "250 audit dump OK");
			}
			return;
		}
    }
	if (0 == strcmp("grey-list", argv[1])) {
		if (3 == argc && 0 == strcmp("reload", argv[2])) {
			switch(grey_list_refresh()) {
			case GREY_REFRESH_OK:
				strncpy(result, "250 grey list reload OK", length);
				return;
			case GREY_REFRESH_FILE_ERROR:
				strncpy(result, "550 grey list file error", length);
				return;
			case GREY_REFRESH_HASH_FAIL:
				strncpy(result, "550 hash map error for grey list", length);
				return;
			}
		}
		if (5 == argc && 0 == strcmp("add", argv[2])) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			HX_strrtrim(argv[4]);
			HX_strltrim(argv[4]);
			if (NULL == (pslash = strchr(argv[4], '/'))) {
				snprintf(result, length, "550 invalid argument %s should be "
						"times/interval", argv[4]);
				return;
			}
			grey_times    = atoi(argv[4]);
			grey_interval = atoitvl(pslash + 1);
			if (grey_interval < 0) {
				snprintf(result, length,"550 %s is illegal", pslash + 1);
			}
			if (TRUE == grey_list_add_ip(temp_ip, grey_times,
				grey_interval)) {
				snprintf(result, length, "250 %s is added into grey list",
					temp_ip);
			} else {
				snprintf(result, length, "550 fail to add %s into grey list",
					temp_ip);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("remove", argv[2])) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			if (TRUE == grey_list_remove_ip(temp_ip)) {
				snprintf(result, length, "250 %s is removed from grey list",
					temp_ip);
			} else {
				snprintf(result, length, "550 fail to remove %s from grey list",
					temp_ip);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("echo", argv[2])) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			if (FALSE == grey_list_echo(temp_ip, &grey_times, &grey_interval)) {
				if (0 == grey_times && 0 == grey_interval) {
					snprintf(result, length, "550 %s is not found in grey list",
						temp_ip);
				} else {
					offset = gx_snprintf(result, length, "250 %s is found in grey "
						"list and it is allowed, original frequency is %d times"
						" within ", temp_ip, grey_times);
					itvltoa(grey_interval, result + offset);
				}
			} else {
				offset = gx_snprintf(result, length, "250 %s is in grey list, and "
					"it is forbidden, original frequency is %d times within ",
					temp_ip, grey_times);
				itvltoa(grey_interval, result + offset);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("dump", argv[2])) {
			if (FALSE == grey_list_dump(argv[3])) {
				snprintf(result, length, "550 fail to dump grey list");
			} else {
				snprintf(result, length, "250 grey list dump OK");
			}
			return;
		}
	}
	if (0 == strcmp(argv[1], "temp-list")) { 
		if (4 == argc && 0 == strcmp(argv[2], "remove")) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			if (TRUE == temp_list_remove_ip(temp_ip)) {
				snprintf(result, length, "250 %s is removed from "
					"temporary list", temp_ip);
			} else {
				snprintf(result, length, "550 fail to remove %s from "
					"temporary list", temp_ip);
			}
			return;
		}
		if (5 == argc && 0 == strcmp(argv[2], "add")) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			temp_interval = atoitvl(argv[4]);
			if (temp_interval <= 0) {
				snprintf(result, length, "550 %s is illegal", argv[4]);
				return;
			}
			if (TRUE == temp_list_add_ip(temp_ip, temp_interval)) {
				snprintf(result, length, "250 %s is added into temporary list",
					temp_ip);
			} else {
				snprintf(result, length, "550 fail to add %s into temporary "
					"list", temp_ip);
			}				
			return;
		}
		if (4 == argc && 0 == strcmp(argv[2], "echo")) {
			if (NULL == extract_ip(argv[3], temp_ip)) {
				snprintf(result, length, "550 %s is not ip address", argv[3]);
				return;
			}
			if (TRUE == temp_list_echo(temp_ip, &until_time)) {
				strftime(last_time, 64, "%Y/%m/%d %H:%M:%S",
					localtime_r(&until_time, &time_buff));
				snprintf(result, length, "250 %s will be in temporary list till"
					" %s", temp_ip, last_time);
			} else {
				snprintf(result, length, "550 %s is not found in temporary "
					"list", temp_ip);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("dump", argv[2])) {
			if (FALSE == temp_list_dump(argv[3])) {
				snprintf(result, length, "550 fail to dump temporary list");
			} else {
				snprintf(result, length, "250 temporary list dump OK");
			}
			return;
		}
	}
    snprintf(result, length, "550 invalid argument %s", argv[1]);
    return;
}

void ip_filter_echo(const char *format, ...)
{
	char msg[256];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, format);
	vsprintf(msg, format, ap);
	printf("[%s]: %s\n", g_module_name, msg);

}
