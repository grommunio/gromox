/*
 *  string filter which take the string and check if it is exist in the 
 *  white or black list, otherwise we let it pass the audit filter sub 
 *  module that assure the string will not occur too many times within
 *  specified interval
 *
 */
#include <stdlib.h>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include "common_types.h"
#include "config_file.h"
#include "str_filter.h"
#include "audit_filter.h"
#include "grey_list.h"
#include "temp_list.h"
#include "util.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

enum{
	STR_FILTER_TEMP_DENY,
	STR_FILTER_GREY_ALLOW,
	STR_FILTER_GREY_DENY,
	STR_FILTER_AUDIT_DENY,
	STR_FILTER_NOT_HIT
};

static int str_filter_search(char* str); 

static char g_module_name[256];
static char g_config_path[256];

/*
 *  string filter's construction function, it includes two parts 
 *  --- blacklist and auditing list
 *  @param 
 *      case_sensitive      is filter case-sensitive?
 *      config_path [in]	config file path
 *      audit_num           number of string to audit
 *      audit_interval      allowing interval for an string
 *      audit_times         during the interval, times of string
 *      temp_list_size		size of temp list
 *      list_path [in]		grey list file path
 */
void str_filter_init(const char *module_name, const char *config_path,
	BOOL case_sensitive, int audit_num, int audit_interval, int audit_times,
	int temp_list_size, const char *list_path, int growing_num) 
{
	strcpy(g_module_name, module_name);
	strcpy(g_config_path, config_path);
    audit_filter_init(case_sensitive, audit_num, audit_interval, audit_times);
    grey_list_init(case_sensitive, list_path, growing_num);
    temp_list_init(case_sensitive, temp_list_size);
}


/*
 *  string filter's destruction function
 */
void str_filter_free()
{
    grey_list_free();
    audit_filter_free();
    temp_list_free();
}

/*
 *  run string filter module
 *  @return  
 *      0       success
 *      <>0     fail
 */
int str_filter_run()
{
    if (0 != grey_list_run()) {
		str_filter_echo("failed to run grey list");
        return -1;
    }
    
    /* initialize the audit-list filter */
    if (0 != audit_filter_run()) {
		str_filter_echo("failed to run audit");
        grey_list_stop();
        return -2;
    }
    if (0 != temp_list_run()) {
		str_filter_echo("failed to run temporary list");
        grey_list_stop();
        audit_filter_stop();
        return -3;
    }

    return 0;
}

/*
 *  stop the string filter
 *  @return  
 *      0       success
 *      <>0     fail
 *
 */
int str_filter_stop() 
{
    grey_list_stop();
    audit_filter_stop();
    temp_list_stop();
   
    return 0;
}


/*
 *  judge if string can pass
 *  @param
 *		str				string
 *  @return  
 *		TRUE			OK pass
 *		FALSE			cannot pass
 */                                                                                        
BOOL str_filter_judge(char* str) 
{
    if (TRUE == temp_list_query(str)) {
        return FALSE;
    }
    switch (grey_list_query(str, TRUE)) {
    case GREY_LIST_ALLOW:
        return TRUE;
    case GREY_LIST_DENY:
        return FALSE;
    case GREY_LIST_NOT_FOUND:
		if (TRUE == audit_filter_judge(str)) {
			return TRUE;
		} else {
			return FALSE;
		}
    }
    return TRUE;
}

/*
 *  query if string is in, do not audit string
 *  @param
 *		str				string
 *  @return  
 *		TRUE			string is in filter
 *		FALSE			string is not in filter
 */                                                                                        
BOOL str_filter_query(char* str) 
{	
    if (TRUE == temp_list_query(str)) {
        return TRUE;
    }
    switch (grey_list_query(str, FALSE)) {
    case GREY_LIST_ALLOW:
        return FALSE;
    case GREY_LIST_DENY:
        return TRUE;
    case GREY_LIST_NOT_FOUND:
		return audit_filter_query(str);
    }
    return FALSE;
}

/*
 *  search string in filter
 *  @param
 *		str				string
 *  @return  
 *		STR_FILTER_TEMP_DENY
 *		STR_FILTER_GREY_ALLOW
 *		STR_FILTER_GREY_DENY
 *		STR_FILTER_AUDIT_DENY
 *		STR_FILTER_NOT_HIT
 */                                                                                        
static int str_filter_search(char* str) 
{
    if (TRUE == temp_list_query(str)) {
        return STR_FILTER_TEMP_DENY;
    }
    switch (grey_list_query(str, FALSE)) {
    case GREY_LIST_ALLOW:
        return STR_FILTER_GREY_ALLOW;
    case GREY_LIST_DENY:
        return STR_FILTER_GREY_DENY;
	}
	if (TRUE == audit_filter_query(str)) {
		return STR_FILTER_AUDIT_DENY;
	}
	return STR_FILTER_NOT_HIT;
}

/*
 *  add one string into temporary string table
 *  @param
 *		str [in]	string
 *		interval	interval
 *	@return
 *		TRUE		OK
 *		FALSE		fail
 */
BOOL str_filter_add_string_into_temp_list(char *str, int interval)
{
    return temp_list_add_string(str, interval);
}

/*
 *	console talk for string filter service plugin
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments array
 *		result [out]	buffer for retriving result
 *		length			result buffer length
 */
void str_filter_console_talk(int argc, char **argv, char *result, int length)
{
	int audit_times, audit_interval, audit_capability;
	int grey_times, grey_interval;
	int temp_interval, offset;
	time_t first_access, last_access;
	time_t until_time;
	struct tm time_buff;
	char first_time[64];
	char last_time[64];
	char *pslash;
	CONFIG_FILE *pconfig;
	char help_string[] = "250 string filter help information:\r\n"
						 "\t%s search <string>\r\n"
						 "\t    --search string in string filter\r\n"
						 "\t%s audit info\r\n"
						 "\t    --print the audit information\r\n"
		                 "\t%s audit set <times/interval>\r\n"
		                 "\t    --set the audit parameters\r\n"
						 "\t%s audit remove <string>\r\n"
						 "\t    --remove string from audit\r\n"
		                 "\t%s audit echo <string>\r\n"
		                 "\t    --print string information in audit\r\n"
		                 "\t%s audit dump <path>\r\n"
		                 "\t    --dump strings in audit to file\r\n"
		                 "\t%s grey-list reload\r\n"
		                 "\t    --reload the grey list table\r\n"
		                 "\t%s grey-list add <string> <times/interval>\r\n"
		                 "\t    --add string into grey list\r\n"
		                 "\t%s grey-list remove <string>\r\n"
		                 "\t    --remove string from grey list\r\n"
		                 "\t%s grey-list echo <string>\r\n"
		                 "\t    --printf string information in grey list\r\n"
		                 "\t%s grey-list dump <path>\r\n"
		                 "\t    --dump strings in grey list to file\r\n"
						 "\t%s temp-list add <string> <interval>\r\n"
						 "\t    --add string into temporary list\r\n"
		                 "\t%s temp-list remove <string>\r\n"
		                 "\t    --remove string from temporary list\r\n"
		                 "\t%s temp-list echo <string>\r\n"
		                 "\t    --print string information in temporary list\r\n"
		                 "\t%s temp-list dump <path>\r\n"
		                 "\t    --dump strings in temporary list to file";
	
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
		switch (str_filter_search(argv[2])) {
		case STR_FILTER_TEMP_DENY:
			snprintf(result, length, "250 %s is found in temporary list",
				argv[2]);
			return;
		case STR_FILTER_GREY_ALLOW:
			snprintf(result, length, "250 %s is allowed by grey list", argv[2]);
			return;
		case STR_FILTER_GREY_DENY:
			snprintf(result, length, "250 %s is denied by grey list", argv[2]);
			return;
		case STR_FILTER_AUDIT_DENY:
			snprintf(result, length, "250 %s is found in audit", argv[2]);
			return;
		case STR_FILTER_NOT_HIT:
			snprintf(result, length, "550 cannot find %s in string filter",
				argv[2]);
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
			if (TRUE == audit_filter_remove_string(argv[3])) {
				snprintf(result, length, "250 %s is remove from audit",
					argv[3]);
			} else {
				snprintf(result, length,"550 fail to remove %s from audit",
					argv[3]);
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
			if (FALSE == audit_filter_echo(argv[3], &first_access,
				&last_access, &audit_times)) {
				snprintf(result, length, "550 %s is not in audit", argv[3]);	
			} else {
				strftime(first_time, 64, "%Y/%m/%d %H:%M:%S",
					localtime_r(&first_access, &time_buff));
				strftime(last_time, 64, "%Y/%m/%d %H:%M:%S",
					localtime_r(&last_access, &time_buff));
				snprintf(result, length, "250 %s is in audit, first access time"
					" is %s, last access time is %s, access audit %d times",
					argv[3], first_time, last_time, audit_times);
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
			if (TRUE == grey_list_add_string(argv[3], grey_times,
				grey_interval)) {
				snprintf(result, length, "250 %s is added into grey list",
					argv[3]);
			} else {
				snprintf(result, length, "550 fail to add %s into grey list",
					argv[3]);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("remove", argv[2])) {
			if (TRUE == grey_list_remove_string(argv[3])) {
				snprintf(result, length, "250 %s is removed from grey list",
					argv[3]);
			} else {
				snprintf(result, length, "550 fail to remove %s from grey list",
					argv[3]);
			}
			return;
		}
		if (4 == argc && 0 == strcmp("echo", argv[2])) {
			if (FALSE == grey_list_echo(argv[3], &grey_times, &grey_interval)) {
				if (0 == grey_times && 0 == grey_interval) {
					snprintf(result, length, "550 %s is not found in grey list",
						argv[3]);
				} else {
					offset = gx_snprintf(result, length, "250 %s is found in grey "
						"list and it is allowed, original frequency is %d times"
						" within ", argv[3], grey_times);
					itvltoa(grey_interval, result + offset);
				}
			} else {
				offset = gx_snprintf(result, length, "250 %s is in grey list, and "
					"it is forbidden, original frequency is %d times within ",
					argv[3], grey_times);
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
			if (TRUE == temp_list_remove_string(argv[3])) {
				snprintf(result, length, "250 %s is removed from "
					"temporary list", argv[3]);
			} else {
				snprintf(result, length, "550 fail to remove %s from "
					"temporary list", argv[3]);
			}
			return;
		}
		if (5 == argc && 0 == strcmp(argv[2], "add")) {
			temp_interval = atoitvl(argv[4]);
			if (temp_interval <= 0) {
				snprintf(result, length, "550 %s is illegal", argv[4]);
				return;
			}
			if (TRUE == temp_list_add_string(argv[3], temp_interval)) {
				snprintf(result, length, "250 %s is added into temporary list",
					argv[3]);
			} else {
				snprintf(result, length, "550 fail to add %s into temporary "
					"list", argv[3]);
			}				
			return;
		}
		if (4 == argc && 0 == strcmp(argv[2], "echo")) {
			if (TRUE == temp_list_echo(argv[3], &until_time)) {
				strftime(last_time, 64, "%Y/%m/%d %H:%M:%S",
					localtime_r(&until_time, &time_buff));
				snprintf(result, length, "250 %s will be in temporary list till"
					" %s", argv[3], last_time);
			} else {
				snprintf(result, length, "550 %s is not found in temporary "
					"list", argv[3]);
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

void str_filter_echo(const char *format, ...)
{
	char msg[256];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, format);
	vsprintf(msg, format, ap);
	va_end(ap);
	printf("[%s]: %s\n", g_module_name, msg);

}

