// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  string filter which take the string and check if it is exist in the 
 *  white or black list, otherwise we let it pass the audit filter sub 
 *  module that assure the string will not occur too many times within
 *  specified interval
 *
 */
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libHX/string.h>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/util.hpp>
#include "user_filter.hpp"

using namespace gromox;

enum{
	STR_FILTER_TEMP_DENY,
	STR_FILTER_GREY_ALLOW,
	STR_FILTER_GREY_DENY,
	STR_FILTER_AUDIT_DENY,
	STR_FILTER_NOT_HIT
};

static char g_module_name[256];

/*
 *  includes two parts
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
void str_filter_init(const char *module_name,
	BOOL case_sensitive, int audit_num, int audit_interval, int audit_times,
	int temp_list_size, const char *list_path, int growing_num) 
{
	gx_strlcpy(g_module_name, module_name, std::size(g_module_name));
    audit_filter_init(case_sensitive, audit_num, audit_interval, audit_times);
    grey_list_init(case_sensitive, list_path, growing_num);
    temp_list_init(case_sensitive, temp_list_size);
}

void str_filter_free()
{
    grey_list_free();
    temp_list_free();
}

int str_filter_run()
{
    if (0 != grey_list_run()) {
		str_filter_echo("failed to run grey list");
        return -1;
    }
    if (0 != temp_list_run()) {
		str_filter_echo("failed to run temporary list");
        audit_filter_stop();
        return -3;
    }

    return 0;
}

void str_filter_stop() 
{
    audit_filter_stop();
}

/*
 *  judge if string can pass
 *  @param
 *		str				string
 *  @return  
 *		TRUE			OK pass
 *		FALSE			cannot pass
 */                                                                                        
BOOL str_filter_judge(const char *str)
{
	if (temp_list_query(str))
		return FALSE;
    switch (grey_list_query(str, TRUE)) {
    case GREY_LIST_ALLOW:
        return TRUE;
    case GREY_LIST_DENY:
        return FALSE;
    case GREY_LIST_NOT_FOUND:
		return audit_filter_judge(str);
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
BOOL str_filter_query(const char *str)
{	
	if (temp_list_query(str))
		return TRUE;
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
 *  add one string into temporary string table
 *  @param
 *		str [in]	string
 *		interval	interval
 *	@return
 *		TRUE		OK
 *		FALSE		fail
 */
BOOL str_filter_add_string_into_temp_list(const char *str, int interval)
{
    return temp_list_add_string(str, interval);
}

void str_filter_echo(const char *format, ...)
{
	char msg[256];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, format);
	vsprintf(msg, format, ap);
	va_end(ap);
	mlog(LV_ERR, "%s: %s", g_module_name, msg);
}
