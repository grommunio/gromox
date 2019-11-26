/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <errno.h>
#include <libHX/string.h>
#include "resource.h"
#include "config_file.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define MAX_FILE_LINE_LEN       1024

/* private global variables */
static char *g_cfg_filename, *g_cfg_filename2;
static CONFIG_FILE *g_config_file;

void resource_init(const char *c1, const char *c2)
{
	g_cfg_filename  = HX_strdup(c1);
	g_cfg_filename2 = HX_strdup(c2);
}

void resource_free()
{   
    /* to avoid memory leak because of not stop */
    if (NULL != g_config_file) {
        config_file_free(g_config_file);
        g_config_file = NULL;
    }
	free(g_cfg_filename);
	free(g_cfg_filename2);
	g_cfg_filename  = NULL;
	g_cfg_filename2 = NULL;
}

int resource_run()
{
	g_config_file = config_file_init2(g_cfg_filename, g_cfg_filename2);
	if (g_cfg_filename != NULL && g_config_file == NULL) {
		printf("[resource]: config_file_init %s: %s\n", g_cfg_filename, strerror(errno));
        return -1;
    }
    return 0;
}

int resource_stop()
{
    if (NULL != g_config_file) {
        config_file_free(g_config_file);
        g_config_file = NULL;
    }
    return 0;
}

BOOL resource_save()
{
	if (NULL == g_config_file) {
		debug_info("[resource]: error: config file not initialized or init failed, but"
                    " it is now being used");
		return FALSE;
	}
	return config_file_save(g_config_file);
}

/*
 *  get a specified integer value that match the key
 *
 *  @param
 *      key             key that describe the integer value
 *      value [out]     pointer to the integer value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
BOOL resource_get_integer(const char *key, int *value)
{
    char *pvalue    = NULL;     /* string value of the mapped key */

	if (key == NULL) {
        debug_info("[resource]: invalid param resource_get_integer");
        return FALSE;
    }

    if (NULL == g_config_file) {
		debug_info("[resource]: error: config file not initialized or init failed, but"
                    " it is now being used");
        return FALSE;
    }
	pvalue = config_file_get_value(g_config_file, key);
    if (NULL == pvalue) {
        debug_info("[resource]: no value map to the key in "
                    "resource_get_integer");
        return FALSE;
    }
    *value = atoi(pvalue);
    return TRUE;
}

/*
 *  set the specified integer that match the key
 *
 *  @param
 *      key             key that describe the integer value
 *      value           the new value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
BOOL resource_set_integer(const char *key, int value)
{
    char m_buf[32];             /* buffer to hold the int string  */

	if (key == NULL) {
        debug_info("[resource]: invalid param in resource_set_integer");
        return FALSE;
    }

    if (NULL == g_config_file) {
		debug_info("[resource]: error: config file not initialized or init failed, but"
                    " it is now being used");
        return FALSE;
    }
    itoa(value, m_buf, 10);
	return config_file_set_value(g_config_file, key, m_buf);
}

/*
 *  set the specified string that match the key
 *
 *  @param
 *      key             key that describe the string value
 *      value [out]     the string value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
BOOL resource_set_string(const char *key, const char *value)
{
	if (key == NULL) {
        debug_info("[resource]: invalid param in resource_set_string");
        return FALSE;
    }

    if (NULL == g_config_file) {
		debug_info("[resource]: error: config file not initialized or init failed, but"
                    " it is now being used");
        return FALSE;
    }
	return config_file_set_value(g_config_file, key, value);
}

/*
 *  get a specified string value that match the key
 *
 *  @param
 *      key             key that describe the string value
 *      value [out]     pointer to the string value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
const char *resource_get_string(const char *key)
{
    const char *pvalue  = NULL;     /* string value of the mapped key */

	if (key == NULL) {
        debug_info("[resource]: invalid param in resource_get_string");
        return NULL;
    }

    if (NULL == g_config_file) {
		debug_info("[resource]: error: config file not initialized or init failed, but"
                    " it is now being used");
        return NULL;
    }
	pvalue = config_file_get_value(g_config_file, key);
    if (NULL == pvalue) {
        debug_info("[resource]: no value map to the key in "
                    "resource_get_string");
        return NULL;
    }
    return pvalue;
}

