/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <errno.h>
#include "resource.h"
#include "config_file.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_FILE_NAME_LEN       256
#define MAX_FILE_LINE_LEN       1024

const struct da_resource_string g_string_table[MAX_RES_CONFG_VAR_NUM] = {
	{RES_HOST_ID, "HOST_ID"},
	{RES_DEFAULT_DOMAIN, "DEFAULT_DOMAIN"},
	{RES_RUNNING_IDENTITY, "RUNNING_IDENTITY"},
	{RES_DOMAIN_LIST_VALID, "DOMAIN_LIST_VALID"},

	{RES_DEQUEUE_PATH, "DEQUEUE_PATH"},
	{RES_DEQUEUE_TAPE_SIZE, "DEQUEUE_TAPE_SIZE"},
	{RES_DEQUEUE_MAXIMUM_MEM, "DEQUEUE_MAXIMUM_MEM"},

	{RES_MPC_PLUGIN_PATH, "MPC_PLUGIN_PATH"},
	{RES_WORK_THREADS_MIN, "WORK_THREADS_MIN"},
	{RES_WORK_THREADS_MAX, "WORK_THREADS_MAX"},
	{RES_FREE_CONTEXT_NUM, "FREE_CONTEXT_NUM"},
	{RES_CONTEXT_AVERAGE_MIME, "CONTEXT_AVERAGE_MIME"},

	{RES_CONSOLE_SERVER_IP, "CONSOLE_SERVER_IP"},
	{RES_CONSOLE_SERVER_PORT, "CONSOLE_SERVER_PORT"},

	{RES_ADMIN_MAILBOX, "ADMIN_MAILBOX"},
	{RES_SERVICE_PLUGIN_PATH, "SERVICE_PLUGIN_PATH"},
	{RES_CONFIG_FILE_PATH, "CONFIG_FILE_PATH"},
	{RES_DATA_FILE_PATH, "DATA_FILE_PATH"},
};

/* private global variables */
static char g_cfg_filename[MAX_FILE_NAME_LEN];
static CONFIG_FILE *g_config_file;

void resource_init(const char *cfg_filename)
{
    strcpy(g_cfg_filename, cfg_filename);
}

void resource_free()
{   
    /* to avoid memory leak because of not stop */
    if (NULL != g_config_file) {
        config_file_free(g_config_file);
        g_config_file = NULL;
    }
}

int resource_run()
{
    g_config_file = config_file_init(g_cfg_filename);

    if (NULL == g_config_file) {
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
		debug_info("[resource]: error!!! config file not init or init fail but"
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
BOOL resource_get_integer(int key, int* value)
{
    char *pvalue    = NULL;     /* string value of the mapped key */

    if ((key < 0 || key > MAX_RES_CONFG_VAR_NUM) && NULL != value) {
        debug_info("[resource]: invalid param resource_get_integer");
        return FALSE;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return FALSE;
    }
    pvalue = config_file_get_value(g_config_file, 
        g_string_table[key].name);

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

BOOL resource_set_integer(int key, int value)
{
    char m_buf[32];             /* buffer to hold the int string  */

    if ((key < 0 || key > MAX_RES_CONFG_VAR_NUM)) {
        debug_info("[resource]: invalid param in resource_set_integer");
        return FALSE;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return FALSE;
    }
    itoa(value, m_buf, 10);
    return config_file_set_value(g_config_file, 
				g_string_table[key].name, m_buf);
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
BOOL resource_set_string(int key, const char *value)
{

    if (key < 0 || key > MAX_RES_CONFG_VAR_NUM || NULL == value) {
        debug_info("[resource]: invalid param in resource_set_string");
        return FALSE;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return FALSE;
    }

    return config_file_set_value(g_config_file,
				g_string_table[key].name, value);
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

const char* resource_get_string(int key)
{
    const char *pvalue  = NULL;     /* string value of the mapped key */

    if ((key < 0 || key > MAX_RES_CONFG_VAR_NUM) && NULL != pvalue) {
        debug_info("[resource]: invalid param in resource_get_string");
        return NULL;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return NULL;
    }

    pvalue = config_file_get_value(g_config_file, g_string_table[key].name);

    if (NULL == pvalue) {
        debug_info("[resource]: no value map to the key in "
                    "resource_get_string");
        return NULL;
    }
    return pvalue;
}

