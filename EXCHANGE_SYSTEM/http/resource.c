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
CONFIG_FILE *g_config_file;

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
