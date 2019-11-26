#include <stdbool.h>
#include "service_common.h"
#include "codepage_lang.h"
#include <stdio.h>
#include <string.h>

DECLARE_API;

static void console_talk(int argc, char **argv, char *result, int length);

BOOL SVC_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char tmp_path[256];
	char file_name[256];
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		if (FALSE == register_talk(console_talk)) {
			printf("[codepage_lang]: fail to register console talk\n");
			return FALSE;
		}
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		codepage_lang_init(tmp_path);
		if (0 != codepage_lang_run()) {
			printf("[codepage_lang]: fail to run the module\n");
			return FALSE;
		}
		if (FALSE == register_service("get_lang", codepage_lang_get_lang)) {
			printf("[codepage_lang]: fail to register \"get_lang\" service\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		codepage_lang_stop();
		codepage_lang_free();
		return TRUE;
	}
	return false;
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 codepage lang help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload list from file";
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}

	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		if (TRUE == codepage_lang_reload()) {
			strncpy(result, "250 reload list OK", length);
		} else {
			strncpy(result, "550 fail to reload list", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}
