// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/svc_common.h>
#include "codepage_lang.h"
#include <cstdio>
#include <cstring>

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char tmp_path[256];
	char file_name[256];
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(tmp_path, "%s/%s.txt", get_data_path(), file_name);
		codepage_lang_init(tmp_path);
		if (0 != codepage_lang_run()) {
			printf("[codepage_lang]: failed to run the module\n");
			return FALSE;
		}
		if (!register_service("get_lang", reinterpret_cast<void *>(codepage_lang_get_lang))) {
			printf("[codepage_lang]: failed to register \"get_lang\" service\n");
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
