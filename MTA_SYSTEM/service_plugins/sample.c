#include <stdbool.h>
#include "service_common.h"
#include <stdio.h>
#include <string.h>

static void console_talk(int argc, char **argv, char *result, int length);

static void foo();

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	char tmp[256];
	int  i;
	
	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
        if (FALSE == register_talk(console_talk)) {
			printf("[sample]: fail to register console talk\n");
			return FALSE;
		}
		for (i=0; i<100; i++) {
			sprintf(tmp, "foo%d", i);
			if (FALSE == register_service(tmp, foo)) {
				printf("[sample]: fail to register foo\n");
			}
		}
		return TRUE;
	case PLUGIN_FREE:
		unregister_talk(console_talk);
		return TRUE;
	}
	return false;
}


static void console_talk(int argc, char **argv, char *result, int length)
{
	strcpy(result, "250 hello world");
}

static void foo()
{
    printf("foo is speaking\n");
}

