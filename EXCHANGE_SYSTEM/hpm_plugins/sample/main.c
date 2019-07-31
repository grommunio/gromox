#include "hpm_common.h"

DECLARE_API;

static BOOL preproc(int context_id);

static BOOL proc(int context_id, const void *pcontent, uint64_t length);

static int retr(int context_id);

static void term(int context_id);

static void console_talk(int argc, char **argv, char *result, int length);

BOOL HPM_LibMain(int reason, void **ppdata)
{
	HPM_INTERFACE interface;
	
	switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		interface.preproc = preproc;
		interface.proc = proc;
		interface.retr = retr;
		interface.term = term;  /* can be null if we don't want use it */
		if (FALSE == register_interface(&interface)) {
			return FALSE;
		}
		register_talk(console_talk);
		return TRUE;
	case PLUGIN_FREE:
		return TRUE;
	}
}

static BOOL preproc(int context_id)
{
	/* TODO add pre-proccess method here */
}

static BOOL proc(int context_id, const void *pcontent, uint64_t length)
{
	/* TODO add process method here */
}

static int retr(int context_id)
{
	/* TODO add retrieve method here */
}

static void term(int context_id)
{
	/* TODO add cleaning method here */
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	/* TODO add code here for read command from console talk */
}
