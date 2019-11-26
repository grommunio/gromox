#include "as_common.h"

DECLARE_API;

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop, 
    CONNECTION *pconnection, char *reason, int length);

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail, 
    CONNECTION *pconnection, char *reason, int length);

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length);

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length);

static void console_talk(int argc, char **argv, char *result, int length);

BOOL AS_LibMain(int reason, void **ppdata)
{
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);	
        /* invoke register_judge for registering judge of mail envelop */
        if (FALSE == register_judge(envelop_judge)) {
            return FALSE;
        }
        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(mime_auditor)) {
            return FALSE;
        }
        /* invoke register_filter for registering text/plain of mime paragraph*/
        if (FALSE == register_filter("text/plain", paragraph_filter)) {
            unregister_auditor(mime_auditor);
            return FALSE;
        }
        /* invoke register_statistic for registering statistic of mail */
        if (FALSE == register_statistic(mail_statistic)) {
            unregister_statistic(mail_statistic);
            return FALSE;
        }
        if (FALSE == register_talk(console_talk)) {
            log_info(0, "fail to register console talk in plugin XXX\n");
        }
        return TRUE;
    case PLUGIN_FREE:
        unregister_judge(envelop_judge);
        unregister_auditor(mime_auditor);
        unregister_filter("text/plain", paragraph_filter);
        unregister_statistic(mail_statistic);
        unregister_talk(console_talk);
        return TRUE;
    case SYS_THREAD_CREATE:
        return TRUE;
        /* a pool thread is created */
    case SYS_THREAD_DESTROY:
        return TRUE;
    }
}

static int envelop_judge(int context_ID, ENVELOP_INFO *penvelop,
    CONNECTION *pconnection, char *reason, int length)
{
    /* TODO add code here for judging mail envelop information */
}

static int mime_auditor(int context_ID, MAIL_ENTITY *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
    /* TODO add code here for auditing mime head information */
}

static int paragraph_filter(int action, int context_ID, MAIL_BLOCK *pblock,
    char *reason, int length)
{
    switch (action) {
    case ACTION_BLOCK_NEW:
        return MESSAGE_ACCEPT;
    case ACTION_BLOCK_PROCESSING:
    /* TODO add code here for filtering paragraph data */
    case ACTION_BLOCK_FREE:
        return MESSAGE_ACCEPT;
    }
}

static int mail_statistic(int context_ID, MAIL_WHOLE *pmail,
    CONNECTION *pconnection, char *reason, int length)
{
    /* TODO add code here for statisticing the mail */
}

static void console_talk(int argc, char **argv, char *result, int length)
{
    /* TODO add code here for read command from console talk */
}


