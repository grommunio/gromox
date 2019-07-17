#include "hook_common.h"
#include <stdio.h>

#define FORWARD_CC			0
#define FORWARD_REDIRECT	1


DECLARE_API;


static BOOL (*get_forward_address)(const char *username, int *ptype,
	char *destination);

static BOOL forwarder_process(MESSAGE_CONTEXT *pcontext);

BOOL HOOK_LibMain(int reason, void **ppdata)
{
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		get_forward_address = query_service("get_forward_address");
		if (NULL == get_forward_address) {
			printf("[user_forwarder]: fail to get \"get_forward_address\" "
				"service\n");
			return FALSE;
		}
        if (FALSE == register_hook(forwarder_process)) {
			printf("[user_forwarder]: fail to register the hook function\n");
            return FALSE;
        }
		printf("[user_forwarder]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
}

static BOOL forwarder_process(MESSAGE_CONTEXT *pcontext)
{
	MIME *pmime;
	BOOL b_touched;
	int type, i, num;
	char rcpt_to[256];
	char forward_to[256];
	char delivered_to[256];
	MEM_FILE temp_file;
	MESSAGE_CONTEXT *pcontext_to;

	mem_file_init(&temp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	
	b_touched = FALSE;
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
		MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		if (FALSE == get_forward_address(rcpt_to, &type, forward_to) ||
			'\0' == forward_to[0]) {
			mem_file_writeline(&temp_file, rcpt_to);
			continue;
		}
		pmime = mail_get_head(pcontext->pmail);
		if (NULL == pmime) {
			mem_file_writeline(&temp_file, rcpt_to);
			continue;
		}
		num = mime_get_field_num(pmime, "Delivered-To");
		for (i=0; i<num; i++) {
			if (TRUE == mime_search_field(pmime, "Delivered-To",
				i, delivered_to, 256)) {
				if (0 == strcasecmp(delivered_to, forward_to)) {
					break;
				}
			}
		}
		if (i < num) {
			/* messge loop detected */
			mem_file_writeline(&temp_file, rcpt_to);
			continue;
		}
		
		if (FORWARD_CC == type) {	
			mem_file_writeline(&temp_file, rcpt_to);
		} else if (FORWARD_REDIRECT == type) {
			b_touched = TRUE;
		} else {
			mem_file_writeline(&temp_file, rcpt_to);
			continue;
		}
		pcontext_to = get_context();
		if (NULL == pcontext_to) {
			/* 
			 * if fail to get context for redirecting,
			 * keep the original ricipients to avoid 
			 * message missing
			 */
			if (FORWARD_REDIRECT == type) {
				mem_file_writeline(&temp_file, rcpt_to);
			}
			continue;
		}
		mail_dup(pcontext->pmail, pcontext_to->pmail);
		strcpy(pcontext_to->pcontrol->from, pcontext->pcontrol->from);
		mem_file_writeline(&pcontext_to->pcontrol->f_rcpt_to, forward_to);
		if (FORWARD_CC == type) {
			pcontext_to->pcontrol->need_bounce = FALSE;
		} else {
			pcontext_to->pcontrol->need_bounce =
						pcontext->pcontrol->need_bounce;
		}
		pmime = mail_get_head(pcontext_to->pmail);
		if (NULL == pmime) {
			put_context(pcontext_to);
			/* 
			 * if fail to get context for redirecting,
			 * keep the original ricipients to avoid 
			 * message missing
			 */
			if (FORWARD_REDIRECT == type) {
				mem_file_writeline(&temp_file, rcpt_to);
			}
			continue;
		}

		mime_set_field(pmime, "Delivered-To", rcpt_to);
		
		switch (pcontext->pcontrol->bound_type) {
		case BOUND_IN:
		case BOUND_OUT:
		case BOUND_RELAY:
			if (FORWARD_CC == type) {
				log_info(8, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"forward cc message to %s", pcontext->pcontrol->queue_ID,
					pcontext->pcontrol->from, rcpt_to, forward_to);
			} else {
				log_info(8, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"forward redirect message to %s",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, forward_to);
			}
			break;
		default:
			if (FORWARD_CC == type) {
				log_info(8, "APP created message FROM: %s, TO: %s  "
					"forward cc messge to %s", pcontext->pcontrol->from,
					rcpt_to, forward_to);
			} else {
				log_info(8, "APP created message FROM: %s, TO: %s  "
					"forward redirect messge to %s", pcontext->pcontrol->from,
					rcpt_to, forward_to);
			}
			break;
		}
		enqueue_context(pcontext_to);
	}

	if (TRUE == b_touched) {
		if (0 == mem_file_get_total_length(&temp_file)) {
			mem_file_free(&temp_file);
			return TRUE;
		}
		mem_file_copy(&temp_file, &pcontext->pcontrol->f_rcpt_to);
	}
	mem_file_free(&temp_file);

	return FALSE;
}



