// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <typeinfo>
#include <gromox/hook_common.h>
#include "bounce_producer.h"
#include "../../exch/mysql_adaptor/mysql_adaptor.h"

DECLARE_API();

#define MLIST_RESULT_OK                 0
#define MLIST_RESULT_NONE               1
#define MLIST_RESULT_PRIVIL_DOMAIN      2
#define MLIST_RESULT_PRIVIL_INTERNAL    3
#define MLIST_RESULT_PRIVIL_SPECIFIED	4

static decltype(mysql_adaptor_get_mlist) *get_mlist;

static BOOL expand_process(MESSAGE_CONTEXT *pcontext);

static void console_talk(int argc, char **argv, char *result, int length);

static BOOL hook_mlist_expand(int reason, void **ppdata)
{
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		query_service2("get_mail_list", get_mlist);
		if (NULL == get_mlist) {
			printf("[mlist_expand]: failed to get service \"get_mail_list\"\n");
			return FALSE;
		}
		bounce_producer_init(";");
		if (bounce_producer_run(get_data_path())) {
			printf("[mlist_expand]: failed to run bounce producer\n");
			return FALSE;
		}

        if (FALSE == register_hook(expand_process)) {
			printf("[mlist_expand]: failed to register the hook function\n");
            return FALSE;
        }

		register_talk(console_talk);

		printf("[mlist_expand]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
    }
	return TRUE;
}
HOOK_ENTRY(hook_mlist_expand);

static BOOL expand_process(MESSAGE_CONTEXT *pcontext)
{
	int result;
	int i, num;
	BOOL b_touched;
	char rcpt_to[256];
	char delivered_to[256];
	std::vector<std::string> temp_file1;
	MEM_FILE temp_file2;
	MIME *phead;
	MESSAGE_CONTEXT *pcontext_expand;
	MESSAGE_CONTEXT *pbounce_context;

	mem_file_init(&temp_file2, pcontext->pcontrol->f_rcpt_to.allocator);
	
	phead = mail_get_head(pcontext->pmail);
	if (NULL == phead) {
		mem_file_free(&temp_file2);
		return FALSE;
	}

	num = mime_get_field_num(phead, "Delivered-To");


	b_touched = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		get_mlist(rcpt_to, pcontext->pcontrol->from, &result, temp_file1);
		switch (result) {
		case MLIST_RESULT_OK:
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				log_info(6, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"mlist %s is expanded", pcontext->pcontrol->queue_ID,
					pcontext->pcontrol->from, rcpt_to, rcpt_to);
				break;
			default:
				log_info(6, "APP created message FROM: %s, TO: %s  "
					"mlist %s is expanded", pcontext->pcontrol->from, rcpt_to,
					rcpt_to);
				break;
			}
			break;
		case MLIST_RESULT_NONE:
			mem_file_writeline(&temp_file2, rcpt_to);
			break;
		case MLIST_RESULT_PRIVIL_DOMAIN:
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				mem_file_writeline(&temp_file2, rcpt_to);
				break;
			}
			bounce_producer_make(pcontext->pcontrol->from, rcpt_to,
					pcontext->pmail, BOUNCE_MLIST_DOMAIN,
					pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
				get_default_domain());
			mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
				pcontext->pcontrol->from);
			throw_context(pbounce_context);
			pbounce_context = NULL;
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				log_info(6, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-domain message can be accepted",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, pcontext->pcontrol->from, rcpt_to);
				break;
			default:
				log_info(6, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-domain message can be accepted",
					pcontext->pcontrol->from, rcpt_to,
					pcontext->pcontrol->from, rcpt_to);
				break;
			}
			break;
		case MLIST_RESULT_PRIVIL_INTERNAL:
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				mem_file_writeline(&temp_file2, rcpt_to);
				break;
			}
			bounce_producer_make(pcontext->pcontrol->from, rcpt_to,
				pcontext->pmail, BOUNCE_MLIST_INTERNAL,
				pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
				get_default_domain());
			mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
				pcontext->pcontrol->from);
			throw_context(pbounce_context);
			pbounce_context = NULL;
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				log_info(6, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-member message can be accepted",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, pcontext->pcontrol->from, rcpt_to);
				break;
			default:
				log_info(6, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-member message can be accepted",
					pcontext->pcontrol->from, rcpt_to,
					pcontext->pcontrol->from, rcpt_to);
				break;
			}
			break;
		case MLIST_RESULT_PRIVIL_SPECIFIED:
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				mem_file_writeline(&temp_file2, rcpt_to);
				break;
			}
			bounce_producer_make(pcontext->pcontrol->from, rcpt_to,
				pcontext->pmail, BOUNCE_MLIST_SPECIFIED,
				pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
				get_default_domain());
			mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
				pcontext->pcontrol->from);
			throw_context(pbounce_context);
			pbounce_context = NULL;
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				log_info(6, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only specified senders' message can be accepted",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, pcontext->pcontrol->from, rcpt_to);
				break;
			default:
				log_info(6, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only specified senders's message can be accepted",
					pcontext->pcontrol->from, rcpt_to,
					pcontext->pcontrol->from, rcpt_to);
				break;
			}
			break;
		}
	}

	if (FALSE == b_touched) {
		mem_file_free(&temp_file2);
		return FALSE;
	}
	
	mem_file_copy(&temp_file2, &pcontext->pcontrol->f_rcpt_to);
	mem_file_free(&temp_file2);

	if (temp_file1.size() == 0) {
		goto EXIT_EXPAND;
	}

	pcontext_expand =  get_context();
	if (NULL == pcontext_expand) {
		for (const auto &rcpt_to : temp_file1) {
			for (i = 0; i < num; ++i)
				if (mime_search_field(phead, "Delivered-To", i, delivered_to, 256) &&
				    strcasecmp(delivered_to, rcpt_to.c_str()) == 0)
					break;
			if (i == num) {
				mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, rcpt_to.c_str());
			}
		}
		goto EXIT_EXPAND;
	}

	strcpy(pcontext_expand->pcontrol->from, pcontext->pcontrol->from);
	pcontext_expand->pcontrol->need_bounce = pcontext->pcontrol->need_bounce;

	for (auto &&rcpt_to : temp_file1) {
		for (i = 0; i < num; ++i)
			if (mime_search_field(phead, "Delivered-To", i, delivered_to, 256) &&
			    strcasecmp(delivered_to, rcpt_to.c_str()) == 0)
				break;
		if (i == num) {
			mem_file_writeline(&pcontext_expand->pcontrol->f_rcpt_to, rcpt_to.c_str());
		}
	}
	mail_dup(pcontext->pmail, pcontext_expand->pmail);
	throw_context(pcontext_expand);

 EXIT_EXPAND:
	if (0 == mem_file_get_total_length(&pcontext->pcontrol->f_rcpt_to)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 mlist expand help information:\r\n"
						 "\t%s bounce reload\r\n"
						 "\t    --reload the bounce resource list";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}

	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] ='\0';
		return;
	}

	if (3 == argc && 0 == strcmp("bounce", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (bounce_producer_refresh(get_data_path()))
			strncpy(result, "250 bounce resource list reload OK", length);
		else
			strncpy(result, "550 bounce resource list reload error", length);
		return;
	}

	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

