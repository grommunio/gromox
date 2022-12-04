// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "bounce_producer.h"
#include <cstdio>
#include <string>
#include <typeinfo>
#include <gromox/hook_common.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

DECLARE_HOOK_API();

#define MLIST_RESULT_OK                 0
#define MLIST_RESULT_NONE               1
#define MLIST_RESULT_PRIVIL_DOMAIN      2
#define MLIST_RESULT_PRIVIL_INTERNAL    3
#define MLIST_RESULT_PRIVIL_SPECIFIED	4

using namespace gromox;

static decltype(mysql_adaptor_get_mlist_memb) *get_mlist_memb;

static BOOL expand_process(MESSAGE_CONTEXT *pcontext);

static BOOL hook_mlist_expand(int reason, void **ppdata)
{
    switch (reason) {
    case PLUGIN_INIT:
		LINK_HOOK_API(ppdata);
		textmaps_init();
		query_service2("get_mlist_memb", get_mlist_memb);
		if (get_mlist_memb == nullptr) {
			mlog(LV_ERR, "mlist_expand: failed to get service \"get_mlist_memb\"");
			return FALSE;
		}
		if (bounce_producer_run(";", get_data_path(),
		    "mlist_bounce") != 0) {
			mlog(LV_ERR, "mlist_expand: failed to run bounce producer");
			return FALSE;
		}
		if (!register_hook(expand_process)) {
			mlog(LV_ERR, "mlist_expand: failed to register the hook function");
            return FALSE;
        }
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
	int result, i;
	BOOL b_touched;
	char rcpt_to[UADDR_SIZE], delivered_to[UADDR_SIZE];
	std::vector<std::string> temp_file1;
	MEM_FILE temp_file2;
	MESSAGE_CONTEXT *pcontext_expand;
	MESSAGE_CONTEXT *pbounce_context;

	mem_file_init(&temp_file2, pcontext->pcontrol->f_rcpt_to.allocator);
	auto phead = pcontext->pmail->get_head();
	if (NULL == phead) {
		mem_file_free(&temp_file2);
		return FALSE;
	}

	auto num = phead->get_field_num("Delivered-To");
	b_touched = FALSE;
	while (pcontext->pcontrol->f_rcpt_to.readline(rcpt_to,
	       arsizeof(rcpt_to)) != MEM_END_OF_FILE) {
		get_mlist_memb(rcpt_to, pcontext->pcontrol->from, &result, temp_file1);
		switch (result) {
		case MLIST_RESULT_OK:
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"mlist %s is expanded", pcontext->pcontrol->queue_ID,
					pcontext->pcontrol->from, rcpt_to, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
					"mlist %s is expanded", pcontext->pcontrol->from, rcpt_to,
					rcpt_to);
				break;
			}
			break;
		case MLIST_RESULT_NONE:
			temp_file2.writeline(rcpt_to);
			break;
		case MLIST_RESULT_PRIVIL_DOMAIN:
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				temp_file2.writeline(rcpt_to);
				break;
			}
			bounce_producer_make(pcontext->pcontrol->from, rcpt_to,
					pcontext->pmail, BOUNCE_MLIST_DOMAIN,
					pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
				get_default_domain());
			pbounce_context->pcontrol->f_rcpt_to.writeline(pcontext->pcontrol->from);
			throw_context(pbounce_context);
			pbounce_context = NULL;
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-domain message can be accepted",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, pcontext->pcontrol->from, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
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
				temp_file2.writeline(rcpt_to);
				break;
			}
			bounce_producer_make(pcontext->pcontrol->from, rcpt_to,
				pcontext->pmail, BOUNCE_MLIST_INTERNAL,
				pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
				get_default_domain());
			pbounce_context->pcontrol->f_rcpt_to.writeline(pcontext->pcontrol->from);
			throw_context(pbounce_context);
			pbounce_context = NULL;
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-member message can be accepted",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, pcontext->pcontrol->from, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
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
				temp_file2.writeline(rcpt_to);
				break;
			}
			bounce_producer_make(pcontext->pcontrol->from, rcpt_to,
				pcontext->pmail, BOUNCE_MLIST_SPECIFIED,
				pbounce_context->pmail);
			pbounce_context->pcontrol->need_bounce = FALSE;
			sprintf(pbounce_context->pcontrol->from, "postmaster@%s",
				get_default_domain());
			pbounce_context->pcontrol->f_rcpt_to.writeline(pcontext->pcontrol->from);
			throw_context(pbounce_context);
			pbounce_context = NULL;
			b_touched = TRUE;
			switch (pcontext->pcontrol->bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only specified senders' message can be accepted",
					pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
					rcpt_to, pcontext->pcontrol->from, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only specified senders's message can be accepted",
					pcontext->pcontrol->from, rcpt_to,
					pcontext->pcontrol->from, rcpt_to);
				break;
			}
			break;
		}
	}

	if (!b_touched) {
		mem_file_free(&temp_file2);
		return FALSE;
	}
	
	temp_file2.copy_to(pcontext->pcontrol->f_rcpt_to);
	mem_file_free(&temp_file2);

	if (temp_file1.size() == 0) {
		goto EXIT_EXPAND;
	}

	pcontext_expand =  get_context();
	if (NULL == pcontext_expand) {
		for (const auto &recip : temp_file1) {
			for (i = 0; i < num; ++i)
				if (phead->search_field("Delivered-To", i,
				    delivered_to, arsizeof(delivered_to)) &&
				    strcasecmp(delivered_to, recip.c_str()) == 0)
					break;
			if (i == num) {
				pcontext->pcontrol->f_rcpt_to.writeline(recip.c_str());
			}
		}
		goto EXIT_EXPAND;
	}

	strcpy(pcontext_expand->pcontrol->from, pcontext->pcontrol->from);
	pcontext_expand->pcontrol->need_bounce = pcontext->pcontrol->need_bounce;

	for (auto &&recip : temp_file1) {
		for (i = 0; i < num; ++i)
			if (phead->search_field("Delivered-To", i,
			    delivered_to, arsizeof(delivered_to)) &&
			    strcasecmp(delivered_to, recip.c_str()) == 0)
				break;
		if (i == num) {
			pcontext_expand->pcontrol->f_rcpt_to.writeline(recip.c_str());
		}
	}
	pcontext->pmail->dup(pcontext_expand->pmail);
	throw_context(pcontext_expand);

 EXIT_EXPAND:
	return pcontext->pcontrol->f_rcpt_to.get_total_length() == 0 ? TRUE : false;
}
