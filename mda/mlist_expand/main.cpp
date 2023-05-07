// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include "bounce_producer.h"
#include <cstdio>
#include <string>
#include <typeinfo>
#include <gromox/bounce_gen.hpp>
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

static hook_result expand_process(MESSAGE_CONTEXT *pcontext);

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
		if (mlex_bounce_init(";", get_config_path(),
		    get_data_path(), "mlist_bounce") != 0) {
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

static hook_result expand_process(MESSAGE_CONTEXT *pcontext) try
{
	int result, i;
	BOOL b_touched;
	char delivered_to[UADDR_SIZE];
	std::vector<std::string> temp_file1; /* all the expandees from mlists */
	std::vector<std::string> unexp;

	auto phead = pcontext->mail.get_head();
	if (NULL == phead) {
		return hook_result::proc_error;
	}

	auto num = phead->get_field_num("Delivered-To");
	b_touched = FALSE;
	for (const auto &rcpt : pcontext->ctrl.rcpt) {
		auto rcpt_to = rcpt.c_str();
		get_mlist_memb(rcpt_to, pcontext->ctrl.from, &result, temp_file1);
		switch (result) {
		case MLIST_RESULT_OK:
			b_touched = TRUE;
			switch (pcontext->ctrl.bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"mlist %s is expanded", pcontext->ctrl.queue_ID,
					pcontext->ctrl.from, rcpt_to, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
					"mlist %s is expanded", pcontext->ctrl.from, rcpt_to,
					rcpt_to);
				break;
			}
			break;
		case MLIST_RESULT_NONE:
			unexp.emplace_back(rcpt);
			break;
		case MLIST_RESULT_PRIVIL_DOMAIN: {
			auto pbounce_context = get_context();
			if (pbounce_context == nullptr ||
			    !mlex_bouncer_make(pcontext->ctrl.from,
			    rcpt_to, &pcontext->mail, "BOUNCE_MLIST_DOMAIN",
			    &pbounce_context->mail)) {
				unexp.emplace_back(rcpt);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			sprintf(pbounce_context->ctrl.from, "postmaster@%s",
				get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			throw_context(pbounce_context);
			b_touched = TRUE;
			switch (pcontext->ctrl.bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-domain message can be accepted",
					pcontext->ctrl.queue_ID, pcontext->ctrl.from,
					rcpt_to, pcontext->ctrl.from, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-domain message can be accepted",
					pcontext->ctrl.from, rcpt_to,
					pcontext->ctrl.from, rcpt_to);
				break;
			}
			break;
		}
		case MLIST_RESULT_PRIVIL_INTERNAL: {
			auto pbounce_context = get_context();
			if (pbounce_context == nullptr ||
			    !mlex_bouncer_make(pcontext->ctrl.from,
			    rcpt_to, &pcontext->mail, "BOUNCE_MLIST_INTERNAL",
			    &pbounce_context->mail)) {
				unexp.emplace_back(rcpt);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			sprintf(pbounce_context->ctrl.from, "postmaster@%s",
				get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			throw_context(pbounce_context);
			b_touched = TRUE;
			switch (pcontext->ctrl.bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-member message can be accepted",
					pcontext->ctrl.queue_ID, pcontext->ctrl.from,
					rcpt_to, pcontext->ctrl.from, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only inter-member message can be accepted",
					pcontext->ctrl.from, rcpt_to,
					pcontext->ctrl.from, rcpt_to);
				break;
			}
			break;
		}
		case MLIST_RESULT_PRIVIL_SPECIFIED: {
			auto pbounce_context = get_context();
			if (pbounce_context == nullptr ||
			    !mlex_bouncer_make(pcontext->ctrl.from,
			    rcpt_to, &pcontext->mail, "BOUNCE_MLIST_SPECIFIED",
			    &pbounce_context->mail)) {
				unexp.emplace_back(rcpt);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			sprintf(pbounce_context->ctrl.from, "postmaster@%s",
				get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			throw_context(pbounce_context);
			b_touched = TRUE;
			switch (pcontext->ctrl.bound_type) {
			case BOUND_IN:
			case BOUND_OUT:
			case BOUND_RELAY:
				mlog(LV_DEBUG, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only specified senders' message can be accepted",
					pcontext->ctrl.queue_ID, pcontext->ctrl.from,
					rcpt_to, pcontext->ctrl.from, rcpt_to);
				break;
			default:
				mlog(LV_DEBUG, "APP created message FROM: %s, TO: %s  "
					"privilege not enough for %s to expand mlist %s, "
					"only specified senders's message can be accepted",
					pcontext->ctrl.from, rcpt_to,
					pcontext->ctrl.from, rcpt_to);
				break;
			}
			break;
		}
		}
	}

	if (!b_touched)
		return hook_result::xcontinue;
	pcontext->ctrl.rcpt = std::move(unexp);
	if (temp_file1.size() == 0) {
		return pcontext->ctrl.rcpt.empty() ?
		       hook_result::stop : hook_result::xcontinue;
	}

	auto pcontext_expand = get_context();
	if (NULL == pcontext_expand) {
		for (auto &&recip : temp_file1) {
			for (i = 0; i < num; ++i)
				if (phead->search_field("Delivered-To", i,
				    delivered_to, arsizeof(delivered_to)) &&
				    strcasecmp(delivered_to, recip.c_str()) == 0)
					break;
			if (i == num) {
				pcontext->ctrl.rcpt.emplace_back(std::move(recip));
			}
		}
		return pcontext->ctrl.rcpt.empty() ?
		       hook_result::stop : hook_result::xcontinue;
	}

	strcpy(pcontext_expand->ctrl.from, pcontext->ctrl.from);
	pcontext_expand->ctrl.need_bounce = pcontext->ctrl.need_bounce;

	for (auto &&recip : temp_file1) {
		for (i = 0; i < num; ++i)
			if (phead->search_field("Delivered-To", i,
			    delivered_to, arsizeof(delivered_to)) &&
			    strcasecmp(delivered_to, recip.c_str()) == 0)
				break;
		if (i == num) {
			pcontext_expand->ctrl.rcpt.emplace_back(std::move(recip));
		}
	}
	pcontext->mail.dup(&pcontext_expand->mail);
	throw_context(pcontext_expand);
	return pcontext->ctrl.rcpt.empty() ?
	       hook_result::stop : hook_result::xcontinue;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1084: ENOMEM");
	return hook_result::proc_error;
}
