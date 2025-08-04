// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>
#include <fmt/core.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/hook_common.h>
#include <gromox/json.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"
#define MAX_DIGLEN				256*1024

using namespace gromox;
DECLARE_HOOK_API(exmdb_local, );
using namespace exmdb_local;

static bool g_lda_twostep, g_lda_mrautoproc;
static char g_org_name[256];
static thread_local alloc_context g_alloc_ctx;
static thread_local const char *g_storedir;
static std::atomic<int> g_sequence_id;

static ec_error_t (*exmdb_local_rules_execute)(const char *, const char *, const char *, eid_t, eid_t, unsigned int flags);

static int exmdb_local_sequence_ID()
{
	int old = 0, nu = 0;
	do {
		old = g_sequence_id.load(std::memory_order_relaxed);
		nu  = old != INT_MAX ? old + 1 : 1;
	} while (!g_sequence_id.compare_exchange_weak(old, nu));
	return nu;
}


void exmdb_local_init(const char *org_name)
{
	gx_strlcpy(g_org_name, org_name, std::size(g_org_name));
}

int exmdb_local_run() try
{
	if (!oxcmail_init_library(g_org_name, mysql_adaptor_get_user_ids,
	    mysql_adaptor_get_domain_ids, mysql_adaptor_userid_to_name)) {
		mlog(LV_ERR, "exmdb_local: failed to init oxcmail library");
		return -2;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "exmdb_local_run: bad_alloc");
	return -3;
}

hook_result exmdb_local_hook(MESSAGE_CONTEXT *pcontext) try
{
	int cache_ID;
	MESSAGE_CONTEXT *pbounce_context;
	/*
	 * For diagnostic purposes, don't modify/steal from ctrl->rcpt until
	 * the replacement list is fully constructed.
	 */
	bool had_error = false;
	std::vector<std::string> new_rcpts;
	for (const auto &rcpt : pcontext->ctrl.rcpt) {
		auto rcpt_buff = rcpt.c_str();
		auto pdomain = strchr(rcpt_buff, '@');
		if (NULL == pdomain) {
			new_rcpts.emplace_back(rcpt);
			continue;
		}
		pdomain ++;
		auto lcldom = mysql_adaptor_domain_list_query(pdomain);
		if (lcldom < 0)
			continue;
		if (lcldom == 0) {
			new_rcpts.emplace_back(rcpt);
			continue;
		}
		switch (exmdb_local_deliverquota(pcontext, rcpt_buff)) {
		case delivery_status::ok:
			break;
		case delivery_status::bounce_sent:
			if (!pcontext->ctrl.need_bounce ||
			    strcasecmp(pcontext->ctrl.from, ENVELOPE_FROM_NULL) == 0)
				break;
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"fail to get bounce context");
				break;
			}
			if (!bounce_audit_check(rcpt_buff) ||
			    !exml_bouncer_make(pcontext->ctrl.from,
			    rcpt_buff, &pcontext->mail, time(nullptr),
			    "BOUNCE_MAIL_DELIVERED", &pbounce_context->mail)) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"delivery_status::bounce_sent %s", rcpt_buff);
				put_context(pbounce_context);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			gx_strlcpy(pbounce_context->ctrl.from, bounce_gen_postmaster(),
				std::size(pbounce_context->ctrl.from));
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case delivery_status::no_user:
			if (!pcontext->ctrl.need_bounce ||
			    strcasecmp(pcontext->ctrl.from, ENVELOPE_FROM_NULL) == 0)
				break;
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"fail to get bounce context");
				break;
			}
			if (!bounce_audit_check(rcpt_buff) ||
			    !exml_bouncer_make(pcontext->ctrl.from,
			    rcpt_buff, &pcontext->mail, time(nullptr),
			    "BOUNCE_NO_USER", &pbounce_context->mail)) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"No such user %s", rcpt_buff);
				put_context(pbounce_context);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			gx_strlcpy(pbounce_context->ctrl.from, bounce_gen_postmaster(),
				std::size(pbounce_context->ctrl.from));
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case delivery_status::mailbox_full:
			if (!pcontext->ctrl.need_bounce ||
			    strcasecmp(pcontext->ctrl.from, ENVELOPE_FROM_NULL) == 0)
				break;
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"fail to get bounce context");
				break;
			}
			if (!bounce_audit_check(rcpt_buff) ||
			    !exml_bouncer_make(pcontext->ctrl.from,
			    rcpt_buff, &pcontext->mail, time(nullptr),
			    "BOUNCE_MAILBOX_FULL", &pbounce_context->mail)) {
				put_context(pbounce_context);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			gx_strlcpy(pbounce_context->ctrl.from, bounce_gen_postmaster(),
				std::size(pbounce_context->ctrl.from));
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case delivery_status::perm_fail:
			had_error = true;
			if (!pcontext->ctrl.need_bounce ||
			    strcasecmp(pcontext->ctrl.from, ENVELOPE_FROM_NULL) == 0)
				break;
			pbounce_context = get_context();
			if (NULL == pbounce_context) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"fail to get bounce context");
				break;
			}
			if (!bounce_audit_check(rcpt_buff) ||
			    !exml_bouncer_make(pcontext->ctrl.from,
			    rcpt_buff, &pcontext->mail, time(nullptr),
			    "BOUNCE_OPERATION_ERROR", &pbounce_context->mail)) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
					"Unspecified error during delivery to %s", rcpt_buff);
				put_context(pbounce_context);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			gx_strlcpy(pbounce_context->ctrl.from, bounce_gen_postmaster(),
				std::size(pbounce_context->ctrl.from));
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case delivery_status::temp_fail:
			had_error = true;
			cache_ID = cache_queue_put(pcontext, rcpt_buff, time(nullptr));
			if (cache_ID >= 0) {
				exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_INFO,
					"message is put into cache queue with cache ID %d and "
					"wait to be delivered next time", cache_ID);
				break;
			}
			exmdb_local_log_info(pcontext->ctrl, rcpt_buff, LV_ERR,
				"failed to put message into cache queue");
			break;
		}
		g_alloc_ctx.clear();
	}
	if (had_error)
		return hook_result::proc_error;
	if (new_rcpts.empty())
		return hook_result::stop;
	pcontext->ctrl.rcpt = std::move(new_rcpts);
	return hook_result::xcontinue;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1082: ENOMEM");
	return hook_result::proc_error;
}

static void* exmdb_local_alloc(size_t size)
{
	return g_alloc_ctx.alloc(size);
}

static BOOL exmdb_local_get_propids(const PROPNAME_ARRAY *ppropnames,
    PROPID_ARRAY *ppropids)
{
	return exmdb_client_remote::get_named_propids(g_storedir, true,
	       ppropnames, ppropids);
}

static void lq_report(unsigned int qid, unsigned long long mid, const char *txt,
    const message_content *ct)
{
	auto &props = ct->proplist;
	auto from = props.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto subj = props.get<const char>(PR_SUBJECT);
	auto abox = ct->children.pattachments;
	auto acount = abox != nullptr ? abox->count : 0;
	mlog(LV_DEBUG, "QID %u/MID %llu/%s: from=<%s> subj=<%s> attachments=%u",
		qid, mid, txt, znul(from), znul(subj), acount);
}

delivery_status exmdb_local_deliverquota(MESSAGE_CONTEXT *pcontext,
    const char *address) try
{
	int sequence_ID;
	uint64_t nt_time;
	char tmzone[64], hostname[UDOM_SIZE];
	uint32_t tmp_int32;
	uint32_t suppress_mask = 0;
	BOOL b_bounce_delivered = false;
	sql_meta_result mres{};

	if (mysql_adaptor_meta(address, WANTPRIV_METAONLY, mres) != 0) {
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR, "fail"
			"to get user information from data source!");
		return delivery_status::temp_fail;
	} else if (mres.maildir.empty()) {
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"<%s> has no mailbox here", address);
		return delivery_status::no_user;
	}
	auto home_dir = mres.maildir.c_str();
	if (*znul(tmzone) == '\0')
		strcpy(tmzone, GROMOX_FALLBACK_TIMEZONE);
	
	auto pmail = &pcontext->mail;
	sequence_ID = exmdb_local_sequence_ID();
	gx_strlcpy(hostname, get_host_ID(), std::size(hostname));
	if ('\0' == hostname[0]) {
		if (gethostname(hostname, std::size(hostname)) < 0)
			strcpy(hostname, "localhost");
		else
			hostname[std::size(hostname)-1] = '\0';
	}
	auto mid_string = fmt::format("{}.l{}.{}", time(nullptr), sequence_ID, hostname);
	auto eml_path = mres.maildir + "/eml/" + mid_string;
	wrapfd fd = open(eml_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, FMODE_PRIVATE);
	if (fd.get() < 0) {
		auto se = errno;
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"open WR %s: %s", eml_path.c_str(), strerror(se));
		errno = se;
		return delivery_status::temp_fail;
	}
	
	auto syserr = pmail->to_fd(fd.get());
	if (syserr != 0) {
		fd.close_rd();
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1386: remove %s: %s",
			        eml_path.c_str(), strerror(errno));
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"%s: pmail->to_fd failed: %s",
			eml_path.c_str(), strerror(syserr));
		return delivery_status::temp_fail;
	}
	auto ret = fd.close_wr();
	if (ret < 0)
		mlog(LV_ERR, "E-1120: close %s: %s", eml_path.c_str(), strerror(ret));

	Json::Value digest;
	auto result = pmail->make_digest(digest);
	if (result <= 0) {
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1387: remove %s: %s",
			        eml_path.c_str(), strerror(errno));
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"permanent failure getting mail digest");
		return delivery_status::perm_fail;
	}
	digest["file"] = std::move(mid_string);
	auto djson = json_to_str(digest);
	g_storedir = mres.maildir.c_str();
	auto pmsg = oxcmail_import(nullptr, tmzone, pmail, exmdb_local_alloc,
	            exmdb_local_get_propids);
	g_storedir = nullptr;
	if (NULL == pmsg) {
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1388: remove %s: %s",
			        eml_path.c_str(), strerror(errno));
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR, "fail "
			"to convert rfc5322 into MAPI message object");
		return delivery_status::perm_fail;
	}
	lq_report(pcontext->ctrl.queue_ID, 0, "before_delivery", pmsg);

	nt_time = rop_util_current_nttime();
	if (pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != ecSuccess)
		/* ignore */;
	if (!pcontext->ctrl.need_bounce) {
		tmp_int32 = UINT32_MAX;
		if (pmsg->proplist.set(PR_AUTO_RESPONSE_SUPPRESS, &tmp_int32) != ecSuccess)
			/* ignore */;
	}
	
	pmsg->proplist.erase(PidTagChangeNumber);
	uint64_t folder_id, message_id = 0;
	uint32_t r32 = 0;
	unsigned int flags = DELIVERY_DO_RULES | DELIVERY_DO_NOTIF;
	if (g_lda_twostep)
		flags = 0;
	if (!exmdb_client_remote::deliver_message(home_dir,
	    pcontext->ctrl.from, address, CP_ACP, flags,
	    pmsg, djson.c_str(), &folder_id, &message_id, &r32))
		return delivery_status::perm_fail;

	auto dm_status = static_cast<deliver_message_result>(r32);
	if (dm_status == deliver_message_result::result_ok) {
		/* XXX: still need to make partial_ok behavior configurable */
		auto num = pmsg->proplist.get<const uint32_t>(PR_AUTO_RESPONSE_SUPPRESS);
		if (num != nullptr)
			suppress_mask = *num;
		auto str = pmsg->proplist.get<const char>(PR_INTERNET_PRECEDENCE);
		if (str != nullptr) {
			if (strcasecmp(str, "bulk") == 0)
				suppress_mask |= AUTO_RESPONSE_SUPPRESS_AUTOREPLY | AUTO_RESPONSE_SUPPRESS_OOF;
			if (strcasecmp(str, "list") == 0)
				suppress_mask |= AUTO_RESPONSE_SUPPRESS_ALL;
		}
		if (pmsg->proplist.has(PR_LIST_HELP) ||
		    pmsg->proplist.has(PR_LIST_HELP_A) ||
		    pmsg->proplist.has(PR_LIST_SUBSCRIBE) ||
		    pmsg->proplist.has(PR_LIST_SUBSCRIBE_A) ||
		    pmsg->proplist.has(PR_LIST_UNSUBSCRIBE) ||
		    pmsg->proplist.has(PR_LIST_UNSUBSCRIBE_A))
			suppress_mask |= AUTO_RESPONSE_SUPPRESS_ALL;
		auto flag = pmsg->proplist.get<const uint8_t>(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
		if (flag != nullptr && *flag != 0) {
			b_bounce_delivered = TRUE;
			if (suppress_mask & AUTO_RESPONSE_SUPPRESS_DR)
				b_bounce_delivered = FALSE;
		} else {
			b_bounce_delivered = FALSE;
		}

		message_content *rbct = nullptr;
		if (exmdb_client_remote::read_message(home_dir, nullptr, CP_ACP,
		    message_id, &rbct) && rbct != nullptr)
			lq_report(pcontext->ctrl.queue_ID, rop_util_get_gc_value(message_id),
				"after_delivery", rbct);
	}
	message_content_free(pmsg);
	switch (dm_status) {
	case deliver_message_result::result_ok:
		exmdb_local_log_info(pcontext->ctrl, address, LV_DEBUG,
			"message %s was delivered OK", eml_path.c_str());
		if (pcontext->ctrl.need_bounce &&
		    strcmp(pcontext->ctrl.from, ENVELOPE_FROM_NULL) != 0&&
		    !(suppress_mask & AUTO_RESPONSE_SUPPRESS_OOF))
			auto_response_reply(home_dir, address, pcontext->ctrl.from);
		break;
	case deliver_message_result::partial_completion:
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"server could not store message in full to %s", home_dir);
		return delivery_status::perm_fail;
	case deliver_message_result::result_error:
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"error result returned when delivering "
			"message into directory %s!", home_dir);
		return delivery_status::temp_fail;
	case deliver_message_result::mailbox_full_bysize:
		exmdb_local_log_info(pcontext->ctrl, address,
			LV_NOTICE, "user's mailbox has reached quota limit");
		return delivery_status::mailbox_full;
	case deliver_message_result::mailbox_full_bymsg:
		exmdb_local_log_info(pcontext->ctrl, address,
			LV_NOTICE, "user's mailbox has reached maximum message count (cf. exmdb_provider.cfg:max_store_message_count)");
		return delivery_status::mailbox_full;
	default:
		return delivery_status::temp_fail;
	}

	if (!g_lda_twostep) {
		if (b_bounce_delivered)
			return delivery_status::bounce_sent;
		return delivery_status::ok;
	}
	if (g_lda_mrautoproc)
		flags |= DELIVERY_DO_MRAUTOPROC;
	auto err = exmdb_local_rules_execute(home_dir, pcontext->ctrl.from,
	           address, folder_id, message_id, flags);
	if (err != ecSuccess)
		mlog(LV_ERR, "TWOSTEP ruleproc unsuccessful: %s", mapi_strerror(err));
	return delivery_status::ok;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1472: ENOMEM");
	return delivery_status::temp_fail;
}

void exmdb_local_log_info(const CONTROL_INFO &ctrl,
    const char *rcpt_to, int level, const char *format, ...)
{
	char log_buf[256];
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	va_end(ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	switch (ctrl.bound_type) {
	case BOUND_IN:
		mlog(level, "SMTP message queue-ID: %d, FROM: %s, TO: %s  %s",
			ctrl.queue_ID, ctrl.from, rcpt_to, log_buf);
		break;
	default:
		mlog(level, "APP created message FROM: %s, TO: %s  %s",
			ctrl.from, rcpt_to, log_buf);
		break;
	}
}

static constexpr cfg_directive mdlgx_cfg_defaults[] = {
	{"autoreply_silence_window", "1day", CFG_TIME, "0"},
	CFG_TABLE_END,
};

BOOL HOOK_exmdb_local(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	char org_name[256], temp_buff[45], cache_path[256];
	int cache_interval, retrying_times;
	int response_capacity, response_interval, conn_num;

	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_HOOK_API(ppdata);
		query_service2("rules_execute", exmdb_local_rules_execute);
		if (exmdb_local_rules_execute == nullptr) {
			mlog(LV_ERR, "exmdb_local: libgxs_ruleproc not initialized");
			return false;
		}
		textmaps_init();
		auto cfg = config_file_initd("gromox.cfg", get_config_path(), mdlgx_cfg_defaults);
		if (cfg != nullptr)
			autoreply_silence_window = cfg->get_ll("autoreply_silence_window");

		auto pfile = config_file_initd("exmdb_local.cfg",
		             get_config_path(), nullptr);
		if (pfile == nullptr) {
			mlog(LV_ERR, "exmdb_local: config_file_initd exmdb_local.cfg: %s",
				strerror(errno));
			return FALSE;
		}

		sprintf(cache_path, "%s/cache", get_queue_path());
		auto str_value = pfile->get_value("X500_ORG_NAME");
		gx_strlcpy(org_name, str_value != nullptr ? str_value : "Gromox default", std::size(org_name));
		mlog(LV_INFO, "exmdb_local: x500 org name is \"%s\"", org_name);

		str_value = pfile->get_value("EXMDB_CONNECTION_NUM");
		conn_num = str_value != nullptr ? strtol(str_value, nullptr, 0) : 5;
		if (conn_num < 2 || conn_num > 100)
			conn_num = 5;
		mlog(LV_INFO, "exmdb_local: exmdb connection number is %d", conn_num);

		str_value = pfile->get_value("CACHE_SCAN_INTERVAL");
		if (str_value == nullptr) {
			cache_interval = 180;
		} else {
			cache_interval = HX_strtoull_sec(str_value, nullptr);
			if (cache_interval <= 0)
				cache_interval = 180;
		}
		HX_unit_seconds(temp_buff, std::size(temp_buff), cache_interval, 0);
		mlog(LV_INFO, "exmdb_local: cache scanning interval is %s", temp_buff);

		str_value = pfile->get_value("RETRYING_TIMES");
		retrying_times = str_value != nullptr ? strtol(str_value, nullptr, 0) : 30;
		if (retrying_times <= 0)
			retrying_times = 30;
		mlog(LV_INFO, "exmdb_local: retrying times on temporary failure is %d",
			retrying_times);

		str_value = pfile->get_value("RESPONSE_AUDIT_CAPACITY");
		response_capacity = str_value != nullptr ? strtol(str_value, nullptr, 0) : 1000;
		if (response_capacity < 0)
			response_capacity = 1000;
		mlog(LV_INFO, "exmdb_local: auto response audit capacity is %d",
			response_capacity);

		str_value = pfile->get_value("RESPONSE_INTERVAL");
		if (str_value == nullptr) {
			response_interval = 180;
		} else {
			response_interval = HX_strtoull_sec(str_value, nullptr);
			if (response_interval <= 0)
				response_interval = 180;
		}
		HX_unit_seconds(temp_buff, std::size(temp_buff), response_interval, 0);
		mlog(LV_INFO, "exmdb_local: auto response interval is %s", temp_buff);

		g_lda_twostep = parse_bool(pfile->get_value("lda_twostep_ruleproc"));
		g_lda_mrautoproc = parse_bool(pfile->get_value("lda_mrautoproc"));

		bounce_audit_init(response_capacity, response_interval);
		cache_queue_init(cache_path, cache_interval, retrying_times);
		exmdb_client.emplace(conn_num, 0);
		exmdb_rpc_alloc = exmdb_local_alloc;
		exmdb_rpc_free  = [](void *) {};
		exmdb_local_init(org_name);

		if (bounce_gen_init(get_config_path(), get_data_path(),
		    "local_bounce") != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start bounce producer");
			return FALSE;
		}
		if (cache_queue_run() != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start cache queue");
			return FALSE;
		}
		if (exmdb_client_run(get_config_path(), EXMDB_CLIENT_ASYNC_CONNECT) != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start exmdb_client");
			return FALSE;
		}
		if (exmdb_local_run() != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start exmdb_local");
			return FALSE;
		}
		if (!register_local(exmdb_local_hook)) {
			mlog(LV_ERR, "exmdb_local: failed to register the hook function");
			return FALSE;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		exmdb_client.reset();
		cache_queue_stop();
		cache_queue_free();
		return TRUE;
	default:
		return TRUE;
	}
}
