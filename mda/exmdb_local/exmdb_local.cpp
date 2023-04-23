// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"
#define MAX_DIGLEN				256*1024

#define DEF_MODE				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

using namespace gromox;

static bool g_lda_twostep;
static char g_org_name[256];
static thread_local ALLOC_CONTEXT *g_alloc_key;
static thread_local const char *g_storedir;
static char g_default_charset[32];
static std::atomic<int> g_sequence_id;

int (*exmdb_local_check_domain)(const char *domainname);

static bool (*exmdb_local_get_user_info)(const char *username, char *home_dir, size_t dsize, char *lang, size_t lsize, char *timezone, size_t tsize);
bool (*exmdb_local_get_lang)(const char *username, char *lang, size_t);
bool (*exmdb_local_get_timezone)(const char *username, char *timezone, size_t);
BOOL (*exmdb_local_check_same_org2)(
	const char *domainname1, const char *domainname2);
static BOOL (*exmdb_local_get_user_ids)(const char *, unsigned int *, unsigned int *, enum display_type *);
static BOOL (*exmdb_local_get_username)(unsigned int, char *, size_t);

static int exmdb_local_sequence_ID()
{
	int old = 0, nu = 0;
	do {
		old = g_sequence_id.load(std::memory_order_relaxed);
		nu  = old != INT_MAX ? old + 1 : 1;
	} while (!g_sequence_id.compare_exchange_weak(old, nu));
	return nu;
}


void exmdb_local_init(const char *org_name, const char *default_charset)
{
	gx_strlcpy(g_org_name, org_name, GX_ARRAY_SIZE(g_org_name));
	gx_strlcpy(g_default_charset, default_charset, GX_ARRAY_SIZE(g_default_charset));
}

int exmdb_local_run() try
{
#define E(f, s) do { \
	query_service2((s), f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "exmdb_local: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(exmdb_local_check_domain, "domain_list_query");
	E(exmdb_local_get_user_info, "get_user_info");
	E(exmdb_local_get_lang, "get_user_lang");
	E(exmdb_local_get_timezone, "get_timezone");
	E(exmdb_local_check_same_org2, "check_same_org2");
	E(exmdb_local_get_user_ids, "get_user_ids");
	E(exmdb_local_get_username, "get_username_from_id");
#undef E

	if (!oxcmail_init_library(g_org_name,
		exmdb_local_get_user_ids, exmdb_local_get_username)) {
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
	
	if (BOUND_NOTLOCAL == pcontext->ctrl.bound_type) {
		return hook_result::xcontinue;
	}

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
		auto lcldom = exmdb_local_check_domain(pdomain);
		if (lcldom < 0)
			continue;
		if (lcldom == 0) {
			new_rcpts.emplace_back(rcpt);
			continue;
		}
		switch (exmdb_local_deliverquota(pcontext, rcpt_buff)) {
		case DELIVERY_OPERATION_OK:
			net_failure_statistic(1, 0, 0, 0);
			break;
		case DELIVERY_OPERATION_DELIVERED:
			net_failure_statistic(1, 0, 0, 0);
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
					"DELIVERY_OPERATION_DELIVERED %s", rcpt_buff);
				put_context(pbounce_context);
				break;
			}
			pbounce_context->ctrl.need_bounce = FALSE;
			sprintf(pbounce_context->ctrl.from,
				"postmaster@%s", get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case DELIVERY_NO_USER:
			net_failure_statistic(0, 0, 0, 1);
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
			sprintf(pbounce_context->ctrl.from,
				"postmaster@%s", get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case DELIVERY_MAILBOX_FULL:
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
			sprintf(pbounce_context->ctrl.from,
				"postmaster@%s", get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case DELIVERY_OPERATION_ERROR:
			had_error = true;
			net_failure_statistic(0, 0, 1, 0);
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
			sprintf(pbounce_context->ctrl.from,
				"postmaster@%s", get_default_domain());
			pbounce_context->ctrl.rcpt.emplace_back(pcontext->ctrl.from);
			enqueue_context(pbounce_context);
			break;
		case DELIVERY_OPERATION_FAILURE:
			had_error = true;
			net_failure_statistic(0, 1, 0, 0);
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
	auto pctx = g_alloc_key;
	if (NULL == pctx) {
		return NULL;
	}
	return pctx->alloc(size);
}

static BOOL exmdb_local_get_propids(const PROPNAME_ARRAY *ppropnames,
    PROPID_ARRAY *ppropids)
{
	return exmdb_client_remote::get_named_propids(g_storedir, false,
	       ppropnames, ppropids);
}

static bool exmdb_local_lang_to_charset(const char *lang, char (&charset)[32])
{
	auto c = lang_to_charset(lang);
	if (c == nullptr)
		return false;
	gx_strlcpy(charset, c, std::size(charset));
	return true;
}

int exmdb_local_deliverquota(MESSAGE_CONTEXT *pcontext, const char *address) try
{
	size_t mess_len;
	int sequence_ID;
	uint64_t nt_time;
	char lang[32], charset[32], tmzone[64], hostname[UDOM_SIZE], home_dir[256];
	uint32_t tmp_int32;
	uint32_t suppress_mask = 0;
	BOOL b_bounce_delivered = false;
	MESSAGE_CONTEXT *pcontext1;

	if (!exmdb_local_get_user_info(address, home_dir, arsizeof(home_dir),
	    lang, arsizeof(lang), tmzone, arsizeof(tmzone))) {
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR, "fail"
			"to get user information from data source!");
		return DELIVERY_OPERATION_FAILURE;
	}

	if (*lang == '\0' ||
	    !exmdb_local_lang_to_charset(lang, charset) || *charset == '\0')
		strcpy(charset, g_default_charset);
	if ('\0' == home_dir[0]) {
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"<%s> has no mailbox here", address);
		return DELIVERY_NO_USER;
	}
	if (tmzone[0] == '\0')
		strcpy(tmzone, GROMOX_FALLBACK_TIMEZONE);
	
	auto pmail = &pcontext->mail;
	if (pcontext->mail.check_dot()) {
		pcontext1 = get_context();
		if (NULL != pcontext1) {
			if (pcontext->mail.transfer_dot(&pcontext1->mail)) {
				pmail = &pcontext1->mail;
			} else {
				put_context(pcontext1);
				pcontext1 = NULL;
			}
		}
	} else {
		pcontext1 = NULL;
	}
	
	sequence_ID = exmdb_local_sequence_ID();
	gx_strlcpy(hostname, get_host_ID(), arsizeof(hostname));
	if ('\0' == hostname[0]) {
		if (gethostname(hostname, arsizeof(hostname)) < 0)
			strcpy(hostname, "localhost");
		else
			hostname[arsizeof(hostname)-1] = '\0';
	}
	auto mid_string = std::to_string(time(nullptr)) + "." +
	                  std::to_string(sequence_ID) + "." + hostname;
	auto eml_path = std::string(home_dir) + "/eml/" + mid_string;
	wrapfd fd = open(eml_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, DEF_MODE);
	if (fd.get() < 0) {
		auto se = errno;
		if (NULL != pcontext1) {
			put_context(pcontext1);
		}
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"open WR %s: %s", eml_path.c_str(), strerror(se));
		errno = se;
		return DELIVERY_OPERATION_FAILURE;
	}
	
	if (!pmail->to_file(fd.get())) {
		fd.close_rd();
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1386: remove %s: %s",
			        eml_path.c_str(), strerror(errno));
		if (NULL != pcontext1) {
			put_context(pcontext1);
		}
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"%s: pmail->to_file failed for unspecified reasons", eml_path.c_str());
		return DELIVERY_OPERATION_FAILURE;
	}
	auto ret = fd.close_wr();
	if (ret < 0)
		mlog(LV_ERR, "E-1120: close %s: %s", eml_path.c_str(), strerror(ret));

	Json::Value digest;
	auto result = pmail->get_digest(&mess_len, digest);
	if (result <= 0) {
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1387: remove %s: %s",
			        eml_path.c_str(), strerror(errno));
		if (NULL != pcontext1) {
			put_context(pcontext1);
		}
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"permanent failure getting mail digest");
		return DELIVERY_OPERATION_ERROR;
	}
	digest["file"] = std::move(mid_string);
	auto djson = json_to_str(digest);
	alloc_context alloc_ctx;
	g_alloc_key = &alloc_ctx;
	g_storedir = home_dir;
	auto pmsg = oxcmail_import(charset, tmzone, pmail, exmdb_local_alloc,
	            exmdb_local_get_propids);
	g_storedir = nullptr;
	if (NULL != pcontext1) {
		put_context(pcontext1);
	}
	if (NULL == pmsg) {
		g_alloc_key = nullptr;
		if (remove(eml_path.c_str()) < 0 && errno != ENOENT)
			mlog(LV_WARN, "W-1388: remove %s: %s",
			        eml_path.c_str(), strerror(errno));
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR, "fail "
			"to convert rfc5322 into MAPI message object");
		return DELIVERY_OPERATION_ERROR;
	}
	g_alloc_key = nullptr;

	nt_time = rop_util_current_nttime();
	if (pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != 0)
		/* ignore */;
	if (!pcontext->ctrl.need_bounce) {
		tmp_int32 = UINT32_MAX;
		if (pmsg->proplist.set(PR_AUTO_RESPONSE_SUPPRESS, &tmp_int32) != 0)
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
		return DELIVERY_OPERATION_ERROR;

	auto dm_status = static_cast<deliver_message_result>(r32);
	if (dm_status == deliver_message_result::result_ok) {
		auto num = pmsg->proplist.get<const uint32_t>(PR_AUTO_RESPONSE_SUPPRESS);
		if (num != nullptr)
			suppress_mask = *num;
		auto flag = pmsg->proplist.get<const uint8_t>(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
		if (flag != nullptr && *flag != 0) {
			b_bounce_delivered = TRUE;
			if (suppress_mask & AUTO_RESPONSE_SUPPRESS_DR) {
				b_bounce_delivered = FALSE;
			}
		} else {
			b_bounce_delivered = FALSE;
		}
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
	case deliver_message_result::result_error:
		exmdb_local_log_info(pcontext->ctrl, address, LV_ERR,
			"error result returned when delivering "
			"message into directory %s!", home_dir);
		return DELIVERY_OPERATION_FAILURE;
	case deliver_message_result::mailbox_full_bysize:
		exmdb_local_log_info(pcontext->ctrl, address,
			LV_NOTICE, "user's mailbox has reached quota limit");
		return DELIVERY_MAILBOX_FULL;
	case deliver_message_result::mailbox_full_bymsg:
		exmdb_local_log_info(pcontext->ctrl, address,
			LV_NOTICE, "user's mailbox has reached maximum message count (cf. exmdb_provider.cfg:max_store_message_count)");
		return DELIVERY_MAILBOX_FULL;
	default:
		return DELIVERY_OPERATION_FAILURE;
	}

	if (!g_lda_twostep) {
		if (b_bounce_delivered)
			return DELIVERY_OPERATION_DELIVERED;
		return DELIVERY_OPERATION_OK;
	}
	auto err = exmdb_local_rules_execute(home_dir, pcontext->ctrl.from,
	           address, folder_id, message_id);
	if (err != ecSuccess)
		mlog(LV_ERR, "TWOSTEP ruleproc unsuccessful: %s\n", mapi_strerror(err));
	return DELIVERY_OPERATION_OK;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1472: ENOMEM");
	return DELIVERY_OPERATION_FAILURE;
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
	case BOUND_OUT:
	case BOUND_RELAY:
		mlog(level, "SMTP message queue-ID: %d, FROM: %s, TO: %s  %s",
			ctrl.queue_ID, ctrl.from, rcpt_to, log_buf);
		break;
	default:
		mlog(level, "APP created message FROM: %s, TO: %s  %s",
			ctrl.from, rcpt_to, log_buf);
		break;
	}
}

DECLARE_HOOK_API();

static BOOL hook_exmdb_local(int reason, void **ppdata)
{
	char charset[32], org_name[256], separator[16], temp_buff[45], cache_path[256];
	int cache_interval, retrying_times, alarm_interval, times, interval;
	int response_capacity, response_interval, conn_num;

	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_HOOK_API(ppdata);
		textmaps_init();
		auto pfile = config_file_initd("exmdb_local.cfg",
		             get_config_path(), nullptr);
		if (pfile == nullptr) {
			mlog(LV_ERR, "exmdb_local: config_file_initd exmdb_local.cfg: %s",
				strerror(errno));
			return FALSE;
		}

		auto str_value = pfile->get_value("SEPARATOR_FOR_BOUNCE");
		gx_strlcpy(separator, str_value == nullptr ? " " : str_value, GX_ARRAY_SIZE(separator));

		sprintf(cache_path, "%s/cache", get_queue_path());

		str_value = pfile->get_value("X500_ORG_NAME");
		gx_strlcpy(org_name, str_value != nullptr ? str_value : "Gromox default", arsizeof(org_name));
		mlog(LV_INFO, "exmdb_local: x500 org name is \"%s\"", org_name);

		str_value = pfile->get_value("DEFAULT_CHARSET");
		gx_strlcpy(charset, str_value != nullptr ? str_value : "windows-1252", arsizeof(charset));
		mlog(LV_INFO, "exmdb_local: default charset is \"%s\"", charset);

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
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), cache_interval, 0);
		mlog(LV_INFO, "exmdb_local: cache scanning interval is %s", temp_buff);

		str_value = pfile->get_value("RETRYING_TIMES");
		retrying_times = str_value != nullptr ? strtol(str_value, nullptr, 0) : 30;
		if (retrying_times <= 0)
			retrying_times = 30;
		mlog(LV_INFO, "exmdb_local: retrying times on temporary failure is %d",
			retrying_times);

		str_value = pfile->get_value("FAILURE_TIMES_FOR_ALARM");
		times = str_value != nullptr ? strtol(str_value, nullptr, 0) : 10;
		if (times <= 0)
			times = 10;
		mlog(LV_INFO, "exmdb_local: failure count for alarm is %d", times);

		str_value = pfile->get_value("INTERVAL_FOR_FAILURE_STATISTIC");
		if (str_value == nullptr) {
			interval = 3600;
		} else {
			interval = HX_strtoull_sec(str_value, nullptr);
			if (interval <= 0)
				interval = 3600;
		}
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), interval, 0);
		mlog(LV_INFO, "exmdb_local: interval for failure alarm is %s", temp_buff);

		str_value = pfile->get_value("ALARM_INTERVAL");
		if (str_value == nullptr) {
			alarm_interval = 1800;
		} else {
			alarm_interval = HX_strtoull_sec(str_value, nullptr);
			if (alarm_interval <= 0)
				alarm_interval = 1800;
		}
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), alarm_interval, 0);
		mlog(LV_INFO, "exmdb_local: alarms interval is %s", temp_buff);

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
		HX_unit_seconds(temp_buff, arsizeof(temp_buff), response_interval, 0);
		mlog(LV_INFO, "exmdb_local: auto response interval is %s", temp_buff);

		g_lda_twostep = parse_bool(pfile->get_value("lda_twostep_ruleproc"));

		net_failure_init(times, interval, alarm_interval);
		bounce_audit_init(response_capacity, response_interval);
		cache_queue_init(cache_path, cache_interval, retrying_times);
		exmdb_client_init(conn_num, 0);
		exmdb_local_init(org_name, charset);

		if (net_failure_run() != 0) {
			mlog(LV_ERR, "exmdb_local: failed to start net_failure component");
			return FALSE;
		}
		if (bounce_gen_init(";", get_config_path(),
		    get_data_path(), "local_bounce") != 0) {
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
		exmdb_client_stop();
		cache_queue_stop();
		cache_queue_free();
		net_failure_free();
		return TRUE;
	}
	return TRUE;
}
HOOK_ENTRY(hook_exmdb_local);
