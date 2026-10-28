// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/endian.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <fmt/format.h>
#include <json/value.h>
#include <vmime/addressList.hpp>
#include <vmime/headerFieldFactory.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/mailbox.hpp>
#include <vmime/message.hpp>
#include <vmime/stringContentHandler.hpp>
#include <vmime/utility/url.hpp>
#include <gromox/algorithm.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/freebusy.hpp>
#include <gromox/ical.hpp>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "../mda/exmdb_local/bounce_producer.hpp"

using namespace gromox;
DECLARE_SVC_API(,);

namespace {

enum {
	POLICY_DECLINE_RECURRING_MEETING_REQUESTS   = 0x2U,
	POLICY_DECLINE_CONFLICTING_MEETING_REQUESTS = 0x4U,
};

/***
 * proptag(l_recurring): object specifies a recurring series
 * proptag(l_is_recurring): object (e.g. exception) is associated with a recurring series
 */
enum {
	l_recurring = 0, l_response_status, l_busy_status, l_recurrence_pat,
	l_appt_state_flags, l_appt_sub_type, l_meeting_type, l_finvited,
	l_cleangoid, l_location, l_where, l_appt_seq, l_ownercritchg,
	l_start_whole, l_end_whole, l_is_exception, l_tzstruct, l_apptrecur,
	l_tzdefrecur, l_is_recurring, l_tz, l_tzdesc, l_goid,
	l_attendeecritchg, l_is_silent, l_reply_time, l_reply_name,
};

/**
 * @rule_id:	if @extended, message id of the extrule, else rule id.
 * @folder_id:	(Current) enclosing folder for @msg_id,
 * 		can change upon %OP_MOVE.
 * @msg_id:	(Current) identifier of the message being processed,
 * 		will change upon %OP_MOVE.
 * @name:	Name for debugging.
 * @provider:	Provider field from the rule, just copied to DAM/DEM.
 * @cond:	Rule conditions; may point to @xcond or something else.
 */
struct rule_node {
	rule_node() = default;
	rule_node(rule_node &&);
	rule_node &operator=(rule_node &&);

	int32_t seq = 0;
	uint32_t state = 0;
	bool extended = false;
	uint64_t rule_id = 0;
	std::string name, provider;
	RESTRICTION xcond{};
	EXT_RULE_ACTIONS xact{};
	NAMEDPROPERTY_INFO xcnames{}, xanames{};
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *act = nullptr;
	/* XXX: Who frees this? */

	bool operator<(const struct rule_node &o) const { return seq < o.seq; }
};

struct message_node {
	std::string dir;
	eid_t fid = 0, mid = 0;
	inline const char *dirc() const { return dir.c_str(); }
};

struct dam_entry {
	const rule_node *rule = nullptr;
	const ACTION_BLOCK *blk = nullptr;
};

struct mr_policy {
	unsigned int dtyp = 0, capacity = 0;
	bool autoproc = true, accept_appts = false;
	bool decline_overlap = false, decline_recurring = false;

	constexpr bool is_resource() const { return dtyp == DT_ROOM || dtyp == DT_EQUIPMENT; }
};

/**
 * @ev_from:      Envelope-From of the original message.
 * @ev_to:        Envelope-To of the original message.
 * @cur:          Pointer to the current message.
 *                Due to OP_MOVE, MIDs can change while rules execute.
 * @ctnt:         Message content. Also due to OP_MOVE, PR_CHANGE_KEY/PCL
 *                can change.
 * @rule_list:    Rules loaded from the mailbox (original Envelope-To's).
 *                Unlike EXC, we won't recurse into other mailbox's rules.
 * @exit:         Flag for op_process to stop early.
 * @del:          Message should be deleted at end of processing.
 * @dlg_copies:   Copies handed to delegates by OP_DELEGATE.
 * @cal_changed:  Meeting processing updated the calendar.
 */
struct rxparam {
	/**
	 * @store_owner, @store_dir, @store_acctid: because EXRPCs APIs are terribly designed
	 * @ctnt: owned by whatever alloc_context exmdb_client was fed with
	 */
	rxparam(message_node &&in);
	NOMOVE(rxparam);
	ec_error_t run();
	ec_error_t run_rules();
	ec_error_t delegate_to(const char *addr);
	ec_error_t is_oof(bool *out) const;
	ec_error_t load_std_rules(bool oof, std::vector<rule_node> &out) const;
	ec_error_t load_ext_rules(bool oof, std::vector<rule_node> &out) const;
	const std::string *get_eml();
	void make_dams();
	void notify();
	void stamp_dlg_copies() const;

	const char *ev_from = nullptr, *ev_to = nullptr;
	message_node cur;
	message_content *ctnt = nullptr;
	std::string orig_dir; /* rule table origin */
	eid_t orig_fid = 0; /* rule folder */
	std::string orig_midstr, eml; /* stored RFC 5322 form of the message */
	std::vector<dam_entry> dams; /* client-side actions */
	std::vector<message_node> dlg_copies;
	bool eml_loaded = false;
	unsigned int m_flags = ~0U;
	uint32_t act_type = 0, act_idx = 0; /* action being run, for DEMs */
	bool del = false, exit = false, cal_changed = false;
	int64_t oof_hist_window = -1; /* seconds, see rx_oof_hist_window */
};

}

unsigned int g_ruleproc_debug;
static std::string rp_smtp_url, rp_org_name;
static unsigned int rp_max_ext_rules = 20;
/*
 * Exchange 2007 marks Out of Office rules with ST_ONLY_WHEN_OOF_EX, with the
 * same meaning as ST_ONLY_WHEN_OOF, MS-OXORULE v23.0 §2.2.1.3.1.3 note 1.
 */
static constexpr uint32_t rx_oof_only = ST_ONLY_WHEN_OOF | ST_ONLY_WHEN_OOF_EX;
static thread_local alloc_context rp_alloc_ctx;
static thread_local const char *rp_storedir;

static void *cu_alloc(size_t z)
{
	return rp_alloc_ctx.alloc(z);
}

template<typename T> T *cu_alloc_t()
{
        static_assert(std::is_trivially_destructible_v<T>);
        return static_cast<T *>(cu_alloc(sizeof(T)));
}

template<typename T> T *cu_alloc_t(size_t elem)
{
        static_assert(std::is_trivially_destructible_v<T>);
        return static_cast<T *>(cu_alloc(sizeof(T) * elem));
}

static BOOL cu_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	return exmdb_client->get_named_propids(rp_storedir, false, names, ids);
}

static BOOL cu_get_propname(propid_t propid, PROPERTY_NAME **name) try
{
	PROPNAME_ARRAY names = {};
	if (!exmdb_client_remote::get_named_propnames(rp_storedir,
	    {propid}, &names) || names.size() != 1)
		return false;
	*name = &names.ppropname[0];
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

rule_node::rule_node(rule_node &&o) :
	seq(o.seq), state(o.state), extended(o.extended), rule_id(o.rule_id),
	name(std::move(o.name)), provider(std::move(o.provider)),
	xcond(std::move(o.xcond)), xact(std::move(o.xact)),
	xcnames(std::move(o.xcnames)), xanames(std::move(o.xanames)),
	cond(o.cond == std::addressof(o.xcond) ? std::addressof(xcond) : o.cond), act(o.act)
{
	o.cond = nullptr;
	o.act = nullptr;
}

rule_node &rule_node::operator=(rule_node &&o)
{
	if (this == &o)
		return *this;
	seq = o.seq;
	state = o.state;
	extended = o.extended;
	rule_id = o.rule_id;
	name = std::move(o.name);
	provider = std::move(o.provider);
	cond = o.cond == std::addressof(o.xcond) ? std::addressof(xcond) : o.cond;
	xcond = std::move(o.xcond);
	xact = std::move(o.xact);
	xcnames = std::move(o.xcnames);
	xanames = std::move(o.xanames);
	o.cond = nullptr;
	act = o.act;
	o.act = nullptr;
	return *this;
}

static void rx_delete_local(PROPNAME_ARRAY &x)
{
	if (x.ppropname == nullptr)
		return;
	for (unsigned int i = 0; i < x.count; ++i)
		if (x.ppropname[i].kind == MNID_STRING)
			exmdb_rpc_free(x.ppropname[i].pname);
	exmdb_rpc_free(x.ppropname);
}

static void rx_npid_collect(const TPROPVAL_ARRAY &props, std::set<uint16_t> &m)
{
	for (unsigned int i = 0; i < props.count; ++i) {
		auto id = PROP_ID(props.ppropval[i].proptag);
		if (is_nameprop_id(id))
			m.emplace(id);
	}
}

static void rx_npid_collect(const MESSAGE_CONTENT &ctnt, std::set<uint16_t> &m)
{
	rx_npid_collect(ctnt.proplist, m);
	if (ctnt.children.prcpts != nullptr)
		for (const auto &rcpt : *ctnt.children.prcpts)
			rx_npid_collect(rcpt, m);
	if (ctnt.children.pattachments != nullptr) {
		for (const auto &at : *ctnt.children.pattachments) {
			rx_npid_collect(at.proplist, m);
			if (at.pembedded != nullptr)
				rx_npid_collect(*at.pembedded, m);
		}
	}
}

/**
 * Rewrite named property ids from the source store's numbering into @dst's,
 * dropping values @dst would not name, and return how many were dropped.
 *
 * A @dst entry of 0 means the target store does not have that name and did not
 * create it (e.g. it is at MAXIMUM_PROPNAME_NUMBER); get_named_propids reports
 * this per entry while succeeding overall. Neither id is usable in the target
 * store: 0 is not a named property, and the source id there denotes an
 * unrelated one.
 *
 * Removal precedes the rewrite: erase() matches whole proptags and removes the
 * first match only, so a rewritten tag can collide with one still queued for
 * removal.
 */
static size_t rx_npid_transform(TPROPVAL_ARRAY &props,
    const std::vector<uint16_t> &src, const PROPID_ARRAY &dst)
{
	std::vector<proptag_t> drop;
	for (const auto &pv : props) {
		if (!is_nameprop_id(PROP_ID(pv.proptag)))
			continue;
		auto it = ct_find(src, PROP_ID(pv.proptag));
		if (it != src.end() && dst[it - src.begin()] == 0)
			drop.push_back(pv.proptag);
	}
	for (auto tag : drop)
		props.erase(tag);
	for (unsigned int i = 0; i < props.count; ++i) {
		auto oldtag = props.ppropval[i].proptag;
		if (!is_nameprop_id(PROP_ID(oldtag)))
			continue;
		auto it = ct_find(src, PROP_ID(oldtag));
		if (it == src.end())
			continue;
		auto newid = dst[it - src.begin()];
		if (newid == 0)
			continue; /* dropped above */
		props.ppropval[i].proptag = PROP_TAG(PROP_TYPE(oldtag), newid);
	}
	return drop.size();
}

static size_t rx_npid_transform(MESSAGE_CONTENT &ctnt,
    const std::vector<uint16_t> &src, const PROPID_ARRAY &dst)
{
	size_t dropped = rx_npid_transform(ctnt.proplist, src, dst);
	if (ctnt.children.prcpts != nullptr)
		for (auto &rcpt : *ctnt.children.prcpts)
			dropped += rx_npid_transform(rcpt, src, dst);
	if (ctnt.children.pattachments != nullptr) {
		for (auto &at : *ctnt.children.pattachments) {
			dropped += rx_npid_transform(at.proplist, src, dst);
			if (at.pembedded != nullptr)
				dropped += rx_npid_transform(*at.pembedded, src, dst);
		}
	}
	return dropped;
}

static ec_error_t rx_npid_replace(rxparam &par, MESSAGE_CONTENT &ctnt,
    const char *newdir)
{
	std::set<uint16_t> src_id_set;
	std::vector<uint16_t> src_id_vec, dst_id_arr;
	rx_npid_collect(ctnt, src_id_set);
	if (src_id_set.size() == 0)
		return ecSuccess;
	for (auto id : src_id_set)
		src_id_vec.push_back(id);
	PROPNAME_ARRAY src_name_arr{};
	auto cl_0 = HX::make_scope_exit([&]() { rx_delete_local(src_name_arr); });
	/* @ctnt was read before any rule ran, so it uses orig_dir's ids */
	if (!exmdb_client->get_named_propnames(par.orig_dir.c_str(),
	    src_id_vec, &src_name_arr)) {
		mlog(LV_DEBUG, "ruleproc: get_named_propnames(%s) failed",
			par.orig_dir.c_str());
		return ecRpcFailed;
	}
	if (src_name_arr.size() != src_id_vec.size()) {
		mlog(LV_ERR, "ruleproc: np(src) counts are fishy");
		return ecError;
	}
	if (!exmdb_client->get_named_propids(newdir, TRUE,
	    &src_name_arr, &dst_id_arr)) {
		mlog(LV_DEBUG, "ruleproc: get_named_propids(%s) failed", newdir);
		return ecRpcFailed;
	}
	if (dst_id_arr.size() != src_name_arr.size()) {
		mlog(LV_ERR, "ruleproc: np(dst) counts are fishy");
		return ecError;
	}
	auto dropped = rx_npid_transform(ctnt, src_id_vec, dst_id_arr);
	if (dropped > 0)
		mlog(LV_WARN, "ruleproc: %zu named property value%s omitted from "
			"the copy because %s would not name them (its "
			"named-property table may be full)", dropped,
			dropped == 1 ? " was" : "s were", newdir);
	return ecSuccess;
}

ec_error_t rxparam::is_oof(bool *oof) const
{
	static constexpr proptag_t tags[] = {PR_OOF_STATE};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client->get_store_properties(cur.dirc(), CP_UTF8, tags, &props))
		return ecError;
	auto flag = props.get<uint8_t>(PR_OOF_STATE);
	*oof = flag != nullptr ? *flag : 0;
	return ecSuccess;
}

/**
 * Preconditions: @this->cur needs to be set
 * Postconditions: @rule_list has new rules appended to
 */
ec_error_t rxparam::load_std_rules(bool oof,
    std::vector<rule_node> &rule_list) const
{
	uint32_t table_id = 0, row_count = 0;

	RESTRICTION_BITMASK rst_1 = {BMR_NEZ, PR_RULE_STATE, ST_ENABLED};
	RESTRICTION_BITMASK rst_2 = {BMR_NEZ, PR_RULE_STATE, oof ? rx_oof_only : 0U};
	RESTRICTION rst_3[]       = {{RES_BITMASK, {&rst_1}}, {RES_BITMASK, {&rst_2}}};
	RESTRICTION_AND_OR rst_4  = {std::size(rst_3), rst_3};

	RESTRICTION_EXIST rst_5   = {PR_RULE_STATE};
	RESTRICTION rst_6[]       = {{RES_EXIST, {&rst_5}}, {RES_OR, {&rst_4}}};
	RESTRICTION_AND_OR rst_7  = {std::size(rst_6), rst_6};
	RESTRICTION rst_8         = {RES_AND, {&rst_7}};

	auto dir = cur.dirc();
	if (!exmdb_client->load_rule_table(dir, cur.fid, 0, &rst_8,
	    &table_id, &row_count))
		return ecError;
	auto cl_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(dir, table_id); });
	static constexpr proptag_t tags[] = {
		PR_RULE_STATE, PR_RULE_ID, PR_RULE_SEQUENCE, PR_RULE_NAME,
		PR_RULE_PROVIDER, PR_RULE_CONDITION, PR_RULE_ACTIONS,
	};
	tarray_set output_rows{};
	if (!exmdb_client->query_table(dir, nullptr, CP_ACP, table_id, tags,
	    0, row_count, &output_rows))
		return ecError;

	for (unsigned int i = 0; i < output_rows.count; ++i) {
		auto row   = output_rows.pparray[i];
		if (row == nullptr)
			continue;
		auto seq   = row->get<const int32_t>(PR_RULE_SEQUENCE);
		auto state = row->get<const uint32_t>(PR_RULE_STATE);
		auto id    = row->get<const uint64_t>(PR_RULE_ID);
		if (seq == nullptr || state == nullptr || id == nullptr)
			continue;
		if (*state & (ST_ERROR | ST_PARSE_ERROR))
			continue;
		if (*state & rx_oof_only && !oof)
			continue;
		rule_node rule;
		rule.seq = *seq;
		rule.state = *state;
		rule.rule_id = *id;
		rule.name = znul(row->get<const char>(PR_RULE_NAME));
		rule.provider = znul(row->get<const char>(PR_RULE_PROVIDER));
		rule.cond = row->get<RESTRICTION>(PR_RULE_CONDITION);
		rule.act = row->get<RULE_ACTIONS>(PR_RULE_ACTIONS);
		rule_list.push_back(std::move(rule));
	}
	return ecSuccess;
}

using npid_map = std::vector<std::pair<propid_t, propid_t>>;

/*
 * Extended rules carry their own named property table, see MS-OXORULE
 * v23.0 §2.2.4.2. Translate it to the numbering of the store at @dir.
 */
static bool rx_xrule_npmap(const char *dir, const NAMEDPROPERTY_INFO &info,
    npid_map &map)
{
	if (info.count == 0)
		return true;
	const PROPNAME_ARRAY names = {info.count, info.ppropname};
	PROPID_ARRAY ids;
	if (!exmdb_client->get_named_propids(dir, TRUE, &names, &ids) ||
	    ids.size() != info.count)
		return false;
	for (unsigned int i = 0; i < info.count; ++i)
		if (ids[i] != 0)
			map.emplace_back(info.ppropid[i], ids[i]);
	return true;
}

static void rx_xrule_retag(const npid_map &map, proptag_t &tag)
{
	if (!is_nameprop_id(PROP_ID(tag)))
		return;
	for (const auto &[from, to] : map) {
		if (from == PROP_ID(tag)) {
			tag = PROP_TAG(PROP_TYPE(tag), to);
			return;
		}
	}
}

static void rx_xrule_retag(const npid_map &map, RESTRICTION &res)
{
	switch (res.rt) {
	case RES_AND:
	case RES_OR:
		for (size_t i = 0; i < res.andor->count; ++i)
			rx_xrule_retag(map, res.andor->pres[i]);
		break;
	case RES_NOT:
		rx_xrule_retag(map, res.xnot->res);
		break;
	case RES_CONTENT:
		rx_xrule_retag(map, res.cont->proptag);
		res.cont->propval.proptag = res.cont->proptag;
		break;
	case RES_PROPERTY:
		rx_xrule_retag(map, res.prop->proptag);
		res.prop->propval.proptag = res.prop->proptag;
		break;
	case RES_PROPCOMPARE:
		rx_xrule_retag(map, res.pcmp->proptag1);
		rx_xrule_retag(map, res.pcmp->proptag2);
		break;
	case RES_BITMASK:
		rx_xrule_retag(map, res.bm->proptag);
		break;
	case RES_SIZE:
		rx_xrule_retag(map, res.size->proptag);
		break;
	case RES_EXIST:
		rx_xrule_retag(map, res.exist->proptag);
		break;
	case RES_SUBRESTRICTION:
		rx_xrule_retag(map, res.sub->res);
		break;
	case RES_COMMENT:
	case RES_ANNOTATION:
		for (size_t i = 0; i < res.comment->count; ++i)
			rx_xrule_retag(map, res.comment->ppropval[i].proptag);
		if (res.comment->pres != nullptr)
			rx_xrule_retag(map, *res.comment->pres);
		break;
	case RES_COUNT:
		rx_xrule_retag(map, res.count->sub_res);
		break;
	default:
		break;
	}
}

/**
 * Preconditions: @this->cur needs to be set
 * Postconditions: @rule_list has new rules appended to
 */
ec_error_t rxparam::load_ext_rules(bool oof,
    std::vector<rule_node> &rule_list) const
{
	uint32_t table_id = 0, row_count = 0;

	RESTRICTION_BITMASK rst_1 = {BMR_NEZ, PR_RULE_MSG_STATE, ST_ENABLED};
	RESTRICTION_BITMASK rst_2 = {BMR_NEZ, PR_RULE_MSG_STATE, oof ? rx_oof_only : 0U};
	RESTRICTION rst_3[2]      = {{RES_BITMASK, {&rst_1}}, {RES_BITMASK, {&rst_2}}};
	RESTRICTION_AND_OR rst_4  = {std::size(rst_3), rst_3};

	RESTRICTION_EXIST rst_5   = {PR_RULE_MSG_STATE};
	RESTRICTION_EXIST rst_6   = {PR_MESSAGE_CLASS};
	RESTRICTION_CONTENT rst_7 = {FL_FULLSTRING | FL_IGNORECASE, PR_MESSAGE_CLASS, {PR_MESSAGE_CLASS, deconst("IPM.ExtendedRule.Message")}};
	RESTRICTION rst_8[]       = {{RES_EXIST, {&rst_5}}, {RES_OR, {&rst_4}}, {RES_EXIST, {&rst_6}}, {RES_CONTENT, {&rst_7}}};
	RESTRICTION_AND_OR rst_9  = {std::size(rst_8), rst_8};
	RESTRICTION rst_10        = {RES_AND, {&rst_9}};

	static constexpr SORT_ORDER sort_spec[] = {{PT_LONG, PROP_ID(PR_RULE_MSG_SEQUENCE), TABLE_SORT_ASCEND}};
	static constexpr SORTORDER_SET sort_order = {std::size(sort_spec), 0, 0, deconst(sort_spec)};
	auto dir = cur.dirc();
	if (!exmdb_client->load_content_table(dir, CP_ACP, cur.fid, nullptr,
	    TABLE_FLAG_ASSOCIATED, &rst_10, &sort_order, &table_id, &row_count))
		return ecError;
	auto cl_0 = HX::make_scope_exit([&]() { exmdb_client->unload_table(dir, table_id); });

	static constexpr proptag_t tags[] = {
		PR_RULE_MSG_STATE, PidTagMid, PR_RULE_MSG_SEQUENCE,
		PR_RULE_MSG_PROVIDER, PR_RULE_MSG_NAME,
	};
	static constexpr proptag_t tags2[] = {
		PR_EXTENDED_RULE_MSG_CONDITION, PR_EXTENDED_RULE_MSG_ACTIONS,
	};
	tarray_set output_rows{};
	if (!exmdb_client->query_table(dir, nullptr, CP_ACP, table_id, tags,
	    0, row_count, &output_rows))
		return ecError;

	unsigned int loaded = 0;
	for (unsigned int i = 0; i < output_rows.count; ++i) {
		auto row   = output_rows.pparray[i];
		if (row == nullptr)
			continue;
		auto seq   = row->get<const int32_t>(PR_RULE_MSG_SEQUENCE);
		auto state = row->get<const uint32_t>(PR_RULE_MSG_STATE);
		auto mid   = row->get<const uint64_t>(PidTagMid);
		if (seq == nullptr || state == nullptr || mid == nullptr)
			continue;
		if (*state & (ST_ERROR | ST_PARSE_ERROR))
			continue;
		if (*state & rx_oof_only && !oof)
			continue;
		if (loaded >= rp_max_ext_rules) {
			mlog(LV_NOTICE, "ruleproc: %s: only the first %u extended rules are run",
				dir, rp_max_ext_rules);
			break;
		}

		rule_node rule;
		rule.seq = *seq;
		rule.state = *state;
		rule.extended = true;
		rule.rule_id = *mid;
		rule.name = znul(row->get<const char>(PR_RULE_MSG_NAME));
		rule.provider = znul(row->get<const char>(PR_RULE_MSG_PROVIDER));
		TPROPVAL_ARRAY vals2{};
		if (!exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
		    *mid, tags2, &vals2))
			continue;
		auto cond = vals2.get<const BINARY>(PR_EXTENDED_RULE_MSG_CONDITION);
		auto act  = vals2.get<const BINARY>(PR_EXTENDED_RULE_MSG_ACTIONS);
		if (act == nullptr || act->cb == 0)
			continue;
		EXT_PULL ep;
		if (cond != nullptr && cond->cb != 0) {
			ep.init(cond->pb, cond->cb, exmdb_rpc_alloc,
				EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
			if (ep.g_namedprop_info(&rule.xcnames) != pack_result::ok ||
			    ep.g_restriction(&rule.xcond) != pack_result::ok) {
				mlog(LV_WARN, "ruleproc: %s: extrule %llxh: unparsable condition",
					dir, static_cast<unsigned long long>(*mid));
				continue;
			}
			npid_map map;
			if (!rx_xrule_npmap(dir, rule.xcnames, map)) {
				mlog(LV_WARN, "ruleproc: %s: extrule %llxh: named properties unresolvable",
					dir, static_cast<unsigned long long>(*mid));
				continue;
			}
			rx_xrule_retag(map, rule.xcond);
			rule.cond = &rule.xcond;
		}
		uint32_t version = 0;
		ep.init(act->pb, act->cb, exmdb_rpc_alloc,
			EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
		if (ep.g_namedprop_info(&rule.xanames) != pack_result::ok ||
		    ep.g_uint32(&version) != pack_result::ok ||
		    version != 1 ||
		    ep.g_ext_rule_actions(&rule.xact) != pack_result::ok) {
			mlog(LV_WARN, "ruleproc: %s: extrule %llxh: unparsable actions",
				dir, static_cast<unsigned long long>(*mid));
			continue;
		}
		npid_map map;
		if (!rx_xrule_npmap(dir, rule.xanames, map)) {
			mlog(LV_WARN, "ruleproc: %s: extrule %llxh: named properties unresolvable",
				dir, static_cast<unsigned long long>(*mid));
			continue;
		}
		for (auto &blk : rule.xact)
			if (blk.type == OP_TAG && blk.pdata != nullptr)
				rx_xrule_retag(map, static_cast<TAGGED_PROPVAL *>(blk.pdata)->proptag);
		rule_list.emplace_back(std::move(rule));
		++loaded;
	}
	return ecSuccess;
}

static bool rx_eval_props(const MESSAGE_CONTENT *ct, const TPROPVAL_ARRAY &props, const RESTRICTION &res);

static bool rx_eval_msgsub(const MESSAGE_CHILDREN &ch, proptag_t tag,
    const RESTRICTION &res)
{
	uint32_t count = 0;
	if (tag == PR_MESSAGE_RECIPIENTS && ch.prcpts != nullptr) {
		for (const auto &rcpt : *ch.prcpts) {
			if (res.rt == RES_COUNT) {
				if (rx_eval_props(nullptr, rcpt,
				    static_cast<RESTRICTION_COUNT *>(res.pres)->sub_res))
					++count;
			} else {
				if (rx_eval_props(nullptr, rcpt, res))
					return true;
			}
		}
	} else if (tag == PR_MESSAGE_ATTACHMENTS && ch.pattachments != nullptr) {
		for (const auto &at : *ch.pattachments) {
			if (res.rt == RES_COUNT) {
				if (rx_eval_props(nullptr, at.proplist,
				    static_cast<RESTRICTION_COUNT *>(res.pres)->sub_res))
					++count;
			} else {
				if (rx_eval_props(nullptr, at.proplist, res))
					return true;
			}
		}
	}
	return res.rt == RES_COUNT && res.count->count == count;
}

static bool rx_eval_sub(const MESSAGE_CONTENT *ct, proptag_t tag,
    const RESTRICTION &res)
{
	switch (res.rt) {
	case RES_OR:
		for (size_t i = 0; i < res.andor->count; ++i)
			if (rx_eval_sub(ct, tag, res.andor->pres[i]))
				return true;
		return false;
	case RES_AND:
		for (size_t i = 0; i < res.andor->count; ++i)
			if (!rx_eval_sub(ct, tag, res.andor->pres[i]))
				return false;
		return true;
	case RES_NOT:
		return !rx_eval_sub(ct, tag, res.xnot->res);
	case RES_CONTENT:
	case RES_PROPERTY:
	case RES_PROPCOMPARE:
	case RES_BITMASK:
	case RES_SIZE:
	case RES_EXIST:
	case RES_COMMENT:
	case RES_ANNOTATION:
	case RES_COUNT: {
		MESSAGE_CHILDREN none{};
		auto &ch = ct != nullptr ? ct->children : none;
		return rx_eval_msgsub(ch, tag, res);
	}
	default:
		mlog(LV_WARN, "W-2334: restriction type %u unevaluated",
                        static_cast<unsigned int>(res.rt));
		return false;
	}
}

/*
 * String restrictions are charset-insensitive. A message stores PT_STRING8 or
 * PT_UNICODE, while Outlook rules reference the PT_UNICODE tag. Fall back to
 * the sibling string type when the exact tag is absent.
 */
/* PR_DISPLAY_TO/CC/BCC as exmdb computes them from the recipients */
static std::string rx_display_list(const MESSAGE_CONTENT &ct, uint32_t type) try
{
	std::string out;
	if (ct.children.prcpts == nullptr)
		return out;
	for (const auto &rcpt : *ct.children.prcpts) {
		auto rt = rcpt.get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (rt == nullptr || (*rt & 0xf) != type)
			continue;
		auto name = rcpt.get<const char>(PR_DISPLAY_NAME);
		if (name == nullptr)
			name = rcpt.get<const char>(PR_SMTP_ADDRESS);
		if (name == nullptr)
			name = rcpt.get<const char>(PR_EMAIL_ADDRESS);
		if (name == nullptr)
			continue;
		if (!out.empty())
			out += "; ";
		out += name;
	}
	return out;
} catch (const std::bad_alloc &) {
	return {};
}

/*
 * @ct is the message whose properties @props are, or nullptr for recipients
 * and attachments. @buf holds a computed value.
 */
static const void *rx_getval(const MESSAGE_CONTENT *ct,
    const TPROPVAL_ARRAY &props, proptag_t tag, std::string &buf)
{
	auto v = props.getval(tag);
	if (v != nullptr)
		return v;
	auto t = PROP_TYPE(tag);
	if (t == PT_UNICODE)
		v = props.getval(CHANGE_PROP_TYPE(tag, PT_STRING8));
	else if (t == PT_STRING8)
		v = props.getval(CHANGE_PROP_TYPE(tag, PT_UNICODE));
	if (v != nullptr)
		return v;
	/*
	 * Delivery stores the flags only when they are true, and read_message
	 * leaves out the display lists that exmdb computes. Outlook conditions
	 * like "sent only to me" compare them with false and "",
	 * conditions 201, 202 and 226 of outlook_rule_spec.rst.
	 */
	switch (CHANGE_PROP_TYPE(tag, PT_UNSPECIFIED)) {
	case CHANGE_PROP_TYPE(PR_MESSAGE_TO_ME, PT_UNSPECIFIED):
	case CHANGE_PROP_TYPE(PR_MESSAGE_CC_ME, PT_UNSPECIFIED):
	case CHANGE_PROP_TYPE(PR_MESSAGE_RECIP_ME, PT_UNSPECIFIED):
		return t == PT_BOOLEAN ? &byte_value_zero : nullptr;
	case CHANGE_PROP_TYPE(PR_DISPLAY_TO, PT_UNSPECIFIED):
	case CHANGE_PROP_TYPE(PR_DISPLAY_CC, PT_UNSPECIFIED):
	case CHANGE_PROP_TYPE(PR_DISPLAY_BCC, PT_UNSPECIFIED):
		if (ct == nullptr || (t != PT_UNICODE && t != PT_STRING8))
			return nullptr;
		buf = rx_display_list(*ct, PROP_ID(tag) == PROP_ID(PR_DISPLAY_TO) ? MAPI_TO :
		      PROP_ID(tag) == PROP_ID(PR_DISPLAY_CC) ? MAPI_CC : MAPI_BCC);
		return buf.c_str();
	}
	return nullptr;
}

static bool rx_eval_props(const MESSAGE_CONTENT *ct, const TPROPVAL_ARRAY &props,
    const RESTRICTION &res)
{
	switch (res.rt) {
	case RES_OR:
		for (size_t i = 0; i < res.andor->count; ++i)
			if (rx_eval_props(ct, props, res.andor->pres[i]))
				return true;
		return false;
	case RES_AND:
		for (size_t i = 0; i < res.andor->count; ++i)
			if (!rx_eval_props(ct, props, res.andor->pres[i]))
				return false;
		return true;
	case RES_NOT:
		return !rx_eval_props(ct, props, res.xnot->res);
	case RES_CONTENT: {
		auto &rcon = *res.cont;
		std::string buf;
		return rcon.comparable() &&
		       rcont_srchkey_eval(rcon, rx_getval(ct, props, rcon.proptag, buf),
		       rp_org_name.c_str(), mysql_adaptor_userid_to_name);
	}
	case RES_PROPERTY: {
		auto &rprop = *res.prop;
		// XXX: special-case PR_ANR?
		if (!rprop.comparable())
			return false;
		std::string buf;
		auto lhs = rx_getval(ct, props, rprop.proptag, buf);
		if (rprop_srchkey_eq(rprop, lhs, rp_org_name.c_str(),
		    mysql_adaptor_userid_to_name))
			return rprop.relop == RELOP_EQ;
		return rprop.eval(lhs);
	}
	case RES_PROPCOMPARE: {
		auto &rprop = *res.pcmp;
		if (!rprop.comparable())
			return false;
		auto lhs = props.getval(rprop.proptag1);
		auto rhs = props.getval(rprop.proptag2);
		return propval_compare_relop_nullok(rprop.relop,
		       PROP_TYPE(rprop.proptag1), lhs, rhs);
	}
	case RES_BITMASK: {
		auto &rbm = *res.bm;
		return rbm.comparable() &&
		       rbm.eval(props.getval(rbm.proptag));
	}
	case RES_SIZE: {
		auto &rsize = *res.size;
		return rsize.eval(props.getval(rsize.proptag));
	}
	case RES_EXIST:
		return props.has(res.exist->proptag);
	case RES_SUBRESTRICTION: {
		auto &rsub = *res.sub;
		if (rsub.subobject == PR_MESSAGE_RECIPIENTS ||
		    rsub.subobject == PR_MESSAGE_ATTACHMENTS)
			return rx_eval_sub(ct, rsub.subobject, rsub.res);
		return false;
	}
	case RES_COMMENT:
	case RES_ANNOTATION:
		if (res.comment->pres == nullptr)
			return TRUE;
		return rx_eval_props(ct, props, *res.comment->pres);
	case RES_COUNT: {
		auto &rcnt = *res.count;
		if (rcnt.count == 0)
			return false;
		if (!rx_eval_props(ct, props, rcnt.sub_res))
			return false;
		--rcnt.count;
		return true;
	}
	case RES_NULL:
		return true;
	default:
		mlog(LV_WARN, "W-2333: restriction type %u unevaluated",
			static_cast<unsigned int>(res.rt));
		return false;
	}
	return false;
}

/* Same limits as the legacy processor */
static constexpr size_t rx_max_rule_rcpts = 256, rx_max_dams = 128;

/*
 * Flag a rule as failed so it is skipped from now on, as the legacy processor
 * does. See MS-OXORULE v23.0 §3.2.5.1.3.
 */
static void rx_disable_rule(rxparam &par, const rule_node &rule)
{
	using LLU = unsigned long long;
	auto dir = par.orig_dir.c_str();
	uint32_t state = rule.state | ST_ERROR;
	bool ok;
	if (rule.extended) {
		const TAGGED_PROPVAL pv[] = {{PR_RULE_MSG_STATE, &state}};
		const TPROPVAL_ARRAY pa = {std::size(pv), deconst(pv)};
		PROBLEM_ARRAY problems{};
		ok = exmdb_client->set_message_properties(dir, nullptr, CP_ACP,
		     rule.rule_id, &pa, &problems);
	} else {
		uint64_t rule_id = rule.rule_id;
		TAGGED_PROPVAL pv[] = {{PR_RULE_ID, &rule_id}, {PR_RULE_STATE, &state}};
		RULE_DATA row;
		row.flags = ROW_MODIFY;
		row.propvals = {std::size(pv), pv};
		BOOL exceed = false;
		ok = exmdb_client->update_folder_rule(dir, par.orig_fid, 1,
		     &row, &exceed);
	}
	if (!ok)
		mlog(LV_ERR, "ruleproc: %s: could not disable %srule %llxh",
			dir, rule.extended ? "ext" : "", LLU{rule.rule_id});
	else
		mlog(LV_NOTICE, "ruleproc: %s: %srule %llxh \"%s\" disabled after an error",
			dir, rule.extended ? "ext" : "", LLU{rule.rule_id},
			rule.name.c_str());
}

/* Deferred Error Message, MS-OXORULE v23.0 §2.2.7 */
static void rx_make_dem(rxparam &par, const rule_node &rule,
    uint32_t rule_error)
{
	if (rule.extended)
		return; /* §2.2.7: extended rules are not used in DEMs */
	auto dir = par.orig_dir.c_str();
	message_content_ptr msg(message_content_init());
	if (msg == nullptr)
		return;
	auto &p = msg->proplist;
	auto now = rop_util_current_nttime();
	uint64_t rule_id = rule.rule_id;
	if (p.set(PR_CLIENT_SUBMIT_TIME, &now) != ecSuccess ||
	    p.set(PR_CREATION_TIME, &now) != ecSuccess ||
	    p.set(PR_LAST_MODIFICATION_TIME, &now) != ecSuccess ||
	    p.set(PR_MESSAGE_DELIVERY_TIME, &now) != ecSuccess ||
	    p.set(PR_MESSAGE_CLASS, "IPC.Microsoft Exchange 4.0.Deferred Error") != ecSuccess ||
	    p.set(PR_RULE_ERROR, &rule_error) != ecSuccess ||
	    p.set(PR_RULE_ACTION_TYPE, &par.act_type) != ecSuccess ||
	    p.set(PR_RULE_ACTION_NUMBER, &par.act_idx) != ecSuccess ||
	    p.set(PR_RULE_PROVIDER, rule.provider.c_str()) != ecSuccess ||
	    p.set(PR_RULE_ID, &rule_id) != ecSuccess)
		return;
	static constexpr proptag_t eidtag[] = {PR_ENTRYID};
	TPROPVAL_ARRAY vals{};
	if (par.cur.dir == par.orig_dir &&
	    exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
	    par.cur.mid, eidtag, &vals)) {
		auto eid = vals.get<const BINARY>(PR_ENTRYID);
		if (eid != nullptr && p.set(PR_DAM_ORIGINAL_ENTRYID, eid) != ecSuccess)
			return;
	}
	vals = {};
	if (exmdb_client->get_folder_properties(dir, CP_ACP, par.orig_fid,
	    eidtag, &vals)) {
		auto eid = vals.get<const BINARY>(PR_ENTRYID);
		if (eid != nullptr && p.set(PR_RULE_FOLDER_ENTRYID, eid) != ecSuccess)
			return;
	}
	uint64_t outmid = 0, outcn = 0;
	auto e_result = ecSuccess;
	if (!exmdb_client->write_message(dir, CP_ACP,
	    eid_t(1, PRIVATE_FID_DEFERRED_ACTION), msg.get(), {},
	    &outmid, &outcn, &e_result) || e_result != ecSuccess)
		mlog(LV_ERR, "ruleproc: %s: could not write DEM: %s",
			dir, mapi_strerror(e_result));
}

static void rx_rule_error(rxparam &par, const rule_node &rule,
    uint32_t rule_error, bool disable)
{
	rx_make_dem(par, rule, rule_error);
	if (disable)
		rx_disable_rule(par, rule);
}

static ec_error_t op_copy_other(rxparam &par, const rule_node &rule,
    const MOVECOPY_ACTION &mc, uint8_t act_type)
{
	using LLU = unsigned long long;
	/* Resolve store */
	if (mc.pstore_eid == nullptr)
		return ecNotFound;
	auto &other_store = *static_cast<const STORE_ENTRYID *>(mc.pstore_eid);
	if (other_store.pserver_name == nullptr)
		return ecNotFound;
	unsigned int user_id = 0, domain_id = 0;
	char *newdir = nullptr;
	if (!exmdb_client->store_eid_to_user(par.cur.dirc(), &other_store,
	    &newdir, &user_id, &domain_id))
		return ecRpcFailed;
	if (newdir == nullptr)
		return ecNotFound;

	/* Resolve folder */
	auto tgt_public = other_store.wrapped_provider_uid == g_muidStorePublic;
	if (!tgt_public && other_store.wrapped_provider_uid != g_muidStorePrivate)
		/* try parsing as FOLDER_ENTRYID directly? (cf. cu_entryid_to_fid) */
		return ecNotFound;
	auto &fid_bin = *static_cast<const BINARY *>(mc.pfolder_eid);
	uint64_t dst_fid, dst_mid = 0, dst_cn = 0;
	if (fid_bin.cb == 0) {
		dst_fid = eid_t(1, tgt_public ?
		          PUBLIC_FID_IPMSUBTREE : PRIVATE_FID_INBOX);
	} else {
		FOLDER_ENTRYID folder_eid{};
		EXT_PULL ep;
		ep.init(fid_bin.pb, fid_bin.cb, malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
		if (ep.g_folder_eid(&folder_eid) != pack_result::success)
			return ecNotFound;
		else if (folder_eid.eid_type == EITLT_PUBLIC_FOLDER && !tgt_public)
			return ecNotFound;
		else if (folder_eid.eid_type == EITLT_PRIVATE_FOLDER && tgt_public)
			return ecNotFound;
		dst_fid = eid_t(1, rop_util_gc_to_value(folder_eid.folder_gc));
	}

	/*
	 * This would be the place to add a check that the message does not
	 * loop. However, as we only ever load one rule table, namely from the
	 * Envelope-To INBOX folder, we know the execution is finite.
	 */

	bool owner_mode = par.orig_dir == newdir;
	if (!owner_mode) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(newdir, dst_fid, par.ev_to, &permission))
			return ecRpcFailed;
		if (!(permission & (frightsOwner | frightsCreate)))
			return ecAccessDenied;
	}

	/* Prepare write */
	message_content_ptr dst(par.ctnt->dup());
	if (dst == nullptr)
		return ecMAPIOOM;
	auto err = rx_npid_replace(par, *dst, newdir);
	if (err != ecSuccess)
		return err;
	if (!exmdb_client->allocate_message_id(newdir, dst_fid, &dst_mid) ||
	    !exmdb_client->allocate_cn(newdir, &dst_cn))
		return ecRpcFailed;
	XID zxid{tgt_public ? rop_util_make_domain_guid(domain_id) :
	         rop_util_make_user_guid(user_id), dst_cn};
	char xidbuf[22];
	BINARY xidbin;
	EXT_PUSH ep;
	if (!ep.init(xidbuf, std::size(xidbuf), 0) ||
	    ep.p_xid(zxid) != pack_result::success)
		return ecMAPIOOM;
	xidbin.pv = xidbuf;
	xidbin.cb = ep.m_offset;
	PCL pcl;
	if (!pcl.append(zxid))
		return ecMAPIOOM;
	binary_ptr pclbin(pcl.serialize());
	if (pclbin == nullptr)
		return ecMAPIOOM;
	auto &props = dst->proplist;
	if (!props.has(PR_LAST_MODIFICATION_TIME)) {
		auto last_time = rop_util_current_nttime();
		err = props.set(PR_LAST_MODIFICATION_TIME, &last_time);
		if (err != ecSuccess)
			return err;
	}
	if ((err = props.set(PidTagMid, &dst_mid)) != ecSuccess ||
	    (err = props.set(PidTagChangeNumber, &dst_cn)) != ecSuccess ||
	    (err = props.set(PR_CHANGE_KEY, &xidbin)) != ecSuccess ||
	    (err = props.set(PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) != ecSuccess)
		return err;

	/* Writeout */
	ec_error_t e_result = ecRpcFailed;
	uint64_t outmid = 0, outcn = 0;
	if (!exmdb_client->write_message(newdir, CP_UTF8, dst_fid,
	    dst.get(), {}, &outmid, &outcn, &e_result)) {
		mlog(LV_DEBUG, "ruleproc: write_message failed");
		return ecRpcFailed;
	} else if (e_result != ecSuccess) {
		mlog(LV_DEBUG, "ruleproc: write_message: %s", mapi_strerror(e_result));
		return ecRpcFailed;
	}
	if (g_ruleproc_debug)
		mlog(LV_DEBUG, "ruleproc: OP_COPY/MOVE to %s:f%llxh:m%llxh",
			newdir, LLU{dst_fid}, LLU{rop_util_get_gc_value(outmid)});
	if (act_type != OP_MOVE)
		return ecSuccess;

	/* Copy done, delete original message object */
	EID_ARRAY del_mids{};
	del_mids.count = 1;
	del_mids.pids  = &par.cur.mid;
	BOOL partial = false;
	if (!exmdb_client->delete_messages(par.cur.dirc(), CP_UTF8, nullptr,
	    par.cur.fid, &del_mids, true, &partial))
		mlog(LV_ERR, "ruleproc: OP_MOVE del_msg %s:%llxh failed",
			par.cur.dirc(), LLU{rop_util_get_gc_value(par.cur.mid)});
	par.cur.dir = newdir;
	par.cur.fid = eid_t(dst_fid);
	par.cur.mid = eid_t(dst_mid);
	return ecSuccess;
}

static ec_error_t op_copy(rxparam &par, const rule_node &rule,
    const MOVECOPY_ACTION &mc, uint8_t act_type)
{
	if (mc.pfolder_eid == nullptr)
		return ecSuccess;
	if (!mc.same_store) {
		auto err = op_copy_other(par, rule, mc, act_type);
		if (err == ecNotFound || err == ecAccessDenied) {
			rx_rule_error(par, rule, err == ecAccessDenied ?
				RULE_ERROR_PERMISSION : RULE_ERROR_MOVECOPY, true);
			return ecSuccess;
		}
		return err;
	}
	auto &svreid = *static_cast<const SVREID *>(mc.pfolder_eid);
	auto dst_fid = svreid.folder_id;
	BOOL exist = false;
	if (rop_util_get_replid(dst_fid) == 1 &&
	    !exmdb_client->is_folder_present(par.cur.dirc(), dst_fid, &exist))
		return ecRpcFailed;
	if (!exist) {
		mlog(LV_WARN, "ruleproc: %s: OP_MOVE/OP_COPY target folder %llxh does not exist",
			par.cur.dirc(), static_cast<unsigned long long>(rop_util_get_gc_value(dst_fid)));
		rx_rule_error(par, rule, RULE_ERROR_MOVECOPY, true);
		return ecSuccess;
	}
	if (eid_t(dst_fid) == par.cur.fid)
		return ecSuccess; /* already there */
	uint64_t dst_mid = 0;
	BOOL result = false;
	if (!exmdb_client->allocate_message_id(par.cur.dirc(), dst_fid, &dst_mid))
		return ecRpcFailed;
	if (!exmdb_client->movecopy_message(par.cur.dirc(), CP_ACP, par.cur.mid,
	    dst_fid, dst_mid, act_type == OP_MOVE ? TRUE : false, &result))
		return ecRpcFailed;
	if (!result) {
		rx_rule_error(par, rule, RULE_ERROR_MOVECOPY, false);
		return ecSuccess;
	}
	if (act_type == OP_MOVE) {
		par.cur.fid = eid_t(dst_fid);
		par.cur.mid = eid_t(dst_mid);
	}
	return ecSuccess;
}

static BINARY *xid_to_bin(const XID &xid)
{
	EXT_PUSH ext_push;
	auto bin = static_cast<BINARY *>(exmdb_rpc_alloc(sizeof(BINARY)));
	if (bin == nullptr)
		return nullptr;
	bin->pv = exmdb_rpc_alloc(24);
	if (bin->pv == nullptr)
		return nullptr;
	if (!ext_push.init(bin->pv, 24, 0) ||
	    ext_push.p_xid(xid) != pack_result::ok)
		return nullptr;
	bin->cb = ext_push.m_offset;
	return bin;
}

/* Set properties on @cur as a new change of the message */
static ec_error_t rx_set_props(const message_node &cur,
    const TAGGED_PROPVAL *setvals, size_t count) try
{
	static constexpr proptag_t oldtags[] = {PR_CHANGE_KEY, PR_PREDECESSOR_CHANGE_LIST};
	TPROPVAL_ARRAY oldvals{};
	if (!exmdb_client->get_message_properties(cur.dirc(), nullptr,
	    CP_ACP, cur.mid, oldtags, &oldvals))
		return ecRpcFailed;
	/* Reuse the replica GUID that delivery put into the change key */
	XID xid{};
	auto oldck = oldvals.get<const BINARY>(PR_CHANGE_KEY);
	if (oldck != nullptr && oldck->cb > sizeof(GUID) && oldck->cb <= 24) {
		EXT_PULL ep;
		ep.init(oldck->pb, oldck->cb, exmdb_rpc_alloc, 0);
		if (ep.g_xid(oldck->cb, &xid) != pack_result::ok)
			xid = {};
	}
	uint64_t change_num = 0;
	if (!exmdb_client->allocate_cn(cur.dirc(), &change_num))
		return ecRpcFailed;
	xid = {xid.guid, change_num};
	auto change_key = xid_to_bin(xid);
	if (change_key == nullptr)
		return ecServerOOM;
	PCL pcl;
	auto oldpcl = oldvals.get<const BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	if (oldpcl != nullptr && !pcl.deserialize(oldpcl))
		pcl.clear();
	if (!pcl.append(xid))
		return ecServerOOM;
	binary_ptr pclbin(pcl.serialize());
	if (pclbin == nullptr)
		return ecServerOOM;
	auto modtime = rop_util_current_nttime();
	std::vector<TAGGED_PROPVAL> valdata = {
		{PidTagChangeNumber, &change_num},
		{PR_CHANGE_KEY, change_key},
		{PR_PREDECESSOR_CHANGE_LIST, pclbin.get()},
		{PR_LOCAL_COMMIT_TIME, &modtime},
		{PR_LAST_MODIFICATION_TIME, &modtime},
	};
	valdata.insert(valdata.end(), setvals, setvals + count);
	const TPROPVAL_ARRAY valhdr = {static_cast<uint16_t>(valdata.size()), valdata.data()};
	PROBLEM_ARRAY problems{};
	if (!exmdb_client->set_message_properties(cur.dirc(),
	    nullptr, CP_ACP, cur.mid, &valhdr, &problems))
		return ecRpcFailed;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

static inline ec_error_t rx_set_prop(const message_node &cur,
    const TAGGED_PROPVAL &setval)
{
	return rx_set_props(cur, &setval, 1);
}

static ec_error_t op_tag(rxparam &par, const rule_node &rule,
    const TAGGED_PROPVAL *setval)
{
	if (setval == nullptr)
		return ecSuccess;
	return rx_set_prop(par.cur, *setval);
}

static ec_error_t op_read(rxparam &par, const rule_node &rule)
{
	uint64_t cn = 0;
	/* XXX: this RPC cannot cope with nullptr username on public stores */
	if (!exmdb_client->set_message_read_state(par.cur.dirc(),
	    nullptr, par.cur.mid, true, &cn))
		return ecRpcFailed;
	return ecSuccess;
}

static inline uint32_t cvidx_make_delta(uint64_t oldtime, uint64_t now)
{
	auto delta = now - oldtime;
	return delta >= (1ULL << 48) ?
	       (delta >> 23) | (1ULL << 31) :
	       (delta >> 18) & ~(1ULL << 31);
}

/* PR_CONVERSATION_INDEX for a message answering one with index @bin */
static bool cvidx_child(const BINARY *bin, uint64_t nt_time, std::string &out)
{
	if (bin == nullptr || bin->cb < 22)
		return false;
	out.assign(bin->pc, bin->cb);
	out.resize(bin->cb + 5);
	/* Well that's just great, Y2057 problem */
	auto oldtime = be64p_to_cpu(&out[1]) & 0xffffffffff000000ULL;
	cpu_to_be32p(&out[bin->cb], cvidx_make_delta(oldtime, nt_time));
	out[bin->cb+4] = gromox::rand();
	return true;
}

/* Make @addr the sender of a message that ruleproc generates */
static ec_error_t rx_set_sender(TPROPVAL_ARRAY &props, const char *addr,
    const char *name = nullptr)
{
	ec_error_t err;
	if ((err = props.set(PR_SENT_REPRESENTING_ADDRTYPE, "SMTP")) != ecSuccess ||
	    (err = props.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, addr)) != ecSuccess ||
	    (err = props.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, addr)) != ecSuccess ||
	    (err = props.set(PR_SENDER_ADDRTYPE, "SMTP")) != ecSuccess ||
	    (err = props.set(PR_SENDER_EMAIL_ADDRESS, addr)) != ecSuccess ||
	    (err = props.set(PR_SENDER_SMTP_ADDRESS, addr)) != ecSuccess)
		return err;
	if (name == nullptr)
		return ecSuccess;
	if ((err = props.set(PR_SENT_REPRESENTING_NAME, name)) != ecSuccess ||
	    (err = props.set(PR_SENDER_NAME, name)) != ecSuccess)
		return err;
	return ecSuccess;
}

/*
 * Whether a forward by a rule already reached @rcpt. Forwards and alerts name
 * their recipients in Delivered-To, which stops forwarding loops.
 */
static bool rx_delivered_before(const MIME &head, const char *rcpt)
{
	auto num = head.get_field_num("Delivered-To");
	for (int i = 0; i < num; ++i) {
		std::string dvto;
		if (head.search_field("Delivered-To", i, dvto) &&
		    strcasecmp(dvto.c_str(), rcpt) == 0)
			return true;
	}
	return false;
}

static std::string mr_owner_lang(const rxparam &);

static std::string rx_html_quote(std::string_view s)
{
	std::unique_ptr<char[], stdlib_delete> q(HX_strquote(std::string(s).c_str(),
		HXQUOTE_HTML, nullptr));
	if (q == nullptr)
		throw std::bad_alloc();
	return q.get();
}

using fwd_header = std::vector<std::pair<std::string, std::string>>;

/* The header block of @ct that a forward quotes above the original text */
static fwd_header rx_fwd_header(const message_content &ct, const char *lang)
{
	auto &p = ct.proplist;
	fwd_header h;
	auto name = p.get<const char>(PR_SENT_REPRESENTING_NAME);
	auto addr = p.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (znoval(name) && znoval(addr)) {
		name = p.get<const char>(PR_SENDER_NAME);
		addr = p.get<const char>(PR_SENDER_SMTP_ADDRESS);
	}
	if (!znoval(name) && !znoval(addr) && strcasecmp(name, addr) != 0)
		h.emplace_back(forward_header_label(lang, "from"),
			std::string(name) + " <" + addr + ">");
	else if (!znoval(name) || !znoval(addr))
		h.emplace_back(forward_header_label(lang, "from"),
			!znoval(name) ? name : addr);
	auto when = p.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (when == nullptr)
		when = p.get<const uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	if (when != nullptr) {
		auto t = rop_util_nttime_to_unix(*when);
		struct tm tm{};
		char buf[64];
		if (localtime_r(&t, &tm) != nullptr &&
		    strftime(buf, std::size(buf), "%a, %d %b %Y %H:%M", &tm) > 0)
			h.emplace_back(forward_header_label(lang, "sent"), buf);
	}
	auto to = rx_display_list(ct, MAPI_TO);
	if (!to.empty())
		h.emplace_back(forward_header_label(lang, "to"), std::move(to));
	auto cc = rx_display_list(ct, MAPI_CC);
	if (!cc.empty())
		h.emplace_back(forward_header_label(lang, "cc"), std::move(cc));
	h.emplace_back(forward_header_label(lang, "subject"),
		znul(p.get<const char>(PR_SUBJECT)));
	return h;
}

/* Bodies of @orig with its header block quoted on top, into @out */
static ec_error_t rx_fwd_body(const message_content &orig, const char *lang,
    TPROPVAL_ARRAY &out)
{
	auto &p = orig.proplist;
	auto cpid = p.get<const uint32_t>(PR_INTERNET_CPID);
	auto text = p.get<const char>(PR_BODY);
	auto html = p.get<const BINARY>(PR_HTML);
	std::string conv;
	ec_error_t err;
	if (text == nullptr && (text = p.get<const char>(PR_BODY_A)) != nullptr) {
		auto cset = cpid != nullptr ? cpid_to_cset(static_cast<cpid_t>(*cpid)) : nullptr;
		conv = cset != nullptr ? iconvtext(text, cset, "UTF-8") : text;
		text = conv.c_str();
	}
	if (text == nullptr && (html == nullptr || html->pc == nullptr)) {
		auto rtf = p.getval(PR_RTF_COMPRESSED);
		if (rtf != nullptr) {
			/* Not worth an RTF editor, keep the body as it is */
			for (auto tag : {PR_RTF_COMPRESSED, PR_RTF_IN_SYNC, PR_NATIVE_BODY_INFO}) {
				auto v = p.getval(tag);
				if (v != nullptr && (err = out.set(tag, v)) != ecSuccess)
					return err;
			}
			return ecSuccess;
		}
		text = "";
	}
	auto hdr = rx_fwd_header(orig, lang);
	std::string plain;
	if (text != nullptr) {
		plain = "\r\n\r\n________________________________\r\n";
		for (const auto &[k, v] : hdr)
			plain += k + ": " + v + "\r\n";
		plain += "\r\n";
		plain += text;
		if ((err = out.set(PR_BODY, plain.c_str())) != ecSuccess)
			return err;
	}
	/* As with EWS ForwardItem, the HTML part goes out in UTF-8 */
	static constexpr uint32_t utf8_cpid = CP_UTF8;
	const uint32_t *out_cpid = &utf8_cpid;
	if (html != nullptr && html->pc != nullptr) {
		std::string_view orig_html(html->pc, html->cb);
		std::string conv_html;
		auto cset = cpid != nullptr && *cpid != CP_UTF8 ?
		            cpid_to_cset(static_cast<cpid_t>(*cpid)) : nullptr;
		if (cset != nullptr && !orig_html.empty()) {
			conv_html = iconvtext(orig_html, cset, "UTF-8");
			if (conv_html.empty()) {
				/* Charset unknown to iconv, pass the HTML on unchanged */
				out_cpid = cpid;
				if ((err = out.set(PR_HTML, html)) != ecSuccess)
					return err;
				return out.set(PR_INTERNET_CPID, out_cpid);
			}
			orig_html = conv_html;
		}
		std::string q = "<div><br></div><hr style=\"display:inline-block;"
		                "width:98%\" tabindex=\"-1\"><div id=\"divRplyFwdMsg\" "
		                "dir=\"ltr\">";
		for (const auto &[k, v] : hdr)
			q += "<b>" + rx_html_quote(k) + ":</b> " + rx_html_quote(v) + "<br>";
		q += "</div><br>";
		static constexpr std::string_view tag = "<body";
		auto it = std::search(orig_html.begin(), orig_html.end(), tag.begin(), tag.end(),
		          [](char a, char b) { return HX_tolower(a) == b; });
		size_t pos = 0;
		if (it != orig_html.end()) {
			auto gt = orig_html.find('>', it - orig_html.begin());
			if (gt != orig_html.npos)
				pos = gt + 1;
		}
		std::string s(orig_html.substr(0, pos));
		s += q;
		s.append(orig_html.substr(pos));
		if (s.size() > UINT32_MAX)
			return ecInvalidParam;
		BINARY bin;
		bin.cb = s.size();
		bin.pc = s.data();
		if ((err = out.set(PR_HTML, &bin)) != ecSuccess)
			return err;
	}
	return out.set(PR_INTERNET_CPID, out_cpid);
}

/**
 * A forward by a rule that does not preserve the sender is a new message
 * from the mailbox owner, which quotes the original as a forward by hand
 * would. EXC does the same.
 */
static ec_error_t rx_fwd_compose(const rxparam &par,
    const std::vector<std::string> &rcpt_list,
    const std::vector<std::string> &rcpt_names, message_content &fwd)
{
	auto &p = par.ctnt->proplist;
	auto &o = fwd.proplist;
	auto norm = p.get<const char>(PR_NORMALIZED_SUBJECT);
	if (norm == nullptr)
		norm = znul(p.get<const char>(PR_SUBJECT));
	auto topic = p.get<const char>(PR_CONVERSATION_TOPIC);
	auto lang = mr_owner_lang(par);
	auto pfx = meeting_subject_prefix(lang.c_str(), "forward");
	auto subj = pfx + std::string(norm);
	auto now = rop_util_current_nttime();
	char msgid[128];
	auto err = make_inet_msgid(msgid, std::size(msgid), 0x5246);
	if (err != ecSuccess)
		return err;
	std::string owner_name;
	if (!mysql_adaptor_get_user_displayname(par.ev_to, owner_name) ||
	    owner_name.empty())
		owner_name = par.ev_to;
	if ((err = o.set(PR_MESSAGE_CLASS, "IPM.Note")) != ecSuccess ||
	    (err = o.set(PR_SUBJECT_PREFIX, pfx)) != ecSuccess ||
	    (err = o.set(PR_NORMALIZED_SUBJECT, norm)) != ecSuccess ||
	    (err = o.set(PR_SUBJECT, subj.c_str())) != ecSuccess ||
	    (err = o.set(PR_CONVERSATION_TOPIC, topic != nullptr ? topic : norm)) != ecSuccess ||
	    (err = o.set(PR_CLIENT_SUBMIT_TIME, &now)) != ecSuccess ||
	    (err = o.set(PR_AUTO_FORWARDED, &byte_value_one)) != ecSuccess ||
	    (err = o.set(PR_INTERNET_MESSAGE_ID, msgid)) != ecSuccess ||
	    (err = rx_set_sender(o, par.ev_to, owner_name.c_str())) != ecSuccess)
		return err;
	auto imp = p.get<const uint32_t>(PR_IMPORTANCE);
	if (imp != nullptr && (err = o.set(PR_IMPORTANCE, imp)) != ecSuccess)
		return err;
	std::string cvidx;
	if (cvidx_child(p.get<const BINARY>(PR_CONVERSATION_INDEX), now, cvidx)) {
		BINARY cvbin;
		cvbin.cb = cvidx.size();
		cvbin.pc = cvidx.data();
		if ((err = o.set(PR_CONVERSATION_INDEX, &cvbin)) != ecSuccess)
			return err;
	}
	auto omid = p.get<const char>(PR_INTERNET_MESSAGE_ID);
	if (!znoval(omid)) {
		auto refs = p.get<const char>(PR_INTERNET_REFERENCES);
		auto nrefs = znoval(refs) ? std::string(omid) : std::string(refs) + " " + omid;
		if ((err = o.set(PR_IN_REPLY_TO_ID, omid)) != ecSuccess ||
		    (err = o.set(PR_INTERNET_REFERENCES, nrefs.c_str())) != ecSuccess)
			return err;
	}
	err = rx_fwd_body(*par.ctnt, lang.c_str(), o);
	if (err != ecSuccess)
		return err;

	auto rcpts = tarray_set_init();
	if (rcpts == nullptr)
		return ecServerOOM;
	fwd.set_rcpts_internal(rcpts);
	static constexpr uint32_t rtype = MAPI_TO;
	for (size_t i = 0; i < rcpt_list.size(); ++i) {
		auto r = rcpts->emplace();
		if (r == nullptr)
			return ecServerOOM;
		auto addr = rcpt_list[i].c_str();
		auto name = rcpt_names[i].empty() ? addr : rcpt_names[i].c_str();
		if ((err = r->set(PR_RECIPIENT_TYPE, &rtype)) != ecSuccess ||
		    (err = r->set(PR_ADDRTYPE, "SMTP")) != ecSuccess ||
		    (err = r->set(PR_EMAIL_ADDRESS, addr)) != ecSuccess ||
		    (err = r->set(PR_SMTP_ADDRESS, addr)) != ecSuccess ||
		    (err = r->set(PR_DISPLAY_NAME, name)) != ecSuccess)
			return err;
	}
	auto atx = par.ctnt->children.pattachments;
	if (atx != nullptr && atx->count > 0) {
		auto dup = atx->dup();
		if (dup == nullptr)
			return ecServerOOM;
		fwd.set_attachments_internal(dup);
	}
	return ecSuccess;
}

/* Whether a forward may rewrite a message of class @cls */
static bool rx_fwd_may_munge(const char *cls)
{
	if (cls == nullptr)
		return true;
	return class_match_prefix(cls, "IPM.Note") == 0 &&
	       class_match_prefix(cls, "IPM.Note.SMIME") != 0;
}

static ec_error_t rx_fwd_new(rxparam &par,
    const std::vector<std::string> &rcpt_list,
    const std::vector<std::string> &rcpt_names)
{
	auto eml = par.get_eml();
	if (eml != nullptr) {
		MAIL orig;
		if (!orig.refonly_parse(eml->c_str(), eml->size()))
			return ecError;
		auto head = orig.get_head();
		if (head != nullptr && rx_delivered_before(*head, par.ev_to)) {
			mlog(LV_DEBUG, "ruleproc: %s: OP_FORWARD skipped, "
				"message was already delivered to %s",
				par.orig_dir.c_str(), par.ev_to);
			return ecSuccess;
		}
	}
	message_content_ptr fwd(message_content_init());
	if (fwd == nullptr)
		return ecServerOOM;
	auto err = rx_fwd_compose(par, rcpt_list, rcpt_names, *fwd);
	if (err != ecSuccess)
		return err;
	auto log_id = "f" + std::to_string(rop_util_get_gc_value(par.cur.fid)) +
	              ":m" + std::to_string(rop_util_get_gc_value(par.cur.mid));
	MAIL imail;
	rp_storedir = par.orig_dir.c_str();
	oxcmail_converter cvt;
	cvt.log_id = log_id.c_str();
	cvt.alloc = cu_alloc;
	cvt.get_propids = cu_get_propids;
	cvt.get_propname = cu_get_propname;
	cvt.use_format_override(*par.ctnt);
	auto ok = cvt.mapi_to_inet(*fwd, imail);
	rp_alloc_ctx.clear();
	rp_storedir = nullptr;
	if (!ok) {
		mlog(LV_ERR, "ruleproc: OP_FORWARD oxcmail_export failed");
		return ecError;
	}
	auto head = imail.get_head();
	if (head == nullptr)
		return ecError;
	for (const auto &eaddr : rcpt_list)
		head->append_field("Delivered-To", eaddr.c_str());
	err = cu_send_mail(imail, rp_smtp_url.c_str(), par.ev_to, rcpt_list);
	if (err != ecSuccess)
		mlog(LV_ERR, "ruleproc: OP_FORWARD cu_send_mail: %s",
			mapi_strerror(err));
	return ecSuccess;
}

/**
 * FWD_AS_SMS_ALERT, MS-OXORULE v23.0 §2.2.5.1.1. There is no SMS gateway, so
 * the alert goes out as a short text mail to the e-mail recipients of the
 * rule. MOBILE recipients cannot be reached, a DEM reports that.
 */
static ec_error_t op_sms_alert(rxparam &par, const rule_node &rule,
    const FORWARDDELEGATE_ACTION &blk) try
{
	std::vector<std::string> rcpt_list;
	bool mobile = false;
	for (const auto &rcptprops : blk) {
		TPROPVAL_ARRAY pv;
		pv.count = rcptprops.count;
		pv.ppropval = rcptprops.ppropval;
		auto atype = pv.get<const char>(PR_ADDRTYPE);
		if (atype != nullptr && strcasecmp(atype, "MOBILE") == 0) {
			mobile = true;
			continue;
		}
		if (cu_rcpt_to_list(std::move(pv), rp_org_name.c_str(),
		    rcpt_list, mysql_adaptor_userid_to_name, false) != ecSuccess)
			return ecError;
	}
	if (mobile) {
		mlog(LV_NOTICE, "ruleproc: %s: SMS alert to a mobile number not sent, "
			"no SMS gateway", par.orig_dir.c_str());
		rx_rule_error(par, rule, RULE_ERROR_DELIVERY, false);
	}
	if (rcpt_list.empty())
		return ecSuccess;
	if (auto eml = par.get_eml(); eml != nullptr) {
		MAIL imail;
		if (imail.refonly_parse(eml->c_str(), eml->size()) &&
		    imail.get_head() != nullptr &&
		    rx_delivered_before(*imail.get_head(), par.ev_to)) {
			mlog(LV_DEBUG, "ruleproc: %s: SMS alert skipped, "
				"message was already delivered to %s",
				par.orig_dir.c_str(), par.ev_to);
			return ecSuccess;
		}
	}

	auto &props = par.ctnt->proplist;
	std::string sender = znul(props.get<const char>(PR_SENT_REPRESENTING_NAME));
	auto saddr = props.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (saddr == nullptr)
		saddr = par.ev_from;
	if (sender.empty() || strcasecmp(sender.c_str(), saddr) == 0)
		sender = saddr;
	else
		sender = sender + " <" + saddr + ">";
	std::string subject = znul(props.get<const char>(PR_SUBJECT));
	std::string body = znul(props.get<const char>(PR_BODY));
	/* The length of one SMS */
	utf8_truncate(body.data(), 160);
	body.resize(strlen(body.c_str()));
	body = "From: " + sender + "\r\nSubject: " + subject + "\r\n\r\n" + body;

	auto msg = vmime::make_shared<vmime::message>();
	auto hdr = msg->getHeader();
	hdr->getField("MIME-Version")->setValue("1.0");
	hdr->From()->setValue(vmime::mailbox(par.ev_to));
	vmime::addressList to;
	for (const auto &r : rcpt_list)
		to.appendAddress(vmime::make_shared<vmime::mailbox>(r));
	hdr->To()->setValue(to);
	hdr->Subject()->setValue(vmime::text(subject, vmime::charsets::UTF_8));
	hdr->Date()->setValue(vmime::datetime::now());
	hdr->getField("Auto-Submitted")->setValue("auto-generated");
	hdr->getField("X-Auto-Response-Suppress")->setValue("All");
	for (const auto &r : rcpt_list)
		hdr->appendField(vmime::headerFieldFactory::getInstance()->create("Delivered-To", r));
	vmime::encoding enc;
	enc.setUsage(vmime::encoding::EncodingUsage::USAGE_TEXT);
	msg->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(body), std::move(enc)),
		vmime::mediaType(vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_PLAIN),
		vmime::charsets::UTF_8);
	auto ret = cu_send_vmail(std::move(msg), rp_smtp_url.c_str(), par.ev_to, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "ruleproc: SMS alert cu_send_vmail: %s", mapi_strerror(ret));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static ec_error_t op_forward2(rxparam &par, const rule_node &rule,
    const FORWARDDELEGATE_ACTION &blk, uint32_t flavor) try
{
	if (blk.count > rx_max_rule_rcpts) {
		rx_rule_error(par, rule, RULE_ERROR_TOO_MANY_RCPTS, true);
		return ecSuccess;
	}
	/*
	 * A forward goes out with a non-null envelope sender. Doing that
	 * for a bounce sends the next bounce back here, which the rule
	 * forwards again (RFC 5321 §4.5.5).
	 */
	if (strcasecmp(par.ev_from, ENVELOPE_FROM_NULL) == 0) {
		mlog(LV_DEBUG, "ruleproc: %s: OP_FORWARD skipped, "
			"message has a null envelope sender",
			par.orig_dir.c_str());
		return ecSuccess;
	}
	if (flavor & FWD_AS_SMS_ALERT)
		return op_sms_alert(par, rule, blk);
	std::vector<std::string> rcpt_list, rcpt_names;
	for (const auto &rcptprops : blk) {
		TPROPVAL_ARRAY pv;
		pv.count = rcptprops.count;
		pv.ppropval = rcptprops.ppropval;
		auto before = rcpt_list.size();
		if (cu_rcpt_to_list(pv, rp_org_name.c_str(),
		    rcpt_list, mysql_adaptor_userid_to_name, false) != ecSuccess)
			return ecError;
		auto name = rcpt_list.size() == before + 1 ?
		            znul(pv.get<const char>(PR_DISPLAY_NAME)) : "";
		rcpt_names.resize(rcpt_list.size(), name);
	}
	if (rcpt_list.empty())
		return ecSuccess;
	if (!(flavor & (FWD_PRESERVE_SENDER | FWD_DO_NOT_MUNGE_MSG | FWD_AS_ATTACHMENT)) &&
	    rx_fwd_may_munge(par.ctnt->proplist.get<const char>(PR_MESSAGE_CLASS)))
		return rx_fwd_new(par, rcpt_list, rcpt_names);

	MAIL imail;
	bool head_kept = false;
	auto eml = par.get_eml();
	if (eml != nullptr) {
		/*
		 * Send the message as received, which keeps signatures intact
		 * and lets the trace headers count hops.
		 */
		if (!imail.refonly_parse(eml->c_str(), eml->size()))
			return ecError;
		auto head = imail.get_head();
		if (head == nullptr)
			return ecError;
		if (rx_delivered_before(*head, par.ev_to)) {
			mlog(LV_DEBUG, "ruleproc: %s: OP_FORWARD skipped, "
				"message was already delivered to %s",
				par.orig_dir.c_str(), par.ev_to);
			return ecSuccess;
		}
		auto af = head->get_field("X-MS-Exchange-Organization-AutoForwarded");
		if (!(flavor & FWD_AS_ATTACHMENT) &&
		    (!(flavor & FWD_PRESERVE_SENDER) || af == nullptr ||
		    strcasecmp(af->c_str(), "true") == 0)) {
			/* Editing the head would re-emit it unfolded */
			std::string pre;
			for (const auto &eaddr : rcpt_list)
				pre += "Delivered-To: " + eaddr + "\r\n";
			if (flavor & FWD_PRESERVE_SENDER && af == nullptr)
				pre += "X-MS-Exchange-Organization-AutoForwarded: true\r\n";
			imail.clear();
			if (!imail.refonly_parse_prepended(pre, eml->c_str(), eml->size()))
				return ecError;
			head_kept = true;
		}
	} else {
		auto log_id = "f" + std::to_string(rop_util_get_gc_value(par.cur.fid)) +
		              ":m" + std::to_string(rop_util_get_gc_value(par.cur.mid));
		rp_storedir = par.orig_dir.c_str();
		oxcmail_converter cvt;
		cvt.log_id = log_id.c_str();
		cvt.alloc = cu_alloc;
		cvt.get_propids = cu_get_propids;
		cvt.get_propname = cu_get_propname;
		cvt.use_format_override(*par.ctnt);
		if (!cvt.mapi_to_inet(*par.ctnt, imail)) {
			mlog(LV_ERR, "ruleproc: OP_FORWARD oxcmail_export failed");
			rp_alloc_ctx.clear();
			rp_storedir = nullptr;
			return ecError;
		}
		rp_alloc_ctx.clear();
		rp_storedir = nullptr;
	}

	ec_error_t ret = ecSuccess;
	if (flavor & FWD_AS_ATTACHMENT) {
		MAIL imail1;
		auto pmime = imail1.add_head();
		if (pmime == nullptr)
			return ecServerOOM;
		if (!pmime->set_content_type("message/rfc822"))
			mlog(LV_WARN, "W-2326: set_content_type not successful");
		char tmp_buff[64*1024];
		snprintf(tmp_buff, std::size(tmp_buff), "<%s>", par.ev_to);
		pmime->set_field("From", tmp_buff);
		int offset = 0;
		for (const auto &eaddr : rcpt_list) {
			if (offset == 0)
				offset = gx_snprintf(tmp_buff, std::size(tmp_buff),
				         "<%s>", eaddr.c_str());
			else
				offset += gx_snprintf(tmp_buff + offset,
				          std::size(tmp_buff) - offset, ", <%s>",
				          eaddr.c_str());
			pmime->append_field("Delivered-To", eaddr.c_str());
		}
		pmime->set_field("To", tmp_buff);
		const std::string *old_subject = nullptr;
		if (auto pmime_old = imail.get_head())
			old_subject = pmime_old->get_field("Subject");
		if (old_subject != nullptr)
			pmime->set_field("Subject", "Fwd: " + *old_subject);
		else
			pmime->set_field("Subject", "Fwd: (no subject)");
		struct tm time_buff;
		auto cur_time = time(nullptr);
		strftime(tmp_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
			localtime_r(&cur_time, &time_buff));
		pmime->set_field("Date", tmp_buff);
		pmime->write_mail(&imail);
		auto env_from = (flavor & FWD_PRESERVE_SENDER) ?
		                par.ev_from : par.ev_to;
		ret = cu_send_mail(imail1, rp_smtp_url.c_str(), env_from, rcpt_list);
	} else {
		auto pmime = imail.get_head();
		if (pmime == nullptr)
			return ecError;
		/*
		 * FWD_PRESERVE_SENDER also "indicates that the message was
		 * autoforwarded", MS-OXORULE v23.0 §2.2.5.1.1.
		 */
		if (!head_kept) {
			for (const auto &eaddr : rcpt_list)
				pmime->append_field("Delivered-To", eaddr.c_str());
			if (flavor & FWD_PRESERVE_SENDER)
				pmime->set_field("X-MS-Exchange-Organization-AutoForwarded", "true");
		}
		auto env_from = (flavor & FWD_PRESERVE_SENDER) ?
		                par.ev_from : par.ev_to;
		ret = cu_send_mail(imail, rp_smtp_url.c_str(), env_from, rcpt_list);
	}
	if (ret != ecSuccess)
		mlog(LV_ERR, "ruleproc: OP_FORWARD cu_send_mail: %s",
			mapi_strerror(ret));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static ec_error_t op_forward(rxparam &par, const rule_node &rule,
    const ACTION_BLOCK &act)
{
	auto fwd = static_cast<const FORWARDDELEGATE_ACTION *>(act.pdata);
	if (fwd == nullptr)
		return ecSuccess;
	return op_forward2(par, rule, *fwd, act.flavor);
}

static ec_error_t opx_forward(rxparam &par, const rule_node &rule,
    const EXT_ACTION_BLOCK &act)
{
	auto fwd = static_cast<const FORWARDDELEGATE_ACTION *>(act.pdata);
	if (fwd == nullptr)
		return ecSuccess;
	return op_forward2(par, rule, *fwd, act.flavor);
}

/* Body of a reply that uses STOCK_REPLY_TEMPLATE */
static bool rx_stock_reply_body(rxparam &par, std::string &body) try
{
	const char *charset = nullptr;
	sql_meta_result mres;
	if (mysql_adaptor_meta(par.ev_from, WANTPRIV_METAONLY, mres) == 0)
		charset = lang_to_charset(mres.lang.c_str());
	auto &props = par.ctnt->proplist;
	if (znoval(charset)) {
		auto cpid = props.get<const uint32_t>(PR_INTERNET_CPID);
		if (cpid != nullptr)
			charset = cpid_to_cset(static_cast<cpid_t>(*cpid));
		if (charset == nullptr)
			charset = "ascii";
	}
	auto tp = bounce_gen_lookup(charset, "BOUNCE_AUTO_RESPONSE");
	if (tp == nullptr)
		return false;
	std::string parts;
	if (par.ctnt->children.pattachments != nullptr) {
		for (const auto &at : *par.ctnt->children.pattachments) {
			auto name = at.proplist.get<const char>(PR_ATTACH_LONG_FILENAME);
			if (name == nullptr)
				continue;
			if (!parts.empty())
				parts += ", ";
			parts += name;
		}
	}
	char date_buf[128], size_buf[64];
	rfc1123_dstring(date_buf, std::size(date_buf), 0);
	auto size = props.get<const uint32_t>(PR_MESSAGE_SIZE);
	HX_unit_size(size_buf, std::size(size_buf), size != nullptr ? *size : 0, 1000, 0);
	auto fa = HXformat_init();
	if (fa == nullptr)
		return false;
	auto cl_0 = HX::make_scope_exit([&]() { HXformat_free(fa); });
	if (HXformat_add(fa, "time", date_buf, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "from", par.ev_from, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "rcpt", par.ev_to, HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "postmaster", bounce_gen_postmaster(), HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "subject", znul(props.get<const char>(PR_SUBJECT)), HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "parts", parts.c_str(), HXTYPE_STRING) < 0 ||
	    HXformat_add(fa, "length", size_buf, HXTYPE_STRING) < 0)
		return false;
	hxmc_t *replaced = nullptr;
	if (HXformat_aprintf(fa, &replaced, &tp->content[tp->body_start]) < 0)
		return false;
	body = replaced;
	HXmc_free(replaced);
	return true;
} catch (const std::bad_alloc &) {
	return false;
}

/**
 * OP_REPLY and OP_OOF_REPLY, MS-OXORULE v23.0 §3.2.5.1. @tpl_mid is the
 * template, an FAI message in the rule folder.
 *
 * Returns ecNotFound if the template is unusable, which the caller turns into
 * a disabled rule.
 */
static ec_error_t op_reply2(rxparam &par, uint8_t act_type, uint32_t flavor,
    eid_t tpl_mid, const GUID &tpl_guid) try
{
	if (strcasecmp(par.ev_from, ENVELOPE_FROM_NULL) == 0)
		return ecSuccess;
	auto &props = par.ctnt->proplist;
	auto suppress = props.get<const uint32_t>(PR_AUTO_RESPONSE_SUPPRESS);
	if (suppress != nullptr && *suppress & (act_type == OP_REPLY ?
	    AUTO_RESPONSE_SUPPRESS_AUTOREPLY : AUTO_RESPONSE_SUPPRESS_OOF))
		return ecSuccess;

	auto dir = par.orig_dir.c_str();
	message_content *tpl = nullptr;
	if (!exmdb_client->read_message(dir, nullptr, CP_ACP, tpl_mid, &tpl))
		return ecRpcFailed;
	if (tpl == nullptr)
		return ecNotFound;
	auto &tprops = tpl->proplist;
	auto cls = tprops.get<const char>(PR_MESSAGE_CLASS);
	if (cls == nullptr || class_match_prefix(cls, act_type == OP_REPLY ?
	    "IPM.Note.rules.ReplyTemplate" : "IPM.Note.rules") != 0)
		return ecNotFound;
	auto fai = tprops.get<const uint8_t>(PR_ASSOCIATED);
	if (fai == nullptr || *fai == 0)
		return ecNotFound;
	if (tpl_guid != GUID_NULL) {
		auto bin = tprops.get<const BINARY>(PR_REPLY_TEMPLATE_ID);
		if (bin == nullptr || bin->cb != sizeof(GUID) ||
		    rop_util_binary_to_guid(bin) != tpl_guid)
			return ecNotFound;
	}

	/* Recipient: the template's own ones, or the sender */
	auto sender = props.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	auto sender_name = props.get<const char>(PR_SENT_REPRESENTING_NAME);
	uint32_t rcpt_type = MAPI_TO;
	TAGGED_PROPVAL rcpt_pv[] = {
		{PR_SMTP_ADDRESS, deconst(sender != nullptr ? sender : par.ev_from)},
		{PR_RECIPIENT_TYPE, &rcpt_type},
		{PR_DISPLAY_NAME, deconst(sender_name)},
	};
	TPROPVAL_ARRAY rcpt = {static_cast<uint16_t>(sender_name != nullptr ? 3 : 2), rcpt_pv};
	TPROPVAL_ARRAY *rcpt_p = &rcpt;
	tarray_set rcpt_set;
	if (flavor & DO_NOT_SEND_TO_ORIGINATOR) {
		if (tpl->children.prcpts == nullptr ||
		    tpl->children.prcpts->count == 0)
			return ecNotFound;
	} else {
		rcpt_set.count = 1;
		rcpt_set.pparray = &rcpt_p;
		tpl->children.prcpts = &rcpt_set;
	}
	std::string body;
	std::vector<TAGGED_PROPVAL> stock_props;
	if (flavor & STOCK_REPLY_TEMPLATE) {
		if (!rx_stock_reply_body(par, body))
			return ecNotFound;
		/*
		 * @tpl lives in the RPC arena, which erase and set would free
		 * into. Point the template at a new list instead.
		 */
		for (const auto &pv : tprops)
			if (pv.proptag != PR_ASSOCIATED && pv.proptag != PidTagMid &&
			    pv.proptag != PR_BODY && pv.proptag != PR_BODY_A &&
			    pv.proptag != PR_HTML && pv.proptag != PR_RTF_COMPRESSED)
				stock_props.push_back(pv);
		stock_props.push_back({PR_BODY, body.data()});
		tprops.count    = static_cast<uint16_t>(stock_props.size());
		tprops.ppropval = stock_props.data();
	}

	auto log_id = par.orig_dir + ":m" + std::to_string(rop_util_get_gc_value(tpl_mid));
	MAIL imail;
	rp_storedir = dir;
	oxcmail_converter cvt;
	cvt.log_id = log_id.c_str();
	cvt.alloc = cu_alloc;
	cvt.get_propids = cu_get_propids;
	cvt.get_propname = cu_get_propname;
	auto ok = cvt.mapi_to_inet(*tpl, imail);
	rp_alloc_ctx.clear();
	rp_storedir = nullptr;
	if (!ok) {
		mlog(LV_ERR, "ruleproc: OP_REPLY oxcmail_export failed");
		return ecError;
	}
	auto head = imail.get_head();
	if (head == nullptr)
		return ecError;
	head->set_field("X-Auto-Response-Suppress", "All");
	head->set_field("From", par.ev_to);
	std::vector<std::string> rcpt_list;
	for (const auto &r : *tpl->children.prcpts) {
		TPROPVAL_ARRAY pv = {r.count, r.ppropval};
		if (cu_rcpt_to_list(std::move(pv), rp_org_name.c_str(),
		    rcpt_list, mysql_adaptor_userid_to_name, false) != ecSuccess)
			return ecError;
	}
	if (rcpt_list.empty())
		return ecSuccess;
	auto ret = cu_send_mail(imail, rp_smtp_url.c_str(), par.ev_to, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "ruleproc: OP_REPLY cu_send_mail: %s", mapi_strerror(ret));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static ec_error_t op_reply(rxparam &par, const rule_node &rule,
    const ACTION_BLOCK &act)
{
	auto ra = static_cast<const REPLY_ACTION *>(act.pdata);
	if (ra == nullptr)
		return ecSuccess;
	auto err = op_reply2(par, act.type, act.flavor,
	           ra->template_message_id, ra->template_guid);
	if (err != ecNotFound)
		return err;
	rx_rule_error(par, rule, RULE_ERROR_RETRIEVE_TEMPLATE, true);
	return ecSuccess;
}

static ec_error_t opx_reply(rxparam &par, const rule_node &rule,
    const EXT_ACTION_BLOCK &act)
{
	auto ra = static_cast<const EXT_REPLY_ACTION *>(act.pdata);
	if (ra == nullptr)
		return ecSuccess;
	auto mid = eid_t(1, rop_util_gc_to_value(ra->message_eid.message_gc));
	auto err = op_reply2(par, act.type, act.flavor, mid, ra->template_guid);
	if (err != ecNotFound)
		return err;
	rx_rule_error(par, rule, RULE_ERROR_RETRIEVE_TEMPLATE, true);
	return ecSuccess;
}

/**
 * Deliver a copy of the message to @addr on behalf of the mailbox owner, then
 * run @addr's own rules on it. OP_DELEGATE, MS-OXORULE v23.0 §3.2.5.1.
 */
ec_error_t rxparam::delegate_to(const char *addr) try
{
	auto mbox = orig_dir.c_str();
	sql_meta_result mres;
	if (mysql_adaptor_meta(addr, WANTPRIV_METAONLY, mres) != 0 ||
	    mres.maildir.empty()) {
		mlog(LV_WARN, "ruleproc: %s: OP_DELEGATE to %s skipped: no such mailbox",
			mbox, addr);
		return ecSuccess;
	}
	auto dlg_dir = mres.maildir.c_str();
	auto src = get_eml();
	if (src == nullptr) {
		mlog(LV_ERR, "ruleproc: %s: OP_DELEGATE: no stored RFC 5322 file", mbox);
		return ecNotFound;
	}
	MAIL imail;
	Json::Value digest;
	if (!imail.refonly_parse(src->c_str(), src->size()) ||
	    imail.make_digest(digest) <= 0)
		return ecError;

	message_content_ptr msg(ctnt->dup());
	if (msg == nullptr)
		return ecServerOOM;
	auto &props = msg->proplist;
	for (auto t : {PR_DISPLAY_TO, PR_DISPLAY_TO_A, PR_DISPLAY_CC,
	     PR_DISPLAY_CC_A, PR_DISPLAY_BCC, PR_DISPLAY_BCC_A, PidTagMid,
	     PR_MESSAGE_SIZE, PR_ASSOCIATED, PidTagChangeNumber,
	     PR_CHANGE_KEY, PR_READ, PR_HASATTACH, PR_PREDECESSOR_CHANGE_LIST,
	     PR_MESSAGE_TO_ME, PR_MESSAGE_CC_ME, PidTagMidString})
		props.erase(t);
	std::string essdn, abkeid, dispname;
	if (!props.has(PR_RCVD_REPRESENTING_ENTRYID)) {
		/* Delivery normally set these already */
		auto err = cvt_username_to_essdn(ev_to, rp_org_name.c_str(),
		           mysql_adaptor_get_user_ids,
		           mysql_adaptor_get_domain_ids, essdn);
		if (err != ecSuccess)
			return err;
		err = cvt_username_to_abkeid(ev_to, rp_org_name.c_str(),
		      DT_MAILUSER, mysql_adaptor_get_user_ids,
		      mysql_adaptor_get_domain_ids, abkeid);
		if (err != ecSuccess)
			return err;
		HX_strupper(essdn.data());
		auto srchkey = "EX:" + essdn;
		BINARY eid_bin, sk_bin;
		eid_bin.cb = abkeid.size();
		eid_bin.pv = abkeid.data();
		sk_bin.cb  = srchkey.size() + 1;
		sk_bin.pv  = srchkey.data();
		if ((err = props.set(PR_RCVD_REPRESENTING_ENTRYID, &eid_bin)) != ecSuccess ||
		    (err = props.set(PR_RCVD_REPRESENTING_ADDRTYPE, "EX")) != ecSuccess ||
		    (err = props.set(PR_RCVD_REPRESENTING_EMAIL_ADDRESS, essdn.c_str())) != ecSuccess ||
		    (err = props.set(PR_RCVD_REPRESENTING_SEARCH_KEY, &sk_bin)) != ecSuccess)
			return err;
		if (mysql_adaptor_get_user_displayname(ev_to, dispname) &&
		    (err = props.set(PR_RCVD_REPRESENTING_NAME, dispname.c_str())) != ecSuccess)
			return err;
	}
	auto err = props.set(PR_DELEGATED_BY_RULE, &byte_value_one);
	if (err != ecSuccess)
		return err;
	err = rx_npid_replace(*this, *msg, dlg_dir);
	if (err != ecSuccess)
		return err;

	char guidtxt[GUIDSTR_SIZE]{};
	GUID::random_new().to_str(guidtxt, std::size(guidtxt), 32);
	auto mid_string = fmt::format("R-{}/{}", &guidtxt[30], guidtxt);
	if (!exmdb_client->imapfile_write(dlg_dir, "eml", mid_string, *src)) {
		mlog(LV_ERR, "ruleproc: OP_DELEGATE: writing %s/eml/%s failed",
			dlg_dir, mid_string.c_str());
		return ecError;
	}
	digest["file"] = std::move(mid_string);
	auto djson = json_to_str(digest);
	unsigned int dflags = DELIVERY_DO_RULES_CL | DELIVERY_DO_NOTIF_CL;
	uint64_t fid = 0, mid = 0;
	uint32_t r32 = 0;
	if (!exmdb_client->deliver_message(dlg_dir, ev_from, addr, CP_ACP,
	    dflags, msg.get(), djson.c_str(), &fid, &mid, &r32)) {
		mlog(LV_ERR, "ruleproc: %s: OP_DELEGATE to %s: deliver_message failed",
			mbox, addr);
		return ecRpcFailed;
	}
	if (r32 != deliver_message_result::result_ok) {
		mlog(LV_ERR, "ruleproc: %s: OP_DELEGATE to %s: delivery result %u",
			mbox, addr, r32);
		return ecSuccess;
	}
	if (g_ruleproc_debug)
		mlog(LV_DEBUG, "ruleproc: %s: OP_DELEGATE copy delivered to %s",
			mbox, addr);
	/* PR_DELEGATED_BY_RULE on the copy keeps this from recursing further */
	rxparam dlg({dlg_dir, eid_t(fid), eid_t(mid)});
	dlg.ev_from = ev_from;
	dlg.ev_to   = addr;
	dlg.m_flags = dflags;
	err = dlg.run();
	if (err != ecSuccess)
		mlog(LV_ERR, "ruleproc: %s: rules of delegate %s: %s",
			mbox, addr, mapi_strerror(err));
	if (!dlg.del)
		dlg_copies.emplace_back(dlg.cur);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

static ec_error_t op_delegate(rxparam &par, const rule_node &rule,
    const FORWARDDELEGATE_ACTION *blk)
{
	if (blk == nullptr || blk->count == 0)
		return ecSuccess;
	if (blk->count > rx_max_rule_rcpts) {
		rx_rule_error(par, rule, RULE_ERROR_TOO_MANY_RCPTS, true);
		return ecSuccess;
	}
	if (par.ctnt->proplist.has(PR_DELEGATED_BY_RULE)) {
		if (g_ruleproc_debug)
			mlog(LV_DEBUG, "ruleproc: %s: delegated message is not delegated again",
				par.orig_dir.c_str());
		return ecSuccess;
	}
	std::vector<std::string> rcpt_list;
	for (const auto &rcptprops : *blk) {
		TPROPVAL_ARRAY pv;
		pv.count = rcptprops.count;
		pv.ppropval = rcptprops.ppropval;
		if (cu_rcpt_to_list(std::move(pv), rp_org_name.c_str(),
		    rcpt_list, mysql_adaptor_userid_to_name, false) != ecSuccess)
			return ecError;
	}
	auto ret = ecSuccess;
	for (const auto &addr : rcpt_list) {
		auto err = par.delegate_to(addr.c_str());
		if (err != ecSuccess && ret == ecSuccess)
			ret = err;
	}
	return ret;
}

/*
 * After OP_DELETE only Out of Office rules still run. Actions that would keep
 * the message in a mailbox are dropped then.
 */
static bool rx_skip_after_delete(const rxparam &par, uint8_t type)
{
	if (!par.del)
		return false;
	switch (type) {
	case OP_MOVE:
	case OP_COPY:
	case OP_TAG:
	case OP_MARK_AS_READ:
	case OP_DEFER_ACTION:
		if (g_ruleproc_debug)
			mlog(LV_DEBUG, "ruleproc: %s: action %u skipped, message is deleted",
				par.orig_dir.c_str(), type);
		return true;
	default:
		return false;
	}
}

/*
 * After a rule with ST_EXIT_LEVEL or OP_DELETE, only Out of Office rules are
 * evaluated, MS-OXORULE v23.0 §3.2.5.1 and §3.2.5.1.1.1.
 */
static bool rx_rule_exited(const rxparam &par, const rule_node &rule)
{
	return (par.exit || par.del) && !(rule.state & rx_oof_only);
}

/**
 * OP_BOUNCE, MS-OXORULE v23.0 §2.2.5.1.2.5 and §3.2.5.1: send a non-delivery
 * report to the sender and drop the message.
 */
static ec_error_t op_bounce(rxparam &par, const rule_node &rule,
    const uint32_t *code) try
{
	if (code == nullptr)
		return ecSuccess;
	const char *type = nullptr;
	switch (*code) {
	case BOUNCE_CODE_MESSAGE_TOO_LARGE:
		type = "BOUNCE_MAIL_TOO_LARGE";
		break;
	case BOUNCE_CODE_MESSAGE_NOT_DISPLAYED:
		type = "BOUNCE_CANNOT_DISPLAY";
		break;
	case BOUNCE_CODE_MESSAGE_DENIED:
		type = "BOUNCE_GENERIC_ERROR";
		break;
	default:
		mlog(LV_WARN, "ruleproc: %s: OP_BOUNCE with unknown code %xh",
			par.orig_dir.c_str(), *code);
		rx_rule_error(par, rule, RULE_ERROR_PARSING, true);
		return ecSuccess;
	}
	par.del = true;
	if (strcasecmp(par.ev_from, ENVELOPE_FROM_NULL) == 0)
		return ecSuccess;
	auto &props = par.ctnt->proplist;
	auto suppress = props.get<const uint32_t>(PR_AUTO_RESPONSE_SUPPRESS);
	if (suppress != nullptr && *suppress & AUTO_RESPONSE_SUPPRESS_NDR)
		return ecSuccess;
	auto domain = strchr(par.ev_to, '@');
	if (domain == nullptr)
		return ecSuccess;
	auto eml = par.get_eml();
	if (eml == nullptr) {
		mlog(LV_ERR, "ruleproc: %s: OP_BOUNCE: no stored RFC 5322 file",
			par.orig_dir.c_str());
		return ecSuccess;
	}
	MAIL orig, ndr;
	if (!orig.refonly_parse(eml->c_str(), eml->size()))
		return ecError;
	auto dtime = props.get<const uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	auto arrival = dtime != nullptr ? rop_util_nttime_to_unix(*dtime) : time(nullptr);
	if (!exml_bouncer_make(get_host_ID(), par.ev_from, par.ev_to, &orig,
	    arrival, type, &ndr)) {
		mlog(LV_ERR, "ruleproc: %s: OP_BOUNCE: no report for %s",
			par.orig_dir.c_str(), type);
		return ecSuccess;
	}
	auto sender = props.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	const std::vector<std::string> rcpt_list = {sender != nullptr ? sender : par.ev_from};
	auto env_from = std::string("postmaster") + domain;
	auto ret = cu_send_mail(ndr, rp_smtp_url.c_str(), env_from.c_str(), rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "ruleproc: OP_BOUNCE cu_send_mail: %s", mapi_strerror(ret));
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static ec_error_t op_switch(rxparam &par, const rule_node &rule,
    const ACTION_BLOCK &act, size_t act_idx)
{
	if (g_ruleproc_debug)
		mlog(LV_DEBUG, "Rule_Action %s", act.repr().c_str());
	par.act_type = act.type;
	par.act_idx  = act_idx;
	if (rx_skip_after_delete(par, act.type))
		return ecSuccess;
	switch (act.type) {
	case OP_MOVE:
	case OP_COPY: {
		auto mc = static_cast<MOVECOPY_ACTION *>(act.pdata);
		if (mc == nullptr)
			return ecSuccess;
		return op_copy(par, rule, *mc, act.type);
	}
	case OP_MARK_AS_READ:
		return op_read(par, rule);
	case OP_TAG:
		return op_tag(par, rule, static_cast<TAGGED_PROPVAL *>(act.pdata));
	case OP_FORWARD:
		return op_forward(par, rule, act);
	case OP_DELETE:
		par.del = true;
		return ecSuccess;
	case OP_DEFER_ACTION:
		par.dams.push_back({&rule, &act});
		return ecSuccess;
	case OP_REPLY:
	case OP_OOF_REPLY:
		return op_reply(par, rule, act);
	case OP_DELEGATE:
		return op_delegate(par, rule, static_cast<const FORWARDDELEGATE_ACTION *>(act.pdata));
	case OP_BOUNCE:
		return op_bounce(par, rule, static_cast<const uint32_t *>(act.pdata));
	default:
		return ecSuccess;
	}
}

/*
 * A rule without a condition is skipped, as in the legacy processor. Clients
 * that mean "all messages" store RES_EXIST(PR_MESSAGE_CLASS).
 */
static bool rx_rule_matches(const rxparam &par, const rule_node &rule)
{
	if (rule.cond == nullptr) {
		if (g_ruleproc_debug)
			mlog(LV_DEBUG, "ruleproc: %s: %srule %llxh has no condition, skipped",
				par.orig_dir.c_str(), rule.extended ? "ext" : "",
				static_cast<unsigned long long>(rule.rule_id));
		return false;
	}
	auto matched = rx_eval_props(par.ctnt, par.ctnt->proplist, *rule.cond);
	if (g_ruleproc_debug)
		mlog(LV_DEBUG, "Rule_Condition %s => %smatch",
			rule.cond->repr().c_str(), matched ? "" : "no ");
	return matched;
}

/*
 * Age limit for ST_KEEP_OOF_HIST entries: the time since the Out of Office
 * state last changed, or since a scheduled period began. Older entries belong
 * to an earlier period, MS-OXORULE v23.0 §3.2.4.2.
 */
static int64_t rx_oof_hist_window(rxparam &par)
{
	if (par.oof_hist_window >= 0)
		return par.oof_hist_window;
	auto dir = par.orig_dir.c_str();
	uint64_t since_change = 0;
	if (!exmdb_client->autoreply_tsquery(dir, OOF_STATE_CHANGE_PEER, 0,
	    &since_change))
		since_change = INT64_MAX;
	int64_t window = std::min(since_change, static_cast<uint64_t>(INT64_MAX));
	static constexpr proptag_t tags[] = {PR_EC_OUTOFOFFICE, PR_EC_OUTOFOFFICE_FROM};
	TPROPVAL_ARRAY props{};
	if (exmdb_client->autoreply_getprop(dir, CP_UTF8, tags, &props)) {
		auto state = props.get<const uint32_t>(PR_EC_OUTOFOFFICE);
		auto from  = props.get<const uint64_t>(PR_EC_OUTOFOFFICE_FROM);
		auto now   = time(nullptr);
		if (state != nullptr && *state == 2 && from != nullptr) {
			auto start = rop_util_nttime_to_unix(*from);
			if (start <= now)
				window = std::min(window, static_cast<int64_t>(now - start));
		}
	}
	par.oof_hist_window = std::max(window, static_cast<int64_t>(1));
	return par.oof_hist_window;
}

/*
 * History key for an OP_OOF_REPLY rule with ST_KEEP_OOF_HIST, MS-OXORULE
 * v23.0 §3.2.5.1.1, or empty if the rule keeps none.
 */
static std::string rx_oof_hist_key(const rxparam &par, const rule_node &rule) try
{
	if (!(rule.state & ST_KEEP_OOF_HIST))
		return {};
	bool oofreply = false;
	if (rule.extended) {
		for (const auto &blk : rule.xact)
			oofreply |= blk.type == OP_OOF_REPLY;
	} else if (rule.act != nullptr) {
		for (size_t i = 0; i < rule.act->count; ++i)
			oofreply |= rule.act->pblock[i].type == OP_OOF_REPLY;
	}
	if (!oofreply)
		return {};
	auto sender = par.ctnt->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (sender == nullptr)
		sender = par.ev_from;
	if (*znul(sender) == '\0' || strcasecmp(sender, ENVELOPE_FROM_NULL) == 0)
		return {};
	std::string key = fmt::format("oofhist:{}{:x}:{}",
	                  rule.extended ? "x" : "", rule.rule_id, sender);
	HX_strlower(key.data());
	return key;
} catch (const std::bad_alloc &) {
	return {};
}

/* Whether the sender already is in the history of the rule */
static bool rx_oof_hist_seen(rxparam &par, const std::string &key)
{
	auto window = rx_oof_hist_window(par);
	uint64_t age = 0;
	if (!exmdb_client->autoreply_tsquery(par.orig_dir.c_str(), key.c_str(),
	    window, &age))
		return false;
	return age < static_cast<uint64_t>(window);
}

/* Evaluate @rule, honoring ST_KEEP_OOF_HIST */
static bool rx_rule_applies(rxparam &par, const rule_node &rule)
{
	auto key = rx_oof_hist_key(par, rule);
	if (!key.empty() && rx_oof_hist_seen(par, key)) {
		if (g_ruleproc_debug)
			mlog(LV_DEBUG, "ruleproc: %s: %srule %llxh skipped, %s was answered before",
				par.orig_dir.c_str(), rule.extended ? "ext" : "",
				static_cast<unsigned long long>(rule.rule_id), key.c_str());
		return false;
	}
	if (!rx_rule_matches(par, rule))
		return false;
	if (!key.empty() &&
	    !exmdb_client->autoreply_tsupdate(par.orig_dir.c_str(), key.c_str()))
		mlog(LV_WARN, "ruleproc: %s: could not update the OOF history",
			par.orig_dir.c_str());
	return true;
}

static ec_error_t op_process(rxparam &par, const rule_node &rule)
{
	if (rx_rule_exited(par, rule))
		return ecSuccess;
	if (!rx_rule_applies(par, rule))
		return ecSuccess;
	if (rule.state & ST_EXIT_LEVEL)
		par.exit = true;
	if (rule.act == nullptr)
		return ecSuccess;
	for (size_t i = 0; i < rule.act->count; ++i) {
		auto ret = op_switch(par, rule, rule.act->pblock[i], i);
		if (ret != ecSuccess) {
			rx_rule_error(par, rule, RULE_ERROR_EXECUTING, false);
			return ret;
		}
	}
	return ecSuccess;
}

/* Extended-rule OP_MOVE/OP_COPY targets a folder in the user's own store. */
static ec_error_t opx_move(rxparam &par, const rule_node &rule,
    const EXT_MOVECOPY_ACTION &mc, uint8_t act_type)
{
	if (mc.folder_eid.eid_type != EITLT_PRIVATE_FOLDER) {
		rx_disable_rule(par, rule);
		return ecSuccess;
	}
	SVREID svreid;
	svreid.folder_id = eid_t(1, rop_util_gc_to_value(mc.folder_eid.folder_gc));
	MOVECOPY_ACTION conv;
	conv.same_store = 1;
	conv.pfolder_eid = &svreid;
	return op_copy(par, rule, conv, act_type);
}

static ec_error_t opx_switch(rxparam &par, const rule_node &rule,
    const EXT_ACTION_BLOCK &act, size_t act_idx)
{
	par.act_type = act.type;
	par.act_idx  = act_idx;
	if (rx_skip_after_delete(par, act.type))
		return ecSuccess;
	switch (act.type) {
	case OP_MOVE:
	case OP_COPY: {
		auto mc = static_cast<EXT_MOVECOPY_ACTION *>(act.pdata);
		if (mc == nullptr)
			return ecSuccess;
		return opx_move(par, rule, *mc, act.type);
	}
	case OP_MARK_AS_READ:
		return op_read(par, rule);
	case OP_TAG:
		return op_tag(par, rule, static_cast<TAGGED_PROPVAL *>(act.pdata));
	case OP_FORWARD:
		return opx_forward(par, rule, act);
	case OP_REPLY:
	case OP_OOF_REPLY:
		return opx_reply(par, rule, act);
	case OP_DELEGATE:
		return op_delegate(par, rule, static_cast<const FORWARDDELEGATE_ACTION *>(act.pdata));
	case OP_DELETE:
		par.del = true;
		return ecSuccess;
	case OP_BOUNCE:
		return op_bounce(par, rule, static_cast<const uint32_t *>(act.pdata));
	default:
		return ecSuccess;
	}
}

static ec_error_t opx_process(rxparam &par, const rule_node &rule)
{
	if (rx_rule_exited(par, rule))
		return ecSuccess;
	if (!rx_rule_applies(par, rule))
		return ecSuccess;
	if (rule.state & ST_EXIT_LEVEL)
		par.exit = true;
	for (size_t i = 0; i < rule.xact.count; ++i) {
		auto ret = opx_switch(par, rule, rule.xact.pblock[i], i);
		if (ret != ecSuccess)
			return ret;
	}
	return ecSuccess;
}

static ec_error_t mr_get_policy(const char *ev_to, mr_policy &pol)
{
	tpropval_array_ptr props(tpropval_array_init());
	if (props == nullptr)
		return ecServerOOM;
	auto &uprop = *props;
	if (!mysql_adaptor_get_user_properties(ev_to, uprop))
		return ecError;
	auto value = uprop.get<uint32_t>(PR_DISPLAY_TYPE_EX);
	pol.dtyp = value == nullptr ? 0 : *value & DTE_MASK_LOCAL;
	auto flag = uprop.get<const uint8_t>(PR_SCHDINFO_DISALLOW_OVERLAPPING_APPTS);
	if (flag != nullptr)
		pol.decline_overlap = *flag != 0;
	else
		pol.decline_overlap = pol.dtyp == DT_ROOM || pol.dtyp == DT_EQUIPMENT;
	flag = uprop.get<uint8_t>(PR_SCHDINFO_DISALLOW_RECURRING_APPTS);
	pol.decline_recurring = flag != nullptr && *flag != 0;
	value = uprop.get<uint32_t>(PR_EMS_AB_ROOM_CAPACITY);
	pol.capacity = value != nullptr ? *value : 0;
	flag = uprop.get<uint8_t>(PR_SCHDINFO_AUTO_ACCEPT_APPTS);
	if (flag != nullptr)
		pol.accept_appts = !!*flag;
	else
		pol.accept_appts = pol.dtyp == DT_ROOM || pol.dtyp == DT_EQUIPMENT;
	return ecSuccess;
}

static const char *mr_get_class(const TPROPVAL_ARRAY &p)
{
	auto cls = p.get<const char>(PR_MESSAGE_CLASS);
	if (cls != nullptr)
		return cls;
	cls = p.get<char>(PR_MESSAGE_CLASS_A);
	return cls != nullptr ? cls : "IPM.Note";
}

/**
 * Mark the inbox message that it was processed.
 *
 * @set_read: Set this to false for messages that a human recipient still needs
 *            to notice.
 */
/*
 * Only update the flags. @par.ctnt was read before the rules ran, writing it
 * back would undo their changes such as OP_TAG and PR_HAS_DAMS, and its named
 * property ids do not fit a message a rule moved into another store.
 */
static ec_error_t mr_mark_done(rxparam &par, bool set_read = true)
{
	if (par.del)
		return ecSuccess; /* deleted by a rule */
	auto err = rx_set_prop(par.cur, {PR_PROCESSED, deconst(&byte_value_one)});
	if (err != ecSuccess)
		return err;
	uint64_t cn = 0;
	if (set_read && !exmdb_client->set_message_read_state(par.cur.dirc(),
	    nullptr, par.cur.mid, true, &cn))
		return ecRpcFailed;
	return ecSuccess;
}

/* Turn the meeting request into the calendar item of the attendee */
static ec_error_t mr_make_cal_item(rxparam &par, const PROPID_ARRAY &propids,
    uint32_t accept_type, uint32_t v_busy, message_content_ptr &msg)
{
	msg.reset(par.ctnt->dup());
	if (msg == nullptr)
		return ecServerOOM;
	auto &prop = msg->proplist;
	static constexpr proptag_t rmprops[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST,
		PR_RECEIVED_BY_ENTRYID, PR_RECEIVED_BY_NAME,
		PR_RECEIVED_BY_ADDRTYPE, PR_RECEIVED_BY_EMAIL_ADDRESS,
		PR_RECEIVED_BY_SEARCH_KEY, PR_RCVD_REPRESENTING_ENTRYID,
		PR_RCVD_REPRESENTING_NAME, PR_RCVD_REPRESENTING_ADDRTYPE,
		PR_RCVD_REPRESENTING_EMAIL_ADDRESS,
		PR_RCVD_REPRESENTING_SEARCH_KEY, PR_MESSAGE_TO_ME,
		PR_TRANSPORT_MESSAGE_HEADERS, PR_CONTENT_FILTER_SCL,
	};
	for (auto t : rmprops)
		prop.erase(t);
	static constexpr uint32_t stateflags = asfMeeting | asfReceived;
	static constexpr uint8_t v_false = false;
	ec_error_t err;
	if ((err = prop.set(PROP_TAG(PT_LONG, propids[l_response_status]), &accept_type)) != ecSuccess ||
	    (err = prop.set(PROP_TAG(PT_LONG, propids[l_busy_status]), &v_busy)) != ecSuccess ||
	    (err = prop.set(PROP_TAG(PT_LONG, propids[l_appt_state_flags]), &stateflags)) != ecSuccess ||
	    (err = prop.set(PR_MESSAGE_CLASS, "IPM.Appointment")) != ecSuccess)
		return err;
	if (!prop.has(propids[l_recurring])) {
		err = prop.set(PROP_TAG(PT_LONG, propids[l_recurring]), &v_false);
		if (err != ecSuccess)
			return err;
	}
	if (!prop.has(PROP_TAG(PT_BOOLEAN, propids[l_appt_sub_type]))) {
		err = prop.set(PROP_TAG(PT_BOOLEAN, propids[l_appt_sub_type]), &v_false);
		if (err != ecSuccess)
			return err;
	}
	return ecSuccess;
}

static ec_error_t mr_insert_to_cal(rxparam &par, const PROPID_ARRAY &propids,
    eid_t cal_fid, uint32_t accept_type)
{
	message_content_ptr msg;
	auto err = mr_make_cal_item(par, propids, accept_type,
	           accept_type == respAccepted ? olBusy : olTentative, msg);
	if (err != ecSuccess)
		return err;
	uint64_t cal_mid = 0, cal_cn = 0;
	if (!exmdb_client->write_message(par.cur.dir.c_str(), CP_ACP,
	    cal_fid, msg.get(), std::string(), &cal_mid, &cal_cn, &err))
		return ecRpcFailed;
	if (err == ecSuccess)
		par.cal_changed = true;
	return err;
}

/*
 * Language of the text that meeting processing writes. The Calendar
 * Attendant of EXC uses the one of the mailbox.
 */
static std::string mr_owner_lang(const rxparam &par)
{
	sql_meta_result mres;
	if (znoval(par.ev_to) ||
	    mysql_adaptor_meta(par.ev_to, WANTPRIV_METAONLY, mres) != 0)
		return {};
	return std::move(mres.lang);
}

static ec_error_t mr_send_response(rxparam &par, bool recurring_flg,
    const PROPID_ARRAY &propids, uint32_t rsp_status) try
{
	auto &rq_prop = par.ctnt->proplist;
	auto want_response = rq_prop.get<const uint8_t>(PR_RESPONSE_REQUESTED);
	if (want_response == nullptr || *want_response == 0)
		return ecSuccess;
	/* OXOCAL v22.1 §3.1.4.8.5: no responses for requests flagged silent */
	auto silent = rq_prop.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_is_silent]));
	if (silent != nullptr && *silent != 0)
		return ecSuccess;

	message_content_ptr rsp_ctnt(message_content_init());
	if (rsp_ctnt == nullptr)
		return ecMAPIOOM;
	auto &rsp_prop = rsp_ctnt->proplist;
	const proptag_t copytags_1[] = {
		/* OXOCAL §3.1.4.8.4 */
		PROP_TAG(PT_UNICODE, propids[l_location]),
		PROP_TAG(PT_UNICODE, propids[l_where]),
		PROP_TAG(PT_LONG, propids[l_appt_seq]),
		PROP_TAG(PT_SYSTIME, propids[l_ownercritchg]),
		PROP_TAG(PT_SYSTIME, propids[l_start_whole]),
		PROP_TAG(PT_SYSTIME, propids[l_end_whole]),
		PROP_TAG(PT_BINARY, propids[l_goid]),
		PROP_TAG(PT_BOOLEAN, propids[l_is_exception]),
		PR_START_DATE, PR_END_DATE, PR_OWNER_APPT_ID, PR_SENSITIVITY,
		PR_ICON_INDEX,
		/* Our stuff */
		PR_SUBJECT_PREFIX, PR_NORMALIZED_SUBJECT,
		PR_CONVERSATION_INDEX_TRACKING,
	};
	const proptag_t copytags_2[] = {
		/* OXOCAL §3.1.4.8.4 */
		PROP_TAG(PT_BINARY, propids[l_tzstruct]),
		PROP_TAG(PT_BINARY, propids[l_apptrecur]),
		PROP_TAG(PT_BINARY, propids[l_tzdefrecur]),
		PROP_TAG(PT_BOOLEAN, propids[l_is_recurring]),
		PROP_TAG(PT_LONG, propids[l_tz]),
		PROP_TAG(PT_UNICODE, propids[l_tzdesc]),
	};
	for (const auto tag : copytags_1) {
		auto v = rq_prop.getval(tag);
		if (v != nullptr) {
			auto err = rsp_prop.set(tag, v);
			if (err != ecSuccess)
				return err;
		}
	}
	if (recurring_flg)
		for (const auto tag : copytags_2) {
			auto v = rq_prop.getval(tag);
			if (v != nullptr) {
				auto err = rsp_prop.set(tag, v);
				if (err != ecSuccess)
					return err;
			}
		}

	/* OXOCAL v22.1 §2.2.7.2 */
	auto lang = mr_owner_lang(par);
	const char *newclass = nullptr, *newprefix = nullptr;
	if (rsp_status == respAccepted) {
		newclass  = "IPM.Schedule.Meeting.Resp.Pos";
		newprefix = meeting_subject_prefix(lang.c_str(), "accepted");
	} else if (rsp_status == respTentative) {
		newclass  = "IPM.Schedule.Meeting.Resp.Tent";
		newprefix = meeting_subject_prefix(lang.c_str(), "tentative");
	} else if (rsp_status == respDeclined) {
		newclass  = "IPM.Schedule.Meeting.Resp.Neg";
		newprefix = meeting_subject_prefix(lang.c_str(), "declined");
	}
	if (newclass != nullptr) {
		auto err = rsp_prop.set(PR_MESSAGE_CLASS, newclass);
		if (err != ecSuccess)
			return err;
	}
	if (newprefix != nullptr) {
		auto norm = rq_prop.get<const char>(PR_NORMALIZED_SUBJECT);
		if (norm == nullptr)
			norm = rq_prop.get<const char>(PR_SUBJECT);
		auto subj = newprefix + std::string(znul(norm));
		ec_error_t err;
		if ((err = rsp_prop.set(PR_SUBJECT_PREFIX, newprefix)) != ecSuccess ||
		    (err = rsp_prop.set(PR_NORMALIZED_SUBJECT, znul(norm))) != ecSuccess ||
		    (err = rsp_prop.set(PR_SUBJECT, subj.c_str())) != ecSuccess)
			return err;
	}
	auto nt_time = rop_util_current_nttime();
	auto err = rsp_prop.set(PROP_TAG(PT_SYSTIME, propids[l_attendeecritchg]), &nt_time);
	if (err != ecSuccess)
		return err;
	auto rcpts = rsp_ctnt->children.prcpts = tarray_set_init();
	if (rcpts == nullptr)
		return ecMAPIOOM;
	auto row = rcpts->emplace();
	if (row == nullptr)
		return ecMAPIOOM;
	auto txt = rq_prop.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
	if (txt == nullptr) {
		mlog(LV_ERR, "%s: no PR_SENT_REPRESENTING_ADDRTYPE available", __func__);
		return ecInvalidParam;
	} else {
		err = row->set(PR_ADDRTYPE, txt);
		if (err != ecSuccess)
			return err;
	}
	txt = rq_prop.get<const char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (txt == nullptr) {
		mlog(LV_ERR, "%s: no PR_SENT_REPRESENTING_EMAIL_ADDRESS available", __func__);
		return ecInvalidParam;
	} else {
		err = row->set(PR_EMAIL_ADDRESS, txt);
		if (err != ecSuccess)
			return err;
	}
	txt = rq_prop.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (txt == nullptr) {
		mlog(LV_ERR, "%s: no PR_SENT_REPRESENTING_SMTP_ADDRESS available", __func__);
		return ecInvalidParam;
	}
	/* ATTENDEE comes from SENT_REPRESENTING, From: from SENDER */
	if (par.ev_to == nullptr || *par.ev_to == '\0') {
		mlog(LV_ERR, "%s: no Envelope-To to identify the responder with", __func__);
		return ecInvalidParam;
	}
	if ((err = rx_set_sender(rsp_prop, par.ev_to)) != ecSuccess)
		return err;
	std::string cvidx;
	if (cvidx_child(rq_prop.get<const BINARY>(PR_CONVERSATION_INDEX),
	    nt_time, cvidx)) {
		BINARY cvbin;
		cvbin.cb = cvidx.size();
		cvbin.pc = cvidx.data();
		err = rsp_prop.set(PR_CONVERSATION_INDEX, &cvbin);
		if (err != ecSuccess)
			return err;
	}

	auto log_id = "f" + std::to_string(rop_util_get_gc_value(par.cur.fid)) +
	              ":m" + std::to_string(rop_util_get_gc_value(par.cur.mid));
	MAIL imail;
	rp_storedir = par.cur.dirc();

	oxcmail_converter cvt;
	cvt.log_id = log_id.c_str();
	cvt.alloc = cu_alloc;
	cvt.get_propids = cu_get_propids;
	cvt.get_propname = cu_get_propname;
	if (!cvt.mapi_to_inet(*rsp_ctnt, imail)) {
		mlog(LV_ERR, "mr_send_response: oxcmail_export failed for an unspecified reason.");
		return ecError;
	}
	err = cu_send_mail(imail, rp_smtp_url.c_str(), par.ev_to, {txt});
	rp_alloc_ctx.clear();
	rp_storedir = nullptr;
	return err;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

/**
 * A cancellation for a single instance of a recurring series carries the
 * instance's original date in the year/month/day fields of the GlobalObjectId
 * (OXOCAL v26 §2.2.1.27). A whole-series or single-meeting cancellation has
 * zeroes there. Returns the instance date as rtime (midnight, local-as-UTC),
 * or 0 for a whole-meeting cancellation.
 *
 * (Producers that emit Z-timezone-form RECURRENCE-ID lines record the UTC day
 * here rather than storing the local one. For meetings whose local day differs
 * from their UTC day, the referenced instance can thus be off by one day.
 * Gromox reads GOID dates as local days throughout, cf. oxcical_export_recid.)
 */
static uint32_t mr_goid_instancedate(const BINARY *goid)
{
	if (goid == nullptr || goid->cb == 0)
		return 0;
	EXT_PULL ep;
	ep.init(goid->pv, goid->cb, exmdb_rpc_alloc, 0);
	GLOBALOBJECTID go{};
	if (ep.g_goid(&go) != pack_result::success)
		return 0;
	if (go.year < 1601 || go.year > 4500 || go.month < 1 || go.month > 12 ||
	    go.day < 1 || go.day > ical_get_monthdays(go.year, go.month))
		return 0;
	time_t ut = 0;
	if (!ical_itime_to_utc(nullptr, ical_time(go.year, go.month, go.day, 0, 0, 0), &ut))
		return 0;
	return rop_util_unix_to_rtime(ut);
}

/**
 * @mid:   message id of the calendar item
 * @seq:   its PidLidAppointmentSequence (0 if absent)
 * @dated: its GlobalObjectId carries an instance date, i.e. the item is a
 *         standalone entry for a single occurrence of a series
 */
struct mr_calitem {
	eid_t mid = 0;
	uint32_t seq = 0;
	bool dated = false;
};

/**
 * Look up calendar item(s) previously entered for this meeting, matched by
 * @match_tag == @match_val. (PidLidGlobalObjectId stays constant across
 * reschedules/updates of the same meeting, and PidLidCleanGlobalObjectId
 * across all messages of a series.) All matches are returned so that the
 * caller can clean any duplicates left over from earlier processing. @goid_tag
 * names the PidLidGlobalObjectId column for the mr_calitem::dated
 * determination.
 */
static ec_error_t mr_find_cal_items(rxparam &par, proptag_t match_tag,
    const BINARY *match_val, proptag_t seq_tag, proptag_t goid_tag,
    std::vector<mr_calitem> &items)
{
	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	if (match_val == nullptr || match_val->cb == 0)
		return ecSuccess;
	const RESTRICTION_PROPERTY rprop = {RELOP_EQ, match_tag, {match_tag, deconst(match_val)}};
	const RESTRICTION rst = {RES_PROPERTY, {deconst(&rprop)}};
	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_content_table(par.cur.dirc(), CP_ACP,
	    cal_fid, nullptr, TABLE_FLAG_NONOTIFICATIONS,
	    &rst, nullptr, &table_id, &row_count))
		return ecRpcFailed;
	auto cl_tbl = HX::make_scope_exit([&]() {
		exmdb_client->unload_table(par.cur.dirc(), table_id);
	});
	if (row_count == 0)
		return ecSuccess;
	const proptag_t qtags[] = {PidTagMid, seq_tag, goid_tag};
	TARRAY_SET rows{};
	if (!exmdb_client->query_table(par.cur.dirc(), nullptr, CP_ACP,
	    table_id, {qtags, std::size(qtags)}, 0, row_count, &rows))
		return ecRpcFailed;
	for (size_t i = 0; i < rows.count; ++i) {
		if (rows.pparray[i] == nullptr)
			continue;
		auto mid = rows.pparray[i]->get<const uint64_t>(PidTagMid);
		if (mid == nullptr)
			continue;
		mr_calitem item;
		item.mid = eid_t(*mid);
		auto seq = rows.pparray[i]->get<const uint32_t>(seq_tag);
		if (seq != nullptr)
			item.seq = *seq;
		item.dated = mr_goid_instancedate(rows.pparray[i]->get<const BINARY>(goid_tag)) != 0;
		items.emplace_back(item);
	}
	return ecSuccess;
}

/**
 * Whether the calendar holds the organizer's own item of the meeting, which
 * has asfMeeting without asfReceived (MS-OXOCAL v22.1 §2.2.1.10). A request or
 * cancellation reaches the organizer only as a forwarded copy, and that must
 * not replace the item.
 */
static ec_error_t mr_have_organizer_item(rxparam &par,
    const PROPID_ARRAY &propids, bool &found)
{
	found = false;
	if (propids[l_appt_state_flags] == 0)
		return ecSuccess;
	auto &rq_prop = par.ctnt->proplist;
	RESTRICTION_PROPERTY id_prop[2];
	RESTRICTION id_rst[2];
	uint32_t id_count = 0;
	for (auto ix : {l_goid, l_cleangoid}) {
		auto tag = PROP_TAG(PT_BINARY, propids[ix]);
		auto val = rq_prop.get<const BINARY>(tag);
		if (propids[ix] == 0 || val == nullptr || val->cb == 0)
			continue;
		id_prop[id_count] = {RELOP_EQ, tag, {tag, deconst(val)}};
		id_rst[id_count] = {RES_PROPERTY, {&id_prop[id_count]}};
		++id_count;
	}
	if (id_count == 0)
		return ecSuccess;
	auto state_tag = PROP_TAG(PT_LONG, propids[l_appt_state_flags]);
	RESTRICTION_AND_OR id_or   = {id_count, id_rst};
	RESTRICTION_BITMASK mtg    = {BMR_NEZ, state_tag, asfMeeting};
	RESTRICTION_BITMASK rcvd   = {BMR_EQZ, state_tag, asfReceived};
	RESTRICTION all[]          = {{RES_OR, {&id_or}}, {RES_BITMASK, {&mtg}}, {RES_BITMASK, {&rcvd}}};
	RESTRICTION_AND_OR all_and = {std::size(all), all};
	RESTRICTION rst            = {RES_AND, {&all_and}};
	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_content_table(par.cur.dirc(), CP_ACP,
	    eid_t(1, PRIVATE_FID_CALENDAR), nullptr, TABLE_FLAG_NONOTIFICATIONS,
	    &rst, nullptr, &table_id, &row_count))
		return ecRpcFailed;
	exmdb_client->unload_table(par.cur.dirc(), table_id);
	found = row_count > 0;
	return ecSuccess;
}

/**
 * Write a modified calendar item back to the store: allocate a new change
 * number, derive a new change key that keeps the replica GUID of the old one,
 * and extend the predecessor change list, so that ICS clients pick up the
 * modification.
 */
static ec_error_t mr_rewrite_cal_item(rxparam &par, eid_t cal_fid,
    uint64_t cal_mid, message_content &cal_ctnt)
{
	auto &props = cal_ctnt.proplist;
	GUID ck_guid{};
	auto old_ck = props.get<const BINARY>(PR_CHANGE_KEY);
	if (old_ck != nullptr && old_ck->cb > 0) {
		EXT_PULL ep;
		XID old_xid;
		ep.init(old_ck->pv, old_ck->cb, exmdb_rpc_alloc, 0);
		if (ep.g_xid(old_ck->cb, &old_xid) == pack_result::success)
			ck_guid = old_xid.guid;
	}
	uint64_t cal_cn = 0;
	if (!exmdb_client->allocate_cn(par.cur.dirc(), &cal_cn))
		return ecRpcFailed;
	XID new_xid{ck_guid, cal_cn};
	auto new_ck = xid_to_bin(new_xid);
	if (new_ck == nullptr)
		return ecServerOOM;
	PCL pcl;
	auto old_pcl = props.get<const BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	if (old_pcl != nullptr && !pcl.deserialize(old_pcl))
		return ecError;
	if (!pcl.append(new_xid))
		return ecServerOOM;
	binary_ptr pclbin(pcl.serialize());
	if (pclbin == nullptr)
		return ecServerOOM;
	ec_error_t err;
	if ((err = props.set(PidTagMid, &cal_mid)) != ecSuccess ||
	    (err = props.set(PidTagChangeNumber, &cal_cn)) != ecSuccess ||
	    (err = props.set(PR_CHANGE_KEY, new_ck)) != ecSuccess ||
	    (err = props.set(PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) != ecSuccess)
		return err;
	uint64_t out_mid = cal_mid, out_cn = 0;
	if (!exmdb_client->write_message(par.cur.dirc(), CP_ACP,
	    cal_fid, &cal_ctnt, {}, &out_mid, &out_cn, &err))
		return ecRpcFailed;
	if (err == ecSuccess)
		par.cal_changed = true;
	return err;
}

/* Attendees of recipient type @type, without the organizer, lowercased */
static std::set<std::string> mr_attendees(const message_content &msg,
    uint32_t type)
{
	std::set<std::string> out;
	if (msg.children.prcpts == nullptr)
		return out;
	for (const auto &row : *msg.children.prcpts) {
		auto rtype = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
		auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (rtype == nullptr || (*rtype & 0xf) != type ||
		    (flags != nullptr && *flags & recipOrganizer))
			continue;
		auto addr = row.get<const char>(PR_SMTP_ADDRESS);
		if (addr == nullptr)
			addr = row.get<const char>(PR_EMAIL_ADDRESS);
		if (addr == nullptr)
			continue;
		std::string a = addr;
		HX_strlower(a.data());
		out.insert(std::move(a));
	}
	return out;
}

/* Start and end of the exceptions by original date */
static std::map<uint32_t, std::pair<uint32_t, uint32_t>>
mr_exceptions(const APPOINTMENT_RECUR_PAT &apr)
{
	std::map<uint32_t, std::pair<uint32_t, uint32_t>> out;
	for (const auto &e : apr.pexceptioninfo)
		out[e.originalstartdate / 1440 * 1440] = {e.startdatetime, e.enddatetime};
	return out;
}

/**
 * Whether two recurrence blobs schedule the same occurrences. An exception
 * on one side for an instance the other side deleted counts as equal: the
 * attendee keeps a cancelled occurrence as an exception, the organizer
 * deletes it.
 */
static bool mr_same_recurrence(const BINARY *a, const BINARY *b)
{
	if (a == nullptr || b == nullptr)
		return a == b;
	if (a->cb == b->cb && memcmp(a->pv, b->pv, a->cb) == 0)
		return true;
	APPOINTMENT_RECUR_PAT x{}, y{};
	EXT_PULL ep;
	ep.init(a->pv, a->cb, exmdb_rpc_alloc, 0);
	if (ep.g_apptrecpat(&x) != pack_result::ok)
		return false;
	ep.init(b->pv, b->cb, exmdb_rpc_alloc, 0);
	if (ep.g_apptrecpat(&y) != pack_result::ok)
		return false;
	auto &p = x.recur_pat, &q = y.recur_pat;
	p.sort_dels();
	q.sort_dels();
	if (p.recurfrequency != q.recurfrequency ||
	    p.patterntype != q.patterntype ||
	    p.calendartype != q.calendartype ||
	    p.firstdatetime != q.firstdatetime || p.period != q.period ||
	    p.pts.monthnth.weekrecur != q.pts.monthnth.weekrecur ||
	    p.pts.monthnth.recurnum != q.pts.monthnth.recurnum ||
	    p.endtype != q.endtype || p.occurrencecount != q.occurrencecount ||
	    p.firstdow != q.firstdow || p.startdate != q.startdate ||
	    p.enddate != q.enddate ||
	    p.pdeletedinstancedates != q.pdeletedinstancedates ||
	    x.starttimeoffset != y.starttimeoffset ||
	    x.endtimeoffset != y.endtimeoffset)
		return false;
	auto ex = mr_exceptions(x), ey = mr_exceptions(y);
	for (const auto &[date, span] : ex) {
		auto i = ey.find(date);
		if (i != ey.end() ? i->second != span : !q.contains_del(date))
			return false;
	}
	for (const auto &[date, span] : ey)
		if (!ex.contains(date) && !p.contains_del(date))
			return false;
	return true;
}

/**
 * Compute PidLidChangeHighlight of meeting request @rq against the calendar
 * item @cal it updates, MS-OXOCAL v22.1 §2.2.6.2. MS-OXCICAL v15.0 maps no
 * iCalendar property to it, so the receiver works it out.
 */
static uint32_t mr_change_highlight(const message_content &rq,
    const message_content &cal, const PROPID_ARRAY &propids)
{
	auto &r = rq.proplist, &c = cal.proplist;
	auto when = [](const TPROPVAL_ARRAY &p, proptag_t tag, proptag_t alt) {
		auto v = p.get<const uint64_t>(tag);
		return v != nullptr ? v : p.get<const uint64_t>(alt);
	};
	auto tdiff = [](const uint64_t *a, const uint64_t *b) {
		return a == nullptr || b == nullptr || *a != *b;
	};
	auto sdiff = [&](proptag_t tag) {
		auto a = r.get<const char>(tag), b = c.get<const char>(tag);
		return strcmp(znul(a), znul(b)) != 0;
	};
	uint32_t ch = 0;
	auto st = PROP_TAG(PT_SYSTIME, propids[l_start_whole]);
	auto et = PROP_TAG(PT_SYSTIME, propids[l_end_whole]);
	if (tdiff(when(r, st, PR_START_DATE), when(c, st, PR_START_DATE)))
		ch |= BIT_CH_START;
	if (tdiff(when(r, et, PR_END_DATE), when(c, et, PR_END_DATE)))
		ch |= BIT_CH_END;
	auto rt = PROP_TAG(PT_BINARY, propids[l_apptrecur]);
	if (!mr_same_recurrence(r.get<const BINARY>(rt), c.get<const BINARY>(rt)))
		ch |= BIT_CH_RECUR;
	if (sdiff(PROP_TAG(PT_UNICODE, propids[l_location])))
		ch |= BIT_CH_LOCATION;
	if (sdiff(PR_SUBJECT))
		ch |= BIT_CH_SUBJECT;
	if (sdiff(PR_BODY))
		ch |= BIT_CH_BODY;
	/* Only added attendees count */
	for (auto [type, bit] : {std::pair{MAPI_TO, BIT_CH_REQATT}, std::pair{MAPI_CC, BIT_CH_OPTATT}}) {
		auto o = mr_attendees(cal, type), n = mr_attendees(rq, type);
		if (!std::includes(o.cbegin(), o.cend(), n.cbegin(), n.cend()))
			ch |= bit;
	}
	return ch;
}

/**
 * Give the rewritten item @msg what the attendee owns on @cal: the
 * reminder, and the response, busy status and reminder of each exception.
 * An informational update changes none of them, MS-OXOCAL v22.1
 * §3.1.4.7.4.2. Exceptions are matched by PidLidExceptionReplaceTime,
 * §3.1.5.1, and in the recurrence blob by their original start.
 */
static ec_error_t mr_keep_attendee_props(rxparam &par,
    const PROPID_ARRAY &propids, const message_content &cal,
    message_content &msg) try
{
	const PROPERTY_NAME xnames[] = {
		{MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime},
		{MNID_ID, PSETID_Common, PidLidReminderSet},
		{MNID_ID, PSETID_Common, PidLidReminderDelta},
		{MNID_ID, PSETID_Common, PidLidReminderTime},
		{MNID_ID, PSETID_Common, PidLidReminderSignalTime},
	};
	const PROPNAME_ARRAY xna = {std::size(xnames), deconst(xnames)};
	PROPID_ARRAY xid;
	if (!exmdb_client->get_named_propids(par.cur.dirc(), true,
	    &xna, &xid) || xid.size() != xna.size())
		return ecRpcFailed;
	for (auto id : xid)
		if (id == 0)
			return ecError;
	const proptag_t rem[] = {
		PROP_TAG(PT_BOOLEAN, xid[1]), PROP_TAG(PT_LONG, xid[2]),
		PROP_TAG(PT_SYSTIME, xid[3]), PROP_TAG(PT_SYSTIME, xid[4]),
	};
	ec_error_t err;
	for (auto tag : rem) {
		auto v = cal.proplist.getval(tag);
		if (v == nullptr)
			msg.proplist.erase(tag);
		else if ((err = msg.proplist.set(tag, v)) != ecSuccess)
			return err;
	}
	if (cal.children.pattachments == nullptr ||
	    msg.children.pattachments == nullptr)
		return ecSuccess;

	auto exrt_tag = PROP_TAG(PT_SYSTIME, xid[0]);
	const proptag_t keep[] = {
		PROP_TAG(PT_LONG, propids[l_response_status]),
		PROP_TAG(PT_LONG, propids[l_busy_status]),
		PROP_TAG(PT_SYSTIME, propids[l_reply_time]),
		PROP_TAG(PT_UNICODE, propids[l_reply_name]),
		rem[0], rem[1], rem[2], rem[3],
	};
	for (auto &na : *msg.children.pattachments) {
		if (na.pembedded == nullptr)
			continue;
		auto t = na.pembedded->proplist.get<const uint64_t>(exrt_tag);
		if (t == nullptr)
			continue;
		/* Nearest replace time, within half a day */
		int64_t best_d = 721;
		const message_content *old = nullptr;
		for (const auto &oa : *cal.children.pattachments) {
			if (oa.pembedded == nullptr)
				continue;
			auto ot = oa.pembedded->proplist.get<const uint64_t>(exrt_tag);
			if (ot == nullptr)
				continue;
			int64_t d = std::abs(static_cast<int64_t>(rop_util_nttime_to_rtime(*ot)) -
			            static_cast<int64_t>(rop_util_nttime_to_rtime(*t)));
			if (d < best_d) {
				best_d = d;
				old = oa.pembedded;
			}
		}
		if (old == nullptr)
			continue;
		for (auto tag : keep) {
			if (PROP_ID(tag) == 0)
				continue;
			auto v = old->proplist.getval(tag);
			if (v != nullptr &&
			    (err = na.pembedded->proplist.set(tag, v)) != ecSuccess)
				return err;
		}
	}

	/* Free/busy and reminders read exceptions from the blob */
	auto recur_tag = PROP_TAG(PT_BINARY, propids[l_apptrecur]);
	auto obin = cal.proplist.get<const BINARY>(recur_tag);
	auto nbin = msg.proplist.get<const BINARY>(recur_tag);
	if (obin == nullptr || nbin == nullptr)
		return ecSuccess;
	APPOINTMENT_RECUR_PAT oapr{}, napr{};
	EXT_PULL ep;
	ep.init(obin->pv, obin->cb, exmdb_rpc_alloc, 0);
	if (ep.g_apptrecpat(&oapr) != pack_result::ok)
		return ecSuccess;
	ep.init(nbin->pv, nbin->cb, exmdb_rpc_alloc, 0);
	if (ep.g_apptrecpat(&napr) != pack_result::ok)
		return ecSuccess;
	static constexpr uint16_t own = ARO_BUSYSTATUS | ARO_REMINDER | ARO_REMINDERDELTA;
	bool changed = false;
	for (const auto &oe : oapr.pexceptioninfo) {
		if (!(oe.overrideflags & own))
			continue;
		for (auto &ne : napr.pexceptioninfo) {
			if (ne.originalstartdate / 1440 != oe.originalstartdate / 1440)
				continue;
			ne.overrideflags |= oe.overrideflags & own;
			if (oe.overrideflags & ARO_BUSYSTATUS)
				ne.busystatus = oe.busystatus;
			if (oe.overrideflags & ARO_REMINDER)
				ne.reminderset = oe.reminderset;
			if (oe.overrideflags & ARO_REMINDERDELTA)
				ne.reminderdelta = oe.reminderdelta;
			changed = true;
		}
	}
	if (!changed)
		return ecSuccess;
	EXT_PUSH epu;
	if (!epu.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    epu.p_apptrecpat(napr) != pack_result::ok)
		return ecError;
	BINARY bin;
	bin.cb = epu.m_offset;
	bin.pv = epu.m_udata;
	return msg.proplist.set(recur_tag, &bin);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

/**
 * Apply a meeting update to the calendar item of an attendee.
 *
 * MS-OXOCAL v22.1 §3.1.4.7.3.1, §3.1.4.7.4.2: an attendee who has
 * responded keeps the response, also those to single occurrences,
 * unless the start, end or recurrence changed. The item is rewritten
 * in place, keeping the attendee's reminders, and the request is marked
 * as an informational update, or as a full one if attendees were added.
 * Sets @done if the update was applied, else the caller replaces the
 * item.
 */
static ec_error_t mr_info_update(rxparam &par, const PROPID_ARRAY &propids,
    const std::vector<mr_calitem> &items, bool &done)
{
	done = false;
	auto it = std::find_if(items.cbegin(), items.cend(),
	          [](const mr_calitem &e) { return !e.dated; });
	if (it == items.cend())
		return ecSuccess;
	message_content *cal = nullptr;
	if (!exmdb_client->read_message(par.cur.dirc(), nullptr, CP_ACP,
	    it->mid, &cal) || cal == nullptr)
		return ecSuccess;
	auto ch = mr_change_highlight(*par.ctnt, *cal, propids);
	const PROPERTY_NAME chname = {MNID_ID, PSETID_Appointment, PidLidChangeHighlight};
	const PROPNAME_ARRAY chnames = {1, deconst(&chname)};
	PROPID_ARRAY chid;
	if (!exmdb_client->get_named_propids(par.cur.dirc(), true,
	    &chnames, &chid) || chid.size() != 1 || chid[0] == 0)
		return ecRpcFailed;
	std::vector<TAGGED_PROPVAL> rqvals{{PROP_TAG(PT_LONG, chid[0]), &ch}};
	auto &cprop = cal->proplist;
	auto resp = cprop.get<const uint32_t>(PROP_TAG(PT_LONG, propids[l_response_status]));
	auto state = cprop.get<const uint32_t>(PROP_TAG(PT_LONG, propids[l_appt_state_flags]));
	/* An attendee added again answers again */
	bool responded = resp != nullptr && (*resp == respTentative ||
	                 *resp == respAccepted || *resp == respDeclined) &&
	                 (state == nullptr || !(*state & asfCanceled));
	if (ch & (BIT_CH_START | BIT_CH_END | BIT_CH_RECUR) || !responded)
		return par.del ? ecSuccess :
		       rx_set_props(par.cur, rqvals.data(), rqvals.size());

	auto busy = cprop.get<const uint32_t>(PROP_TAG(PT_LONG, propids[l_busy_status]));
	message_content_ptr msg;
	auto err = mr_make_cal_item(par, propids, *resp,
	           busy != nullptr ? *busy : *resp == respAccepted ? olBusy : olTentative, msg);
	if (err != ecSuccess)
		return err;
	err = mr_keep_attendee_props(par, propids, *cal, *msg);
	if (err != ecSuccess)
		return err;
	/* Keep what the attendee's response wrote */
	const proptag_t keep[] = {
		PROP_TAG(PT_SYSTIME, propids[l_reply_time]),
		PROP_TAG(PT_UNICODE, propids[l_reply_name]),
		PR_CHANGE_KEY, PR_PREDECESSOR_CHANGE_LIST,
	};
	for (auto tag : keep) {
		if (PROP_ID(tag) == 0)
			continue;
		auto v = cprop.getval(tag);
		if (v != nullptr && (err = msg->proplist.set(tag, v)) != ecSuccess)
			return err;
	}
	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	err = mr_rewrite_cal_item(par, cal_fid, it->mid, *msg);
	if (err != ecSuccess)
		return err;
	/* Duplicates from earlier processing */
	std::vector<eid_t> stale;
	for (const auto &e : items)
		if (e.mid != it->mid)
			stale.emplace_back(e.mid);
	if (!stale.empty()) {
		EID_ARRAY ids = {static_cast<uint32_t>(stale.size()), stale.data()};
		BOOL partial = false;
		if (!exmdb_client->delete_messages(par.cur.dirc(), CP_ACP,
		    nullptr, cal_fid, &ids, true /* hard */, &partial))
			return ecRpcFailed;
	}
	/* MS-OXOCAL v22.1 §2.2.6.5 */
	uint32_t mtg_type = ch & (BIT_CH_REQATT | BIT_CH_OPTATT) ? mtgFull : mtgInfo;
	if (propids[l_meeting_type] != 0)
		rqvals.push_back({PROP_TAG(PT_LONG, propids[l_meeting_type]), &mtg_type});
	if (!par.del) {
		err = rx_set_props(par.cur, rqvals.data(), rqvals.size());
		if (err != ecSuccess)
			return err;
	}
	done = true;
	return ecSuccess;
}

static ec_error_t mr_remove_occurrence(rxparam &, const PROPID_ARRAY &,
	eid_t cal_fid, eid_t cal_mid, uint32_t basedate);
static ec_error_t mr_do_request_occ(rxparam &, const PROPID_ARRAY &,
	uint32_t basedate);

static ec_error_t mr_do_request(rxparam &par, const PROPID_ARRAY &propids,
    const mr_policy &policy)
{
	auto &rq_prop = par.ctnt->proplist;
	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	auto goid_tag  = PROP_TAG(PT_BINARY, propids[l_goid]);
	auto cgoid_tag = PROP_TAG(PT_BINARY, propids[l_cleangoid]);
	auto seq_tag   = PROP_TAG(PT_LONG, propids[l_appt_seq]);
	auto goid      = rq_prop.get<const BINARY>(goid_tag);
	auto cgoid     = rq_prop.get<const BINARY>(cgoid_tag);
	auto basedate  = mr_goid_instancedate(goid);

	/*
	 * An update for one occurrence of a series carries a
	 * GlobalObjectId with the instance date embedded, which by
	 * construction never equals the series master's. In a user
	 * mailbox it becomes an exception of the master. A standalone
	 * item would show the occurrence twice.
	 */
	if (basedate != 0 && !policy.is_resource())
		return mr_do_request_occ(par, propids, basedate);

	/*
	 * Locate the calendar item(s) this request supersedes. An update or
	 * reschedule of the series carries the same GOID as the master, but
	 * standalone items entered earlier for individual occurrences carry an
	 * instance date in theirs and would never match it, so for a series
	 * match on CleanGlobalObjectId, which is shared by the master and all
	 * of its occurrences. An occurrence update matches its own dated GOID,
	 * which selects just that instance.
	 */
	std::vector<eid_t> existing;
	std::vector<mr_calitem> items;
	{
		auto match_tag = goid_tag;
		auto match_val = goid;
		if (basedate == 0 && cgoid != nullptr && cgoid->cb != 0) {
			match_tag = cgoid_tag;
			match_val = cgoid;
		}
		auto err = mr_find_cal_items(par, match_tag, match_val, seq_tag,
		           goid_tag, items);
		if (err != ecSuccess)
			return err;
		/* Ignore stale out-of-order updates that predate what we already have. */
		if (!items.empty()) {
			/*
			 * For a series, compare against the master's
			 * sequence only: per-instance sequences run
			 * independently per RECURRENCE-ID and can
			 * exceed a series update's, which would
			 * discard a valid update as stale.
			 */
			uint32_t newest_seq = 0;
			for (const auto &e : items) {
				if (basedate == 0 && e.dated)
					continue;
				if (e.seq > newest_seq)
					newest_seq = e.seq;
			}
			auto seq = rq_prop.get<const uint32_t>(seq_tag);
			if (seq != nullptr && *seq < newest_seq)
				return mr_mark_done(par);
			for (const auto &e : items)
				existing.emplace_back(e.mid);
		}
	}

	/*
	 * Reject recurring requests right away if so configured. This is a
	 * policy decision independent of any existing booking, so it must run
	 * before the cleanup below: a rejected recurrence must not delete a
	 * single instance the room had already accepted under the same GOID.
	 */
	auto recurring_ptr = rq_prop.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_recurring]));
	auto recurring_flg = recurring_ptr != nullptr && *recurring_ptr != 0;
	if (recurring_flg && policy.decline_recurring) {
		auto err = mr_send_response(par, recurring_flg, propids, respDeclined);
		if (err != ecSuccess)
			return err;
		return mr_mark_done(par);
	}

	if (!policy.is_resource() && !items.empty()) {
		bool done = false;
		auto err = mr_info_update(par, propids, items, done);
		if (err != ecSuccess || done)
			return err;
	}

	/*
	 * Drop the prior booking(s) before the free/busy check, so a rescheduled
	 * meeting does not clash with its own earlier slot. The request
	 * supersedes them: replaced by the new entry below, or released if the
	 * new time now conflicts with another booking.
	 */
	if (!existing.empty()) {
		EID_ARRAY ids = {static_cast<uint32_t>(existing.size()), existing.data()};
		BOOL partial = false;
		if (!exmdb_client->delete_messages(par.cur.dirc(), CP_ACP,
		    nullptr, cal_fid, &ids, true /* hard */, &partial))
			return ecRpcFailed;
	}
	/*
	 * A moved occurrence still holds its original slot in the master's
	 * recurrence blob. Punch it out before the free/busy check, for the
	 * same reason the prior bookings are dropped first: the occurrence
	 * must not clash with its own earlier slot, and the resource must
	 * not go on reporting both as busy afterwards. Reached for
	 * resources only, per the note at the top of this function.
	 */
	if (basedate != 0 && cgoid != nullptr && cgoid->cb != 0) {
		auto seq = rq_prop.get<const uint32_t>(seq_tag);
		std::vector<mr_calitem> masters;
		auto err = mr_find_cal_items(par, cgoid_tag, cgoid, seq_tag,
		           goid_tag, masters);
		if (err != ecSuccess)
			return err;
		for (const auto &e : masters) {
			/* another instance's standalone item */
			if (e.dated)
				continue;
			/*
			 * With no standalone item for this instance, its
			 * sequence lineage is the master's, so a master ahead
			 * of the update means the series was re-issued after
			 * the update was sent and the update is stale. Same
			 * test as in mr_do_cancel.
			 */
			if (existing.empty() && seq != nullptr && e.seq > *seq)
				continue;
			err = mr_remove_occurrence(par, propids, cal_fid,
			      e.mid, basedate);
			if (err != ecSuccess)
				return err;
		}
	}

	/* Lookup conflict state */
	bool res_in_use = false, response_allowed = false;
	auto start_nt = rq_prop.get<uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_start_whole]));
	auto end_nt   = rq_prop.get<uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_end_whole]));
	if (start_nt == nullptr || end_nt == nullptr) {
		start_nt = rq_prop.get<uint64_t>(PR_START_DATE);
		end_nt   = rq_prop.get<uint64_t>(PR_END_DATE);
	}
	if (start_nt != nullptr && end_nt != nullptr) {
		std::vector<freebusy_event> fbdata;
		auto start_ts = rop_util_nttime_to_unix(*start_nt);
		auto end_ts   = rop_util_nttime_to_unix(*end_nt);
		/* XXX: May need PR_SENDER rather than Envelope-From */
		response_allowed = freebusy_perms(par.ev_from, par.cur.dirc()) != 0;
		auto err = get_freebusy(nullptr, par.cur.dirc(), rp_org_name.c_str(),
		           start_ts, end_ts, fbdata);
		if (err != ecSuccess)
			mlog(LV_ERR, "W-PREC: cannot retrieve freebusy %s: %s",
				par.cur.dirc(), mapi_strerror(err));

		for (const freebusy_event &event : fbdata)
			/*
			 * Calendar slots are half-open intervals [start, end):
			 * two ranges conflict iff each starts strictly before the
			 * other ends. Back-to-back bookings (one ends exactly when
			 * the next begins) share only the boundary and do not clash.
			 */
			if (event.start_time < end_ts && event.end_time > start_ts)
				if (event.busy_status != olFree) {
					res_in_use = true;
					break;
				}
	}

	/* Decline double-booking if so configured */
	if (res_in_use && policy.decline_overlap) {
		if (response_allowed) {
			auto err = mr_send_response(par, recurring_flg, propids, respDeclined);
			if (err != ecSuccess)
				return err;
		}
		return mr_mark_done(par);
	}

	/* Enter meeting into calendar */
	auto tent = policy.accept_appts ? respAccepted : respNotResponded;
	auto err = mr_insert_to_cal(par, propids, cal_fid, tent);
	if (err != ecSuccess)
		return err;
	if (tent == respAccepted) {
		if (response_allowed) {
			err = mr_send_response(par, recurring_flg, propids, tent);
			if (err != ecSuccess)
				return err;
		}
		return mr_mark_done(par);
	}
	if (policy.is_resource())
		return mr_mark_done(par);
	return ecSuccess;
}

/**
 * Process an incoming meeting response (Resp.Pos/Tent/Neg) by updating the
 * matching recipient's track status on the organizer's calendar item.
 */
static ec_error_t mr_do_response(rxparam &par, const PROPID_ARRAY &propids)
{
	auto &rsp_prop = par.ctnt->proplist;
	auto rsp_class = mr_get_class(rsp_prop);

	/* Determine response type from message class */
	uint32_t track_status;
	if (class_match_prefix(rsp_class, "IPM.Schedule.Meeting.Resp.Pos") == 0)
		track_status = respAccepted;
	else if (class_match_prefix(rsp_class, "IPM.Schedule.Meeting.Resp.Tent") == 0)
		track_status = respTentative;
	else if (class_match_prefix(rsp_class, "IPM.Schedule.Meeting.Resp.Neg") == 0)
		track_status = respDeclined;
	else
		return ecSuccess;

	/*
	 * The attendee is the represented user. The sender differs when a
	 * delegate answered, see MS-OXOCAL v22.1 §3.1.4.8.4.
	 */
	auto responder = rsp_prop.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (responder == nullptr)
		responder = rsp_prop.get<const char>(PR_SENDER_SMTP_ADDRESS);
	if (responder == nullptr) {
		mlog(LV_WARN, "mr_do_response: no sender SMTP address on response");
		return ecSuccess;
	}

	/* Look up calendar item by CleanGlobalObjectId */
	auto cgoid_tag = PROP_TAG(PT_BINARY, propids[l_cleangoid]);
	auto cgoid = rsp_prop.get<const BINARY>(cgoid_tag);
	if (cgoid == nullptr || cgoid->cb == 0) {
		mlog(LV_WARN, "mr_do_response: no CleanGlobalObjectId on response");
		return ecSuccess;
	}

	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	const RESTRICTION_PROPERTY rprop = {RELOP_EQ, cgoid_tag, {cgoid_tag, deconst(cgoid)}};
	const RESTRICTION rst = {RES_PROPERTY, {deconst(&rprop)}};
	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client->load_content_table(par.cur.dirc(), CP_ACP,
	    cal_fid, nullptr, TABLE_FLAG_NONOTIFICATIONS,
	    &rst, nullptr, &table_id, &row_count))
		return ecRpcFailed;
	auto cl_tbl = HX::make_scope_exit([&]() {
		exmdb_client->unload_table(par.cur.dirc(), table_id);
	});
	if (row_count == 0) {
		mlog(LV_DEBUG, "mr_do_response: no matching calendar item for response from %s", responder);
		return ecSuccess;
	}
	static constexpr proptag_t mid_tag = PidTagMid;
	TARRAY_SET rows{};
	if (!exmdb_client->query_table(par.cur.dirc(), nullptr, CP_ACP,
	    table_id, {&mid_tag, 1}, 0, 1, &rows))
		return ecRpcFailed;
	if (rows.count == 0 || rows.pparray[0] == nullptr)
		return ecSuccess;
	auto cal_mid_p = rows.pparray[0]->get<const uint64_t>(PidTagMid);
	if (cal_mid_p == nullptr)
		return ecSuccess;
	auto cal_mid = *cal_mid_p;

	/* Read the calendar item and duplicate it so we own the memory */
	MESSAGE_CONTENT *cal_raw = nullptr;
	if (!exmdb_client->read_message(par.cur.dirc(), nullptr, CP_ACP,
	    cal_mid, &cal_raw) || cal_raw == nullptr)
		return ecSuccess;
	message_content_ptr cal_ctnt(cal_raw->dup());
	if (cal_ctnt == nullptr)
		return ecServerOOM;

	/* Find matching recipient by SMTP address and update track status */
	bool updated = false;
	if (cal_ctnt->children.prcpts != nullptr) {
		auto nt_time = rop_util_current_nttime();
		for (auto &rcpt : *cal_ctnt->children.prcpts) {
			auto smtp = rcpt.get<const char>(PR_SMTP_ADDRESS);
			if (smtp == nullptr) {
				auto atype = rcpt.get<const char>(PR_ADDRTYPE);
				if (atype != nullptr && strcasecmp(atype, "SMTP") == 0)
					smtp = rcpt.get<const char>(PR_EMAIL_ADDRESS);
			}
			if (smtp == nullptr || strcasecmp(smtp, responder) != 0)
				continue;
			rcpt.set(PR_RECIPIENT_TRACKSTATUS, &track_status);
			rcpt.set(PR_RECIPIENT_TRACKSTATUS_TIME, &nt_time);
			updated = true;
			break;
		}
	}
	if (!updated) {
		mlog(LV_DEBUG, "mr_do_response: recipient %s not found on calendar item", responder);
		return ecSuccess;
	}

	/* Write back the modified calendar item */
	return mr_rewrite_cal_item(par, cal_fid, cal_mid, *cal_ctnt);
}

static std::string mr_cancel_subject(const char *pfx, const char *subj);
static ec_error_t mr_cancel_embedded(message_content &, const PROPID_ARRAY &,
	const char *norm_subj, const char *pfx);

/**
 * Flag a calendar item as cancelled without removing it, i.e. what the EXC
 * Calendar Attendant does for non-resource mailboxes: the item stays visible,
 * but the slot no longer counts as busy.
 */
static ec_error_t mr_cancel_cal_item(rxparam &par, const PROPID_ARRAY &propids,
    eid_t cal_fid, eid_t cal_mid) try
{
	message_content *cal_raw = nullptr;
	if (!exmdb_client->read_message(par.cur.dirc(), nullptr, CP_ACP,
	    cal_mid, &cal_raw) || cal_raw == nullptr)
		return ecSuccess;
	message_content_ptr cal_ctnt(cal_raw->dup());
	if (cal_ctnt == nullptr)
		return ecServerOOM;

	auto &props = cal_ctnt->proplist;
	auto flags_tag = PROP_TAG(PT_LONG, propids[l_appt_state_flags]);
	auto oldfl = props.get<const uint32_t>(flags_tag);
	uint32_t stateflags = (oldfl != nullptr ? *oldfl : asfMeeting | asfReceived) | asfCanceled;
	static constexpr uint32_t v_free = olFree;
	auto pfx = meeting_subject_prefix(mr_owner_lang(par).c_str(), "canceled");
	auto norm = props.get<const char>(PR_NORMALIZED_SUBJECT);
	if (norm == nullptr)
		norm = props.get<const char>(PR_SUBJECT);
	std::string ns = znul(norm);
	props.erase(PR_SUBJECT);
	ec_error_t err;
	if ((err = props.set(flags_tag, &stateflags)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_LONG, propids[l_busy_status]), &v_free)) != ecSuccess ||
	    (err = props.set(PR_SUBJECT_PREFIX, pfx)) != ecSuccess ||
	    (err = props.set(PR_NORMALIZED_SUBJECT, ns.c_str())) != ecSuccess)
		return err;
	/*
	 * The item-level busy status does not cover exceptions carrying an
	 * ARO_BUSYSTATUS override (freebusy reports those from the blob), so
	 * release them too. Exceptions with a subject of their own get the
	 * prefix as well.
	 */
	auto recur_tag = PROP_TAG(PT_BINARY, propids[l_apptrecur]);
	auto recur_bin = props.get<const BINARY>(recur_tag);
	if (recur_bin != nullptr) {
		EXT_PULL ep;
		ep.init(recur_bin->pv, recur_bin->cb, nullptr, 0);
		APPOINTMENT_RECUR_PAT apr{};
		bool changed = false;
		if (ep.g_apptrecpat(&apr) == pack_result::success &&
		    apr.pexceptioninfo.size() == apr.pextendedexception.size()) {
			for (size_t i = 0; i < apr.pexceptioninfo.size(); ++i) {
				auto &ei = apr.pexceptioninfo[i];
				auto &ee = apr.pextendedexception[i];
				if (ei.overrideflags & ARO_SUBJECT) {
					ei.subject = ee.subject = mr_cancel_subject(pfx, ee.subject.c_str());
					changed = true;
				}
				if (!(ei.overrideflags & ARO_BUSYSTATUS) ||
				    ei.busystatus == olFree)
					continue;
				ei.busystatus = olFree;
				changed = true;
			}
		}
		if (changed) {
			EXT_PUSH epu;
			BINARY new_bin;
			if (!epu.init(nullptr, 0, EXT_FLAG_UTF16) ||
			    epu.p_apptrecpat(apr) != pack_result::success)
				return ecError;
			new_bin.cb = epu.m_offset;
			new_bin.pv = epu.m_udata;
			err = props.set(recur_tag, &new_bin);
			if (err != ecSuccess)
				return err;
		}
	}
	/* The exceptions are cancelled with the series */
	if (cal_ctnt->children.pattachments != nullptr)
		for (auto &at : *cal_ctnt->children.pattachments) {
			if (at.pembedded == nullptr)
				continue;
			auto afl = at.proplist.get<const uint32_t>(PR_ATTACHMENT_FLAGS);
			auto cls = at.pembedded->proplist.get<const char>(PR_MESSAGE_CLASS);
			if ((afl == nullptr || !(*afl & afException)) &&
			    (cls == nullptr || strcasecmp(cls, IPM_Appointment_Exception) != 0))
				continue;
			err = mr_cancel_embedded(*at.pembedded, propids, ns.c_str(), pfx);
			if (err != ecSuccess)
				return err;
			auto en = at.pembedded->proplist.get<const char>(PR_NORMALIZED_SUBJECT);
			auto dn = mr_cancel_subject(pfx, znul(en));
			if ((err = at.proplist.set(PR_DISPLAY_NAME, dn.c_str())) != ecSuccess)
				return err;
		}
	return mr_rewrite_cal_item(par, cal_fid, cal_mid, *cal_ctnt);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

/**
 * Remove one occurrence from a recurring master: enter @basedate into the
 * deleted-instance list of the recurrence blob, and if that instance had been
 * rescheduled earlier (i.e. has an exception), drop the exception from the
 * blob as well. A leftover exception attachment is tolerated; clients render
 * occurrences from the blob.
 */
static ec_error_t mr_remove_occurrence(rxparam &par, const PROPID_ARRAY &propids,
    eid_t cal_fid, eid_t cal_mid, uint32_t basedate) try
{
	message_content *cal_raw = nullptr;
	if (!exmdb_client->read_message(par.cur.dirc(), nullptr, CP_ACP,
	    cal_mid, &cal_raw) || cal_raw == nullptr)
		return ecSuccess;
	message_content_ptr cal_ctnt(cal_raw->dup());
	if (cal_ctnt == nullptr)
		return ecServerOOM;
	auto &props = cal_ctnt->proplist;
	auto recur_tag = PROP_TAG(PT_BINARY, propids[l_apptrecur]);
	auto recur_bin = props.get<const BINARY>(recur_tag);
	if (recur_bin == nullptr)
		/* not a recurring master (e.g. a standalone occurrence item) */
		return ecSuccess;
	EXT_PULL ep;
	ep.init(recur_bin->pv, recur_bin->cb, nullptr, 0);
	APPOINTMENT_RECUR_PAT apr{};
	if (ep.g_apptrecpat(&apr) != pack_result::success) {
		mlog(LV_WARN, "mr_remove_occurrence: %s:m%llu: unparsable recurrence blob",
			par.cur.dirc(), static_cast<unsigned long long>(rop_util_get_gc_value(cal_mid)));
		return ecSuccess;
	}
	auto ret = apr.remove_instance(basedate);
	if (ret == 0)
		return ecSuccess; /* already gone */
	if (ret == 2)
		mlog(LV_WARN, "mr_remove_occurrence: %s:m%llu: no modified-instance "
			"entry for exception, leaving exception in place.",
			par.cur.dirc(), static_cast<unsigned long long>(cal_mid.gcv()));
	EXT_PUSH epu;
	if (!epu.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    epu.p_apptrecpat(apr) != pack_result::success)
		return ecError;
	BINARY new_bin;
	new_bin.cb = epu.m_offset;
	new_bin.pv = epu.m_udata;
	auto err = props.set(recur_tag, &new_bin);
	if (err != ecSuccess)
		return err;
	return mr_rewrite_cal_item(par, cal_fid, cal_mid, *cal_ctnt);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

static std::string mr_cancel_subject(const char *pfx, const char *subj)
{
	std::string s = znul(subj);
	if (strncasecmp(s.c_str(), pfx, strlen(pfx)) != 0)
		s.insert(0, pfx);
	return s;
}

/**
 * Flag the exception embedded message of a series as cancelled, like
 * mr_cancel_cal_item does for a whole item.
 */
static ec_error_t mr_cancel_embedded(message_content &emb,
    const PROPID_ARRAY &propids, const char *norm_subj, const char *pfx)
{
	auto &props = emb.proplist;
	auto flags_tag = PROP_TAG(PT_LONG, propids[l_appt_state_flags]);
	auto oldfl = props.get<const uint32_t>(flags_tag);
	uint32_t stateflags = (oldfl != nullptr ? *oldfl : asfMeeting | asfReceived) | asfCanceled;
	static constexpr uint32_t v_free = olFree;
	auto subj = props.get<const char>(PR_NORMALIZED_SUBJECT);
	std::string ns = znul(subj != nullptr ? subj : norm_subj);
	props.erase(PR_SUBJECT);
	ec_error_t err;
	if ((err = props.set(flags_tag, &stateflags)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_LONG, propids[l_busy_status]), &v_free)) != ecSuccess ||
	    (err = props.set(PR_SUBJECT_PREFIX, pfx)) != ecSuccess ||
	    (err = props.set(PR_NORMALIZED_SUBJECT, ns.c_str())) != ecSuccess)
		return err;
	return ecSuccess;
}

/**
 * Build the Exception Attachment object of MS-OXOCAL v22.1 §3.1.4.6.2 for
 * an instance that has none yet, with the embedded message already flagged
 * cancelled. The instance is described by its local-as-UTC rtimes
 * @lstart/@lend and its UTC equivalents @ustart/@uend.
 */
static ec_error_t mr_make_exception(const message_content &master,
    const PROPID_ARRAY &propids, const PROPID_ARRAY &xids,
    uint32_t lstart, uint32_t lend, uint64_t ustart, uint64_t uend,
    const char *pfx, attachment_content *&out) try
{
	message_content_ptr emb(master.dup());
	if (emb == nullptr)
		return ecServerOOM;
	emb->set_attachments_internal(nullptr);
	auto &props = emb->proplist;
	auto norm = props.get<const char>(PR_NORMALIZED_SUBJECT);
	if (norm == nullptr)
		norm = props.get<const char>(PR_SUBJECT);
	std::string ns = znul(norm);
	static constexpr proptag_t rmprops[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST, PR_ENTRYID, PR_SOURCE_KEY,
		PR_PARENT_SOURCE_KEY, PR_HASATTACH, PR_MESSAGE_SIZE,
		PidTagMidString,
	};
	for (auto t : rmprops)
		props.erase(t);
	props.erase(PROP_TAG(PT_BINARY, propids[l_apptrecur]));
	auto exrt_tag   = PROP_TAG(PT_SYSTIME, xids[0]);
	auto cstart_tag = PROP_TAG(PT_SYSTIME, xids[1]);
	auto cend_tag   = PROP_TAG(PT_SYSTIME, xids[2]);
	static constexpr uint8_t v_false = false, v_true = true;
	ec_error_t err;
	if ((err = props.set(PR_MESSAGE_CLASS, IPM_Appointment_Exception)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_BOOLEAN, propids[l_recurring]), &v_false)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_BOOLEAN, propids[l_is_exception]), &v_true)) != ecSuccess ||
	    (err = props.set(PR_START_DATE, &ustart)) != ecSuccess ||
	    (err = props.set(PR_END_DATE, &uend)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, propids[l_start_whole]), &ustart)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, propids[l_end_whole]), &uend)) != ecSuccess ||
	    (err = props.set(cstart_tag, &ustart)) != ecSuccess ||
	    (err = props.set(cend_tag, &uend)) != ecSuccess ||
	    (err = props.set(exrt_tag, &ustart)) != ecSuccess)
		return err;
	err = mr_cancel_embedded(*emb, propids, ns.c_str(), pfx);
	if (err != ecSuccess)
		return err;

	attachment_content_ptr at(attachment_content_init());
	if (at == nullptr)
		return ecServerOOM;
	auto &ap = at->proplist;
	static constexpr uint32_t v_method = ATTACH_EMBEDDED_MSG, v_afl = afException;
	static constexpr uint32_t v_zero = 0, v_rpos = UINT32_MAX;
	uint64_t xstart = rop_util_rtime_to_nttime(lstart);
	uint64_t xend   = rop_util_rtime_to_nttime(lend);
	BINARY v_enc{};
	auto dispname = mr_cancel_subject(pfx, ns.c_str());
	if ((err = ap.set(PR_ATTACH_METHOD, &v_method)) != ecSuccess ||
	    (err = ap.set(PR_ATTACHMENT_FLAGS, &v_afl)) != ecSuccess ||
	    (err = ap.set(PR_ATTACHMENT_HIDDEN, &v_true)) != ecSuccess ||
	    (err = ap.set(PR_ATTACHMENT_LINKID, &v_zero)) != ecSuccess ||
	    (err = ap.set(PR_ATTACH_FLAGS, &v_zero)) != ecSuccess ||
	    (err = ap.set(PR_ATTACH_ENCODING, &v_enc)) != ecSuccess ||
	    (err = ap.set(PR_RENDERING_POSITION, &v_rpos)) != ecSuccess ||
	    (err = ap.set(PR_EXCEPTION_STARTTIME, &xstart)) != ecSuccess ||
	    (err = ap.set(PR_EXCEPTION_ENDTIME, &xend)) != ecSuccess ||
	    (err = ap.set(PR_DISPLAY_NAME, dispname.c_str())) != ecSuccess)
		return err;
	at->set_embedded_internal(emb.release());
	out = at.release();
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

/**
 * Mark one occurrence of a recurring master in an attendee's calendar as
 * cancelled, as the EXC Calendar Attendant does: the occurrence becomes an
 * exception, or keeps the one it already has, whose embedded message carries
 * asfCanceled and the "Canceled:" prefix, and whose slot no longer counts as
 * busy. An instance the user already deleted is not brought back, see
 * MS-OXOCAL v22.1 §3.1.4.9.2.1.
 *
 * @cn_start/@cn_end: the cancellation's start and end in UTC, or nullptr
 */
static ec_error_t mr_cancel_occurrence(rxparam &par, const PROPID_ARRAY &propids,
    eid_t cal_fid, eid_t cal_mid, uint32_t basedate,
    const uint64_t *cn_start, const uint64_t *cn_end) try
{
	message_content *cal_raw = nullptr;
	if (!exmdb_client->read_message(par.cur.dirc(), nullptr, CP_ACP,
	    cal_mid, &cal_raw) || cal_raw == nullptr)
		return ecSuccess;
	message_content_ptr cal_ctnt(cal_raw->dup());
	if (cal_ctnt == nullptr)
		return ecServerOOM;
	auto &props = cal_ctnt->proplist;
	auto recur_tag = PROP_TAG(PT_BINARY, propids[l_apptrecur]);
	auto recur_bin = props.get<const BINARY>(recur_tag);
	if (recur_bin == nullptr)
		return ecSuccess;
	EXT_PULL ep;
	ep.init(recur_bin->pv, recur_bin->cb, nullptr, 0);
	APPOINTMENT_RECUR_PAT apr{};
	if (ep.g_apptrecpat(&apr) != pack_result::success ||
	    apr.pexceptioninfo.size() != apr.pextendedexception.size()) {
		mlog(LV_WARN, "mr_cancel_occurrence: %s:m%llu: unparsable recurrence blob",
			par.cur.dirc(), static_cast<unsigned long long>(cal_mid.gcv()));
		return ecSuccess;
	}
	auto &rp = apr.recur_pat;
	auto day_eq = [](uint32_t a, uint32_t b) { return a / 1440 == b / 1440; };
	auto exi = ct_index_if(apr.pexceptioninfo,
	           [&](const EXCEPTIONINFO &e) { return day_eq(e.originalstartdate, basedate); });
	bool have_exc = exi < apr.pexceptioninfo.size();
	if (!have_exc && std::any_of(rp.pdeletedinstancedates.cbegin(),
	    rp.pdeletedinstancedates.cend(),
	    [&](uint32_t d) { return day_eq(d, basedate); }))
		return ecSuccess;

	const PROPERTY_NAME xnames[] = {
		{MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime},
		{MNID_ID, PSETID_Common, PidLidCommonStart},
		{MNID_ID, PSETID_Common, PidLidCommonEnd},
	};
	const PROPNAME_ARRAY xna = {std::size(xnames), deconst(xnames)};
	PROPID_ARRAY xids;
	if (!exmdb_client->get_named_propids(par.cur.dirc(), TRUE, &xna, &xids) ||
	    xids.size() != xna.size())
		return ecRpcFailed;
	for (auto id : xids)
		if (id == 0)
			return ecError;

	/*
	 * Local time minus UTC, in minutes, at the instance. The series time
	 * zone gives it exactly. Without one, take it from the series start,
	 * and for an instance that kept its slot, from the cancellation's
	 * own start.
	 */
	int64_t off = 0, bias = 0;
	int64_t lorig = static_cast<int64_t>(basedate) + apr.starttimeoffset;
	auto tzbin = props.get<const BINARY>(PROP_TAG(PT_BINARY, propids[l_tzdefrecur]));
	auto tzdef = tzbin != nullptr ? EXT_PULL::bin_to_tzdef(*tzbin) : std::nullopt;
	if (tzdef && tz_to_offset(*tzdef, rop_util_rtime_to_unix(lorig), bias)) {
		off = -bias;
	} else {
		auto mstart = props.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_start_whole]));
		if (mstart == nullptr)
			mstart = props.get<const uint64_t>(PR_START_DATE);
		if (mstart != nullptr)
			off = static_cast<int64_t>(rp.startdate) + apr.starttimeoffset -
			      rop_util_nttime_to_rtime(*mstart);
		if (cn_start != nullptr) {
			int64_t o2 = lorig - rop_util_nttime_to_rtime(*cn_start);
			if (std::abs(o2 - off) <= 120)
				off = o2;
		}
	}

	auto norm = props.get<const char>(PR_NORMALIZED_SUBJECT);
	if (norm == nullptr)
		norm = props.get<const char>(PR_SUBJECT);
	auto pfx = meeting_subject_prefix(mr_owner_lang(par).c_str(), "canceled");
	if (have_exc) {
		auto &ei = apr.pexceptioninfo[exi];
		auto &ee = apr.pextendedexception[exi];
		auto subj = mr_cancel_subject(pfx, ei.overrideflags & ARO_SUBJECT ?
		            ee.subject.c_str() : norm);
		if (!(ei.overrideflags & (ARO_SUBJECT | ARO_LOCATION))) {
			ee.startdatetime     = ei.startdatetime;
			ee.enddatetime       = ei.enddatetime;
			ee.originalstartdate = ei.originalstartdate;
		}
		ei.overrideflags |= ARO_SUBJECT | ARO_BUSYSTATUS;
		ei.subject = ee.subject = std::move(subj);
		ei.busystatus = olFree;
		/*
		 * Find the embedded message by PidLidExceptionReplaceTime of
		 * MS-OXOCAL v22.1 §3.1.5.1, the one nearest the original
		 * start and within half a day of it.
		 */
		auto exrt_tag = PROP_TAG(PT_SYSTIME, xids[0]);
		int64_t uorig = lorig - off, best_d = 721;
		message_content *best = nullptr;
		if (cal_ctnt->children.pattachments != nullptr)
			for (auto &at : *cal_ctnt->children.pattachments) {
				if (at.pembedded == nullptr)
					continue;
				auto t = at.pembedded->proplist.get<const uint64_t>(exrt_tag);
				if (t == nullptr)
					continue;
				int64_t d = std::abs(static_cast<int64_t>(rop_util_nttime_to_rtime(*t)) - uorig);
				if (d < best_d) {
					best_d = d;
					best = at.pembedded;
				}
			}
		if (best != nullptr) {
			auto err = mr_cancel_embedded(*best, propids, norm, pfx);
			if (err != ecSuccess)
				return err;
		} else {
			mlog(LV_WARN, "mr_cancel_occurrence: %s:m%llu: no embedded "
				"message for the exception, blob updated only",
				par.cur.dirc(), static_cast<unsigned long long>(cal_mid.gcv()));
		}
	} else {
		uint32_t lstart = basedate + apr.starttimeoffset;
		uint32_t lend   = basedate + apr.endtimeoffset;
		uint64_t ustart = rop_util_rtime_to_nttime(lstart - off);
		uint64_t uend   = rop_util_rtime_to_nttime(lend - off);
		attachment_content *at = nullptr;
		auto err = mr_make_exception(*cal_ctnt, propids, xids, lstart,
		           lend, ustart, uend, pfx, at);
		if (err != ecSuccess)
			return err;
		if (cal_ctnt->children.pattachments == nullptr) {
			auto al = attachment_list_init();
			if (al == nullptr) {
				attachment_content_free(at);
				return ecServerOOM;
			}
			cal_ctnt->set_attachments_internal(al);
		}
		if (!cal_ctnt->children.pattachments->append_internal(at)) {
			attachment_content_free(at);
			return ecServerOOM;
		}
		if (!rp.contains_del(basedate)) {
			rp.pdeletedinstancedates.emplace_back(basedate);
			rp.sort_dels();
		}
		if (!rp.contains_mod(basedate)) {
			rp.pmodifiedinstancedates.emplace_back(basedate);
			rp.sort_mods();
		}
		auto subj = mr_cancel_subject(pfx, norm);
		auto &ei = apr.pexceptioninfo.emplace_back();
		ei.startdatetime     = lstart;
		ei.enddatetime       = lend;
		ei.originalstartdate = basedate;
		ei.overrideflags     = ARO_SUBJECT | ARO_BUSYSTATUS;
		ei.subject           = subj;
		ei.busystatus        = olFree;
		auto &ee = apr.pextendedexception.emplace_back();
		ee.startdatetime     = lstart;
		ee.enddatetime       = lend;
		ee.originalstartdate = basedate;
		ee.subject           = std::move(subj);
		apr.sort_exceptions();
	}
	EXT_PUSH epu;
	if (!epu.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    epu.p_apptrecpat(apr) != pack_result::success)
		return ecError;
	BINARY new_bin;
	new_bin.cb = epu.m_offset;
	new_bin.pv = epu.m_udata;
	auto err = props.set(recur_tag, &new_bin);
	if (err != ecSuccess)
		return err;
	return mr_rewrite_cal_item(par, cal_fid, cal_mid, *cal_ctnt);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

/**
 * Minutes that local time is ahead of UTC at the local-as-UTC rtime
 * @lt in the series @props. The series time zone gives it exactly.
 * Without one, take it from the series start.
 */
static int64_t mr_series_offset(const TPROPVAL_ARRAY &props,
    const PROPID_ARRAY &propids, const APPOINTMENT_RECUR_PAT &apr, int64_t lt)
{
	int64_t bias = 0;
	auto tzbin = props.get<const BINARY>(PROP_TAG(PT_BINARY, propids[l_tzdefrecur]));
	auto tzdef = tzbin != nullptr ? EXT_PULL::bin_to_tzdef(*tzbin) : std::nullopt;
	if (tzdef && tz_to_offset(*tzdef, rop_util_rtime_to_unix(lt), bias))
		return -bias;
	auto mstart = props.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_start_whole]));
	if (mstart == nullptr)
		mstart = props.get<const uint64_t>(PR_START_DATE);
	if (mstart == nullptr)
		return 0;
	return static_cast<int64_t>(apr.recur_pat.startdate) + apr.starttimeoffset -
	       rop_util_nttime_to_rtime(*mstart);
}

/**
 * Turn the request for one occurrence into the embedded message of its
 * exception: times @ustart/@uend in UTC, @uorig the original start, and
 * not yet answered, see MS-OXOCAL v22.1 §3.1.4.7.4.2.
 */
static ec_error_t mr_occ_embedded(const message_content &rq,
    const PROPID_ARRAY &propids, const PROPID_ARRAY &xids, uint64_t ustart,
    uint64_t uend, uint64_t uorig, message_content_ptr &emb)
{
	emb.reset(rq.dup());
	if (emb == nullptr)
		return ecServerOOM;
	auto &props = emb->proplist;
	static constexpr proptag_t rmprops[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST, PR_ENTRYID, PR_SOURCE_KEY,
		PR_PARENT_SOURCE_KEY, PR_HASATTACH, PR_MESSAGE_SIZE,
		PidTagMidString, PR_PROCESSED,
		PR_RECEIVED_BY_ENTRYID, PR_RECEIVED_BY_NAME,
		PR_RECEIVED_BY_ADDRTYPE, PR_RECEIVED_BY_EMAIL_ADDRESS,
		PR_RECEIVED_BY_SEARCH_KEY, PR_RCVD_REPRESENTING_ENTRYID,
		PR_RCVD_REPRESENTING_NAME, PR_RCVD_REPRESENTING_ADDRTYPE,
		PR_RCVD_REPRESENTING_EMAIL_ADDRESS,
		PR_RCVD_REPRESENTING_SEARCH_KEY, PR_MESSAGE_TO_ME,
		PR_TRANSPORT_MESSAGE_HEADERS, PR_CONTENT_FILTER_SCL,
	};
	for (auto t : rmprops)
		props.erase(t);
	props.erase(PROP_TAG(PT_BINARY, propids[l_apptrecur]));
	auto intended = props.get<const uint32_t>(PROP_TAG(PT_LONG, xids[3]));
	uint32_t v_busy = intended != nullptr && *intended == olFree ? olFree : olTentative;
	static constexpr uint32_t v_resp = respNotResponded;
	static constexpr uint32_t v_state = asfMeeting | asfReceived;
	static constexpr uint8_t v_false = false, v_true = true;
	ec_error_t err;
	if ((err = props.set(PR_MESSAGE_CLASS, IPM_Appointment_Exception)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_BOOLEAN, propids[l_recurring]), &v_false)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_BOOLEAN, propids[l_is_recurring]), &v_true)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_BOOLEAN, propids[l_is_exception]), &v_true)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_LONG, propids[l_response_status]), &v_resp)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_LONG, propids[l_busy_status]), &v_busy)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_LONG, propids[l_appt_state_flags]), &v_state)) != ecSuccess ||
	    (err = props.set(PR_START_DATE, &ustart)) != ecSuccess ||
	    (err = props.set(PR_END_DATE, &uend)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, propids[l_start_whole]), &ustart)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, propids[l_end_whole]), &uend)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, xids[1]), &ustart)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, xids[2]), &uend)) != ecSuccess ||
	    (err = props.set(PROP_TAG(PT_SYSTIME, xids[0]), &uorig)) != ecSuccess)
		return err;
	return ecSuccess;
}

/**
 * Enter an update of one occurrence into the attendee's series, as the EXC
 * Calendar Attendant does. The occurrence becomes an exception with the
 * times, subject and location of the request, or its exception is replaced,
 * see MS-OXOCAL v22.1 §3.1.4.7.4.2. A deleted occurrence comes back. The
 * client finds the exception by its original start, §3.1.5.1.
 */
static ec_error_t mr_update_occurrence(rxparam &par, const PROPID_ARRAY &propids,
    eid_t cal_fid, eid_t cal_mid, uint32_t basedate) try
{
	auto &rq_prop = par.ctnt->proplist;
	auto pstart = rq_prop.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_start_whole]));
	auto pend   = rq_prop.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_end_whole]));
	if (pstart == nullptr || pend == nullptr) {
		pstart = rq_prop.get<const uint64_t>(PR_START_DATE);
		pend   = rq_prop.get<const uint64_t>(PR_END_DATE);
	}
	if (pstart == nullptr || pend == nullptr || *pend < *pstart)
		return ecSuccess;
	uint64_t ustart = *pstart, uend = *pend;

	message_content *cal_raw = nullptr;
	if (!exmdb_client->read_message(par.cur.dirc(), nullptr, CP_ACP,
	    cal_mid, &cal_raw) || cal_raw == nullptr)
		return ecSuccess;
	message_content_ptr cal_ctnt(cal_raw->dup());
	if (cal_ctnt == nullptr)
		return ecServerOOM;
	auto &props = cal_ctnt->proplist;
	/* The organizer's own series is not updated, §3.1.4.7.4.2 */
	auto state = props.get<const uint32_t>(PROP_TAG(PT_LONG, propids[l_appt_state_flags]));
	if (state != nullptr && (*state & asfMeeting) && !(*state & asfReceived))
		return ecSuccess;
	auto recur_tag = PROP_TAG(PT_BINARY, propids[l_apptrecur]);
	auto recur_bin = props.get<const BINARY>(recur_tag);
	if (recur_bin == nullptr)
		return ecSuccess;
	EXT_PULL ep;
	ep.init(recur_bin->pv, recur_bin->cb, nullptr, 0);
	APPOINTMENT_RECUR_PAT apr{};
	if (ep.g_apptrecpat(&apr) != pack_result::success ||
	    apr.pexceptioninfo.size() != apr.pextendedexception.size()) {
		mlog(LV_WARN, "mr_update_occurrence: %s:m%llu: unparsable recurrence blob",
			par.cur.dirc(), static_cast<unsigned long long>(cal_mid.gcv()));
		return ecSuccess;
	}

	const PROPERTY_NAME xnames[] = {
		{MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime},
		{MNID_ID, PSETID_Common, PidLidCommonStart},
		{MNID_ID, PSETID_Common, PidLidCommonEnd},
		{MNID_ID, PSETID_Appointment, PidLidIntendedBusyStatus},
	};
	const PROPNAME_ARRAY xna = {std::size(xnames), deconst(xnames)};
	PROPID_ARRAY xids;
	if (!exmdb_client->get_named_propids(par.cur.dirc(), TRUE, &xna, &xids) ||
	    xids.size() != xna.size())
		return ecRpcFailed;
	for (auto id : xids)
		if (id == 0)
			return ecError;

	auto &rp = apr.recur_pat;
	uint32_t lorig = basedate / 1440 * 1440 + apr.starttimeoffset;
	uint64_t uorig = rop_util_rtime_to_nttime(lorig -
	                 mr_series_offset(props, propids, apr, lorig));
	auto to_local = [&](uint64_t nt) {
		int64_t t = rop_util_nttime_to_rtime(nt);
		return static_cast<uint32_t>(t + mr_series_offset(props, propids, apr, t));
	};
	uint32_t lstart = to_local(ustart), lend = to_local(uend);

	message_content_ptr emb;
	auto err = mr_occ_embedded(*par.ctnt, propids, xids, ustart, uend, uorig, emb);
	if (err != ecSuccess)
		return err;
	auto subj = emb->proplist.get<const char>(PR_SUBJECT);
	auto loc  = emb->proplist.get<const char>(PROP_TAG(PT_UNICODE, propids[l_location]));
	auto busy = *emb->proplist.get<const uint32_t>(PROP_TAG(PT_LONG, propids[l_busy_status]));

	auto day_eq = [](uint32_t a, uint32_t b) { return a / 1440 == b / 1440; };
	auto exi = ct_index_if(apr.pexceptioninfo,
	           [&](const EXCEPTIONINFO &e) { return day_eq(e.originalstartdate, basedate); });
	bool have_exc = exi < apr.pexceptioninfo.size();
	attachment_content *at = nullptr;
	if (have_exc && cal_ctnt->children.pattachments != nullptr) {
		/* Nearest PidLidExceptionReplaceTime, within half a day */
		int64_t best_d = 721;
		for (auto &a : *cal_ctnt->children.pattachments) {
			if (a.pembedded == nullptr)
				continue;
			auto t = a.pembedded->proplist.get<const uint64_t>(PROP_TAG(PT_SYSTIME, xids[0]));
			if (t == nullptr)
				continue;
			int64_t d = std::abs(static_cast<int64_t>(rop_util_nttime_to_rtime(*t)) -
			            static_cast<int64_t>(rop_util_nttime_to_rtime(uorig)));
			if (d < best_d) {
				best_d = d;
				at = &a;
			}
		}
	}
	if (at != nullptr) {
		/* Out-of-date for this instance, §3.1.5.2 */
		auto seq_tag = PROP_TAG(PT_LONG, propids[l_appt_seq]);
		auto oseq = at->pembedded->proplist.get<const uint32_t>(seq_tag);
		auto nseq = rq_prop.get<const uint32_t>(seq_tag);
		if (oseq != nullptr && nseq != nullptr && *nseq < *oseq)
			return ecSuccess;
	} else {
		attachment_content_ptr nat(attachment_content_init());
		if (nat == nullptr)
			return ecServerOOM;
		static constexpr uint32_t v_method = ATTACH_EMBEDDED_MSG, v_afl = afException;
		static constexpr uint32_t v_zero = 0, v_rpos = UINT32_MAX;
		static constexpr uint8_t v_true = true;
		BINARY v_enc{};
		auto &ap = nat->proplist;
		if ((err = ap.set(PR_ATTACH_METHOD, &v_method)) != ecSuccess ||
		    (err = ap.set(PR_ATTACHMENT_FLAGS, &v_afl)) != ecSuccess ||
		    (err = ap.set(PR_ATTACHMENT_HIDDEN, &v_true)) != ecSuccess ||
		    (err = ap.set(PR_ATTACHMENT_LINKID, &v_zero)) != ecSuccess ||
		    (err = ap.set(PR_ATTACH_FLAGS, &v_zero)) != ecSuccess ||
		    (err = ap.set(PR_ATTACH_ENCODING, &v_enc)) != ecSuccess ||
		    (err = ap.set(PR_RENDERING_POSITION, &v_rpos)) != ecSuccess)
			return err;
		if (cal_ctnt->children.pattachments == nullptr) {
			auto al = attachment_list_init();
			if (al == nullptr)
				return ecServerOOM;
			cal_ctnt->set_attachments_internal(al);
		}
		auto raw = nat.release();
		if (!cal_ctnt->children.pattachments->append_internal(raw)) {
			attachment_content_free(raw);
			return ecServerOOM;
		}
		auto &al = *cal_ctnt->children.pattachments;
		at = &al.back();
	}
	uint64_t xstart = rop_util_rtime_to_nttime(lstart);
	uint64_t xend   = rop_util_rtime_to_nttime(lend);
	if ((err = at->proplist.set(PR_EXCEPTION_STARTTIME, &xstart)) != ecSuccess ||
	    (err = at->proplist.set(PR_EXCEPTION_ENDTIME, &xend)) != ecSuccess)
		return err;
	if (subj != nullptr &&
	    (err = at->proplist.set(PR_DISPLAY_NAME, subj)) != ecSuccess)
		return err;
	at->set_embedded_internal(emb.release());

	if (!have_exc) {
		exi = apr.pexceptioninfo.size();
		auto &ei = apr.pexceptioninfo.emplace_back();
		auto &ee = apr.pextendedexception.emplace_back();
		/* MS-OXOCAL v22.1 §2.2.1.44.2: the original start, not its day */
		ei.originalstartdate = ee.originalstartdate = lorig;
		ee.changehighlight.size = sizeof(uint32_t);
		if (!rp.contains_del(basedate)) {
			rp.pdeletedinstancedates.emplace_back(basedate);
			rp.sort_dels();
		}
	} else {
		/* The new start day replaces the old one, §3.1.4.6.2 */
		auto day = apr.pexceptioninfo[exi].startdatetime / 1440 * 1440;
		auto &mods = rp.pmodifiedinstancedates;
		auto it = std::find(mods.begin(), mods.end(), day);
		if (it != mods.end())
			mods.erase(it);
	}
	auto &ei = apr.pexceptioninfo[exi];
	auto &ee = apr.pextendedexception[exi];
	ei.startdatetime = ee.startdatetime = lstart;
	ei.enddatetime   = ee.enddatetime   = lend;
	ei.overrideflags |= ARO_BUSYSTATUS;
	ei.busystatus = busy;
	if (subj != nullptr) {
		ei.overrideflags |= ARO_SUBJECT;
		ei.subject = ee.subject = subj;
	}
	if (loc != nullptr) {
		ei.overrideflags |= ARO_LOCATION;
		ei.location = ee.location = loc;
	}
	rp.pmodifiedinstancedates.emplace_back(lstart / 1440 * 1440);
	rp.sort_mods();
	apr.sort_exceptions();

	EXT_PUSH epu;
	if (!epu.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    epu.p_apptrecpat(apr) != pack_result::success)
		return ecError;
	BINARY new_bin;
	new_bin.cb = epu.m_offset;
	new_bin.pv = epu.m_udata;
	err = props.set(recur_tag, &new_bin);
	if (err != ecSuccess)
		return err;
	return mr_rewrite_cal_item(par, cal_fid, cal_mid, *cal_ctnt);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

/**
 * Update for one occurrence in a user mailbox. The series master of the
 * attendee gets the exception. A standalone item that earlier versions
 * entered for the instance, or a missing series, is left to the client.
 */
static ec_error_t mr_do_request_occ(rxparam &par, const PROPID_ARRAY &propids,
    uint32_t basedate)
{
	auto &rq_prop  = par.ctnt->proplist;
	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	auto goid_tag  = PROP_TAG(PT_BINARY, propids[l_goid]);
	auto cgoid_tag = PROP_TAG(PT_BINARY, propids[l_cleangoid]);
	auto seq_tag   = PROP_TAG(PT_LONG, propids[l_appt_seq]);
	auto goid      = rq_prop.get<const BINARY>(goid_tag);
	auto cgoid     = rq_prop.get<const BINARY>(cgoid_tag);
	auto seq       = rq_prop.get<const uint32_t>(seq_tag);
	if (cgoid == nullptr || cgoid->cb == 0)
		return ecSuccess;
	std::vector<mr_calitem> items;
	auto err = mr_find_cal_items(par, goid_tag, goid, seq_tag, goid_tag, items);
	if (err != ecSuccess)
		return err;
	if (!items.empty())
		return ecSuccess;
	std::vector<mr_calitem> masters;
	err = mr_find_cal_items(par, cgoid_tag, cgoid, seq_tag, goid_tag, masters);
	if (err != ecSuccess)
		return err;
	for (const auto &e : masters) {
		if (e.dated)
			continue;
		/* Same staleness test as in mr_do_cancel */
		if (seq != nullptr && e.seq > *seq)
			continue;
		err = mr_update_occurrence(par, propids, cal_fid, e.mid, basedate);
		if (err != ecSuccess)
			return err;
	}
	return ecSuccess;
}

/**
 * Single occurrence cancelled in a user mailbox. A standalone item entered
 * for the instance is flagged like a cancelled meeting, and in the recurring
 * master the instance becomes a cancelled exception.
 */
static ec_error_t mr_do_cancel_occ(rxparam &par, const PROPID_ARRAY &propids,
    uint32_t basedate)
{
	auto &cn_prop  = par.ctnt->proplist;
	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	auto goid_tag  = PROP_TAG(PT_BINARY, propids[l_goid]);
	auto cgoid_tag = PROP_TAG(PT_BINARY, propids[l_cleangoid]);
	auto seq_tag   = PROP_TAG(PT_LONG, propids[l_appt_seq]);
	auto goid      = cn_prop.get<const BINARY>(goid_tag);
	auto cgoid     = cn_prop.get<const BINARY>(cgoid_tag);
	auto seq       = cn_prop.get<const uint32_t>(seq_tag);
	auto cn_start  = cn_prop.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_start_whole]));
	auto cn_end    = cn_prop.get<const uint64_t>(PROP_TAG(PT_SYSTIME, propids[l_end_whole]));
	if (cn_start == nullptr || cn_end == nullptr) {
		cn_start = cn_prop.get<const uint64_t>(PR_START_DATE);
		cn_end   = cn_prop.get<const uint64_t>(PR_END_DATE);
	}

	std::vector<mr_calitem> items;
	auto err = mr_find_cal_items(par, goid_tag, goid, seq_tag, goid_tag, items);
	if (err != ecSuccess)
		return err;
	uint32_t newest_seq = 0;
	for (const auto &e : items)
		newest_seq = std::max(newest_seq, e.seq);
	if (seq != nullptr && *seq < newest_seq)
		return ecSuccess;
	bool found = false;
	for (const auto &e : items) {
		err = mr_cancel_cal_item(par, propids, cal_fid, e.mid);
		if (err != ecSuccess)
			return err;
		found = true;
	}
	if (cgoid != nullptr && cgoid->cb != 0) {
		std::vector<mr_calitem> masters;
		err = mr_find_cal_items(par, cgoid_tag, cgoid, seq_tag,
		      goid_tag, masters);
		if (err != ecSuccess)
			return err;
		for (const auto &e : masters) {
			if (e.dated)
				continue;
			/* Same staleness test as for resources in mr_do_cancel */
			if (items.empty() && seq != nullptr && e.seq > *seq)
				continue;
			err = mr_cancel_occurrence(par, propids, cal_fid, e.mid,
			      basedate, cn_start, cn_end);
			if (err != ecSuccess)
				return err;
			found = true;
		}
	}
	/* Nothing found: leave the cancellation to the client */
	if (!found)
		return ecSuccess;
	return mr_mark_done(par, false);
}

/**
 * Process an incoming meeting cancellation. Resource mailboxes have their
 * booking dropped outright, like the EXC Resource Booking Attendant does;
 * other mailboxes keep the calendar item, but it is flagged cancelled and
 * its slot freed.
 */
static ec_error_t mr_do_cancel(rxparam &par, const PROPID_ARRAY &propids,
    const mr_policy &policy) try
{
	auto &cn_prop  = par.ctnt->proplist;
	eid_t cal_fid(1, PRIVATE_FID_CALENDAR);
	auto goid_tag  = PROP_TAG(PT_BINARY, propids[l_goid]);
	auto cgoid_tag = PROP_TAG(PT_BINARY, propids[l_cleangoid]);
	auto seq_tag   = PROP_TAG(PT_LONG, propids[l_appt_seq]);
	auto goid      = cn_prop.get<const BINARY>(goid_tag);
	auto cgoid     = cn_prop.get<const BINARY>(cgoid_tag);
	auto basedate  = mr_goid_instancedate(goid);
	auto seq       = cn_prop.get<const uint32_t>(seq_tag);

	if (basedate == 0) {
		/*
		 * Whole meeting/series cancelled. Match by CleanGlobalObjectId
		 * so that standalone items entered for single-occurrence
		 * updates are caught along with the master.
		 */
		if (cgoid == nullptr || cgoid->cb == 0)
			cgoid = goid; /* equal when no instance date is set */
		std::vector<mr_calitem> items;
		auto err = mr_find_cal_items(par, cgoid_tag, cgoid, seq_tag,
		           goid_tag, items);
		if (err != ecSuccess)
			return err;
		if (items.empty())
			return policy.is_resource() ? mr_mark_done(par) : ecSuccess;
		/*
		 * Ignore stale out-of-order cancellations. Compare against the
		 * master's sequence only: per-instance items number their
		 * sequences independently (per RECURRENCE-ID) and may
		 * legitimately exceed that of a series cancellation.
		 */
		uint32_t master_seq = 0;
		for (const auto &e : items)
			if (!e.dated)
				master_seq = std::max(master_seq, e.seq);
		if (seq != nullptr && *seq < master_seq)
			return policy.is_resource() ? mr_mark_done(par) : ecSuccess;
		if (policy.is_resource()) {
			std::vector<eid_t> mids;
			for (const auto &e : items)
				mids.emplace_back(e.mid);
			EID_ARRAY ids = {static_cast<uint32_t>(mids.size()), mids.data()};
			BOOL partial = false;
			if (!exmdb_client->delete_messages(par.cur.dirc(),
			    CP_ACP, nullptr, cal_fid, &ids, true /* hard */, &partial))
				return ecRpcFailed;
			par.cal_changed = true;
			return mr_mark_done(par);
		}
		for (const auto &e : items) {
			err = mr_cancel_cal_item(par, propids, cal_fid, e.mid);
			if (err != ecSuccess)
				return err;
		}
		/*
		 * Flag the message handled so the recipient's client does not
		 * fold the cancellation in a second time, but leave it unread:
		 * the recipient still needs to notice it.
		 */
		return mr_mark_done(par, false);
	}

	/* Single occurrence cancelled */
	if (!policy.is_resource())
		return mr_do_cancel_occ(par, propids, basedate);
	/*
	 * Drop any standalone item previously entered for this instance
	 * (a single-occurrence update arrives with the same dated GOID).
	 */
	std::vector<mr_calitem> items;
	auto err = mr_find_cal_items(par, goid_tag, goid, seq_tag, goid_tag, items);
	if (err != ecSuccess)
		return err;
	if (!items.empty()) {
		/* Ignore stale out-of-order cancellations of this instance */
		uint32_t newest_seq = 0;
		for (const auto &e : items)
			newest_seq = std::max(newest_seq, e.seq);
		if (seq != nullptr && *seq < newest_seq)
			return mr_mark_done(par);
		std::vector<eid_t> mids;
		for (const auto &e : items)
			mids.emplace_back(e.mid);
		EID_ARRAY ids = {static_cast<uint32_t>(mids.size()), mids.data()};
		BOOL partial = false;
		if (!exmdb_client->delete_messages(par.cur.dirc(), CP_ACP,
		    nullptr, cal_fid, &ids, true /* hard */, &partial))
			return ecRpcFailed;
		par.cal_changed = true;
	}

	/* Punch the instance out of the recurring master */
	if (cgoid != nullptr && cgoid->cb != 0) {
		std::vector<mr_calitem> masters;
		err = mr_find_cal_items(par, cgoid_tag, cgoid, seq_tag,
		      goid_tag, masters);
		if (err != ecSuccess)
			return err;
		for (const auto &e : masters) {
			if (e.dated)
				continue; /* another instance's standalone item */
			/*
			 * If the instance was never split off into a standalone
			 * item, its sequence lineage is the master's: a master
			 * with a higher sequence than the cancellation means the
			 * series was re-issued after this cancellation was sent,
			 * i.e. the cancellation is stale. (With a standalone item
			 * present, per-instance sequences run independently and
			 * may legitimately trail the master's.)
			 */
			if (items.empty() && seq != nullptr && e.seq > *seq)
				continue;
			err = mr_remove_occurrence(par, propids, cal_fid, e.mid, basedate);
			if (err != ecSuccess)
				return err;
		}
	}
	return mr_mark_done(par);
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

/**
 * @par.mprop:	message properties of meeting request
 * @ev_from:	sender
 * @policy:	metadata of user ev_to
 */
static ec_error_t mr_start(rxparam &par, const mr_policy &policy)
{
	if (!policy.autoproc)
		return ecSuccess;

	/* Obtain namedprop mappings to supplant @rq_prop */
	const PROPERTY_NAME rq_propname1[] = {
		/* Order as per enum */
		{MNID_ID, PSETID_Appointment, PidLidRecurring},
		{MNID_ID, PSETID_Appointment, PidLidResponseStatus},
		{MNID_ID, PSETID_Appointment, PidLidBusyStatus},
		{MNID_ID, PSETID_Appointment, PidLidRecurrencePattern},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentStateFlags},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSubType},
		{MNID_ID, PSETID_Meeting,     PidLidMeetingType},
		{MNID_ID, PSETID_Appointment, PidLidFInvited},
		{MNID_ID, PSETID_Meeting,     PidLidCleanGlobalObjectId},
		{MNID_ID, PSETID_Appointment, PidLidLocation},
		{MNID_ID, PSETID_Meeting,     PidLidWhere},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSequence},
		{MNID_ID, PSETID_Meeting,     PidLidOwnerCriticalChange},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole},
		{MNID_ID, PSETID_Meeting,     PidLidIsException},
		{MNID_ID, PSETID_Appointment, PidLidTimeZoneStruct},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionRecur},
		{MNID_ID, PSETID_Meeting,     PidLidIsRecurring},
		{MNID_ID, PSETID_Meeting,     PidLidTimeZone},
		{MNID_ID, PSETID_Appointment, PidLidTimeZoneDescription},
		{MNID_ID, PSETID_Meeting,     PidLidGlobalObjectId},
		{MNID_ID, PSETID_Meeting,     PidLidAttendeeCriticalChange},
		{MNID_ID, PSETID_Meeting,     PidLidIsSilent},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentReplyTime},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentReplyName},
	};
	static_assert(std::size(rq_propname1) == l_reply_name + 1);
	const PROPNAME_ARRAY rq_propname = {std::size(rq_propname1), deconst(rq_propname1)};
	PROPID_ARRAY propids;
	if (!exmdb_client->get_named_propids(par.cur.dir.c_str(), false,
	    &rq_propname, &propids) || propids.size() != rq_propname.size())
		return ecError;

	auto &rq_prop = par.ctnt->proplist;
	auto rq_class = mr_get_class(rq_prop);
	bool is_rq = class_match_prefix(rq_class, "IPM.Schedule.Meeting.Request") == 0;
	bool is_cn = class_match_prefix(rq_class, "IPM.Schedule.Meeting.Canceled") == 0;
	if (is_rq || is_cn) {
		bool organizer = false;
		auto err = mr_have_organizer_item(par, propids, organizer);
		if (err != ecSuccess || organizer)
			return err;
	}
	if (is_rq)
		return mr_do_request(par, propids, policy);
	if (is_cn)
		return mr_do_cancel(par, propids, policy);
	if (class_match_prefix(rq_class, "IPM.Schedule.Meeting.Resp") == 0) {
		auto err = mr_do_response(par, propids);
		if (err != ecSuccess)
			return err;
		/*
		 * Flag the response handled so the organizer's client does not
		 * also fold it into the calendar item: a second, independent edit
		 * would diverge from the update mr_do_response just made and would
		 * trip the client's conflict resolution.
		 */
		return mr_mark_done(par);
	}
	return ecSuccess;
}

rxparam::rxparam(message_node &&x) : cur(std::move(x))
{}

ec_error_t rxparam::run_rules()
{
	bool oof = false;
	auto err = is_oof(&oof);
	if (err != ecSuccess)
		return err;
	orig_dir = cur.dir; /* remember where the rule table came from */
	orig_fid = cur.fid;
	std::vector<rule_node> rule_list;
	err = load_std_rules(oof, rule_list);
	if (err != ecSuccess)
		return err;
	err = load_ext_rules(oof, rule_list);
	if (err != ecSuccess)
		return err;
	/*
	 * load_rule_table has no sortorder parameter, but ok, we have to
	 * download the entire rule table anyway, so the benefits of
	 * server-side sorting are zero.
	 */
	std::sort(rule_list.begin(), rule_list.end());

	if (!exmdb_client->read_message(cur.dirc(), nullptr, CP_ACP,
	    cur.mid, &ctnt))
		return ecError;
	if (ctnt == nullptr)
		return ecNotFound;
	/* Rules may move the message, so remember the file name now */
	static constexpr proptag_t midtag[] = {PidTagMidString};
	TPROPVAL_ARRAY midvals{};
	if (exmdb_client->get_message_properties(cur.dirc(), nullptr, CP_ACP,
	    cur.mid, midtag, &midvals))
		orig_midstr = znul(midvals.get<const char>(PidTagMidString));
	for (auto &&rule : rule_list) {
		err = rule.extended ? opx_process(*this, rule) : op_process(*this, rule);
		if (err != ecSuccess)
			/* One failing rule must not keep the others from running */
			mlog(LV_ERR, "ruleproc: %s: %srule %llxh \"%s\" failed: %s",
				orig_dir.c_str(), rule.extended ? "ext" : "",
				static_cast<unsigned long long>(rule.rule_id),
				rule.name.c_str(), mapi_strerror(err));
	}
	if (!del)
		make_dams();
	if (del) {
		const EID_ARRAY ids = {1, &cur.mid};
		BOOL partial;
		if (!exmdb_client->delete_messages(cur.dirc(), CP_ACP, nullptr,
		    cur.fid, &ids, true/*hard*/, &partial))
			mlog(LV_DEBUG, "ruleproc: deletion unsuccessful");
	}
	return ecSuccess;
}

ec_error_t rxparam::run()
{
	ec_error_t ret = ecSuccess;
	if (m_flags & DELIVERY_DO_RULES_CL)
		ret = run_rules();
	/*
	 * A message the rules deleted is still processed for the calendar
	 * when delegates got a copy, as with "send meeting requests to my
	 * delegates only": the delegates act on the calendar of this mailbox,
	 * see MS-OXOCAL v22.1 §3.1.5.1.
	 */
	if (del && dlg_copies.empty())
		/* Message is gone, nothing left to process or announce */
		return ret;

	if (m_flags & DELIVERY_DO_MRAUTOPROC) {
		mr_policy res_policy;
		auto err = ecSuccess;
		if (ctnt == nullptr && (!exmdb_client->read_message(cur.dirc(),
		    nullptr, CP_ACP, cur.mid, &ctnt) || ctnt == nullptr))
			err = ecNotFound;
		if (err == ecSuccess)
			err = mr_get_policy(ev_to, res_policy);
		if (err == ecSuccess)
			err = mr_start(*this, res_policy);
		if (err == ecSuccess && cal_changed)
			stamp_dlg_copies();
		if (ret == ecSuccess)
			ret = err;
	}
	if (del)
		return ret;

	/* The message is committed, so always announce it */
	if (m_flags & DELIVERY_DO_NOTIF_CL)
		notify();
	return ret;
}

/**
 * Tell the delegates' copies that the calendar of this mailbox has been
 * updated for them already, so that their clients may skip doing it
 * again, see MS-OXOCAL v22.1 §3.1.4.7.2.1 and §3.1.4.9.2.1.
 */
void rxparam::stamp_dlg_copies() const try
{
	if (dlg_copies.empty() || ctnt == nullptr)
		return;
	uint32_t actions = cpsUpdatedCalItem;
	if (class_match_prefix(mr_get_class(ctnt->proplist),
	    "IPM.Schedule.Meeting.Request") == 0)
		actions |= cpsCreatedOnPrincipal;
	const PROPERTY_NAME names[] = {
		{MNID_ID, PSETID_CalendarAssistant, PidLidServerProcessed},
		{MNID_ID, PSETID_CalendarAssistant, PidLidServerProcessingActions},
	};
	const PROPNAME_ARRAY pna = {std::size(names), deconst(names)};
	for (const auto &c : dlg_copies) {
		PROPID_ARRAY ids;
		if (!exmdb_client->get_named_propids(c.dirc(), TRUE, &pna, &ids) ||
		    ids.size() != pna.size() || ids[0] == 0 || ids[1] == 0) {
			mlog(LV_ERR, "ruleproc: %s: cannot map named properties", c.dirc());
			continue;
		}
		const TAGGED_PROPVAL pv[] = {
			{PROP_TAG(PT_BOOLEAN, ids[0]), deconst(&byte_value_one)},
			{PROP_TAG(PT_LONG, ids[1]), &actions},
		};
		const TPROPVAL_ARRAY pva = {std::size(pv), deconst(pv)};
		PROBLEM_ARRAY problems{};
		if (!exmdb_client->set_message_properties(c.dirc(), nullptr,
		    CP_ACP, c.mid, &pva, &problems))
			mlog(LV_ERR, "ruleproc: %s: cannot flag the delegate copy", c.dirc());
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "ruleproc: %s: ENOMEM", __func__);
}

/**
 * The RFC 5322 representation stored at delivery time. exmdb does not unlink
 * it when a rule moves or deletes the message, so it stays readable for the
 * whole rule run.
 */
const std::string *rxparam::get_eml()
{
	if (!eml_loaded) {
		eml_loaded = true;
		if (!orig_midstr.empty() &&
		    !exmdb_client->imapfile_read(orig_dir.c_str(), "eml",
		    orig_midstr, &eml))
			eml.clear();
	}
	return eml.empty() ? nullptr : &eml;
}

/**
 * Deferred Action Messages for client-side rules, MS-OXORULE v23.0
 * §2.2.6 and §3.2.5.1.2. One DAM per rule provider.
 */
void rxparam::make_dams() try
{
	if (dams.empty())
		return;
	auto dir = orig_dir.c_str();
	if (dams.size() > rx_max_dams) {
		mlog(LV_NOTICE, "ruleproc: %s: too many deferred actions (%zu), none written",
			dir, dams.size());
		return;
	}
	if (cur.dir != orig_dir) {
		mlog(LV_NOTICE, "ruleproc: %s: message was moved to another store, "
			"deferred actions dropped", dir);
		return;
	}
	static constexpr proptag_t eidtag[] = {PR_ENTRYID};
	TPROPVAL_ARRAY mvals{}, fvals{};
	if (!exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
	    cur.mid, eidtag, &mvals) ||
	    !exmdb_client->get_folder_properties(dir, CP_ACP, orig_fid,
	    eidtag, &fvals))
		return;
	auto msg_eid = mvals.get<const BINARY>(PR_ENTRYID);
	auto fld_eid = fvals.get<const BINARY>(PR_ENTRYID);
	if (msg_eid == nullptr || fld_eid == nullptr)
		return;
	/* ServerEid layout, MS-OXORULE v23.0 §2.2.5.1.2.1.1 */
	EXT_PUSH svp;
	if (!svp.init(nullptr, 0, 0) || svp.p_uint8(1) != pack_result::ok ||
	    svp.p_uint64(cur.fid) != pack_result::ok ||
	    svp.p_uint64(cur.mid) != pack_result::ok ||
	    svp.p_uint32(0) != pack_result::ok)
		return;
	BINARY svreid_bin;
	svreid_bin.cb = svp.m_offset;
	svreid_bin.pv = svp.m_udata;
	uint64_t rule_fid = orig_fid;

	std::vector<bool> done(dams.size());
	for (size_t i = 0; i < dams.size(); ++i) {
		if (done[i])
			continue;
		auto &provider = dams[i].rule->provider;
		std::vector<ACTION_BLOCK> blocks;
		std::vector<uint64_t> ids;
		for (size_t j = i; j < dams.size(); ++j) {
			if (done[j] || strcasecmp(dams[j].rule->provider.c_str(),
			    provider.c_str()) != 0)
				continue;
			done[j] = true;
			blocks.push_back(*dams[j].blk);
			if (std::find(ids.begin(), ids.end(),
			    dams[j].rule->rule_id) == ids.end())
				ids.push_back(dams[j].rule->rule_id);
		}
		const RULE_ACTIONS actions = {static_cast<uint16_t>(blocks.size()), blocks.data()};
		EXT_PUSH acp, idp;
		if (!acp.init(nullptr, 0, EXT_FLAG_UTF16) ||
		    acp.p_rule_actions(actions) != pack_result::ok ||
		    !idp.init(nullptr, 0, 0))
			return;
		for (auto id : ids)
			if (idp.p_uint64(id) != pack_result::ok)
				return;
		BINARY act_bin;
		act_bin.cb = acp.m_offset;
		act_bin.pv = acp.m_udata;
		BINARY ids_bin;
		ids_bin.cb = idp.m_offset;
		ids_bin.pv = idp.m_udata;

		message_content_ptr msg(message_content_init());
		if (msg == nullptr)
			return;
		auto &p = msg->proplist;
		auto now = rop_util_current_nttime();
		if (p.set(PR_CLIENT_SUBMIT_TIME, &now) != ecSuccess ||
		    p.set(PR_CREATION_TIME, &now) != ecSuccess ||
		    p.set(PR_LAST_MODIFICATION_TIME, &now) != ecSuccess ||
		    p.set(PR_MESSAGE_DELIVERY_TIME, &now) != ecSuccess ||
		    p.set(PR_MESSAGE_CLASS, "IPC.Microsoft Exchange 4.0.Deferred Action") != ecSuccess ||
		    p.set(PR_DAM_BACK_PATCHED, &byte_value_zero) != ecSuccess ||
		    p.set(PR_DAM_ORIGINAL_ENTRYID, msg_eid) != ecSuccess ||
		    p.set(PR_DAM_ORIG_MSG_SVREID, &svreid_bin) != ecSuccess ||
		    p.set(PR_RULE_FOLDER_ENTRYID, fld_eid) != ecSuccess ||
		    p.set(PR_RULE_FOLDER_FID, &rule_fid) != ecSuccess ||
		    p.set(PR_RULE_PROVIDER, provider.c_str()) != ecSuccess ||
		    p.set(PR_CLIENT_ACTIONS, &act_bin) != ecSuccess ||
		    p.set(PR_RULE_IDS, &ids_bin) != ecSuccess)
			return;
		uint64_t outmid = 0, outcn = 0;
		auto e_result = ecSuccess;
		if (!exmdb_client->write_message(dir, CP_ACP,
		    eid_t(1, PRIVATE_FID_DEFERRED_ACTION), msg.get(), {},
		    &outmid, &outcn, &e_result) || e_result != ecSuccess) {
			mlog(LV_ERR, "ruleproc: %s: could not write DAM: %s",
				dir, mapi_strerror(e_result));
			return;
		}
	}
	const TAGGED_PROPVAL hasdam[] = {{PR_HAS_DAMS, deconst(&byte_value_one)}};
	const TPROPVAL_ARRAY hasdam_arr = {std::size(hasdam), deconst(hasdam)};
	PROBLEM_ARRAY problems{};
	if (!exmdb_client->set_message_properties(dir, nullptr, CP_ACP,
	    cur.mid, &hasdam_arr, &problems))
		mlog(LV_ERR, "ruleproc: %s: could not set PR_HAS_DAMS", dir);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

void rxparam::notify()
{
	static constexpr proptag_t tagdata[] = {PR_MESSAGE_FLAGS, PR_MESSAGE_CLASS};
	TPROPVAL_ARRAY vals{};
	if (!exmdb_client->get_message_properties(cur.dirc(), nullptr, CP_UTF8,
	    cur.mid, tagdata, &vals)) {
		mlog(LV_ERR, "ruleproc: getprops FL/C failed");
		return;
	}
	auto cls   = vals.get<const char>(PR_MESSAGE_CLASS);
	auto Tflags = vals.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (cls == nullptr || Tflags == nullptr) {
		mlog(LV_ERR, "ruleproc: msg %llxh oddly missing FL/C", static_cast<unsigned long long>(cur.mid));
		return;
	}
	if (!exmdb_client->transport_new_mail(cur.dirc(), cur.fid, cur.mid, *Tflags, cls))
		mlog(LV_ERR, "ruleproc: tnewmail notification unsuccessful");
}

static ec_error_t exmdb_local_rules_execute(const char *dir, const char *ev_from,
    const char *ev_to, eid_t folder_id, eid_t msg_id, unsigned int flags) try
{
	rxparam p({dir, folder_id, msg_id});
	p.ev_from = ev_from;
	p.ev_to   = ev_to;
	p.m_flags = flags;
	return std::move(p).run();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

static constexpr cfg_directive rp_config_defaults[] = {
	{"outgoing_smtp_url", "sendmail://localhost"},
	{"ruleproc_debug", "0", CFG_BOOL},
	CFG_TABLE_END,
};

bool SVC_ruleproc(enum plugin_op reason, const struct dlfuncs &param)
{
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(param);
	if (!register_service("rules_execute", exmdb_local_rules_execute))
		return false;
	auto cfg = config_file_initd("gromox.cfg", get_config_path(), rp_config_defaults);
	if (cfg == nullptr)
		/* e.g. permission error */
		return false;
	g_ruleproc_debug = parse_bool(cfg->get_value("ruleproc_debug"));
	/* Only needed for STOCK_REPLY_TEMPLATE */
	if (bounce_gen_init(get_config_path(), get_data_path(), "mail_bounce") != 0)
		mlog(LV_WARN, "ruleproc: stock reply templates unavailable");
	auto org = cfg->get_value("x500_org_name");
	std::shared_ptr<config_file> lcl;
	if (*znul(org) == '\0') {
		/* Fallback for old installations */
		lcl = config_file_initd("exmdb_local.cfg",
		      get_config_path(), nullptr);
		if (lcl != nullptr)
			org = lcl->get_value("x500_org_name");
	}
	rp_org_name = *znul(org) != '\0' ? org : "Gromox default";
	mlog(LV_DEBUG, "ruleproc: x500 org name is \"%s\"", rp_org_name.c_str());
	/* Same limit as the legacy processor in exmdb_provider */
	static constexpr cfg_directive xp_defaults[] = {
		{"max_ext_rule_number", "20", CFG_SIZE},
		CFG_TABLE_END,
	};
	auto xpc = config_file_initd("exmdb_provider.cfg", get_config_path(), xp_defaults);
	if (xpc != nullptr)
		rp_max_ext_rules = xpc->get_ll("max_ext_rule_number");
	auto str = cfg->get_value("outgoing_smtp_url");
	if (str != nullptr) {
		try {
			rp_smtp_url = vmime::utility::url(str);
		} catch (const vmime::exceptions::malformed_url &e) {
			mlog(LV_ERR, "Malformed URL: outgoing_smtp_url=\"%s\": %s",
				str, e.what());
			return false;
		}
	}
	return TRUE;
}
