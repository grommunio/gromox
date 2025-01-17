// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <vmime/utility/url.hpp>
#include <gromox/config_file.hpp>
#include <gromox/element_data.hpp>
#include <gromox/endian.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#include <gromox/mapidefs.h>
#include <gromox/freebusy.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/svc_common.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include <gromox/rop_util.hpp>

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;
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
	l_attendeecritchg, l_is_silent,
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

struct rx_delete {
	void operator()(BINARY *x) const { rop_util_free_binary(x); }
	void operator()(MESSAGE_CONTENT *x) const { message_content_free(x); }
};

struct mr_policy {
	unsigned int dtyp = 0, capacity = 0;
	bool autoproc = true, accept_appts = false;
	bool decline_overlap = false, decline_recurring = false;

	constexpr bool is_resource() const { return dtyp == DT_ROOM || dtyp == DT_EQUIPMENT; }
};

using message_content_ptr = std::unique_ptr<MESSAGE_CONTENT, rx_delete>;

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
 */
struct rxparam {
	/**
	 * @store_owner, @store_dir, @store_acctid: because EXRPCs APIs are terribly designed
	 */
	struct deleter {
		void operator()(message_content *x) const { message_content_free(x); }
	};

	rxparam(message_node &&in);
	ec_error_t run();
	ec_error_t is_oof(bool *out) const;
	ec_error_t load_std_rules(bool oof, std::vector<rule_node> &out) const;
	ec_error_t load_ext_rules(bool oof, std::vector<rule_node> &out) const;

	const char *ev_from = nullptr, *ev_to = nullptr;
	message_node cur;
	message_content_ptr ctnt;
	bool del = false, exit = false, do_autoproc = true;
};

}

unsigned int g_ruleproc_debug;
static std::string rp_smtp_url;
static thread_local alloc_context rp_alloc_ctx;
static thread_local const char *rp_storedir;

static void *cu_alloc(size_t z)
{
	return rp_alloc_ctx.alloc(z);
}

static BOOL cu_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	return exmdb_client::get_named_propids(rp_storedir, false, names, ids);
}

static BOOL cu_get_propname(uint16_t propid, PROPERTY_NAME **name) try
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

static void rx_npid_transform(TPROPVAL_ARRAY &props,
    const std::vector<uint16_t> &src, const PROPID_ARRAY &dst)
{
	for (unsigned int i = 0; i < props.count; ++i) {
		auto oldtag = props.ppropval[i].proptag;
		if (!is_nameprop_id(PROP_ID(oldtag)))
			continue;
		auto it = std::find(src.begin(), src.end(), PROP_ID(oldtag));
		if (it == src.end())
			continue;
		props.ppropval[i].proptag = PROP_TAG(PROP_TYPE(oldtag), dst[it - src.begin()]);
	}
}

static void rx_npid_transform(MESSAGE_CONTENT &ctnt,
    const std::vector<uint16_t> &src, const PROPID_ARRAY &dst)
{
	rx_npid_transform(ctnt.proplist, src, dst);
	if (ctnt.children.prcpts != nullptr)
		for (auto &rcpt : *ctnt.children.prcpts)
			rx_npid_transform(rcpt, src, dst);
	if (ctnt.children.pattachments != nullptr) {
		for (auto &at : *ctnt.children.pattachments) {
			rx_npid_transform(at.proplist, src, dst);
			if (at.pembedded != nullptr)
				rx_npid_transform(*at.pembedded, src, dst);
		}
	}
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
	auto cl_0 = make_scope_exit([&]() { rx_delete_local(src_name_arr); });
	if (!exmdb_client::get_named_propnames(par.cur.dirc(),
	    src_id_vec, &src_name_arr)) {
		mlog(LV_DEBUG, "ruleproc: get_named_propnames(%s) failed",
			par.cur.dirc());
		return ecRpcFailed;
	}
	if (src_name_arr.size() != src_id_vec.size()) {
		mlog(LV_ERR, "ruleproc: np(src) counts are fishy");
		return ecError;
	}
	if (!exmdb_client::get_named_propids(newdir, TRUE,
	    &src_name_arr, &dst_id_arr)) {
		mlog(LV_DEBUG, "ruleproc: get_named_propids(%s) failed", newdir);
		return ecRpcFailed;
	}
	if (dst_id_arr.size() != src_name_arr.size()) {
		mlog(LV_ERR, "ruleproc: np(dst) counts are fishy");
		return ecError;
	}
	rx_npid_transform(ctnt, src_id_vec, dst_id_arr);
	return ecSuccess;
}

ec_error_t rxparam::is_oof(bool *oof) const
{
	static constexpr uint32_t tags[] = {PR_OOF_STATE};
	static constexpr PROPTAG_ARRAY pt = {std::size(tags), deconst(tags)};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client::get_store_properties(cur.dirc(), CP_UTF8, &pt, &props))
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
	RESTRICTION_BITMASK rst_2 = {BMR_NEZ, PR_RULE_STATE, oof ? ST_ONLY_WHEN_OOF : 0U};
	RESTRICTION rst_3[]       = {{RES_BITMASK, {&rst_1}}, {RES_BITMASK, {&rst_2}}};
	RESTRICTION_AND_OR rst_4  = {std::size(rst_3), rst_3};

	RESTRICTION_EXIST rst_5   = {PR_RULE_STATE};
	RESTRICTION rst_6[]       = {{RES_EXIST, {&rst_5}}, {RES_OR, {&rst_4}}};
	RESTRICTION_AND_OR rst_7  = {std::size(rst_6), rst_6};
	RESTRICTION rst_8         = {RES_AND, {&rst_7}};

	auto dir = cur.dirc();
	if (!exmdb_client::load_rule_table(dir, cur.fid, 0, &rst_8,
	    &table_id, &row_count))
		return ecError;
	auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(dir, table_id); });
	static constexpr uint32_t tags[] = {
		PR_RULE_STATE, PR_RULE_ID, PR_RULE_SEQUENCE, PR_RULE_NAME,
		PR_RULE_PROVIDER, PR_RULE_CONDITION, PR_RULE_ACTIONS,
	};
	const PROPTAG_ARRAY ptags = {std::size(tags), deconst(tags)};
	tarray_set output_rows{};
	if (!exmdb_client::query_table(dir, nullptr, CP_ACP, table_id, &ptags,
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

/**
 * Preconditions: @this->cur needs to be set
 * Postconditions: @rule_list has new rules appended to
 */
ec_error_t rxparam::load_ext_rules(bool oof,
    std::vector<rule_node> &rule_list) const
{
	uint32_t table_id = 0, row_count = 0;

	RESTRICTION_BITMASK rst_1 = {BMR_NEZ, PR_RULE_MSG_STATE, ST_ENABLED};
	RESTRICTION_BITMASK rst_2 = {BMR_NEZ, PR_RULE_MSG_STATE, oof ? ST_ONLY_WHEN_OOF : 0U};
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
	if (!exmdb_client::load_content_table(dir, CP_ACP, cur.fid, nullptr,
	    TABLE_FLAG_ASSOCIATED, &rst_10, &sort_order, &table_id, &row_count))
		return ecError;
	auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(dir, table_id); });

	static constexpr uint32_t tags[] = {
		PR_RULE_MSG_STATE, PidTagMid, PR_RULE_MSG_SEQUENCE,
		PR_RULE_MSG_PROVIDER,
	};
	static constexpr uint32_t tags2[] = {
		PR_EXTENDED_RULE_MSG_CONDITION, PR_EXTENDED_RULE_MSG_ACTIONS,
	};
	const PROPTAG_ARRAY ptags = {std::size(tags), deconst(tags)};
	const PROPTAG_ARRAY ptags2 = {std::size(tags2), deconst(tags2)};
	tarray_set output_rows{};
	if (!exmdb_client::query_table(dir, nullptr, CP_ACP, table_id, &ptags,
	    0, row_count, &output_rows))
		return ecError;

	for (unsigned int i = 0; i < output_rows.count; ++i) {
		auto row   = output_rows.pparray[i];
		if (row == nullptr)
			continue;
		auto seq   = row->get<const int32_t>(PR_RULE_MSG_SEQUENCE);
		auto state = row->get<const uint32_t>(PR_RULE_MSG_STATE);
		auto mid   = row->get<const uint64_t>(PidTagMid);
		if (seq == nullptr || state == nullptr || mid == nullptr)
			continue;

		rule_node rule;
		rule.seq = *seq;
		rule.state = *state;
		rule.extended = true;
		rule.rule_id = *mid;
		rule.name = znul(row->get<const char>(PR_RULE_MSG_NAME));
		rule.provider = znul(row->get<const char>(PR_RULE_MSG_PROVIDER));
		TPROPVAL_ARRAY vals2{};
		if (!exmdb_client::get_message_properties(dir, nullptr, CP_ACP,
		    *mid, &ptags2, &vals2))
			continue;
		auto cond = vals2.get<const BINARY>(PR_EXTENDED_RULE_MSG_CONDITION);
		auto act  = vals2.get<const BINARY>(PR_EXTENDED_RULE_MSG_ACTIONS);
		if (act == nullptr || act->cb == 0)
			continue;
		EXT_PULL ep;
		if (cond != nullptr && cond->cb != 0) {
			ep.init(cond->pb, cond->cb, exmdb_rpc_alloc,
				EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
			if (ep.g_namedprop_info(&rule.xcnames) != EXT_ERR_SUCCESS ||
			    ep.g_restriction(&rule.xcond) != EXT_ERR_SUCCESS)
				return ecError;
			rule.cond = &rule.xcond;
		}
		uint32_t version = 0;
		ep.init(act->pb, act->cb, exmdb_rpc_alloc,
			EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
		if (ep.g_namedprop_info(&rule.xanames) != EXT_ERR_SUCCESS ||
		    ep.g_uint32(&version) != EXT_ERR_SUCCESS ||
		    version != 1 ||
		    ep.g_ext_rule_actions(&rule.xact) != EXT_ERR_SUCCESS)
			return ecError;
		rule_list.emplace_back(std::move(rule));
	}
	return ecSuccess;
}

static bool rx_eval_props(const MESSAGE_CONTENT *ct, const TPROPVAL_ARRAY &props, const RESTRICTION &res);

static bool rx_eval_msgsub(const MESSAGE_CHILDREN &ch, uint32_t tag,
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

static bool rx_eval_sub(const MESSAGE_CONTENT *ct, uint32_t tag, const RESTRICTION &res)
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
		return false;
	}
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
		return rcon.comparable() && rcon.eval(props.getval(rcon.proptag));
	}
	case RES_PROPERTY: {
		auto &rprop = *res.prop;
		// XXX: special-case PR_ANR?
		return rprop.comparable() && rprop.eval(props.getval(rprop.proptag));
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
	}
	return false;
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
	if (!exmdb_client::store_eid_to_user(par.cur.dirc(), &other_store,
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
		dst_fid = rop_util_make_eid_ex(1, tgt_public ?
		          PUBLIC_FID_IPMSUBTREE : PRIVATE_FID_INBOX);
	} else {
		FOLDER_ENTRYID folder_eid{};
		EXT_PULL ep;
		ep.init(fid_bin.pb, fid_bin.cb, malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
		if (ep.g_folder_eid(&folder_eid) != pack_result::success)
			return ecNotFound;
		else if (folder_eid.folder_type == EITLT_PUBLIC_FOLDER && !tgt_public)
			return ecNotFound;
		else if (folder_eid.folder_type == EITLT_PRIVATE_FOLDER && tgt_public)
			return ecNotFound;
		dst_fid = rop_util_make_eid_ex(1, rop_util_gc_to_value(folder_eid.global_counter));
	}

	/*
	 * This would be the place to add a check that the message does not
	 * loop. However, as we only ever load one rule table, namely from the
	 * Envelope-To INBOX folder, we know the execution is finite.
	 */
	uint32_t permission = 0;
	if (!exmdb_client::get_folder_perm(newdir, dst_fid, par.ev_to, &permission))
		return ecRpcFailed;
	if (!(permission & (frightsOwner | frightsCreate)))
		return ecAccessDenied;

	/* Prepare write */
	message_content_ptr dst(par.ctnt->dup());
	if (dst == nullptr)
		return ecMAPIOOM;
	auto err = rx_npid_replace(par, *dst, newdir);
	if (err != ecSuccess)
		return err;
	if (!exmdb_client::allocate_message_id(newdir, dst_fid, &dst_mid) ||
	    !exmdb_client::allocate_cn(newdir, &dst_cn))
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
	std::unique_ptr<BINARY, rx_delete> pclbin(pcl.serialize());
	if (pclbin == nullptr)
		return ecMAPIOOM;
	auto &props = dst->proplist;
	if (!props.has(PR_LAST_MODIFICATION_TIME)) {
		auto last_time = rop_util_current_nttime();
		auto ret = props.set(PR_LAST_MODIFICATION_TIME, &last_time);
		if (ret != 0)
			return ecError;
	}
	int ret;
	if ((ret = props.set(PidTagMid, &dst_mid)) != 0 ||
	    (ret = props.set(PidTagChangeNumber, &dst_cn)) != 0 ||
	    (ret = props.set(PR_CHANGE_KEY, &xidbin)) != 0 ||
	    (ret = props.set(PR_PREDECESSOR_CHANGE_LIST, pclbin.get())) != 0) {
		return ecError;
	}

	/* Writeout */
	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client::write_message(newdir, CP_UTF8, dst_fid,
	    dst.get(), &e_result)) {
		mlog(LV_DEBUG, "ruleproc: write_message failed");
		return ecRpcFailed;
	} else if (e_result != ecSuccess) {
		mlog(LV_DEBUG, "ruleproc: write_message: %s", mapi_strerror(e_result));
		return ecRpcFailed;
	}
	if (g_ruleproc_debug)
		mlog(LV_DEBUG, "ruleproc: OP_COPY/MOVE to %s:%llxh", newdir, LLU{dst_fid});
	if (act_type != OP_MOVE)
		return ecSuccess;

	/* Copy done, delete original message object */
	EID_ARRAY del_mids{};
	del_mids.count = 1;
	del_mids.pids = reinterpret_cast<uint64_t *>(&par.cur.mid);
	BOOL partial = false;
	if (!exmdb_client::delete_messages(par.cur.dirc(), CP_UTF8, nullptr,
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
	if (!mc.same_store)
		return op_copy_other(par, rule, mc, act_type);
	auto &svreid = *static_cast<const SVREID *>(mc.pfolder_eid);
	auto dst_fid = svreid.folder_id;
	if (rop_util_get_replid(dst_fid) != 1)
		return ecNotFound;
	uint64_t dst_mid = 0;
	BOOL result = false;
	if (!exmdb_client::allocate_message_id(par.cur.dirc(), dst_fid, &dst_mid))
		return ecRpcFailed;
	if (!exmdb_client::movecopy_message(par.cur.dirc(), CP_ACP, par.cur.mid,
	    dst_fid, dst_mid, act_type == OP_MOVE ? TRUE : false, &result))
		return ecRpcFailed;
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
	    ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		return nullptr;
	bin->cb = ext_push.m_offset;
	return bin;
}

static ec_error_t op_tag(rxparam &par, const rule_node &rule,
    const TAGGED_PROPVAL *setval)
{
	if (setval == nullptr)
		return ecSuccess;
	uint64_t change_num = 0, modtime = 0;
	if (!exmdb_client::allocate_cn(par.cur.dirc(), &change_num))
		return ecRpcFailed;
	auto change_key = xid_to_bin({GUID{}, change_num});
	if (change_key == nullptr)
		return ecServerOOM;
	const TAGGED_PROPVAL valdata[] = {
		{PidTagChangeNumber, &change_num},
		{PR_CHANGE_KEY, change_key},
		{PR_LOCAL_COMMIT_TIME, &modtime},
		{PR_LAST_MODIFICATION_TIME, &modtime},
		{setval->proptag, setval->pvalue},
	};
	const TPROPVAL_ARRAY valhdr = {std::size(valdata), deconst(valdata)};
	if (valdata[1].pvalue == nullptr)
		return ecServerOOM;
	PROBLEM_ARRAY problems{};
	if (!exmdb_client::set_message_properties(par.cur.dirc(),
	    nullptr, CP_ACP, par.cur.mid, &valhdr, &problems))
		return ecRpcFailed;
	return ecSuccess;
}

static ec_error_t op_read(rxparam &par, const rule_node &rule)
{
	uint64_t cn = 0;
	/* XXX: this RPC cannot cope with nullptr username on public stores */
	if (!exmdb_client::set_message_read_state(par.cur.dirc(),
	    nullptr, par.cur.mid, true, &cn))
		return ecRpcFailed;
	return ecSuccess;
}

static ec_error_t op_switch(rxparam &par, const rule_node &rule,
    const ACTION_BLOCK &act, size_t act_idx)
{
	if (g_ruleproc_debug)
		mlog(LV_DEBUG, "Rule_Action %s", act.repr().c_str());
	switch (act.type) {
	case OP_MOVE:
	case OP_COPY: {
		auto mc = static_cast<MOVECOPY_ACTION *>(act.pdata);
		return mc != nullptr ? op_copy(par, rule, *mc, act.type) : ecSuccess;
	}
	case OP_MARK_AS_READ:
		return op_read(par, rule);
	case OP_TAG:
		return op_tag(par, rule, static_cast<TAGGED_PROPVAL *>(act.pdata));
	case OP_DELETE:
		par.del = true;
		return ecSuccess;
	default:
		return ecSuccess;
	}
}

static ec_error_t op_process(rxparam &par, const rule_node &rule)
{
	/* WHEN_OOF rules already excluded during rule loading. */
	if (par.exit /* && !(rule.state & ST_ONLY_WHEN_OOF) */)
		return ecSuccess;
	if (rule.cond != nullptr) {
		if (g_ruleproc_debug)
			mlog(LV_DEBUG, "Rule_Condition %s", rule.cond->repr().c_str());
		if (!rx_eval_props(par.ctnt.get(), par.ctnt->proplist, *rule.cond))
			return ecSuccess;
	}
	if (rule.state & ST_EXIT_LEVEL)
		par.exit = true;
	if (rule.act == nullptr)
		return ecSuccess;
	for (size_t i = 0; i < rule.act->count; ++i) {
		auto ret = op_switch(par, rule, rule.act->pblock[i], i);
		if (ret != ecSuccess)
			return ret;
	}
	return ecSuccess;
}

static ec_error_t opx_switch(rxparam &par, const rule_node &rule,
    const EXT_ACTION_BLOCK &act, size_t act_idx)
{
	switch (act.type) {
	case OP_MARK_AS_READ:
		return op_read(par, rule);
	case OP_TAG:
		return op_tag(par, rule, static_cast<TAGGED_PROPVAL *>(act.pdata));
	case OP_DELETE:
		par.del = true;
		return ecSuccess;
	default:
		return ecSuccess;
	}
}

static ec_error_t opx_process(rxparam &par, const rule_node &rule)
{
	if (par.exit && !(rule.state & ST_ONLY_WHEN_OOF))
		return ecSuccess;
	if (rule.cond != nullptr &&
	    !rx_eval_props(par.ctnt.get(), par.ctnt->proplist, *rule.cond))
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
	TPROPVAL_ARRAY uprop{};
	if (!mysql_adaptor_get_user_properties(ev_to, uprop))
		return ecError;
	auto flag = uprop.get<const uint8_t>(PR_SCHDINFO_DISALLOW_OVERLAPPING_APPTS);
	pol.decline_overlap = flag != nullptr && *flag != 0;
	flag = uprop.get<uint8_t>(PR_SCHDINFO_DISALLOW_RECURRING_APPTS);
	pol.decline_recurring = flag != nullptr && *flag != 0;
	auto value = uprop.get<uint32_t>(PR_EMS_AB_ROOM_CAPACITY);
	pol.capacity = value != nullptr ? *value : 0;
	value = uprop.get<uint32_t>(PR_DISPLAY_TYPE_EX);
	pol.dtyp = value == nullptr ? 0 : *value & DTE_MASK_LOCAL;
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
 */
static ec_error_t mr_mark_done(rxparam &par)
{
	static constexpr uint8_t v_yes = 1;
	auto &prop = par.ctnt->proplist;
	prop.erase(PR_CHANGE_KEY); /* assign new CK upon write */
	prop.erase(PidTagChangeNumber);
	if (prop.set(PR_PROCESSED, &v_yes) != 0 ||
	    prop.set(PR_READ, &v_yes) != 0)
		return ecServerOOM;
	uint64_t cal_mid = par.cur.mid, cal_cn = 0;
	ec_error_t err = ecSuccess;
	if (!exmdb_client::write_message_v2(par.cur.dir.c_str(), CP_ACP,
	    par.cur.fid, par.ctnt.get(), &cal_mid, &cal_cn, &err))
		return ecRpcFailed;
	return err;
}

static ec_error_t mr_insert_to_cal(rxparam &par, const PROPID_ARRAY &propids,
    eid_t cal_fid, uint32_t accept_type)
{
	message_content_ptr msg(par.ctnt->dup());
	if (msg == nullptr)
		return ecServerOOM;
	auto &prop = msg->proplist;
	static constexpr uint32_t rmprops[] = {
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
	static constexpr uint32_t v_busy = olBusy;
	if (prop.set(PROP_TAG(PT_LONG, propids[l_response_status]), deconst(&accept_type)) != 0 ||
	    prop.set(PROP_TAG(PT_LONG, propids[l_busy_status]), deconst(&v_busy)) != 0 ||
	    prop.set(PR_MESSAGE_CLASS, "IPM.Appointment") != 0)
		return ecError;
	uint64_t cal_mid = 0, cal_cn = 0;
	ec_error_t err = ecSuccess;
	if (!exmdb_client::write_message_v2(par.cur.dir.c_str(), CP_ACP,
	    cal_fid, msg.get(), &cal_mid, &cal_cn, &err))
		return ecRpcFailed;
	return err;
}

static inline uint32_t cvidx_make_delta(uint64_t oldtime, uint64_t now)
{
	auto delta = now - oldtime;
	return delta >= (1ULL << 48) ?
	       (delta >> 23) | (1ULL << 31) :
	       (delta >> 18) & ~(1ULL << 31);
}

static ec_error_t mr_send_response(rxparam &par, bool recurring_flg,
    const PROPID_ARRAY &propids, uint32_t rsp_status) try
{
	auto &rq_prop = par.ctnt->proplist;
	auto want_response = rq_prop.get<const uint8_t>(PR_RESPONSE_REQUESTED);
	if (want_response == nullptr || *want_response == 0)
		return ecSuccess;

	message_content_ptr rsp_ctnt(message_content_init());
	if (rsp_ctnt == nullptr)
		return ecMAPIOOM;
	auto &rsp_prop = rsp_ctnt->proplist;
	static const uint32_t copytags_1[] = {
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
	static const uint32_t copytags_2[] = {
		/* OXOCAL §3.1.4.8.4 */
		PROP_TAG(PT_BINARY, propids[l_tzstruct]),
		PROP_TAG(PT_BINARY, propids[l_apptrecur]),
		PROP_TAG(PT_BINARY, propids[l_tzdefrecur]),
		PROP_TAG(PT_BOOLEAN, propids[l_is_recurring]),
		PROP_TAG(PT_LONG, propids[l_tz]),
		PROP_TAG(PT_UNICODE, propids[l_tzdesc]),
	};
	for (const auto propid : copytags_1) {
		auto v = rq_prop.getval(propid);
		if (v != nullptr && rsp_prop.set(propid, v) != 0)
			return ecMAPIOOM;
	}
	if (recurring_flg)
		for (const auto propid : copytags_2) {
			auto v = rq_prop.getval(propid);
			if (v != nullptr && rsp_prop.set(propid, v) != 0)
				return ecMAPIOOM;
		}
	if (rsp_status == respAccepted) {
		if (rsp_prop.set(PR_MESSAGE_CLASS, "IPM.Schedule.Meeting.Resp.Pos") != 0 ||
		    rsp_prop.set(PR_SUBJECT_PREFIX, "Accepted: ") != 0)
			return ecMAPIOOM;
	} else if (rsp_status == respTentative) {
		if (rsp_prop.set(PR_MESSAGE_CLASS, "IPM.Schedule.Meeting.Resp.Tent") != 0 ||
		    rsp_prop.set(PR_SUBJECT_PREFIX, "Maybe: ") != 0)
			return ecMAPIOOM;
	} else if (rsp_status == respDeclined) {
		if (rsp_prop.set(PR_MESSAGE_CLASS, "IPM.Schedule.Meeting.Resp.Neg") != 0 ||
		    rsp_prop.set(PR_SUBJECT_PREFIX, "Declined: ") != 0)
			return ecMAPIOOM;
	}
	auto nt_time = rop_util_current_nttime();
	if (rsp_prop.set(PROP_TAG(PT_SYSTIME, propids[l_attendeecritchg]), &nt_time) != 0)
		return ecMAPIOOM;
	auto rcpts = tarray_set_init();
	if (rcpts == nullptr)
		return ecMAPIOOM;
	auto row = rcpts->emplace();
	if (row == nullptr)
		return ecMAPIOOM;
	auto txt = rq_prop.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
	if (txt == nullptr) {
		mlog(LV_ERR, "%s: no PR_SENT_REPRESENTING_ADDRTYPE available", __func__);
		return ecInvalidParam;
	} else if (row->set(PR_ADDRTYPE, txt) != 0) {
		return ecMAPIOOM;
	}
	txt = rq_prop.get<const char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (txt == nullptr) {
		mlog(LV_ERR, "%s: no PR_SENT_REPRESENTING_EMAIL_ADDRESS available", __func__);
		return ecInvalidParam;
	} else if (row->set(PR_EMAIL_ADDRESS, txt) != 0) {
		return ecMAPIOOM;
	}
	txt = rq_prop.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (txt == nullptr) {
		mlog(LV_ERR, "%s: no PR_SENT_REPRESENTING_SMTP_ADDRESS available", __func__);
		return ecInvalidParam;
	}
	auto bin = rq_prop.get<const BINARY>(PR_CONVERSATION_INDEX);
	if (bin != nullptr && bin->cb >= 22) {
		auto cvidx = std::make_unique<char[]>(bin->cb + 5);
		memcpy(&cvidx[0], bin->pv, bin->cb);
		/* Well that's just great, Y2057 problem */
		auto oldtime = be64p_to_cpu(&cvidx[1]) & 0xffffffffff000000ULL;
		cpu_to_be32p(&cvidx[bin->cb], cvidx_make_delta(oldtime, nt_time));
		cvidx[bin->cb+4] = gromox::rand();
		BINARY cvbin;
		cvbin.cb = bin->cb + 5;
		cvbin.pc = cvidx.get();
		if (rsp_prop.set(PR_CONVERSATION_INDEX, &cvbin) != 0)
			return ecMAPIOOM;
	}

	MAIL imail;
	rp_storedir = par.cur.dirc();
	if (!oxcmail_export(rsp_ctnt.get(), "-", false, oxcmail_body::plain_and_html,
	    &imail, cu_alloc, cu_get_propids, cu_get_propname)) {
		mlog(LV_ERR, "mr_send_response: oxcmail_export failed for an unspecified reason.\n");
		return ecError;
	}
	auto err = cu_send_mail(imail, rp_smtp_url.c_str(), par.ev_to, {txt});
	rp_alloc_ctx.clear();
	rp_storedir = nullptr;
	return err;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

static ec_error_t mr_do_request(rxparam &par, const PROPID_ARRAY &propids,
    const mr_policy &policy)
{
	/* Reject recurring requests right away if so configured */
	auto &rq_prop = par.ctnt->proplist;
	auto recurring_ptr = rq_prop.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_recurring]));
	auto recurring_flg = recurring_ptr != nullptr && *recurring_ptr != 0;
	if (recurring_flg && policy.decline_recurring) {
		auto err = mr_send_response(par, recurring_flg, propids, respDeclined);
		if (err != ecSuccess)
			return err;
		return mr_mark_done(par);
	}

	/* Lookup conflict state */
	bool res_in_use = false;
	auto start_nt = rq_prop.get<uint64_t>(PR_START_DATE);
	auto end_nt   = rq_prop.get<uint64_t>(PR_END_DATE);
	if (start_nt != nullptr && end_nt != nullptr) {
		std::vector<freebusy_event> fbdata;
		auto start_ts = rop_util_nttime_to_unix(*start_nt);
		auto end_ts   = rop_util_nttime_to_unix(*end_nt);
		/* XXX: May need PR_SENDER rather than Envelope-From */
		if (!get_freebusy(par.ev_from, par.cur.dirc(), start_ts, end_ts, fbdata))
			mlog(LV_ERR, "W-PREC: cannot retrieve freebusy %s", par.cur.dirc());

		for (const freebusy_event &event : fbdata)
			if ((event.start_time >= start_ts && event.start_time <= end_ts) ||
			    (event.end_time   >= start_ts && event.end_time <= end_ts) ||
			    (event.start_time < start_ts  && event.end_time > end_ts))
				if (event.busy_status == olBusy) {
					res_in_use = true;
					break;
				}
	}

	/* Decline double-booking if so configured */
	if (res_in_use && policy.decline_overlap) {
		auto err = mr_send_response(par, recurring_flg, propids, respDeclined);
		if (err != ecSuccess)
			return err;
		return mr_mark_done(par);
	}

	/* Enter meeting into calendar */
	auto tent = policy.accept_appts ? respAccepted : respTentative;
	auto cal_fid = rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR);
	auto err = mr_insert_to_cal(par, propids, cal_fid, tent);
	if (err != ecSuccess)
		return err;
	if (policy.is_resource())
		return mr_mark_done(par);
	if (tent == respAccepted) {
		err = mr_send_response(par, recurring_flg, propids, tent);
		if (err != ecSuccess)
			return err;
		return mr_mark_done(par);
	}
	return ecSuccess;
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
		{MNID_ID, PSETID_Meeting,     PidLidTimeZoneStruct},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionRecur},
		{MNID_ID, PSETID_Meeting,     PidLidIsRecurring},
		{MNID_ID, PSETID_Meeting,     PidLidTimeZone},
		{MNID_ID, PSETID_Appointment, PidLidTimeZoneDescription},
		{MNID_ID, PSETID_Meeting,     PidLidGlobalObjectId},
		{MNID_ID, PSETID_Meeting,     PidLidAttendeeCriticalChange},
		{MNID_ID, PSETID_Meeting,     PidLidIsSilent},
	};
	static_assert(std::size(rq_propname1) == l_is_silent + 1);
	const PROPNAME_ARRAY rq_propname = {std::size(rq_propname1), deconst(rq_propname1)};
	PROPID_ARRAY propids;
	if (!exmdb_client::get_named_propids(par.cur.dir.c_str(), false,
	    &rq_propname, &propids) || propids.size() != rq_propname.size())
		return ecError;

	auto &rq_prop = par.ctnt->proplist;
	auto rq_class = mr_get_class(rq_prop);
	if (class_match_prefix(rq_class, "IPM.Schedule.Meeting.Request") == 0)
		return mr_do_request(par, propids, policy);
	return ecSuccess;
}

rxparam::rxparam(message_node &&x) : cur(std::move(x))
{}

ec_error_t rxparam::run()
{
	bool oof = false;
	auto err = is_oof(&oof);
	if (err != ecSuccess)
		return err;
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

	if (!exmdb_client::read_message(cur.dirc(), nullptr, CP_ACP,
	    cur.mid, &unique_tie(ctnt)))
		return ecError;
	if (ctnt == nullptr)
		return ecNotFound;
	for (auto &&rule : rule_list) {
		err = rule.extended ? opx_process(*this, rule) : op_process(*this, rule);
		if (err != ecSuccess)
			return err;
		if (del)
			break;
	}
	if (del) {
		const EID_ARRAY ids = {1, reinterpret_cast<uint64_t *>(&cur.mid)};
		BOOL partial;
		if (!exmdb_client::delete_messages(cur.dirc(), CP_ACP, nullptr,
		    cur.fid, &ids, true/*hard*/, &partial))
			mlog(LV_DEBUG, "ruleproc: deletion unsuccessful");
		return ecSuccess;
	}

	if (do_autoproc) {
		mr_policy res_policy;
		err = mr_get_policy(ev_to, res_policy);
		if (err != ecSuccess)
			return err;
		err = mr_start(*this, res_policy);
		if (err != ecSuccess)
			return err;
	}

	if (!exmdb_client::notify_new_mail(cur.dirc(), cur.fid, cur.mid))
		mlog(LV_ERR, "ruleproc: newmail notification unsuccessful");
	return ecSuccess;
}

static ec_error_t exmdb_local_rules_execute(const char *dir, const char *ev_from,
    const char *ev_to, eid_t folder_id, eid_t msg_id, unsigned int flags) try
{
	rxparam p({dir, folder_id, msg_id});
	p.ev_from = ev_from;
	p.ev_to   = ev_to;
	p.do_autoproc = flags & DELIVERY_DO_MRAUTOPROC;
	return std::move(p).run();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1121: ENOMEM");
	return ecServerOOM;
}

static constexpr cfg_directive rp_config_defaults[] = {
	{"outgoing_smtp_url", "sendmail://localhost"},
	CFG_TABLE_END,
};

BOOL SVC_ruleproc(enum plugin_op reason, const struct dlfuncs &param)
{
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(param);
	if (!register_service("rules_execute", exmdb_local_rules_execute))
		return false;
	auto cfg = config_file_prg(nullptr, "gromox.cfg", rp_config_defaults);
	auto str = cfg->get_value("outgoing_smtp_url");
	if (str != nullptr) {
		try {
			rp_smtp_url = vmime::utility::url(str);
		} catch (const vmime::exceptions::malformed_url &e) {
			mlog(LV_ERR, "Malformed URL: outgoing_smtp_url=\"%s\": %s",
				str, e.what());
			return EXIT_FAILURE;
		}
	}
	return TRUE;
}
