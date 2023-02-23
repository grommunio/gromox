// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <set>
#include <utility>
#include <vector>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/propval.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

namespace {
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

struct folder_node {
	std::string dir;
	eid_t fid = 0;
	inline bool operator<(const struct folder_node &o) const { return std::tie(dir, fid) < std::tie(o.dir, o.fid); }
	inline bool operator==(const struct folder_node &o) const { return dir == o.dir && fid == o.fid; }
};

struct message_node : public folder_node {
	eid_t mid = 0;
	void operator<(const struct message_node &) = delete;
	void operator==(const struct message_node &) = delete;
};

/**
 * @cur:	current pointer to message
 */
struct rxparam {
	const char *ev_from = nullptr, *ev_to = nullptr;
	message_node cur;
	std::set<folder_node> loop_check;
	MESSAGE_CONTENT *ctnt = nullptr;
	bool exit = false;
};

}

rule_node::rule_node(rule_node &&o) :
	seq(o.seq), state(o.state), extended(o.extended), rule_id(o.rule_id),
	name(std::move(o.name)), provider(std::move(o.provider)),
	xcond(std::move(o.xcond)), xact(std::move(o.xact)),
	xcnames(std::move(o.xcnames)), xanames(std::move(o.xanames)),
	cond(o.cond), act(o.act)
{
	if (o.cond == &o.xcond)
		cond = &xcond;
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
	xcond = std::move(o.xcond);
	xact = std::move(o.xact);
	xcnames = std::move(o.xcnames);
	xanames = std::move(o.xanames);
	cond = o.cond == &o.xcond ? &xcond : o.cond;
	o.cond = nullptr;
	act = o.act;
	o.act = nullptr;
	return *this;
}

static ec_error_t rx_is_oof(const char *dir, bool *oof)
{
	static constexpr uint32_t tags[] = {PR_OOF_STATE};
	static constexpr PROPTAG_ARRAY pt = {std::size(tags), deconst(tags)};
	TPROPVAL_ARRAY props{};
	if (!exmdb_client::get_store_properties(dir, CP_UTF8, &pt, &props))
		return ecError;
	auto flag = props.get<uint8_t>(PR_OOF_STATE);
	*oof = flag != nullptr ? *flag : 0;
	return ecSuccess;
}

static ec_error_t rx_load_std_rules(const char *dir, eid_t fid, bool oof,
    std::vector<rule_node> &rule_list)
{
	uint32_t table_id = 0, row_count = 0;

	RESTRICTION_BITMASK rst_1 = {BMR_NEZ, PR_RULE_STATE, ST_ENABLED};
	RESTRICTION_BITMASK rst_2 = {BMR_NEZ, PR_RULE_STATE, oof ? ST_ONLY_WHEN_OOF : 0U};
	RESTRICTION rst_3[]       = {{RES_BITMASK, {&rst_1}}, {RES_BITMASK, {&rst_2}}};
	RESTRICTION_AND_OR rst_4  = {std::size(rst_3), {rst_3}};

	RESTRICTION_EXIST rst_5   = {PR_RULE_STATE};
	RESTRICTION rst_6[]       = {{RES_EXIST, {&rst_5}}, {RES_OR, {&rst_4}}};
	RESTRICTION_AND_OR rst_7  = {std::size(rst_6), {rst_6}};
	RESTRICTION rst_8         = {RES_AND, {&rst_7}};

	/* XXX: Where is my sort order parameter */
	if (!exmdb_client::load_rule_table(dir, fid, 0, &rst_8,
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
		rule.act  = row->get<RULE_ACTIONS>(PR_RULE_ACTIONS);
		rule_list.push_back(std::move(rule));
	}
	return ecSuccess;
}

static ec_error_t rx_load_ext_rules(const char *dir, eid_t fid, bool oof,
    std::vector<rule_node> &rule_list)
{
	uint32_t table_id = 0, row_count = 0;

	RESTRICTION_BITMASK rst_1 = {BMR_NEZ, PR_RULE_MSG_STATE, ST_ENABLED};
	RESTRICTION_BITMASK rst_2 = {BMR_NEZ, PR_RULE_MSG_STATE, oof ? ST_ONLY_WHEN_OOF : 0U};
	RESTRICTION rst_3[2]      = {{RES_BITMASK, {&rst_1}}, {RES_BITMASK, {&rst_2}}};
	RESTRICTION_AND_OR rst_4  = {std::size(rst_3), {rst_3}};

	RESTRICTION_EXIST rst_5   = {PR_RULE_MSG_STATE};
	RESTRICTION_EXIST rst_6   = {PR_MESSAGE_CLASS};
	RESTRICTION_CONTENT rst_7 = {FL_FULLSTRING | FL_IGNORECASE, PR_MESSAGE_CLASS, {PR_MESSAGE_CLASS, deconst("IPM.ExtendedRule.Message")}};
	RESTRICTION rst_8[]       = {{RES_EXIST, {&rst_5}}, {RES_OR, {&rst_4}}, {RES_EXIST, {&rst_6}}, {RES_CONTENT, {&rst_7}}};
	RESTRICTION_AND_OR rst_9  = {std::size(rst_8), {rst_8}};
	RESTRICTION rst_10        = {RES_AND, {&rst_9}};

	static constexpr SORT_ORDER sort_spec[] = {{PT_LONG, PROP_ID(PR_RULE_MSG_SEQUENCE), TABLE_SORT_ASCEND}};
	static constexpr SORTORDER_SET sort_order = {std::size(sort_spec), 0, 0, deconst(sort_spec)};
	if (!exmdb_client::load_content_table(dir, CP_ACP, fid, nullptr,
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
	case RES_SUBRESTRICTION:
		return false;
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

static ec_error_t op_process(rxparam &par, const rule_node &rule)
{
	if (par.exit && !(rule.state & ST_ONLY_WHEN_OOF))
		return ecSuccess;
	if (rule.cond != nullptr &&
	    !rx_eval_props(par.ctnt, par.ctnt->proplist, *rule.cond))
		return ecSuccess;
	if (rule.state & ST_EXIT_LEVEL)
		par.exit = true;
	return ecSuccess;
}

static ec_error_t opx_process(rxparam &par, const rule_node &rule)
{
	if (par.exit && !(rule.state & ST_ONLY_WHEN_OOF))
		return ecSuccess;
	if (rule.cond != nullptr &&
	    !rx_eval_props(par.ctnt, par.ctnt->proplist, *rule.cond))
		return ecSuccess;
	if (rule.state & ST_EXIT_LEVEL)
		par.exit = true;
	return ecSuccess;
}

ec_error_t exmdb_local_rules_execute(const char *dir, const char *ev_from,
    const char *ev_to, eid_t folder_id, eid_t msg_id) try
{
	bool oof = false;
	auto err = rx_is_oof(dir, &oof);
	if (err != ecSuccess)
		return err;
	std::vector<rule_node> rule_list;
	err = rx_load_std_rules(dir, folder_id, oof, rule_list);
	if (err != ecSuccess)
		return err;
	err = rx_load_ext_rules(dir, folder_id, oof, rule_list);
	if (err != ecSuccess)
		return err;
	std::sort(rule_list.begin(), rule_list.end());

	rxparam par = {ev_from, ev_to, {dir, folder_id, msg_id}, {{dir, folder_id}}};
	if (!exmdb_client::read_message(par.cur.dir.c_str(), nullptr, CP_ACP,
	    par.cur.mid, &par.ctnt))
		return ecError;
	for (auto &&rule : rule_list) {
		err = rule.extended ? opx_process(par, rule) : op_process(par, rule);
		if (err != ecSuccess)
			return err;
	}
	if (!exmdb_client::notify_new_mail(par.cur.dir.c_str(),
	    par.cur.fid, par.cur.mid))
		mlog(LV_ERR, "ruleproc: newmail notification unsuccessful");
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1121: ENOMEM");
	return ecServerOOM;
}
