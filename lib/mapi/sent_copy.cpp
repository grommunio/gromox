// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/sent_copy.hpp>
#include <gromox/util.hpp>

using namespace gromox;

namespace {

/*
 * Properties which name a particular object or its location within the source
 * store. Left in place, they would make the new message claim an identity that
 * belongs to a different mailbox.
 */
constexpr proptag_t strip_location[] = {
	PR_ENTRYID, PidTagMid, PidTagFolderId, PidTagParentFolderId,
	PR_PARENT_ENTRYID, PR_STORE_ENTRYID, PR_STORE_RECORD_KEY,
	PR_OBJECT_TYPE, PR_SOURCE_KEY, PR_PARENT_SOURCE_KEY,
	PR_CHANGE_KEY, PidTagChangeNumber, PR_PREDECESSOR_CHANGE_LIST,
};

/*
 * Properties which exmdb recomputes on write. PR_CONVERSATION_ID in
 * particular is emplaced unconditionally by message_rectify_message, so
 * leaving ours behind yields the same proptag twice in one array.
 */
constexpr proptag_t strip_recomputed[] = {
	PR_MESSAGE_SIZE, PR_MESSAGE_SIZE_EXTENDED, PR_HAS_NAMED_PROPERTIES,
	PR_HASATTACH, PR_DISPLAY_TO, PR_DISPLAY_TO_A, PR_DISPLAY_CC,
	PR_DISPLAY_CC_A, PR_DISPLAY_BCC, PR_DISPLAY_BCC_A,
	PR_INTERNET_ARTICLE_NUMBER, PR_CONVERSATION_ID,
};

/*
 * Submission bookkeeping. Some of these point into the source store, so a
 * resubmit of the copy would act upon the wrong mailbox. The rest is stale the
 * moment the message has been sent.
 */
constexpr proptag_t strip_submit[] = {
	PR_TARGET_ENTRYID, PR_SENTMAIL_ENTRYID, PidTagSentMailSvrEID,
	PR_DELETE_AFTER_SUBMIT, PR_DEFERRED_SEND_TIME,
	PR_DEFERRED_SEND_NUMBER, PR_DEFERRED_SEND_UNITS,
	PR_READ_RECEIPT_ENTRYID, PR_MESSAGE_DELIVERY_TIME,
};

void npid_collect(const TPROPVAL_ARRAY &props, std::set<propid_t> &out)
{
	for (const auto &pv : props)
		if (is_nameprop_id(PROP_ID(pv.proptag)))
			out.emplace(PROP_ID(pv.proptag));
}

void npid_collect(const MESSAGE_CONTENT &ctnt, std::set<propid_t> &out)
{
	npid_collect(ctnt.proplist, out);
	if (ctnt.children.prcpts != nullptr)
		for (const auto &rcpt : *ctnt.children.prcpts)
			npid_collect(rcpt, out);
	if (ctnt.children.pattachments == nullptr)
		return;
	for (const auto &at : *ctnt.children.pattachments) {
		npid_collect(at.proplist, out);
		if (at.pembedded != nullptr)
			npid_collect(*at.pembedded, out);
	}
}

/**
 * Returns the number of property values that had to be dropped because the
 * target store would not name them. One property occurring on the message and
 * on three of its recipients counts as four.
 */
size_t npid_apply(TPROPVAL_ARRAY &props, const std::vector<propid_t> &src,
    const PROPID_ARRAY &dst)
{
	/*
	 * A target store which has reached MAXIMUM_PROPNAME_NUMBER makes
	 * get_named_propids stop creating names and report id 0 for the ones
	 * it did not have, while still succeeding overall. Keeping the source
	 * id in that case would not preserve the property, it would name an
	 * unrelated one in the target store, so such properties have to go.
	 */
	return props.erase_if([&](TAGGED_PROPVAL &pv) {
		auto id = PROP_ID(pv.proptag);
		if (!is_nameprop_id(id))
			return false;
		auto it = std::find(src.begin(), src.end(), id);
		if (it == src.end())
			return false;
		auto newid = dst[it-src.begin()];
		if (newid == 0)
			return true;
		pv.proptag = PROP_TAG(PROP_TYPE(pv.proptag), newid);
		return false;
	});
}

size_t npid_apply(MESSAGE_CONTENT &ctnt, const std::vector<propid_t> &src,
    const PROPID_ARRAY &dst)
{
	auto dropped = npid_apply(ctnt.proplist, src, dst);
	if (ctnt.children.prcpts != nullptr)
		for (auto &rcpt : *ctnt.children.prcpts)
			dropped += npid_apply(rcpt, src, dst);
	if (ctnt.children.pattachments == nullptr)
		return dropped;
	for (auto &at : *ctnt.children.pattachments) {
		dropped += npid_apply(at.proplist, src, dst);
		if (at.pembedded != nullptr)
			dropped += npid_apply(*at.pembedded, src, dst);
	}
	return dropped;
}

/**
 * Named property ids are assigned per store, so the very same id can stand for
 * a different property in @dstdir than it does in @srcdir. Resolve every id
 * used by @ctnt to its name in the source store, look the names up in (or add
 * them to) the target store, and rewrite the proptags accordingly.
 *
 * Nothing is released here on purpose. The arrays handed out by the resolvers
 * come from a per-request pool in some subsystems, where freeing them
 * individually is at best pointless and at worst memory corruption.
 */
ec_error_t npid_remap(const sent_copy_ctx &ctx, MESSAGE_CONTENT &ctnt,
    const char *srcdir, const char *dstdir)
{
	if (ctx.get_named_propnames == nullptr || ctx.get_named_propids == nullptr)
		return ecInvalidParam;
	std::set<propid_t> id_set;
	npid_collect(ctnt, id_set);
	if (id_set.size() == 0)
		return ecSuccess;
	std::vector<propid_t> src_ids(id_set.begin(), id_set.end());
	PROPNAME_ARRAY names{};
	if (!ctx.get_named_propnames(srcdir, src_ids, &names)) {
		mlog(LV_DEBUG, "sent_copy: get_named_propnames(%s) failed", srcdir);
		return ecRpcFailed;
	}
	if (names.size() != src_ids.size()) {
		mlog(LV_ERR, "sent_copy: np(src) count mismatch for %s", srcdir);
		return ecError;
	}
	PROPID_ARRAY dst_ids;
	if (!ctx.get_named_propids(dstdir, TRUE, &names, &dst_ids)) {
		mlog(LV_DEBUG, "sent_copy: get_named_propids(%s) failed", dstdir);
		return ecRpcFailed;
	}
	if (dst_ids.size() != names.size()) {
		mlog(LV_ERR, "sent_copy: np(dst) count mismatch for %s", dstdir);
		return ecError;
	}
	auto dropped = npid_apply(ctnt, src_ids, dst_ids);
	if (dropped > 0)
		mlog(LV_WARN, "sent_copy: %s: %zu named property value%s omitted "
			"from the copy because %s would not name them (its "
			"named property table may be full)", ctx.log_id, dropped,
			dropped == 1 ? " was" : "s were", dstdir);
	return ecSuccess;
}

}

namespace gromox {

/**
 * Produce a copy of a just-submitted message that is fit to be written into
 * another mailbox, e.g. so that a shared mailbox retains a record of what was
 * sent in its name.
 *
 * @ctnt is duplicated rather than modified, because callers generally still
 * need the original to file their own copy. Neither a message id nor a change
 * number is assigned. Leaving PidTagChangeNumber absent makes exmdb allocate
 * one and derive PR_CHANGE_KEY from the *target* store's GUID, which is what
 * we want and saves two RPCs.
 */
ec_error_t sent_copy_prepare(const sent_copy_ctx &ctx,
    const MESSAGE_CONTENT &src, const char *srcdir, const char *dstdir,
    std::unique_ptr<MESSAGE_CONTENT, mc_delete> &out)
{
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> dst(src.dup());
	if (dst == nullptr)
		return ecMAPIOOM;
	/*
	 * Only the top-level proplist, unlike the named property pass below
	 * which has to descend. Every tag in the three lists is a property of
	 * a message as an object in a store. An embedded message is stored
	 * inside its attachment rather than as an addressable message of its
	 * own, so its copies of these carry no meaning to strip.
	 */
	for (auto tag : strip_location)
		dst->proplist.erase(tag);
	for (auto tag : strip_recomputed)
		dst->proplist.erase(tag);
	for (auto tag : strip_submit)
		dst->proplist.erase(tag);
	auto err = npid_remap(ctx, *dst, srcdir, dstdir);
	if (err != ecSuccess)
		return err;

	/*
	 * try_mark_submit ran before the message was read back, so the content
	 * carries MSGFLAG_SUBMITTED. A copy retaining it is rendered as still
	 * being sent, and it is not going to be submitted from here anyway.
	 */
	auto flags = dst->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	uint32_t newflags = (flags != nullptr ? *flags : 0) &
	                    ~(MSGFLAG_SUBMITTED | MSGFLAG_UNSENT |
	                    MSGFLAG_RESEND | MSGFLAG_RN_PENDING |
	                    MSGFLAG_NRN_PENDING);
	newflags |= MSGFLAG_READ | MSGFLAG_FROMME;
	err = dst->proplist.set(PR_MESSAGE_FLAGS, &newflags);
	if (err != ecSuccess)
		return err;
	if (!dst->proplist.has(PR_LAST_MODIFICATION_TIME)) {
		auto now = rop_util_current_nttime();
		err = dst->proplist.set(PR_LAST_MODIFICATION_TIME, &now);
		if (err != ecSuccess)
			return err;
	}
	out = std::move(dst);
	return ecSuccess;
}

}
