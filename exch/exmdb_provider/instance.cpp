// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <fmt/core.h>
#include <libHX/defs.h>
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/endian.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "db_engine.h"

enum {
	PR_BODY_U = CHANGE_PROP_TYPE(PR_BODY, PT_UNSPECIFIED),
	PR_TRANSPORT_MESSAGE_HEADERS_U = CHANGE_PROP_TYPE(PR_TRANSPORT_MESSAGE_HEADERS, PT_UNSPECIFIED),
	PR_HTML_U = CHANGE_PROP_TYPE(PR_HTML, PT_UNSPECIFIED),
	PR_ATTACH_DATA_BIN_U = CHANGE_PROP_TYPE(PR_ATTACH_DATA_BIN, PT_UNSPECIFIED),
};

#define MAX_RECIPIENT_NUMBER							4096
#define MAX_ATTACHMENT_NUMBER							1024

using XUI = unsigned int;
using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

static BOOL instance_read_message(
	const MESSAGE_CONTENT *pmsgctnt1, MESSAGE_CONTENT *pmsgctnt);

static BOOL instance_identify_message(MESSAGE_CONTENT *pmsgctnt);

static constexpr uint32_t dummy_rcpttype = MAPI_TO;
static constexpr char dummy_addrtype[] = "NONE", dummy_string[] = "";

instance_node::instance_node(instance_node &&o) noexcept :
	instance_id(o.instance_id), parent_id(o.parent_id),
	folder_id(o.folder_id), last_id(o.last_id), cpid(o.cpid),
	type(o.type), b_new(o.b_new), change_mask(o.change_mask),
	username(std::move(o.username)), pcontent(o.pcontent)
{
	o.pcontent = nullptr;
}

void instance_node::release()
{
	if (pcontent == nullptr)
		return;
	if (type == instance_type::message)
		message_content_free(static_cast<MESSAGE_CONTENT *>(pcontent));
	else
		attachment_content_free(static_cast<ATTACHMENT_CONTENT *>(pcontent));
	pcontent = nullptr;
}

instance_node &instance_node::operator=(instance_node &&o) noexcept
{
	release();
	instance_id = o.instance_id;
	parent_id = o.parent_id;
	folder_id = o.folder_id;
	last_id = o.last_id;
	cpid = o.cpid;
	type = o.type;
	b_new = o.b_new;
	change_mask = o.change_mask;
	username = std::move(o.username);
	pcontent = o.pcontent;
	o.pcontent = nullptr;
	return *this;
}

static BOOL instance_load_message(sqlite3 *psqlite,
	uint64_t message_id, uint32_t *plast_id,
	MESSAGE_CONTENT **ppmsgctnt)
{
	char sql_string[124];
	
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM"
	          " messages WHERE message_id=%llu", LLU{message_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW) {
		*ppmsgctnt = NULL;
		return TRUE;
	}
	pstmt.finalize();
	std::unique_ptr<message_content, mc_delete> pmsgctnt(message_content_init());
	if (pmsgctnt == nullptr)
		return FALSE;
	std::vector<uint32_t> proptags;
	if (!cu_get_proptags(MAPI_MESSAGE, message_id,
	    psqlite, proptags))
		return FALSE;
	for (uint32_t tag : proptags) {
		switch (tag) {
		case PR_DISPLAY_TO:
		case PR_DISPLAY_TO_A:
		case PR_DISPLAY_CC:
		case PR_DISPLAY_CC_A:
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_BCC_A:
		case PR_SUBJECT:
		case PR_SUBJECT_A:
		case PR_MESSAGE_SIZE:
		case PR_HASATTACH:
			continue;
		case PR_BODY:
		case PR_BODY_A: {
			snprintf(sql_string, sizeof(sql_string),
			         "SELECT proptag, propval FROM message_properties "
			         "WHERE message_id=%llu AND proptag IN (%u,%u)",
			         LLU{message_id}, PR_BODY, PR_BODY_A);
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				return FALSE;
			uint32_t proptag = pstmt.col_uint64(0);
			auto cid = pstmt.col_text(1);
			if (cid == nullptr) {
				mlog(LV_DEBUG, "W-1441: illegal CID reference in msg %llu prop %xh",
					LLU{message_id}, tag);
				break;
			}
			uint32_t wtag = proptag == PR_BODY ? ID_TAG_BODY : ID_TAG_BODY_STRING8;
			if (pmsgctnt->proplist.set(wtag, cid) != 0)
				return FALSE;	
			break;
		}
		case PR_HTML:
		case PR_RTF_COMPRESSED: {
			snprintf(sql_string, sizeof(sql_string),
			         "SELECT propval FROM message_properties "
			         "WHERE message_id=%llu AND proptag=%u",
			         LLU{message_id}, XUI{tag});
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				return FALSE;
			auto cid = pstmt.col_text(0);
			if (cid == nullptr) {
				mlog(LV_DEBUG, "W-1442: illegal CID reference in msg %llu prop %xh",
					LLU{message_id}, tag);
				break;
			}
			tag = tag == PR_HTML ? ID_TAG_HTML : ID_TAG_RTFCOMPRESSED;
			if (pmsgctnt->proplist.set(tag, cid) != 0)
				return FALSE;
			break;
		}
		case PR_TRANSPORT_MESSAGE_HEADERS:
		case PR_TRANSPORT_MESSAGE_HEADERS_A: {
			snprintf(sql_string, std::size(sql_string),
			         "SELECT proptag, propval FROM message_properties "
			         "WHERE message_id=%llu AND proptag IN (%u,%u)",
			         LLU{message_id}, PR_TRANSPORT_MESSAGE_HEADERS,
			         PR_TRANSPORT_MESSAGE_HEADERS_A);
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
				return FALSE;
			uint32_t proptag = pstmt.col_uint64(0);
			auto cid = pstmt.col_text(1);
			if (cid == nullptr) {
				mlog(LV_DEBUG, "W-1444: illegal CID reference in msg %llu prop %xh",
					LLU{message_id}, tag);
				break;
			}
			uint32_t wtag = proptag == PR_TRANSPORT_MESSAGE_HEADERS ?
			                ID_TAG_TRANSPORTMESSAGEHEADERS :
			                ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8;
			if (pmsgctnt->proplist.set(wtag, cid) != 0)
				return FALSE;	
			break;
		}
		default: {
			void *newval = nullptr;
			if (!cu_get_property(MAPI_MESSAGE, message_id, CP_ACP,
			    psqlite, tag, &newval) || newval == nullptr ||
			    pmsgctnt->proplist.set(tag, newval) != 0)
				return FALSE;
			break;
		}
		}
	}
	auto prcpts = tarray_set_init();
	if (prcpts == nullptr)
		return FALSE;
	pmsgctnt->set_rcpts_internal(prcpts);
	snprintf(sql_string, std::size(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	uint32_t row_id = 0;
	while (pstmt.step() == SQLITE_ROW) {
		auto pproplist = prcpts->emplace();
		if (pproplist == nullptr || pproplist->set(PR_ROWID, &row_id) != 0)
			return FALSE;	
		row_id ++;
		uint64_t rcpt_id = pstmt.col_uint64(0);
		std::vector<uint32_t> rcpt_tags;
		if (!cu_get_proptags(MAPI_MAILUSER, rcpt_id, psqlite, rcpt_tags))
			return false;
		for (auto tag : rcpt_tags) {
			void *newval = nullptr;
			if (!cu_get_property(MAPI_MAILUSER, rcpt_id, CP_ACP,
			    psqlite, tag, &newval) || newval == nullptr ||
			    pproplist->set(tag, newval) != 0)
				return FALSE;
		}
	}
	pstmt.finalize();
	auto pattachments = attachment_list_init();
	if (pattachments == nullptr)
		return FALSE;
	pmsgctnt->set_attachments_internal(pattachments);
	snprintf(sql_string, std::size(sql_string), "SELECT attachment_id FROM "
	          "attachments WHERE message_id=%llu", LLU{message_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	auto pstmt1 = gx_sql_prep(psqlite, "SELECT message_id"
	         " FROM messages WHERE parent_attid=?");
	if (pstmt1 == nullptr)
		return FALSE;
	while (pstmt.step() == SQLITE_ROW) {
		auto pattachment = attachment_content_init();
		if (pattachment == nullptr)
			return FALSE;
		if (!pattachments->append_internal(pattachment)) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		if (pattachment->proplist.set(PR_ATTACH_NUM, plast_id) != 0)
			return FALSE;	
		(*plast_id) ++;
		uint64_t attachment_id = pstmt.col_uint64(0);
		if (!cu_get_proptags(MAPI_ATTACH,
		    attachment_id, psqlite, proptags))
			return FALSE;
		for (auto tag : proptags) {
			switch (tag) {
			case PR_ATTACH_DATA_BIN:
			case PR_ATTACH_DATA_OBJ: {
				snprintf(sql_string, sizeof(sql_string),
				         "SELECT propval FROM attachment_properties "
				         "WHERE attachment_id=%llu AND proptag=%u",
				         LLU{attachment_id}, XUI{tag});
				auto pstmt2 = gx_sql_prep(psqlite, sql_string);
				if (pstmt2 == nullptr || pstmt2.step() != SQLITE_ROW)
					return FALSE;
				auto cid = pstmt2.col_text(0);
				tag = tag == PR_ATTACH_DATA_BIN ?
				      ID_TAG_ATTACHDATABINARY : ID_TAG_ATTACHDATAOBJECT;
				if (pattachment->proplist.set(tag, cid) != 0)
					return FALSE;
				break;
			}
			default: {
				void *newval = nullptr;
				if (!cu_get_property(MAPI_ATTACH, attachment_id,
				    CP_ACP, psqlite, tag, &newval) ||
				    newval == nullptr ||
				    pattachment->proplist.set(tag, newval) != 0)
					return FALSE;
				break;
			}
			}
		}
		sqlite3_bind_int64(pstmt1, 1, attachment_id);
		if (pstmt1.step() == SQLITE_ROW) {
			uint64_t message_id1 = pstmt1.col_uint64(0);
			uint32_t last_id = 0;
			message_content *pmsgctnt1 = nullptr;
			if (!instance_load_message(psqlite, message_id1,
			    &last_id, &pmsgctnt1))
				return FALSE;
			pattachment->set_embedded_internal(pmsgctnt1);
		}
		sqlite3_reset(pstmt1);
	}
	*ppmsgctnt = pmsgctnt.release();
	return TRUE;
}

static uint32_t next_instance_id(db_item_ptr &db)
{
	if (db->instance_list.empty())
		return 1;
	auto id = db->instance_list.back().instance_id + 1;
	if (id == UINT32_MAX)
		mlog(LV_ERR, "E-1270: instance IDs exhausted");
	return id;
}

/**
 * @username:   Used for operations on public store readstates
 */
BOOL exmdb_server::load_message_instance(const char *dir, const char *username,
    cpid_t cpid, BOOL b_new, uint64_t folder_id, uint64_t message_id,
    uint32_t *pinstance_id) try
{
	uint64_t mid_val;
	uint32_t tmp_int32;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto instance_id = next_instance_id(pdb);
	if (instance_id == UINT32_MAX)
		return false;

	instance_node inode, *pinstance = &inode;
	inode.instance_id = instance_id;
	pinstance->folder_id = rop_util_get_gc_value(folder_id);
	pinstance->cpid = cpid;
	mid_val = rop_util_get_gc_value(message_id);
	pinstance->type = instance_type::message;
	if (!exmdb_server::is_private())
		pinstance->username = username;
	if (b_new) {
		/* message_id MUST NOT exist in messages table */
		pinstance->b_new = TRUE;
		pinstance->pcontent = message_content_init();
		if (pinstance->pcontent == nullptr)
			return FALSE;
		auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
		if (ict->proplist.set(PidTagMid, &message_id) != 0)
			return FALSE;
		tmp_int32 = 0;
		if (ict->proplist.set(PR_MSG_STATUS, &tmp_int32) != 0)
			return false;
		pdb->instance_list.push_back(std::move(inode));
		*pinstance_id = instance_id;
		return TRUE;
	}
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(username);
	auto cl_0 = make_scope_exit([]() { exmdb_server::set_public_username(nullptr); });
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!common_util_begin_message_optimize(pdb->psqlite, __func__))
		return FALSE;
	auto ret = instance_load_message(pdb->psqlite, mid_val, &pinstance->last_id,
	           reinterpret_cast<MESSAGE_CONTENT **>(&pinstance->pcontent));
	common_util_end_message_optimize();
	if (!ret)
		return FALSE;
	if (sql_transact.commit() != 0)
		return false;
	if (NULL == pinstance->pcontent) {
		*pinstance_id = 0;
		return TRUE;
	}
	pinstance->b_new = FALSE;
	pdb->instance_list.push_back(std::move(inode));
	*pinstance_id = instance_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1299: ENOMEM");
	return false;
}

static INSTANCE_NODE* instance_get_instance(db_item_ptr &pdb, uint32_t instance_id)
{
	for (auto &i : pdb->instance_list)
		if (i.instance_id == instance_id)
			return &i;
	return NULL;
}

static const INSTANCE_NODE *instance_get_instance_c(db_item_ptr &pdb, uint32_t id)
{
	return instance_get_instance(pdb, id);
}

BOOL exmdb_server::load_embedded_instance(const char *dir, BOOL b_new,
    uint32_t attachment_instance_id, uint32_t *pinstance_id) try
{
	uint64_t mid_val;
	uint64_t message_id;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto instance_id = next_instance_id(pdb);
	if (instance_id == UINT32_MAX)
		return false;
	auto pinstance1 = instance_get_instance_c(pdb, attachment_instance_id);
	if (pinstance1 == nullptr || pinstance1->type != instance_type::attachment)
		return FALSE;
	auto pmsgctnt = static_cast<ATTACHMENT_CONTENT *>(pinstance1->pcontent)->pembedded;
	if (NULL == pmsgctnt) {
		if (!b_new) {
			*pinstance_id = 0;
			return TRUE;
		}
		if (!common_util_allocate_eid(pdb->psqlite, &mid_val))
			return FALSE;
		message_id = rop_util_make_eid_ex(1, mid_val);

		instance_node inode, *pinstance = &inode;
		pinstance->instance_id = instance_id;
		pinstance->parent_id = attachment_instance_id;
		pinstance->cpid = pinstance1->cpid;
		inode.username = pinstance1->username;
		pinstance->type = instance_type::message;
		pinstance->b_new = TRUE;
		pinstance->pcontent = message_content_init();
		if (pinstance->pcontent == nullptr)
			return FALSE;
		auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
		if (ict->proplist.set(PidTagMid, &message_id) != 0)
			return FALSE;
		pdb->instance_list.push_back(std::move(inode));
		*pinstance_id = instance_id;
		return TRUE;
	}
	if (b_new) {
		*pinstance_id = 0;
		return TRUE;
	}

	instance_node inode, *pinstance = &inode;
	pinstance->instance_id = instance_id;
	pinstance->parent_id = attachment_instance_id;
	if (NULL != pmsgctnt->children.pattachments &&
		0 != pmsgctnt->children.pattachments->count) {
		pattachment = pmsgctnt->children.pattachments->pplist[
					pmsgctnt->children.pattachments->count - 1];
		auto pattach_id = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
		if (NULL != pattach_id) {
			pinstance->last_id = *pattach_id;
			pinstance->last_id ++;
		}
	}
	pinstance->cpid = pinstance1->cpid;
	inode.username = pinstance1->username;
	pinstance->type = instance_type::message;
	pinstance->b_new = FALSE;
	pinstance->pcontent = pmsgctnt->dup();
	if (pinstance->pcontent == nullptr)
		return FALSE;
	pdb->instance_list.push_back(std::move(inode));
	*pinstance_id = instance_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1269: ENOMEM");
	return false;
}

/* get PidTagChangeNumber from embedded message */
BOOL exmdb_server::get_embedded_cn(const char *dir, uint32_t instance_id,
    uint64_t **ppcn)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	*ppcn = pinstance->parent_id == 0 ? nullptr :
	        ict->proplist.get<uint64_t>(PidTagChangeNumber);
	return TRUE;
}

/* if instance does not exist, do not reload the instance */
BOOL exmdb_server::reload_message_instance(const char *dir,
    uint32_t instance_id, BOOL *pb_result)
{
	uint32_t last_id;
	MESSAGE_CONTENT *pmsgctnt;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	if (pinstance->b_new) {
		*pb_result = FALSE;
		return TRUE;
	}
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (0 == pinstance->parent_id) {
		auto lnum = ict->proplist.get<const eid_t>(PidTagMid);
		if (lnum == nullptr)
			return FALSE;
		last_id = 0;
		if (!instance_load_message(pdb->psqlite, *lnum, &last_id, &pmsgctnt))
			return FALSE;	
		if (NULL == pmsgctnt) {
			*pb_result = FALSE;
			return TRUE;
		}
		if (pinstance->last_id < last_id)
			pinstance->last_id = last_id;
	} else {
		auto pinstance1 = instance_get_instance_c(pdb, pinstance->parent_id);
		if (pinstance1 == nullptr || pinstance1->type != instance_type::attachment)
			return FALSE;
		auto atx = static_cast<ATTACHMENT_CONTENT *>(pinstance1->pcontent);
		if (atx->pembedded == nullptr) {
			*pb_result = FALSE;
			return TRUE;	
		}
		pmsgctnt = atx->pembedded->dup();
		if (pmsgctnt == nullptr)
			return FALSE;
		if (NULL != pmsgctnt->children.pattachments &&
			0 != pmsgctnt->children.pattachments->count) {
			pattachment = pmsgctnt->children.pattachments->pplist[
						pmsgctnt->children.pattachments->count - 1];
			auto pattach_id = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
			if (NULL != pattach_id && pinstance->last_id <= *pattach_id) {
				pinstance->last_id = *pattach_id;
				pinstance->last_id ++;
			}
		}
	}
	message_content_free(ict);
	pinstance->pcontent = pmsgctnt;
	*pb_result = TRUE;
	return TRUE;
}

BOOL exmdb_server::clear_message_instance(const char *dir, uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	auto lnum = ict->proplist.get<const eid_t>(PidTagMid);
	if (lnum == nullptr)
		return FALSE;
	auto pmsgctnt = message_content_init();
	if (pmsgctnt == nullptr)
		return FALSE;
	if (pmsgctnt->proplist.set(PidTagMid, lnum) != 0) {
		message_content_free(pmsgctnt);
		return FALSE;
	}
	message_content_free(ict);
	pinstance->pcontent = pmsgctnt;
	return TRUE;
}

static void *fake_read_cid(unsigned int mode, uint32_t tag, const char *cid,
    uint32_t *outlen) try
{
	std::string buf;
	if (tag == ID_TAG_HTML)
		buf = "<html><body><p><tt>";
	else if (tag == ID_TAG_RTFCOMPRESSED)
		buf = "\x7b\\rtf1\\ansi{\\fonttbl\\f0\\fswiss Helvetica;}\\f0\\pard\n";
	else if (tag == ID_TAG_BODY)
		buf.resize(4);
	if (tag != 0)
		buf += fmt::format("[CID={} Tag={:x}] {}", cid, tag,
		       mode <= 1 ? "Property/Attachment absent" : "Filler text for debugging");
	if (tag == ID_TAG_HTML) {
		buf += "</tt></p></body></html>";
	} else if (tag == ID_TAG_RTFCOMPRESSED) {
		buf += "\\par\n\x7d";
		auto bin = rtfcp_compress(buf.c_str(), buf.size());
		if (bin == nullptr)
			return nullptr;
		auto out = bin->pb;
		if (outlen != nullptr)
			*outlen = bin->cb;
		free(bin);
		return out;
	}
	auto out = cu_alloc<char>(buf.size() + 1);
	if (out == nullptr)
		return nullptr;
	memcpy(out, buf.c_str(), buf.size() + 1);
	if (outlen != nullptr) {
		*outlen = buf.size();
		if (tag == ID_TAG_BODY)
			cpu_to_le32p(out, *outlen - 4);
	}
	return out;
} catch (const std::bad_alloc &) {
	return nullptr;
}

/**
 * Returns a buffer with the raw file content (including UTF-8 length marker,
 * if any), plus a trailing NUL.
 */
void *instance_read_cid_content(const char *cid, uint32_t *plen, uint32_t tag) try
{
	struct stat node_stat;

	if (g_dbg_synth_content == 2)
		return fake_read_cid(g_dbg_synth_content, tag, cid, plen);

	BINARY dxbin;
	if (strchr(cid, '/') != nullptr) {
		/* v3 */
		errno = gx_decompress_file(cu_cid_path(nullptr, cid, 0).c_str(), dxbin,
			common_util_alloc, [](void *, size_t z) { return common_util_alloc(z); });
		if (errno == ENOENT && g_dbg_synth_content)
			return fake_read_cid(g_dbg_synth_content, tag, cid, plen);
		if (errno != 0)
			return nullptr;
		if (plen != nullptr)
			*plen = dxbin.cb;
		return dxbin.pv;
	}

	errno = gx_decompress_file(cu_cid_path(nullptr, cid, 2).c_str(), dxbin,
	        common_util_alloc, [](void *, size_t z) { return common_util_alloc(z); });
	if (errno == 0) {
		if (plen != nullptr)
			*plen = dxbin.cb;
		return dxbin.pv;
	} else if (errno != ENOENT) {
		return nullptr;
	}
	errno = gx_decompress_file(cu_cid_path(nullptr, cid, 1).c_str(), dxbin,
	        common_util_alloc, [](void *, size_t z) { return common_util_alloc(z); });
	if (errno == 0) {
		if (plen != nullptr)
			*plen = dxbin.cb;
		return dxbin.pv;
	} else if (errno != ENOENT) {
		return nullptr;
	}

	auto path = cu_cid_path(nullptr, cid, 0);
	if (path.empty())
		return nullptr;
	wrapfd fd = open(path.c_str(), O_RDONLY);
	if (fd.get() < 0) {
		if (g_dbg_synth_content)
			return fake_read_cid(g_dbg_synth_content, tag, cid, plen);
		mlog(LV_ERR, "E-1587: %s: %s", path.c_str(), strerror(errno));
		return nullptr;
	}
	if (fstat(fd.get(), &node_stat) != 0)
		return NULL;
	if (!S_ISREG(node_stat.st_mode)) {
		errno = ENOENT;
		return nullptr;
	}
#if defined(HAVE_POSIX_FADVISE)
	if (posix_fadvise(fd.get(), 0, node_stat.st_size, POSIX_FADV_SEQUENTIAL) != 0)
		/* ignore */;
#endif
	auto pbuff = cu_alloc<char>(node_stat.st_size + 1);
	if (pbuff == nullptr)
		return nullptr;
	if (tag == ID_TAG_BODY || tag == ID_TAG_BODY_STRING8) {
		/* Skip over old UTF8LEN_MARKER */
		if (lseek(fd.get(), 4, SEEK_CUR) != 4)
			return nullptr;
		node_stat.st_size -= 4;
	}
	if (read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size)
		return NULL;
	pbuff[node_stat.st_size] = '\0';
	if (plen != nullptr)
		*plen = node_stat.st_size;
	return pbuff;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1588: ENOMEM");
	return nullptr;
}

static BOOL instance_read_attachment(const ATTACHMENT_CONTENT *src,
    ATTACHMENT_CONTENT *dst)
{
	if (src->proplist.count > 1) {
		dst->proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(src->proplist.count);
		if (dst->proplist.ppropval == nullptr)
			return FALSE;
	} else {
		dst->proplist.count = 0;
		dst->proplist.ppropval = nullptr;
		return TRUE;
	}
	dst->proplist.count = 0;
	for (unsigned int i = 0; i < src->proplist.count; ++i) {
		auto tag = src->proplist.ppropval[i].proptag;
		switch (tag) {
		case ID_TAG_ATTACHDATABINARY:
		case ID_TAG_ATTACHDATAOBJECT: {
			auto pbin = cu_alloc<BINARY>();
			if (pbin == nullptr)
				return FALSE;
			auto cidstr = static_cast<const char *>(src->proplist.ppropval[i].pvalue);
			pbin->pv = instance_read_cid_content(cidstr, &pbin->cb, 0);
			if (pbin->pv == nullptr)
				return FALSE;
			dst->proplist.emplace_back(tag == ID_TAG_ATTACHDATABINARY ?
				PR_ATTACH_DATA_BIN : PR_ATTACH_DATA_OBJ, pbin);
			break;
		}
		default:
			dst->proplist.ppropval[dst->proplist.count++] =
				src->proplist.ppropval[i];
			break;
		}
	}
	if (src->pembedded == nullptr) {
		dst->pembedded = nullptr;
		return TRUE;
	}
	dst->pembedded = cu_alloc<MESSAGE_CONTENT>();
	if (dst->pembedded == nullptr)
		return FALSE;
	return instance_read_message(src->pembedded, dst->pembedded);
}

static BOOL instance_read_message(const MESSAGE_CONTENT *src,
    MESSAGE_CONTENT *dst)
{
	void *pbuff;
	uint32_t length;
	const char *psubject_prefix;
	TPROPVAL_ARRAY *pproplist1;
	ATTACHMENT_CONTENT *pattachment1;
	
	dst->proplist.count = src->proplist.count;
	if (src->proplist.count != 0) {
		dst->proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(src->proplist.count + 1);
		if (dst->proplist.ppropval == nullptr)
			return FALSE;
	} else {
		dst->proplist.ppropval = NULL;
	}
	for (size_t i = 0; i < src->proplist.count; ++i) {
		auto tag = src->proplist.ppropval[i].proptag;
		switch (tag) {
		case ID_TAG_BODY: {
			auto cidstr = static_cast<const char *>(src->proplist.ppropval[i].pvalue);
			pbuff = instance_read_cid_content(cidstr, nullptr, ID_TAG_BODY);
			if (pbuff == nullptr)
				return FALSE;
			dst->proplist.ppropval[i].proptag = PR_BODY;
			dst->proplist.ppropval[i].pvalue = static_cast<char *>(pbuff);
			break;
		}
		case ID_TAG_BODY_STRING8: {
			auto cidstr = static_cast<const char *>(src->proplist.ppropval[i].pvalue);
			pbuff = instance_read_cid_content(cidstr, nullptr, 0);
			if (pbuff == nullptr)
				return FALSE;
			dst->proplist.ppropval[i].proptag = PR_BODY_A;
			dst->proplist.ppropval[i].pvalue = pbuff;
			break;
		}
		case ID_TAG_HTML:
		case ID_TAG_RTFCOMPRESSED: {
			auto cidstr = static_cast<const char *>(src->proplist.ppropval[i].pvalue);
			pbuff = instance_read_cid_content(cidstr, &length, tag);
			if (pbuff == nullptr)
				return FALSE;
			dst->proplist.ppropval[i].proptag = tag == ID_TAG_HTML ? PR_HTML : PR_RTF_COMPRESSED;
			auto pbin = cu_alloc<BINARY>();
			if (pbin == nullptr)
				return FALSE;
			pbin->cb = length;
			pbin->pv = pbuff;
			dst->proplist.ppropval[i].pvalue = pbin;
			break;
		}
		case ID_TAG_TRANSPORTMESSAGEHEADERS: {
			auto cidstr = static_cast<const char *>(src->proplist.ppropval[i].pvalue);
			pbuff = instance_read_cid_content(cidstr, nullptr, ID_TAG_BODY);
			if (pbuff == nullptr)
				return FALSE;
			dst->proplist.ppropval[i].proptag = PR_TRANSPORT_MESSAGE_HEADERS;
			dst->proplist.ppropval[i].pvalue = static_cast<char *>(pbuff);
			break;
		}
		case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8: {
			auto cidstr = static_cast<const char *>(src->proplist.ppropval[i].pvalue);
			pbuff = instance_read_cid_content(cidstr, nullptr, 0);
			if (pbuff == nullptr)
				return FALSE;
			dst->proplist.ppropval[i].proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
			dst->proplist.ppropval[i].pvalue = pbuff;
			break;
		}
		default:
			dst->proplist.ppropval[i] = src->proplist.ppropval[i];
			break;
		}
	}
	size_t i = src->proplist.count;
	auto wtf = reinterpret_cast<const TPROPVAL_ARRAY *>(src);
	auto pnormalized_subject = wtf->get<char>(PR_NORMALIZED_SUBJECT);
	if (NULL == pnormalized_subject) {
		pnormalized_subject = wtf->get<char>(PR_NORMALIZED_SUBJECT_A);
		if (NULL != pnormalized_subject) {
			psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX_A);
			if (psubject_prefix == nullptr)
				psubject_prefix = "";
			length = strlen(pnormalized_subject)
					+ strlen(psubject_prefix) + 1;
			dst->proplist.ppropval[i].proptag = PR_SUBJECT_A;
			dst->proplist.ppropval[i].pvalue =
						common_util_alloc(length);
			if (dst->proplist.ppropval[i].pvalue == nullptr)
				return FALSE;
			sprintf(static_cast<char *>(dst->proplist.ppropval[i].pvalue),
				"%s%s", psubject_prefix, pnormalized_subject);
			++dst->proplist.count;
		} else {
			psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX);
			if (NULL == psubject_prefix) {
				psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX_A);
				if (NULL != psubject_prefix) {
					dst->proplist.ppropval[i].proptag = PR_SUBJECT_A;
					dst->proplist.ppropval[i].pvalue =
						deconst(psubject_prefix);
					++dst->proplist.count;
				}
			} else {
				dst->proplist.ppropval[i].proptag = PR_SUBJECT;
				dst->proplist.ppropval[i].pvalue =
					deconst(psubject_prefix);
				++dst->proplist.count;
			}
		}
	} else {
		psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX);
		if (psubject_prefix == nullptr)
			psubject_prefix = "";
		length = strlen(pnormalized_subject)
					+ strlen(psubject_prefix) + 1;
		dst->proplist.ppropval[i].proptag = PR_SUBJECT;
		dst->proplist.ppropval[i].pvalue =
					common_util_alloc(length);
		if (dst->proplist.ppropval[i].pvalue == nullptr)
			return FALSE;
		sprintf(static_cast<char *>(dst->proplist.ppropval[i].pvalue),
			"%s%s", psubject_prefix, pnormalized_subject);
		++dst->proplist.count;
	}
	if (src->children.prcpts == nullptr) {
		dst->children.prcpts = nullptr;
	} else {
		dst->children.prcpts = cu_alloc<TARRAY_SET>();
		if (dst->children.prcpts == nullptr)
			return FALSE;
		dst->children.prcpts->count =
			src->children.prcpts->count;
		if (src->children.prcpts->count != 0) {
			dst->children.prcpts->pparray = cu_alloc<TPROPVAL_ARRAY *>(src->children.prcpts->count);
			if (dst->children.prcpts->pparray == nullptr)
				return FALSE;
		} else {
			dst->children.prcpts->pparray = nullptr;
		}
		for (i = 0; i < src->children.prcpts->count; ++i) {
			auto pproplist = cu_alloc<TPROPVAL_ARRAY>();
			if (pproplist == nullptr)
				return FALSE;
			dst->children.prcpts->pparray[i] = pproplist;
			pproplist1 = src->children.prcpts->pparray[i];
			if (pproplist1->count > 1) {
				pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(pproplist1->count);
				if (pproplist->ppropval == nullptr)
					return FALSE;
			} else {
				pproplist->count = 0;
				pproplist->ppropval = NULL;
				continue;
			}
			pproplist->count = 0;
			for (size_t j = 0; j < pproplist1->count; ++j)
				pproplist->ppropval[pproplist->count++] = pproplist1->ppropval[j];
		}
	}
	if (src->children.pattachments == nullptr) {
		dst->children.pattachments = nullptr;
		return TRUE;
	}
	dst->children.pattachments = cu_alloc<ATTACHMENT_LIST>();
	if (dst->children.pattachments == nullptr)
		return FALSE;
	dst->children.pattachments->count =
		src->children.pattachments->count;
	if (src->children.pattachments->count != 0) {
		dst->children.pattachments->pplist = cu_alloc<ATTACHMENT_CONTENT *>(src->children.pattachments->count);
		if (dst->children.pattachments->pplist == nullptr)
			return FALSE;
	} else {
		dst->children.pattachments->pplist = nullptr;
	}
	for (i = 0; i < src->children.pattachments->count; i++) {
		auto pattachment = cu_alloc<ATTACHMENT_CONTENT>();
		if (pattachment == nullptr)
			return FALSE;
		memset(pattachment, 0 ,sizeof(ATTACHMENT_CONTENT));
		dst->children.pattachments->pplist[i] = pattachment;
		pattachment1 = src->children.pattachments->pplist[i];
		if (!instance_read_attachment(pattachment1, pattachment))
			return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server::read_message_instance(const char *dir,
	uint32_t instance_id, MESSAGE_CONTENT *pmsgctnt)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	memset(pmsgctnt, 0, sizeof(MESSAGE_CONTENT));
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	return instance_read_message(static_cast<MESSAGE_CONTENT *>(pinstance->pcontent), pmsgctnt);
}

static BOOL instance_identify_rcpts(TARRAY_SET *prcpts)
{
	for (uint32_t i = 0; i < prcpts->count; ++i)
		if (prcpts->pparray[i]->set(PR_ROWID, &i) != 0)
			return FALSE;
	return TRUE;
}

static BOOL instance_identify_attachments(ATTACHMENT_LIST *pattachments)
{
	uint32_t i;
	
	for (i=0; i<pattachments->count; i++) {
		if (pattachments->pplist[i]->proplist.set(PR_ATTACH_NUM, &i) != 0)
			return FALSE;	
		if (pattachments->pplist[i]->pembedded != nullptr &&
		    !instance_identify_message(pattachments->pplist[i]->pembedded))
			return FALSE;	
	}
	return TRUE;
}

static BOOL instance_identify_message(MESSAGE_CONTENT *pmsgctnt)
{
	if (pmsgctnt->children.prcpts != nullptr &&
	    !instance_identify_rcpts(pmsgctnt->children.prcpts))
		return FALSE;
	if (pmsgctnt->children.pattachments != nullptr &&
	    !instance_identify_attachments(pmsgctnt->children.pattachments))
		return FALSE;
	return TRUE;
}

/* pproptags is for returning successful proptags */
BOOL exmdb_server::write_message_instance(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt,
	BOOL b_force, PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems)
{
	int i;
	uint32_t proptag;
	TARRAY_SET *prcpts;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pmsgctnt->proplist.count + 2);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<uint32_t>(pmsgctnt->proplist.count + 2);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	auto pproplist = &ict->proplist;
	for (i=0; i<pmsgctnt->proplist.count; i++) {
		proptag = pmsgctnt->proplist.ppropval[i].proptag;
		switch (proptag) {
		case PR_ASSOCIATED:
			if (pinstance->b_new)
				break;
		case PidTagMid:
		case PR_ENTRYID:
		case PidTagFolderId:
		case PR_CODE_PAGE_ID:
		case PidTagParentFolderId:
		case PR_INSTANCE_SVREID:
		case PR_HAS_NAMED_PROPERTIES:
		case PR_MESSAGE_SIZE:
		case PR_HASATTACH:
		case PR_DISPLAY_TO:
		case PR_DISPLAY_CC:
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_TO_A:
		case PR_DISPLAY_CC_A:
		case PR_DISPLAY_BCC_A:
			pproblems->emplace_back(i, proptag, ecAccessDenied);
			continue;
		default:
			break;
		}
		if (!b_force) {
			switch (proptag) {
			case PR_BODY:
			case PR_BODY_A:	
				if (pproplist->has(ID_TAG_BODY) ||
				    pproplist->has(ID_TAG_BODY_STRING8))
					continue;	
				break;
			case PR_HTML:
				if (pproplist->has(ID_TAG_HTML))
					continue;	
				break;
			case PR_RTF_COMPRESSED:
				if (pproplist->has(ID_TAG_RTFCOMPRESSED))
					continue;	
				break;
			}
			if (PROP_TYPE(proptag) == PT_STRING8) {
				if (pproplist->has(CHANGE_PROP_TYPE(proptag, PT_UNICODE)))
					continue;
			} else if (PROP_TYPE(proptag) == PT_UNICODE) {
				if (pproplist->has(CHANGE_PROP_TYPE(proptag, PT_STRING8)))
					continue;
			}
			if (pproplist->has(proptag))
				continue;
		}
		switch (proptag) {
		case PR_BODY:
		case PR_BODY_A:	
			pproplist->erase(ID_TAG_BODY);
			pproplist->erase(ID_TAG_BODY_STRING8);
			pinstance->change_mask |= CHANGE_MASK_BODY;
			break;
		case PR_HTML:
			pproplist->erase(ID_TAG_HTML);
			pproplist->erase(PR_BODY_HTML);
			pproplist->erase(PR_BODY_HTML_A);
			pinstance->change_mask |= CHANGE_MASK_HTML;
			break;
		case PR_RTF_COMPRESSED:
			pproplist->erase(ID_TAG_RTFCOMPRESSED);
			break;
		}
		if (pproplist->set(pmsgctnt->proplist.ppropval[i]) != 0)
			return FALSE;
		switch (proptag) {
		case PR_CHANGE_KEY:
		case PidTagChangeNumber:
		case PR_PREDECESSOR_CHANGE_LIST:
			continue;
		}
		pproptags->emplace_back(proptag);
	}
	if (pmsgctnt->children.prcpts != nullptr &&
	    (b_force || ict->children.prcpts == nullptr)) {
		prcpts = pmsgctnt->children.prcpts->dup();
		if (prcpts == nullptr)
			return FALSE;
		if (!instance_identify_rcpts(prcpts)) {
			tarray_set_free(prcpts);
			return FALSE;
		}
		ict->set_rcpts_internal(prcpts);
		pproptags->emplace_back(PR_MESSAGE_RECIPIENTS);
	}
	if (pmsgctnt->children.pattachments != nullptr &&
	    (b_force || ict->children.pattachments == nullptr)) {
		auto pattachments = pmsgctnt->children.pattachments->dup();
		if (pattachments == nullptr)
			return FALSE;
		if (!instance_identify_attachments(pattachments)) {
			attachment_list_free(pattachments);
			return FALSE;
		}
		ict->set_attachments_internal(pattachments);
		pproptags->emplace_back(PR_MESSAGE_ATTACHMENTS);
	}
	return TRUE;
}

BOOL exmdb_server::load_attachment_instance(const char *dir,
    uint32_t message_instance_id, uint32_t attachment_num,
    uint32_t *pinstance_id) try
{
	int i;
	ATTACHMENT_CONTENT *pattachment = nullptr;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto instance_id = next_instance_id(pdb);
	if (instance_id == UINT32_MAX)
		return false;
	auto pinstance1 = instance_get_instance_c(pdb, message_instance_id);
	if (pinstance1 == nullptr || pinstance1->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent);
	if (NULL == pmsgctnt->children.pattachments) {
		*pinstance_id = 0;
		return TRUE;
	}
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		pattachment = pmsgctnt->children.pattachments->pplist[i];
		auto pvalue = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
		if (pvalue == nullptr)
			return FALSE;
		if (*pvalue == attachment_num)
			break;
	}
	if (i >= pmsgctnt->children.pattachments->count) {
		*pinstance_id = 0;
		return TRUE;
	}

	instance_node inode, *pinstance = &inode;
	pinstance->instance_id = instance_id;
	pinstance->parent_id = message_instance_id;
	pinstance->cpid = pinstance1->cpid;
	inode.username = pinstance1->username;
	pinstance->type = instance_type::attachment;
	pinstance->b_new = FALSE;
	pinstance->pcontent = pattachment->dup();
	if (pinstance->pcontent == nullptr)
		return FALSE;
	pdb->instance_list.push_back(std::move(inode));
	*pinstance_id = instance_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1268: ENOMEM");
	return false;
}

BOOL exmdb_server::create_attachment_instance(const char *dir,
    uint32_t message_instance_id, uint32_t *pinstance_id,
    uint32_t *pattachment_num) try
{
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto instance_id = next_instance_id(pdb);
	if (instance_id == UINT32_MAX)
		return false;
	auto pinstance1 = instance_get_instance(pdb, message_instance_id);
	if (pinstance1 == nullptr || pinstance1->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent);
	if (NULL != pmsgctnt->children.pattachments &&
		pmsgctnt->children.pattachments->count >=
		MAX_ATTACHMENT_NUMBER) {
		*pinstance_id = 0;
		*pattachment_num = ATTACHMENT_NUM_INVALID;
		return TRUE;	
	}

	instance_node inode, *pinstance = &inode;
	pinstance->instance_id = instance_id;
	pinstance->parent_id = message_instance_id;
	pinstance->cpid = pinstance1->cpid;
	inode.username = pinstance1->username;
	pinstance->type = instance_type::attachment;
	pinstance->b_new = TRUE;
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return FALSE;
	*pattachment_num = pinstance1->last_id++;
	if (pattachment->proplist.set(PR_ATTACH_NUM, pattachment_num) != 0) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	pinstance->pcontent = pattachment;
	pdb->instance_list.push_back(std::move(inode));
	*pinstance_id = instance_id;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1267: ENOMEM");
	return false;
}

BOOL exmdb_server::read_attachment_instance(const char *dir,
	uint32_t instance_id, ATTACHMENT_CONTENT *pattctnt)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	memset(pattctnt, 0, sizeof(ATTACHMENT_CONTENT));
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::attachment)
		return FALSE;
	return instance_read_attachment(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent), pattctnt);
}

BOOL exmdb_server::write_attachment_instance(const char *dir,
	uint32_t instance_id, const ATTACHMENT_CONTENT *pattctnt,
	BOOL b_force, PROBLEM_ARRAY *pproblems)
{
	int i;
	uint32_t proptag;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::attachment)
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pattctnt->proplist.count + 1);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	auto pproplist = &static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent)->proplist;
	for (i=0; i<pattctnt->proplist.count; i++) {
		proptag = pattctnt->proplist.ppropval[i].proptag;
		switch (proptag) {
		case PR_RECORD_KEY:
			pproblems->emplace_back(i, proptag, ecAccessDenied);
			continue;
		}
		if (!b_force) {
			switch (proptag) {
			case PR_ATTACH_DATA_BIN:
				if (pproplist->has(ID_TAG_ATTACHDATABINARY))
					continue;	
				break;
			case PR_ATTACH_DATA_OBJ:
				if (pproplist->has(ID_TAG_ATTACHDATAOBJECT))
					continue;	
				break;
			}
			if (PROP_TYPE(proptag) == PT_STRING8) {
				if (pproplist->has(CHANGE_PROP_TYPE(proptag, PT_UNICODE)))
					continue;
			} else if (PROP_TYPE(proptag) == PT_UNICODE) {
				if (pproplist->has(CHANGE_PROP_TYPE(proptag, PT_STRING8)))
					continue;
			}
			if (pproplist->has(proptag))
				continue;
		}
		switch (proptag) {
		case PR_ATTACH_DATA_BIN:
			pproplist->erase(ID_TAG_ATTACHDATABINARY);
			break;
		case PR_ATTACH_DATA_OBJ:
			pproplist->erase(ID_TAG_ATTACHDATAOBJECT);
			break;
		}
		if (pproplist->set(pattctnt->proplist.ppropval[i]) != 0)
			return FALSE;
	}
	if (pattctnt->pembedded != nullptr &&
	    (!b_force || static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent)->pembedded == nullptr)) {
		auto pmsgctnt = pattctnt->pembedded->dup();
		if (pmsgctnt == nullptr)
			return FALSE;
		if (!instance_identify_message(pmsgctnt)) {
			message_content_free(pmsgctnt);
			return FALSE;
		}
		static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent)->set_embedded_internal(pmsgctnt);
	}
	return TRUE;
}

BOOL exmdb_server::delete_message_instance_attachment(const char *dir,
    uint32_t message_instance_id, uint32_t attachment_num)
{
	int i;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, message_instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (pmsgctnt->children.pattachments == nullptr)
		return TRUE;
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		auto pattachment = pmsgctnt->children.pattachments->pplist[i];
		auto pvalue = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
		if (pvalue == nullptr)
			return FALSE;
		if (*pvalue == attachment_num)
			break;
	}
	if (i >= pmsgctnt->children.pattachments->count)
		return TRUE;
	pmsgctnt->children.pattachments->remove(i);
	if (0 == pmsgctnt->children.pattachments->count) {
		attachment_list_free(pmsgctnt->children.pattachments);
		pmsgctnt->children.pattachments = NULL;
	}
	return TRUE;
}

/* account must be available when it is a normal message instance */ 
BOOL exmdb_server::flush_instance(const char *dir, uint32_t instance_id,
    const char *account, ec_error_t *pe_result)
{
	int i;
	uint64_t folder_id;
	char tmp_buff[1024];
	char address_type[16];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (pinstance == nullptr)
		return FALSE;
	if (pinstance->type == instance_type::attachment) {
		auto pinstance1 = instance_get_instance_c(pdb, pinstance->parent_id);
		if (pinstance1 == nullptr || pinstance1->type != instance_type::message)
			return FALSE;
		auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent);
		auto pattachment = static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent)->dup();
		if (pattachment == nullptr)
			return FALSE;
		if (pinstance->b_new) {
			if (NULL == pmsgctnt->children.pattachments) {
				pmsgctnt->children.pattachments = attachment_list_init();
				if (NULL == pmsgctnt->children.pattachments) {
					attachment_content_free(pattachment);
					return FALSE;
				}
			}
			if (!pmsgctnt->children.pattachments->append_internal(pattachment)) {
				attachment_content_free(pattachment);
				return FALSE;
			}
			pinstance->b_new = FALSE;
		} else {
			if (NULL == pmsgctnt->children.pattachments) {
				pmsgctnt->children.pattachments = attachment_list_init();
				if (NULL == pmsgctnt->children.pattachments) {
					attachment_content_free(pattachment);
					return FALSE;
				}
			}
			auto pvalue = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
			if (NULL == pvalue) {
				attachment_content_free(pattachment);
				return FALSE;
			}
			auto attachment_num = *pvalue;
			for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
				pvalue = pmsgctnt->children.pattachments->pplist[i]->proplist.get<uint32_t>(PR_ATTACH_NUM);
				if (NULL == pvalue) {
					attachment_content_free(pattachment);
					return FALSE;
				}
				if (*pvalue == attachment_num)
					break;
			}
			if (i < pmsgctnt->children.pattachments->count) {
				attachment_content_free(
					pmsgctnt->children.pattachments->pplist[i]);
				pmsgctnt->children.pattachments->pplist[i] = pattachment;
			} else if (!pmsgctnt->children.pattachments->append_internal(pattachment)) {
				attachment_content_free(pattachment);
				return FALSE;
			}
		}
		*pe_result = ecSuccess;
		return TRUE;
	}
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if ((pinstance->change_mask & CHANGE_MASK_HTML) &&
	    !(pinstance->change_mask & CHANGE_MASK_BODY)) {
		auto pbin  = ict->proplist.get<BINARY>(PR_HTML);
		auto pcpid = ict->proplist.get<uint32_t>(PR_INTERNET_CPID);
		if (NULL != pbin && NULL != pcpid) {
			std::string plainbuf;
			auto ret = html_to_plain(pbin->pc, pbin->cb, plainbuf);
			if (ret < 0)
				return false;
			void *pvalue;
			if (ret == CP_UTF8 || *pcpid == CP_UTF8) {
				pvalue = plainbuf.data();
			} else {
				pvalue = common_util_convert_copy(TRUE,
				         static_cast<cpid_t>(*pcpid),
				         plainbuf.c_str());
				if (pvalue == nullptr)
					return false;
			}
			if (ict->proplist.set(PR_BODY_W, pvalue) != 0)
				return false;
		}
	}
	pinstance->change_mask = 0;
	if (0 != pinstance->parent_id) {
		auto pinstance1 = instance_get_instance_c(pdb, pinstance->parent_id);
		if (pinstance1 == nullptr || pinstance1->type != instance_type::attachment)
			return FALSE;
		auto pmsgctnt = ict->dup();
		if (pmsgctnt == nullptr)
			return FALSE;
		static_cast<ATTACHMENT_CONTENT *>(pinstance1->pcontent)->set_embedded_internal(pmsgctnt);
		*pe_result = ecSuccess;
		return TRUE;
	}
	auto pmsgctnt = ict->dup();
	if (pmsgctnt == nullptr)
		return FALSE;	
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> upmsgctnt(pmsgctnt);
	auto pbin = pmsgctnt->proplist.get<BINARY>(PR_SENT_REPRESENTING_ENTRYID);
	if (pbin != nullptr &&
	    !pmsgctnt->proplist.has(PR_SENT_REPRESENTING_EMAIL_ADDRESS)) {
		auto sr_addrtype = pmsgctnt->proplist.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
		if (sr_addrtype == nullptr) {
			if (common_util_parse_addressbook_entryid(pbin,
			    address_type, std::size(address_type),
			    tmp_buff, std::size(tmp_buff))) {
				if (pmsgctnt->proplist.set(PR_SENT_REPRESENTING_ADDRTYPE, address_type) != 0 ||
				    pmsgctnt->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, tmp_buff) != 0)
					return FALSE;
			}
		} else if (strcasecmp(sr_addrtype, "EX") == 0) {
			if (common_util_addressbook_entryid_to_essdn(pbin,
			    tmp_buff, std::size(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		} else if (strcasecmp(sr_addrtype, "SMTP") == 0) {
			if (common_util_addressbook_entryid_to_username(pbin,
			    tmp_buff, std::size(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		}
	}
	pbin = pmsgctnt->proplist.get<BINARY>(PR_SENDER_ENTRYID);
	if (pbin != nullptr && !pmsgctnt->proplist.has(PR_SENDER_EMAIL_ADDRESS)) {
		auto sr_addrtype = pmsgctnt->proplist.get<const char>(PR_SENDER_ADDRTYPE);
		if (sr_addrtype == nullptr) {
			if (common_util_parse_addressbook_entryid(pbin,
			    address_type, std::size(address_type),
			    tmp_buff, std::size(tmp_buff))) {
				if (pmsgctnt->proplist.set(PR_SENDER_ADDRTYPE, address_type) != 0 ||
				    pmsgctnt->proplist.set(PR_SENDER_EMAIL_ADDRESS, tmp_buff) != 0)
					return FALSE;
			}
		} else if (strcasecmp(sr_addrtype, "EX") == 0) {
			if (common_util_addressbook_entryid_to_essdn(pbin,
			    tmp_buff, std::size(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENDER_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		} else if (strcasecmp(sr_addrtype, "SMTP") == 0) {
			if (common_util_addressbook_entryid_to_username(pbin,
			    tmp_buff, std::size(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENDER_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		}
	}
	pinstance->b_new = FALSE;
	folder_id = rop_util_make_eid_ex(1, pinstance->folder_id);
	if (!exmdb_server::is_private())
		exmdb_server::set_public_username(pinstance->username.c_str());
	pdb.reset();
	g_inside_flush_instance = true;
	BOOL b_result = exmdb_server::write_message(dir, account, CP_ACP,
	                folder_id, pmsgctnt, pe_result);
	g_inside_flush_instance = false;
	exmdb_server::set_public_username(nullptr);
	return b_result;
}
	
BOOL exmdb_server::unload_instance(const char *dir, uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	for (auto it = pdb->instance_list.begin(); it != pdb->instance_list.end(); ++it) {
		if (it->instance_id == instance_id) {
			pdb->instance_list.erase(it);
			break;
		}
	}
	return TRUE;
}

static uint32_t msg_idtopr(uint32_t t)
{
	switch (t) {
	case ID_TAG_BODY: return PR_BODY;
	case ID_TAG_BODY_STRING8: return PR_BODY_A;
	case ID_TAG_HTML: return PR_HTML;
	case ID_TAG_RTFCOMPRESSED: return PR_RTF_COMPRESSED;
	case ID_TAG_TRANSPORTMESSAGEHEADERS: return PR_TRANSPORT_MESSAGE_HEADERS;
	case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8: return PR_TRANSPORT_MESSAGE_HEADERS_A;
	default: return t;
	}
}

static uint32_t atx_idtopr(uint32_t t)
{
	switch (t) {
	case ID_TAG_ATTACHDATABINARY: return PR_ATTACH_DATA_BIN;
	case ID_TAG_ATTACHDATAOBJECT: return PR_ATTACH_DATA_OBJ;
	default: return t;
	}
}

static BOOL giat_message(MESSAGE_CONTENT *pmsgctnt, PROPTAG_ARRAY *pproptags)
{
	pproptags->count = pmsgctnt->proplist.count + 6;
	if (pmsgctnt->children.prcpts != nullptr)
		pproptags->count++;
	if (pmsgctnt->children.pattachments != nullptr)
		pproptags->count++;
	pproptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == pproptags->pproptag) {
		pproptags->count = 0;
		return FALSE;
	}
	for (unsigned int i = 0; i < pmsgctnt->proplist.count; ++i)
		pproptags->pproptag[i] = msg_idtopr(pmsgctnt->proplist.ppropval[i].proptag);
	pproptags->count = pmsgctnt->proplist.count;
	for (auto t : {PR_CODE_PAGE_ID, PR_MESSAGE_SIZE, PR_HASATTACH,
	     PR_DISPLAY_TO, PR_DISPLAY_CC, PR_DISPLAY_BCC})
		pproptags->emplace_back(t);
	return TRUE;
}

static BOOL giat_attachment(ATTACHMENT_CONTENT *pattachment, PROPTAG_ARRAY *pproptags)
{
	pproptags->count = pattachment->proplist.count + 1;
	if (pattachment->pembedded != nullptr)
		pproptags->count++;
	pproptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == pproptags->pproptag) {
		pproptags->count = 0;
		return FALSE;
	}
	for (unsigned int i = 0; i < pattachment->proplist.count; ++i)
		pproptags->pproptag[i] = atx_idtopr(pattachment->proplist.ppropval[i].proptag);
	pproptags->count = pattachment->proplist.count;
	pproptags->emplace_back(PR_ATTACH_SIZE);
	return TRUE;
}

BOOL exmdb_server::get_instance_all_proptags(const char *dir,
    uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr)
		return FALSE;
	return pinstance->type == instance_type::message ?
	       giat_message(static_cast<MESSAGE_CONTENT *>(pinstance->pcontent), pproptags) :
	       giat_attachment(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent), pproptags);
}

static BOOL instance_get_message_display_recipients(TARRAY_SET *prcpts,
    cpid_t cpid, uint32_t proptag, void **ppvalue) try
{
	std::string dr;
	uint32_t recipient_type = 0;
	static constexpr uint8_t fake_empty = 0;

	switch (proptag) {
	case PR_DISPLAY_TO:
	case PR_DISPLAY_TO_A:
		recipient_type = MAPI_TO;
		break;
	case PR_DISPLAY_CC:
	case PR_DISPLAY_CC_A:
		recipient_type = MAPI_CC;
		break;
	case PR_DISPLAY_BCC:
	case PR_DISPLAY_BCC_A:
		recipient_type = MAPI_BCC;
		break;
	}
	for (size_t i = 0; i < prcpts->count; ++i) {
		auto rcpttype = prcpts->pparray[i]->get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (rcpttype == nullptr || *rcpttype != recipient_type)
			continue;
		auto name = prcpts->pparray[i]->get<const char>(PR_DISPLAY_NAME);
		if (name == nullptr) {
			name = prcpts->pparray[i]->get<char>(PR_DISPLAY_NAME_A);
			if (name != nullptr)
				name = common_util_convert_copy(TRUE, cpid, name);
		}
		if (name == nullptr)
			name = prcpts->pparray[i]->get<char>(PR_SMTP_ADDRESS);
		if (name == nullptr)
			continue;
		if (!dr.empty())
			dr += "; ";
		dr += name;
	}
	if (dr.empty()) {
		*ppvalue = deconst(&fake_empty);
		return TRUE;
	}
	*ppvalue = PROP_TYPE(proptag) == PT_UNICODE ? common_util_dup(dr.c_str()) :
	           common_util_convert_copy(false, cpid, dr.c_str());
	return *ppvalue != nullptr ? TRUE : false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1160: ENOMEM");
	return false;
}

static uint32_t instance_get_message_flags(MESSAGE_CONTENT *pmsgctnt)
{
	TPROPVAL_ARRAY *pproplist;
	
	pproplist = &pmsgctnt->proplist;
	auto flags_p = pproplist->get<const uint32_t>(PR_MESSAGE_FLAGS);
	uint32_t message_flags = flags_p == nullptr ? 0 : *flags_p;
	message_flags &= ~(MSGFLAG_READ | MSGFLAG_HASATTACH | MSGFLAG_FROMME |
	                 MSGFLAG_ASSOCIATED | MSGFLAG_RN_PENDING |
	                 MSGFLAG_NRN_PENDING);
	auto pbool = pproplist->get<const uint8_t>(PR_READ);
	if (pbool != nullptr && *pbool)
		message_flags |= MSGFLAG_READ;
	if (pmsgctnt->children.pattachments != nullptr &&
	    pmsgctnt->children.pattachments->count != 0)
		message_flags |= MSGFLAG_HASATTACH;
	pbool = pproplist->get<uint8_t>(PR_ASSOCIATED);
	if (pbool != nullptr && *pbool)
		message_flags |= MSGFLAG_ASSOCIATED;
	pbool = pproplist->get<uint8_t>(PR_READ_RECEIPT_REQUESTED);
	if (pbool != nullptr && *pbool)
		message_flags |= MSGFLAG_RN_PENDING;
	pbool = pproplist->get<uint8_t>(PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
	if (pbool != nullptr && *pbool)
		message_flags |= MSGFLAG_NRN_PENDING;
	return message_flags;
}

static BOOL instance_get_message_subject(TPROPVAL_ARRAY *pproplist,
    cpid_t cpid, uint32_t proptag, void **ppvalue)
{
	auto pnormalized_subject = pproplist->get<const char>(PR_NORMALIZED_SUBJECT);
	if (NULL == pnormalized_subject) {
		auto pvalue = pproplist->get<char>(PR_NORMALIZED_SUBJECT_A);
		if (pvalue != nullptr)
			pnormalized_subject =
				common_util_convert_copy(TRUE, cpid, pvalue);
	}
	auto psubject_prefix = pproplist->get<const char>(PR_SUBJECT_PREFIX);
	if (NULL == psubject_prefix) {
		auto pvalue = pproplist->get<char>(PR_SUBJECT_PREFIX_A);
		if (pvalue != nullptr)
			psubject_prefix =
				common_util_convert_copy(TRUE, cpid, pvalue);
	}
	if (NULL == pnormalized_subject && NULL == psubject_prefix) {
		*ppvalue = NULL;
		return TRUE;
	}
	if (pnormalized_subject == nullptr)
		pnormalized_subject = "";
	if (psubject_prefix == nullptr)
		psubject_prefix = "";
	auto pvalue = cu_alloc<char>(strlen(pnormalized_subject) + strlen(psubject_prefix) + 1);
	if (pvalue == nullptr)
		return FALSE;
	strcpy(pvalue, psubject_prefix);
	strcat(pvalue, pnormalized_subject);
	if (PROP_TYPE(proptag) != PT_UNICODE) {
		*ppvalue = common_util_convert_copy(FALSE, cpid, pvalue);
		return TRUE;
	}
	*ppvalue = common_util_dup(pvalue);
	return *ppvalue != nullptr ? TRUE : false;
}

static BOOL instance_get_attachment_properties(cpid_t cpid,
	const uint64_t *pmessage_id, ATTACHMENT_CONTENT *pattachment,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	uint32_t length;
	uint16_t proptype;
	
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		auto pvalue = pattachment->proplist.getval(tag);
		if (NULL != pvalue) {
			ppropvals->emplace_back(tag, pvalue);
			continue;
		}
		auto &vc = ppropvals->ppropval[ppropvals->count];
		vc.pvalue = NULL;
		if (PROP_TYPE(tag) == PT_STRING8) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_UNICODE);
			auto str = pattachment->proplist.get<const char>(u_tag);
			if (str != nullptr) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy(false, cpid, str);
			}
		} else if (PROP_TYPE(tag) == PT_UNICODE) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_STRING8);
			auto str = pattachment->proplist.get<const char>(u_tag);
			if (str != nullptr) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy(TRUE, cpid, str);
			}
		} else if (PROP_TYPE(tag) == PT_MV_STRING8) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_MV_UNICODE);
			auto sa = pattachment->proplist.get<const STRING_ARRAY>(u_tag);
			if (sa != nullptr) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy_string_array(false, cpid, sa);
			}
		} else if (PROP_TYPE(tag) == PT_MV_UNICODE) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_MV_STRING8);
			auto sa = pattachment->proplist.get<const STRING_ARRAY>(u_tag);
			if (sa != nullptr) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy_string_array(TRUE, cpid, sa);
			}
		} else if (PROP_TYPE(tag) == PT_UNSPECIFIED) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_UNICODE);
			pvalue = pattachment->proplist.getval(u_tag);
			if (NULL != pvalue) {
				vc.proptag = tag;
				auto tp = cu_alloc<TYPED_PROPVAL>();
				vc.pvalue = tp;
				if (tp == nullptr)
					return FALSE;	
				tp->type = PT_UNICODE;
				tp->pvalue = pvalue;
			} else {
				u_tag = CHANGE_PROP_TYPE(tag, PT_STRING8);
				pvalue = pattachment->proplist.getval(u_tag);
				if (NULL != pvalue) {
					vc.proptag = tag;
					auto tp = cu_alloc<TYPED_PROPVAL>();
					vc.pvalue = tp;
					if (tp == nullptr)
						return FALSE;	
					tp->type = PT_UNICODE;
					tp->pvalue = pvalue;
				}
			}
		}
		if (vc.pvalue != nullptr) {
			ppropvals->count ++;
			continue;
		}
		switch (tag) {
		case PidTagMid: {
			if (pmessage_id == nullptr)
				break;
			auto pv = cu_alloc<uint64_t>();
			vc.pvalue = pv;
			if (pv == nullptr)
				return FALSE;
			*pv = rop_util_make_eid_ex(1, *pmessage_id);
			vc.proptag = tag;
			ppropvals->count ++;
			continue;
		}
		case PR_ATTACH_SIZE: {
			length = common_util_calculate_attachment_size(pattachment);
			auto uv = cu_alloc<uint32_t>();
			if (uv == nullptr)
				return FALSE;
			*uv = length;
			ppropvals->emplace_back(tag, uv);
			continue;
		}
		case PR_ATTACH_DATA_BIN_U: {
			proptype = PT_BINARY;
			auto pbin = pattachment->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
			if (NULL == pbin) {
				auto cidstr = pattachment->proplist.get<const char>(ID_TAG_ATTACHDATABINARY);
				if (cidstr != nullptr) {
					pvalue = instance_read_cid_content(cidstr, &length, 0);
					if (pvalue == nullptr)
						return FALSE;
					pbin = cu_alloc<BINARY>();
					if (pbin == nullptr)
						return FALSE;
					pbin->cb = length;
					pbin->pv = pvalue;
				}
			}
			if (NULL == pbin) {
				proptype = PT_OBJECT;
				pbin = pattachment->proplist.get<BINARY>(PR_ATTACH_DATA_OBJ);
				if (NULL == pbin) {
					auto cidstr = pattachment->proplist.get<const char>(ID_TAG_ATTACHDATAOBJECT);
					if (cidstr != nullptr) {
						pvalue = instance_read_cid_content(cidstr, &length, 0);
						if (pvalue == nullptr)
							return FALSE;
						pbin = cu_alloc<BINARY>();
						if (pbin == nullptr)
							return FALSE;
						pbin->cb = length;
						pbin->pv = pvalue;
					}
				}
			}
			if (pbin == nullptr)
				break;
			auto tp = cu_alloc<TYPED_PROPVAL>();
			if (tp == nullptr)
				return FALSE;
			tp->type = proptype;
			tp->pvalue = pbin;
			ppropvals->emplace_back(tag, tp);
			continue;
		}
		case PR_ATTACH_DATA_BIN:
		case PR_ATTACH_DATA_OBJ: {
			auto cidstr = pattachment->proplist.get<const char>(
			              tag == PR_ATTACH_DATA_BIN ?
			              ID_TAG_ATTACHDATABINARY : ID_TAG_ATTACHDATAOBJECT);
			if (cidstr == nullptr)
				break;
			pvalue = instance_read_cid_content(cidstr, &length, 0);
			if (pvalue == nullptr)
				return FALSE;
			auto pbin = cu_alloc<BINARY>();
			if (pbin == nullptr)
				return FALSE;
			pbin->cb = length;
			pbin->pv = pvalue;
			ppropvals->emplace_back(tag, pbin);
			continue;
		}
		}
	}
	return TRUE;
}	

BOOL exmdb_server::get_instance_properties(const char *dir,
    uint32_t size_limit, uint32_t instance_id, const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	uint16_t propid;
	uint32_t length;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr)
		return FALSE;
	if (pinstance->type == instance_type::attachment) {
		auto pinstance1 = instance_get_instance_c(pdb, pinstance->parent_id);
		if (pinstance1 == nullptr)
			return FALSE;
		auto pvalue = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent)->proplist.get<uint64_t>(PidTagMid);
		if (!instance_get_attachment_properties(pinstance->cpid, pvalue,
		    static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent),
		    pproptags, ppropvals))
			return FALSE;
		return TRUE;
	}
	pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		auto &vc = ppropvals->ppropval[ppropvals->count];
		const auto tag = pproptags->pproptag[i];
		if (tag == PR_MESSAGE_FLAGS) {
			vc.proptag = tag;
			auto uv = cu_alloc<uint32_t>();
			vc.pvalue = uv;
			if (vc.pvalue == nullptr)
				return FALSE;
			*uv = instance_get_message_flags(pmsgctnt);
			ppropvals->count ++;
			continue;
		}
		auto pvalue = pmsgctnt->proplist.getval(tag);
		if (NULL != pvalue) {
			vc.proptag = tag;
			vc.pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		vc.pvalue = nullptr;
		if (PROP_TYPE(tag) == PT_STRING8) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_UNICODE);
			pvalue = pmsgctnt->proplist.getval(u_tag);
			if (NULL != pvalue) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy(false,
				            pinstance->cpid, static_cast<char *>(pvalue));
			}
		} else if (PROP_TYPE(tag) == PT_UNICODE) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_STRING8);
			pvalue = pmsgctnt->proplist.getval(u_tag);
			if (NULL != pvalue) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy(TRUE,
				            pinstance->cpid, static_cast<char *>(pvalue));
			}
		} else if (PROP_TYPE(tag) == PT_MV_STRING8) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_MV_UNICODE);
			pvalue = pmsgctnt->proplist.getval(u_tag);
			if (NULL != pvalue) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy_string_array(false,
				            pinstance->cpid, static_cast<STRING_ARRAY *>(pvalue));
			}
		} else if (PROP_TYPE(tag) == PT_MV_UNICODE) {
			auto u_tag = CHANGE_PROP_TYPE(tag, PT_MV_STRING8);
			pvalue = pmsgctnt->proplist.getval(u_tag);
			if (NULL != pvalue) {
				vc.proptag = tag;
				vc.pvalue = common_util_convert_copy_string_array(TRUE,
				            pinstance->cpid, static_cast<STRING_ARRAY *>(pvalue));
			}	
		} else if (PROP_TYPE(tag) == PT_UNSPECIFIED) {
			propid = PROP_ID(tag);
			for (unsigned int j = 0; j < pmsgctnt->proplist.count; ++j) {
				if (propid != PROP_ID(pmsgctnt->proplist.ppropval[j].proptag))
					continue;
				vc.proptag = tag;
				auto tp = cu_alloc<TYPED_PROPVAL>();
				vc.pvalue = tp;
				if (vc.pvalue == nullptr)
					return FALSE;
				tp->type = PROP_TYPE(pmsgctnt->proplist.ppropval[j].proptag);
				tp->pvalue = pmsgctnt->proplist.ppropval[j].pvalue;
				break;
			}
		}
		if (vc.pvalue != nullptr) {
			ppropvals->count ++;
			continue;
		}
		switch (tag) {
		case PR_BODY_A:
		case PR_BODY_W:
		case PR_BODY_U:
		case PR_HTML:
		case PR_HTML_U:
		case PR_RTF_COMPRESSED: {
			auto ret = instance_get_message_body(pmsgctnt, tag, pinstance->cpid, ppropvals);
			if (ret < 0)
				return false;
			break;
		}
		case PR_TRANSPORT_MESSAGE_HEADERS_U: {
			auto cidstr = pmsgctnt->proplist.get<const char>(ID_TAG_TRANSPORTMESSAGEHEADERS);
			if (cidstr != nullptr) {
				pvalue = instance_read_cid_content(cidstr, nullptr, ID_TAG_BODY);
				if (pvalue == nullptr)
					return FALSE;
				vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_U;
				auto tp = cu_alloc<TYPED_PROPVAL>();
				vc.pvalue = tp;
				if (vc.pvalue == nullptr)
					return FALSE;
				tp->type = PT_UNICODE;
				tp->pvalue = static_cast<char *>(pvalue);
				ppropvals->count ++;
				continue;
			}
			cidstr = pmsgctnt->proplist.get<const char>(ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
			if (cidstr == nullptr)
				break;
			pvalue = instance_read_cid_content(cidstr, nullptr, 0);
			if (pvalue == nullptr)
				return FALSE;
			vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_U;
			auto tp = cu_alloc<TYPED_PROPVAL>();
			vc.pvalue = tp;
			if (vc.pvalue == nullptr)
				return FALSE;
			tp->type = PT_STRING8;
			tp->pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		case PR_SUBJECT:
		case PR_SUBJECT_A:
			if (!instance_get_message_subject(&pmsgctnt->proplist,
			    pinstance->cpid, tag, &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				break;
			vc.proptag = tag;
			vc.pvalue = pvalue;
			ppropvals->count++;
			continue;
		case PR_TRANSPORT_MESSAGE_HEADERS: {
			auto cidstr = pmsgctnt->proplist.get<const char>(ID_TAG_TRANSPORTMESSAGEHEADERS);
			if (cidstr != nullptr) {
				pvalue = instance_read_cid_content(cidstr, nullptr, ID_TAG_BODY);
				if (pvalue == nullptr)
					return FALSE;
				vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS;
				vc.pvalue = static_cast<char *>(pvalue);
				ppropvals->count ++;
				continue;
			}
			cidstr = pmsgctnt->proplist.get<const char>(ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
			if (cidstr == nullptr)
				break;
			pvalue = instance_read_cid_content(cidstr, nullptr, 0);
			if (pvalue == nullptr)
				return FALSE;
			vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS;
			vc.pvalue = common_util_convert_copy(TRUE,
				    pinstance->cpid, static_cast<char *>(pvalue));
			if (vc.pvalue != nullptr) {
				ppropvals->count++;
				continue;
			}
			break;
		}
		case PR_TRANSPORT_MESSAGE_HEADERS_A: {
			auto cidstr = pmsgctnt->proplist.get<const char>(ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
			if (cidstr != nullptr) {
				pvalue = instance_read_cid_content(cidstr, nullptr, 0);
				if (pvalue == nullptr)
					return FALSE;
				vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
				vc.pvalue = pvalue;
				ppropvals->count ++;
				continue;
			}
			cidstr = pmsgctnt->proplist.get<char>(ID_TAG_TRANSPORTMESSAGEHEADERS);
			if (cidstr == nullptr)
				break;
			pvalue = instance_read_cid_content(cidstr, nullptr, ID_TAG_BODY);
			if (pvalue == nullptr)
				return FALSE;
			vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
			vc.pvalue = common_util_convert_copy(false,
				    pinstance->cpid, static_cast<char *>(pvalue));
			if (vc.pvalue != nullptr) {
				ppropvals->count++;
				continue;
			}
			break;
		}
		case PidTagFolderId: {
			if (pinstance->parent_id != 0)
				break;
			vc.proptag = tag;
			auto uv = cu_alloc<uint64_t>();
			vc.pvalue = uv;
			if (vc.pvalue == nullptr)
				return FALSE;
			*uv = rop_util_make_eid_ex(1, pinstance->folder_id);
			ppropvals->count++;
			continue;
		}
		case PR_CODE_PAGE_ID:
			vc.proptag = tag;
			vc.pvalue = deconst(&pinstance->cpid);
			ppropvals->count ++;
			continue;
		case PR_MESSAGE_SIZE:
		case PR_MESSAGE_SIZE_EXTENDED:
			vc.proptag = tag;
			length = common_util_calculate_message_size(pmsgctnt);
			if (tag == PR_MESSAGE_SIZE) {
				auto uv = cu_alloc<uint32_t>();
				if (uv == nullptr)
					return FALSE;
				*uv = length;
				vc.pvalue = uv;
			} else {
				auto uv = cu_alloc<uint64_t>();
				if (uv == nullptr)
					return FALSE;
				*uv = length;
				vc.pvalue = uv;
			}
			ppropvals->count ++;
			continue;
		case PR_HASATTACH: {
			vc.proptag = tag;
			auto uv = cu_alloc<uint8_t>();
			if (uv == nullptr)
				return FALSE;
			vc.pvalue = uv;
			ppropvals->count ++;
			*uv = pmsgctnt->children.pattachments == nullptr ||
			      pmsgctnt->children.pattachments->count == 0 ? 0 : 1;
			continue;
		}
		case PR_DISPLAY_TO:
		case PR_DISPLAY_TO_A:
		case PR_DISPLAY_CC:
		case PR_DISPLAY_CC_A:
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_BCC_A:
			if (pmsgctnt->children.prcpts == nullptr)
				break;
			if (!instance_get_message_display_recipients(pmsgctnt->children.prcpts,
			    pinstance->cpid, tag, &pvalue))
				return FALSE;
			vc.proptag = tag;
			vc.pvalue = pvalue;
			ppropvals->count++;
			continue;
		}
	}
	return TRUE;
}

/* A duplicate implementation is in common_util_set_message_subject. */
static BOOL xns_set_msg_subj(TPROPVAL_ARRAY &msgprop,
    const TPROPVAL_ARRAY &nuprop, size_t subj_id, cpid_t cpid)
{
	auto &stag   = nuprop.ppropval[subj_id].proptag;
	/* No support for mixed STRING8/UNICODE */
	auto pfxtag  = CHANGE_PROP_TYPE(PR_SUBJECT_PREFIX, PROP_TYPE(stag));
	auto normtag = CHANGE_PROP_TYPE(PR_NORMALIZED_SUBJECT, PROP_TYPE(stag));
	auto pfx  = nuprop.get<const char>(pfxtag);
	auto norm = nuprop.get<const char>(normtag);
	msgprop.erase(stag);
	if (pfx != nullptr && norm != nullptr)
		/* Decomposition not needed; parts are complete. */
		return TRUE;

	auto subj = static_cast<const char *>(nuprop.ppropval[subj_id].pvalue);
	if (!cu_rebuild_subjects(subj, pfx, norm))
		return false;

	if (pfx == nullptr) {
		msgprop.erase(pfxtag);
	} else if (PROP_TYPE(pfxtag) == PT_UNICODE) {
		if (msgprop.set(pfxtag, pfx) != 0)
			return false;
	} else {
		pfx = common_util_convert_copy(TRUE, cpid, pfx);
		if (pfx == nullptr)
			return false;
		if (msgprop.set(pfxtag, pfx) != 0)
			return false;
	}
	if (norm == nullptr) {
		msgprop.erase(normtag);
	} else if (PROP_TYPE(normtag) == PT_UNICODE) {
		if (msgprop.set(normtag, norm) != 0)
			return false;
	} else {
		norm = common_util_convert_copy(TRUE, cpid, norm);
		if (norm == nullptr || msgprop.set(normtag, norm) != 0)
			return false;
	}
	return TRUE;
}

static BOOL set_xns_props_msg(INSTANCE_NODE *pinstance,
    const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems)
{
	static constexpr uint8_t one_byte = 1;

	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproperties->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	for (size_t i = 0; i < pproperties->count; ++i) {
		auto tag = pproperties->ppropval[i].proptag;
		switch (tag) {
		case PR_ASSOCIATED:
			if (pinstance->b_new)
				break;
		case ID_TAG_BODY:
		case ID_TAG_BODY_STRING8:
		case ID_TAG_HTML:
		case ID_TAG_RTFCOMPRESSED:
		case PidTagMid:
		case PR_ENTRYID:
		case PidTagFolderId:
		case PR_CODE_PAGE_ID:
		case PidTagParentFolderId:
		case PR_INSTANCE_SVREID:
		case PR_HAS_NAMED_PROPERTIES:
		case PR_MESSAGE_SIZE:
		case PR_HASATTACH:
		case PR_DISPLAY_TO:
		case PR_DISPLAY_CC:
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_TO_A:
		case PR_DISPLAY_CC_A:
		case PR_DISPLAY_BCC_A:
			pproblems->emplace_back(i, tag, ecAccessDenied);
			continue;
		case PR_READ: {
			if (*static_cast<uint8_t *>(pproperties->ppropval[i].pvalue) == 0)
				break;
			auto flags = pmsgctnt->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
			if (flags != nullptr)
				*flags |= MSGFLAG_EVERREAD;
			break;
		}
		case PR_MSG_STATUS:
			/* PidTagMessageStatus can only be
				set by RopSetMessageStatus */
			continue;
		case PR_MESSAGE_FLAGS: {
			if (!pinstance->b_new) {
				pproblems->emplace_back(i, tag, ecAccessDenied);
				continue;
			}
			auto message_flags = *static_cast<uint32_t *>(pproperties->ppropval[i].pvalue);
			if (message_flags & MSGFLAG_READ &&
			    pmsgctnt->proplist.set(PR_READ, &one_byte) != 0)
				return FALSE;
			if (message_flags & MSGFLAG_ASSOCIATED &&
			    pmsgctnt->proplist.set(PR_ASSOCIATED, &one_byte) != 0)
				return FALSE;
			if (message_flags & MSGFLAG_RN_PENDING &&
			    pmsgctnt->proplist.set(PR_READ_RECEIPT_REQUESTED, &one_byte) != 0)
				return FALSE;
			if (message_flags & MSGFLAG_NRN_PENDING &&
			    pmsgctnt->proplist.set(PR_NON_RECEIPT_NOTIFICATION_REQUESTED, &one_byte) != 0)
				return FALSE;
			message_flags &= ~(MSGFLAG_READ | MSGFLAG_UNMODIFIED |
					 MSGFLAG_HASATTACH | MSGFLAG_FROMME |
					 MSGFLAG_ASSOCIATED | MSGFLAG_RN_PENDING |
					 MSGFLAG_NRN_PENDING);
			*static_cast<uint32_t *>(pproperties->ppropval[i].pvalue) = message_flags;
			break;
		}
		case PR_SUBJECT:
		case PR_SUBJECT_A: {
			if (!xns_set_msg_subj(pmsgctnt->proplist, *pproperties,
			    i, pinstance->cpid))
				return FALSE;
			continue;
		}
		case PR_BODY:
		case PR_BODY_A:
			pmsgctnt->proplist.erase(ID_TAG_BODY);
			pmsgctnt->proplist.erase(ID_TAG_BODY_STRING8);
			break;
		case PR_HTML:
			pmsgctnt->proplist.erase(ID_TAG_HTML);
			break;
		case PR_RTF_COMPRESSED:
			pmsgctnt->proplist.erase(ID_TAG_RTFCOMPRESSED);
			break;
		}
		TAGGED_PROPVAL propval;
		switch (PROP_TYPE(tag)) {
		case PT_STRING8:
		case PT_UNICODE:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_STRING8));
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(tag, PT_UNICODE);
			if (PROP_TYPE(tag) == PT_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy(TRUE,
				pinstance->cpid, static_cast<char *>(pproperties->ppropval[i].pvalue));
			if (propval.pvalue == nullptr)
				return FALSE;
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_STRING8));
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(tag, PT_MV_UNICODE);
			if (PROP_TYPE(tag) == PT_MV_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy_string_array(
			                 TRUE, pinstance->cpid,
			                 static_cast<STRING_ARRAY *>(pproperties->ppropval[i].pvalue));
			if (propval.pvalue == nullptr)
				return FALSE;
			break;
		default:
			propval = pproperties->ppropval[i];
			break;
		}
		if (pmsgctnt->proplist.set(propval) != 0)
			return FALSE;
		if (propval.proptag != PR_BODY && propval.proptag != PR_HTML &&
		    propval.proptag != PR_BODY_HTML &&
		    propval.proptag != PR_RTF_COMPRESSED)
			continue;

		uint32_t body_type = 0;
		switch (propval.proptag) {
		case PR_BODY:
			pinstance->change_mask |= CHANGE_MASK_BODY;
			body_type = NATIVE_BODY_PLAIN;
			break;
		case PR_HTML:
			pinstance->change_mask |= CHANGE_MASK_HTML;
			[[fallthrough]];
		case PR_BODY_HTML:
			body_type = NATIVE_BODY_HTML;
			break;
		case PR_RTF_COMPRESSED:
			body_type = NATIVE_BODY_RTF;
			break;
		}
		if (pmsgctnt->proplist.set(PR_NATIVE_BODY_INFO, &body_type) != 0)
			return FALSE;
	}
	return TRUE;
}

static BOOL set_xns_props_atx(INSTANCE_NODE *pinstance,
    const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems)
{
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproperties->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	auto pattachment = static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent);
	for (size_t i = 0; i < pproperties->count; ++i) {
		TAGGED_PROPVAL propval;
		auto tag = pproperties->ppropval[i].proptag;
		switch (tag) {
		case ID_TAG_ATTACHDATABINARY:
		case ID_TAG_ATTACHDATAOBJECT:
		case PR_ATTACH_NUM:
		case PR_RECORD_KEY:
			pproblems->emplace_back(i, tag, ecAccessDenied);
			continue;
		case PR_ATTACH_DATA_BIN:
			pattachment->proplist.erase(ID_TAG_ATTACHDATABINARY);
			break;
		case PR_ATTACH_DATA_OBJ:
			pattachment->proplist.erase(ID_TAG_ATTACHDATAOBJECT);
			break;
		}
		switch (PROP_TYPE(tag)) {
		case PT_STRING8:
		case PT_UNICODE:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_STRING8));
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(tag, PT_UNICODE);
			if (PROP_TYPE(tag) == PT_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy(TRUE,
				pinstance->cpid, static_cast<char *>(pproperties->ppropval[i].pvalue));
			if (propval.pvalue == nullptr)
				return FALSE;
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_STRING8));
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(tag, PT_MV_UNICODE);
			if (PROP_TYPE(tag) == PT_MV_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy_string_array(
			                 TRUE, pinstance->cpid,
					 static_cast<STRING_ARRAY *>(pproperties->ppropval[i].pvalue));
			if (propval.pvalue == nullptr)
				return FALSE;
			break;
		default:
			propval = pproperties->ppropval[i];
			break;
		}
		if (pattachment->proplist.set(propval) != 0)
			return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server::set_instance_properties(const char *dir,
    uint32_t instance_id, const TPROPVAL_ARRAY *props, PROBLEM_ARRAY *prob)
{
	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto ins = instance_get_instance(db, instance_id);
	if (ins == nullptr)
		return false;
	if (ins->type == instance_type::message)
		return set_xns_props_msg(ins, props, prob);
	return set_xns_props_atx(ins, props, prob);
}

static BOOL rip_message(MESSAGE_CONTENT *pmsgctnt,
    const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
{
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		switch (tag) {
		case PR_BODY:
		case PR_BODY_A:
		case PR_BODY_U: {
			pmsgctnt->proplist.erase(ID_TAG_BODY);
			pmsgctnt->proplist.erase(ID_TAG_BODY_STRING8);
			auto num = pmsgctnt->proplist.get<uint32_t>(PR_NATIVE_BODY_INFO);
			if (num != nullptr && *num == NATIVE_BODY_PLAIN)
				*num = NATIVE_BODY_UNDEFINED;
			break;
		}
		case PR_HTML:
		case PR_BODY_HTML:
		case PR_BODY_HTML_A:
		case PR_HTML_U: {
			pmsgctnt->proplist.erase(PR_BODY_HTML);
			pmsgctnt->proplist.erase(PR_BODY_HTML_A);
			pmsgctnt->proplist.erase(ID_TAG_HTML);
			auto num = pmsgctnt->proplist.get<uint32_t>(PR_NATIVE_BODY_INFO);
			if (num != nullptr && *num == NATIVE_BODY_HTML)
				*num = NATIVE_BODY_UNDEFINED;
			break;
		}
		case PR_RTF_COMPRESSED: {
			auto num = pmsgctnt->proplist.get<uint32_t>(PR_NATIVE_BODY_INFO);
			if (num != nullptr && *num == NATIVE_BODY_RTF)
				*num = NATIVE_BODY_UNDEFINED;
			pmsgctnt->proplist.erase(ID_TAG_RTFCOMPRESSED);
			break;
		}
		}
		pmsgctnt->proplist.erase(tag);
		switch (PROP_TYPE(tag)) {
		case PT_STRING8:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_UNICODE));
			break;
		case PT_UNICODE:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_STRING8));
			break;
		case PT_MV_STRING8:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
			break;
		case PT_MV_UNICODE:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_STRING8));
			break;
		}
	}
	return TRUE;
}

static BOOL rip_attachment(ATTACHMENT_CONTENT *pattachment,
    const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
{
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		switch (tag) {
		case PR_ATTACH_DATA_BIN:
			pattachment->proplist.erase(ID_TAG_ATTACHDATABINARY);
			break;
		case PR_ATTACH_DATA_OBJ:
			pattachment->proplist.erase(ID_TAG_ATTACHDATAOBJECT);
			break;
		}
		pattachment->proplist.erase(tag);
		switch (PROP_TYPE(tag)) {
		case PT_STRING8:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_UNICODE));
			break;
		case PT_UNICODE:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_STRING8));
			break;
		case PT_MV_STRING8:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_UNICODE));
			break;
		case PT_MV_UNICODE:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(tag, PT_MV_STRING8));
			break;
		}
	}
	return TRUE;
}

BOOL exmdb_server::remove_instance_properties(const char *dir,
    uint32_t instance_id, const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr)
		return FALSE;
	pproblems->count = 0;
	return pinstance->type == instance_type::message ?
	       rip_message(static_cast<MESSAGE_CONTENT *>(pinstance->pcontent), pproptags, pproblems) :
	       rip_attachment(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent), pproptags, pproblems);
}

BOOL exmdb_server::check_instance_cycle(const char *dir,
	uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_cycle)
{
	if (src_instance_id == dst_instance_id) {
		*pb_cycle = TRUE;
		return TRUE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, dst_instance_id);
	while (NULL != pinstance && 0 != pinstance->parent_id) {
		if (pinstance->parent_id == src_instance_id) {
			*pb_cycle = TRUE;
			return TRUE;
		}
		pinstance = instance_get_instance_c(pdb, pinstance->parent_id);
	}
	*pb_cycle = FALSE;
	return TRUE;
}

BOOL exmdb_server::empty_message_instance_rcpts(const char *dir,
    uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL != pmsgctnt->children.prcpts) {
		tarray_set_free(pmsgctnt->children.prcpts);
		pmsgctnt->children.prcpts = NULL;
	}
	return TRUE;
}

BOOL exmdb_server::get_message_instance_rcpts_num(const char *dir,
    uint32_t instance_id, uint16_t *pnum)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	*pnum = pmsgctnt->children.prcpts == nullptr ? 0 :
	        pmsgctnt->children.prcpts->count;
	return TRUE;
}

BOOL exmdb_server::get_message_instance_rcpts_all_proptags(const char *dir,
    uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	TARRAY_SET *prcpts;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.prcpts) {
		pproptags->count = 0;
		pproptags->pproptag = NULL;
		return TRUE;
	}
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pproptags1(proptag_array_init());
	if (pproptags1 == nullptr)
		return FALSE;
	prcpts = pmsgctnt->children.prcpts;
	for (size_t i = 0; i < prcpts->count; ++i)
		for (size_t j = 0; j < prcpts->pparray[i]->count; ++j)
			if (!proptag_array_append(pproptags1.get(),
			    prcpts->pparray[i]->ppropval[j].proptag))
				return FALSE;
	/* MSMAPI expects to always see these four tags, even if no rows are sent later. */
	proptag_array_append(pproptags1.get(), PR_RECIPIENT_TYPE);
	proptag_array_append(pproptags1.get(), PR_DISPLAY_NAME);
	proptag_array_append(pproptags1.get(), PR_ADDRTYPE);
	proptag_array_append(pproptags1.get(), PR_EMAIL_ADDRESS);
	pproptags->count = pproptags1->count;
	pproptags->pproptag = cu_alloc<uint32_t>(pproptags1->count);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, pproptags1->pproptag,
				sizeof(uint32_t)*pproptags1->count);
	return TRUE;
}

BOOL exmdb_server::get_message_instance_rcpts(const char *dir,
    uint32_t instance_id, uint32_t row_id, uint16_t need_count,
    TARRAY_SET *pset)
{
	TARRAY_SET *prcpts;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.prcpts) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	prcpts = pmsgctnt->children.prcpts;
	size_t i;
	for (i=0; i<prcpts->count; i++) {
		auto prow_id = prcpts->pparray[i]->get<uint32_t>(PR_ROWID);
		if (prow_id != nullptr && row_id == *prow_id)
			break;
	}
	if (i >= prcpts->count) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	auto begin_pos = i;
	if (begin_pos + need_count > prcpts->count)
		need_count = prcpts->count - begin_pos;
	pset->count = need_count;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(need_count);
	if (pset->pparray == nullptr)
		return FALSE;
	for (i=0; i<need_count; i++) {
		pset->pparray[i] = cu_alloc<TPROPVAL_ARRAY>();
		if (pset->pparray[i] == nullptr)
			return FALSE;
		pset->pparray[i]->count =
			prcpts->pparray[begin_pos + i]->count;
		pset->pparray[i]->ppropval = cu_alloc<TAGGED_PROPVAL>(pset->pparray[i]->count + 4);
		if (NULL == pset->pparray[i]->ppropval) {
			pset->pparray[i]->count = 0;
			return FALSE;
		}
		memcpy(pset->pparray[i]->ppropval,
			prcpts->pparray[begin_pos + i]->ppropval,
			sizeof(TAGGED_PROPVAL)*pset->pparray[i]->count);

		auto &srecip = *prcpts->pparray[begin_pos+i];
		auto drecip = *pset->pparray[i];
		if (!srecip.has(PR_RECIPIENT_TYPE))
			drecip.emplace_back(PR_RECIPIENT_TYPE, &dummy_rcpttype);
		if (!srecip.has(PR_DISPLAY_NAME))
			drecip.emplace_back(PR_DISPLAY_NAME, dummy_string);
		if (!srecip.has(PR_ADDRTYPE))
			drecip.emplace_back(PR_ADDRTYPE, &dummy_addrtype);
		if (!srecip.has(PR_EMAIL_ADDRESS))
			drecip.emplace_back(PR_EMAIL_ADDRESS, dummy_string);
	}
	return TRUE;
}

/* if only PR_ROWID in propvals, means delete this row */
BOOL exmdb_server::update_message_instance_rcpts(const char *dir,
    uint32_t instance_id, const TARRAY_SET *pset)
{
	uint32_t row_id;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.prcpts) {
		pmsgctnt->children.prcpts = tarray_set_init();
		if (pmsgctnt->children.prcpts == nullptr)
			return FALSE;
	}
	for (size_t i = 0; i < pset->count; ++i) {
		auto &mod = *pset->pparray[i];
		auto prow_id = mod.get<uint32_t>(PR_ROWID);
		if (prow_id == nullptr)
			continue;
		row_id = *prow_id;
		bool did_match = false;
		size_t j;
		for (j=0; j<pmsgctnt->children.prcpts->count; j++) {
			auto ex_rcpt = pmsgctnt->children.prcpts->pparray[j];
			prow_id = ex_rcpt->get<uint32_t>(PR_ROWID);
			if (prow_id == nullptr || *prow_id != row_id)
				continue;
			did_match = true;
			if (mod.count == 1) {
				/* contains just ROWID */
				pmsgctnt->children.prcpts->erase(j);
				break;
			}
			auto prcpt = mod.dup();
			if (prcpt == nullptr)
				return FALSE;
			tpropval_array_free(ex_rcpt);
			pmsgctnt->children.prcpts->pparray[j] = prcpt;
			break;
		}
		if (j < pmsgctnt->children.prcpts->count || did_match)
			continue;
		/* No previous rowid matched, so this constitutes a new entry */
		if (pmsgctnt->children.prcpts->count >= MAX_RECIPIENT_NUMBER)
			return FALSE;
		tpropval_array_ptr prcpt(mod.dup());
		if (prcpt == nullptr)
			return FALSE;
		if (pmsgctnt->children.prcpts->append_move(std::move(prcpt)) != 0)
			return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server::copy_instance_rcpts(const char *dir, BOOL b_force,
    uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_result)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance_src = instance_get_instance_c(pdb, src_instance_id);
	if (pinstance_src == nullptr || pinstance_src->type != instance_type::message)
		return FALSE;
	if (static_cast<MESSAGE_CONTENT *>(pinstance_src->pcontent)->children.prcpts == nullptr) {
		*pb_result = FALSE;
		return TRUE;
	}
	auto pinstance_dst = instance_get_instance_c(pdb, dst_instance_id);
	if (pinstance_dst == nullptr || pinstance_dst->type != instance_type::message)
		return FALSE;
	if (!b_force && static_cast<MESSAGE_CONTENT *>(pinstance_dst->pcontent)->children.prcpts != nullptr) {
		*pb_result = FALSE;
		return TRUE;	
	}
	auto prcpts = static_cast<MESSAGE_CONTENT *>(pinstance_src->pcontent)->children.prcpts->dup();
	if (prcpts == nullptr)
		return FALSE;
	auto dm = static_cast<MESSAGE_CONTENT *>(pinstance_dst->pcontent);
	if (dm->children.prcpts != nullptr)
		tarray_set_free(dm->children.prcpts);
	dm->children.prcpts = prcpts;
	*pb_result = TRUE;
	return TRUE;
}

BOOL exmdb_server::empty_message_instance_attachments(const char *dir,
    uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL != pmsgctnt->children.pattachments) {
		attachment_list_free(pmsgctnt->children.pattachments);
		pmsgctnt->children.pattachments = NULL;
	}
	return TRUE;
}

BOOL exmdb_server::get_message_instance_attachments_num(const char *dir,
    uint32_t instance_id, uint16_t *pnum)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	*pnum = pmsgctnt->children.pattachments == nullptr ? 0 :
	        pmsgctnt->children.pattachments->count;
	return TRUE;
}

BOOL exmdb_server::get_message_instance_attachment_table_all_proptags(const char *dir,
    uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.pattachments) {
		pproptags->count = 0;
		pproptags->pproptag = NULL;
		return TRUE;
	}
	std::unique_ptr<PROPTAG_ARRAY, pta_delete> pproptags1(proptag_array_init());
	if (pproptags1 == nullptr)
		return FALSE;
	auto pattachments = pmsgctnt->children.pattachments;
	for (unsigned int i = 0; i < pattachments->count; ++i) {
		for (unsigned int j = 0; j < pattachments->pplist[i]->proplist.count; ++j) {
			auto tag = pattachments->pplist[i]->proplist.ppropval[j].proptag;
			switch (PROP_TYPE(tag)) {
			case PT_UNSPECIFIED:
			case PT_NULL:
			case PT_GXI_STRING:
				continue;
			}
			if (!proptag_array_append(pproptags1.get(), tag))
				return FALSE;
		}
	}
	pproptags->count = pproptags1->count;
	pproptags->pproptag = cu_alloc<uint32_t>(pproptags1->count);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, pproptags1->pproptag,
				sizeof(uint32_t)*pproptags1->count);
	return TRUE;
}

BOOL exmdb_server::copy_instance_attachments(const char *dir, BOOL b_force,
    uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_result)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance_src = instance_get_instance_c(pdb, src_instance_id);
	if (pinstance_src == nullptr || pinstance_src->type != instance_type::message)
		return FALSE;
	auto srcmsg = static_cast<MESSAGE_CONTENT *>(pinstance_src->pcontent);
	if (srcmsg->children.pattachments == nullptr) {
		*pb_result = FALSE;
		return TRUE;	
	}
	auto pinstance_dst = instance_get_instance_c(pdb, dst_instance_id);
	if (pinstance_dst == nullptr || pinstance_dst->type != instance_type::message)
		return FALSE;
	auto dstmsg = static_cast<MESSAGE_CONTENT *>(pinstance_dst->pcontent);
	if (!b_force && dstmsg->children.pattachments != nullptr) {
		*pb_result = FALSE;
		return TRUE;	
	}
	auto pattachments = srcmsg->children.pattachments->dup();
	if (pattachments == nullptr)
		return FALSE;
	if (dstmsg->children.pattachments != nullptr)
		attachment_list_free(dstmsg->children.pattachments);
	dstmsg->children.pattachments = pattachments;
	return TRUE;
}

BOOL exmdb_server::query_message_instance_attachment_table(const char *dir,
    uint32_t instance_id, const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
    int32_t row_needed, TARRAY_SET *pset)
{
	int i;
	int32_t end_pos;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.pattachments ||
		0 == pmsgctnt->children.pattachments->count ||
		start_pos >= pmsgctnt->children.pattachments->count) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	auto msgidnum = pmsgctnt->proplist.get<const uint64_t>(PidTagMid);
	auto pattachments = pmsgctnt->children.pattachments;
	end_pos = start_pos + row_needed;
	pset->count = 0;
	if (row_needed > 0) {
		if (end_pos >= pattachments->count)
			end_pos = pattachments->count - 1;
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - start_pos + 1);
		if (pset->pparray == nullptr)
			return FALSE;
		for (i=start_pos; i<=end_pos; i++) {
			pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
			if (pset->pparray[pset->count] == nullptr)
				return FALSE;
			if (!instance_get_attachment_properties(
			    pinstance->cpid, msgidnum,
			    pattachments->pplist[i], pproptags,
			    pset->pparray[pset->count]))
				return FALSE;
			pset->count ++;
		}
	} else {
		if (end_pos < 0)
			end_pos = 0;
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(start_pos - end_pos + 1);
		if (pset->pparray == nullptr)
			return FALSE;
		for (i=start_pos; i>=end_pos; i--) {
			pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
			if (pset->pparray[pset->count] == nullptr)
				return FALSE;
			if (!instance_get_attachment_properties(
			    pinstance->cpid, msgidnum,
			    pattachments->pplist[i],
			    pproptags, pset->pparray[pset->count]))
				return FALSE;
			pset->count ++;
		}
	}
	return TRUE;
}

BOOL exmdb_server::set_message_instance_conflict(const char *dir,
    uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt)
{
	uint8_t tmp_byte;
	BOOL b_inconflict;
	uint32_t tmp_status;
	MESSAGE_CONTENT msgctnt;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance_c(pdb, instance_id);
	if (pinstance == nullptr || pinstance->type != instance_type::message)
		return FALSE;
	auto pmsg = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	auto num = pmsg->proplist.get<uint32_t>(PR_MSG_STATUS);
	b_inconflict = FALSE;
	if (num != nullptr && *num & MSGSTATUS_IN_CONFLICT)
		b_inconflict = TRUE;
	if (!b_inconflict) {
		if (!instance_read_message(pmsg, &msgctnt))
			return FALSE;
		if (NULL == pmsg->children.pattachments) {
			pattachments = attachment_list_init();
			if (pattachments == nullptr)
				return FALSE;
			pmsg->children.pattachments = pattachments;
		} else {
			pattachments = pmsg->children.pattachments;
		}
		pattachment = attachment_content_init();
		if (pattachment == nullptr)
			return FALSE;
		auto pembedded = msgctnt.dup();
		if (NULL == pembedded) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		pembedded->proplist.erase(PidTagMid);
		pattachment->set_embedded_internal(pembedded);
		if (!pattachments->append_internal(pattachment)) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		tmp_byte = 1;
		if (pattachment->proplist.set(PR_IN_CONFLICT, &tmp_byte) != 0)
			/* ignore; reevaluate another time */;
	} else if (pmsg->children.pattachments == nullptr) {
		pattachments = attachment_list_init();
		if (pattachments == nullptr)
			return FALSE;
		pmsg->children.pattachments = pattachments;
	} else {
		pattachments = pmsg->children.pattachments;
	}
	pattachment = attachment_content_init();
	if (pattachment == nullptr)
		return FALSE;
	auto pembedded = pmsgctnt->dup();
	if (NULL == pembedded) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	pembedded->proplist.erase(PidTagMid);
	pattachment->set_embedded_internal(pembedded);
	if (!pattachments->append_internal(pattachment)) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	tmp_byte = 1;
	if (pattachment->proplist.set(PR_IN_CONFLICT, &tmp_byte) != 0)
		/* ignore; reevaluate */;
	num = pmsg->proplist.get<uint32_t>(PR_MSG_STATUS);
	if (num == nullptr) {
		num = &tmp_status;
		tmp_status = MSGSTATUS_IN_CONFLICT;
	} else {
		*num |= MSGSTATUS_IN_CONFLICT;
	}
	if (pmsg->proplist.set(PR_MSG_STATUS, num) != 0)
		/* ignore; reevaluate */;
	return TRUE;
}
