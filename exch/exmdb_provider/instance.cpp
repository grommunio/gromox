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
#include <sys/stat.h>
#include <gromox/database.h>
#include <gromox/endian.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include "common_util.h"
#include "db_engine.h"
#include "exmdb_server.h"

enum {
	PR_BODY_U = CHANGE_PROP_TYPE(PR_BODY, PT_UNSPECIFIED),
	PR_TRANSPORT_MESSAGE_HEADERS_U = CHANGE_PROP_TYPE(PR_TRANSPORT_MESSAGE_HEADERS, PT_UNSPECIFIED),
	PR_HTML_U = CHANGE_PROP_TYPE(PR_HTML, PT_UNSPECIFIED),
	PR_ATTACH_DATA_BIN_U = CHANGE_PROP_TYPE(PR_ATTACH_DATA_BIN, PT_UNSPECIFIED),
};

#define MAX_RECIPIENT_NUMBER							4096
#define MAX_ATTACHMENT_NUMBER							1024

using UI = unsigned int;
using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

namespace {
struct msg_delete {
	inline void operator()(MESSAGE_CONTENT *msg) const { message_content_free(msg); }
};
}

static BOOL instance_read_message(
	const MESSAGE_CONTENT *pmsgctnt1, MESSAGE_CONTENT *pmsgctnt);

static BOOL instance_identify_message(MESSAGE_CONTENT *pmsgctnt);

static constexpr uint32_t dummy_rcpttype = MAPI_TO;
static constexpr char dummy_addrtype[] = "NONE", dummy_string[] = "";

static BOOL instance_load_message(sqlite3 *psqlite,
	uint64_t message_id, uint32_t *plast_id,
	MESSAGE_CONTENT **ppmsgctnt)
{
	int i;
	uint64_t cid;
	uint32_t row_id;
	uint32_t last_id;
	uint32_t proptag;
	uint64_t rcpt_id;
	TARRAY_SET *prcpts;
	char sql_string[256];
	uint64_t message_id1;
	PROPTAG_ARRAY proptags;
	uint64_t attachment_id;
	MESSAGE_CONTENT *pmsgctnt;
	MESSAGE_CONTENT *pmsgctnt1;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	snprintf(sql_string, arsizeof(sql_string), "SELECT message_id FROM"
	          " messages WHERE message_id=%llu", LLU(message_id));
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		*ppmsgctnt = NULL;
		return TRUE;
	}
	pstmt.finalize();
	pmsgctnt = message_content_init();
	if (NULL == pmsgctnt) {
		return FALSE;
	}
	auto cl_msgctnt = make_scope_exit([&]() { message_content_free(pmsgctnt); });
	if (!cu_get_proptags(db_table::msg_props, message_id,
		psqlite, &proptags)) {
		return FALSE;
	}
	for (i=0; i<proptags.count; i++) {
		switch (proptags.pproptag[i]) {
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
			snprintf(sql_string, arsizeof(sql_string), "SELECT proptag, propval FROM "
				"message_properties WHERE (message_id=%llu AND proptag=%u)"
				" OR (message_id=%llu AND proptag=%u)", LLU(message_id),
				PR_BODY, LLU(message_id), PR_BODY_A);
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW) {
				return FALSE;
			}
			proptag = sqlite3_column_int64(pstmt, 0);
			cid = sqlite3_column_int64(pstmt, 1);
			pstmt.finalize();
			uint32_t tag = proptag == PR_BODY ? ID_TAG_BODY : ID_TAG_BODY_STRING8;
			if (pmsgctnt->proplist.set(tag, &cid) != 0) {
				return FALSE;	
			}
			break;
		}
		case PR_HTML:
		case PR_RTF_COMPRESSED: {
			snprintf(sql_string, arsizeof(sql_string), "SELECT propval FROM "
				"message_properties WHERE message_id=%llu AND "
				"proptag=%u", LLU(message_id), UI(proptags.pproptag[i]));
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW) {
				return FALSE;
			}
			cid = sqlite3_column_int64(pstmt, 0);
			pstmt.finalize();
			uint32_t tag = proptags.pproptag[i] == PR_HTML ?
			               ID_TAG_HTML : ID_TAG_RTFCOMPRESSED;
			if (pmsgctnt->proplist.set(tag, &cid) != 0) {
				return FALSE;
			}
			break;
		}
		case PR_TRANSPORT_MESSAGE_HEADERS:
		case PR_TRANSPORT_MESSAGE_HEADERS_A: {
			snprintf(sql_string, arsizeof(sql_string), "SELECT proptag, propval FROM "
				"message_properties WHERE (message_id=%llu AND proptag=%u)"
				" OR (message_id=%llu AND proptag=%u)", LLU(message_id),
			         PR_TRANSPORT_MESSAGE_HEADERS, LLU(message_id),
			         PR_TRANSPORT_MESSAGE_HEADERS_A);
			pstmt = gx_sql_prep(psqlite, sql_string);
			if (pstmt == nullptr || sqlite3_step(pstmt) != SQLITE_ROW) {
				return FALSE;
			}
			proptag = sqlite3_column_int64(pstmt, 0);
			cid = sqlite3_column_int64(pstmt, 1);
			pstmt.finalize();
			uint32_t tag = proptag == PR_TRANSPORT_MESSAGE_HEADERS ?
			               ID_TAG_TRANSPORTMESSAGEHEADERS :
			               ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8;
			if (pmsgctnt->proplist.set(tag, &cid) != 0) {
				return FALSE;	
			}
			break;
		}
		default: {
			void *newval = nullptr;
			if (!cu_get_property(db_table::msg_props,
			    message_id, 0, psqlite, proptags.pproptag[i], &newval) ||
			    newval == nullptr ||
			    pmsgctnt->proplist.set(proptags.pproptag[i], newval) != 0) {
				return FALSE;
			}
			break;
		}
		}
	}
	prcpts = tarray_set_init();
	if (NULL == prcpts) {
		return FALSE;
	}
	message_content_set_rcpts_internal(pmsgctnt, prcpts);
	snprintf(sql_string, arsizeof(sql_string), "SELECT recipient_id FROM"
	          " recipients WHERE message_id=%llu", LLU(message_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	auto pstmt1 = gx_sql_prep(psqlite, "SELECT proptag FROM"
	              " recipients_properties WHERE recipient_id=?");
	if (pstmt1 == nullptr) {
		return FALSE;
	}
	row_id = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		auto pproplist = prcpts->emplace();
		if (NULL == pproplist) {
			return FALSE;
		}
		if (pproplist->set(PR_ROWID, &row_id) != 0) {
			return FALSE;	
		}
		row_id ++;
		rcpt_id = sqlite3_column_int64(pstmt, 0);
		sqlite3_bind_int64(pstmt1, 1, rcpt_id);
		while (SQLITE_ROW == sqlite3_step(pstmt1)) {
			uint32_t tag = sqlite3_column_int64(pstmt1, 0);
			void *newval = nullptr;
			if (!cu_get_property(db_table::rcpt_props,
			    rcpt_id, 0, psqlite, tag, &newval) ||
			    newval == nullptr ||
			    pproplist->set(tag, newval) != 0) {
				return FALSE;
			}
		}
		sqlite3_reset(pstmt1);
		if (!pproplist->has(PR_RECIPIENT_TYPE))
			pproplist->set(PR_RECIPIENT_TYPE, &dummy_rcpttype);
		if (!pproplist->has(PR_DISPLAY_NAME))
			pproplist->set(PR_DISPLAY_NAME, dummy_string);
		if (!pproplist->has(PR_ADDRTYPE))
			pproplist->set(PR_ADDRTYPE, &dummy_addrtype);
		if (!pproplist->has(PR_EMAIL_ADDRESS))
			pproplist->set(PR_EMAIL_ADDRESS, dummy_string);
	}
	pstmt.finalize();
	pstmt1.finalize();
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		return FALSE;
	}
	message_content_set_attachments_internal(pmsgctnt, pattachments);
	snprintf(sql_string, arsizeof(sql_string), "SELECT attachment_id FROM "
	          "attachments WHERE message_id=%llu", LLU(message_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr) {
		return FALSE;
	}
	pstmt1 = gx_sql_prep(psqlite, "SELECT message_id"
	         " FROM messages WHERE parent_attid=?");
	if (pstmt1 == nullptr) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		pattachment = attachment_content_init();
		if (NULL == pattachment) {
			return FALSE;
		}
		if (!attachment_list_append_internal(pattachments, pattachment)) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		if (pattachment->proplist.set(PR_ATTACH_NUM, plast_id) != 0) {
			return FALSE;	
		}
		(*plast_id) ++;
		attachment_id = sqlite3_column_int64(pstmt, 0);
		if (!cu_get_proptags(db_table::atx_props,
			attachment_id, psqlite, &proptags)) {
			return FALSE;
		}
		for (i=0; i<proptags.count; i++) {
			switch (proptags.pproptag[i]) {
			case PR_ATTACH_DATA_BIN:
			case PR_ATTACH_DATA_OBJ: {
				snprintf(sql_string, arsizeof(sql_string), "SELECT propval FROM "
					"attachment_properties WHERE attachment_id=%llu AND"
					" proptag=%u", static_cast<unsigned long long>(attachment_id),
					static_cast<unsigned int>(proptags.pproptag[i]));
				auto pstmt2 = gx_sql_prep(psqlite, sql_string);
				if (pstmt2 == nullptr || sqlite3_step(pstmt2) != SQLITE_ROW) {
					return FALSE;
				}
				cid = sqlite3_column_int64(pstmt2, 0);
				pstmt2.finalize();
				uint32_t tag = proptags.pproptag[i] == PR_ATTACH_DATA_BIN ?
				               ID_TAG_ATTACHDATABINARY : ID_TAG_ATTACHDATAOBJECT;
				if (pattachment->proplist.set(tag, &cid) != 0) {
					return FALSE;
				}
				break;
			}
			default: {
				void *newval = nullptr;
				if (!cu_get_property(db_table::atx_props,
				    attachment_id, 0, psqlite, proptags.pproptag[i], &newval) ||
				    newval == nullptr ||
				    pattachment->proplist.set(proptags.pproptag[i], newval) != 0) {
					return FALSE;
				}
				break;
			}
			}
		}
		sqlite3_bind_int64(pstmt1, 1, attachment_id);
		if (SQLITE_ROW == sqlite3_step(pstmt1)) {
			message_id1 = sqlite3_column_int64(pstmt1, 0);
			last_id = 0;
			if (!instance_load_message(psqlite, message_id1,
			    &last_id, &pmsgctnt1))
				return FALSE;
			attachment_content_set_embedded_internal(pattachment, pmsgctnt1);
		}
		sqlite3_reset(pstmt1);
	}
	*ppmsgctnt = pmsgctnt;
	cl_msgctnt.release();
	return TRUE;
}

BOOL exmdb_server_load_message_instance(const char *dir,
	const char *username, uint32_t cpid, BOOL b_new,
	uint64_t folder_id, uint64_t message_id,
	uint32_t *pinstance_id)
{
	uint64_t mid_val;
	uint32_t tmp_int32;
	DOUBLE_LIST_NODE *pnode;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	pnode = double_list_get_tail(&pdb->instance_list);
	uint32_t instance_id = pnode == nullptr ? 0 :
	                       static_cast<INSTANCE_NODE *>(pnode->pdata)->instance_id;
	instance_id ++;
	auto pinstance = me_alloc<INSTANCE_NODE>();
	if (NULL == pinstance) {
		return FALSE;
	}
	memset(pinstance, 0, sizeof(INSTANCE_NODE));
	pinstance->node.pdata = pinstance;
	pinstance->instance_id = instance_id;
	pinstance->folder_id = rop_util_get_gc_value(folder_id);
	pinstance->cpid = cpid;
	mid_val = rop_util_get_gc_value(message_id);
	pinstance->type = INSTANCE_TYPE_MESSAGE;
	if (!exmdb_server_check_private()) {
		pinstance->username = strdup(username);
		if (NULL == pinstance->username) {
			free(pinstance);
			return FALSE;
		}
	}
	if (b_new) {
		/* message_id MUST NOT exist in messages table */
		pinstance->b_new = TRUE;
		pinstance->pcontent = message_content_init();
		if (NULL == pinstance->pcontent) {
			if (NULL != pinstance->username) {
				free(pinstance->username);
			}
			free(pinstance);
			return FALSE;
		}
		auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
		if (ict->proplist.set(PidTagMid, &message_id) != 0) {
			message_content_free(ict);
			if (NULL != pinstance->username) {
				free(pinstance->username);
			}
			free(pinstance);
			return FALSE;
		}
		tmp_int32 = 0;
		if (ict->proplist.set(PROP_TAG_MESSAGESTATUS, &tmp_int32) != 0) {
			message_content_free(ict);
			if (pinstance->username != nullptr)
				free(pinstance->username);
			free(pinstance);
			return false;
		}
		double_list_append_as_tail(&pdb->instance_list, &pinstance->node);
		*pinstance_id = instance_id;
		return TRUE;
	}
	if (!exmdb_server_check_private())
		exmdb_server_set_public_username(username);
	auto sql_transact = gx_sql_begin_trans(pdb->psqlite);
	if (!common_util_begin_message_optimize(pdb->psqlite))
		return FALSE;
	if (!instance_load_message(pdb->psqlite, mid_val, &pinstance->last_id,
	    reinterpret_cast<MESSAGE_CONTENT **>(&pinstance->pcontent))) {
		common_util_end_message_optimize();
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		free(pinstance);
		return FALSE;
	}
	common_util_end_message_optimize();
	sql_transact.commit();
	if (NULL == pinstance->pcontent) {
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		free(pinstance);
		*pinstance_id = 0;
		return TRUE;
	}
	pinstance->b_new = FALSE;
	double_list_append_as_tail(&pdb->instance_list, &pinstance->node);
	*pinstance_id = instance_id;
	return TRUE;
}

static INSTANCE_NODE* instance_get_instance(db_item_ptr &pdb, uint32_t instance_id)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pdb->instance_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->instance_list, pnode)) {
		if (((INSTANCE_NODE*)pnode->pdata)->instance_id == instance_id) {
			return static_cast<INSTANCE_NODE *>(pnode->pdata);
		}
	}
	return NULL;
}

BOOL exmdb_server_load_embedded_instance(const char *dir,
	BOOL b_new, uint32_t attachment_instance_id,
	uint32_t *pinstance_id)
{
	uint64_t mid_val;
	uint64_t message_id;
	DOUBLE_LIST_NODE *pnode;
	INSTANCE_NODE *pinstance;
	INSTANCE_NODE *pinstance1;
	MESSAGE_CONTENT *pmsgctnt;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	pnode = double_list_get_tail(&pdb->instance_list);
	uint32_t instance_id = pnode == nullptr ? 0 :
	                       static_cast<INSTANCE_NODE *>(pnode->pdata)->instance_id;
	instance_id ++;
	pinstance1 = instance_get_instance(pdb, attachment_instance_id);
	if (NULL == pinstance1 || INSTANCE_TYPE_ATTACHMENT != pinstance1->type) {
		return FALSE;
	}
	pmsgctnt = ((ATTACHMENT_CONTENT*)pinstance1->pcontent)->pembedded;
	if (NULL == pmsgctnt) {
		if (!b_new) {
			*pinstance_id = 0;
			return TRUE;
		}
		if (!common_util_allocate_eid(pdb->psqlite, &mid_val))
			return FALSE;
		message_id = rop_util_make_eid_ex(1, mid_val);
		pinstance = me_alloc<INSTANCE_NODE>();
		if (NULL == pinstance) {
			return FALSE;
		}
		memset(pinstance, 0, sizeof(INSTANCE_NODE));
		pinstance->node.pdata = pinstance;
		pinstance->instance_id = instance_id;
		pinstance->parent_id = attachment_instance_id;
		pinstance->cpid = pinstance1->cpid;
		if (NULL != pinstance1->username) {
			pinstance->username = strdup(pinstance1->username);
			if (NULL == pinstance->username) {
				free(pinstance);
				return FALSE;
			}
		}
		pinstance->type = INSTANCE_TYPE_MESSAGE;
		pinstance->b_new = TRUE;
		pinstance->pcontent = message_content_init();
		if (NULL == pinstance->pcontent) {
			if (NULL != pinstance->username) {
				free(pinstance->username);
			}
			free(pinstance);
			return FALSE;
		}
		auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
		if (ict->proplist.set(PidTagMid, &message_id) != 0) {
			message_content_free(ict);
			if (NULL != pinstance->username) {
				free(pinstance->username);
			}
			free(pinstance);
			return FALSE;
		}
		double_list_append_as_tail(&pdb->instance_list, &pinstance->node);
		*pinstance_id = instance_id;
		return TRUE;
	}
	if (b_new) {
		*pinstance_id = 0;
		return TRUE;
	}
	pinstance = me_alloc<INSTANCE_NODE>();
	if (NULL == pinstance) {
		return FALSE;
	}
	memset(pinstance, 0, sizeof(INSTANCE_NODE));
	pinstance->node.pdata = pinstance;
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
	if (NULL != pinstance1->username) {
		pinstance->username = strdup(pinstance1->username);
		if (NULL == pinstance->username) {
			free(pinstance);
			return FALSE;
		}
	}
	pinstance->type = INSTANCE_TYPE_MESSAGE;
	pinstance->b_new = FALSE;
	pinstance->pcontent = message_content_dup(pmsgctnt);
	if (NULL == pinstance->pcontent) {
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		free(pinstance);
		return FALSE;
	}
	double_list_append_as_tail(&pdb->instance_list, &pinstance->node);
	*pinstance_id = instance_id;
	return TRUE;
}

/* get PidTagChangeNumber from embedded message */
BOOL exmdb_server_get_embedded_cn(const char *dir, uint32_t instance_id,
    uint64_t **ppcn)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	*ppcn = pinstance->parent_id == 0 ? nullptr :
	        ict->proplist.get<uint64_t>(PidTagChangeNumber);
	return TRUE;
}

/* if instance does not exist, do not reload the instance */
BOOL exmdb_server_reload_message_instance(
	const char *dir, uint32_t instance_id, BOOL *pb_result)
{
	uint32_t last_id;
	MESSAGE_CONTENT *pmsgctnt;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	if (pinstance->b_new) {
		*pb_result = FALSE;
		return TRUE;
	}
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (0 == pinstance->parent_id) {
		auto pvalue = ict->proplist.getval(PidTagMid);
		if (NULL == pvalue) {
			return FALSE;
		}
		last_id = 0;
		if (!instance_load_message(pdb->psqlite,
		    *static_cast<uint64_t *>(pvalue), &last_id, &pmsgctnt))
			return FALSE;	
		if (NULL == pmsgctnt) {
			*pb_result = FALSE;
			return TRUE;
		}
		if (pinstance->last_id < last_id) {
			pinstance->last_id = last_id;
		}
	} else {
		auto pinstance1 = instance_get_instance(pdb, pinstance->parent_id);
		if (NULL == pinstance1 || INSTANCE_TYPE_ATTACHMENT
			!= pinstance1->type) {
			return FALSE;
		}
		if (NULL == ((ATTACHMENT_CONTENT*)
			pinstance1->pcontent)->pembedded) {
			*pb_result = FALSE;
			return TRUE;	
		}
		pmsgctnt = message_content_dup(((ATTACHMENT_CONTENT*)
							pinstance1->pcontent)->pembedded);
		if (NULL == pmsgctnt) {
			return FALSE;
		}
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

BOOL exmdb_server_clear_message_instance(
	const char *dir, uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	auto pvalue = ict->proplist.getval(PidTagMid);
	if (NULL == pvalue) {
		return FALSE;
	}
	auto pmsgctnt = message_content_init();
	if (NULL == pmsgctnt) {
		return FALSE;
	}
	if (pmsgctnt->proplist.set(PidTagMid, pvalue) != 0) {
		message_content_free(pmsgctnt);
		return FALSE;
	}
	message_content_free(ict);
	pinstance->pcontent = pmsgctnt;
	return TRUE;
}

static void *fake_read_cid(unsigned int mode, uint32_t tag, uint64_t cid, uint32_t *outlen) try
{
	static constexpr size_t bmaxsize = 256;
	auto buf = cu_alloc<char>(bmaxsize);
	if (buf == nullptr)
		return nullptr;
	buf[0] = '\0';

	if (tag == ID_TAG_HTML)
		strcpy(buf, "<html><body><p><tt>");
	else if (tag == ID_TAG_RTFCOMPRESSED)
		strcpy(buf, "\\rtf1\\ansi{\\fonttbl\\f0\\fswiss Helvetica;}\\f0\\pard\n");
	else if (tag == ID_TAG_BODY)
		strcpy(buf, "XXXX");
	if (tag != 0)
		snprintf(buf + strlen(buf), bmaxsize - strlen(buf),
		         mode <= 1 ? "[CID=%llu Tag=%xh] Property/Attachment absent" :
		         "[CID=%llu Tag=%xh] Filler text for debugging",
		         LLU(cid), tag);
	if (tag == ID_TAG_HTML)
		snprintf(buf + strlen(buf), bmaxsize - strlen(buf),
		         "</tt></p></body></html>");
	else if (tag == ID_TAG_RTFCOMPRESSED)
		snprintf(buf + strlen(buf), bmaxsize - strlen(buf), "\\par\n}");

	if (outlen != nullptr) {
		*outlen = strlen(buf);
		if (tag == ID_TAG_BODY)
			cpu_to_le32p(buf, *outlen - 4);
	}
	return buf;
} catch (const std::bad_alloc &) {
	return nullptr;
}

void *instance_read_cid_content(uint64_t cid, uint32_t *plen, uint32_t tag)
{
	struct stat node_stat;
	std::string path;

	try {
		if (g_dbg_synth_content == 2)
			return fake_read_cid(g_dbg_synth_content, tag, cid, plen);
		path = exmdb_server_get_dir() + "/cid/"s + std::to_string(cid);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1588: ENOMEM\n");
		return nullptr;
	}
	wrapfd fd = open(path.c_str(), O_RDONLY);
	if (fd.get() < 0) {
		if (g_dbg_synth_content)
			return fake_read_cid(g_dbg_synth_content, tag, cid, plen);
		fprintf(stderr, "E-1587: %s: %s\n", path.c_str(), strerror(errno));
		return nullptr;
	}
	if (fstat(fd.get(), &node_stat) != 0) {
		return NULL;
	}
	auto pbuff = cu_alloc<char>(node_stat.st_size);
	if (pbuff == nullptr ||
	    read(fd.get(), pbuff, node_stat.st_size) != node_stat.st_size)
		return NULL;
	if (NULL != plen) {
		*plen = node_stat.st_size;
	}
	return pbuff;
}

static BOOL instance_read_attachment(
	const ATTACHMENT_CONTENT *pattachment1,
	ATTACHMENT_CONTENT *pattachment)
{
	int i;
	uint64_t cid;
	
	if (pattachment1->proplist.count > 1) {
		pattachment->proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(pattachment1->proplist.count);
		if (NULL == pattachment->proplist.ppropval) {
			return FALSE;
		}
	} else {
		pattachment->proplist.count = 0;
		pattachment->proplist.ppropval = NULL;
		return TRUE;
	}
	pattachment->proplist.count = 0;
	for (i=0; i<pattachment1->proplist.count; i++) {
		switch (pattachment1->proplist.ppropval[i].proptag) {
		case ID_TAG_ATTACHDATABINARY:
		case ID_TAG_ATTACHDATAOBJECT: {
			auto pbin = cu_alloc<BINARY>();
			if (NULL == pbin) {
				return FALSE;
			}
			cid = *(uint64_t*)pattachment1->proplist.ppropval[i].pvalue;
			pbin->pv = instance_read_cid_content(cid, &pbin->cb, 0);
			if (pbin->pv == nullptr)
				return FALSE;
			if (ID_TAG_ATTACHDATABINARY ==
				pattachment1->proplist.ppropval[i].proptag) {
				pattachment->proplist.ppropval[pattachment->proplist.count].proptag = PR_ATTACH_DATA_BIN;
			} else {
				pattachment->proplist.ppropval[pattachment->proplist.count].proptag = PR_ATTACH_DATA_OBJ;
			}
			pattachment->proplist.ppropval[pattachment->proplist.count++].pvalue = pbin;
			break;
		}
		default:
			pattachment->proplist.ppropval[pattachment->proplist.count++] =
				pattachment1->proplist.ppropval[i];
			break;
		}
	}
	if (NULL != pattachment1->pembedded) {
		pattachment->pembedded = cu_alloc<MESSAGE_CONTENT>();
		if (NULL == pattachment->pembedded) {
			return FALSE;
		}
		return instance_read_message(
				pattachment1->pembedded,
				pattachment->pembedded);
	} else {
		pattachment->pembedded = NULL;
	}
	return TRUE;
}

static BOOL instance_read_message(
	const MESSAGE_CONTENT *pmsgctnt1,
	MESSAGE_CONTENT *pmsgctnt)
{
	void *pbuff;
	uint64_t cid;
	uint32_t length;
	const char *psubject_prefix;
	TPROPVAL_ARRAY *pproplist1;
	ATTACHMENT_CONTENT *pattachment1;
	
	pmsgctnt->proplist.count = pmsgctnt1->proplist.count;
	if (0 != pmsgctnt1->proplist.count) {
		pmsgctnt->proplist.ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt1->proplist.count + 1);
		if (NULL == pmsgctnt->proplist.ppropval) {
			return FALSE;
		}
	} else {
		pmsgctnt->proplist.ppropval = NULL;
	}
	size_t i;
	for (i=0; i<pmsgctnt1->proplist.count; i++) {
		switch (pmsgctnt1->proplist.ppropval[i].proptag) {
		case ID_TAG_BODY:
			cid = *(uint64_t*)pmsgctnt1->proplist.ppropval[i].pvalue;
			pbuff = instance_read_cid_content(cid, nullptr, ID_TAG_BODY);
			if (NULL == pbuff) {
				return FALSE;
			}
			pmsgctnt->proplist.ppropval[i].proptag = PR_BODY;
			pmsgctnt->proplist.ppropval[i].pvalue = static_cast<char *>(pbuff) + sizeof(uint32_t);
			break;
		case ID_TAG_BODY_STRING8:
			cid = *(uint64_t*)pmsgctnt1->proplist.ppropval[i].pvalue;
			pbuff = instance_read_cid_content(cid, nullptr, 0);
			if (NULL == pbuff) {
				return FALSE;
			}
			pmsgctnt->proplist.ppropval[i].proptag = PR_BODY_A;
			pmsgctnt->proplist.ppropval[i].pvalue = pbuff;
			break;
		case ID_TAG_HTML:
		case ID_TAG_RTFCOMPRESSED: {
			cid = *(uint64_t*)pmsgctnt1->proplist.ppropval[i].pvalue;
			pbuff = instance_read_cid_content(cid, &length, pmsgctnt1->proplist.ppropval[i].proptag);
			if (NULL == pbuff) {
				return FALSE;
			}
			pmsgctnt->proplist.ppropval[i].proptag =
				pmsgctnt1->proplist.ppropval[i].proptag == ID_TAG_HTML ?
				PR_HTML : PR_RTF_COMPRESSED;
			auto pbin = cu_alloc<BINARY>();
			if (NULL == pbin) {
				return FALSE;
			}
			pbin->cb = length;
			pbin->pv = pbuff;
			pmsgctnt->proplist.ppropval[i].pvalue = pbin;
			break;
		}
		case ID_TAG_TRANSPORTMESSAGEHEADERS:
			cid = *(uint64_t*)pmsgctnt1->proplist.ppropval[i].pvalue;
			pbuff = instance_read_cid_content(cid, nullptr, ID_TAG_BODY);
			if (NULL == pbuff) {
				return FALSE;
			}
			pmsgctnt->proplist.ppropval[i].proptag = PR_TRANSPORT_MESSAGE_HEADERS;
			pmsgctnt->proplist.ppropval[i].pvalue = static_cast<char *>(pbuff) + sizeof(uint32_t);
			break;
		case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
			cid = *(uint64_t*)pmsgctnt1->proplist.ppropval[i].pvalue;
			pbuff = instance_read_cid_content(cid, nullptr, 0);
			if (NULL == pbuff) {
				return FALSE;
			}
			pmsgctnt->proplist.ppropval[i].proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
			pmsgctnt->proplist.ppropval[i].pvalue = pbuff;
			break;
		default:
			pmsgctnt->proplist.ppropval[i] = pmsgctnt1->proplist.ppropval[i];
			break;
		}
	}
	auto wtf = reinterpret_cast<const TPROPVAL_ARRAY *>(pmsgctnt1);
	auto pnormalized_subject = wtf->get<char>(PR_NORMALIZED_SUBJECT);
	if (NULL == pnormalized_subject) {
		pnormalized_subject = wtf->get<char>(PR_NORMALIZED_SUBJECT_A);
		if (NULL != pnormalized_subject) {
			psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX_A);
			if (NULL == psubject_prefix) {
				psubject_prefix = "";
			}
			length = strlen(pnormalized_subject)
					+ strlen(psubject_prefix) + 1;
			pmsgctnt->proplist.ppropval[i].proptag = PR_SUBJECT_A;
			pmsgctnt->proplist.ppropval[i].pvalue =
						common_util_alloc(length);
			if (NULL == pmsgctnt->proplist.ppropval[i].pvalue) {
				return FALSE;
			}
			sprintf(static_cast<char *>(pmsgctnt->proplist.ppropval[i].pvalue),
				"%s%s", psubject_prefix, pnormalized_subject);
			pmsgctnt->proplist.count ++;
		} else {
			psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX);
			if (NULL == psubject_prefix) {
				psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX_A);
				if (NULL != psubject_prefix) {
					pmsgctnt->proplist.ppropval[i].proptag = PR_SUBJECT_A;
					pmsgctnt->proplist.ppropval[i].pvalue =
						deconst(psubject_prefix);
					pmsgctnt->proplist.count ++;
				}
			} else {
				pmsgctnt->proplist.ppropval[i].proptag = PR_SUBJECT;
				pmsgctnt->proplist.ppropval[i].pvalue =
					deconst(psubject_prefix);
				pmsgctnt->proplist.count ++;
			}
		}
	} else {
		psubject_prefix = wtf->get<char>(PR_SUBJECT_PREFIX);
		if (NULL == psubject_prefix) {
			psubject_prefix = "";
		}
		length = strlen(pnormalized_subject)
					+ strlen(psubject_prefix) + 1;
		pmsgctnt->proplist.ppropval[i].proptag = PR_SUBJECT;
		pmsgctnt->proplist.ppropval[i].pvalue =
					common_util_alloc(length);
		if (NULL == pmsgctnt->proplist.ppropval[i].pvalue) {
			return FALSE;
		}
		sprintf(static_cast<char *>(pmsgctnt->proplist.ppropval[i].pvalue),
			"%s%s", psubject_prefix, pnormalized_subject);
		pmsgctnt->proplist.count ++;
	}
	if (NULL == pmsgctnt1->children.prcpts) {
		pmsgctnt->children.prcpts = NULL;
	} else {
		pmsgctnt->children.prcpts = cu_alloc<TARRAY_SET>();
		if (NULL == pmsgctnt->children.prcpts) {
			return FALSE;
		}
		pmsgctnt->children.prcpts->count =
			pmsgctnt1->children.prcpts->count;
		if (0 != pmsgctnt1->children.prcpts->count) {
			pmsgctnt->children.prcpts->pparray = cu_alloc<TPROPVAL_ARRAY *>(pmsgctnt1->children.prcpts->count);
			if (NULL == pmsgctnt->children.prcpts->pparray) {
				return FALSE;
			}
		} else {
			pmsgctnt->children.prcpts->pparray = NULL;
		}
		for (i=0; i<pmsgctnt1->children.prcpts->count; i++) {
			auto pproplist = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == pproplist) {
				return FALSE;
			}
			pmsgctnt->children.prcpts->pparray[i] = pproplist;
			pproplist1 = pmsgctnt1->children.prcpts->pparray[i];
			if (pproplist1->count > 1) {
				pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(pproplist1->count);
				if (NULL == pproplist->ppropval) {
					return FALSE;
				}
			} else {
				pproplist->count = 0;
				pproplist->ppropval = NULL;
				continue;
			}
			pproplist->count = 0;
			for (size_t j = 0; j < pproplist1->count; ++j) {
				pproplist->ppropval[pproplist->count++] = pproplist1->ppropval[j];
			}
		}
	}
	if (NULL == pmsgctnt1->children.pattachments) {
		pmsgctnt->children.pattachments = NULL;
	} else {
		pmsgctnt->children.pattachments = cu_alloc<ATTACHMENT_LIST>();
		if (NULL == pmsgctnt->children.pattachments) {
			return FALSE;
		}
		pmsgctnt->children.pattachments->count =
			pmsgctnt1->children.pattachments->count;
		if (0 != pmsgctnt1->children.pattachments->count) {
			pmsgctnt->children.pattachments->pplist = cu_alloc<ATTACHMENT_CONTENT *>(pmsgctnt1->children.pattachments->count);
			if (NULL == pmsgctnt->children.pattachments->pplist) {
				return FALSE;
			}
		} else {
			pmsgctnt->children.pattachments->pplist = NULL;
		}
		for (i=0; i<pmsgctnt1->children.pattachments->count; i++) {
			auto pattachment = cu_alloc<ATTACHMENT_CONTENT>();
			if (NULL == pattachment) {
				return FALSE;
			}
			memset(pattachment, 0 ,sizeof(ATTACHMENT_CONTENT));
			pmsgctnt->children.pattachments->pplist[i] = pattachment;
			pattachment1 = pmsgctnt1->children.pattachments->pplist[i];
			if (!instance_read_attachment(pattachment1, pattachment))
				return FALSE;	
		}
	}
	return TRUE;
}

BOOL exmdb_server_read_message_instance(const char *dir,
	uint32_t instance_id, MESSAGE_CONTENT *pmsgctnt)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	memset(pmsgctnt, 0, sizeof(MESSAGE_CONTENT));
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	return instance_read_message(static_cast<MESSAGE_CONTENT *>(pinstance->pcontent), pmsgctnt);
}

static BOOL instance_identify_rcpts(TARRAY_SET *prcpts)
{
	uint32_t i;
	
	for (i=0; i<prcpts->count; i++) {
		if (prcpts->pparray[i]->set(PR_ROWID, &i) != 0)
			return FALSE;
	}
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
BOOL exmdb_server_write_message_instance(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt,
	BOOL b_force, PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems)
{
	int i;
	uint32_t proptag;
	TARRAY_SET *prcpts;
	ATTACHMENT_LIST *pattachments;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pmsgctnt->proplist.count + 2);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	pproptags->count = 0;
	pproptags->pproptag = cu_alloc<uint32_t>(pmsgctnt->proplist.count + 2);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
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
		case PROP_TAG_CODEPAGEID:
		case PidTagParentFolderId:
		case PROP_TAG_INSTANCESVREID:
		case PROP_TAG_HASNAMEDPROPERTIES:
		case PR_MESSAGE_SIZE:
		case PR_HASATTACH:
		case PR_DISPLAY_TO:
		case PR_DISPLAY_CC:
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_TO_A:
		case PR_DISPLAY_CC_A:
		case PR_DISPLAY_BCC_A:
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag = proptag;
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
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
		pproptags->pproptag[pproptags->count++] = proptag;
	}
	if (NULL != pmsgctnt->children.prcpts) {
		if (b_force || ict->children.prcpts == nullptr) {
			prcpts = pmsgctnt->children.prcpts->dup();
			if (NULL == prcpts) {
				return FALSE;
			}
			if (!instance_identify_rcpts(prcpts)) {
				tarray_set_free(prcpts);
				return FALSE;
			}
			message_content_set_rcpts_internal(ict, prcpts);
			pproptags->pproptag[pproptags->count++] = PR_MESSAGE_RECIPIENTS;
		}
	}
	if (NULL != pmsgctnt->children.pattachments) {
		if (b_force || ict->children.pattachments == nullptr) {
			pattachments = attachment_list_dup(
				pmsgctnt->children.pattachments);
			if (NULL == pattachments) {
				return FALSE;
			}
			if (!instance_identify_attachments(pattachments)) {
				attachment_list_free(pattachments);
				return FALSE;
			}
			message_content_set_attachments_internal(ict, pattachments);
			pproptags->pproptag[pproptags->count++] = PR_MESSAGE_ATTACHMENTS;
		}
	}
	return TRUE;
}

BOOL exmdb_server_load_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t attachment_num,
	uint32_t *pinstance_id)
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	ATTACHMENT_CONTENT *pattachment = nullptr;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	pnode = double_list_get_tail(&pdb->instance_list);
	uint32_t instance_id = pnode == nullptr ? 0 :
	                       static_cast<INSTANCE_NODE *>(pnode->pdata)->instance_id;
	instance_id ++;
	auto pinstance1 = instance_get_instance(pdb, message_instance_id);
	if (NULL == pinstance1 || INSTANCE_TYPE_MESSAGE != pinstance1->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent);
	if (NULL == pmsgctnt->children.pattachments) {
		*pinstance_id = 0;
		return TRUE;
	}
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		pattachment = pmsgctnt->children.pattachments->pplist[i];
		auto pvalue = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (*pvalue == attachment_num)
			break;
	}
	if (i >= pmsgctnt->children.pattachments->count) {
		*pinstance_id = 0;
		return TRUE;
	}
	auto pinstance = me_alloc<INSTANCE_NODE>();
	if (NULL == pinstance) {
		return FALSE;
	}
	memset(pinstance, 0, sizeof(INSTANCE_NODE));
	pinstance->node.pdata = pinstance;
	pinstance->instance_id = instance_id;
	pinstance->parent_id = message_instance_id;
	pinstance->cpid = pinstance1->cpid;
	if (NULL != pinstance1->username) {
		pinstance->username = strdup(pinstance1->username);
		if (NULL == pinstance->username) {
			free(pinstance);
			return FALSE;
		}
	}
	pinstance->type = INSTANCE_TYPE_ATTACHMENT;
	pinstance->b_new = FALSE;
	pinstance->pcontent = attachment_content_dup(pattachment);
	if (NULL == pinstance->pcontent) {
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		free(pinstance);
		return FALSE;
	}
	double_list_append_as_tail(&pdb->instance_list, &pinstance->node);
	*pinstance_id = instance_id;
	return TRUE;
}

BOOL exmdb_server_create_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t *pinstance_id,
	uint32_t *pattachment_num)
{
	DOUBLE_LIST_NODE *pnode;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	pnode = double_list_get_tail(&pdb->instance_list);
	uint32_t instance_id = pnode == nullptr ? 0 :
	                       static_cast<INSTANCE_NODE *>(pnode->pdata)->instance_id;
	instance_id ++;
	auto pinstance1 = instance_get_instance(pdb, message_instance_id);
	if (NULL == pinstance1 || INSTANCE_TYPE_MESSAGE != pinstance1->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent);
	if (NULL != pmsgctnt->children.pattachments &&
		pmsgctnt->children.pattachments->count >=
		MAX_ATTACHMENT_NUMBER) {
		*pinstance_id = 0;
		*pattachment_num = ATTACHMENT_NUM_INVALID;
		return TRUE;	
	}
	auto pinstance = me_alloc<INSTANCE_NODE>();
	if (NULL == pinstance) {
		return FALSE;
	}
	memset(pinstance, 0, sizeof(INSTANCE_NODE));
	pinstance->node.pdata = pinstance;
	pinstance->instance_id = instance_id;
	pinstance->parent_id = message_instance_id;
	pinstance->cpid = pinstance1->cpid;
	if (NULL != pinstance1->username) {
		pinstance->username = strdup(pinstance1->username);
		if (NULL == pinstance->username) {
			free(pinstance);
			return FALSE;
		}
	}
	pinstance->type = INSTANCE_TYPE_ATTACHMENT;
	pinstance->b_new = TRUE;
	pattachment = attachment_content_init();
	if (NULL == pattachment) {
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		free(pinstance);
		return FALSE;
	}
	*pattachment_num = pinstance1->last_id++;
	if (pattachment->proplist.set(PR_ATTACH_NUM, pattachment_num) != 0) {
		attachment_content_free(pattachment);
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		free(pinstance);
		return FALSE;
	}
	pinstance->pcontent = pattachment;
	double_list_append_as_tail(&pdb->instance_list, &pinstance->node);
	*pinstance_id = instance_id;
	return TRUE;
}

BOOL exmdb_server_read_attachment_instance(const char *dir,
	uint32_t instance_id, ATTACHMENT_CONTENT *pattctnt)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	memset(pattctnt, 0, sizeof(ATTACHMENT_CONTENT));
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_ATTACHMENT != pinstance->type) {
		return FALSE;
	}
	return instance_read_attachment(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent), pattctnt);
}

BOOL exmdb_server_write_attachment_instance(const char *dir,
	uint32_t instance_id, const ATTACHMENT_CONTENT *pattctnt,
	BOOL b_force, PROBLEM_ARRAY *pproblems)
{
	int i;
	uint32_t proptag;
	TPROPVAL_ARRAY *pproplist;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_ATTACHMENT != pinstance->type) {
		return FALSE;
	}
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pattctnt->proplist.count + 1);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	pproplist = &((ATTACHMENT_CONTENT*)pinstance->pcontent)->proplist;
	for (i=0; i<pattctnt->proplist.count; i++) {
		proptag = pattctnt->proplist.ppropval[i].proptag;
		switch (proptag) {
		case PR_RECORD_KEY:
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag = proptag;
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
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
		pmsgctnt = message_content_dup(pattctnt->pembedded);
		if (NULL == pmsgctnt) {
			return FALSE;
		}
		if (!instance_identify_message(pmsgctnt)) {
			message_content_free(pmsgctnt);
			return FALSE;
		}
		attachment_content_set_embedded_internal(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent), pmsgctnt);
	}
	return TRUE;
}

BOOL exmdb_server_delete_message_instance_attachment(
	const char *dir, uint32_t message_instance_id,
	uint32_t attachment_num)
{
	int i;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, message_instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.pattachments) {
		return TRUE;
	}
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		auto pattachment = pmsgctnt->children.pattachments->pplist[i];
		auto pvalue = pattachment->proplist.get<uint32_t>(PR_ATTACH_NUM);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (*pvalue == attachment_num)
			break;
	}
	if (i >= pmsgctnt->children.pattachments->count) {
		return TRUE;
	}
	attachment_list_remove(pmsgctnt->children.pattachments, i);
	if (0 == pmsgctnt->children.pattachments->count) {
		attachment_list_free(pmsgctnt->children.pattachments);
		pmsgctnt->children.pattachments = NULL;
	}
	return TRUE;
}

/* account must be available when it is a normal message instance */ 
BOOL exmdb_server_flush_instance(const char *dir, uint32_t instance_id,
    const char *account, gxerr_t *pe_result)
{
	int i;
	uint64_t folder_id;
	char tmp_buff[1024];
	char address_type[16];
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance) {
		return FALSE;
	}
	if (INSTANCE_TYPE_ATTACHMENT == pinstance->type) {
		auto pinstance1 = instance_get_instance(pdb, pinstance->parent_id);
		if (NULL == pinstance1 ||
			INSTANCE_TYPE_MESSAGE != pinstance1->type) {
			return FALSE;
		}
		auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent);
		auto pattachment = attachment_content_dup(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent));
		if (NULL == pattachment) {
			return FALSE;
		}
		if (pinstance->b_new) {
			if (NULL == pmsgctnt->children.pattachments) {
				pmsgctnt->children.pattachments = attachment_list_init();
				if (NULL == pmsgctnt->children.pattachments) {
					attachment_content_free(pattachment);
					return FALSE;
				}
			}
			if (!attachment_list_append_internal(pmsgctnt->children.pattachments, pattachment)) {
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
			} else if (!attachment_list_append_internal(pmsgctnt->children.pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return FALSE;
			}
		}
		*pe_result = GXERR_SUCCESS;
		return TRUE;
	}
	auto ict = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if ((pinstance->change_mask & CHANGE_MASK_HTML) &&
		0 == (pinstance->change_mask & CHANGE_MASK_BODY)) {
		auto pbin  = ict->proplist.get<BINARY>(PR_HTML);
		auto pcpid = ict->proplist.get<uint32_t>(PR_INTERNET_CPID);
		if (NULL != pbin && NULL != pcpid) {
			std::string plainbuf;
			auto ret = html_to_plain(pbin->pc, pbin->cb, plainbuf);
			if (ret < 0)
				return false;
			void *pvalue;
			if (ret == 65001 || *pcpid == 65001) {
				pvalue = plainbuf.data();
			} else {
				pvalue = common_util_convert_copy(TRUE, *pcpid, plainbuf.c_str());
				if (pvalue == nullptr)
					return false;
			}
			if (ict->proplist.set(PR_BODY_W, pvalue) != 0)
				return false;
		}
	}
	pinstance->change_mask = 0;
	if (0 != pinstance->parent_id) {
		auto pinstance1 = instance_get_instance(pdb, pinstance->parent_id);
		if (NULL == pinstance1 ||
			INSTANCE_TYPE_ATTACHMENT != pinstance1->type) {
			return FALSE;
		}
		auto pmsgctnt = message_content_dup(ict);
		if (NULL == pmsgctnt) {
			return FALSE;
		}
		attachment_content_set_embedded_internal(static_cast<ATTACHMENT_CONTENT *>(pinstance1->pcontent), pmsgctnt);
		*pe_result = GXERR_SUCCESS;
		return TRUE;
	}
	auto pmsgctnt = message_content_dup(ict);
	if (NULL == pmsgctnt) {
		return FALSE;	
	}
	std::unique_ptr<MESSAGE_CONTENT, msg_delete> upmsgctnt(pmsgctnt);
	auto pbin = pmsgctnt->proplist.get<BINARY>(PR_SENT_REPRESENTING_ENTRYID);
	if (pbin != nullptr &&
	    !pmsgctnt->proplist.has(PR_SENT_REPRESENTING_EMAIL_ADDRESS)) {
		auto pvalue = pmsgctnt->proplist.getval(PR_SENT_REPRESENTING_ADDRTYPE);
		if (NULL == pvalue) {
			if (common_util_parse_addressbook_entryid(pbin,
			    address_type, GX_ARRAY_SIZE(address_type),
			    tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
				if (pmsgctnt->proplist.set(PR_SENT_REPRESENTING_ADDRTYPE, address_type) != 0 ||
				    pmsgctnt->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, tmp_buff) != 0)
					return FALSE;
			}
		} else if (strcasecmp(static_cast<char *>(pvalue), "EX") == 0) {
			if (common_util_addressbook_entryid_to_essdn(pbin,
			    tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		} else if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
			if (common_util_addressbook_entryid_to_username(pbin,
			    tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		}
	}
	pbin = pmsgctnt->proplist.get<BINARY>(PR_SENDER_ENTRYID);
	if (pbin != nullptr && !pmsgctnt->proplist.has(PR_SENDER_EMAIL_ADDRESS)) {
		auto pvalue = pmsgctnt->proplist.getval(PR_SENDER_ADDRTYPE);
		if (NULL == pvalue) {
			if (common_util_parse_addressbook_entryid(pbin,
			    address_type, GX_ARRAY_SIZE(address_type),
			    tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
				if (pmsgctnt->proplist.set(PR_SENDER_ADDRTYPE, address_type) != 0 ||
				    pmsgctnt->proplist.set(PR_SENDER_EMAIL_ADDRESS, tmp_buff) != 0)
					return FALSE;
			}
		} else if (strcasecmp(static_cast<char *>(pvalue), "EX") == 0) {
			if (common_util_addressbook_entryid_to_essdn(pbin,
			    tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENDER_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		} else if (strcasecmp(static_cast<char *>(pvalue), "SMTP") == 0) {
			if (common_util_addressbook_entryid_to_username(pbin,
			    tmp_buff, GX_ARRAY_SIZE(tmp_buff)) &&
			    pmsgctnt->proplist.set(PR_SENDER_EMAIL_ADDRESS, tmp_buff) != 0)
				return FALSE;
		}
	}
	pinstance->b_new = FALSE;
	folder_id = rop_util_make_eid_ex(1, pinstance->folder_id);
	if (!exmdb_server_check_private())
		exmdb_server_set_public_username(pinstance->username);
	pdb.reset();
	common_util_set_tls_var(pmsgctnt);
	BOOL b_result = exmdb_server_write_message(dir, account, 0, folder_id,
	                pmsgctnt, pe_result);
	common_util_set_tls_var(NULL);
	return b_result;
}
	
BOOL exmdb_server_unload_instance(
	const char *dir, uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance) {
		return TRUE;
	}
	double_list_remove(&pdb->instance_list, &pinstance->node);
	if (INSTANCE_TYPE_ATTACHMENT == pinstance->type) {
		attachment_content_free(static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent));
	} else {
		message_content_free(static_cast<MESSAGE_CONTENT *>(pinstance->pcontent));
	}
	if (NULL != pinstance->username) {
		free(pinstance->username);
	}
	free(pinstance);
	return TRUE;
}

BOOL exmdb_server_get_instance_all_proptags(
	const char *dir, uint32_t instance_id,
	PROPTAG_ARRAY *pproptags)
{
	int i;
	MESSAGE_CONTENT *pmsgctnt;
	ATTACHMENT_CONTENT *pattachment = nullptr;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance) {
		return FALSE;
	}
	if (INSTANCE_TYPE_MESSAGE == pinstance->type) {
		pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
		pproptags->count = pmsgctnt->proplist.count + 6;
		if (NULL != pmsgctnt->children.prcpts) {
			pproptags->count ++;
		}
		if (NULL != pmsgctnt->children.pattachments) {
			pproptags->count ++;
		}
		pproptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
		if (NULL == pproptags->pproptag) {
			pproptags->count = 0;
			return FALSE;
		}
		for (i=0; i<pmsgctnt->proplist.count; i++) {
			switch (pmsgctnt->proplist.ppropval[i].proptag) {
			case ID_TAG_BODY:
				pproptags->pproptag[i] = PR_BODY;
				break;
			case ID_TAG_BODY_STRING8:
				pproptags->pproptag[i] = PR_BODY_A;
				break;
			case ID_TAG_HTML:
				pproptags->pproptag[i] = PR_HTML;
				break;
			case ID_TAG_RTFCOMPRESSED:
				pproptags->pproptag[i] = PR_RTF_COMPRESSED;
				break;
			case ID_TAG_TRANSPORTMESSAGEHEADERS:
				pproptags->pproptag[i] = PR_TRANSPORT_MESSAGE_HEADERS;
				break;
			case ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8:
				pproptags->pproptag[i] = PR_TRANSPORT_MESSAGE_HEADERS_A;
				break;
			default:
				pproptags->pproptag[i] =
					pmsgctnt->proplist.ppropval[i].proptag;
				break;
			}
		}
		pproptags->count = pmsgctnt->proplist.count;
		pproptags->pproptag[pproptags->count++] = PROP_TAG_CODEPAGEID;
		pproptags->pproptag[pproptags->count++] = PR_MESSAGE_SIZE;
		pproptags->pproptag[pproptags->count++] = PR_HASATTACH;
		pproptags->pproptag[pproptags->count++] = PR_DISPLAY_TO;
		pproptags->pproptag[pproptags->count++] = PR_DISPLAY_CC;
		pproptags->pproptag[pproptags->count++] = PR_DISPLAY_BCC;
	} else {
		pattachment = static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent);
		pproptags->count = pattachment->proplist.count + 1;
		if (NULL != pattachment->pembedded) {
			pproptags->count ++;
		}
		pproptags->pproptag = cu_alloc<uint32_t>(pproptags->count);
		if (NULL == pproptags->pproptag) {
			pproptags->count = 0;
			return FALSE;
		}
		for (i=0; i<pattachment->proplist.count; i++) {
			switch (pattachment->proplist.ppropval[i].proptag) {
			case ID_TAG_ATTACHDATABINARY:
				pproptags->pproptag[i] = PR_ATTACH_DATA_BIN;
				break;
			case ID_TAG_ATTACHDATAOBJECT:
				pproptags->pproptag[i] = PR_ATTACH_DATA_OBJ;
				break;
			default:
				pproptags->pproptag[i] =
					pattachment->proplist.ppropval[i].proptag;
				break;
			}
		}
		pproptags->count = pattachment->proplist.count;
		pproptags->pproptag[pproptags->count++] = PR_ATTACH_SIZE;
	}
	return TRUE;
}

static BOOL instance_get_message_display_recipients(
	TARRAY_SET *prcpts, uint32_t cpid, uint32_t proptag,
	void **ppvalue)
{
	char tmp_buff[64*1024];
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
	size_t offset = 0;
	for (size_t i = 0; i < prcpts->count; ++i) {
		auto pvalue = prcpts->pparray[i]->getval(PR_RECIPIENT_TYPE);
		if (NULL == pvalue || *(uint32_t*)pvalue != recipient_type) {
			continue;
		}
		pvalue = prcpts->pparray[i]->getval(PR_DISPLAY_NAME);
		if (NULL == pvalue) {
			pvalue = prcpts->pparray[i]->getval(PR_DISPLAY_NAME_A);
			if (NULL != pvalue) {
				pvalue = static_cast<char *>(common_util_convert_copy(TRUE, cpid, static_cast<char *>(pvalue)));
			}
		}
		if (NULL == pvalue) {
			pvalue = prcpts->pparray[i]->getval(PR_SMTP_ADDRESS);
		}
		if (NULL == pvalue) {
			continue;
		}
		if (0 == offset) {
			offset = gx_snprintf(tmp_buff, GX_ARRAY_SIZE(tmp_buff), "%s",
			         static_cast<const char *>(pvalue));
		} else {
			offset += gx_snprintf(tmp_buff + offset,
			          GX_ARRAY_SIZE(tmp_buff) - offset, "; %s",
			          static_cast<const char *>(pvalue));
		}
	}
	if  (0 == offset) {
		*ppvalue = deconst(&fake_empty);
		return TRUE;
	}
	*ppvalue = PROP_TYPE(proptag) == PT_UNICODE ? common_util_dup(tmp_buff) :
	           common_util_convert_copy(FALSE, cpid, tmp_buff);
	return *ppvalue != nullptr ? TRUE : false;
}

static uint32_t instance_get_message_flags(MESSAGE_CONTENT *pmsgctnt)
{
	TPROPVAL_ARRAY *pproplist;
	
	pproplist = &pmsgctnt->proplist;
	auto pvalue = pproplist->getval(PR_MESSAGE_FLAGS);
	uint32_t message_flags = pvalue == nullptr ? 0 : *static_cast<uint32_t *>(pvalue);
	message_flags &= ~(MSGFLAG_READ | MSGFLAG_HASATTACH | MSGFLAG_FROMME |
	                 MSGFLAG_ASSOCIATED | MSGFLAG_RN_PENDING |
	                 MSGFLAG_NRN_PENDING);
	pvalue = pproplist->getval(PR_READ);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		message_flags |= MSGFLAG_READ;
	}
	if (NULL != pmsgctnt->children.pattachments &&
		0 != pmsgctnt->children.pattachments->count) {
		message_flags |= MSGFLAG_HASATTACH;
	}
	pvalue = pproplist->getval(PR_ASSOCIATED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		message_flags |= MSGFLAG_ASSOCIATED;
	}
	pvalue = pproplist->getval(PR_READ_RECEIPT_REQUESTED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		message_flags |= MSGFLAG_RN_PENDING;
	}
	pvalue = pproplist->getval(PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		message_flags |= MSGFLAG_NRN_PENDING;
	}
	return message_flags;
}

static BOOL instance_get_message_subject(
	TPROPVAL_ARRAY *pproplist, uint16_t cpid,
	uint32_t proptag, void **ppvalue)
{
	auto pnormalized_subject = pproplist->get<const char>(PR_NORMALIZED_SUBJECT);
	if (NULL == pnormalized_subject) {
		auto pvalue = pproplist->get<char>(PR_NORMALIZED_SUBJECT_A);
		if (NULL != pvalue) {
			pnormalized_subject =
				common_util_convert_copy(TRUE, cpid, pvalue);
		}
	}
	auto psubject_prefix = pproplist->get<const char>(PR_SUBJECT_PREFIX);
	if (NULL == psubject_prefix) {
		auto pvalue = pproplist->get<char>(PR_SUBJECT_PREFIX_A);
		if (NULL != pvalue) {
			psubject_prefix =
				common_util_convert_copy(TRUE, cpid, pvalue);
		}
	}
	if (NULL == pnormalized_subject && NULL == psubject_prefix) {
		*ppvalue = NULL;
		return TRUE;
	}
	if (NULL == pnormalized_subject) {
		pnormalized_subject = "";
	}
	if (NULL == psubject_prefix) {
		psubject_prefix = "";
	}
	auto pvalue = cu_alloc<char>(strlen(pnormalized_subject) + strlen(psubject_prefix) + 1);
	if (NULL == pvalue) {
		return FALSE;
	}
	strcpy(pvalue, psubject_prefix);
	strcat(pvalue, pnormalized_subject);
	if (PROP_TYPE(proptag) == PT_UNICODE) {
		*ppvalue = common_util_dup(pvalue);
		if (NULL == *ppvalue) {
			return FALSE;
		}
	} else {
		*ppvalue = common_util_convert_copy(FALSE, cpid, pvalue);
	}
	return TRUE;
}

static BOOL instance_get_attachment_properties(uint32_t cpid,
	const uint64_t *pmessage_id, ATTACHMENT_CONTENT *pattachment,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	uint32_t length;
	uint32_t proptag;
	uint16_t proptype;
	
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		auto pvalue = pattachment->proplist.getval(pproptags->pproptag[i]);
		auto &vc = ppropvals->ppropval[ppropvals->count];
		if (NULL != pvalue) {
			vc.proptag = pproptags->pproptag[i];
			vc.pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		vc.pvalue = NULL;
		if (PROP_TYPE(pproptags->pproptag[i]) == PT_STRING8) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE);
			pvalue = pattachment->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy(false,
				            cpid, static_cast<char *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_UNICODE) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8);
			pvalue = pattachment->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy(TRUE,
				            cpid, static_cast<char *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_MV_STRING8) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE);
			pvalue = pattachment->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy_string_array(false,
				            cpid, static_cast<STRING_ARRAY *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_MV_UNICODE) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_STRING8);
			pvalue = pattachment->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy_string_array(TRUE,
				            cpid, static_cast<STRING_ARRAY *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_UNSPECIFIED) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE);
			pvalue = pattachment->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				auto tp = cu_alloc<TYPED_PROPVAL>();
				vc.pvalue = tp;
				if (tp == nullptr)
					return FALSE;	
				tp->type = PT_UNICODE;
				tp->pvalue = pvalue;
			} else {
				proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8);
				pvalue = pattachment->proplist.getval(proptag);
				if (NULL != pvalue) {
					vc.proptag = pproptags->pproptag[i];
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
		switch (pproptags->pproptag[i]) {
		case PidTagMid:
			if (NULL != pmessage_id) {
				auto pv = cu_alloc<uint64_t>();
				vc.pvalue = pv;
				if (pv == nullptr)
					return FALSE;
				*pv = rop_util_make_eid_ex(1, *pmessage_id);
				vc.proptag = pproptags->pproptag[i];
				ppropvals->count ++;
				continue;
			}
			break;
		case PR_ATTACH_SIZE: {
			vc.proptag = pproptags->pproptag[i];
			length = common_util_calculate_attachment_size(pattachment);
			auto uv = cu_alloc<uint32_t>();
			if (uv == nullptr)
				return FALSE;
			*uv = length;
			vc.pvalue = uv;
			ppropvals->count ++;
			continue;
		}
		case PR_ATTACH_DATA_BIN_U: {
			proptype = PT_BINARY;
			auto pbin = pattachment->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
			if (NULL == pbin) {
				pvalue = pattachment->proplist.getval(ID_TAG_ATTACHDATABINARY);
				if (NULL != pvalue) {
					pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), &length, 0);
					if (NULL == pvalue) {
						return FALSE;
					}
					pbin = cu_alloc<BINARY>();
					if (NULL == pbin) {
						return FALSE;
					}
					pbin->cb = length;
					pbin->pv = pvalue;
				}
			}
			if (NULL == pbin) {
				proptype = PT_OBJECT;
				pbin = pattachment->proplist.get<BINARY>(PR_ATTACH_DATA_OBJ);
				if (NULL == pbin) {
					pvalue = pattachment->proplist.getval(ID_TAG_ATTACHDATAOBJECT);
					if (NULL != pvalue) {
						pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), &length, 0);
						if (NULL == pvalue) {
							return FALSE;
						}
						pbin = cu_alloc<BINARY>();
						if (NULL == pbin) {
							return FALSE;
						}
						pbin->cb = length;
						pbin->pv = pvalue;
					}
				}
			}
			if (NULL != pbin) {
				vc.proptag = pproptags->pproptag[i];
				auto tp = cu_alloc<TYPED_PROPVAL>();
				vc.pvalue = tp;
				if (tp == nullptr)
					return FALSE;	
				tp->type = proptype;
				tp->pvalue = pbin;
				ppropvals->count ++;
				continue;
			}
			break;
		}
		case PR_ATTACH_DATA_BIN:
		case PR_ATTACH_DATA_OBJ:
			if (pproptags->pproptag[i] == PR_ATTACH_DATA_BIN)
				pvalue = pattachment->proplist.getval(ID_TAG_ATTACHDATABINARY);
			else
				pvalue = pattachment->proplist.getval(ID_TAG_ATTACHDATAOBJECT);
			if (NULL != pvalue) {
				pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), &length, 0);
				if (NULL == pvalue) {
					return FALSE;
				}
				auto pbin = cu_alloc<BINARY>();
				if (NULL == pbin) {
					return FALSE;
				}
				pbin->cb = length;
				pbin->pv = pvalue;
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = pbin;
				ppropvals->count ++;
				continue;
			}
			break;
		}
	}
	return TRUE;
}	

BOOL exmdb_server_get_instance_properties(
	const char *dir, uint32_t size_limit, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i, j;
	uint16_t propid;
	uint32_t length;
	uint32_t proptag;
	MESSAGE_CONTENT *pmsgctnt;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance) {
		return FALSE;
	}
	if (INSTANCE_TYPE_ATTACHMENT == pinstance->type) {
		auto pinstance1 = instance_get_instance(pdb, pinstance->parent_id);
		if (NULL == pinstance1) {
			return FALSE;
		}
		auto pvalue = static_cast<MESSAGE_CONTENT *>(pinstance1->pcontent)->proplist.get<uint64_t>(PidTagMid);
		if (!instance_get_attachment_properties(pinstance->cpid, pvalue,
		    static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent),
			pproptags, ppropvals)) {
			return FALSE;
		}
		return TRUE;
	}
	pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		auto &vc = ppropvals->ppropval[ppropvals->count];
		if (pproptags->pproptag[i] == PR_MESSAGE_FLAGS) {
			vc.proptag = pproptags->pproptag[i];
			auto uv = cu_alloc<uint32_t>();
			vc.pvalue = uv;
			if (vc.pvalue == nullptr)
				return FALSE;
			*uv = instance_get_message_flags(pmsgctnt);
			ppropvals->count ++;
			continue;
		}
		auto pvalue = pmsgctnt->proplist.getval(pproptags->pproptag[i]);
		if (NULL != pvalue) {
			vc.proptag = pproptags->pproptag[i];
			vc.pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		vc.pvalue = nullptr;
		if (PROP_TYPE(pproptags->pproptag[i]) == PT_STRING8) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE);
			pvalue = pmsgctnt->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy(false,
				            pinstance->cpid, static_cast<char *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_UNICODE) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8);
			pvalue = pmsgctnt->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy(TRUE,
				            pinstance->cpid, static_cast<char *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_MV_STRING8) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE);
			pvalue = pmsgctnt->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy_string_array(false,
				            pinstance->cpid, static_cast<STRING_ARRAY *>(pvalue));
			}
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_MV_UNICODE) {
			proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_STRING8);
			pvalue = pmsgctnt->proplist.getval(proptag);
			if (NULL != pvalue) {
				vc.proptag = pproptags->pproptag[i];
				vc.pvalue = common_util_convert_copy_string_array(TRUE,
				            pinstance->cpid, static_cast<STRING_ARRAY *>(pvalue));
			}	
		} else if (PROP_TYPE(pproptags->pproptag[i]) == PT_UNSPECIFIED) {
			propid = PROP_ID(pproptags->pproptag[i]);
			for (j=0; j<pmsgctnt->proplist.count; j++) {
				if (propid != PROP_ID(pmsgctnt->proplist.ppropval[j].proptag))
					continue;
				vc.proptag = pproptags->pproptag[i];
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
		switch (pproptags->pproptag[i]) {
		case PR_BODY_A:
		case PR_BODY_W:
		case PR_BODY_U:
		case PR_HTML:
		case PR_HTML_U:
		case PR_RTF_COMPRESSED: {
			auto ret = instance_get_message_body(pmsgctnt, pproptags->pproptag[i], pinstance->cpid, ppropvals);
			if (ret < 0) {
				return false;
			}
			break;
		}
		case PR_TRANSPORT_MESSAGE_HEADERS_U: {
			pvalue = pmsgctnt->proplist.getval(ID_TAG_TRANSPORTMESSAGEHEADERS);
			if (NULL != pvalue) {
				pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), nullptr, ID_TAG_BODY);
				if (NULL == pvalue) {
					return FALSE;
				}
				vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_U;
				auto tp = cu_alloc<TYPED_PROPVAL>();
				vc.pvalue = tp;
				if (vc.pvalue == nullptr)
					return FALSE;
				tp->type = PT_UNICODE;
				tp->pvalue = static_cast<char *>(pvalue) + sizeof(uint32_t);
				ppropvals->count ++;
				continue;
			}
			pvalue = pmsgctnt->proplist.getval(ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
			if (pvalue == nullptr)
				break;
			pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), nullptr, 0);
			if (NULL == pvalue) {
				return FALSE;
			}
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
			    pinstance->cpid, pproptags->pproptag[i], &pvalue))
				return FALSE;
			if (pvalue == nullptr)
				break;
			vc.proptag = pproptags->pproptag[i];
			vc.pvalue = pvalue;
			ppropvals->count++;
			continue;
		case PR_TRANSPORT_MESSAGE_HEADERS:
			pvalue = pmsgctnt->proplist.getval(ID_TAG_TRANSPORTMESSAGEHEADERS);
			if (NULL != pvalue) {
				pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), nullptr, ID_TAG_BODY);
				if (NULL == pvalue) {
					return FALSE;
				}
				vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS;
				vc.pvalue = static_cast<char *>(pvalue) + sizeof(uint32_t);
				ppropvals->count ++;
				continue;
			}
			pvalue = pmsgctnt->proplist.getval(ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
			if (pvalue == nullptr)
				break;
			pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), nullptr, 0);
			if (NULL == pvalue) {
				return FALSE;
			}
			vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS;
			vc.pvalue = common_util_convert_copy(TRUE,
				    pinstance->cpid, static_cast<char *>(pvalue));
			if (vc.pvalue != nullptr) {
				ppropvals->count++;
				continue;
			}
			break;
		case PR_TRANSPORT_MESSAGE_HEADERS_A:
			pvalue = pmsgctnt->proplist.getval(ID_TAG_TRANSPORTMESSAGEHEADERS_STRING8);
			if (NULL != pvalue) {
				pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), nullptr, 0);
				if (NULL == pvalue) {
					return FALSE;
				}
				vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
				vc.pvalue = pvalue;
				ppropvals->count ++;
				continue;
			}
			pvalue = pmsgctnt->proplist.getval(ID_TAG_TRANSPORTMESSAGEHEADERS);
			if (pvalue == nullptr)
				break;
			pvalue = instance_read_cid_content(*static_cast<uint64_t *>(pvalue), nullptr, ID_TAG_BODY);
			if (NULL == pvalue) {
				return FALSE;
			}
			vc.proptag = PR_TRANSPORT_MESSAGE_HEADERS_A;
			vc.pvalue = common_util_convert_copy(false,
				    pinstance->cpid, static_cast<char *>(pvalue) + sizeof(uint32_t));
			if (vc.pvalue != nullptr) {
				ppropvals->count++;
				continue;
			}
			break;
		case PidTagFolderId: {
			if (pinstance->parent_id != 0)
				break;
			vc.proptag = pproptags->pproptag[i];
			auto uv = cu_alloc<uint64_t>();
			vc.pvalue = uv;
			if (vc.pvalue == nullptr)
				return FALSE;
			*uv = rop_util_make_eid_ex(1, pinstance->folder_id);
			ppropvals->count++;
			continue;
		}
		case PROP_TAG_CODEPAGEID:
			vc.proptag = pproptags->pproptag[i];
			vc.pvalue = &pinstance->cpid;
			ppropvals->count ++;
			continue;
		case PR_MESSAGE_SIZE:
		case PR_MESSAGE_SIZE_EXTENDED:
			vc.proptag = pproptags->pproptag[i];
			length = common_util_calculate_message_size(pmsgctnt);
			if (pproptags->pproptag[i] == PR_MESSAGE_SIZE) {
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
			vc.proptag = pproptags->pproptag[i];
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
			    pinstance->cpid, pproptags->pproptag[i], &pvalue))
				return FALSE;
			vc.proptag = pproptags->pproptag[i];
			vc.pvalue = pvalue;
			ppropvals->count++;
			continue;
		}
	}
	return TRUE;
}

static BOOL set_xns_props_msg(INSTANCE_NODE *pinstance,
    const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems)
{
	static constexpr uint8_t one_byte = 1;

	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproperties->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	for (size_t i = 0; i < pproperties->count; ++i) {
		switch (pproperties->ppropval[i].proptag) {
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
		case PROP_TAG_CODEPAGEID:
		case PidTagParentFolderId:
		case PROP_TAG_INSTANCESVREID:
		case PROP_TAG_HASNAMEDPROPERTIES:
		case PR_MESSAGE_SIZE:
		case PR_HASATTACH:
		case PR_DISPLAY_TO:
		case PR_DISPLAY_CC:
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_TO_A:
		case PR_DISPLAY_CC_A:
		case PR_DISPLAY_BCC_A:
		case PR_TRANSPORT_MESSAGE_HEADERS:
		case PR_TRANSPORT_MESSAGE_HEADERS_A:
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							pproperties->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
			continue;
		case PR_READ: {
			if (*static_cast<uint8_t *>(pproperties->ppropval[i].pvalue) == 0)
				break;
			auto pvalue = pmsgctnt->proplist.getval(PR_MESSAGE_FLAGS);
			if (NULL != pvalue) {
				*static_cast<uint32_t *>(pvalue) |= MSGFLAG_EVERREAD;
			}
			break;
		}
		case PROP_TAG_MESSAGESTATUS:
			/* PidTagMessageStatus can only be
				set by RopSetMessageStatus */
			continue;
		case PR_MESSAGE_FLAGS: {
			if (!pinstance->b_new) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
								pproperties->ppropval[i].proptag;
				pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
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
			*(uint32_t*)pproperties->ppropval[i].pvalue = message_flags;
			break;
		}
		case PR_SUBJECT:
		case PR_SUBJECT_A: {
			pmsgctnt->proplist.erase(PR_SUBJECT_PREFIX);
			pmsgctnt->proplist.erase(PR_SUBJECT_PREFIX_A);
			pmsgctnt->proplist.erase(PR_NORMALIZED_SUBJECT);
			pmsgctnt->proplist.erase(PR_NORMALIZED_SUBJECT_A);
			void *pvalue;
			if (pproperties->ppropval[i].proptag == PR_SUBJECT) {
				pvalue = pproperties->ppropval[i].pvalue;
			} else {
				pvalue = common_util_convert_copy(TRUE,
					pinstance->cpid, static_cast<char *>(pproperties->ppropval[i].pvalue));
				if (pvalue == nullptr)
					return FALSE;
			}
			if (pmsgctnt->proplist.set(PR_NORMALIZED_SUBJECT, pvalue) != 0)
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
		switch (PROP_TYPE(pproperties->ppropval[i].proptag)) {
		case PT_STRING8:
		case PT_UNICODE:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_STRING8));
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_UNICODE);
			if (PROP_TYPE(pproperties->ppropval[i].proptag) == PT_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy(TRUE,
				pinstance->cpid, static_cast<char *>(pproperties->ppropval[i].pvalue));
			if (NULL == propval.pvalue) {
				return FALSE;
			}
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_MV_STRING8));
			pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_MV_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_MV_UNICODE);
			if (PROP_TYPE(pproperties->ppropval[i].proptag) == PT_MV_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy_string_array(
			                 TRUE, pinstance->cpid,
			                 static_cast<STRING_ARRAY *>(pproperties->ppropval[i].pvalue));
			if (NULL == propval.pvalue) {
				return FALSE;
			}
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
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	auto pattachment = static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent);
	for (size_t i = 0; i < pproperties->count; ++i) {
		TAGGED_PROPVAL propval;
		switch (pproperties->ppropval[i].proptag) {
		case ID_TAG_ATTACHDATABINARY:
		case ID_TAG_ATTACHDATAOBJECT:
		case PR_ATTACH_NUM:
		case PR_RECORD_KEY:
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							pproperties->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
			continue;
		case PR_ATTACH_DATA_BIN:
			pattachment->proplist.erase(ID_TAG_ATTACHDATABINARY);
			break;
		case PR_ATTACH_DATA_OBJ:
			pattachment->proplist.erase(ID_TAG_ATTACHDATAOBJECT);
			break;
		}
		switch (PROP_TYPE(pproperties->ppropval[i].proptag)) {
		case PT_STRING8:
		case PT_UNICODE:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_STRING8));
			pattachment->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_UNICODE);
			if (PROP_TYPE(pproperties->ppropval[i].proptag) == PT_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy(TRUE,
				pinstance->cpid, static_cast<char *>(pproperties->ppropval[i].pvalue));
			if (NULL == propval.pvalue) {
				return FALSE;
			}
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			pattachment->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_MV_STRING8));
			pattachment->proplist.erase(CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_MV_UNICODE));
			propval.proptag = CHANGE_PROP_TYPE(pproperties->ppropval[i].proptag, PT_MV_UNICODE);
			if (PROP_TYPE(pproperties->ppropval[i].proptag) == PT_MV_UNICODE) {
				propval.pvalue = pproperties->ppropval[i].pvalue;
				break;
			}
			propval.pvalue = common_util_convert_copy_string_array(
			                 TRUE, pinstance->cpid,
					 static_cast<STRING_ARRAY *>(pproperties->ppropval[i].pvalue));
			if (NULL == propval.pvalue) {
				return FALSE;
			}
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

BOOL exmdb_server_set_instance_properties(const char *dir, uint32_t instance_id,
    const TPROPVAL_ARRAY *props, PROBLEM_ARRAY *prob)
{
	auto db = db_engine_get_db(dir);
	if (db == nullptr || db->psqlite == nullptr)
		return false;
	auto ins = instance_get_instance(db, instance_id);
	if (ins == nullptr)
		return false;
	if (ins->type == INSTANCE_TYPE_MESSAGE)
		return set_xns_props_msg(ins, props, prob);
	return set_xns_props_atx(ins, props, prob);
}

BOOL exmdb_server_remove_instance_properties(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
{
	int i;
	void *pvalue;
	MESSAGE_CONTENT *pmsgctnt;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance) {
		return FALSE;
	}
	pproblems->count = 0;
	if (INSTANCE_TYPE_MESSAGE == pinstance->type) {
		pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
		for (i=0; i<pproptags->count; i++) {
			switch (pproptags->pproptag[i]) {
			case PR_BODY:
			case PR_BODY_A:
			case PR_BODY_U:
				pmsgctnt->proplist.erase(ID_TAG_BODY);
				pmsgctnt->proplist.erase(ID_TAG_BODY_STRING8);
				if ((pvalue = pmsgctnt->proplist.getval(PR_NATIVE_BODY_INFO)) != nullptr &&
				    *static_cast<uint32_t *>(pvalue) == NATIVE_BODY_PLAIN)
					*(uint32_t*)pvalue = NATIVE_BODY_UNDEFINED;	
				break;
			case PR_HTML:
			case PR_BODY_HTML:
			case PR_BODY_HTML_A:
			case PR_HTML_U:
				pmsgctnt->proplist.erase(PR_BODY_HTML);
				pmsgctnt->proplist.erase(PR_BODY_HTML_A);
				pmsgctnt->proplist.erase(ID_TAG_HTML);
				if ((pvalue = pmsgctnt->proplist.getval(PR_NATIVE_BODY_INFO)) != nullptr &&
				    *static_cast<uint32_t *>(pvalue) == NATIVE_BODY_HTML)
					*(uint32_t*)pvalue = NATIVE_BODY_UNDEFINED;	
				break;
			case PR_RTF_COMPRESSED:
				if ((pvalue = pmsgctnt->proplist.getval(PR_NATIVE_BODY_INFO)) != nullptr &&
				    *static_cast<uint32_t *>(pvalue) == NATIVE_BODY_RTF)
					*(uint32_t*)pvalue = NATIVE_BODY_UNDEFINED;	
				pmsgctnt->proplist.erase(ID_TAG_RTFCOMPRESSED);
				break;
			}
			pmsgctnt->proplist.erase(pproptags->pproptag[i]);
			switch (PROP_TYPE(pproptags->pproptag[i])) {
			case PT_STRING8:
				pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				break;
			case PT_UNICODE:
				pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8));
				break;
			case PT_MV_STRING8:
				pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			case PT_MV_UNICODE:
				pmsgctnt->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_STRING8));
				break;
			}
		}
	} else {
		pattachment = static_cast<ATTACHMENT_CONTENT *>(pinstance->pcontent);
		for (i=0; i<pproptags->count; i++) {
			switch (pproptags->pproptag[i]) {
			case PR_ATTACH_DATA_BIN:
				pattachment->proplist.erase(ID_TAG_ATTACHDATABINARY);
				break;
			case PR_ATTACH_DATA_OBJ:
				pattachment->proplist.erase(ID_TAG_ATTACHDATAOBJECT);
				break;
			}
			pattachment->proplist.erase(pproptags->pproptag[i]);
			switch (PROP_TYPE(pproptags->pproptag[i])) {
			case PT_STRING8:
				pattachment->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_UNICODE));
				break;
			case PT_UNICODE:
				pattachment->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_STRING8));
				break;
			case PT_MV_STRING8:
				pattachment->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_UNICODE));
				break;
			case PT_MV_UNICODE:
				pattachment->proplist.erase(CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_MV_STRING8));
				break;
			}
		}
	}
	return TRUE;
}

BOOL exmdb_server_check_instance_cycle(const char *dir,
	uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_cycle)
{
	if (src_instance_id == dst_instance_id) {
		*pb_cycle = TRUE;
		return TRUE;
	}
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, dst_instance_id);
	while (NULL != pinstance && 0 != pinstance->parent_id) {
		if (pinstance->parent_id == src_instance_id) {
			*pb_cycle = TRUE;
			return TRUE;
		}
		pinstance = instance_get_instance(pdb, pinstance->parent_id);
	}
	*pb_cycle = FALSE;
	return TRUE;
}

BOOL exmdb_server_empty_message_instance_rcpts(
	const char *dir, uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL != pmsgctnt->children.prcpts) {
		tarray_set_free(pmsgctnt->children.prcpts);
		pmsgctnt->children.prcpts = NULL;
	}
	return TRUE;
}

BOOL exmdb_server_get_message_instance_rcpts_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	*pnum = pmsgctnt->children.prcpts == nullptr ? 0 :
	        pmsgctnt->children.prcpts->count;
	return TRUE;
}

BOOL exmdb_server_get_message_instance_rcpts_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	TARRAY_SET *prcpts;
	PROPTAG_ARRAY *pproptags1;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.prcpts) {
		pproptags->count = 0;
		pproptags->pproptag = NULL;
		return TRUE;
	}
	pproptags1 = proptag_array_init();
	if (NULL == pproptags1) {
		return FALSE;
	}
	prcpts = pmsgctnt->children.prcpts;
	for (size_t i = 0; i < prcpts->count; ++i)
		for (size_t j = 0; j < prcpts->pparray[i]->count; ++j)
			if (!proptag_array_append(pproptags1,
			    prcpts->pparray[i]->ppropval[j].proptag)) {
				proptag_array_free(pproptags1);
				return FALSE;
			}
	/* MSMAPI expects to always see these four tags, even if no rows are sent later. */
	proptag_array_append(pproptags1, PR_RECIPIENT_TYPE);
	proptag_array_append(pproptags1, PR_DISPLAY_NAME);
	proptag_array_append(pproptags1, PR_ADDRTYPE);
	proptag_array_append(pproptags1, PR_EMAIL_ADDRESS);

	pproptags->count = pproptags1->count;
	pproptags->pproptag = cu_alloc<uint32_t>(pproptags1->count);
	if (NULL == pproptags->pproptag) {
		proptag_array_free(pproptags1);
		return FALSE;
	}
	memcpy(pproptags->pproptag, pproptags1->pproptag,
				sizeof(uint32_t)*pproptags1->count);
	proptag_array_free(pproptags1);
	return TRUE;
}

BOOL exmdb_server_get_message_instance_rcpts(
	const char *dir, uint32_t instance_id, uint32_t row_id,
	uint16_t need_count, TARRAY_SET *pset)
{
	TARRAY_SET *prcpts;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
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
		if (NULL != prow_id && row_id == *prow_id) {
			break;
		}
	}
	if (i >= prcpts->count) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	auto begin_pos = i;
	if (begin_pos + need_count > prcpts->count) {
		need_count = prcpts->count - begin_pos;
	}
	pset->count = need_count;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(need_count);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	for (i=0; i<need_count; i++) {
		pset->pparray[i] = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == pset->pparray[i]) {
			return FALSE;
		}
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
		if (!srecip.has(PR_RECIPIENT_TYPE)) {
			auto &p = drecip.ppropval[drecip.count++];
			p.proptag = PR_RECIPIENT_TYPE;
			p.pvalue = deconst(&dummy_rcpttype);
		}
		if (!srecip.has(PR_DISPLAY_NAME)) {
			auto &p = drecip.ppropval[drecip.count++];
			p.proptag = PR_DISPLAY_NAME;
			p.pvalue = deconst(dummy_string);
		}
		if (!srecip.has(PR_ADDRTYPE)) {
			auto &p = drecip.ppropval[drecip.count++];
			p.proptag = PR_ADDRTYPE;
			p.pvalue = deconst(&dummy_addrtype);
		}
		if (!srecip.has(PR_EMAIL_ADDRESS)) {
			auto &p = drecip.ppropval[drecip.count++];
			p.proptag = PR_EMAIL_ADDRESS;
			p.pvalue = deconst(dummy_string);
		}
	}
	return TRUE;
}

/* if only PR_ROWID in propvals, means delete this row */
BOOL exmdb_server_update_message_instance_rcpts(
	const char *dir, uint32_t instance_id, const TARRAY_SET *pset)
{
	uint32_t row_id;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.prcpts) {
		pmsgctnt->children.prcpts = tarray_set_init();
		if (NULL == pmsgctnt->children.prcpts) {
			return FALSE;
		}
	}
	for (size_t i = 0; i < pset->count; ++i) {
		auto &mod = *pset->pparray[i];
		auto prow_id = mod.get<uint32_t>(PR_ROWID);
		if (NULL == prow_id) {
			continue;
		}
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
			if (NULL == prcpt) {
				return FALSE;
			}
			tpropval_array_free(ex_rcpt);
			pmsgctnt->children.prcpts->pparray[j] = prcpt;
			break;
		}
		if (j < pmsgctnt->children.prcpts->count || did_match)
			continue;
		/* No previous rowid matched, so this constitutes a new entry */
		if (pmsgctnt->children.prcpts->count
			>= MAX_RECIPIENT_NUMBER) {
			return FALSE;
		}
		tpropval_array_ptr prcpt(mod.dup());
		if (NULL == prcpt) {
			return FALSE;
		}
		if (pmsgctnt->children.prcpts->append_move(std::move(prcpt)) != 0)
			return FALSE;
	}
	return TRUE;
}

BOOL exmdb_server_copy_instance_rcpts(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance_src = instance_get_instance(pdb, src_instance_id);
	if (NULL == pinstance_src ||
		INSTANCE_TYPE_MESSAGE != pinstance_src->type) {
		return FALSE;
	}
	if (static_cast<MESSAGE_CONTENT *>(pinstance_src->pcontent)->children.prcpts == nullptr) {
		*pb_result = FALSE;
		return TRUE;
	}
	auto pinstance_dst = instance_get_instance(pdb, dst_instance_id);
	if (NULL == pinstance_dst ||
		INSTANCE_TYPE_MESSAGE != pinstance_dst->type) {
		return FALSE;
	}
	if (!b_force && static_cast<MESSAGE_CONTENT *>(pinstance_dst->pcontent)->children.prcpts != nullptr) {
		*pb_result = FALSE;
		return TRUE;	
	}
	auto prcpts = static_cast<MESSAGE_CONTENT *>(pinstance_src->pcontent)->children.prcpts->dup();
	if (NULL == prcpts) {
		return FALSE;
	}
	auto dm = static_cast<MESSAGE_CONTENT *>(pinstance_dst->pcontent);
	if (dm->children.prcpts != nullptr)
		tarray_set_free(dm->children.prcpts);
	dm->children.prcpts = prcpts;
	*pb_result = TRUE;
	return TRUE;
}

BOOL exmdb_server_empty_message_instance_attachments(
	const char *dir, uint32_t instance_id)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL != pmsgctnt->children.pattachments) {
		attachment_list_free(pmsgctnt->children.pattachments);
		pmsgctnt->children.pattachments = NULL;
	}
	return TRUE;
}

BOOL exmdb_server_get_message_instance_attachments_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	*pnum = pmsgctnt->children.pattachments == nullptr ? 0 :
	        pmsgctnt->children.pattachments->count;
	return TRUE;
}

BOOL exmdb_server_get_message_instance_attachment_table_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags)
{
	int i, j;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.pattachments) {
		pproptags->count = 0;
		pproptags->pproptag = NULL;
		return TRUE;
	}
	auto pproptags1 = proptag_array_init();
	if (NULL == pproptags1) {
		return FALSE;
	}
	auto pattachments = pmsgctnt->children.pattachments;
	for (i=0; i<pattachments->count; i++) {
		for (j=0; j<pattachments->pplist[i]->proplist.count; j++) {
			if (!proptag_array_append(pproptags1,
			    pattachments->pplist[i]->proplist.ppropval[j].proptag)) {
				proptag_array_free(pproptags1);
				return FALSE;
			}
		}
	}
	pproptags->count = pproptags1->count;
	pproptags->pproptag = cu_alloc<uint32_t>(pproptags1->count);
	if (NULL == pproptags->pproptag) {
		proptag_array_free(pproptags1);
		return FALSE;
	}
	memcpy(pproptags->pproptag, pproptags1->pproptag,
				sizeof(uint32_t)*pproptags1->count);
	proptag_array_free(pproptags1);
	return TRUE;
}

BOOL exmdb_server_copy_instance_attachments(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result)
{
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance_src = instance_get_instance(pdb, src_instance_id);
	if (NULL == pinstance_src ||
		INSTANCE_TYPE_MESSAGE != pinstance_src->type) {
		return FALSE;
	}
	auto srcmsg = static_cast<MESSAGE_CONTENT *>(pinstance_src->pcontent);
	if (srcmsg->children.pattachments == nullptr) {
		*pb_result = FALSE;
		return TRUE;	
	}
	auto pinstance_dst = instance_get_instance(pdb, dst_instance_id);
	if (NULL == pinstance_dst ||
		INSTANCE_TYPE_MESSAGE != pinstance_dst->type) {
		return FALSE;
	}
	auto dstmsg = static_cast<MESSAGE_CONTENT *>(pinstance_dst->pcontent);
	if (!b_force && dstmsg->children.pattachments != nullptr) {
		*pb_result = FALSE;
		return TRUE;	
	}
	auto pattachments = attachment_list_dup(srcmsg->children.pattachments);
	if (NULL == pattachments) {
		return FALSE;
	}
	if (dstmsg->children.pattachments != nullptr)
		attachment_list_free(dstmsg->children.pattachments);
	dstmsg->children.pattachments = pattachments;
	return TRUE;
}

BOOL exmdb_server_query_message_instance_attachment_table(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
	int32_t row_needed, TARRAY_SET *pset)
{
	int i;
	int32_t end_pos;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	if (NULL == pmsgctnt->children.pattachments ||
		0 == pmsgctnt->children.pattachments->count ||
		start_pos >= pmsgctnt->children.pattachments->count) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	auto pvalue = pmsgctnt->proplist.getval(PidTagMid);
	auto pattachments = pmsgctnt->children.pattachments;
	if (row_needed > 0) {
		end_pos = start_pos + row_needed;
		if (end_pos >= pattachments->count) {
			end_pos = pattachments->count - 1;
		}
		pset->count = 0;
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - start_pos + 1);
		if (NULL == pset->pparray) {
			return FALSE;
		}
		for (i=start_pos; i<=end_pos; i++) {
			pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == pset->pparray[pset->count]) {
				return FALSE;
			}
			if (!instance_get_attachment_properties(
			    pinstance->cpid, static_cast<uint64_t *>(pvalue),
			    pattachments->pplist[i], pproptags,
			    pset->pparray[pset->count]))
				return FALSE;
			pset->count ++;
		}
	} else {
		end_pos = start_pos + row_needed;
		if (end_pos < 0) {
			end_pos = 0;
		}
		pset->count = 0;
		pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(start_pos - end_pos + 1);
		if (NULL == pset->pparray) {
			return FALSE;
		}
		for (i=start_pos; i>=end_pos; i--) {
			pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == pset->pparray[pset->count]) {
				return FALSE;
			}
			if (!instance_get_attachment_properties(
			    pinstance->cpid, static_cast<uint64_t *>(pvalue),
			    pattachments->pplist[i],
			    pproptags, pset->pparray[pset->count]))
				return FALSE;
			pset->count ++;
		}
	}
	return TRUE;
}

BOOL exmdb_server_set_message_instance_conflict(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt)
{
	uint8_t tmp_byte;
	BOOL b_inconflict;
	uint32_t tmp_status;
	MESSAGE_CONTENT msgctnt;
	MESSAGE_CONTENT *pembedded;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pdb = db_engine_get_db(dir);
	if (pdb == nullptr || pdb->psqlite == nullptr)
		return FALSE;
	auto pinstance = instance_get_instance(pdb, instance_id);
	if (NULL == pinstance || INSTANCE_TYPE_MESSAGE != pinstance->type) {
		return FALSE;
	}
	auto pmsg = static_cast<MESSAGE_CONTENT *>(pinstance->pcontent);
	auto pvalue = pmsg->proplist.getval(PROP_TAG_MESSAGESTATUS);
	b_inconflict = FALSE;
	if (pvalue != nullptr && *static_cast<uint32_t *>(pvalue) & MSGSTATUS_IN_CONFLICT)
		b_inconflict = TRUE;
	if (!b_inconflict) {
		if (!instance_read_message(pmsg, &msgctnt))
			return FALSE;
		if (NULL == pmsg->children.pattachments) {
			pattachments = attachment_list_init();
			if (NULL == pattachments) {
				return FALSE;
			}
			pmsg->children.pattachments = pattachments;
		} else {
			pattachments = pmsg->children.pattachments;
		}
		pattachment = attachment_content_init();
		if (NULL == pattachment) {
			return FALSE;
		}
		pembedded = message_content_dup(&msgctnt);
		if (NULL == pembedded) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		pembedded->proplist.erase(PidTagMid);
		attachment_content_set_embedded_internal(pattachment, pembedded);
		if (!attachment_list_append_internal(pattachments, pattachment)) {
			attachment_content_free(pattachment);
			return FALSE;
		}
		tmp_byte = 1;
		if (pattachment->proplist.set(PROP_TAG_INCONFLICT, &tmp_byte) != 0)
			/* ignore; reevaluate another time */;
	} else if (pmsg->children.pattachments == nullptr) {
		pattachments = attachment_list_init();
		if (NULL == pattachments) {
			return FALSE;
		}
		pmsg->children.pattachments = pattachments;
	} else {
		pattachments = pmsg->children.pattachments;
	}
	pattachment = attachment_content_init();
	if (NULL == pattachment) {
		return FALSE;
	}
	pembedded = message_content_dup(pmsgctnt);
	if (NULL == pembedded) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	pembedded->proplist.erase(PidTagMid);
	attachment_content_set_embedded_internal(pattachment, pembedded);
	if (!attachment_list_append_internal(pattachments, pattachment)) {
		attachment_content_free(pattachment);
		return FALSE;
	}
	tmp_byte = 1;
	if (pattachment->proplist.set(PROP_TAG_INCONFLICT, &tmp_byte) != 0)
		/* ignore; reevaluate */;
	pvalue = pmsg->proplist.getval(PROP_TAG_MESSAGESTATUS);
	if (NULL == pvalue) {
		pvalue = &tmp_status;
		tmp_status = MSGSTATUS_IN_CONFLICT;
	} else {
		*static_cast<uint32_t *>(pvalue) |= MSGSTATUS_IN_CONFLICT;
	}
	if (pmsg->proplist.set(PROP_TAG_MESSAGESTATUS, pvalue) != 0)
		/* ignore; reevaluate */;
	return TRUE;
}
