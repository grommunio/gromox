// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#pragma once
#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <tinyxml2.h>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>

/*
 * Inbox rules as seen by EWS, MS-OXWSRULES v9.0, and their mapping onto the
 * server-side rules table, MS-OXORULE v23.0. Nothing in here talks to exmdb,
 * everything mailbox-specific goes through Rules::Env.
 */
namespace gromox::EWS::Rules {

/* t:RulePredicatesType children, in schema order */
enum pred_kind : uint8_t {
	P_Categories, P_ContainsBodyStrings, P_ContainsHeaderStrings,
	P_ContainsRecipientStrings, P_ContainsSenderStrings,
	P_ContainsSubjectOrBodyStrings, P_ContainsSubjectStrings,
	P_FlaggedForAction, P_FromAddresses, P_FromConnectedAccounts,
	P_HasAttachments, P_Importance, P_IsApprovalRequest,
	P_IsAutomaticForward, P_IsAutomaticReply, P_IsEncrypted,
	P_IsMeetingRequest, P_IsMeetingResponse, P_IsNDR,
	P_IsPermissionControlled, P_IsReadReceipt, P_IsSigned, P_IsVoicemail,
	P_ItemClasses, P_MessageClassifications, P_NotSentToMe, P_SentCcMe,
	P_SentOnlyToMe, P_SentToAddresses, P_SentToMe, P_SentToOrCcMe,
	P_Sensitivity, P_WithinDateRange, P_WithinSizeRange, P_COUNT,
};

/* t:RuleActionsType children, in schema order */
enum act_kind : uint8_t {
	A_AssignCategories, A_CopyToFolder, A_Delete,
	A_ForwardAsAttachmentToRecipients, A_ForwardToRecipients,
	A_MarkImportance, A_MarkAsRead, A_MoveToFolder, A_PermanentDelete,
	A_RedirectToRecipients, A_SendSMSAlertToRecipients,
	A_ServerReplyWithMessage, A_StopProcessingRules, A_COUNT,
};

enum class vtype : uint8_t {
	strings, addresses, boolean, flag, importance, sensitivity,
	date_range, size_range, folder, item,
};

struct Address {
	std::string name, email, routing;

	bool operator==(const Address &) const = default;
};

/* t:TargetFolderIdType */
struct FolderRef {
	bool distinguished = false;
	std::string id, change_key, mailbox;

	bool operator==(const FolderRef &) const = default;
};

/* t:ItemIdType */
struct ItemRef {
	std::string id, change_key;

	bool operator==(const ItemRef &) const = default;
};

struct Value {
	std::vector<std::string> strings;
	std::vector<Address> addrs;
	bool flag = false;
	std::string text;
	std::optional<time_t> start, end;
	std::optional<int32_t> min, max;
	FolderRef folder;
	ItemRef item;

	bool operator==(const Value &) const = default;
};

struct Predicates {
	std::array<std::optional<Value>, P_COUNT> v;

	bool empty() const;
	bool operator==(const Predicates &) const = default;
};

struct Actions {
	std::array<std::optional<Value>, A_COUNT> v;

	bool operator==(const Actions &) const = default;
};

/* t:RuleType */
struct Rule {
	std::optional<std::string> id;
	std::string name;
	int32_t priority = 0;
	bool enabled = false;
	std::optional<bool> not_supported, in_error;
	Predicates conditions, exceptions;
	Actions actions;
};

struct Operation {
	enum kind_t : uint8_t { CREATE, SET, DELETE } kind = CREATE;
	Rule rule;
	std::string rule_id; /* DeleteRuleOperation */
};

/* t:RuleValidationErrorType */
struct ValidationError {
	std::string field, code, message, value;
};

/* t:RuleOperationErrorType */
struct OperationError {
	int32_t index = 0;
	std::vector<ValidationError> errors;
};

class ParseError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

/*
 * Mailbox-specific services for the mapping.
 * Write-side resolvers return nullptr on success or a
 * t:RuleValidationErrorCodeType value.
 */
class Env {
	public:
	virtual ~Env() = default;
	virtual void *alloc(size_t) = 0;
	virtual uint16_t keywords_propid(bool create) = 0;
	virtual uint16_t flagrequest_propid(bool create) = 0;
	virtual const char *resolve_folder(const FolderRef &, MOVECOPY_ACTION &) = 0;
	virtual const char *deleted_items(MOVECOPY_ACTION &) = 0;
	virtual const char *resolve_template(const ItemRef &, REPLY_ACTION &) = 0;
	/* Turn the address into plain SMTP form */
	virtual const char *resolve_address(Address &) = 0;
	virtual bool folder_ref(const MOVECOPY_ACTION &, FolderRef &, bool &deleted_items) = 0;
	virtual bool template_ref(const REPLY_ACTION &, ItemRef &) = 0;
	virtual bool essdn_to_smtp(const char *essdn, std::string &smtp) = 0;
};

static constexpr size_t MAX_RECIPIENTS = 256;
static constexpr int32_t MAX_SIZE_KB = 2097151;

extern const char *pred_name(unsigned int);
extern const char *act_name(unsigned int);
extern vtype pred_type(unsigned int);
extern vtype act_type(unsigned int);

extern std::string encode_rule_id(uint64_t);
extern std::optional<uint64_t> decode_rule_id(const std::string &);

extern Rule parse_rule(const tinyxml2::XMLElement *);
extern std::vector<Operation> parse_operations(const tinyxml2::XMLElement *);
extern void write_rule(tinyxml2::XMLElement *parent, const Rule &);
extern void write_errors(tinyxml2::XMLElement *parent, const std::vector<OperationError> &);

extern void strip_wildcards(Rule &);
extern std::vector<ValidationError> validate(const Rule &, Operation::kind_t);
extern bool to_mapi(const Rule &, Env &, RESTRICTION *&, RULE_ACTIONS *&, std::vector<ValidationError> &);
extern Rule from_mapi(const TPROPVAL_ARRAY &, Env &);
extern bool is_visible(const TPROPVAL_ARRAY &);
extern std::vector<uint32_t> assign_sequences(std::vector<uint32_t> old, size_t count);

}
