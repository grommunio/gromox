#pragma once
#include <cstdint>
#include <gromox/ndr.hpp>
#include "pdu_ndr_ids.hpp"

struct DCERPC_CTX_LIST {
	uint16_t context_id;
	uint8_t num_transfer_syntaxes;
	SYNTAX_ID abstract_syntax;
	SYNTAX_ID *transfer_syntaxes;
};

union DCERPC_OBJECT {
	char empty;
	GUID object;
};

struct DCERPC_ACK_CTX {
	uint16_t result;
	uint16_t reason;
	SYNTAX_ID syntax;
};

struct dcerpc_payload {};

struct dcerpc_request final : public dcerpc_payload {
	uint32_t alloc_hint;
	uint16_t context_id;
	uint16_t opnum;
	DCERPC_OBJECT object;
	DATA_BLOB pad;
	DATA_BLOB stub_and_verifier;
};
using DCERPC_REQUEST = dcerpc_request;

struct dcerpc_response final : public dcerpc_payload {
	uint32_t alloc_hint;
	uint16_t context_id;
	uint8_t cancel_count;
	DATA_BLOB pad;
	DATA_BLOB stub_and_verifier;
};
using DCERPC_RESPONSE = dcerpc_response;

struct dcerpc_fault final : public dcerpc_payload {
	uint32_t alloc_hint;
	uint16_t context_id;
	uint8_t cancel_count;
	int status; /* dcerpc ncacn status */
	DATA_BLOB pad;
};
using DCERPC_FAULT = dcerpc_fault;

struct dcerpc_fack final : public dcerpc_payload {
	uint32_t version;
	uint8_t pad;
	uint16_t window_size;
	uint32_t max_tdsu;
	uint32_t max_frag_size;
	uint16_t serial_no;
	uint16_t selack_size;
	uint32_t *selack;
};
using DCERPC_FACK = dcerpc_fack;

struct dcerpc_cancel_ack final : public dcerpc_payload {
	uint32_t version;
	uint32_t id;
	uint32_t server_is_accepting;
};
using DCERPC_CANCEL_ACK = dcerpc_cancel_ack;

struct dcerpc_bind final : public dcerpc_payload {
	uint16_t max_xmit_frag;
	uint16_t max_recv_frag;
	uint32_t assoc_group_id;
	uint8_t num_contexts;
	DCERPC_CTX_LIST *ctx_list;
	DATA_BLOB auth_info;
};
using DCERPC_BIND = dcerpc_bind;

struct dcerpc_bind_ack final : public dcerpc_payload {
	uint16_t max_xmit_frag;
	uint16_t max_recv_frag;
	uint32_t assoc_group_id;
	uint16_t secondary_address_size;
	char secondary_address[64];
	DATA_BLOB pad;
	uint8_t num_contexts;
	DCERPC_ACK_CTX *ctx_list;
	DATA_BLOB auth_info;
};
using DCERPC_BIND_ACK = dcerpc_bind_ack;

struct dcerpc_bind_nak final : public dcerpc_payload {
	uint16_t reject_reason;
	uint32_t num_versions;
	uint32_t *versions;
};
using DCERPC_BIND_NAK = dcerpc_bind_nak;

struct dcerpc_co_cancel final : public dcerpc_payload {
	DATA_BLOB auth_info;
};
using DCERPC_CO_CANCEL = dcerpc_co_cancel;

struct DCERPC_AUTH {
	~DCERPC_AUTH() { clear(); }
	void clear();

	uint8_t auth_type = 0, auth_level = 0, auth_pad_length = 0;
	uint8_t auth_reserved = 0;
	uint32_t auth_context_id = 0;
	DATA_BLOB credentials{};
};

struct dcerpc_auth3 final : public dcerpc_payload {
	uint32_t pad;
	DATA_BLOB auth_info;
};
using DCERPC_AUTH3 = dcerpc_auth3;

struct dcerpc_orphaned final : public dcerpc_payload {
	DATA_BLOB auth_info;
};
using DCERPC_ORPHANED = dcerpc_orphaned;

struct RTS_FLOWCONTROLACK {
	uint32_t bytes_received;
	uint32_t available_window;
	GUID channel_cookie;
};

struct RTS_CLIENTADDRESS {
	uint32_t address_type;
	char client_address[64];
};

union RTS_CMDS {
	uint32_t receivewindowsize;
	RTS_FLOWCONTROLACK flowcontrolack;
	uint32_t connectiontimeout;
	GUID cookie;
	uint32_t channellifetime;
	uint32_t clientkeepalive;
	uint32_t version;
	char empty;
	uint32_t padding;
	char negative_ance;
	char ance;
	RTS_CLIENTADDRESS clientaddress;
	GUID associationgroupid;
	uint32_t destination;
	uint32_t pingtrafficsentnotify;
};

struct RTS_CMD {
	uint32_t command_type;
	RTS_CMDS command;
};

struct dcerpc_rts final : public dcerpc_payload {
	uint16_t flags;
	uint16_t num;
	RTS_CMD *commands;
};
using DCERPC_RTS = dcerpc_rts;

/*
 * RTS PDU Header
 *
 * NCA = Network Connection Architecture
 * CN = Connection
 * DG = Datagram / Connectionless
 *
 * C706 §12.6.1 / RPCH v19 §2.2.3.6.1
 */
struct dcerpc_ncacn_packet {
	~dcerpc_ncacn_packet();

	constexpr dcerpc_ncacn_packet(bool be)
	{
		drep[0] = be ? 0 : DCERPC_DREP_LE;
	}
	uint8_t rpc_vers = 5;
	uint8_t rpc_vers_minor = 0;
	uint8_t pfc_flags = 0;
	uint8_t drep[4]{};

	/*
	 * Concerning NDR_PUSH: frag_length is 0 in the class, and so
	 * serialized with pdu_ndr_push_ncacnpkt. The produced blob is later
	 * updated with pdu_processor_set_frag_length.
	 */
	uint16_t frag_length = 0;
	uint16_t auth_length = 0;
	uint32_t call_id = 0;
	uint8_t pkt_type = DCERPC_PKT_INVALID;
	dcerpc_payload *payload = nullptr;
};
using DCERPC_NCACN_PACKET = dcerpc_ncacn_packet;

extern pack_result pdu_ndr_pull_dcerpc_auth(NDR_PULL *, DCERPC_AUTH *);
extern pack_result pdu_ndr_push_dcerpc_auth(NDR_PUSH *, const DCERPC_AUTH *);
extern pack_result pdu_ndr_pull_ncacnpkt(NDR_PULL *, DCERPC_NCACN_PACKET *);
extern pack_result pdu_ndr_push_ncacnpkt(NDR_PUSH *, DCERPC_NCACN_PACKET *);
