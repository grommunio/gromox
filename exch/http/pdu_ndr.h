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

struct DCERPC_REQUEST {
	uint32_t alloc_hint;
	uint16_t context_id;
	uint16_t opnum;
	DCERPC_OBJECT object;
	DATA_BLOB pad;
	DATA_BLOB stub_and_verifier;
};

struct DCERPC_RESPONSE {
	uint32_t alloc_hint;
	uint16_t context_id;
	uint8_t cancel_count;
	DATA_BLOB pad;
	DATA_BLOB stub_and_verifier;
};

struct DCERPC_FAULT {
	uint32_t alloc_hint;
	uint16_t context_id;
	uint8_t cancel_count;
	int status;  /*dcerpc ncan status */
	DATA_BLOB pad;
};

struct DCERPC_FACK {
	uint32_t version;
	uint8_t pad;
	uint16_t window_size;
	uint32_t max_tdsu;
	uint32_t max_frag_size;
	uint16_t serial_no;
	uint16_t selack_size;
	uint32_t *selack;
};

struct DCERPC_CANCEL_ACK {
	uint32_t version;
	uint32_t id;
	uint32_t server_is_accepting;
};

struct DCERPC_BIND {
	uint16_t max_xmit_frag;
	uint16_t max_recv_frag;
	uint32_t assoc_group_id;
	uint8_t num_contexts;
	DCERPC_CTX_LIST *ctx_list;
	DATA_BLOB auth_info;
};

struct DCERPC_BIND_ACK {
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

struct DCERPC_BIND_NAK {
	uint16_t reject_reason;
	uint32_t num_versions;
	uint32_t *versions;
};

struct DCERPC_CO_CANCEL {
	DATA_BLOB auth_info;
};

struct DCERPC_AUTH {
	uint8_t auth_type;
	uint8_t auth_level;
	uint8_t auth_pad_length;
	uint8_t auth_reserved;
	uint32_t auth_context_id;
	DATA_BLOB credentials;
};

struct DCERPC_AUTH3 {
	uint32_t pad;
	DATA_BLOB auth_info;
};

struct DCERPC_ORPHANED {
	DATA_BLOB auth_info;
};

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

struct DCERPC_RTS {
	uint16_t flags;
	uint16_t num;
	RTS_CMD *commands;
};

union DCERPC_PAYLOAD {
	DCERPC_REQUEST request;
	char ping;
	DCERPC_RESPONSE response;
	DCERPC_FAULT fault;
	char working;
	DCERPC_FACK nocall;
	DCERPC_FAULT reject;
	char ack;
	DCERPC_FACK fack;
	DCERPC_CANCEL_ACK cancel_ack;
	DCERPC_BIND bind;
	DCERPC_BIND_ACK bind_ack;
	DCERPC_BIND_NAK bind_nak;
	DCERPC_BIND alter;
	DCERPC_BIND_ACK alter_ack;
	char shutdown;
	DCERPC_CO_CANCEL co_cancel;
	DCERPC_ORPHANED orphaned;
	DCERPC_AUTH3 auth3;
	DCERPC_RTS rts;
};

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
	DCERPC_PAYLOAD payload{};
};
using DCERPC_NCACN_PACKET = dcerpc_ncacn_packet;

extern pack_result pdu_ndr_pull_dcerpc_auth(NDR_PULL *, DCERPC_AUTH *);
extern void pdu_ndr_free_dcerpc_auth(DCERPC_AUTH *r);
extern pack_result pdu_ndr_push_dcerpc_auth(NDR_PUSH *, const DCERPC_AUTH *);
extern pack_result pdu_ndr_pull_ncacnpkt(NDR_PULL *, DCERPC_NCACN_PACKET *);
void pdu_ndr_free_ncacnpkt(DCERPC_NCACN_PACKET *pkt);
extern pack_result pdu_ndr_push_ncacnpkt(NDR_PUSH *, DCERPC_NCACN_PACKET *);
