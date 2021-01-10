#pragma once
#include <gromox/ndr.hpp>
#define DCERPC_SECURITY_CONTEXT_MULTIPLEXING		0x1
#define DCERPC_CONNECTION_ORPHAN_SUPPORTED			0x2


#define DCERPC_AUTH_TYPE_NONE						0
#define DCERPC_AUTH_TYPE_KRB5_1						1
#define DCERPC_AUTH_TYPE_SPNEGO						9
#define DCERPC_AUTH_TYPE_NTLMSSP					10
#define DCERPC_AUTH_TYPE_KRB5						16
#define DCERPC_AUTH_TYPE_DPA						17
#define DCERPC_AUTH_TYPE_MSN						18
#define DCERPC_AUTH_TYPE_DIGEST						21
#define DCERPC_AUTH_TYPE_SCHANNEL					68
#define DCERPC_AUTH_TYPE_MSMQ						100
#define DCERPC_AUTH_TYPE_NCALRPC_AS_SYSTEM			200


#define DCERPC_AUTH_LEVEL_EMPTY						0
#define DCERPC_AUTH_LEVEL_NONE						1
#define DCERPC_AUTH_LEVEL_CONNECT					2
#define DCERPC_AUTH_LEVEL_CALL						3
#define DCERPC_AUTH_LEVEL_PACKET					4
#define DCERPC_AUTH_LEVEL_INTEGRITY					5
#define DCERPC_AUTH_LEVEL_PRIVACY					6


#define DCERPC_PKT_REQUEST							0
#define DCERPC_PKT_PING								1
#define DCERPC_PKT_RESPONSE							2
#define DCERPC_PKT_FAULT							3
#define DCERPC_PKT_WORKING							4
#define DCERPC_PKT_NOCALL							5
#define DCERPC_PKT_REJECT							6
#define DCERPC_PKT_ACK								7

#define DCERPC_PKT_FACK								9
#define DCERPC_PKT_CANCEL_ACK						10
#define DCERPC_PKT_BIND								11
#define DCERPC_PKT_BIND_ACK							12
#define DCERPC_PKT_BIND_NAK							13
#define DCERPC_PKT_ALTER							14
#define DCERPC_PKT_ALTER_ACK						15
#define DCERPC_PKT_AUTH3							16
#define DCERPC_PKT_SHUTDOWN							17
#define DCERPC_PKT_CO_CANCEL						18
#define DCERPC_PKT_ORPHANED							19
#define DCERPC_PKT_RTS								20

#define DCERPC_REQUEST_LENGTH						24
#define DCERPC_BIND_RESULT_USER_REJECTION			1
#define DCERPC_BIND_RESULT_PROVIDER_REJECT			2
#define DCERPC_BIND_RESULT_NEGOTIATE_ACK			3
#define DCERPC_BIND_REASON_NOT_SPECIFIED			0
#define DCERPC_BIND_REASON_ASYNTAX					1
#define DECRPC_BIND_REASON_LOCAL_LIMIT_EXCEEDED		2
#define DECRPC_BIND_REASON_VERSION_NOT_SUPPORTED	4
#define DCERPC_BIND_REASON_INVALID_AUTH_TYPE		8
#define DCERPC_BIND_REASON_INVALID_CHECKSUM			9
#define DCERPC_RESPONSE_LENGTH						24

#define DCERPC_FAULT_SUCCESS						0x0
#define DCERPC_FAULT_COMM_FAILURE					0x1C010001
#define DCERPC_FAULT_OP_RNG_ERROR					0x1c010002
#define DCERPC_FAULT_UNK_IF							0x1c010003
#define DCERPC_FAULT_NDR							0x000006f7
#define DCERPC_FAULT_INVALID_TAG					0x1c000006
#define DCERPC_FAULT_CONTEXT_MISMATCH				0x1c00001a
#define DCERPC_FAULT_OTHER							0x00000001
#define DCERPC_FAULT_ACCESS_DENIED					0x00000005
#define DCERPC_FAULT_CANT_PERFORM					0x000006d8
#define DCERPC_FAULT_SEC_PKG_ERROR					0x00000721
#define DCERPC_FAULT_TODO							0x00000042

#define DCERPC_AUTH_LEVEL_DEFAULT					2
#define DCERPC_AUTH_TRAILER_LENGTH					8
#define DCERPC_PFC_FLAG_FIRST						0x01
#define DCERPC_PFC_FLAG_LAST						0x02
#define DCERPC_PFC_FLAG_PENDING_CANCEL				0x04
#define DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN			0x04
#define DCERPC_PFC_FLAG_CONC_MPX					0x10
#define DCERPC_PFC_FLAG_DID_NOT_EXECUTE				0x20
#define DCERPC_PFC_FLAG_MAYBE						0x40
#define DCERPC_PFC_FLAG_OBJECT_UUID					0x80
#define DCERPC_PTYPE_OFFSET							2
#define DCERPC_PFC_OFFSET							3
#define DCERPC_DREP_OFFSET							4
#define DCERPC_FRAG_LEN_OFFSET						8
#define DCERPC_AUTH_LEN_OFFSET						10
#define DCERPC_DREP_LE								0x10


#define RTS_IPV4									0
#define RTS_IPV6									1


#define FD_CLIENT									0
#define FD_INROXY									1
#define FD_SERVER									2
#define FD_OUTPROXY									3

#define RTS_CMD_RECEIVE_WINDOW_SIZE 				0
#define RTS_CMD_FLOW_CONTROL_ACK					1
#define RTS_CMD_CONNECTION_TIMEOUT					2
#define RTS_CMD_COOKIE								3
#define RTS_CMD_CHANNEL_LIFETIME					4
#define RTS_CMD_CLIENT_KEEPALIVE					5
#define RTS_CMD_VERSION								6
#define RTS_CMD_EMPTY								7
#define RTS_CMD_PADDING								8
#define RTS_CMD_NEGATIVE_ANCE						9
#define RTS_CMD_ANCE								10
#define RTS_CMD_CLIENT_ADDRESS						11
#define RTS_CMD_ASSOCIATION_GROUP_ID				12
#define RTS_CMD_DESTINATION							13
#define RTS_CMD_PING_TRAFFIC_SENT_NOTIFY			14


#define RTS_FLAG_NONE								0x0000
#define RTS_FLAG_PING								0x0001
#define RTS_FLAG_OTHER_CMD							0x0002
#define RTS_FLAG_RECYCLE_CHANNEL					0x0004
#define RTS_FLAG_IN_CHANNEL							0x0008
#define RTS_FLAG_OUT_CHANNEL						0x0010
#define RTS_FLAG_EOF								0x0020
#define RTS_FLAG_ECHO								0x0040


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

struct DCERPC_NCACN_PACKET {
	uint8_t rpc_vers;
	uint8_t rpc_vers_minor;
	uint8_t pfc_flags;
	uint8_t drep[4];
	uint16_t frag_length;
	uint16_t auth_length;
	uint32_t call_id;
	uint8_t pkt_type;
	DCERPC_PAYLOAD payload;
};

int pdu_ndr_pull_dcerpc_auth(NDR_PULL *pndr, DCERPC_AUTH *r);
extern void pdu_ndr_free_dcerpc_auth(DCERPC_AUTH *r);
int pdu_ndr_push_dcerpc_auth(NDR_PUSH *pndr, const DCERPC_AUTH *r);

int pdu_ndr_pull_ncacnpkt(NDR_PULL *pndr, DCERPC_NCACN_PACKET *pkt);

void pdu_ndr_free_ncacnpkt(DCERPC_NCACN_PACKET *pkt);

int pdu_ndr_push_ncacnpkt(NDR_PUSH *pndr, DCERPC_NCACN_PACKET *pkt);
