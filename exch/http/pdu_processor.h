#pragma once
#include <string>
#include <gromox/dcerpc.hpp>
#include <gromox/ndr.hpp>
#include <gromox/plugin.hpp>
#include <gromox/ntlmssp.hpp>
#include <gromox/stream.hpp>
#include <gromox/double_list.hpp>
#include "pdu_ndr.h"
#define DCERPC_BASE_MARSHALL_SIZE					(16*1024)
#define DISPATCH_FAIL								0
#define DISPATCH_SUCCESS							1
#define DISPATCH_PENDING							2

enum {
	PDU_PROCESSOR_ERROR,
	PDU_PROCESSOR_INPUT,
	PDU_PROCESSOR_OUTPUT,
	PDU_PROCESSOR_FORWARD,
	PDU_PROCESSOR_TERMINATE
};

struct PROC_PLUGIN {
	PROC_PLUGIN();
	PROC_PLUGIN(PROC_PLUGIN &&);
	~PROC_PLUGIN();
	void operator=(PROC_PLUGIN &&) = delete;

	DOUBLE_LIST list_reference{}, interface_list{};
	void *handle = nullptr;
	PLUGIN_MAIN lib_main = nullptr;
	TALK_MAIN talk_main = nullptr;
	std::string file_name;
	bool completed_init = false;
};

struct DCERPC_ENDPOINT {
	DOUBLE_LIST_NODE node;
	char host[128];
	int tcp_port;		/* only for ncacn_http */
	DOUBLE_LIST interface_list;
	uint32_t last_group_id;
};

/* virtual connection to DCE RPC server, actually only data structure of context */
struct PDU_PROCESSOR {
	DOUBLE_LIST_NODE node;
	int async_num;
	DCERPC_ENDPOINT *pendpoint;
	uint32_t assoc_group_id; 	/* we do not support association mechanism */
	DOUBLE_LIST context_list;
	DOUBLE_LIST auth_list;
	DOUBLE_LIST fragmented_list;
	uint32_t cli_max_recv_frag;	/* the maximum size the client wants to receive */
};

struct DCERPC_AUTH_CONTEXT {
	DOUBLE_LIST_NODE node;
	NTLMSSP_CTX *pntlmssp;
	DCERPC_AUTH auth_info;	/* auth_context_id is inside this structure */
	NTLMSSP_SESSION_INFO session_info;
	BOOL is_login;
};

struct DCERPC_INTERFACE;
struct DCERPC_CONTEXT {
	DOUBLE_LIST_NODE node;
	uint32_t context_id;
	BOOL b_ndr64;
	uint32_t stat_flags; /* this is the default stat_flags */
	uint32_t assoc_group_id;
	DCERPC_INTERFACE *pinterface; /* the ndr function table for the chosen interface */
	DCERPC_ENDPOINT *pendpoint;
	DOUBLE_LIST async_list;
};

/* the state of an ongoing dcerpc call */
struct DCERPC_CALL {
	DOUBLE_LIST_NODE node;
	PDU_PROCESSOR *pprocessor;
	DCERPC_CONTEXT *pcontext;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	BOOL pkt_loaded;
	uint32_t alloc_size; /* alloc size for request stub data */
	DCERPC_NCACN_PACKET pkt;
	BOOL b_bigendian;
	struct timeval time; /* the time the request arrived in the server */
	DOUBLE_LIST reply_list;
	uint32_t ptr_cnt;
};

/* PDU blob for output */
struct BLOB_NODE {
	DOUBLE_LIST_NODE node;
	BOOL b_rts;
	DATA_BLOB blob;
};

extern void pdu_processor_init(int connection_num, int connection_ratio,
	const char *netbios_name, const char *dns_name, const char *dns_domain,
	BOOL header_signing, size_t max_request_mem, const char *plugins_path,
	const char *const *names, bool ignerr);
extern int pdu_processor_run();
extern void pdu_processor_stop();
extern void pdu_processor_free();
PDU_PROCESSOR* pdu_processor_create(const char *host, int tcp_port);
void pdu_processor_destroy(PDU_PROCESSOR *pprocessor);
int pdu_processor_input(PDU_PROCESSOR *pprocessor, const char *pbuff,
	uint16_t length, DCERPC_CALL **ppcall);
int pdu_processor_rts_input(const char *pbuff, uint16_t length,
	DCERPC_CALL **ppcall);
void pdu_processor_output_stream(DCERPC_CALL *pcall, STREAM *pstream);
void pdu_processor_output_pdu(DCERPC_CALL *pcall, DOUBLE_LIST *ppdu_list);
void pdu_processor_free_blob(BLOB_NODE *pbnode);
void pdu_processor_free_call(DCERPC_CALL *pcall);
BOOL pdu_processor_rts_conn_c2(DCERPC_CALL *pcall, uint32_t in_window_size);
BOOL pdu_processor_rts_inr2_a4(DCERPC_CALL *pcall);
BOOL pdu_processor_rts_outr2_a2(DCERPC_CALL *pcall);
BOOL pdu_processor_rts_outr2_a6(DCERPC_CALL *pcall);
BOOL pdu_processor_rts_outr2_b3(DCERPC_CALL *pcall);
BOOL pdu_processor_rts_ping(DCERPC_CALL *pcall);
void pdu_processor_rts_echo(char *pbuff);
BOOL pdu_processor_rts_flowcontrolack_withdestination(
	DCERPC_CALL *pcall, uint32_t bytes_received,
	uint32_t available_window, const char *channel_cookie);
int pdu_processor_console_talk(int argc, char** argv,
	char *result, int length);
void pdu_processor_enum_endpoints(void (*enum_ep)(DCERPC_ENDPOINT*));
void pdu_processor_enum_interfaces(DCERPC_ENDPOINT *pendpoint,
	void (*enum_if)(DCERPC_INTERFACE*));
void* pdu_processor_ndr_stack_alloc(int type, size_t size);
extern BOOL pdu_processor_rpc_new_environment();
extern void pdu_processor_rpc_free_environment();
extern void pdu_processor_reload();
