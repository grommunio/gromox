#pragma once
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <gromox/dcerpc.hpp>
#include <gromox/double_list.hpp>
#include <gromox/ndr.hpp>
#include <gromox/ntlmssp.hpp>
#include <gromox/plugin.hpp>
#include <gromox/stream.hpp>
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

struct DCERPC_ENDPOINT {
	char host[UDOM_SIZE]{};
	std::list<DCERPC_INTERFACE> interface_list;
	uint32_t last_group_id = 0;
	uint16_t tcp_port = 0; /* only for ncacn_http */
};

struct PROC_PLUGIN : public gromox::generic_module {
	PROC_PLUGIN() = default;
	PROC_PLUGIN(PROC_PLUGIN &&o) noexcept : generic_module(std::move(o)) {}
	~PROC_PLUGIN();
	void operator=(PROC_PLUGIN &&) noexcept = delete;

	std::vector<gromox::service_node> list_reference;
};

/* virtual connection to DCE RPC server, actually only data structure of context */
struct PDU_PROCESSOR {
	~PDU_PROCESSOR();

	int async_num = 0;
	uint32_t assoc_group_id = 0; /* we do not support association mechanism */
	uint32_t cli_max_recv_frag = 0; /* the maximum size the client wants to receive */
	DCERPC_ENDPOINT *pendpoint = nullptr;
	DOUBLE_LIST context_list{}, auth_list{}, fragmented_list{};
};

struct DCERPC_AUTH_CONTEXT {
	DOUBLE_LIST_NODE node{};
	std::unique_ptr<ntlmssp_ctx> pntlmssp;
	DCERPC_AUTH auth_info{}; /* auth_context_id is inside this structure */
	NTLMSSP_SESSION_INFO session_info{};
	BOOL is_login = false;
};

struct DCERPC_CONTEXT {
	DOUBLE_LIST_NODE node;
	uint32_t context_id;
	BOOL b_ndr64;
	uint32_t stat_flags; /* this is the default stat_flags */
	uint32_t assoc_group_id;
	const DCERPC_INTERFACE *pinterface; /* the ndr function table for the chosen interface */
	const DCERPC_ENDPOINT *pendpoint;
	DOUBLE_LIST async_list;
};

/* the state of an ongoing dcerpc call */
struct dcerpc_call {
	dcerpc_call();
	~dcerpc_call();
	NOMOVE(dcerpc_call);
	void output_pdus(STREAM &);
	void move_pdus(DOUBLE_LIST &);
	BOOL rts_conn_c2(uint32_t in_window_size);
	BOOL rts_outr2_a2();
	BOOL rts_outr2_a6();
	BOOL rts_outr2_b3();
	BOOL rts_ping();

	DOUBLE_LIST_NODE node{};
	PDU_PROCESSOR *pprocessor = nullptr;
	DCERPC_CONTEXT *pcontext = nullptr;
	DCERPC_AUTH_CONTEXT *pauth_ctx = nullptr;
	BOOL b_bigendian = false;
	uint32_t alloc_size = 0; /* alloc size for request stub data */
	uint32_t ptr_cnt = 0;
	dcerpc_ncacn_packet pkt;
	DOUBLE_LIST reply_list{};
};
using DCERPC_CALL = dcerpc_call;

/* PDU blob for output */
struct BLOB_NODE {
	DOUBLE_LIST_NODE node;
	BOOL b_rts;
	DATA_BLOB blob;
};

extern void pdu_processor_init(int connection_num, const char *netbios_name, const char *dns_name, const char *dns_domain, BOOL header_signing, size_t max_request_mem, std::vector<std::string> &&names);
extern int pdu_processor_run();
extern void pdu_processor_stop();
extern std::unique_ptr<PDU_PROCESSOR> pdu_processor_create(const char *host, uint16_t tcp_port);
extern void pdu_processor_destroy(std::unique_ptr<PDU_PROCESSOR> &&);
int pdu_processor_input(PDU_PROCESSOR *pprocessor, const char *pbuff,
	uint16_t length, DCERPC_CALL **ppcall);
int pdu_processor_rts_input(const char *pbuff, uint16_t length,
	DCERPC_CALL **ppcall);
void pdu_processor_free_blob(BLOB_NODE *pbnode);
void pdu_processor_rts_echo(char *pbuff);
BOOL pdu_processor_rts_flowcontrolack_withdestination(
	DCERPC_CALL *pcall, uint32_t bytes_received,
	uint32_t available_window, const char *channel_cookie);
void* pdu_processor_ndr_stack_alloc(int type, size_t size);
extern BOOL pdu_processor_rpc_new_stack();
extern void pdu_processor_rpc_free_stack();
extern void pdu_processor_trigger(unsigned int ev);
