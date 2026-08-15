#pragma once
#include <list>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>
#include <gromox/dcerpc.hpp>
#include <gromox/double_list.hpp>
#include <gromox/ndr.hpp>
#include <gromox/plugin.hpp>
#include <gromox/stream.hpp>
#include "ntlmssp.hpp"
#include "pdu_ndr.hpp"
#define DCERPC_BASE_MARSHALL_SIZE					(16*1024)
#define DISPATCH_FAIL								0
#define DISPATCH_SUCCESS							1
#define DISPATCH_PENDING							2

enum pduproc_result {
	PDU_PROCESSOR_ERROR,
	PDU_PROCESSOR_INPUT,
	PDU_PROCESSOR_OUTPUT,
	PDU_PROCESSOR_FORWARD,
	PDU_PROCESSOR_TERMINATE
};

struct dcerpc_call;
struct dcerpc_endpoint {
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

struct dcerpc_auth_context {
	std::unique_ptr<ntlmssp_ctx> pntlmssp;
	DCERPC_AUTH auth_info{}; /* auth_context_id is inside this structure */
	NTLMSSP_SESSION_INFO session_info{};
	BOOL is_login = false;
};

struct dcerpc_context {
	~dcerpc_context();

	uint32_t context_id;
	BOOL b_ndr64;
	uint32_t stat_flags; /* this is the default stat_flags */
	uint32_t assoc_group_id;
	const DCERPC_INTERFACE *pinterface; /* the ndr function table for the chosen interface */
	const dcerpc_endpoint *pendpoint;
	DOUBLE_LIST async_list;
};

/* virtual connection to DCE RPC server, actually only data structure of context */
struct pdu_processor {
	~pdu_processor();
	static std::unique_ptr<pdu_processor> create(const char *host, uint16_t tcp_port);
	std::shared_ptr<dcerpc_context> find_ctx(uint32_t id) const;
	std::shared_ptr<dcerpc_auth_context> find_auth_ctx(uint32_t id) const;
	dcerpc_call *pop_frag_call(uint32_t id);
	int input(const char *pbuff, uint16_t length, dcerpc_call **ppcall);
	void wait_for_asyncs();

	int async_num = 0;
	uint32_t assoc_group_id = 0; /* we do not support association mechanism */
	uint32_t cli_max_recv_frag = 0; /* the maximum size the client wants to receive */
	dcerpc_endpoint *pendpoint = nullptr;
	std::vector<std::shared_ptr<dcerpc_context>> context_list;
	std::vector<std::shared_ptr<dcerpc_auth_context>> auth_list;
	DOUBLE_LIST fragmented_list{};
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
	pdu_processor *pprocessor = nullptr;
	std::shared_ptr<dcerpc_context> pcontext;
	std::shared_ptr<dcerpc_auth_context> pauth_ctx;
	BOOL b_bigendian = false;
	uint32_t alloc_size = 0; /* alloc size for request stub data */
	uint32_t ptr_cnt = 0;
	dcerpc_ncacn_packet pkt;
	DOUBLE_LIST reply_list{};
};

/* PDU blob for output */
struct BLOB_NODE {
	DOUBLE_LIST_NODE node;
	BOOL b_rts;
	DATA_BLOB blob;
};

extern void pdu_processor_init(int connection_num, const char *netbios_name, const char *dns_name, const char *dns_domain, BOOL header_signing, size_t max_request_mem, std::span<const gromox::generic_module> &&names);
extern int pdu_processor_run();
extern void pdu_processor_stop();
int pdu_processor_rts_input(const char *pbuff, uint16_t length,
	dcerpc_call **ppcall);
void pdu_processor_free_blob(BLOB_NODE *pbnode);
void pdu_processor_rts_echo(char *pbuff);
BOOL pdu_processor_rts_flowcontrolack_withdestination(
	dcerpc_call *pcall, uint32_t bytes_received,
	uint32_t available_window, const char *channel_cookie);
void* pdu_processor_ndr_stack_alloc(int type, size_t size);
extern bool pdu_processor_rpc_new_stack();
extern void pdu_processor_rpc_free_stack();
extern void pdu_processor_trigger(enum plugin_op);
