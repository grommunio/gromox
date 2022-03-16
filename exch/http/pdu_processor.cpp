// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "hpm_processor.h"
#include "http_parser.h"
#include "pdu_processor.h"
#include "resource.h"
#define ASSOC_GROUP_HASH_SIZE			10000
#define ASSOC_GROUP_HASH_GROWING		1000

#define MAX_CONTEXTS_PER_CONNECTION		100

#define MAX_FRAGMENTED_CALLS			100
#define MAX_SYNC_PER_CONTEXT			10

/* this is only used when the client asks for an unknown interface */
#define DUMMY_ASSOC_GROUP 0x0FFFFFFF

#define NDR_STACK_IN					0
#define NDR_STACK_OUT					1

using namespace std::string_literals;
using namespace gromox;

namespace {

/* structure for describing service reference */
struct pdu_service_node {
	DOUBLE_LIST_NODE node;
	void *service_addr;
	char *service_name;
};

struct ndr_stack_root {
	alloc_context in_stack, out_stack;
};
using NDR_STACK_ROOT = ndr_stack_root;

struct ASYNC_NODE {
	DOUBLE_LIST_NODE node;
	BOOL b_cancelled;
	uint32_t async_id;
	DCERPC_CALL *pcall;
	NDR_STACK_ROOT* pstack_root;
	char vconn_host[UDOM_SIZE];
	uint16_t vconn_port;
	char vconn_cookie[64];
};

class endpoint_eq {
	public:
	constexpr endpoint_eq(const char *h, uint16_t p) : host(h), port(p) {}
	bool operator()(const DCERPC_ENDPOINT &e) const {
		return e.tcp_port == port && strcasecmp(e.host, host) == 0;
	}
	protected:
	const char *host = nullptr;
	uint16_t port = 0;
};

class endpoint_mt : public endpoint_eq {
	public:
	using endpoint_eq::endpoint_eq;
	bool operator()(const DCERPC_ENDPOINT &e) const {
		return e.tcp_port == port && wildcard_match(host, e.host, TRUE) > 0;
	}
};

class interface_eq {
	public:
	constexpr interface_eq(const GUID &g, uint32_t v) : uuid(g), ver(v) {}
	bool operator()(const DCERPC_INTERFACE &i) const {
		return i.uuid == uuid && i.version == ver;
	}
	protected:
	GUID uuid{};
	uint32_t ver = 0;
};

}

unsigned int g_msrpc_debug;
static BOOL g_bigendian;
static unsigned int g_connection_num;
static char g_dns_name[128];
static BOOL g_header_signing;
static int g_connection_ratio;
static char g_dns_domain[128];
static char g_netbios_name[128];
static size_t g_max_request_mem;
static uint32_t g_last_async_id;
static thread_local DCERPC_CALL *g_call_key;
static thread_local NDR_STACK_ROOT *g_stack_key;
static PROC_PLUGIN *g_cur_plugin;
static std::list<PROC_PLUGIN> g_plugin_list;
static std::mutex g_list_lock, g_async_lock;
static std::list<DCERPC_ENDPOINT> g_endpoint_list;
static bool support_negotiate = false; /* possibly nonfunctional */
static std::unique_ptr<INT_HASH_TABLE> g_async_hash;
static std::list<PDU_PROCESSOR *> g_processor_list; /* ptrs owned by VIRTUAL_CONNECTION */
static alloc_limiter<DCERPC_CALL> g_call_allocator{"g_call_allocator.d"};
static alloc_limiter<DCERPC_AUTH_CONTEXT> g_auth_allocator{"g_auth_allocator.d"};
static alloc_limiter<ASYNC_NODE> g_async_allocator{"g_async_allocator.d"};
static alloc_limiter<BLOB_NODE> g_bnode_allocator{"g_bnode_allocator.d"};
static alloc_limiter<NDR_STACK_ROOT> g_stack_allocator{"g_stack_allocator.d"};
static alloc_limiter<DCERPC_CONTEXT> g_context_allocator{"g_context_allocator.d"};
static std::vector<std::string> g_plugin_names;
static const SYNTAX_ID g_transfer_syntax_ndr = 
	/* {8a885d04-1ceb-11c9-9fe8-08002b104860} */
	{{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8}, {0x08,0x00,0x2b,0x10,0x48,0x60}}, 2};

static const SYNTAX_ID g_transfer_syntax_ndr64 =
	/* {71710533-beba-4937-8319-b5dbef9ccc36} */
	{{0x71710533, 0xbeba, 0x4937, {0x83, 0x19}, {0xb5,0xdb,0xef,0x9c,0xcc,0x36}}, 1};

static int pdu_processor_load_library(const char* plugin_name);

dcerpc_call::dcerpc_call() :
	pkt(b_bigendian)
{
	/*
	 * b_bigendian is false => pkt(false) => pkt.drep[0]=LE. That's ok
	 * because: If and when we read a packet from the wire, then e.g.
	 * pdu_processor_rts_input will set b_bigendian based on peeking into
	 * the packet before ndr_pull_init is called.
	 */
	node.pdata = this;
	gettimeofday(&time, nullptr);
	double_list_init(&reply_list);
}

static NDR_STACK_ROOT* pdu_processor_new_stack_root()
{
	auto pstack_root = g_stack_allocator.get();
	if (NULL == pstack_root) {
		return NULL;
	}
	return pstack_root;
}

void* pdu_processor_ndr_stack_alloc(int type, size_t size)
{
	auto proot = g_stack_key;
	if (NULL == proot) {
		return NULL;
	}
	if (NDR_STACK_IN == type) {
		return proot->in_stack.alloc(size);
	} else if (NDR_STACK_OUT == type) {
		return proot->out_stack.alloc(size);
	}
	return NULL;
}

static void pdu_processor_free_stack_root(NDR_STACK_ROOT *pstack_root)
{
	if (g_stack_key == pstack_root)
		g_stack_key = nullptr;
	g_stack_allocator->put(pstack_root);
}

static size_t pdu_processor_ndr_stack_size(NDR_STACK_ROOT *pstack_root, int type)
{
	if (NDR_STACK_IN == type) {
		return pstack_root->in_stack.get_total();
	} else if (NDR_STACK_OUT) {
		return pstack_root->out_stack.get_total();
	}
	return 0;
}

void pdu_processor_init(int connection_num, const char *netbios_name,
    const char *dns_name, const char *dns_domain, BOOL header_signing,
    size_t max_request_mem, std::vector<std::string> &&names)
{
	static constexpr unsigned int connection_ratio = 10;
	union {
		uint32_t i;
		char c[4];
    } e;

	e.i = 0xFF000000;
	if (0 != e.c[0]) {
		g_bigendian = TRUE;
	} else {
		g_bigendian = FALSE;
	}
	g_last_async_id = 0;
	g_connection_ratio = connection_ratio;
	g_connection_num = connection_num;
	g_max_request_mem = max_request_mem;
	gx_strlcpy(g_netbios_name, netbios_name, GX_ARRAY_SIZE(g_netbios_name));
	gx_strlcpy(g_dns_name, dns_name, GX_ARRAY_SIZE(g_dns_name));
	gx_strlcpy(g_dns_domain, dns_domain, GX_ARRAY_SIZE(g_dns_domain));
	g_header_signing = header_signing;
	g_plugin_names = std::move(names);
}

int pdu_processor_run()
{
	int context_num;
	
	g_call_allocator = alloc_limiter<DCERPC_CALL>(g_connection_num * g_connection_ratio,
	                   "pdu_call_allocator", "http.cfg:context_num");
	context_num = g_connection_num*g_connection_ratio;
	g_context_allocator = alloc_limiter<DCERPC_CONTEXT>(context_num,
	                      "pdu_ctx_allocator", "http.cfg:context_num");
	g_auth_allocator = alloc_limiter<DCERPC_AUTH_CONTEXT>(context_num,
	                   "pdu_auth_allocator", "http.cfg:context_num");
	g_bnode_allocator = alloc_limiter<BLOB_NODE>(32 * g_connection_num,
	                    "pdu_bnode_allocator", "http.cfg:context_num");
	g_async_allocator = alloc_limiter<ASYNC_NODE>(2 * context_num,
	                    "pdu_async_allocator", "http.cfg:context_num");
	g_stack_allocator = alloc_limiter<NDR_STACK_ROOT>(4 * context_num,
	                    "pdu_stack_allocator", "http.cfg:context_num");
	g_async_hash = INT_HASH_TABLE::create(context_num * 2, sizeof(ASYNC_NODE *));
	if (NULL == g_async_hash) {
		return -8;
	}
	for (const auto &i : g_plugin_names) {
		int ret = pdu_processor_load_library(i.c_str());
		if (ret != PLUGIN_LOAD_OK)
			return -1;
	}
	return 0;
}

void pdu_processor_free_call(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (pcall->pkt_loaded)
		pdu_ndr_free_ncacnpkt(&pcall->pkt);
	while ((pnode = double_list_pop_front(&pcall->reply_list)) != nullptr) {
		pblob_node = (BLOB_NODE*)pnode->pdata;
		free(pblob_node->blob.data);
		g_bnode_allocator->put(pblob_node);
	}
	double_list_free(&pcall->reply_list);
	if (g_call_key == pcall)
		g_call_key = nullptr;
	g_call_allocator->put(pcall);
}

static void pdu_processor_free_context(DCERPC_CONTEXT *pcontext)
{
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	
	while (true) {
		std::unique_lock as_hold(g_async_lock);
		pnode = double_list_pop_front(&pcontext->async_list);
		if (NULL == pnode) {
			break;
		}
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		g_async_hash->remove(pasync_node->async_id);
		as_hold.unlock();
		if (NULL != pcontext->pinterface->reclaim) {
			pcontext->pinterface->reclaim(pasync_node->async_id);
		}
		pdu_processor_free_stack_root(pasync_node->pstack_root);
		pdu_processor_free_call(pasync_node->pcall);
		g_async_allocator->put(pasync_node);
	}
	double_list_free(&pcontext->async_list);
	g_context_allocator->put(pcontext);
}

void pdu_processor_stop()
{
	auto z = g_processor_list.size();
	if (z > 0) {
		/* http_parser_stop runs before pdu_processor_stop, so all
		 * VIRTUAL_CONNECTION objects ought to be gone already. */
		fprintf(stderr, "W-1573: %zu PDU_PROCESSORs remaining\n", z);
		g_processor_list.clear();
	}

	g_plugin_list.clear();
	g_endpoint_list.clear();
	g_async_hash.reset();
}

static uint16_t pdu_processor_find_secondary(const char *host,
    uint16_t tcp_port, const GUID *puuid, uint32_t version)
{
	auto ei = std::find_if(g_endpoint_list.cbegin(), g_endpoint_list.cend(),
	          endpoint_eq(host, tcp_port));
	if (ei == g_endpoint_list.cend())
		return tcp_port;
	auto &lst = ei->interface_list;
	auto ix = std::find_if(lst.cbegin(), lst.cend(), interface_eq(*puuid, version));
	return ix != lst.cend() ? ei->tcp_port : tcp_port;
}

/* find the interface operations on an endpoint by uuid */
static const DCERPC_INTERFACE *
pdu_processor_find_interface_by_uuid(const DCERPC_ENDPOINT *pendpoint,
    const GUID *puuid, uint32_t if_version)
{
	auto &lst = pendpoint->interface_list;
	auto ix = std::find_if(lst.begin(), lst.end(), interface_eq(*puuid, if_version));
	return ix != lst.end() ? &*ix : nullptr;
}

std::unique_ptr<PDU_PROCESSOR>
pdu_processor_create(const char *host, uint16_t tcp_port)
{
	std::unique_ptr<PDU_PROCESSOR> pprocessor;
	
	try {
		pprocessor = std::make_unique<PDU_PROCESSOR>();
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1574: ENOMEM\n");
		return NULL;
	}
	/* verify that EP&INTF exists */
	auto ei = std::find_if(g_endpoint_list.begin(), g_endpoint_list.end(),
	          endpoint_mt(host, tcp_port));
	if (ei == g_endpoint_list.end())
		return nullptr;
	{
			double_list_init(&pprocessor->context_list);
			double_list_init(&pprocessor->auth_list);
			double_list_init(&pprocessor->fragmented_list);
			pprocessor->pendpoint = &*ei;
			std::lock_guard li_hold(g_list_lock);
			g_processor_list.push_back(pprocessor.get());
			return pprocessor;
	}
	return NULL;
}

PDU_PROCESSOR::~PDU_PROCESSOR()
{
	auto pprocessor = this;
	uint64_t handle;
	DCERPC_CALL *pcall;
	DCERPC_CALL fake_call;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	while ((pnode = double_list_pop_front(&pprocessor->context_list)) != nullptr) {
		pcontext = (DCERPC_CONTEXT*)pnode->pdata;
		if (NULL != pcontext->pinterface->unbind) {
			fake_call.pprocessor = pprocessor;
			fake_call.pcontext = pcontext;
			g_call_key = &fake_call;
			handle = pcontext->assoc_group_id;
			handle <<= 32;
			handle |= pcontext->context_id;
			pcontext->pinterface->unbind(handle);
			g_call_key = nullptr;
		}
		pdu_processor_free_context(pcontext);
	}
	double_list_free(&pprocessor->context_list);
	
	while ((pnode = double_list_pop_front(&pprocessor->auth_list)) != nullptr) {
		pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
		pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
		if (NULL != pauth_ctx->pntlmssp) {
			ntlmssp_destroy(pauth_ctx->pntlmssp);
			pauth_ctx->pntlmssp = NULL;
		}
		g_auth_allocator->put(pauth_ctx);
	}
	double_list_free(&pprocessor->auth_list);
	
	while ((pnode = double_list_pop_front(&pprocessor->fragmented_list)) != nullptr) {
		pcall = (DCERPC_CALL*)pnode->pdata;
		pdu_processor_free_call(pcall);
	}
	double_list_free(&pprocessor->fragmented_list);
	
	pprocessor->cli_max_recv_frag = 0;
	std::unique_lock li_hold(g_list_lock);
	g_processor_list.remove(this);
	li_hold.unlock();
	pprocessor->pendpoint = NULL;
}

void pdu_processor_destroy(std::unique_ptr<PDU_PROCESSOR> &&p)
{
	auto pprocessor = std::move(p); /* cause destruction at end of this function */
	while (true) {
		std::unique_lock as_hold(g_async_lock);
		if (pprocessor->async_num <= 0) {
			pprocessor->async_num = -1;
			break;
		}
		as_hold.unlock();
		usleep(100000);
	}
}

static void pdu_processor_set_frag_length(DATA_BLOB *pblob, uint16_t v)
{
	auto r = &pblob->data[DCERPC_FRAG_LEN_OFFSET];
	if (pblob->data[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE)
		cpu_to_le16p(r, v);
	else
		cpu_to_be16p(r, v);
}

static void pdu_processor_set_auth_length(DATA_BLOB *pblob, uint16_t v)
{
	auto r = &pblob->data[DCERPC_AUTH_LEN_OFFSET];
	if (pblob->data[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE)
		cpu_to_le16p(r, v);
	else
		cpu_to_be16p(r, v);
}

void pdu_processor_output_stream(DCERPC_CALL *pcall, STREAM *pstream)
{
	BLOB_NODE *pblob_node;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pcall->reply_list)) != nullptr) {
		pblob_node = (BLOB_NODE*)pnode->pdata;
		pstream->write(pblob_node->blob.data, pblob_node->blob.length);
		free(pblob_node->blob.data);
		g_bnode_allocator->put(pblob_node);
	}
}

void pdu_processor_output_pdu(DCERPC_CALL *pcall, DOUBLE_LIST *ppdu_list)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pcall->reply_list)) != nullptr)
		double_list_append_as_tail(ppdu_list, pnode);
}

void pdu_processor_free_blob(BLOB_NODE *pbnode)
{
	g_bnode_allocator->put(pbnode);
}

static DCERPC_CALL* pdu_processor_get_fragmented_call(
	PDU_PROCESSOR *pprocessor, uint32_t call_id)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pprocessor->fragmented_list); NULL!=pnode;
		pnode=double_list_get_after(&pprocessor->fragmented_list, pnode)) {
		pcall = (DCERPC_CALL*)pnode->pdata;
		if (pcall->pkt.call_id == call_id) {
			double_list_remove(&pprocessor->fragmented_list, pnode);
			return pcall;
		}
	}
	return NULL;
}

static uint32_t pdu_processor_allocate_group_id(DCERPC_ENDPOINT *pendpoint)
{
	uint32_t group_id;
	
	pendpoint->last_group_id ++;
	group_id = pendpoint->last_group_id;
	if (pendpoint->last_group_id >= INT32_MAX)
		pendpoint->last_group_id = 0;
	return group_id;
}

/* find a registered context_id from a bind or alter_context */
static DCERPC_CONTEXT* pdu_processor_find_context(PDU_PROCESSOR *pprocessor, 
	uint32_t context_id)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext;
	
	for (pnode=double_list_get_head(&pprocessor->context_list); NULL!=pnode;
		pnode=double_list_get_after(&pprocessor->context_list, pnode)) {
		pcontext = (DCERPC_CONTEXT*)pnode->pdata;
		if (context_id == pcontext->context_id) {
			return pcontext;
		}
	}
	return NULL;
}

static DCERPC_AUTH_CONTEXT* pdu_processor_find_auth_context(
	PDU_PROCESSOR *pprocessor, uint32_t auth_context_id)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	for (pnode=double_list_get_head(&pprocessor->auth_list); NULL!=pnode;
		pnode=double_list_get_after(&pprocessor->auth_list, pnode)) {
		pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
		if (auth_context_id == pauth_ctx->auth_info.auth_context_id) {
			return pauth_ctx;
		}
	}
	return NULL;
}

static BOOL pdu_processor_pull_auth_trailer(DCERPC_NCACN_PACKET *ppkt,
	DATA_BLOB *ptrailer, DCERPC_AUTH *pauth, uint32_t *pauth_length,
	BOOL auth_data_only)
{
	NDR_PULL ndr;
	uint32_t flags;
	uint32_t data_and_pad;
	
	
	data_and_pad = ptrailer->length -
		(DCERPC_AUTH_TRAILER_LENGTH + ppkt->auth_length);
	if (data_and_pad > ptrailer->length) {
		return FALSE;
	}
	*pauth_length = ptrailer->length - data_and_pad;
	
	flags = 0;
	if (0 == (ppkt->drep[0] & DCERPC_DREP_LE)) {
		flags = NDR_FLAG_BIGENDIAN;
	}
	
	ndr_pull_init(&ndr, ptrailer->data, ptrailer->length, flags);
	if (NDR_ERR_SUCCESS != ndr_pull_advance(&ndr, data_and_pad)) {
		return FALSE;
	}
	if (NDR_ERR_SUCCESS != pdu_ndr_pull_dcerpc_auth(&ndr, pauth)) {
		return FALSE;
	}

	if (auth_data_only && data_and_pad != pauth->auth_pad_length) {
		debug_info("[pdu_processor]: WARNING: pad length mismatch, "
			"calculated %u got %u\n", data_and_pad, pauth->auth_pad_length);
		pdu_ndr_free_dcerpc_auth(pauth);
		return FALSE;
	}
	
	return TRUE;
}

/* check credentials on a request */
static BOOL pdu_processor_auth_request(DCERPC_CALL *pcall, DATA_BLOB *pblob)
{
	size_t hdr_size;
	DCERPC_AUTH auth;
	uint32_t auth_length;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_REQUEST *prequest;
	DCERPC_NCACN_PACKET *ppkt;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	ppkt = &pcall->pkt;
	prequest = &ppkt->payload.request;
	hdr_size = DCERPC_REQUEST_LENGTH;
	if (0 == ppkt->auth_length) {
		if (0 == double_list_get_nodes_num(&pcall->pprocessor->auth_list)) {
			return FALSE;
		}
		pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
		pcall->pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
		switch (pcall->pauth_ctx->auth_info.auth_level) {
		case RPC_C_AUTHN_LEVEL_DEFAULT:
		case RPC_C_AUTHN_LEVEL_CONNECT:
		case RPC_C_AUTHN_LEVEL_NONE:
			return TRUE;
		default:
			return FALSE;
		}
	}
	if (!pdu_processor_pull_auth_trailer(ppkt,
	    &prequest->stub_and_verifier, &auth, &auth_length, false))
		return FALSE;
	pauth_ctx = pdu_processor_find_auth_context(
				pcall->pprocessor, auth.auth_context_id);
	if (NULL == pauth_ctx) {
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	pcall->pauth_ctx = pauth_ctx;
	
	if (ppkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		hdr_size += 16;
	}
	
	switch (pauth_ctx->auth_info.auth_level) {
	case RPC_C_AUTHN_LEVEL_DEFAULT:
		pdu_ndr_free_dcerpc_auth(&auth);
		return TRUE;
	case RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
	case RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
	case RPC_C_AUTHN_LEVEL_CONNECT:
		break;
	case RPC_C_AUTHN_LEVEL_NONE:
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	default:
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	
	ppkt->payload.request.stub_and_verifier.length -= auth_length;

	/* check signature or unseal the packet */
	switch (pauth_ctx->auth_info.auth_level) {
	case RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
		if (!ntlmssp_unseal_packet(pauth_ctx->pntlmssp,
		    pblob->data + hdr_size, prequest->stub_and_verifier.length,
		    pblob->data, pblob->length - auth.credentials.length,
		    &auth.credentials)) {
			pdu_ndr_free_dcerpc_auth(&auth);
			return FALSE;
		}
		memcpy(prequest->stub_and_verifier.data, pblob->data + hdr_size,
			prequest->stub_and_verifier.length);
		break;
	case RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
		if (!ntlmssp_check_packet(pauth_ctx->pntlmssp,
		    prequest->stub_and_verifier.data,
		    prequest->stub_and_verifier.length, pblob->data,
		    pblob->length - auth.credentials.length, &auth.credentials)) {
			pdu_ndr_free_dcerpc_auth(&auth);
			return FALSE;
		}
		break;
	case RPC_C_AUTHN_LEVEL_CONNECT:
		/* ignore possible signatures here */
		break;
	default:
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	
	/* remove the indicated amount of padding */
	if (prequest->stub_and_verifier.length < auth.auth_pad_length) {
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	prequest->stub_and_verifier.length -= auth.auth_pad_length;
	pdu_ndr_free_dcerpc_auth(&auth);
	return TRUE;
}

static BOOL pdu_processor_ncacn_push_with_auth(DATA_BLOB *pblob,
	DCERPC_NCACN_PACKET *ppkt, DCERPC_AUTH *pauth_info)
{
	void *pdata;
	NDR_PUSH ndr;
	uint32_t flags;
	
	
	pdata = malloc(DCERPC_BASE_MARSHALL_SIZE);
	if (NULL == pdata) {
		return FALSE;
	}
	
	flags = 0;
	if (0 == (ppkt->drep[0] & DCERPC_DREP_LE)) {
		flags = NDR_FLAG_BIGENDIAN;
	}
	if (ppkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		flags |= NDR_FLAG_OBJECT_PRESENT;
	}
	
	ndr_push_init(&ndr, pdata, DCERPC_BASE_MARSHALL_SIZE, flags);
	
	if (NULL != pauth_info) {
		ppkt->auth_length = pauth_info->credentials.length;
	} else {
		ppkt->auth_length = 0;
	}

	if (NDR_ERR_SUCCESS != pdu_ndr_push_ncacnpkt(&ndr, ppkt)) {
		free(pdata);
		return FALSE;
	}

	if (NULL != pauth_info) {
		pauth_info->auth_pad_length = 0;
		if (NDR_ERR_SUCCESS != pdu_ndr_push_dcerpc_auth(&ndr, pauth_info)) {
			free(pdata);
			return FALSE;
		}
	}
	
	pblob->data = ndr.data;
	pblob->length = ndr.offset;
	
	/* fill in the frag length */
	pdu_processor_set_frag_length(pblob, pblob->length);

	return TRUE;
}

static BOOL pdu_processor_fault(DCERPC_CALL *pcall, uint32_t fault_code)
{
	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	static constexpr uint8_t zeros[4] = {};
	
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_FAULT;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.fault.alloc_hint = 0;
	pkt.payload.fault.context_id = 0;
	pkt.payload.fault.cancel_count = 0;
	pkt.payload.fault.status = fault_code;
	pkt.payload.fault.pad.data = deconst(zeros);
	pkt.payload.fault.pad.length = sizeof(zeros);

	auto pblob_node = g_bnode_allocator->get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	return TRUE;
}

/*
  parse any auth information from a dcerpc bind request
  return false if we can't handle the auth request for some 
  reason (in which case we send a bind_nak)
*/
static BOOL pdu_processor_auth_bind(DCERPC_CALL *pcall)
{
	DCERPC_BIND *pbind;
	uint32_t auth_length;
	DCERPC_NCACN_PACKET *ppkt = &pcall->pkt;
	pbind = &ppkt->payload.bind;
	
	if (double_list_get_nodes_num(&pcall->pprocessor->auth_list) >
		MAX_CONTEXTS_PER_CONNECTION) {
		debug_info("[pdu_processor]: maximum auth contexts"
			" number of connection reached\n");
		return FALSE;
	}
	auto pauth_ctx = g_auth_allocator->get();
	if (NULL == pauth_ctx) {
		return FALSE;
	}
	memset(pauth_ctx, 0, sizeof(DCERPC_AUTH_CONTEXT));
	pauth_ctx->node.pdata = pauth_ctx;
	
	if (0 == pbind->auth_info.length) {
		pauth_ctx->auth_info.auth_type = RPC_C_AUTHN_NONE;
		pauth_ctx->auth_info.auth_level = RPC_C_AUTHN_LEVEL_DEFAULT;
		double_list_append_as_tail(&pcall->pprocessor->auth_list,
			&pauth_ctx->node);
		return TRUE;
	}
	if (!pdu_processor_pull_auth_trailer(ppkt, &pbind->auth_info,
		&pauth_ctx->auth_info, &auth_length, FALSE)) {
		g_auth_allocator->put(pauth_ctx);
		return FALSE;
	}
	
	if (NULL != pdu_processor_find_auth_context(pcall->pprocessor,
		pauth_ctx->auth_info.auth_context_id)) {
		pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
		g_auth_allocator->put(pauth_ctx);
		return FALSE;
	}
	
	if (pauth_ctx->auth_info.auth_type == RPC_C_AUTHN_NONE) {
		double_list_append_as_tail(&pcall->pprocessor->auth_list,
			&pauth_ctx->node);
		return TRUE;
	} else if (pauth_ctx->auth_info.auth_type == RPC_C_AUTHN_NTLMSSP) {
		if (pauth_ctx->auth_info.auth_level <= RPC_C_AUTHN_LEVEL_CONNECT) {
			pauth_ctx->pntlmssp = ntlmssp_init(g_netbios_name,
									g_dns_name, g_dns_domain, TRUE,
									NTLMSSP_NEGOTIATE_128|
									NTLMSSP_NEGOTIATE_56|
									NTLMSSP_NEGOTIATE_NTLM2|
									NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
									http_parser_get_password);
		} else {
			pauth_ctx->pntlmssp = ntlmssp_init(g_netbios_name,
									g_dns_name, g_dns_domain, TRUE,
									NTLMSSP_NEGOTIATE_128|
									NTLMSSP_NEGOTIATE_56|
									NTLMSSP_NEGOTIATE_KEY_EXCH|
									NTLMSSP_NEGOTIATE_NTLM2|
									NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
									http_parser_get_password);
		}
		if (NULL == pauth_ctx->pntlmssp) {
			pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
			g_auth_allocator->put(pauth_ctx);
			return FALSE;
		}
		double_list_append_as_tail(&pcall->pprocessor->auth_list,
			&pauth_ctx->node);
		return TRUE;
	}
	pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
	g_auth_allocator->put(pauth_ctx);
	debug_info("[pdu_processor]: unsupported authentication type\n");
	return FALSE;
}

/*
  add any auth information needed in a bind ack, and 
  process the authentication information found in the bind.
*/
static BOOL pdu_processor_auth_bind_ack(DCERPC_CALL *pcall)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		return TRUE;
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	switch (pauth_ctx->auth_info.auth_type) {
	case RPC_C_AUTHN_NONE:
		return pauth_ctx->auth_info.auth_level == RPC_C_AUTHN_LEVEL_DEFAULT ||
		       pauth_ctx->auth_info.auth_level == RPC_C_AUTHN_LEVEL_NONE;
	case RPC_C_AUTHN_NTLMSSP:
		if (!ntlmssp_update(pauth_ctx->pntlmssp, &pauth_ctx->auth_info.credentials))
			return FALSE;
		if (NTLMSSP_PROCESS_AUTH == ntlmssp_expected_state(pauth_ctx->pntlmssp)) {
			pauth_ctx->auth_info.auth_pad_length = 0;
			pauth_ctx->auth_info.auth_reserved = 0;
			return TRUE;
		}
		return ntlmssp_session_info(pauth_ctx->pntlmssp,
		       &pauth_ctx->session_info) ? TRUE : false;
	default:
		return false;
	}
}

/* return a dcerpc bind_nak */
static BOOL pdu_processor_bind_nak(DCERPC_CALL *pcall, uint32_t reason)
{
	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_BIND_NAK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.bind_nak.reject_reason = reason;
	pkt.payload.bind_nak.num_versions = 0;

	auto pblob_node = g_bnode_allocator->get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	if (!pdu_processor_ncacn_push_with_auth(
		&pblob_node->blob, &pkt, NULL)) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}

	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_process_bind(DCERPC_CALL *pcall)
{
	int i;
	GUID uuid;
	BOOL b_found;
	BOOL b_ndr64;
	uint32_t reason;
	uint32_t result;
	DCERPC_BIND *pbind;
	uint32_t context_id;
	uint32_t if_version;
	uint32_t extra_flags;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	BOOL b_negotiate = FALSE;

	pbind = &pcall->pkt.payload.bind;

	if (pbind->num_contexts < 1 ||
		pbind->ctx_list[0].num_transfer_syntaxes < 1) {
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	/* can not bind twice on the same connection */
	if (0 != pcall->pprocessor->assoc_group_id) {
		return pdu_processor_bind_nak(pcall, 0);
	}

	context_id = pbind->ctx_list[0].context_id;

	/* bind only there's no context, otherwise, use alter */
	if (double_list_get_nodes_num(&pcall->pprocessor->context_list) > 0) {
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	if_version = pbind->ctx_list[0].abstract_syntax.version;
	uuid = pbind->ctx_list[0].abstract_syntax.uuid;

	b_ndr64 = FALSE;
	b_found = FALSE;
	for (i=0; i<pbind->ctx_list[0].num_transfer_syntaxes; i++) {
		if (g_transfer_syntax_ndr.uuid == pbind->ctx_list[0].transfer_syntaxes[i].uuid &&
			pbind->ctx_list[0].transfer_syntaxes[i].version ==
			g_transfer_syntax_ndr.version) {
			b_found = TRUE;
			break;
		}
	}
	if (!b_found) {
		for (i=0; i<pbind->ctx_list[0].num_transfer_syntaxes; i++) {
			if (g_transfer_syntax_ndr64.uuid == pbind->ctx_list[0].transfer_syntaxes[i].uuid &&
				pbind->ctx_list[0].transfer_syntaxes[i].version ==
				g_transfer_syntax_ndr64.version) {
				b_found = TRUE;
				break;
			}
		}
		if (!b_found) {
			debug_info("[pdu_processor]: only NDR or NDR64 transfer syntax "
				"can be accepted by system\n");
			return pdu_processor_bind_nak(pcall, 0);
		}
		b_ndr64 = TRUE;
	}
	if (support_negotiate && b_found && pbind->num_contexts > 1 &&
	    memcmp(&pbind->ctx_list[0].abstract_syntax,
	    &pbind->ctx_list[1].abstract_syntax, sizeof(SYNTAX_ID)) == 0 &&
	    pbind->ctx_list[1].num_transfer_syntaxes > 0) {
		char uuid_str[GUIDSTR_SIZE];
		pbind->ctx_list[1].transfer_syntaxes[0].uuid.to_str(uuid_str, sizeof(uuid_str));
		if (0 == strncmp("6cb71c2c-9812-4540", uuid_str, 18)) {
			b_negotiate = TRUE;
		}
	}
	auto pinterface = pdu_processor_find_interface_by_uuid(
					pcall->pprocessor->pendpoint, &uuid, if_version);
	if (NULL == pinterface) {
		char uuid_str[GUIDSTR_SIZE];
		uuid.to_str(uuid_str, arsizeof(uuid_str));
		debug_info("[pdu_processor]: interface %s/%d unknown when binding\n",
			uuid_str, if_version);
		/* we don't know about that interface */
		result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;
		pcontext = NULL;
	} else {
		/* add this context to the list of available context_ids */
		pcontext = g_context_allocator->get();
		if (NULL == pcontext) {
			return pdu_processor_bind_nak(pcall, 0);
		}
		pcontext->node.pdata = pcontext;
		pcontext->pinterface = pinterface;
		pcontext->context_id = context_id;
		pcontext->b_ndr64 = b_ndr64;
		pcontext->stat_flags = 0;
		pcontext->pendpoint = pcall->pprocessor->pendpoint;
		if (0 == pbind->assoc_group_id) {
			pcall->pprocessor->assoc_group_id = 
				pdu_processor_allocate_group_id(pcall->pprocessor->pendpoint);
		} else {
			pcall->pprocessor->assoc_group_id = pbind->assoc_group_id;
		}
		pcontext->assoc_group_id = pcall->pprocessor->assoc_group_id;
		double_list_init(&pcontext->async_list);
		pcall->pcontext = pcontext;
		result = 0;
		reason = 0;
	}

	if (0 == pcall->pprocessor->cli_max_recv_frag) {
		if (pbind->max_recv_frag > 0x2000) {
			pcall->pprocessor->cli_max_recv_frag = 0x2000;
		} else {
			pcall->pprocessor->cli_max_recv_frag = pbind->max_recv_frag;
		}
	}

	extra_flags = 0;
	if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN &&
	    g_header_signing) {
		if (NULL != pcontext) {
			pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_HEADER_SIGNING;
		}
		extra_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) {
		if (NULL != pcontext) {
			pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_MULTIPLEXED;
		}
		extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	/* handle any authentication that is being requested */
	if (!pdu_processor_auth_bind(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall,
					DCERPC_BIND_REASON_INVALID_AUTH_TYPE);
	}
	if (!pdu_processor_auth_bind_ack(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_BIND_ACK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.payload.bind_ack.max_xmit_frag = pcall->pprocessor->cli_max_recv_frag;
	pkt.payload.bind_ack.max_recv_frag = 0x2000;
	pkt.payload.bind_ack.pad.data = NULL;
	pkt.payload.bind_ack.pad.length = 0;
	
	if (NULL != pcall->pcontext) {
		pkt.payload.bind_ack.assoc_group_id = pcall->pcontext->assoc_group_id;
	} else {
		pkt.payload.bind_ack.assoc_group_id = DUMMY_ASSOC_GROUP;
	}

	if (NULL != pinterface) {
		auto port2 = pdu_processor_find_secondary(
					pcall->pprocessor->pendpoint->host,
					pcall->pprocessor->pendpoint->tcp_port,
					&pinterface->uuid, pinterface->version);
		snprintf(pkt.payload.bind_ack.secondary_address, 64, "%hu", port2);
	} else {
		pkt.payload.bind_ack.secondary_address[0] = '\0';
	}
	if (!b_negotiate) {
		pkt.payload.bind_ack.num_contexts = 1;
		pkt.payload.bind_ack.ctx_list = me_alloc<DCERPC_ACK_CTX>(1);
		if (NULL == pkt.payload.bind_ack.ctx_list) {
			if (NULL != pcontext) {
				pdu_processor_free_context(pcontext);
			}
			return pdu_processor_bind_nak(pcall, 0);
		}
	} else {
		pkt.payload.bind_ack.num_contexts = 2;
		pkt.payload.bind_ack.ctx_list = me_alloc<DCERPC_ACK_CTX>(2);
		if (NULL == pkt.payload.bind_ack.ctx_list) {
			if (NULL != pcontext) {
				pdu_processor_free_context(pcontext);
			}
			return pdu_processor_bind_nak(pcall, 0);
		}
		pkt.payload.bind_ack.ctx_list[1].result =
				DCERPC_BIND_RESULT_NEGOTIATE_ACK;
		auto &u = pbind->ctx_list[1].transfer_syntaxes[0].uuid;
		char bitmap = pcall->b_bigendian ? u.node[5] : u.clock_seq[0];
		pkt.payload.bind_ack.ctx_list[1].reason = bitmap & DCERPC_SECURITY_CONTEXT_MULTIPLEXING;;
		memset(&pkt.payload.bind_ack.ctx_list[1].syntax, 0, sizeof(SYNTAX_ID));
	}
	pkt.payload.bind_ack.ctx_list[0].result = result;
	pkt.payload.bind_ack.ctx_list[0].reason = reason;
	pkt.payload.bind_ack.ctx_list[0].syntax = g_transfer_syntax_ndr;
	pkt.payload.bind_ack.auth_info.data = NULL;
	pkt.payload.bind_ack.auth_info.length = 0;
	
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		debug_info("[pdu_processor]: fata error in pdu_processor_process_bind"
			" cannot get auth_context from list\n");
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	auto pblob_node = g_bnode_allocator->get();
	if (NULL == pblob_node) {
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, &pauth_ctx->auth_info)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	if (NULL != pcontext) {
		double_list_insert_as_head(&pcall->pprocessor->context_list,
			&pcontext->node);
	}
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_process_auth3(DCERPC_CALL *pcall)
{
	uint32_t auth_length;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_NCACN_PACKET *ppkt;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	ppkt = &pcall->pkt;
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		return TRUE;
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	/* can't work without an existing state, and an new blob to feed it */
	if ((pauth_ctx->auth_info.auth_type == RPC_C_AUTHN_NONE &&
	    pauth_ctx->auth_info.auth_level == RPC_C_AUTHN_LEVEL_DEFAULT) ||
		NULL == pauth_ctx->pntlmssp ||
	    0 == ppkt->payload.auth3.auth_info.length) {
		goto AUTH3_FAIL;
	}
	
	pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
	if (!pdu_processor_pull_auth_trailer(ppkt,
	    &ppkt->payload.auth3.auth_info, &pauth_ctx->auth_info,
	    &auth_length, TRUE))
		goto AUTH3_FAIL;
	if (!ntlmssp_update(pauth_ctx->pntlmssp, &pauth_ctx->auth_info.credentials))
		goto AUTH3_FAIL;
	if (!ntlmssp_session_info(pauth_ctx->pntlmssp, &pauth_ctx->session_info)) {
		debug_info("[pdu_processor]: failed to establish session_info\n");
		goto AUTH3_FAIL;
	}
	if (pauth_ctx->auth_info.auth_type != RPC_C_AUTHN_NONE)
		pauth_ctx->is_login = TRUE;
	return TRUE;
	
 AUTH3_FAIL:
	double_list_remove(&pcall->pprocessor->auth_list, pnode);
	pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
	if (NULL != pauth_ctx->pntlmssp) {
		ntlmssp_destroy(pauth_ctx->pntlmssp);
		pauth_ctx->pntlmssp = NULL;
	}
	g_auth_allocator->put(pauth_ctx);
	return TRUE;
}

static BOOL pdu_processor_auth_alter(DCERPC_CALL *pcall)
{
	return pdu_processor_auth_bind(pcall);
}

static BOOL pdu_processor_auth_alter_ack(DCERPC_CALL *pcall)
{
	return pdu_processor_auth_bind_ack(pcall);
}

static BOOL pdu_processor_process_alter(DCERPC_CALL *pcall)
{
	int i;
	GUID uuid;
	BOOL b_ndr64;
	BOOL b_found;
	uint32_t result = 0, reason = 0;
	uint32_t if_version;
	uint32_t context_id;
	DCERPC_BIND *palter;
	uint32_t extra_flags;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext = nullptr;
	PDU_PROCESSOR *pprocessor;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	palter = &pcall->pkt.payload.alter;
	pprocessor = pcall->pprocessor;
	
	
	if (palter->num_contexts < 1 ||
	    palter->ctx_list[0].num_transfer_syntaxes < 1) {
		result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;
		goto ALTER_ACK;
	}
	
	/* cannot process alter before bind */
	if (0 == pcall->pprocessor->assoc_group_id) {
		result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;
		goto ALTER_ACK;
	}
		
	if_version = palter->ctx_list[0].abstract_syntax.version;
	uuid = palter->ctx_list[0].abstract_syntax.uuid;
	context_id = palter->ctx_list[0].context_id;

	/* check if they are asking for a new interface */
	pcontext = NULL;
	pcall->pcontext = pdu_processor_find_context(pprocessor, context_id);
	if (NULL == pcall->pcontext) {
		b_ndr64 = FALSE;
		b_found = FALSE;
		
		for (i=0; i<palter->ctx_list[0].num_transfer_syntaxes; i++) {
			if (g_transfer_syntax_ndr.uuid == palter->ctx_list[0].transfer_syntaxes[i].uuid &&
				palter->ctx_list[0].transfer_syntaxes[i].version ==
				g_transfer_syntax_ndr.version) {
				b_found = TRUE;
				break;
			}
		}
		if (!b_found) {
			for (i=0; i<palter->ctx_list[0].num_transfer_syntaxes; i++) {
				if (g_transfer_syntax_ndr64.uuid == palter->ctx_list[0].transfer_syntaxes[i].uuid &&
					palter->ctx_list[0].transfer_syntaxes[i].version ==
					g_transfer_syntax_ndr64.version) {
					b_found = TRUE;
					break;
				}
			}
			if (!b_found) {
				debug_info("[pdu_processor]: only NDR or NDR64 transfer syntax "
					"can be accepted by system\n");
				result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
				reason = DCERPC_BIND_REASON_ASYNTAX;
				goto ALTER_ACK;
			}
			b_ndr64 = TRUE;
		}

		auto pinterface = pdu_processor_find_interface_by_uuid(pprocessor->pendpoint,
						&uuid, if_version);
		if (NULL == pinterface) {
			char uuid_str[GUIDSTR_SIZE];
			uuid.to_str(uuid_str, arsizeof(uuid_str));
			debug_info("[pdu_processor]: interface %s/%d unknown when altering\n",
				uuid_str, if_version);
			result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
			reason = DCERPC_BIND_REASON_ASYNTAX;
			goto ALTER_ACK;
		}

		if (double_list_get_nodes_num(&pprocessor->context_list) >
			MAX_CONTEXTS_PER_CONNECTION) {
			debug_info("[pdu_processor]: maximum rpc contexts"
				" number of connection reached\n");
			result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
			reason = DECRPC_BIND_REASON_LOCAL_LIMIT_EXCEEDED;
			goto ALTER_ACK;
		}
		/* add this context to the list of available context_ids */
		pcontext = g_context_allocator->get();
		if (NULL == pcontext) {
			result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
			reason = DECRPC_BIND_REASON_LOCAL_LIMIT_EXCEEDED;
			goto ALTER_ACK;
		}
		pcontext->node.pdata = pcontext;
		pcontext->pinterface = pinterface;
		pcontext->context_id = context_id;
		pcontext->b_ndr64 = b_ndr64;
		pcontext->pendpoint = pprocessor->pendpoint;
		pcontext->assoc_group_id = pprocessor->assoc_group_id;
		
		double_list_init(&pcontext->async_list);
		pcall->pcontext = pcontext;
		result = 0;
		reason = 0;
	}
	
 ALTER_ACK:
	extra_flags = 0;
	if (0 == result) {
		if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN &&
		    g_header_signing) {
			if (NULL != pcontext) {
				pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_HEADER_SIGNING;
			}
			extra_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
		} else {
			if (NULL != pcontext) {
				pcontext->stat_flags &= ~DCERPC_CALL_STAT_FLAG_HEADER_SIGNING;
			}
		}
		if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) {
			if (NULL != pcontext) {
				pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_MULTIPLEXED;
			}
			extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
		} else {
			if (NULL != pcontext) {
				pcontext->stat_flags &= ~DCERPC_CALL_STAT_FLAG_MULTIPLEXED;
			}
		}
	}
	if (!pdu_processor_auth_alter(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	if (!pdu_processor_auth_alter_ack(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	
	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_ALTER_ACK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.payload.alter_ack.max_xmit_frag = 0x2000;
	pkt.payload.alter_ack.max_recv_frag = 0x2000;
	pkt.payload.alter_ack.pad.data = NULL;
	pkt.payload.alter_ack.pad.length = 0;
	
	if (NULL != pcontext) {
		pkt.payload.alter_ack.assoc_group_id = pcall->pcontext->assoc_group_id;
	} else {
		pkt.payload.alter_ack.assoc_group_id = DUMMY_ASSOC_GROUP;
	}
	
	pkt.payload.alter_ack.secondary_address[0] = '\0';
	
	pkt.payload.alter_ack.num_contexts = 1;
	pkt.payload.alter_ack.ctx_list = me_alloc<DCERPC_ACK_CTX>(1);
	if (NULL == pkt.payload.alter_ack.ctx_list) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	pkt.payload.alter_ack.ctx_list[0].result = result;
	pkt.payload.alter_ack.ctx_list[0].reason = reason;
	pkt.payload.alter_ack.ctx_list[0].syntax = g_transfer_syntax_ndr;
	pkt.payload.alter_ack.auth_info.data = NULL;
	pkt.payload.alter_ack.auth_info.length = 0;
	
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		debug_info("[pdu_processor]: fata error in pdu_processor_process_alter"
			" cannot get auth_context from list\n");
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	
	auto pblob_node = g_bnode_allocator->get();
	if (NULL == pblob_node) {
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	if (!pdu_processor_ncacn_push_with_auth(
		&pblob_node->blob, &pkt, &pauth_ctx->auth_info)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	if (NULL != pcontext) {
		double_list_insert_as_head(&pprocessor->context_list, &pcontext->node);
	}
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

/* push a signed or sealed dcerpc request packet into a blob */
static BOOL pdu_processor_auth_response(DCERPC_CALL *pcall,
	DATA_BLOB *pblob, size_t sig_size, DCERPC_NCACN_PACKET *ppkt)
{
	NDR_PUSH ndr;
	uint32_t flags;
	DATA_BLOB creds2;
	uint8_t creds2_buff[16];
	uint32_t payload_length;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	char ndr_buff[DCERPC_BASE_MARSHALL_SIZE];

	
	creds2.data = creds2_buff;
	creds2.length = 0;
	pauth_ctx = pcall->pauth_ctx;
	/* non-signed packets are simple */
	if (0 == sig_size) {
		return pdu_processor_ncacn_push_with_auth(pblob, ppkt, NULL);
	}

	switch (pauth_ctx->auth_info.auth_level) {
	case RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
	case RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
		break;
	case RPC_C_AUTHN_LEVEL_CONNECT:
	case RPC_C_AUTHN_LEVEL_NONE:
	case RPC_C_AUTHN_LEVEL_DEFAULT:
		return pdu_processor_ncacn_push_with_auth(pblob, ppkt, NULL);
	default:
		return FALSE;
	}
	
	flags = 0;
	if (pcall->b_bigendian) {
		flags |= NDR_FLAG_BIGENDIAN;
	}
	if (pcall->pcontext->b_ndr64)
		flags |= NDR_FLAG_NDR64;
	ndr_push_init(&ndr, ndr_buff, DCERPC_BASE_MARSHALL_SIZE, flags);
	
	if (NDR_ERR_SUCCESS != pdu_ndr_push_ncacnpkt(&ndr, ppkt)) {
		return FALSE;
	}
	
	pauth_ctx->auth_info.auth_pad_length =
		(16 - (ppkt->payload.response.stub_and_verifier.length & 15)) & 15;
	if (NDR_ERR_SUCCESS != ndr_push_zero(&ndr,
		pauth_ctx->auth_info.auth_pad_length)) {
		return FALSE;
	}

	payload_length = ppkt->payload.response.stub_and_verifier.length +
						pauth_ctx->auth_info.auth_pad_length;

	/* start without signature, will be appended later */
	if (NULL != pauth_ctx->auth_info.credentials.data) {
		free(pauth_ctx->auth_info.credentials.data);
		pauth_ctx->auth_info.credentials.data = NULL;
	}
	pauth_ctx->auth_info.credentials.length = 0;
	
	/* change back into NDR */
	if (pcall->pcontext->b_ndr64)
		ndr.flags &= ~NDR_FLAG_NDR64;
	/* add the auth verifier */
	if (NDR_ERR_SUCCESS != pdu_ndr_push_dcerpc_auth(&ndr,
		&pauth_ctx->auth_info)) {
		return FALSE;
	}

	/* extract the whole packet as a blob */
	pblob->data = ndr.data;
	pblob->length = ndr.offset;
	
	pdu_processor_set_frag_length(pblob, pblob->length + sig_size);
	pdu_processor_set_auth_length(pblob, sig_size);

	/* sign or seal the packet */
	switch (pauth_ctx->auth_info.auth_level) {
	case RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
		if (!ntlmssp_seal_packet(pauth_ctx->pntlmssp,
		    ndr.data + DCERPC_REQUEST_LENGTH, payload_length,
		    pblob->data, pblob->length, &creds2))
			return FALSE;
		break;
	case RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
		if (!ntlmssp_sign_packet(pauth_ctx->pntlmssp,
		    ndr.data + DCERPC_REQUEST_LENGTH, payload_length,
		    pblob->data, pblob->length, &creds2))
			return FALSE;
		break;

	default:
		return FALSE;
	}

	if (creds2.length != sig_size) {
		debug_info("[pdu_processor]: auth_response: creds2.length[%u] != "
			"sig_size[%u] pad[%u] stub[%u]\n", creds2.length, (uint32_t)sig_size,
			pauth_ctx->auth_info.auth_pad_length,
			ppkt->payload.response.stub_and_verifier.length);
		pdu_processor_set_frag_length(pblob, pblob->length + creds2.length);
		pdu_processor_set_auth_length(pblob, creds2.length);
	}

	auto pdata = me_alloc<uint8_t>(pblob->cb + creds2.cb);
	if (NULL == pdata) {
		return FALSE;
	}
	memcpy(pdata, pblob->data, pblob->length);
	memcpy(&pdata[pblob->cb], creds2.data, creds2.cb);
	pblob->pb = pdata;
	pblob->length += creds2.length;
	
	return TRUE;
}

static DCERPC_CALL* pdu_processor_get_call()
{
	return g_call_key;
}

static BOOL pdu_processor_reply_request(DCERPC_CALL *pcall,
	NDR_STACK_ROOT *pstack_root, void *pout)
{
	void *pdata;
	uint32_t flags;
	DATA_BLOB stub;
	uint32_t length;
	size_t sig_size;
	size_t alloc_size;
	NDR_PUSH ndr_push;
	uint32_t chunk_size;
	uint32_t total_length;
	DCERPC_REQUEST *prequest;
	
	
	flags = 0;
	if (pcall->b_bigendian)
		flags |= NDR_FLAG_BIGENDIAN;
	if (pcall->pcontext->b_ndr64)
		flags |= NDR_FLAG_NDR64;
	prequest = &pcall->pkt.payload.request;
	
	alloc_size = pdu_processor_ndr_stack_size(pstack_root, NDR_STACK_OUT);
	alloc_size = 2 * alloc_size + 1024;
	pdata = malloc(alloc_size);
	if (NULL == pdata) {
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: push fail on RPC call %u on %s\n",
			prequest->opnum, pcall->pcontext->pinterface->name);
		return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
	}
	ndr_push_init(&ndr_push, pdata, alloc_size, flags);
	
	ndr_push_set_ptrcnt(&ndr_push, pcall->ptr_cnt);
	
	/* marshaling the NDR out param data */
	auto ret = pcall->pcontext->pinterface->ndr_push(prequest->opnum, &ndr_push, pout);
	if (ret != EXT_ERR_SUCCESS) {
		fprintf(stderr, "E-1918: ndr_push failed with result code %d\n", ret);
		free(pdata);
		pdu_processor_free_stack_root(pstack_root);
		return pdu_processor_fault(pcall, DCERPC_FAULT_NDR);
	}
	pdu_processor_free_stack_root(pstack_root);
	
	stub.data = ndr_push.data;
	stub.length = ndr_push.offset;

	total_length = stub.length;
	
	sig_size = 0;
	
	/* full max_recv_frag size minus the dcerpc request header size */
	chunk_size = pcall->pprocessor->cli_max_recv_frag;
	chunk_size -= DCERPC_REQUEST_LENGTH;
	if (pcall->pauth_ctx->auth_info.auth_type != RPC_C_AUTHN_NONE &&
	    pcall->pauth_ctx->auth_info.auth_level != RPC_C_AUTHN_LEVEL_DEFAULT &&
	    pcall->pauth_ctx->auth_info.auth_level != RPC_C_AUTHN_LEVEL_NONE &&
		NULL != pcall->pauth_ctx->pntlmssp) {
		sig_size = ntlmssp_sig_size();
		if (0 != sig_size) {
			chunk_size -= DCERPC_AUTH_TRAILER_LENGTH;
			chunk_size -= sig_size;
		}
	}
	chunk_size -= chunk_size % 16;

	/* Fragmentation into Transport Service Data Units (TSDU) */
	do {
		auto pblob_node = g_bnode_allocator->get();
		if (NULL == pblob_node) {
			free(pdata);
			return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
		}
		pblob_node->node.pdata = pblob_node;
		pblob_node->b_rts = FALSE;

		if (chunk_size > stub.length) {
			length = stub.length;
		} else {
			length = chunk_size;
		}

		/* form the dcerpc response packet */
		dcerpc_ncacn_packet pkt(pcall->b_bigendian);
		pkt.call_id = pcall->pkt.call_id;
		pkt.pkt_type = DCERPC_PKT_RESPONSE;
		pkt.pfc_flags = 0;
		if (stub.length == total_length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_FIRST;
		}
		if (length == stub.length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_LAST;
		}
		pkt.payload.response.alloc_hint = stub.length;
		pkt.payload.response.context_id = prequest->context_id;
		pkt.payload.response.cancel_count = 0;
		pkt.payload.response.pad.data = prequest->pad.data;
		pkt.payload.response.pad.length = prequest->pad.length;
		pkt.payload.response.stub_and_verifier.data = stub.data;
		pkt.payload.response.stub_and_verifier.length = length;

		if (!pdu_processor_auth_response(pcall,
			&pblob_node->blob, sig_size, &pkt)) {
			g_bnode_allocator->put(pblob_node);
			free(pdata);
			return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
		}

		double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);

		stub.data += length;
		stub.length -= length;
	} while (stub.length != 0);
	free(pdata);
	return TRUE;
}

static uint32_t pdu_processor_apply_async_id()
{
	int async_id;
	DCERPC_CALL *pcall;
	HTTP_CONTEXT *pcontext;
	ASYNC_NODE *pfake_async;
	RPC_IN_CHANNEL *pchannel_in;
	
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return 0;
	}
	auto pstack_root = g_stack_key;
	if (NULL == pstack_root) {
		return 0;
	}
	if (double_list_get_nodes_num(&pcall->pcontext->async_list) >= MAX_SYNC_PER_CONTEXT) {
		debug_info("[pdu_processor]: maximum async contexts"
			" number of connection reached\n");
		return 0;
	}
	pcontext = http_parser_get_context();
	if (NULL == pcontext) {
		return 0;
	}
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return 0;
	}
	pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
	auto pasync_node = g_async_allocator->get();
	if (NULL == pasync_node) {
		return 0;
	}
	pasync_node->node.pdata = pasync_node;
	pasync_node->b_cancelled = FALSE;
	pasync_node->pcall = pcall;
	pasync_node->pstack_root = pstack_root;
	gx_strlcpy(pasync_node->vconn_host, pcontext->host, arsizeof(pasync_node->vconn_host));
	pasync_node->vconn_port = pcontext->port;
	strcpy(pasync_node->vconn_cookie, pchannel_in->connection_cookie);
	
	std::unique_lock as_hold(g_async_lock);
	g_last_async_id ++;
	async_id = g_last_async_id;
	if (g_last_async_id >= INT32_MAX)
		g_last_async_id = 0;
	pfake_async = NULL;
	if (g_async_hash->add(async_id, &pfake_async) != 1) {
		as_hold.unlock();
		g_async_allocator->put(pasync_node);
		return 0;
	}
	pasync_node->async_id = async_id;
	double_list_append_as_tail(&pcall->pcontext->async_list,
		&pasync_node->node);
	return async_id;
}

static void pdu_processor_activate_async_id(uint32_t async_id)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return;
	}
	std::lock_guard as_hold(g_async_lock);
	auto ppasync_node = g_async_hash->query<ASYNC_NODE *>(async_id);
	if (NULL == ppasync_node || NULL != *ppasync_node) {
		return;
	}
	for (pnode=double_list_get_head(&pcall->pcontext->async_list); NULL!=pnode;
		pnode=double_list_get_after(&pcall->pcontext->async_list, pnode)) {
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		if (pasync_node->async_id == async_id) {
			*ppasync_node = pasync_node;
			break;
		}
	}
}

static void pdu_processor_cancel_async_id(uint32_t async_id)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return;
	}
	std::unique_lock as_hold(g_async_lock);
	auto ppasync_node = g_async_hash->query<ASYNC_NODE *>(async_id);
	if (NULL == ppasync_node || NULL != *ppasync_node) {
		return;
	}
	for (pnode=double_list_get_head(&pcall->pcontext->async_list); NULL!=pnode;
		pnode=double_list_get_after(&pcall->pcontext->async_list, pnode)) {
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		if (pasync_node->async_id == async_id) {
			g_async_hash->remove(async_id);
			double_list_remove(&pcall->pcontext->async_list, pnode);
			break;
		}
	}
	as_hold.unlock();
	if (NULL != pnode) {
		g_async_allocator->put(pasync_node);
	}
}

/* to check if the async_id is still available and
   then lock the async_id in async hash table */
static BOOL pdu_processor_rpc_build_environment(int async_id)
{
	ASYNC_NODE *pasync_node;
	
 BUILD_BEGIN:
	std::unique_lock as_hold(g_async_lock);
	auto ppasync_node = g_async_hash->query<ASYNC_NODE *>(async_id);
	if (NULL == ppasync_node) {
		return FALSE;
	} else if (NULL == *ppasync_node) {
		as_hold.unlock();
		usleep(10000);
		goto BUILD_BEGIN;
	}
	pasync_node = *ppasync_node;
	/* remove from async hash table to forbidden
		cancel pdu while async replying */
	g_async_hash->remove(async_id);
	as_hold.unlock();
	g_call_key = pasync_node->pcall;
	g_stack_key = pasync_node->pstack_root;
	/* Later unset by calling free_call */
	return TRUE;
}

/* only can be invoked in non-rpc thread */
BOOL pdu_processor_rpc_new_stack()
{
	NDR_STACK_ROOT *pstack_root;
	
	pstack_root = pdu_processor_new_stack_root();
	if (NULL == pstack_root) {
		return FALSE;
	}
	g_stack_key = pstack_root;
	return TRUE;
}

/* only can be invoked in non-rpc thread */
void pdu_processor_rpc_free_stack()
{
	auto pstack_root = g_stack_key;
	if (NULL != pstack_root) {
		g_stack_key = nullptr;
		pdu_processor_free_stack_root(pstack_root);
	}
}

static void pdu_processor_async_reply(uint32_t async_id, void *pout)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	
	/* Caller needs to have invoked rpc_build_environment */
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return;
	}
	std::unique_lock as_hold(g_async_lock);
	for (pnode=double_list_get_head(&pcall->pcontext->async_list); NULL!=pnode;
		pnode=double_list_get_after(&pcall->pcontext->async_list, pnode)) {
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		if (pasync_node->async_id == async_id) {
			break;
		}
	}
	if (pnode == nullptr || pasync_node == nullptr)
		return;
	double_list_remove(&pcall->pcontext->async_list, pnode);
	if (pcall->pprocessor->async_num < 0 || pasync_node->b_cancelled) {
		as_hold.unlock();
		pdu_processor_free_stack_root(pasync_node->pstack_root);
		pdu_processor_free_call(pasync_node->pcall);
		g_async_allocator->put(pasync_node);
		return;
	}
	pcall->pprocessor->async_num ++;
	as_hold.unlock();
	/* stack root will be freed in pdu_processor_reply_request */
	if (pdu_processor_reply_request(pcall, pasync_node->pstack_root, pout)) {
		as_hold.lock();
		pcall->pprocessor->async_num --;
		as_hold.unlock();
		http_parser_vconnection_async_reply(pasync_node->vconn_host,
			pasync_node->vconn_port, pasync_node->vconn_cookie,
			pasync_node->pcall);
	} else {
		as_hold.lock();
		pcall->pprocessor->async_num --;
		as_hold.unlock();
	}
	pdu_processor_free_call(pasync_node->pcall);
	g_async_allocator->put(pasync_node);
}

static BOOL pdu_processor_process_request(DCERPC_CALL *pcall, BOOL *pb_async)
{
	GUID *pobject;
	uint32_t flags;
	uint64_t handle;
	void *pin, *pout;
	NDR_PULL ndr_pull;
	DCERPC_REQUEST *prequest;
	DCERPC_CONTEXT *pcontext;
	PDU_PROCESSOR *pprocessor;
	NDR_STACK_ROOT *pstack_root;
	
	
	pprocessor = pcall->pprocessor;
	prequest = &pcall->pkt.payload.request;
	pcontext = pdu_processor_find_context(pprocessor, prequest->context_id);
	if (NULL == pcontext) {
		return pdu_processor_fault(pcall, DCERPC_FAULT_UNK_IF);
	}
	
	/* normally, stack root will be freed in pdu_processor_reply_request */
	pstack_root = pdu_processor_new_stack_root();
	if (NULL == pstack_root) {
		return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
	}
	
	g_call_key = pcall;
	g_stack_key = pstack_root;
	auto cl_0 = make_scope_exit([]() {
		g_stack_key = nullptr;
		g_call_key = nullptr;
	});
	flags = 0;
	if (pcall->b_bigendian)
		flags |= NDR_FLAG_BIGENDIAN;
	if (pcontext->b_ndr64)
		flags |= NDR_FLAG_NDR64;
	ndr_pull_init(&ndr_pull, prequest->stub_and_verifier.data,
		prequest->stub_and_verifier.length, flags);
	
	pcall->pcontext	= pcontext;
	
	/* unmarshaling the NDR in param data */
	if (NDR_ERR_SUCCESS != pcontext->pinterface->ndr_pull(
		prequest->opnum, &ndr_pull, &pin)) {
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: pull fail on RPC call %u on %s\n",
			prequest->opnum, pcontext->pinterface->name);
		return pdu_processor_fault(pcall, DCERPC_FAULT_NDR);
	}
	
	pcall->ptr_cnt = ndr_pull_get_ptrcnt(&ndr_pull);
	
	if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		pobject = &prequest->object.object;
	} else {
		pobject = NULL;
	}
	
	handle = pcall->pcontext->assoc_group_id;
	handle <<= 32;
	handle |= pcall->pcontext->context_id;
	*pb_async = false;
	/* call the dispatch function */
	uint32_t ecode = 0;
	auto ret = pcontext->pinterface->dispatch(prequest->opnum,
	           pobject, handle, pin, &pout, &ecode);
	bool dbg = g_msrpc_debug >= 2;
	if (g_msrpc_debug >= 1 &&
	    (ret != DISPATCH_SUCCESS || ecode != ecSuccess))
		dbg = true;
	if (dbg)
		fprintf(stderr, "rpc_dispatch(%s, %u) EC=%xh RS=%d\n",
		        pcontext->pinterface->name, prequest->opnum,
		        static_cast<unsigned int>(ecode), ret);
	switch (ret) {
	case DISPATCH_FAIL:
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: RPC execution fault in call %s:%02x\n",
			pcontext->pinterface->name, prequest->opnum);
		return pdu_processor_fault(pcall, DCERPC_FAULT_OP_RNG_ERROR);
	case DISPATCH_PENDING:
		*pb_async = TRUE;
		return TRUE;
	case DISPATCH_SUCCESS:
		return pdu_processor_reply_request(pcall, pstack_root, pout);
	default:
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: unknown return value by %s:%02x\n",
			pcontext->pinterface->name, prequest->opnum);
		return pdu_processor_fault(pcall, DCERPC_FAULT_OP_RNG_ERROR);
	}
}

static void pdu_processor_process_cancel(DCERPC_CALL *pcall)
{
	int async_id;
	BOOL b_cancel;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode, *pnode1 = nullptr;
	DCERPC_CONTEXT *pcontext = nullptr;
	ASYNC_NODE *pasync_node = nullptr;
	
	async_id = 0;
	b_cancel = FALSE;
	std::unique_lock as_hold(g_async_lock);
	plist = &pcall->pprocessor->context_list;
	for (pnode = double_list_pop_front(plist); pnode != nullptr;
		pnode=double_list_get_after(plist, pnode)) {
		pcontext = (DCERPC_CONTEXT*)pnode->pdata;
		for (pnode1=double_list_get_head(&pcontext->async_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pcontext->async_list, pnode1)) {
			pasync_node = (ASYNC_NODE*)pnode1->pdata;
			if (pasync_node->pcall->pkt.call_id == pcall->pkt.call_id) {
				async_id = pasync_node->async_id;
				pasync_node->b_cancelled = TRUE;
				break;
			}
		}
	}
	if (0 != async_id) {
		auto ppasync_node = g_async_hash->query<ASYNC_NODE *>(async_id);
		if (NULL != ppasync_node && NULL != *ppasync_node) {
			b_cancel = TRUE;
			g_async_hash->remove(async_id);
			double_list_remove(&pcontext->async_list, pnode1);
		}
	}
	as_hold.unlock();
	if (b_cancel) {
		if (NULL != pcontext->pinterface->reclaim) {
			pcontext->pinterface->reclaim(async_id);
		}
		pdu_processor_free_stack_root(pasync_node->pstack_root);
		pdu_processor_free_call(pasync_node->pcall);
		g_async_allocator->put(pasync_node);
	}
}

static void pdu_processor_process_orphaned(DCERPC_CALL *pcall)
{
	DCERPC_CALL *pcallx;
	
	pcallx = pdu_processor_get_fragmented_call(
		pcall->pprocessor, pcall->pkt.call_id);
	if (NULL != pcallx) {
		pdu_processor_free_call(pcallx);
	}
}

void pdu_processor_rts_echo(char *pbuff)
{
	int flags;
	NDR_PUSH ndr;
	dcerpc_ncacn_packet pkt(g_bigendian);
	
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.frag_length = 20;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_ECHO;
	pkt.payload.rts.num = 0;
	pkt.payload.rts.commands = NULL;
	
	if (g_bigendian)
		flags = NDR_FLAG_BIGENDIAN;
	else
		flags = 0;
	ndr_push_init(&ndr, pbuff, 20, flags);
	pdu_ndr_push_ncacnpkt(&ndr, &pkt);
	ndr_push_destroy(&ndr);
}

BOOL pdu_processor_rts_ping(DCERPC_CALL *pcall)
{
	dcerpc_ncacn_packet pkt(pcall->b_bigendian);

	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_PING;
	pkt.payload.rts.num = 0;
	pkt.payload.rts.commands = NULL;

	auto pblob_node = g_bnode_allocator->get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}

	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_conn_b1(DCERPC_CALL *pcall,
    char *conn_cookie, size_t conn_ck_size, char *chan_cookie,
    size_t chan_ck_size, uint32_t *plife_time, time_duration *pclient_keepalive,
    char *associationgroupid, size_t gid_size)
{
	DCERPC_RTS *prts;
	
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (6 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	prts->commands[1].command.cookie.to_str(conn_cookie, conn_ck_size);
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	prts->commands[2].command.cookie.to_str(chan_cookie, chan_ck_size);
	if (RTS_CMD_CHANNEL_LIFETIME != prts->commands[3].command_type) {
		return FALSE;
	}
	*plife_time = prts->commands[3].command.channellifetime;
	
	if (RTS_CMD_CLIENT_KEEPALIVE != prts->commands[4].command_type) {
		return FALSE;
	}
	*pclient_keepalive = std::chrono::milliseconds(prts->commands[4].command.clientkeepalive);
	if (RTS_CMD_ASSOCIATION_GROUP_ID !=
		prts->commands[5].command_type) {
		return FALSE;
	}
	prts->commands[5].command.associationgroupid.to_str(associationgroupid, gid_size);
	return TRUE;
}

static BOOL pdu_processor_retrieve_conn_a1(DCERPC_CALL *pcall,
    char *conn_cookie, size_t conn_ck_size, char *chan_cookie,
    size_t chan_ck_size, uint32_t *pwindow_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (4 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	prts->commands[1].command.cookie.to_str(conn_cookie, conn_ck_size);
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	prts->commands[2].command.cookie.to_str(chan_cookie, chan_ck_size);
	if (RTS_CMD_RECEIVE_WINDOW_SIZE != prts->commands[3].command_type) {
		return FALSE;
	}
	*pwindow_size = prts->commands[3].command.receivewindowsize;
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_inr2_a1(DCERPC_CALL *pcall,
    char *conn_cookie, size_t conn_ck_size, char *pred_cookie,
    size_t pred_ck_size, char *succ_cookie, size_t succ_ck_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (4 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_VERSION != prts->commands[0].command_type) {
		return FALSE;
	}
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	prts->commands[1].command.cookie.to_str(conn_cookie, conn_ck_size);
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	prts->commands[2].command.cookie.to_str(pred_cookie, pred_ck_size);
	if (RTS_CMD_COOKIE != prts->commands[3].command_type) {
		return FALSE;
	}
	prts->commands[3].command.cookie.to_str(succ_cookie, succ_ck_size);
	return TRUE;
}

static BOOL pdu_processor_retrieve_inr2_a5(DCERPC_CALL *pcall,
    char *succ_cookie, size_t succ_ck_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (1 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	prts->commands[1].command.cookie.to_str(succ_cookie, succ_ck_size);
	return TRUE;
}

static BOOL pdu_processor_retrieve_outr2_a7(DCERPC_CALL *pcall,
    char *succ_cookie, size_t succ_ck_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (3 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_DESTINATION != prts->commands[0].command_type) {
		return FALSE;
	}
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	prts->commands[1].command.cookie.to_str(succ_cookie, succ_ck_size);
	if (RTS_CMD_VERSION != prts->commands[2].command_type) {
		return FALSE;
	}
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_outr2_a3(DCERPC_CALL *pcall,
    char *conn_cookie, size_t conn_ck_size, char *pred_cookie,
    size_t pred_ck_size, char *succ_cookie, size_t succ_ck_size,
    uint32_t *pwindow_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (5 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_VERSION != prts->commands[0].command_type) {
		return FALSE;
	}
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	prts->commands[1].command.cookie.to_str(conn_cookie, conn_ck_size);
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	prts->commands[2].command.cookie.to_str(pred_cookie, pred_ck_size);
	if (RTS_CMD_COOKIE != prts->commands[3].command_type) {
		return FALSE;
	}
	prts->commands[3].command.cookie.to_str(succ_cookie, succ_ck_size);
	if (RTS_CMD_RECEIVE_WINDOW_SIZE != prts->commands[4].command_type) {
		return FALSE;
	}
	*pwindow_size = prts->commands[4].command.receivewindowsize;
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_outr2_c1(DCERPC_CALL *pcall)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (1 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_EMPTY != prts->commands[0].command_type &&
		RTS_CMD_PADDING != prts->commands[0].command_type) {
		return FALSE;
	}
	
	return TRUE;
	
}

static BOOL pdu_processor_retrieve_keep_alive(DCERPC_CALL *pcall,
    time_duration *pkeep_alive)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (1 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_CLIENT_KEEPALIVE != prts->commands[0].command_type) {
		return FALSE;
	}
	*pkeep_alive = std::chrono::milliseconds(prts->commands[0].command.clientkeepalive);
	return TRUE;
}

static BOOL pdu_processor_retrieve_flowcontrolack_withdestination(
	DCERPC_CALL *pcall)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (2 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_DESTINATION != prts->commands[0].command_type ||
		RTS_CMD_FLOW_CONTROL_ACK != prts->commands[1].command_type) {
		return FALSE;
	}
	return TRUE;
}

static BOOL pdu_processor_rts_conn_a3(DCERPC_CALL *pcall)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(1);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_CONNECTION_TIMEOUT;
	pkt.payload.rts.commands[0].command.connectiontimeout =
							http_parser_get_param(HTTP_SESSION_TIMEOUT)*1000;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_conn_c2(DCERPC_CALL *pcall, uint32_t in_window_size)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 3;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(3);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_VERSION;
	pkt.payload.rts.commands[0].command.version = 1;
	pkt.payload.rts.commands[1].command_type = RTS_CMD_RECEIVE_WINDOW_SIZE;
	pkt.payload.rts.commands[1].command.receivewindowsize = in_window_size;
	pkt.payload.rts.commands[2].command_type = RTS_CMD_CONNECTION_TIMEOUT;
	pkt.payload.rts.commands[2].command.connectiontimeout =
							http_parser_get_param(HTTP_SESSION_TIMEOUT)*1000;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_rts_inr2_a4(DCERPC_CALL *pcall)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(1);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_outr2_a2(DCERPC_CALL *pcall)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_RECYCLE_CHANNEL;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(1);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_outr2_a6(DCERPC_CALL *pcall)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 2;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(2);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	
	pkt.payload.rts.commands[1].command_type = RTS_CMD_ANCE;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_outr2_b3(DCERPC_CALL *pcall)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_EOF;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(1);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_ANCE;
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_flowcontrolack_withdestination(
	DCERPC_CALL *pcall, uint32_t bytes_received,
	uint32_t available_window, const char *channel_cookie)
{
	auto pblob_node = g_bnode_allocator.get();
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	dcerpc_ncacn_packet pkt(pcall->b_bigendian);
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_OTHER_CMD;
	pkt.payload.rts.num = 2;
	pkt.payload.rts.commands = me_alloc<RTS_CMD>(2);
	if (NULL == pkt.payload.rts.commands) {
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	
	pkt.payload.rts.commands[1].command_type = RTS_CMD_FLOW_CONTROL_ACK;
	auto &fc = pkt.payload.rts.commands[1].command.flowcontrolack;
	fc.bytes_received = bytes_received;
	fc.available_window = available_window;
	if (!fc.channel_cookie.from_str(channel_cookie)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	if (!pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		g_bnode_allocator->put(pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

int pdu_processor_rts_input(const char *pbuff, uint16_t length,
	DCERPC_CALL **ppcall)
{
	NDR_PULL ndr;
	uint32_t flags;
	BOOL b_bigendian;
	HTTP_CONTEXT *pcontext;
	RPC_IN_CHANNEL *pchannel_in;
	RPC_OUT_CHANNEL *pchannel_out;
	
	/* only rts pdu can be processed by this function */
	if (pbuff[DCERPC_PTYPE_OFFSET] != DCERPC_PKT_RTS)
		return PDU_PROCESSOR_FORWARD;
	flags = 0;
	if (!(pbuff[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE)) {
		flags |= NDR_FLAG_BIGENDIAN;
		b_bigendian = TRUE;
	} else {
		b_bigendian = FALSE;
	}
	if (pbuff[DCERPC_PFC_OFFSET] & DCERPC_PFC_FLAG_OBJECT_UUID)
		flags |= NDR_FLAG_OBJECT_PRESENT;
	pcontext = http_parser_get_context();
	if (NULL == pcontext) {
		return PDU_PROCESSOR_ERROR;
	}
	
	ndr_pull_init(&ndr, (uint8_t *)pbuff, length, flags);
	auto pcall = g_call_allocator->get();
	if (NULL == pcall) {
		return PDU_PROCESSOR_ERROR;
	}
	pcall->b_bigendian = b_bigendian;
	if (NDR_ERR_SUCCESS != pdu_ndr_pull_ncacnpkt(&ndr, &pcall->pkt)) {
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	}
	pcall->pkt_loaded = TRUE;
	
	
	if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
		pchannel_out = (RPC_OUT_CHANNEL*)pcontext->pchannel;
		if (76 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_out->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (RTS_FLAG_NONE != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (!pdu_processor_retrieve_conn_a1(pcall,
			    pchannel_out->connection_cookie, arsizeof(pchannel_out->connection_cookie),
			    pchannel_out->channel_cookie, arsizeof(pchannel_out->channel_cookie),
			    &pchannel_out->window_size)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_out->available_window = pchannel_out->window_size;
			if (!http_parser_try_create_vconnection(pcontext)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (!pdu_processor_rts_conn_a3(pcall)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		} else if (96 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_out->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (RTS_FLAG_RECYCLE_CHANNEL != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			/* process outr2/a3 rts pdu and do recycling */
			char channel_cookie[GUIDSTR_SIZE];
			if (!pdu_processor_retrieve_outr2_a3(pcall,
			    pchannel_out->connection_cookie, arsizeof(pchannel_out->connection_cookie),
			    channel_cookie, arsizeof(channel_cookie),
			    pchannel_out->channel_cookie, arsizeof(pchannel_out->channel_cookie),
			    &pchannel_out->window_size)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_out->available_window = pchannel_out->window_size;
			pdu_processor_free_call(pcall);
			if (!http_parser_recycle_outchannel(pcontext, channel_cookie))
				return PDU_PROCESSOR_ERROR;
			pchannel_out->channel_stat = CHANNEL_STAT_RECYCLING;
			return PDU_PROCESSOR_INPUT;
		} else if (24 == length) {
			if (CHANNEL_STAT_RECYCLING != pchannel_out->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (RTS_FLAG_PING != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (!pdu_processor_retrieve_outr2_c1(pcall)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		}
	} else if (CHANNEL_TYPE_IN == pcontext->channel_type) {
		pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
		if (104 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_NONE != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			/* process conn/b1 rts pdu and do connection to out channel */ 
			if (!pdu_processor_retrieve_conn_b1(pcall,
			    pchannel_in->connection_cookie, arsizeof(pchannel_in->connection_cookie),
			    pchannel_in->channel_cookie, arsizeof(pchannel_in->channel_cookie),
			    &pchannel_in->life_time, &pchannel_in->client_keepalive,
			    pchannel_in->assoc_group_id, arsizeof(pchannel_in->assoc_group_id))) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pdu_processor_free_call(pcall);
			/* notify out channel to send conn/c2 to client */
			if (!http_parser_try_create_vconnection(pcontext))
				return PDU_PROCESSOR_ERROR;
			pchannel_in->channel_stat = CHANNEL_STAT_OPENED;
			return PDU_PROCESSOR_INPUT;
		} else if (88 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_RECYCLE_CHANNEL != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			/* process inr2/a1 rts pdu and do recycling */
			char channel_cookie[GUIDSTR_SIZE];
			if (!pdu_processor_retrieve_inr2_a1(pcall,
			    pchannel_in->connection_cookie, arsizeof(pchannel_in->connection_cookie),
			    channel_cookie, arsizeof(channel_cookie),
			    pchannel_in->channel_cookie, arsizeof(pchannel_in->channel_cookie))) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (!http_parser_recycle_inchannel(pcontext, channel_cookie)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_in->channel_stat = CHANNEL_STAT_OPENED;
			pdu_processor_rts_inr2_a4(pcall);
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		} else if (28 == length) {
			/*
			if (CHANNEL_STAT_OPENED != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*/
			if (RTS_FLAG_OTHER_CMD != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}

			time_duration keep_alive;
			if (!pdu_processor_retrieve_keep_alive(pcall, &keep_alive)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			/* MS-RPCH 2.2.3.5.6 */
			using namespace std::chrono_literals;
			if (keep_alive == 0ms)
				keep_alive = 300000ms;
			else if (keep_alive < 60000ms)
				keep_alive = 60000ms;
			pchannel_in->client_keepalive = keep_alive;
			http_parser_set_keep_alive(pcontext, keep_alive);
			pdu_processor_free_call(pcall);
			return PDU_PROCESSOR_INPUT;
		} else if (40 == length) {
			if (CHANNEL_STAT_OPENED != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_NONE != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			char channel_cookie[GUIDSTR_SIZE];
			if (!pdu_processor_retrieve_inr2_a5(pcall,
			    channel_cookie, arsizeof(channel_cookie))) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pdu_processor_free_call(pcall);
			if (http_parser_activate_inrecycling(pcontext, channel_cookie))
				return PDU_PROCESSOR_TERMINATE;
			return PDU_PROCESSOR_INPUT;
		} else if (56 == length) {
			if (CHANNEL_STAT_OPENED != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_OTHER_CMD == pcall->pkt.payload.rts.flags) {
				if (!pdu_processor_retrieve_flowcontrolack_withdestination(pcall)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				http_parser_set_outchannel_flowcontrol(pcontext,
					pcall->pkt.payload.rts.commands[1].command.flowcontrolack.bytes_received,
					pcall->pkt.payload.rts.commands[1].command.flowcontrolack.available_window);
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_INPUT;
			} else if (RTS_FLAG_OUT_CHANNEL == pcall->pkt.payload.rts.flags) {
				char channel_cookie[GUIDSTR_SIZE];
				if (!pdu_processor_retrieve_outr2_a7(pcall,
				    channel_cookie, arsizeof(channel_cookie))) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				pdu_processor_free_call(pcall);
				http_parser_activate_outrecycling(pcontext, channel_cookie);
				return PDU_PROCESSOR_INPUT;
			} else {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
		} else if (20 == length) {
			if (RTS_FLAG_PING == pcall->pkt.payload.rts.flags &&
				0 == pcall->pkt.payload.rts.num) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_INPUT;
			}
		}
	}
	
	debug_info("[pdu_processor]: unknown pdu in RTS process procedure\n");
	
	pdu_processor_free_call(pcall);
	return PDU_PROCESSOR_ERROR;
}

int pdu_processor_input(PDU_PROCESSOR *pprocessor, const char *pbuff,
	uint16_t length, DCERPC_CALL **ppcall)
{
	NDR_PULL ndr;
	BOOL b_result;
	uint32_t flags;
	BOOL b_bigendian;
	DATA_BLOB tmp_blob;
	DCERPC_CALL *pcallx;
	uint32_t alloc_size;
	DCERPC_REQUEST *prequest;
	DCERPC_REQUEST *prequestx;
	
	
	flags = 0;
	*ppcall = NULL;
	if (!(pbuff[DCERPC_DREP_OFFSET] & DCERPC_DREP_LE)) {
		flags |= NDR_FLAG_BIGENDIAN;
		b_bigendian = TRUE;
	} else {
		b_bigendian = FALSE;
	}
	if (pbuff[DCERPC_PFC_OFFSET] & DCERPC_PFC_FLAG_OBJECT_UUID)
		flags |= NDR_FLAG_OBJECT_PRESENT;
	ndr_pull_init(&ndr, (uint8_t *)pbuff, length, flags);
	
	auto pcall = g_call_allocator->get();
	if (NULL == pcall) {
		return PDU_PROCESSOR_ERROR;
	}
	pcall->pprocessor = pprocessor;
	pcall->b_bigendian = b_bigendian;
	if (NDR_ERR_SUCCESS != pdu_ndr_pull_ncacnpkt(&ndr, &pcall->pkt)) {
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	}
	pcall->pkt_loaded = TRUE;
	
	if (pcall->pkt.frag_length != length) {
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	}
	
	/* we only allow fragmented requests, no other packet types */
	if ((0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) ||
		0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) &&
		pcall->pkt.pkt_type != DCERPC_PKT_REQUEST) {
		if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
			pdu_processor_free_call(pcall);
			return PDU_PROCESSOR_ERROR;
		}
		*ppcall = pcall;
		return PDU_PROCESSOR_OUTPUT;
	}
	
	if (DCERPC_PKT_REQUEST == pcall->pkt.pkt_type) {
		prequest = &pcall->pkt.payload.request;
		tmp_blob.data = (uint8_t*)pbuff;
		tmp_blob.length = length;
		if (!pdu_processor_auth_request(pcall, &tmp_blob)) {
			if (!pdu_processor_fault(pcall, DCERPC_FAULT_ACCESS_DENIED)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		}

		if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) {
			if (0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
				alloc_size = prequest->alloc_hint;
				if (alloc_size < prequest->stub_and_verifier.length) {
					alloc_size = prequest->stub_and_verifier.length * 8;
				}
				if (alloc_size > g_max_request_mem) {
					if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}
				alloc_size = strange_roundup(alloc_size - 1, 16 * 1024);
				auto pdata = me_alloc<uint8_t>(alloc_size);
				if (NULL == pdata) {
					if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}
				
				memcpy(pdata, prequest->stub_and_verifier.data,
					prequest->stub_and_verifier.length);
				free(prequest->stub_and_verifier.data);
				prequest->stub_and_verifier.data = pdata;
				pcall->alloc_size = alloc_size;
			}
		} else {
			pcallx = pdu_processor_get_fragmented_call(
						pprocessor, pcall->pkt.call_id);
			if (NULL == pcallx) {
				if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				*ppcall = pcall;
				return PDU_PROCESSOR_OUTPUT;
			}
			
			if (pcallx->pkt.pkt_type != pcall->pkt.pkt_type) {
				pdu_processor_free_call(pcallx);
				if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				
				*ppcall = pcall;
				return PDU_PROCESSOR_OUTPUT;
			}
			
			prequestx = &pcallx->pkt.payload.request;

			alloc_size = prequestx->stub_and_verifier.length +
							prequest->stub_and_verifier.length;
			if (prequestx->alloc_hint > alloc_size) {
				alloc_size = prequestx->alloc_hint;
			}
			
			if (pcallx->alloc_size < alloc_size) {
				if (alloc_size > g_max_request_mem) {
					pdu_processor_free_call(pcallx);
					if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}	
				alloc_size = strange_roundup(alloc_size - 1, 16 * 1024);
				auto pdata = me_alloc<uint8_t>(alloc_size);
				if (NULL == pdata) {
					pdu_processor_free_call(pcallx);
					if (!pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}
				memcpy(pdata, prequestx->stub_and_verifier.data,
					prequestx->stub_and_verifier.length);
				free(prequestx->stub_and_verifier.data);
				prequestx->stub_and_verifier.data = pdata;
				pcallx->alloc_size = alloc_size;
			}
				
			memcpy(prequestx->stub_and_verifier.data +
				prequestx->stub_and_verifier.length,
				prequest->stub_and_verifier.data,
				prequest->stub_and_verifier.length);
			
			prequestx->stub_and_verifier.length +=
				prequest->stub_and_verifier.length;

			pcallx->pkt.pfc_flags |= pcall->pkt.pfc_flags&DCERPC_PFC_FLAG_LAST;
			pdu_processor_free_call(pcall);
			pcall = pcallx;
		}
		

		/* this may not be the last pdu in the chain - if its isn't then
		just put it on the fragmented_list and wait for the rest */
		if (0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
			if (double_list_get_nodes_num(&pprocessor->fragmented_list) >
				MAX_FRAGMENTED_CALLS) {
				debug_info("[pdu_processor]: maximum fragments"
					" number of call reached\n");
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			double_list_append_as_tail(&pprocessor->fragmented_list,
				&pcall->node);
			*ppcall = pcall;
			return PDU_PROCESSOR_INPUT;
		}
	}
	
	switch (pcall->pkt.pkt_type) {
	case DCERPC_PKT_BIND:
		b_result = pdu_processor_process_bind(pcall);
		break;
	case DCERPC_PKT_AUTH3:
		b_result = pdu_processor_process_auth3(pcall);
		if (b_result) {
			pdu_processor_free_call(pcall);
			return PDU_PROCESSOR_INPUT;
		}
		break;
	case DCERPC_PKT_ALTER:
		b_result = pdu_processor_process_alter(pcall);
		break;
	case DCERPC_PKT_REQUEST: {
		BOOL b_async = false;
		b_result = pdu_processor_process_request(pcall, &b_async);
		if (b_result && b_async)
			return PDU_PROCESSOR_INPUT;
		break;
	}
	case DCERPC_PKT_CO_CANCEL:
		pdu_processor_process_cancel(pcall);
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_INPUT;
	case DCERPC_PKT_ORPHANED:
		pdu_processor_process_orphaned(pcall);
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_INPUT;
	default:
		b_result = FALSE;
		debug_info("[pdu_processor]: invalid ncancn packet type "
			"in process procedure\n");
		break;
	}
	
	if (!b_result) {
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	} else {
		*ppcall = pcall;
		return PDU_PROCESSOR_OUTPUT;
	}
}

static DCERPC_ENDPOINT* pdu_processor_register_endpoint(const char *host,
    uint16_t tcp_port) try
{
	auto ei = std::find_if(g_endpoint_list.begin(), g_endpoint_list.end(),
	          endpoint_eq(host, tcp_port));
	if (ei != g_endpoint_list.end())
		return &*ei;
	auto &ep = g_endpoint_list.emplace_back();
	auto pendpoint = &ep;
	gx_strlcpy(pendpoint->host, host, GX_ARRAY_SIZE(pendpoint->host));
	pendpoint->tcp_port = tcp_port;
	pendpoint->last_group_id = 0;
	printf("[pdu_processor]: registered endpoint [%s]:%hu\n",
	       pendpoint->host, pendpoint->tcp_port);
	return pendpoint;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1575: ENOMEM\n");
	return nullptr;
}

static BOOL pdu_processor_register_interface(DCERPC_ENDPOINT *pendpoint,
    const DCERPC_INTERFACE *pinterface)
{
	if (NULL == pinterface->ndr_pull) {
		printf("[pdu_processor]: ndr_pull of interface %s cannot be NULL\n",
			pinterface->name);
		return FALSE;
	}
	if (NULL == pinterface->dispatch) {
		printf("[pdu_processor]: dispatch of interface %s cannot be NULL\n",
			pinterface->name);
		return FALSE;
	}
	if (NULL == pinterface->ndr_push) {
		printf("[pdu_processor]: ndr_push of interface %s cannot be NULL\n",
			pinterface->name);
		return FALSE;
	}
	auto &lst = pendpoint->interface_list;
	auto ix = std::find_if(lst.cbegin(), lst.cend(),
	          interface_eq(pinterface->uuid, pinterface->version));
	if (ix != lst.cend()) {
		printf("[pdu_processor]: interface already exists under "
		       "endpoint [%s]:%hu\n", pendpoint->host, pendpoint->tcp_port);
		return FALSE;
	}
	try {
		pendpoint->interface_list.emplace_back(*pinterface);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1576: ENOMEM\n");
		return false;
	}
	char uuid_string[GUIDSTR_SIZE];
	pinterface->uuid.to_str(uuid_string, arsizeof(uuid_string));
	printf("[pdu_processor]: EP [%s]:%hu: registered interface %s {%s} (v %u.%02u)\n",
	       pendpoint->host, pendpoint->tcp_port, pinterface->name,
	       uuid_string, pinterface->version & 0xFFFF,
	       (pinterface->version >> 16) & 0xFFFF);
	return TRUE;
}

static void pdu_processor_unregister_interface(DCERPC_ENDPOINT *ep,
    const DCERPC_INTERFACE *tp)
{
	auto &lst = ep->interface_list;
#if __cplusplus >= 202000L
	lst.remove_if(interface_eq(tp->uuid, tp->version));
#else
	auto ei = std::find_if(lst.begin(), lst.end(),
	          interface_eq(tp->uuid, tp->version));
	if (ei != lst.end())
		lst.erase(ei);
#endif
}

PROC_PLUGIN::PROC_PLUGIN()
{
	double_list_init(&list_reference);
}

PROC_PLUGIN::PROC_PLUGIN(PROC_PLUGIN &&o) noexcept :
	list_reference(o.list_reference), lib_main(o.lib_main),
	file_name(std::move(o.file_name)), completed_init(o.completed_init)
{
	o.list_reference = {};
	o.handle = nullptr;
	o.completed_init = false;
}

PROC_PLUGIN::~PROC_PLUGIN()
{
	PLUGIN_MAIN func;
	DOUBLE_LIST_NODE *pnode;
	auto pplugin = this;
	
	if (pplugin->file_name.size() > 0)
		printf("[pdu_processor]: unloading %s\n", pplugin->file_name.c_str());
	func = (PLUGIN_MAIN)pplugin->lib_main;
	if (func != nullptr && pplugin->completed_init)
		/* notify the plugin that it willbe unloaded */
		func(PLUGIN_FREE, NULL);
	
	/* free the reference list */
	while ((pnode = double_list_pop_front(&pplugin->list_reference)) != nullptr) {
		service_release(static_cast<pdu_service_node *>(pnode->pdata)->service_name,
			pplugin->file_name.c_str());
		free(static_cast<pdu_service_node *>(pnode->pdata)->service_name);
		free(pnode->pdata);
	}
	double_list_free(&pplugin->list_reference);
	if (handle != nullptr)
		dlclose(handle);
}

static const char *pdu_processor_get_host_ID()
{
	return resource_get_string("HOST_ID");
}

static const char* pdu_processor_get_plugin_name()
{
	if (NULL == g_cur_plugin) {
		return NULL;
	}
	auto fn = g_cur_plugin->file_name.c_str();
	return strncmp(fn, "libgxp_", 7) == 0 ? fn + 7 : fn;
}

static const char* pdu_processor_get_config_path()
{
	const char *ret_value = resource_get_string("CONFIG_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGSYSCONFDIR;
    }
    return ret_value;
}

static const char* pdu_processor_get_data_path()
{
	const char *ret_value = resource_get_string("DATA_FILE_PATH");
    if (NULL == ret_value) {
		ret_value = PKGDATADIR "/http:" PKGDATADIR;
    }
    return ret_value;
}

static const char *pdu_processor_get_state_path()
{
	const char *p = resource_get_string("STATE_PATH");
	return p != nullptr ? p : PKGSTATEDIR;
}

static unsigned int pdu_processor_get_context_num()
{
	return g_connection_num;
}

/* this function can also be invoked from hpm_plugins,
	you should first set context TLS before call this
	function, if you don't do that, you will get nothing
*/
static DCERPC_INFO pdu_processor_get_rpc_info()
{
	DCERPC_INFO info;
	DCERPC_CALL *pcall;
	HTTP_CONTEXT *pcontext;
	
	memset(&info, 0, sizeof(DCERPC_INFO));
	pcall = pdu_processor_get_call();
	pcontext = http_parser_get_context();
	if (NULL != pcontext) {
		info.client_ip = pcontext->connection.client_ip;
		info.client_port = pcontext->connection.client_port;
		info.server_ip = pcontext->connection.server_ip;
		info.server_port = pcontext->connection.server_port;
		info.ep_host = pcontext->host;
		info.ep_port = pcontext->port;
		info.username = pcontext->username;
		info.maildir = pcontext->maildir;
		info.lang = pcontext->lang;
	}
	if (NULL != pcall) {
		if (NULL == pcall->pauth_ctx) {
			info.is_login = FALSE;
		} else {
			info.is_login = pcall->pauth_ctx->is_login;
		}
		if (NULL != pcall->pcontext) {
			info.stat_flags = pcall->pcontext->stat_flags;
		}
	} else {
		if (NULL == pcontext || '\0' == pcontext->username[0]) {
			info.is_login = FALSE;
		} else {
			info.is_login = TRUE;
		}
		info.stat_flags = 0;
	}
	return info;
}

static BOOL pdu_processor_is_rpc_bigendian()
{
	DCERPC_CALL *pcall;
	
	pcall = pdu_processor_get_call();
	if (NULL != pcall) {
		return pcall->b_bigendian;
	}
	return g_bigendian;
}

static uint64_t pdu_processor_get_binding_handle()
{
	uint64_t handle;
	DCERPC_CALL *pcall;
	
	pcall = pdu_processor_get_call();
	if (NULL != pcall) {
		handle = pcall->pcontext->assoc_group_id;
		handle <<= 32;
		handle |= pcall->pcontext->context_id;
		return handle;
	}
	return 0;
}

static void *pdu_processor_queryservice(const char *service, const std::type_info &ti)
{
	DOUBLE_LIST_NODE *pnode;
	void *ret_addr;

	if (NULL == g_cur_plugin) {
		return NULL;
	}
	if (strcmp(service, "register_endpoint") == 0) {
		return reinterpret_cast<void *>(pdu_processor_register_endpoint);
	}
	if (strcmp(service, "register_interface") == 0) {
		return reinterpret_cast<void *>(pdu_processor_register_interface);
	}
	if (strcmp(service, "unregister_interface") == 0)
		return reinterpret_cast<void *>(pdu_processor_unregister_interface);
	if (strcmp(service, "register_service") == 0)
		return reinterpret_cast<void *>(service_register_service);
	if (strcmp(service, "get_host_ID") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_host_ID);
	}
	if (strcmp(service, "get_plugin_name") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_plugin_name);
	}
	if (strcmp(service, "get_config_path") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_config_path);
	}
	if (strcmp(service, "get_data_path") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_data_path);
	}
	if (strcmp(service, "get_state_path") == 0)
		return reinterpret_cast<void *>(pdu_processor_get_state_path);
	if (strcmp(service, "get_context_num") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_context_num);
	}
	if (strcmp(service, "get_binding_handle") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_binding_handle);
	}
	if (strcmp(service, "get_rpc_info") == 0) {
		return reinterpret_cast<void *>(pdu_processor_get_rpc_info);
	}
	if (strcmp(service, "is_rpc_bigendian") == 0) {
		return reinterpret_cast<void *>(pdu_processor_is_rpc_bigendian);
	}
	if (strcmp(service, "ndr_stack_alloc") == 0) {
		return reinterpret_cast<void *>(pdu_processor_ndr_stack_alloc);
	}
	if (strcmp(service, "apply_async_id") == 0) {
		return reinterpret_cast<void *>(pdu_processor_apply_async_id);
	}
	if (strcmp(service, "activate_async_id") == 0) {
		return reinterpret_cast<void *>(pdu_processor_activate_async_id);
	}
	if (strcmp(service, "cancel_async_id") == 0) {
		return reinterpret_cast<void *>(pdu_processor_cancel_async_id);
	}
	if (strcmp(service, "rpc_build_environment") == 0) {
		return reinterpret_cast<void *>(pdu_processor_rpc_build_environment);
	}
	if (strcmp(service, "rpc_new_stack") == 0)
		return reinterpret_cast<void *>(pdu_processor_rpc_new_stack);
	if (strcmp(service, "rpc_free_stack") == 0)
		return reinterpret_cast<void *>(pdu_processor_rpc_free_stack);
	if (strcmp(service, "async_reply") == 0) {
		return reinterpret_cast<void *>(pdu_processor_async_reply);
	}
	/* check if already exists in the reference list */
	for (pnode=double_list_get_head(&g_cur_plugin->list_reference);
		NULL!=pnode;
		pnode=double_list_get_after(&g_cur_plugin->list_reference, pnode)) {
		auto pservice = static_cast<pdu_service_node *>(pnode->pdata);
		if (0 == strcmp(service, pservice->service_name)) {
			return pservice->service_addr;
		}
	}
	auto fn = g_cur_plugin->file_name.c_str();
	ret_addr = service_query(service, fn, ti);
	if (NULL == ret_addr) {
		return NULL;
	}
	auto pservice = me_alloc<pdu_service_node>();
	if (NULL == pservice) {
		debug_info("[pdu_processor]: Failed to allocate memory "
			"for service node\n");
		service_release(service, fn);
		return NULL;
	}
	pservice->service_name = me_alloc<char>(strlen(service) + 1);
	if (NULL == pservice->service_name) {
		debug_info("[pdu_processor]: Failed to allocate memory "
			"for service name\n");
		service_release(service, fn);
		free(pservice);
		return NULL;
	}
	strcpy(pservice->service_name, service);
	pservice->node.pdata = pservice;
	pservice->service_addr = ret_addr;
	double_list_append_as_tail(&g_cur_plugin->list_reference,
		&pservice->node);
	return ret_addr;
}

/*
 *	load the hook plugin
 *	@param
 *		path [in]					plugin name
 *	@return
 *		PLUGIN_LOAD_OK				OK
 *		PLUGIN_ALREADY_LOADED		plugin is already loaded
 *		PLUGIN_FAIL_OPEN			fail to open share library
 *		PLUGIN_NO_MAIN				cannot find main entry
 *		PLUGIN_FAIL_ALLOCNODE		fail to allocate node for plugin
 *		PLUGIN_FAIL_EXECUTEMAIN		main entry in plugin returns FALSE
 */
static int pdu_processor_load_library(const char* plugin_name)
{
	static void *const server_funcs[] = {reinterpret_cast<void *>(pdu_processor_queryservice)};
	const char *fake_path = plugin_name;
	PROC_PLUGIN plug;

	plug.handle = dlopen(plugin_name, RTLD_LAZY);
	if (plug.handle == nullptr && strchr(plugin_name, '/') == nullptr)
		plug.handle = dlopen((PKGLIBDIR + "/"s + plugin_name).c_str(), RTLD_LAZY);
	if (plug.handle == nullptr) {
		printf("[pdu_processor]: error loading %s: %s\n", fake_path,
			dlerror());
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
    }
	plug.lib_main = reinterpret_cast<decltype(plug.lib_main)>(dlsym(plug.handle, "PROC_LibMain"));
	if (plug.lib_main == nullptr) {
		printf("[pdu_processor]: error finding the PROC_LibMain function in %s\n",
			fake_path);
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_NO_MAIN;
	}
	plug.file_name = plugin_name;
	g_plugin_list.push_back(std::move(plug));
	g_cur_plugin = &g_plugin_list.back();
	
	/* append the pendpoint node into endpoint list */
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (!g_cur_plugin->lib_main(PLUGIN_INIT, const_cast<void **>(server_funcs))) {
		printf("[pdu_processor]: error executing the plugin's init function "
			"in %s\n", fake_path);
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		g_plugin_list.pop_back();
		g_cur_plugin = NULL;
		return PLUGIN_FAIL_EXECUTEMAIN;
	}
	g_cur_plugin->completed_init = true;
	g_cur_plugin = NULL;
	return PLUGIN_LOAD_OK;
}

void pdu_processor_trigger(unsigned int ev)
{
	for (auto &p : g_plugin_list) {
		g_cur_plugin = &p;
		p.lib_main(ev, nullptr);
	}
	g_cur_plugin = nullptr;
}
