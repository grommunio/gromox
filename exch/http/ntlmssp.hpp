#pragma once
#include <cstdint>
#include <mutex>
#include <gromox/common_types.hpp>

#define NTLMSSP_PROCESS_NEGOTIATE		1
#define	NTLMSSP_PROCESS_CHALLENGE		2
#define NTLMSSP_PROCESS_AUTH			3
#define NTLMSSP_PROCESS_UNKNOWN			4
#define NTLMSSP_PROCESS_DONE			5
#define NTLMSSP_NEGOTIATE_UNICODE					0x00000001
#define NTLMSSP_NEGOTIATE_OEM						0x00000002
#define NTLMSSP_REQUEST_TARGET						0x00000004
#define NTLMSSP_NEGOTIATE_SIGN						0x00000010
#define NTLMSSP_NEGOTIATE_SEAL						0x00000020
#define NTLMSSP_NEGOTIATE_DATAGRAM					0x00000040
#define NTLMSSP_NEGOTIATE_LM_KEY					0x00000080
#define NTLMSSP_NEGOTIATE_NETWARE					0x00000100
#define NTLMSSP_NEGOTIATE_NTLM						0x00000200
#define NTLMSSP_NEGOTIATE_NT_ONLY					0x00000400
#define NTLMSSP_ANONYMOUS							0x00000800
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED		0x00001000
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED	0x00002000
#define NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL		0x00004000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN				0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN					0x00010000
#define NTLMSSP_TARGET_TYPE_SERVER					0x00020000
#define NTLMSSP_TARGET_TYPE_SHARE					0x00040000
#define NTLMSSP_NEGOTIATE_NTLM2						0x00080000
#define NTLMSSP_NEGOTIATE_IDENTIFY					0x00100000
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY			0x00400000
#define NTLMSSP_NEGOTIATE_TARGET_INFO				0x00800000
#define NTLMSSP_NEGOTIATE_VERSION					0x02000000
#define NTLMSSP_NEGOTIATE_128						0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH					0x40000000
#define NTLMSSP_NEGOTIATE_56						0x80000000

struct ARCFOUR_STATE {
	void init(const uint8_t *key, size_t len);
	void crypt_sbox(uint8_t *data, int len);
	static void crypt(uint8_t *data, const uint8_t key[16], int datalen);

	uint8_t sbox[256];
	uint8_t index_i;
	uint8_t index_j;
};

struct GX_EXPORT NTLMSSP_SESSION_INFO {
	char username[UADDR_SIZE];
	DATA_BLOB session_key;
	uint8_t session_key_buff[16];
};

struct GX_EXPORT NTLM_AUTH_CHALLENGE {
	DATA_BLOB blob;
	uint8_t blob_buff[8]; /* buffer for DATA_BLOB's data */
};

struct GX_EXPORT NTLMSSP_CRYPT_DIRECTION {
	uint32_t seq_num;
	uint8_t sign_key[16];
	ARCFOUR_STATE seal_state;
};

struct GX_EXPORT NTLMSSP_CRYPT_DIRECTION_V2 {
	NTLMSSP_CRYPT_DIRECTION sending;
	NTLMSSP_CRYPT_DIRECTION receiving;
};

union NTLMSSP_CRYPT_STATE {
	NTLMSSP_CRYPT_DIRECTION ntlm;     /* NTLM */
	NTLMSSP_CRYPT_DIRECTION_V2 ntlm2; /* NTLM2 */
};

using NTLMSSP_GET_PASSWORD = bool (*)(const char *, char *);

struct GX_EXPORT ntlmssp_ctx {
	static constexpr unsigned int SIG_SIZE = 16;

	static std::unique_ptr<ntlmssp_ctx> create(const char *netbios_name, const char *dns_name, const char *dns_domain, bool b_lm_key, uint32_t net_flags, NTLMSSP_GET_PASSWORD);
	bool update(DATA_BLOB *);
	static size_t sig_size() { return SIG_SIZE; }
	bool sign_packet(const uint8_t *data, size_t len, const uint8_t *whole_pdu, size_t pdu_len, DATA_BLOB *sig);
	bool check_packet(const uint8_t *data, size_t len, const uint8_t *whole_pdu, size_t pdu_len, const DATA_BLOB *sig);
	bool seal_packet(uint8_t *data, size_t len, const uint8_t *whole_pdu, size_t pdu_len, DATA_BLOB *sig);
	bool unseal_packet(uint8_t *data, size_t len, const uint8_t *whole_pdu, size_t pdu_len, const DATA_BLOB *sig);
	bool session_info(NTLMSSP_SESSION_INFO *);

	std::mutex lock;
	uint32_t expected_state = NTLMSSP_PROCESS_NEGOTIATE;
	bool unicode = false;
	bool allow_lm_key = false; /* The LM_KEY code is not very secure... */
	char user[128]{}, domain[128]{};
	uint8_t *nt_hash = nullptr, *lm_hash = nullptr;
	char netbios_name[128]{}, dns_name[128]{}, dns_domain[128]{};
	DATA_BLOB internal_chal{}; /* Random challenge as supplied to the client for NTLM authentication */
	uint8_t internal_chal_buff[32]{};
	DATA_BLOB lm_resp{}, nt_resp{}, session_key{};
	uint8_t lm_resp_buff[32]{}, nt_resp_buff[512]{}, session_key_buff[32];
	uint32_t neg_flags = /* the current state of negotiation with the NTLMSSP partner */
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL;
	NTLMSSP_CRYPT_STATE crypt{};
	NTLM_AUTH_CHALLENGE challenge{};
	NTLMSSP_GET_PASSWORD get_password = nullptr;
};
using NTLMSSP_CTX = ntlmssp_ctx;
