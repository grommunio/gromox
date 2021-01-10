#pragma once
#include <gromox/arcfour.hpp>
#include <gromox/rpc_types.hpp>
#include "common_types.h"
#include <pthread.h>

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


#define NTLMSSP_WINDOWS_MAJOR_VERSION_5				0x05
#define NTLMSSP_WINDOWS_MAJOR_VERSION_6				0x06
#define NTLMSSP_WINDOWS_MINOR_VERSION_0				0x00
#define NTLMSSP_WINDOWS_MINOR_VERSION_1				0x01
#define NTLMSSP_WINDOWS_MINOR_VERSION_2				0x02


#define NTLMSSP_REVISION_W2K3_RC10x0A				0x0A
#define NTLMSSP_REVISION_W2K3						0x0F


typedef struct _NTLMSSP_VERSION {
	uint8_t major_vers;
	uint8_t minor_vers;
	uint16_t product_build;
	uint8_t reserved[3];
	uint8_t ntlm_revers;
} NTLMSSP_VERSION;


typedef struct _NTLMSSP_CRYPT_DIRECTION {
	uint32_t seq_num;
	uint8_t sign_key[16];
	ARCFOUR_STATE seal_state;
} NTLMSSP_CRYPT_DIRECTION;

typedef struct _NTLMSSP_CRYPT_DIRECTION_V2 {
	NTLMSSP_CRYPT_DIRECTION sending;
	NTLMSSP_CRYPT_DIRECTION receiving;
} NTLMSSP_CRYPT_DIRECTION_V2;

typedef union _NTLMSSP_CRYPT_STATE {
	NTLMSSP_CRYPT_DIRECTION ntlm;     /* NTLM */
	NTLMSSP_CRYPT_DIRECTION_V2 ntlm2; /* NTLM2 */
} NTLMSSP_CRYPT_STATE;

typedef struct _NTLM_AUTH_CHALLENGE {
	DATA_BLOB blob;
	uint8_t blob_buff[8]; /* buffer for DATA_BLOB's data */
} NTLM_AUTH_CHALLENGE;

typedef struct _NTLMSSP_SESSION_INFO {
	char username[128];
	DATA_BLOB session_key;
	uint8_t session_key_buff[16];
} NTLMSSP_SESSION_INFO;

typedef BOOL (*NTLMSSP_GET_PASSWORD)(const char*, char*);

typedef struct _NTLMSSP_CTX {
	pthread_mutex_t lock;
	uint32_t expected_state;
	BOOL unicode;
	BOOL use_nt_response; /* Set to 'False' to debug what happens when the NT response is omited */
	BOOL allow_lm_key;    /* The LM_KEY code is not very secure... */

	char user[128];
	char domain[128];
	uint8_t *nt_hash;
	uint8_t *lm_hash;
	
	char netbios_name[128];
	char dns_name[128];
	char dns_domain[128];
	
	DATA_BLOB internal_chal; /* Random challenge as supplied to the client for NTLM authentication */
	uint8_t internal_chal_buff[32];
	
	DATA_BLOB lm_resp;
	uint8_t lm_resp_buff[32];
	DATA_BLOB nt_resp;
	uint8_t nt_resp_buff[512];
	DATA_BLOB session_key;
	uint8_t session_key_buff[32];

	uint32_t neg_flags; /* the current state of negotiation with the NTLMSSP partner */

	NTLMSSP_CRYPT_STATE crypt;
	NTLM_AUTH_CHALLENGE challenge;
	
	NTLMSSP_GET_PASSWORD get_password;
} NTLMSSP_CTX;

#ifdef __cplusplus
extern "C" {
#endif

NTLMSSP_CTX* ntlmssp_init(const char *netbios_name, const char *dns_name,
	const char *dns_domain, BOOL b_lm_key, uint32_t net_flags,
	NTLMSSP_GET_PASSWORD get_password);

BOOL ntlmssp_update(NTLMSSP_CTX *pntlmssp, DATA_BLOB *pblob);
extern size_t ntlmssp_sig_size(void);
uint32_t ntlmssp_expected_state(NTLMSSP_CTX *pntlmssp);

BOOL ntlmssp_sign_packet(NTLMSSP_CTX *pntlmssp, const uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	DATA_BLOB *psig);
					
BOOL ntlmssp_check_packet(NTLMSSP_CTX *pntlmssp, const uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	const DATA_BLOB *psig);

BOOL ntlmssp_seal_packet(NTLMSSP_CTX *pntlmssp, uint8_t *pdata, size_t length,
	const uint8_t *pwhole_pdu, size_t pdu_length, DATA_BLOB *psig);
	
BOOL ntlmssp_unseal_packet(NTLMSSP_CTX *pntlmssp, uint8_t *pdata,
	size_t length, const uint8_t *pwhole_pdu, size_t pdu_length,
	const DATA_BLOB *psig);

BOOL ntlmssp_session_key(NTLMSSP_CTX *pntlmssp, DATA_BLOB *psession_key);

BOOL ntlmssp_session_info(NTLMSSP_CTX *pntlmssp,
	NTLMSSP_SESSION_INFO *psession);

void ntlmssp_destroy(NTLMSSP_CTX *pntlmssp);

#ifdef __cplusplus
}
#endif
