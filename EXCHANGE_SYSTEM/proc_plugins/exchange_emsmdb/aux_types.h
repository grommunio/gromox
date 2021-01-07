#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "rpc_types.h"
#include "double_list.h"

#define AUX_VERSION_1								0x1
#define AUX_VERSION_2								0x2


#define AUX_TYPE_PERF_REQUESTID						0x01
#define AUX_TYPE_PERF_CLIENTINFO					0x02
#define AUX_TYPE_PERF_SERVERINFO					0x03
#define AUX_TYPE_PERF_SESSIONINFO					0x04
#define AUX_TYPE_PERF_DEFMDB_SUCCESS				0x05
#define AUX_TYPE_PERF_DEFGC_SUCCESS					0x06
#define AUX_TYPE_PERF_MDB_SUCCESS					0x07
#define AUX_TYPE_PERF_GC_SUCCESS					0x08
#define AUX_TYPE_PERF_FAILURE						0x09
#define AUX_TYPE_CLIENT_CONTROL						0x0A
#define AUX_TYPE_PERF_PROCESSINFO					0x0B
#define AUX_TYPE_PERF_BG_DEFMDB_SUCCESS				0x0C
#define AUX_TYPE_PERF_BG_DEFGC_SUCCESS				0x0D
#define AUX_TYPE_PERF_BG_MDB_SUCCESS				0x0E
#define AUX_TYPE_PERF_BG_GC_SUCCESS					0x0F
#define AUX_TYPE_PERF_BG_FAILURE					0x10
#define AUX_TYPE_PERF_FG_DEFMDB_SUCCESS				0x11
#define AUX_TYPE_PERF_FG_DEFGC_SUCCESS				0x12
#define AUX_TYPE_PERF_FG_MDB_SUCCESS				0x13
#define AUX_TYPE_PERF_FG_GC_SUCCESS					0x14
#define AUX_TYPE_PERF_FG_FAILURE					0x15
#define AUX_TYPE_OSVERSIONINFO						0x16
#define AUX_TYPE_EXORGINFO							0x17
#define AUX_TYPE_PERF_ACCOUNTINFO					0x18
#define AUX_TYPE_ENDPOINT_CAPABILITIES				0x48
#define AUX_TYPE_CLIENT_CONNECTION_INFO				0x4A
#define AUX_TYPE_SERVER_SESSION_INFO				0x4B
#define AUX_TYPE_PROTOCOL_DEVICE_ID					0x4E


struct AUX_PERF_REQUESTID {
	uint16_t session_id;
	uint16_t request_id;
};

struct AUX_PERF_SESSIONINFO {
	uint16_t session_id;
	uint16_t reserved;
	GUID session_guid;
};

struct AUX_PERF_SESSIONINFO_V2 {
	uint16_t session_id;
	uint16_t reserved;
	GUID session_guid;
	uint32_t connection_id;
};

#define CLIENT_MODE_UNKNOWN							0x0
#define CLIENT_MODE_CLASSIC							0x1
#define CLIENT_MODE_CACHED							0x2

struct AUX_PERF_CLIENTINFO {
	uint32_t adapter_speed;
	uint16_t client_id;
	uint16_t client_ip_size;
	uint16_t client_ip_mask_size;
	uint16_t mac_address_size;
	uint16_t client_mode;
	uint16_t reserved;
	char *machine_name;
	char *user_name;
	uint8_t *client_ip;
	uint8_t *client_ip_mask;
	char *adapter_name;
	uint8_t *mac_address;
};

#define SERVER_TYPE_UNKNOWN							0x0
#define SERVER_TYPE_PRIVATE							0x1
#define SERVER_TYPE_PUBLIC							0x2
#define SERVER_TYPE_DIRECTORY						0x3
#define SERVER_TYPE_REFERRAL						0x4

struct AUX_PERF_SERVERINFO {
	uint16_t server_id;
	uint16_t server_type;
	char *server_dn;
	char *server_name;
};

struct AUX_PERF_PROCESSINFO {
	uint16_t process_id;
	uint16_t reserved1;
	GUID process_guid;
	uint16_t reserved2;
	char *process_name;
};

struct AUX_PERF_DEFMDB_SUCCESS {
	uint32_t time_since_request;
	uint32_t time_to_complete_request;
	uint16_t request_id;
	uint16_t reserved;
};

struct AUX_PERF_DEFGC_SUCCESS {
	uint16_t server_id;
	uint16_t session_id;
	uint32_t time_since_request;
	uint32_t time_to_complete_request;
	uint8_t request_operation;
	uint8_t reserved[3];
};

struct AUX_PERF_MDB_SUCCESS {
	uint16_t client_id;
	uint16_t server_id;
	uint16_t session_id;
	uint16_t request_id;
	uint32_t time_since_request;
	uint32_t time_to_complete_request;
};

struct AUX_PERF_MDB_SUCCESS_V2 {
	uint16_t process_id;
	uint16_t client_id;
	uint16_t server_id;
	uint16_t session_id;
	uint16_t request_id;
	uint16_t reserved;
	uint32_t time_since_request;
	uint32_t time_to_complete_request;
};

struct AUX_PERF_GC_SUCCESS {
	uint16_t client_id;
	uint16_t server_id;
	uint16_t session_id;
	uint16_t reserved1;
	uint32_t time_since_request;
	uint32_t time_to_complete_request;
	uint8_t request_operation;
	uint8_t reserved2[3];
};

struct AUX_PERF_GC_SUCCESS_V2 {
	uint16_t process_id;
	uint16_t client_id;
	uint16_t server_id;
	uint16_t session_id;
	uint32_t time_since_request;
	uint32_t time_to_complete_request;
	uint8_t request_operation;
	uint8_t reserved[3];
};

struct AUX_PERF_FAILURE {
	uint16_t client_id;
	uint16_t server_id;
	uint16_t session_id;
	uint16_t request_id;
	uint32_t time_since_request;
	uint32_t time_to_fail_request;
	uint32_t result_code;
	uint8_t request_operation;
	uint8_t reserved[3];
};

struct AUX_PERF_FAILURE_V2 {
	uint16_t process_id;
	uint16_t client_id;
	uint16_t server_id;
	uint16_t session_id;
	uint16_t request_id;
	uint16_t reserved1;
	uint32_t time_since_request;
	uint32_t time_to_fail_request;
	uint32_t result_code;
	uint8_t request_operation;
	uint8_t reserved2[3];
};

/* bitmap CLIENT_CONTROL_ENABLEFLAGS */
#define ENABLE_PERF_SENDTOSERVER					0x00000001
#define ENABLE_COMPRESSION							0x00000004
#define ENABLE_HTTP_TUNNELING						0x00000008
#define ENABLE_PERF_SENDGCDATA						0x00000010

struct AUX_CLIENT_CONTROL {
	uint32_t enable_flags;
	uint32_t expiry_time;
};

struct AUX_OSVERSIONINFO {
	uint32_t os_version_info_size;
	uint32_t major_version;
	uint32_t minor_version;
	uint32_t build_number;
	uint8_t reserved1[132];
	uint16_t service_pack_major;
	uint16_t service_pack_minor;
	uint32_t reserved2;
};

/* bitmap EXORGINFO_ORGFLAGS */
#define PUBLIC_FOLDERS_ENABLED								0x00000001
#define USE_AUTODISCOVER_FOR_PUBLIC_FOLDR_CONFIGURATION		0x00000002

struct AUX_EXORGINFO {
	uint32_t org_flags;
};

struct AUX_PERF_ACCOUNTINFO {
	uint16_t client_id;
	uint16_t reserved;
	GUID account;
};

#define ENDPOINT_CAPABILITIES_SINGLE_ENDPOINT		0x00000001

struct AUX_ENDPOINT_CAPABILITIES {
	uint32_t endpoint_capability_flag;
};

#define CONNECTION_FLAG_CACHED_MODE					0x00000001

struct AUX_CLIENT_CONNECTION_INFO {
	GUID connection_guid;
	uint16_t reserved;
	uint32_t connection_attempts;
	uint32_t connection_flags;
	char *connection_context_info;
};

struct AUX_SERVER_SESSION_INFO {
	char *server_session_context_info;
};

struct AUX_PROTOCOL_DEVICE_IDENTIFICATION {
	char *device_manufacturer;
	char *device_model;
	char *device_serial_number;
	char *device_version;
	char *device_firmware_version;
};

struct AUX_HEADER {
	uint8_t version;
	uint8_t type;
	void *ppayload;
};


/* bitmap pulFlags */
#define PUL_FLAGS_NOCOMPRESSION						0x00000001
#define PUL_FLAGS_NOXORMAGIC						0x00000002
#define PUL_FLAGS_CHAIN								0x00000004

struct AUX_INFO {
	uint16_t rhe_version;
	uint16_t rhe_flags;
	DOUBLE_LIST aux_list;
};
