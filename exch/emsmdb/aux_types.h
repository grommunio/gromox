#pragma once
#include <cstdint>
#include <gromox/double_list.hpp>
#include <gromox/rpc_types.hpp>

/* OXCRPC v23 §2.2.2.2 */

enum {
	AUX_VERSION_1 = 0x1U,
	AUX_VERSION_2 = 0x2U,
};

enum {
	AUX_TYPE_PERF_REQUESTID         = 0x01U,
	AUX_TYPE_PERF_CLIENTINFO        = 0x02U,
	AUX_TYPE_PERF_SERVERINFO        = 0x03U,
	AUX_TYPE_PERF_SESSIONINFO       = 0x04U,
	AUX_TYPE_PERF_DEFMDB_SUCCESS    = 0x05U,
	AUX_TYPE_PERF_DEFGC_SUCCESS     = 0x06U,
	AUX_TYPE_PERF_MDB_SUCCESS       = 0x07U,
	AUX_TYPE_PERF_GC_SUCCESS        = 0x08U,
	AUX_TYPE_PERF_FAILURE           = 0x09U,
	AUX_TYPE_CLIENT_CONTROL         = 0x0AU,
	AUX_TYPE_PERF_PROCESSINFO       = 0x0BU,
	AUX_TYPE_PERF_BG_DEFMDB_SUCCESS = 0x0CU,
	AUX_TYPE_PERF_BG_DEFGC_SUCCESS  = 0x0DU,
	AUX_TYPE_PERF_BG_MDB_SUCCESS    = 0x0EU,
	AUX_TYPE_PERF_BG_GC_SUCCESS     = 0x0FU,
	AUX_TYPE_PERF_BG_FAILURE        = 0x10U,
	AUX_TYPE_PERF_FG_DEFMDB_SUCCESS = 0x11U,
	AUX_TYPE_PERF_FG_DEFGC_SUCCESS  = 0x12U,
	AUX_TYPE_PERF_FG_MDB_SUCCESS    = 0x13U,
	AUX_TYPE_PERF_FG_GC_SUCCESS     = 0x14U,
	AUX_TYPE_PERF_FG_FAILURE        = 0x15U,
	AUX_TYPE_OSVERSIONINFO          = 0x16U,
	AUX_TYPE_EXORGINFO              = 0x17U,
	AUX_TYPE_PERF_ACCOUNTINFO       = 0x18U,
	AUX_TYPE_ENDPOINT_CAPABILITIES  = 0x48U,
	AUX_TYPE_CLIENT_CONNECTION_INFO = 0x4AU,
	AUX_TYPE_SERVER_SESSION_INFO    = 0x4BU,
	AUX_TYPE_PROTOCOL_DEVICE_ID     = 0x4EU,
};

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

enum { /* OXCRPC v23 §2.2.2.2.4 */
	CLIENT_MODE_UNKNOWN = 0U,
	CLIENT_MODE_CLASSIC = 1U,
	CLIENT_MODE_CACHED  = 2U,
};

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

enum { /* OXCRPC v23 §2.2.2.2.5 */
	SERVER_TYPE_UNKNOWN   = 0x0U,
	SERVER_TYPE_PRIVATE   = 0x1U,
	SERVER_TYPE_PUBLIC    = 0x2U,
	SERVER_TYPE_DIRECTORY = 0x3U,
	SERVER_TYPE_REFERRAL  = 0x4U,
};

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

/* Bitmap for CLIENT_CONTROL_ENABLEFLAGS (OXCRPC v23 §2.2.2.2.15) */
enum {
	ENABLE_PERF_SENDTOSERVER = 0x01U,
	ENABLE_COMPRESSION       = 0x04U,
	ENABLE_HTTP_TUNNELING    = 0x08U,
	ENABLE_PERF_SENDGCDATA   = 0x10U,
};

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

/* bitmap EXORGINFO_ORGFLAGS (OXCRPC v23 §2.2.2.2.17) */
enum {
	PUBLIC_FOLDERS_ENABLED = 0x1U,
	USE_AUTODISCOVER_FOR_PUBLIC_FOLDER_CONFIGURATION = 0x2U,
};

struct AUX_EXORGINFO {
	uint32_t org_flags;
};

struct AUX_PERF_ACCOUNTINFO {
	uint16_t client_id;
	uint16_t reserved;
	GUID account;
};

enum {
	ENDPOINT_CAPABILITIES_SINGLE_ENDPOINT = 0x1U,
};

struct AUX_ENDPOINT_CAPABILITIES {
	uint32_t endpoint_capability_flag;
};

enum {
	CONNECTION_FLAG_CACHED_MODE = 0x1U,
};

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

/* bitmap pulFlags (OXCRPC v23 §2.2.2.1) */
enum {
	PUL_FLAGS_NOCOMPRESSION = 0x1U,
	PUL_FLAGS_NOXORMAGIC    = 0x2U,
	PUL_FLAGS_CHAIN         = 0x4U,
};

struct AUX_INFO {
	uint16_t rhe_version;
	uint16_t rhe_flags;
	DOUBLE_LIST aux_list;
};
