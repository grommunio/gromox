#ifndef _H_RPC_TYPES_
#define _H_RPC_TYPES_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "common_types.h"

typedef struct _CONTEXT_HANDLE {
	uint32_t handle_type;
	GUID guid;
} CONTEXT_HANDLE;

typedef struct _SYNTAX_ID {
	GUID uuid;
	uint32_t version;
} SYNTAX_ID;

#endif /* _H_RPC_TYPES_ */
