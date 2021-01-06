#pragma once
#include "mapi_types.h"
#include "double_list.h"

#ifdef __cplusplus
extern "C" {
#endif

IDSET* idset_init(BOOL b_serialize, uint8_t repl_type);
	
BOOL idset_register_mapping(IDSET *pset,
	BINARY *pparam, REPLICA_MAPPING mapping);

void idset_free(IDSET *pset);

void idset_clear(IDSET *pset);

BOOL idset_check_empty(IDSET *pset);

BOOL idset_append(IDSET *pset, uint64_t eid);

BOOL idset_append_range(IDSET *pset, uint16_t replid,
	uint64_t low_value, uint64_t high_value);
void idset_remove(IDSET *pset, uint64_t eid);

BOOL idset_concatenate(IDSET *pset_dst, const IDSET *pset_src);

BOOL idset_hint(IDSET *pset, uint64_t eid);

BINARY* idset_serialize(IDSET *pset);

BINARY* idset_serialize_replid(IDSET *pset);

BINARY* idset_serialize_replguid(IDSET *pset);

BOOL idset_deserialize(IDSET *pset, const BINARY *pbin);

/* convert from deserialize idset into serialize idset */
BOOL idset_convert(IDSET *pset);

/* get maximum of first range in idset for specified replid */
BOOL idset_get_repl_first_max(IDSET *pset,
	uint16_t replid, uint64_t *peid);

BOOL idset_enum_replist(IDSET *pset, void *pparam,
	REPLIST_ENUM replist_enum);

BOOL idset_enum_repl(IDSET *pset, uint16_t replid,
	void *pparam, REPLICA_ENUM repl_enum);

#ifdef __cplusplus
}
#endif
