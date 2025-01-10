#pragma once
#include <cstdint>
#include <cstdlib>
#include <type_traits>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#define MAX_DIGLEN											256*1024

extern BOOL cu_build_environment(const char *maildir);
extern void cu_free_environment();
extern void *cu_alloc_bytes(size_t size);
template<typename T> T *cu_alloc()
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(cu_alloc_bytes(sizeof(T)));
}
template<typename T> T *cu_alloc(size_t elem)
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(cu_alloc_bytes(sizeof(T) * elem));
}
extern BOOL cu_switch_allocator();
extern void cu_set_maildir(const char *maildir);
extern const char *cu_get_maildir();
extern char *cu_dup(const char *pstr);
extern BINARY *cu_xid_to_bin(const XID &);
extern BINARY *cu_pcl_append(const BINARY *pcl, const BINARY *change_key);
extern BOOL cu_create_folder(const char *dir, int user_id, uint64_t parent_id, const char *folder_name, uint64_t *folder_id);
extern BOOL cu_get_propids(const PROPNAME_ARRAY *, PROPID_ARRAY *);
extern BOOL cu_get_propids_create(const PROPNAME_ARRAY *, PROPID_ARRAY *);
extern BOOL cu_get_propname(gromox::propid_t, PROPERTY_NAME **);
