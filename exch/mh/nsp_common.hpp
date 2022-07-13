#pragma once
#include <type_traits>
#include "nsp_ops.hpp"

extern void *cu_alloc1(size_t size);
template<typename T> T *cu_alloc()
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(cu_alloc1(sizeof(T)));
}
template<typename T> T *cu_alloc(size_t elem)
{
	static_assert(std::is_trivially_destructible_v<T>);
	return static_cast<T *>(cu_alloc1(sizeof(T) * elem));
}
extern FLATUID cu_guid_to_flatuid(const GUID &);
extern GUID cu_flatuid_to_guid(const FLATUID &);
extern BOOL cu_propname_to_nsp(const nsp_propname2 &, NSP_PROPNAME &);
extern BOOL cu_tpropval_to_propval(const TAGGED_PROPVAL &, PROPERTY_VALUE &);
extern BOOL cu_nsp_proprow_to_proplist(const NSP_PROPROW &, LTPROPVAL_ARRAY &);
extern BOOL cu_proplist_to_nsp_proprow(const LTPROPVAL_ARRAY &, NSP_PROPROW &);
extern BOOL cu_nsp_rowset_to_colrow(const LPROPTAG_ARRAY *cols, const NSP_ROWSET &, nsp_rowset2 &);
extern BOOL cu_restriction_to_nspres(const RESTRICTION &, NSPRES &);
