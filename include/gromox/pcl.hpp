#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>		

extern PCL *pcl_init();
void pcl_free(PCL *ppcl);
extern GX_EXPORT BOOL pcl_append(PCL *, const SIZED_XID &);
BOOL pcl_merge(PCL *ppcl1, const PCL *ppcl2);
extern GX_EXPORT BINARY *pcl_serialize(const PCL *);
BOOL pcl_deserialize(PCL *ppcl, const BINARY *pbin);
uint32_t pcl_compare(const PCL *ppcl1, const PCL *ppcl2);
