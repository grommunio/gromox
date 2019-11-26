#ifndef _H_PCL_
#define _H_PCL_
#include "mapi_types.h"		

#ifdef __cplusplus
extern "C" {
#endif

extern PCL *pcl_init(void);
void pcl_free(PCL *ppcl);

BOOL pcl_append(PCL *ppcl, const SIZED_XID *pxid);

BOOL pcl_merge(PCL *ppcl1, const PCL *ppcl2);

BINARY* pcl_serialize(PCL *ppcl);

BOOL pcl_deserialize(PCL *ppcl, const BINARY *pbin);

uint32_t pcl_compare(const PCL *ppcl1, const PCL *ppcl2);

#ifdef __cplusplus
}
#endif

#endif /* _H_PCL_ */
