#include <gromox/defs.h>
#include "mapi_types.h"

unsigned int gxerr_to_hresult(gxerr_t e)
{
	switch (e) {
	case GXERR_SUCCESS: return EC_SUCCESS;
	default: return EC_ERROR;
	}
}
