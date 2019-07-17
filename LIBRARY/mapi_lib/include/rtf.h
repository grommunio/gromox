#ifndef _H_RTF_
#define _H_RTF_
#include "element_data.h"


#ifdef __cplusplus
extern "C" {
#endif

BOOL rtf_init_library(CPID_TO_CHARSET cpid_to_charset);

BOOL rtf_to_html(const char *pbuff_in, size_t length,
	const char *charset, char *pbuff_out, size_t *plength,
	ATTACHMENT_LIST *pattachments);


#ifdef __cplusplus
}
#endif

#endif /* _H_RTF_ */

