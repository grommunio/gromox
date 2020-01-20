#pragma once
#include "assoc_array.h"
#include "idx_array.h"

#define REQUEST_PARSER			ASSOC_ARRAY

#ifdef __cplusplus
extern "C" {
#endif


REQUEST_PARSER* request_parser_init(const char *request_string);

const char* request_parser_get(REQUEST_PARSER *pparser, const char *name);

IDX_ARRAY* request_parser_get_array(REQUEST_PARSER *pparser, const char *name);

size_t request_parser_num(REQUEST_PARSER *pparser);

void request_parser_free(REQUEST_PARSER *pparser);


#ifdef __cplusplus
}
#endif
