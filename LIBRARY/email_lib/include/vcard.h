#ifndef _H_VCARD_
#define _H_VCARD_
#include "common_types.h"
#include "double_list.h"

#define VCARD				DOUBLE_LIST

#define VCARD_NAME_LEN		32

typedef struct _VCARD_PARAM {
	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST *pparamval_list;
} VCARD_PARAM;

typedef struct _VCARD_VALUE {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST subval_list;
} VCARD_VALUE;

typedef struct _VCARD_LINE {
	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST param_list;
	DOUBLE_LIST value_list;
} VCARD_LINE;


#ifdef __cplusplus
extern "C" {
#endif

void vcard_init(VCARD *pvcard);

void vcard_free(VCARD *pvcard);

BOOL vcard_retrieve(VCARD *pvcard, char *in_buff);

BOOL vcard_serialize(VCARD *pvcard, char *out_buff, size_t max_length);

VCARD_LINE* vcard_new_line(const char *name);

void vcard_append_line(VCARD *pvcard, VCARD_LINE *pvline);

void vcard_delete_line(VCARD *pvcard, VCARD_LINE *pvline);

VCARD_PARAM* vcard_new_param(const char*name);

BOOL vcard_append_paramval(VCARD_PARAM *pvparam, const char *paramval);

void vcard_append_param(VCARD_LINE *pvline, VCARD_PARAM *pvparam);
extern VCARD_VALUE *vcard_new_value(void);
BOOL vcard_append_subval(VCARD_VALUE *pvvalue, const char *subval);

void vcard_append_value(VCARD_LINE *pvline, VCARD_VALUE *pvvalue);

const char* vcard_get_first_subvalue(VCARD_LINE *pvline);

VCARD_LINE* vcard_new_simple_line(const char *name, const char *value);

#ifdef __cplusplus
}
#endif

#endif /* _H_VCARD_ */
