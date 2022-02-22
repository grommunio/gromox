#pragma once
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#define VCARD_NAME_LEN		32

struct VCARD_PARAM {
	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST *pparamval_list;
};

struct VCARD_VALUE {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST subval_list;
};

struct VCARD_LINE {
	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST param_list;
	DOUBLE_LIST value_list;
};

struct GX_EXPORT vcard {
	vcard();
	~vcard();
	NOMOVE(vcard);
	void clear();

	DOUBLE_LIST line_list{};
};
using VCARD = vcard;

BOOL vcard_retrieve(VCARD *pvcard, char *in_buff);
BOOL vcard_serialize(VCARD *pvcard, char *out_buff, size_t max_length);
VCARD_LINE* vcard_new_line(const char *name);
void vcard_append_line(VCARD *pvcard, VCARD_LINE *pvline);
VCARD_PARAM* vcard_new_param(const char*name);
BOOL vcard_append_paramval(VCARD_PARAM *pvparam, const char *paramval);
void vcard_append_param(VCARD_LINE *pvline, VCARD_PARAM *pvparam);
extern VCARD_VALUE *vcard_new_value();
BOOL vcard_append_subval(VCARD_VALUE *pvvalue, const char *subval);
void vcard_append_value(VCARD_LINE *pvline, VCARD_VALUE *pvvalue);
const char* vcard_get_first_subvalue(VCARD_LINE *pvline);
VCARD_LINE* vcard_new_simple_line(const char *name, const char *value);
