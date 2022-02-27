#pragma once
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#define VCARD_NAME_LEN		32

struct VCARD_PARAM {
	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST *pparamval_list;
};

struct GX_EXPORT vcard_value {
	BOOL append_subval(const char *);

	DOUBLE_LIST_NODE node;
	DOUBLE_LIST subval_list;
};
using VCARD_VALUE = vcard_value;

struct GX_EXPORT vcard_line {
	void append_param(VCARD_PARAM *);
	void append_value(VCARD_VALUE *);
	const char *get_first_subval() const;

	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST param_list;
	DOUBLE_LIST value_list;
};
using VCARD_LINE = vcard_line;

struct GX_EXPORT vcard {
	vcard();
	~vcard();
	NOMOVE(vcard);
	void clear();
	BOOL retrieve(char *in_buff);
	BOOL serialize(char *out_buff, size_t max_length);
	void append_line(VCARD_LINE *);

	DOUBLE_LIST line_list{};
};
using VCARD = vcard;

VCARD_LINE* vcard_new_line(const char *name);
VCARD_PARAM* vcard_new_param(const char*name);
BOOL vcard_append_paramval(VCARD_PARAM *pvparam, const char *paramval);
extern VCARD_VALUE *vcard_new_value();
VCARD_LINE* vcard_new_simple_line(const char *name, const char *value);
