#pragma once
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/double_list.hpp>
#define VCARD_NAME_LEN		32

struct GX_EXPORT vcard_param {
	ec_error_t append_paramval(const char *paramval);

	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST pparamval_list;
};
using VCARD_PARAM = vcard_param;

struct GX_EXPORT vcard_value {
	ec_error_t append_subval(const char *);

	DOUBLE_LIST_NODE node;
	DOUBLE_LIST subval_list;
};
using VCARD_VALUE = vcard_value;

struct GX_EXPORT vcard_line {
	ec_error_t append_param(VCARD_PARAM *);
	ec_error_t append_param(const char *);
	ec_error_t append_param(const char *, const char *);
	ec_error_t append_value();
	ec_error_t append_value(VCARD_VALUE *);
	ec_error_t append_value(const char *);
	const char *get_first_subval() const;

	DOUBLE_LIST_NODE node;
	char name[VCARD_NAME_LEN];
	DOUBLE_LIST param_list;
	DOUBLE_LIST value_list;
};
using VCARD_LINE = vcard_line;

struct GX_EXPORT vcard {
	vcard();
	vcard(vcard &&o);
	~vcard();
	vcard &operator=(vcard &&);

	void clear();
	ec_error_t retrieve_single(char *in_buff);
	BOOL serialize(char *out_buff, size_t max_length);
	ec_error_t append_line2(VCARD_LINE *);
	ec_error_t append_line2(const char *, const char *);

	DOUBLE_LIST line_list{};
};
using VCARD = vcard;

VCARD_LINE* vcard_new_line(const char *name);
VCARD_PARAM* vcard_new_param(const char*name);
extern VCARD_VALUE *vcard_new_value();
extern GX_EXPORT ec_error_t vcard_retrieve_multi(char *input, std::vector<vcard> &, size_t limit = 0);
