#include <cstdint>
#include <cstring>
#include <libHX/defs.h>
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include "nsp_interface.h"

enum TRow_ctl_type {
	TRC_LABEL      = 0x0,
	TRC_TEXTCTRL   = 0x1,
	TRC_LISTBOX    = 0x2,
	TRC_CHECKBOX   = 0x5,
	TRC_GROUPBOX   = 0x6,
	TRC_BUTTON     = 0x7,
	TRC_TABPAGE    = 0x8,
	TRC_MVLISTBOX  = 0xb,
	TRC_MVDROPDOWN = 0xc,
};

enum TRow_ctl_flags {
	TRF_NONE       = 0,
	TRF_MULTILINE  = 1 << 0,
	TRF_EDITABLE   = 1 << 1,
	TRF_MANDATORY  = 1 << 2,
	TRF_IMMEDIATE  = 1 << 3,
	TRF_PASSWORD   = 1 << 4,
	TRF_DOUBLEBYTE = 1 << 5,
	TRF_INDEX      = 1 << 6,
};

struct CNTRL {
	uint32_t type, size, string_ofs;
};

struct TRow {
	uint32_t x_pos, delta_x, y_pos, delta_y, control_type, control_flags;
	struct CNTRL cs;
};

struct TRowSet {
	uint32_t type, crows;
};

enum {
	TI_TEMPLATE = 0x1,
	TI_SCRIPT = 0x4,
};

int nsp_interface_get_templateinfo(NSPI_HANDLE handle, uint32_t flags,
    uint32_t type, char *dn, uint32_t codepage, uint32_t locale_id,
    PROPERTY_ROW **ppdata)
{
	*ppdata = nullptr;
	if ((flags & (TI_TEMPLATE | TI_SCRIPT)) != TI_TEMPLATE)
		return ecNotSupported;
	auto row = *ppdata = static_cast<PROPERTY_ROW *>(ndr_stack_alloc(NDR_STACK_OUT, sizeof(PROPERTY_ROW)));
	if (row == nullptr)
		return MAPI_E_NOT_ENOUGH_MEMORY;
	row->reserved = 0;
	row->cvalues  = 1;
	auto val = row->pprops = static_cast<PROPERTY_VALUE *>(ndr_stack_alloc(NDR_STACK_OUT, sizeof(PROPERTY_VALUE)));
	if (val == nullptr)
		return MAPI_E_NOT_ENOUGH_MEMORY;
	val->proptag  = PROP_TAG_TEMPLATEDATA;
	val->reserved = 0;

	static constexpr struct mydia {
		struct TRowSet hdr;
		struct TRow c[28];
		char t[17][16];
	} dialogbox = {
		{1, ARRAY_SIZE(dialogbox.c)},
		{
		{  0, 545,   0-0,  71, TRC_GROUPBOX, TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[0])}},
		{ 10, 100,  20-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[1])}},
		{120,  54,  20-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_GIVENNAME, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{177,  35,  20-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[2])}},
		{247,  21,  20-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_INITIALS, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{277, 100,  20-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[3])}},
		{384, 148,  20-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_SURNAME, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{ 10, 100,  46-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[4])}},
		{120, 148,  46-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_DISPLAYNAME, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{277, 100,  46-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[5])}},
		{ 10, 100,  78-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[6])}},
		{120, 148,  78-2,  36, TRC_TEXTCTRL, TRF_MULTILINE, {PROP_TAG_POSTALADDRESS, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{ 10, 100, 127-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[7])}},
		{120, 148, 127-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_LOCATION, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{ 10, 100, 151-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[8])}},
		{120, 148, 151-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_POSTALADDRESS, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{ 10, 100, 175-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[9])}},
		{120, 148, 175-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_POSTALCODE, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{ 10, 100, 200-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[10])}},
		{120, 148, 200-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_LOCATION, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{277, 100,  78-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[11])}},
		{384, 148,  78-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_TITLE, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{277, 100, 127-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[12])}},
		{384, 148, 127-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_COMPANYNAME, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{277, 100, 151-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[13])}},
		{384, 148, 151-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_DEPARTMENTNAME, 255, offsetof(__typeof__(dialogbox), t[15])}},
		{277, 100, 200-0,  14, TRC_LABEL,    TRF_NONE, {0, 0, offsetof(__typeof__(dialogbox), t[14])}},
		{384, 148, 200-2,  14, TRC_TEXTCTRL, TRF_NONE, {PROP_TAG_BUSINESSTELEPHONENUMBER, 255, offsetof(__typeof__(dialogbox), t[15])}},
		},
		{
		/*0*/ "Name:",
		/*1*/ "First:",
		/*2*/ "Initials:",
		/*3*/ "Last:",
		/*4*/ "Display:",
		/*5*/ "Alias:",
		/*6*/ "Address:",
		/*7*/ "City:",
		/*8*/ "State:",
		/*9*/ "Zip code:",
		/*10*/ "Country/Region:",
		/*11*/ "Title:",
		/*12*/ "Company:",
		/*13*/ "Department:",
		/*14*/ "Phone:",
		/*15*/ "*",
		},
	};
	val->value.bin.cb = sizeof(dialogbox);
	val->value.bin.pv = ndr_stack_alloc(NDR_STACK_OUT, sizeof(dialogbox));
	if (val->value.bin.pv == nullptr)
		return MAPI_E_NOT_ENOUGH_MEMORY;
	memcpy(val->value.bin.pv, &dialogbox, sizeof(dialogbox));
	return 0;
}
