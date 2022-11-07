// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tnef.hpp>
#include <gromox/util.hpp>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

#define TNEF_LEGACY								0x0001
#define TNEF_VERSION							0x10000

/*
	TRIPLES										0x0000
	STRING										0x0001
	TEXT										0x0002
	DATE										0x0003
	SHORT										0x0004
	LONG										0x0005
	BINARY										0x0006
	CLASS										0x0007
	LONGARRAY									0x0008
*/

#define ATTRIBUTE_ID_OWNER						0x00060000
#define ATTRIBUTE_ID_SENTFOR					0x00060001
#define ATTRIBUTE_ID_DELEGATE					0x00060002
#define ATTRIBUTE_ID_DATESTART					0x00030006
#define ATTRIBUTE_ID_DATEEND					0x00030007
#define ATTRIBUTE_ID_AIDOWNER					0x00050008
#define ATTRIBUTE_ID_REQUESTRES					0x00040009
#define ATTRIBUTE_ID_ORIGNINALMESSAGECLASS		0x00070600
#define ATTRIBUTE_ID_FROM						0x00008000
#define ATTRIBUTE_ID_SUBJECT 					0x00018004
#define ATTRIBUTE_ID_DATESENT					0x00038005
#define ATTRIBUTE_ID_DATERECD					0x00038006
#define ATTRIBUTE_ID_MESSAGESTATUS				0x00068007
#define ATTRIBUTE_ID_MESSAGECLASS				0x00078008
#define ATTRIBUTE_ID_MESSAGEID					0x00018009
#define ATTRIBUTE_ID_BODY						0x0002800C
#define ATTRIBUTE_ID_PRIORITY					0x0004800D
#define ATTRIBUTE_ID_ATTACHDATA					0x0006800F
#define ATTRIBUTE_ID_ATTACHTITLE				0x00018010
#define ATTRIBUTE_ID_ATTACHMETAFILE				0x00068011
#define ATTRIBUTE_ID_ATTACHCREATEDATE			0x00038012
#define ATTRIBUTE_ID_ATTACHMODIFYDATE			0x00038013
#define ATTRIBUTE_ID_DATEMODIFY					0x00038020
#define ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME	0x00069001
#define ATTRIBUTE_ID_ATTACHRENDDATA				0x00069002
#define ATTRIBUTE_ID_MSGPROPS					0x00069003
#define ATTRIBUTE_ID_RECIPTABLE					0x00069004
#define ATTRIBUTE_ID_ATTACHMENT					0x00069005
#define ATTRIBUTE_ID_TNEFVERSION				0x00089006
#define ATTRIBUTE_ID_OEMCODEPAGE				0x00069007
#define ATTRIBUTE_ID_PARENTID					0x0001800A
#define ATTRIBUTE_ID_CONVERSATIONID				0x0001800B

#define LVL_MESSAGE								0x1
#define LVL_ATTACHMENT							0x2

#define ATTACH_TYPE_FILE						0x0001
#define ATTACH_TYPE_OLE							0x0002

#define FILE_DATA_DEFAULT						0x00000000
#define FILE_DATA_MACBINARY						0x00000001

#define FMS_READ								0x20
#define FMS_MODIFIED							0x01
#define FMS_SUBMITTED							0x04
#define FMS_LOCAL								0x02
#define FMS_HASATTACH							0x80

using namespace std::string_literals;
using namespace gromox;
using propmap_t = std::unordered_map<std::string, uint16_t>;
using propididmap_t = std::unordered_map<uint16_t, uint16_t>;

namespace {
struct TNEF_ATTRIBUTE {
	uint8_t lvl;
	uint32_t attr_id;
	void *pvalue;
};

struct TRP_HEADER {
	uint16_t trp_id;
	uint16_t total_len;
	uint16_t displayname_len;
	uint16_t address_len;
};

struct DTR {
    uint16_t year;
	uint16_t month;
	uint16_t day;
    uint16_t hour;
	uint16_t min;
	uint16_t sec;
    uint16_t dow;
};

struct ATTR_ADDR {
	char *displayname;
	char *address;
};

struct REND_DATA {
	uint16_t attach_type;
	uint32_t attach_position;
	uint16_t render_width;
	uint16_t render_height;
	uint32_t data_flags;
};

struct TNEF_PROPVAL {
	uint16_t proptype;
	uint16_t propid;
	PROPERTY_NAME *ppropname;
	void *pvalue;
};

struct TNEF_PROPLIST {
	uint32_t count;
	TNEF_PROPVAL *ppropval;
};

struct TNEF_PROPSET {
	uint32_t count;
	TNEF_PROPLIST **pplist;
};

struct tnef_pull : public EXT_PULL {
	int g_propname(PROPERTY_NAME *);
	int g_propval(TNEF_PROPVAL *);
	int g_attr(TNEF_ATTRIBUTE *);
};

struct tnef_push : public EXT_PUSH {
	int p_propname(const PROPERTY_NAME &);
	int p_propval(const TNEF_PROPVAL &);
	int p_attr(uint8_t level, uint32_t attr_id, const void *value);

	EXT_BUFFER_ALLOC tnef_alloc = nullptr;
	GET_PROPNAME tnef_getpropname = nullptr;
};

}

static constexpr uint32_t indet_rendering_pos = UINT32_MAX;
static const uint8_t g_pad_bytes[3]{};
static BOOL tnef_serialize_internal(tnef_push &, BOOL b_embedded, const MESSAGE_CONTENT *);

void tnef_init_library()
{
	textmaps_init();
}
	
static BOOL tnef_username_to_oneoff(const char *username,
	const char *pdisplay_name, BINARY *pbin)
{
	EXT_PUSH ext_push;
	ONEOFF_ENTRYID tmp_entry;
	
	tmp_entry.flags = 0;
	tmp_entry.version = 0;
	tmp_entry.ctrl_flags = CTRL_FLAG_NORICH | CTRL_FLAG_UNICODE;
	if (NULL != pdisplay_name) {
		tmp_entry.pdisplay_name = deconst(pdisplay_name);
	} else {
		tmp_entry.pdisplay_name = deconst("");
	}
	tmp_entry.paddress_type = deconst("SMTP");
	tmp_entry.pmail_address = deconst(username);
	if (!ext_push.init(pbin->pb, 1280, EXT_FLAG_UTF16) ||
	    ext_push.p_oneoff_eid(tmp_entry) != EXT_ERR_SUCCESS)
		return false;
	pbin->cb = ext_push.m_offset;
	return TRUE;
}

static uint16_t tnef_generate_checksum(
	const uint8_t *pdata, uint32_t len)
{
	uint32_t mysum;

	mysum = 0;
	for (size_t i = 0; i < len; ++i)
		mysum = (mysum + pdata[i]) & 0xFFFF;
	return mysum;
}

static uint8_t tnef_align(uint32_t length)
{
    return ((length + 3) & ~3) - length;
}

int tnef_pull::g_propname(PROPERTY_NAME *r)
{
	auto pext = this;
	auto &ext = *pext;
	uint32_t tmp_int;
	
	TRY(pext->g_guid(&r->guid));
	TRY(pext->g_uint32(&tmp_int));
	if (0 == tmp_int) {
		r->kind = MNID_ID;
		return pext->g_uint32(&r->lid);
	} else if (1 == tmp_int) {
		r->kind = MNID_STRING;
		TRY(pext->g_uint32(&tmp_int));
		uint32_t offset = ext.m_offset + tmp_int;
		TRY(pext->g_wstr(&r->pname));
		if (ext.m_offset > offset)
			return EXT_ERR_FORMAT;
		ext.m_offset = offset;
		return pext->advance(tnef_align(tmp_int));
	}
	return EXT_ERR_FORMAT;
}

int tnef_pull::g_propval(TNEF_PROPVAL *r)
{
	auto pext = this;
	auto &ext = *pext;
	uint32_t tmp_int;
	uint16_t fake_byte;
	
	TRY(pext->g_uint16(&r->proptype));
	TRY(pext->g_uint16(&r->propid));
	r->ppropname = NULL;
	if (r->propid == PROP_ID_INVALID)
		mlog(LV_WARN, "W-1273: TNEF with PROP_ID_INVALID seen");
	if (is_nameprop_id(r->propid)) {
		r->ppropname = pext->anew<PROPERTY_NAME>();
		if (NULL == r->ppropname) {
			return EXT_ERR_ALLOC;
		}
		TRY(g_propname(r->ppropname));
	}
	switch (r->proptype) {
	case PT_SHORT:
		r->pvalue = pext->anew<uint16_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint16(static_cast<uint16_t *>(r->pvalue)));
		return pext->advance(2);
	case PT_ERROR:
	case PT_LONG:
		r->pvalue = pext->anew<uint32_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		return pext->g_uint32(static_cast<uint32_t *>(r->pvalue));
	case PT_FLOAT:
		r->pvalue = pext->anew<float>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		return pext->g_float( static_cast<float *>(r->pvalue));
	case PT_DOUBLE:
	case PT_APPTIME:
		r->pvalue = pext->anew<double>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		return pext->g_double(static_cast<double *>(r->pvalue));
	case PT_BOOLEAN:
		r->pvalue = pext->anew<uint8_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint16(&fake_byte));
		*(uint8_t*)r->pvalue = fake_byte;
		return pext->advance(2);
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		r->pvalue = pext->anew<uint64_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		return pext->g_uint64(static_cast<uint64_t *>(r->pvalue));
	case PT_STRING8: {
		TRY(pext->g_uint32(&tmp_int));
		if (1 != tmp_int) {
			return EXT_ERR_FORMAT;
		}
		TRY(pext->g_uint32(&tmp_int));
		uint32_t offset = ext.m_offset + tmp_int;
		TRY(pext->g_str(reinterpret_cast<char **>(&r->pvalue)));
		if (ext.m_offset > offset)
			return EXT_ERR_FORMAT;
		ext.m_offset = offset;
		return pext->advance(tnef_align(tmp_int));
	}
	case PT_UNICODE: {
		TRY(pext->g_uint32(&tmp_int));
		if (1 != tmp_int) {
			return EXT_ERR_FORMAT;
		}
		TRY(pext->g_uint32(&tmp_int));
		uint32_t offset = ext.m_offset + tmp_int;
		TRY(pext->g_wstr(reinterpret_cast<char **>(&r->pvalue)));
		if (ext.m_offset > offset)
			return EXT_ERR_FORMAT;
		ext.m_offset = offset;
		return pext->advance(tnef_align(tmp_int));
	}
	case PT_CLSID:
		r->pvalue = pext->anew<GUID>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		return pext->g_guid(static_cast<GUID *>(r->pvalue));
	case PT_SVREID:
		r->pvalue = pext->anew<SVREID>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		return pext->g_svreid(static_cast<SVREID *>(r->pvalue));
	case PT_OBJECT: {
		r->pvalue = pext->anew<BINARY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint32(&tmp_int));
		if (1 != tmp_int) {
			return EXT_ERR_FORMAT;
		}
		auto bv = static_cast<BINARY *>(r->pvalue);
		TRY(pext->g_uint32(&bv->cb));
		if (bv->cb < 16 || bv->cb > ext.m_data_size - ext.m_offset)
			return EXT_ERR_FORMAT;
		bv->pv = ext.m_alloc(bv->cb);
		if (bv->pv == nullptr) {
			bv->cb = 0;
			return EXT_ERR_ALLOC;
		}
		uint32_t offset = ext.m_offset;
		TRY(pext->g_bytes(bv->pv, bv->cb));
		if (memcmp(bv->pv, &IID_IMessage, sizeof(IID_IMessage)) != 0 &&
		    memcmp(bv->pv, &IID_IStorage, sizeof(IID_IMessage)) != 0 &&
		    memcmp(bv->pv, &IID_IStream, sizeof(IID_IMessage)) != 0)
			return EXT_ERR_FORMAT;
		return pext->advance(tnef_align(ext.m_offset - offset));
	}
	case PT_BINARY: {
		r->pvalue = pext->anew<BINARY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint32(&tmp_int));
		if (1 != tmp_int) {
			return EXT_ERR_FORMAT;
		}
		auto bv = static_cast<BINARY *>(r->pvalue);
		TRY(pext->g_uint32(&bv->cb));
		if (bv->cb + ext.m_offset > ext.m_data_size)
			return EXT_ERR_FORMAT;
		bv->pv = ext.m_alloc(bv->cb);
		if (bv->pv == nullptr) {
			bv->cb = 0;
			return EXT_ERR_ALLOC;
		}
		uint32_t offset = ext.m_offset;
		TRY(pext->g_bytes(bv->pv, bv->cb));
		return pext->advance(tnef_align(ext.m_offset - offset));
	}
	case PT_MV_SHORT: {
		r->pvalue = pext->anew<SHORT_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto sa = static_cast<SHORT_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&sa->count));
		if (sa->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (sa->count == 0) {
			sa->ps = NULL;
		} else {
			sa->ps = pext->anew<uint16_t>(sa->count);
			if (sa->ps == nullptr) {
				sa->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < sa->count; ++i) {
			TRY(pext->g_uint16(&sa->ps[i]));
			TRY(pext->advance(2));
		}
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_LONG: {
		r->pvalue = pext->anew<LONG_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto la = static_cast<LONG_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&la->count));
		if (la->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (la->count == 0) {
			la->pl = nullptr;
		} else {
			la->pl = pext->anew<uint32_t>(la->count);
			if (la->pl == nullptr) {
				la->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->g_uint32(&la->pl[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		r->pvalue = pext->anew<LONGLONG_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto la = static_cast<LONGLONG_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&la->count));
		if (la->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (la->count == 0) {
			la->pll = nullptr;
		} else {
			la->pll = pext->anew<uint64_t>(la->count);
			if (la->pll == nullptr) {
				la->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->g_uint64(&la->pll[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_FLOAT: {
		r->pvalue = pext->anew<FLOAT_ARRAY>();
		if (r->pvalue == nullptr)
			return EXT_ERR_ALLOC;
		auto la = static_cast<FLOAT_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&la->count));
		if (la->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (la->count == 0) {
			la->mval = nullptr;
		} else {
			la->mval = pext->anew<float>(la->count);
			if (la->mval == nullptr) {
				la->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->g_float(&la->mval[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		r->pvalue = pext->anew<DOUBLE_ARRAY>();
		if (r->pvalue == nullptr)
			return EXT_ERR_ALLOC;
		auto la = static_cast<DOUBLE_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&la->count));
		if (la->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (la->count == 0) {
			la->mval = nullptr;
		} else {
			la->mval = pext->anew<double>(la->count);
			if (la->mval == nullptr) {
				la->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->g_double(&la->mval[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_STRING8: {
		r->pvalue = pext->anew<STRING_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto sa = static_cast<STRING_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&sa->count));
		if (sa->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (sa->count == 0) {
			sa->ppstr = nullptr;
		} else {
			sa->ppstr = pext->anew<char *>(sa->count);
			if (sa->ppstr == nullptr) {
				sa->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < sa->count; ++i) {
			TRY(pext->g_uint32(&tmp_int));
			uint32_t offset = ext.m_offset + tmp_int;
			TRY(pext->g_str(&sa->ppstr[i]));
			if (ext.m_offset > offset)
				return EXT_ERR_FORMAT;
			ext.m_offset = offset;
			TRY(pext->advance(tnef_align(tmp_int)));
		}
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_UNICODE: {
		r->pvalue = pext->anew<STRING_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto sa = static_cast<STRING_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&sa->count));
		if (sa->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (sa->count == 0) {
			sa->ppstr = nullptr;
		} else {
			sa->ppstr = pext->anew<char *>(sa->count);
			if (sa->ppstr == nullptr) {
				sa->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < sa->count; ++i) {
			TRY(pext->g_uint32(&tmp_int));
			uint32_t offset = ext.m_offset + tmp_int;
			TRY(pext->g_wstr(&sa->ppstr[i]));
			if (ext.m_offset > offset)
				return EXT_ERR_FORMAT;
			ext.m_offset = offset;
			TRY(pext->advance(tnef_align(tmp_int)));
		}
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_CLSID: {
		r->pvalue = pext->anew<GUID_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto ga = static_cast<GUID_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&ga->count));
		if (ga->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (ga->count == 0) {
			ga->pguid = nullptr;
		} else {
			ga->pguid = pext->anew<GUID>(ga->count);
			if (ga->pguid == nullptr) {
				ga->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < ga->count; ++i)
			TRY(pext->g_guid(&ga->pguid[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_BINARY: {
		r->pvalue = pext->anew<BINARY_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto ba = static_cast<BINARY_ARRAY *>(r->pvalue);
		TRY(pext->g_uint32(&ba->count));
		if (ba->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (ba->count == 0) {
			ba->pbin = nullptr;
		} else {
			ba->pbin = pext->anew<BINARY>(ba->count);
			if (ba->pbin == nullptr) {
				ba->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < ba->count; ++i) {
			TRY(pext->g_uint32(&ba->pbin[i].cb));
			if (ba->pbin[i].cb + ext.m_offset > ext.m_data_size)
				return EXT_ERR_FORMAT;
			if (ba->pbin[i].cb == 0) {
				ba->pbin[i].pv = nullptr;
			} else {
				ba->pbin[i].pv = ext.m_alloc(ba->pbin[i].cb);
				if (ba->pbin[i].pv == nullptr) {
					ba->pbin[i].cb = 0;
					return EXT_ERR_ALLOC;
				}
				TRY(pext->g_bytes(ba->pbin[i].pv, ba->pbin[i].cb));
				TRY(pext->advance(tnef_align(ba->pbin[i].cb)));
			}
		}
		return EXT_ERR_SUCCESS;
	}
	}
	return EXT_ERR_BAD_SWITCH;
}

int tnef_pull::g_attr(TNEF_ATTRIBUTE *r)
{
	auto pext = this;
	auto &ext = *pext;
	DTR tmp_dtr;
	uint32_t len;
	uint16_t tmp_len;
	struct tm tmp_tm;
    uint16_t checksum;
	TRP_HEADER header;

	TRY(pext->g_uint8(&r->lvl));
	if (LVL_MESSAGE != r->lvl &&
		LVL_ATTACHMENT != r->lvl) {
		mlog(LV_DEBUG, "tnef: attribute level error");
		return EXT_ERR_FORMAT;
	}
	TRY(pext->g_uint32(&r->attr_id));
	if (LVL_MESSAGE == r->lvl) {
		switch (r->attr_id) {
		case ATTRIBUTE_ID_MSGPROPS:
		case ATTRIBUTE_ID_OWNER:
		case ATTRIBUTE_ID_SENTFOR:
		case ATTRIBUTE_ID_DELEGATE:
		case ATTRIBUTE_ID_DATESTART:
		case ATTRIBUTE_ID_DATEEND:
		case ATTRIBUTE_ID_AIDOWNER:
		case ATTRIBUTE_ID_REQUESTRES:
		case ATTRIBUTE_ID_ORIGNINALMESSAGECLASS:
		case ATTRIBUTE_ID_FROM:
		case ATTRIBUTE_ID_SUBJECT:
		case ATTRIBUTE_ID_DATESENT:
		case ATTRIBUTE_ID_DATERECD:
		case ATTRIBUTE_ID_MESSAGESTATUS:
		case ATTRIBUTE_ID_MESSAGECLASS:
		case ATTRIBUTE_ID_MESSAGEID:
		case ATTRIBUTE_ID_BODY:
		case ATTRIBUTE_ID_PRIORITY:
		case ATTRIBUTE_ID_DATEMODIFY:
		case ATTRIBUTE_ID_RECIPTABLE:
		case ATTRIBUTE_ID_TNEFVERSION:
		case ATTRIBUTE_ID_OEMCODEPAGE:
		case ATTRIBUTE_ID_PARENTID:
		case ATTRIBUTE_ID_CONVERSATIONID:
			break;
		default:
			mlog(LV_DEBUG, "tnef: unknown attribute 0x%x", r->attr_id);
			return EXT_ERR_FORMAT;
		}
		
	} else {
		switch (r->attr_id) {
		case ATTRIBUTE_ID_ATTACHMENT:
		case ATTRIBUTE_ID_ATTACHDATA:
		case ATTRIBUTE_ID_ATTACHTITLE:
		case ATTRIBUTE_ID_ATTACHMETAFILE:
		case ATTRIBUTE_ID_ATTACHCREATEDATE:
		case ATTRIBUTE_ID_ATTACHMODIFYDATE:
		case ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME:
		case ATTRIBUTE_ID_ATTACHRENDDATA:
			break;
		default:
			mlog(LV_DEBUG, "tnef: unknown attribute 0x%x", r->attr_id);
			return EXT_ERR_FORMAT;
		}
	}
	TRY(pext->g_uint32(&len));
	if (ext.m_offset + len > ext.m_data_size)
		return EXT_ERR_FORMAT;
	uint32_t offset = ext.m_offset;
	switch (r->attr_id) {
	case ATTRIBUTE_ID_FROM: {
		r->pvalue = pext->anew<ATTR_ADDR>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint16(&header.trp_id));
		if (0x0004 != header.trp_id) {
			mlog(LV_DEBUG, "tnef: tripidOneOff error");
			return EXT_ERR_FORMAT;
		}
		TRY(pext->g_uint16(&header.total_len));
		TRY(pext->g_uint16(&header.displayname_len));
		TRY(pext->g_uint16(&header.address_len));
		if (header.total_len != header.displayname_len +
			header.address_len + 16) {
			mlog(LV_DEBUG, "tnef: triple header's structure-length error");
			return EXT_ERR_FORMAT;
		}
		uint32_t offset1 = ext.m_offset;
		TRY(pext->g_str(&static_cast<ATTR_ADDR *>(r->pvalue)->displayname));
		offset1 += header.displayname_len;
		if (ext.m_offset > offset1) {
			mlog(LV_DEBUG, "tnef: triple header's sender-name-length error");
			return EXT_ERR_FORMAT;
		}
		ext.m_offset = offset1;
		TRY(pext->g_str(&static_cast<ATTR_ADDR *>(r->pvalue)->address));
		offset1 += header.address_len;
		if (ext.m_offset > offset1) {
			mlog(LV_DEBUG, "tnef: triple header's sender-email-length error");
			return EXT_ERR_FORMAT;
		}
		ext.m_offset = offset1;
		TRY(pext->advance(8));
		break;
	}
	case ATTRIBUTE_ID_SUBJECT:
	case ATTRIBUTE_ID_MESSAGEID:
	case ATTRIBUTE_ID_ATTACHTITLE:
	case ATTRIBUTE_ID_ORIGNINALMESSAGECLASS:
	case ATTRIBUTE_ID_MESSAGECLASS:
	case ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME:
	case ATTRIBUTE_ID_PARENTID:
	case ATTRIBUTE_ID_CONVERSATIONID:
		TRY(pext->g_str(reinterpret_cast<char **>(&r->pvalue)));
		break;
	case ATTRIBUTE_ID_DATESTART:
	case ATTRIBUTE_ID_DATEEND:
	case ATTRIBUTE_ID_DATESENT:
	case ATTRIBUTE_ID_DATERECD:
	case ATTRIBUTE_ID_ATTACHCREATEDATE:
	case ATTRIBUTE_ID_ATTACHMODIFYDATE:
	case ATTRIBUTE_ID_DATEMODIFY:
		r->pvalue = pext->anew<uint64_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint16(&tmp_dtr.year));
		TRY(pext->g_uint16(&tmp_dtr.month));
		TRY(pext->g_uint16(&tmp_dtr.day));
		TRY(pext->g_uint16(&tmp_dtr.hour));
		TRY(pext->g_uint16(&tmp_dtr.min));
		TRY(pext->g_uint16(&tmp_dtr.sec));
		TRY(pext->g_uint16(&tmp_dtr.dow));
		tmp_tm.tm_sec = tmp_dtr.sec;
		tmp_tm.tm_min = tmp_dtr.min;
		tmp_tm.tm_hour = tmp_dtr.hour;
		tmp_tm.tm_mday = tmp_dtr.day;
		tmp_tm.tm_mon = tmp_dtr.month - 1;
		tmp_tm.tm_year = tmp_dtr.year - 1900;
		tmp_tm.tm_wday = tmp_dtr.dow - 1;
		tmp_tm.tm_yday = 0;
		tmp_tm.tm_isdst = 0;
		*(uint64_t*)r->pvalue = rop_util_unix_to_nttime(mktime(&tmp_tm));
		break;
	case ATTRIBUTE_ID_REQUESTRES:
	case ATTRIBUTE_ID_PRIORITY:
		r->pvalue = pext->anew<uint16_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint16(static_cast<uint16_t *>(r->pvalue)));
		break;
	case ATTRIBUTE_ID_AIDOWNER:
		r->pvalue = pext->anew<uint32_t>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint32(static_cast<uint32_t *>(r->pvalue)));
		break;
	case ATTRIBUTE_ID_BODY:
		r->pvalue = ext.m_alloc(len + 1);
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_bytes(r->pvalue, len));
		((char*)r->pvalue)[len] = '\0';
		break;
	case ATTRIBUTE_ID_MSGPROPS:
	case ATTRIBUTE_ID_ATTACHMENT: {
		r->pvalue = pext->anew<TNEF_PROPLIST>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto tf = static_cast<TNEF_PROPLIST *>(r->pvalue);
		TRY(pext->g_uint32(&tf->count));
		if (tf->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (tf->count == 0) {
			tf->ppropval = nullptr;
		} else {
			tf->ppropval = pext->anew<TNEF_PROPVAL>(tf->count);
			if (tf->ppropval == nullptr) {
				tf->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < tf->count; ++i)
			TRY(g_propval(&tf->ppropval[i]));
		break;
	}
	case ATTRIBUTE_ID_RECIPTABLE: {
		r->pvalue = pext->anew<TNEF_PROPSET>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto tf = static_cast<TNEF_PROPSET *>(r->pvalue);
		TRY(pext->g_uint32(&tf->count));
		if (tf->count > 0xFFFF)
			return EXT_ERR_FORMAT;
		if (tf->count == 0) {
			tf->pplist = nullptr;
		} else {
			tf->pplist = pext->anew<TNEF_PROPLIST *>(tf->count);
			if (tf->pplist == nullptr) {
				tf->count = 0;
				return EXT_ERR_ALLOC;
			}
		}
		for (size_t i = 0; i < tf->count; ++i) {
			tf->pplist[i] = pext->anew<TNEF_PROPLIST>();
			if (tf->pplist[i] == nullptr)
				return EXT_ERR_ALLOC;
			TRY(pext->g_uint32(&tf->pplist[i]->count));
			if (tf->pplist[i]->count > 0xFFFF)
				return EXT_ERR_FORMAT;
			if (tf->pplist[i]->count == 0) {
				tf->pplist[i]->ppropval = nullptr;
			} else {
				tf->pplist[i]->ppropval = pext->anew<TNEF_PROPVAL>(tf->pplist[i]->count);
				if (tf->pplist[i]->ppropval == nullptr) {
					tf->pplist[i]->count = 0;
					return EXT_ERR_ALLOC;
				}
			}
			for (size_t j = 0; j < tf->pplist[i]->count; ++j)
				TRY(g_propval(&tf->pplist[i]->ppropval[j]));
		}
		break;
	}
	case ATTRIBUTE_ID_OWNER:
	case ATTRIBUTE_ID_SENTFOR: {
		r->pvalue = pext->anew<ATTR_ADDR>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		TRY(pext->g_uint16(&tmp_len));
		uint32_t offset1 = ext.m_offset + tmp_len;
		TRY(pext->g_str(&static_cast<ATTR_ADDR *>(r->pvalue)->displayname));
		if (ext.m_offset > offset1) {
			mlog(LV_DEBUG, "tnef: owner's display-name-length error");
			return EXT_ERR_FORMAT;
		}
		ext.m_offset = offset1;
		TRY(pext->g_uint16(&tmp_len));
		offset1 = ext.m_offset + tmp_len;
		TRY(pext->g_str(&static_cast<ATTR_ADDR *>(r->pvalue)->address));
		if (ext.m_offset > offset1) {
			mlog(LV_DEBUG, "tnef: owner's address-length error");
			return EXT_ERR_FORMAT;
		}
		ext.m_offset = offset1;
		break;
	}
	case ATTRIBUTE_ID_ATTACHRENDDATA: {
		r->pvalue = pext->anew<REND_DATA>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto rd = static_cast<REND_DATA *>(r->pvalue);
		TRY(pext->g_uint16(&rd->attach_type));
		TRY(pext->g_uint32(&rd->attach_position));
		TRY(pext->g_uint16(&rd->render_width));
		TRY(pext->g_uint16(&rd->render_height));
		TRY(pext->g_uint32(&rd->data_flags));
		break;
	}
	case ATTRIBUTE_ID_DELEGATE:
	case ATTRIBUTE_ID_ATTACHDATA:
	case ATTRIBUTE_ID_ATTACHMETAFILE:
	case ATTRIBUTE_ID_MESSAGESTATUS: {
		r->pvalue = pext->anew<BINARY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto bv = static_cast<BINARY *>(r->pvalue);
		bv->cb = len;
		bv->pv = ext.m_alloc(len);
		if (bv->pv == nullptr)
			return EXT_ERR_ALLOC;
		TRY(pext->g_bytes(bv->pv, len));
		break;
	}
	case ATTRIBUTE_ID_TNEFVERSION:
	case ATTRIBUTE_ID_OEMCODEPAGE: {
		r->pvalue = pext->anew<LONG_ARRAY>();
		if (NULL == r->pvalue) {
			return EXT_ERR_ALLOC;
		}
		auto la = static_cast<LONG_ARRAY *>(r->pvalue);
		la->count = len / sizeof(uint32_t);
		la->pl = pext->anew<uint32_t>(la->count);
		if (la->pl == nullptr) {
			la->count = 0;
			return EXT_ERR_ALLOC;
		}
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->g_uint32(&la->pl[i]));
		break;
	}
	}
	if (ext.m_offset > offset + len) {
		mlog(LV_DEBUG, "tnef: attribute data length error");
		return EXT_ERR_FORMAT;
	}
	ext.m_offset = offset + len;
	TRY(pext->g_uint16(&checksum));
#ifdef _DEBUG_UMTA
	if (checksum != tnef_generate_checksum(
		pext->data + offset, len)) {
		mlog(LV_DEBUG, "tnef: invalid checksum");
	}
#endif
	return EXT_ERR_SUCCESS;
}

static const char *tnef_to_msgclass(const char *str_class)
{
	if (0 == strcasecmp("IPM.Microsoft Mail.Note", str_class)) {
		return "IPM.Note";
	} else if (0 == strcasecmp("IPM.Microsoft Mail.Read Receipt",
		str_class)) {
		return "Report.IPM.Note.IPNRN";
	} else if (0 == strcasecmp("IPM.Microsoft Mail.Non-Delivery",
		str_class)) {
		return "Report.IPM.Note.NDR";
	} else if (0 == strcasecmp("IPM.Microsoft Schedule.MtgRespP",
		str_class)) {
		return "IPM.Schedule.Meeting.Resp.Pos";
	} else if (0 == strcasecmp("IPM.Microsoft Schedule.MtgRespN",
		str_class)) {
		return "IPM.Schedule.Meeting.Resp.Neg";
	} else if (0 == strcasecmp("IPM.Microsoft Schedule.MtgRespA",
		str_class)) {
		return "IPM.Schedule.Meeting.Resp.Tent";
	} else if (0 == strcasecmp("IPM.Microsoft Schedule.MtgReq",
		str_class)) {
		return "IPM.Schedule.Meeting.Request";
	} else if (0 == strcasecmp("IPM.Microsoft Schedule.MtgCncl",
		str_class)) {
		return "IPM.Schedule.Meeting.Canceled";
	}
	return str_class;
}

static BOOL tnef_set_attribute_address(TPROPVAL_ARRAY *pproplist,
	uint32_t proptag1, uint32_t proptag2, uint32_t proptag3,
	ATTR_ADDR *paddr)
{
	if (pproplist->set(proptag1, paddr->displayname) != 0)
		return FALSE;
	auto ptr = strchr(paddr->address, ':');
	if (NULL == ptr) {
		return FALSE;
	}
	*ptr = '\0';
	ptr ++;
	return pproplist->set(proptag2, paddr->address) == 0 &&
	       pproplist->set(proptag3, ptr) == 0 ? TRUE : false;
}

static void tnef_convert_from_propname(const PROPERTY_NAME *ppropname,
    char *tag_string, size_t tag_size)
{
	char tmp_guid[GUIDSTR_SIZE];
	
	ppropname->guid.to_str(tmp_guid, arsizeof(tmp_guid));
	if (ppropname->kind == MNID_ID)
		snprintf(tag_string, tag_size, "%s:lid:%u", tmp_guid, ppropname->lid);
	else
		snprintf(tag_string, tag_size, "%s:name:%s", tmp_guid, ppropname->pname);
	HX_strlower(tag_string);
}

static BOOL tnef_convert_to_propname(const std::string &input_tag,
	PROPERTY_NAME *ppropname, EXT_BUFFER_ALLOC alloc)
{
	std::string working_tag;
	try {
		working_tag = input_tag;
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1567: ENOMEM");
		return false;
	}
	char *tag_string = working_tag.data();
	int len;
	char *ptr;
	
	ptr = strchr(tag_string, ':');
	if (NULL == ptr) {
		return FALSE;
	}
	*ptr = '\0';
	if (!ppropname->guid.from_str(tag_string))
		return FALSE;
	ptr ++;
	if (0 == strncmp(ptr, "lid:", 4)) {
		ppropname->kind = MNID_ID;
		ppropname->pname = NULL;
		ppropname->lid = strtol(ptr + 4, nullptr, 0);
		return TRUE;
	} else if (0 == strncmp(ptr, "name:", 5)) {
		ppropname->kind = MNID_STRING;
		ppropname->lid = 0;
		len = strlen(ptr + 5) + 1;
		ppropname->pname = static_cast<char *>(alloc(len));
		if (NULL == ppropname->pname) {
			return FALSE;
		}
		strcpy(ppropname->pname, ptr + 5);
		return TRUE;
	}
	return FALSE;
}

static void tnef_replace_propid(TPROPVAL_ARRAY *pproplist,
    const propididmap_t &phash)
{
	int i;
	uint16_t propid;
	uint32_t proptag;
	
	for (i=0; i<pproplist->count; i++) {
		proptag = pproplist->ppropval[i].proptag;
		propid = PROP_ID(proptag);
		if (!is_nameprop_id(propid))
			continue;
		auto ppropid = phash.find(propid);
		if (ppropid == phash.cend() || ppropid->second == 0) {
			pproplist->erase(proptag);
			i --;
			continue;
		}
		pproplist->ppropval[i].proptag =
			PROP_TAG(PROP_TYPE(pproplist->ppropval[i].proptag), ppropid->second);
	}
}

static char *tnef_duplicate_string_to_unicode(const char *charset,
    const char *pstring)
{
	auto z = mb_to_utf8_len(pstring);
	auto pstr_out = me_alloc<char>(z);
	if (NULL == pstr_out) {
		return NULL;
	}
	if (!string_to_utf8(charset, pstring, pstr_out, z)) {
		free(pstr_out);
		return NULL;
	}
	return pstr_out;
}

static STRING_ARRAY *tnef_duplicate_string_array_to_unicode(const char *charset,
    STRING_ARRAY *parray)
{
	auto parray_out = me_alloc<STRING_ARRAY>();
	if (NULL == parray_out) {
		return NULL;
	}
	parray_out->count = parray->count;
	if (parray->count > 0) {
		parray_out->ppstr = me_alloc<char *>(parray->count);
		if (NULL == parray_out->ppstr) {
			free(parray_out);
			return NULL;
		}
	} else {
		parray_out->ppstr = NULL;
	}
	for (size_t i = 0; i < parray->count; ++i) {
		parray_out->ppstr[i] =
			tnef_duplicate_string_to_unicode(
			charset, parray->ppstr[i]);
		if (NULL == parray_out->ppstr[i]) {
			while (i-- > 0)
				free(parray_out->ppstr[i]);
			free(parray_out->ppstr);
			free(parray_out);
			return NULL;
		}
	}
	return parray_out;
}

static void tnef_tpropval_array_to_unicode(
	const char *charset, TPROPVAL_ARRAY *pproplist)
{
	int i;
	void *pvalue;
	uint16_t proptype;
	
	for (i=0; i<pproplist->count; i++) {
		proptype = PROP_TYPE(pproplist->ppropval[i].proptag);
		if (proptype == PT_STRING8) {
			pvalue = tnef_duplicate_string_to_unicode(charset,
			         static_cast<char *>(pproplist->ppropval[i].pvalue));
			proptype = PT_UNICODE;
		} else if (proptype == PT_MV_STRING8) {
			pvalue = tnef_duplicate_string_array_to_unicode(charset,
			         static_cast<STRING_ARRAY *>(pproplist->ppropval[i].pvalue));
			proptype = PT_MV_UNICODE;
		} else {
			continue;
		}
		if (NULL == pvalue) {
			continue;
		}
		propval_free(proptype, pproplist->ppropval[i].pvalue);
		pproplist->ppropval[i].pvalue = pvalue;
		pproplist->ppropval[i].proptag = CHANGE_PROP_TYPE(pproplist->ppropval[i].proptag, proptype);
	}
}

static void tnef_message_to_unicode(
	uint32_t cpid, MESSAGE_CONTENT *pmsg)
{
	auto charset = cpid_to_cset(cpid);
	if (NULL == charset) {
		charset = "CP1252";
	}
	tnef_tpropval_array_to_unicode(charset, &pmsg->proplist);
	if (NULL != pmsg->children.prcpts) {
		for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
			tnef_tpropval_array_to_unicode(charset,
				pmsg->children.prcpts->pparray[i]);
	}
	if (NULL != pmsg->children.pattachments) {
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i)
			tnef_tpropval_array_to_unicode(charset,
				&pmsg->children.pattachments->pplist[i]->proplist);
	}
}

static bool rec_namedprop(propmap_t &map, uint16_t &last_propid, TNEF_PROPVAL *tnef_pv)
{
	if (tnef_pv->ppropname == nullptr)
		return true;
	char ts[NP_STRBUF_SIZE];
	tnef_convert_from_propname(tnef_pv->ppropname, ts, arsizeof(ts));
	auto iter = map.find(ts);
	if (iter != map.end()) {
		tnef_pv->propid = iter->second;
		return true;
	} else if (map.size() >= 0x1000) {
		mlog(LV_WARN, "W-1544: TNEF namedpropmap full");
		return false;
	}
	try {
		map.emplace(ts, last_propid);
	} catch (const std::bad_alloc &) {
		mlog(LV_WARN, "W-1545: ENOMEM");
		return false;
	}
	tnef_pv->propid = last_propid++;
	return true;
}

enum { X_ERROR = -1, X_RUNOFF, X_CONTINUE, };

static MESSAGE_CONTENT *tnef_deserialize_internal(const void *, uint32_t, BOOL, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID);

static int rec_ptobj(EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
    USERNAME_TO_ENTRYID u2e, ATTACHMENT_CONTENT *atc, TNEF_PROPVAL *tnef_pv)
{
	if (tnef_pv->proptype != PT_OBJECT)
		return X_RUNOFF;
	auto bv = static_cast<BINARY *>(tnef_pv->pvalue);
	if (memcmp(bv->pb, &IID_IMessage, sizeof(IID_IMessage)) == 0) {
		auto emb = tnef_deserialize_internal(bv->pb + 16, bv->cb - 16,
		           TRUE, alloc, get_propids, u2e);
		if (emb == nullptr)
			return X_ERROR;
		attachment_content_set_embedded_internal(atc, emb);
	} else {
		bv->cb -= 16;
		memmove(bv->pb, bv->pb + 16, bv->cb);
	}
	return X_CONTINUE;
}

static bool is_meeting_request(const char *s)
{
	return strcasecmp(s, "IPM.Schedule.Meeting.Request") == 0 ||
	       strcasecmp(s, "IPM.Schedule.Meeting.Canceled") == 0;
}

static bool is_meeting_response(const char *s)
{
	return strcasecmp(s, "IPM.Schedule.Meeting.Resp.Pos") == 0 ||
	       strcasecmp(s, "IPM.Schedule.Meeting.Resp.Neg") == 0 ||
	       strcasecmp(s, "IPM.Schedule.Meeting.Resp.Tent") == 0;
}

static MESSAGE_CONTENT* tnef_deserialize_internal(const void *pbuff,
	uint32_t length, BOOL b_embedded, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, USERNAME_TO_ENTRYID username_to_entryid)
{
	BOOL b_props;
	uint32_t cpid;
	BINARY tmp_bin;
	uint8_t cur_lvl;
	uint8_t tmp_byte;
	ATTR_ADDR *powner;
	uint16_t tmp_int16;
	uint32_t tmp_int32;
	TARRAY_SET *prcpts;
	uint8_t tmp_buff[1280];
	uint16_t last_propid;
	PROPID_ARRAY propids;
	PROPID_ARRAY propids1;
	PROPNAME_ARRAY propnames;
	TNEF_ATTRIBUTE attribute;
	const char *message_class;
	TNEF_PROPLIST *ptnef_proplist;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment = nullptr;
	tnef_pull ext_pull;
	
	ext_pull.init(pbuff, length, alloc, EXT_FLAG_UTF16);
	if (ext_pull.g_uint32(&tmp_int32) != EXT_ERR_SUCCESS)
		return NULL;
	if (tmp_int32 != 0x223e9f78) {
		mlog(LV_DEBUG, "tnef: TNEF SIGNATURE error");
		return NULL;
	}
	if (ext_pull.g_uint16(&tmp_int16) != EXT_ERR_SUCCESS)
		return NULL;
	if (ext_pull.g_attr(&attribute) != EXT_ERR_SUCCESS)
		return NULL;
	if (ATTRIBUTE_ID_TNEFVERSION != attribute.attr_id) {
		mlog(LV_DEBUG, "tnef: cannot find idTnefVersion");
		return NULL;
	}
	if (ext_pull.g_attr(&attribute) != EXT_ERR_SUCCESS)
		return NULL;
	if (ATTRIBUTE_ID_OEMCODEPAGE != attribute.attr_id) {
		mlog(LV_DEBUG, "tnef: cannot find idOEMCodePage");
		return NULL;
	}
	if (0 == ((LONG_ARRAY*)attribute.pvalue)->count) {
		mlog(LV_DEBUG, "tnef: cannot find PrimaryCodePage");
		return NULL;
	}
	cpid = ((LONG_ARRAY*)attribute.pvalue)->pl[0];
	b_props = FALSE;
	cur_lvl = LVL_MESSAGE;
	powner = NULL;
	message_class = NULL;
	auto pmsg = message_content_init();
	if (NULL == pmsg) {
		return NULL;
	}
	auto cl_0 = make_scope_exit([&]() {
		if (pmsg != nullptr)
			message_content_free(pmsg);
	});
	last_propid = 0x8000;
	propmap_t phash;
	do {
		if (ext_pull.g_attr(&attribute) != EXT_ERR_SUCCESS) {
			if (0 == pmsg->proplist.count) {
				return NULL;
			}
			break;
		}
		if (attribute.lvl != cur_lvl) {
			if (ATTRIBUTE_ID_ATTACHRENDDATA == attribute.attr_id) {
				cur_lvl = LVL_ATTACHMENT;
				break;
			} else {
				mlog(LV_DEBUG, "tnef: attachment should "
					"begin with attAttachRendData");
				return NULL;
			}
		}
		if (b_props) {
			mlog(LV_DEBUG, "tnef: attMsgProps should be "
				"the last attribute in message level");
			return NULL;
		}
		switch (attribute.attr_id) {
		case ATTRIBUTE_ID_MSGPROPS: {
			auto tf = static_cast<TNEF_PROPLIST *>(attribute.pvalue);
			auto count = tf->count;
			for (size_t i = 0; i < count; ++i) {
				auto ptnef_propval = &tf->ppropval[i];
				if (!rec_namedprop(phash, last_propid, ptnef_propval) ||
				    pmsg->proplist.set(PROP_TAG(ptnef_propval->proptype,
				    ptnef_propval->propid), ptnef_propval->pvalue) != 0)
					return NULL;
			}
			b_props = TRUE;
			break;
		}
		case ATTRIBUTE_ID_OWNER:
			powner = static_cast<ATTR_ADDR *>(attribute.pvalue);
			break;
		case ATTRIBUTE_ID_SENTFOR:
			if (!tnef_set_attribute_address(&pmsg->proplist,
			    PR_SENT_REPRESENTING_NAME_A,
			    PR_SENT_REPRESENTING_ADDRTYPE_A,
			    PR_SENT_REPRESENTING_EMAIL_ADDRESS_A,
			    static_cast<ATTR_ADDR *>(attribute.pvalue))) {
				return NULL;
			}
			break;
		case ATTRIBUTE_ID_DELEGATE:
			if (pmsg->proplist.set(PR_RCVD_REPRESENTING_ENTRYID,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_DATESTART:
			if (pmsg->proplist.set(PR_START_DATE, attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_DATEEND:
			if (pmsg->proplist.set(PR_END_DATE, attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_AIDOWNER:
			if (pmsg->proplist.set(PR_OWNER_APPT_ID,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_REQUESTRES:
			tmp_byte = !!*static_cast<uint16_t *>(attribute.pvalue);
			if (pmsg->proplist.set(PR_RESPONSE_REQUESTED, &tmp_byte) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ORIGNINALMESSAGECLASS:
			if (pmsg->proplist.set(PR_ORIG_MESSAGE_CLASS_A,
			    tnef_to_msgclass(static_cast<char *>(attribute.pvalue))) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_FROM:
			if (!tnef_set_attribute_address(&pmsg->proplist,
			    PR_SENDER_NAME_A,
			    PR_SENDER_ADDRTYPE_A,
			    PR_SENDER_EMAIL_ADDRESS_A,
			    static_cast<ATTR_ADDR *>(attribute.pvalue))) {
				return NULL;
			}
			break;
		case ATTRIBUTE_ID_SUBJECT:
			if (pmsg->proplist.set(PR_SUBJECT_A, attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_DATESENT:
			if (pmsg->proplist.set(PR_CLIENT_SUBMIT_TIME,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_DATERECD:
			if (pmsg->proplist.set(PR_MESSAGE_DELIVERY_TIME,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_MESSAGESTATUS: {
			auto bv = static_cast<BINARY *>(attribute.pvalue);
			if (b_embedded && bv->cb != 0) {
				tmp_int32 = 0;
				if (*bv->pb & FMS_LOCAL)
					tmp_int32 |= MSGFLAG_UNSENT;
				if (*bv->pb & FMS_SUBMITTED)
					tmp_int32 |= MSGFLAG_SUBMITTED;
				if (tmp_int32 != 0 &&
				    pmsg->proplist.set(PR_MESSAGE_FLAGS, &tmp_int32) != 0)
					return NULL;
			}
			break;
		}
		case ATTRIBUTE_ID_MESSAGECLASS:
			message_class = tnef_to_msgclass(static_cast<char *>(attribute.pvalue));
			if (pmsg->proplist.set(PR_MESSAGE_CLASS_A, message_class) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_MESSAGEID:
			tmp_bin.cb = strlen(static_cast<char *>(attribute.pvalue)) / 2;
			if (tmp_bin.cb > 0) { 
				tmp_bin.pv = alloc(tmp_bin.cb);
				if (tmp_bin.pv == nullptr ||
				    !decode_hex_binary(static_cast<char *>(attribute.pvalue),
				    tmp_bin.pv, tmp_bin.cb) ||
				    pmsg->proplist.set(PR_SEARCH_KEY, &tmp_bin) != 0)
					return NULL;
			}
			break;
		case ATTRIBUTE_ID_BODY:
			if (pmsg->proplist.set(PR_BODY_A, attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_PRIORITY:
			switch (*(uint16_t*)attribute.pvalue) {
			case 3:
				tmp_int32 = IMPORTANCE_LOW;
				break;
			case 2:
				tmp_int32 = IMPORTANCE_NORMAL;
				break;
			case 1:
				tmp_int32 = IMPORTANCE_HIGH;
				break;
			default:
				mlog(LV_DEBUG, "tnef: attPriority error");
				return NULL;
			}
			if (pmsg->proplist.set(PR_IMPORTANCE, &tmp_int32) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_DATEMODIFY:
			if (pmsg->proplist.set(PR_LAST_MODIFICATION_TIME,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_RECIPTABLE: {
			if (NULL != pmsg->children.prcpts) {
				mlog(LV_DEBUG, "tnef: idRecipTable already met");
				return NULL;
			}
			prcpts = tarray_set_init();
			if (NULL == prcpts) {
				return NULL;
			}
			message_content_set_rcpts_internal(pmsg, prcpts);
			auto tf = static_cast<TNEF_PROPSET *>(attribute.pvalue);
			for (size_t i = 0; i < tf->count; ++i) {
				ptnef_proplist = tf->pplist[i];
				auto pproplist = prcpts->emplace();
				if (NULL == pproplist) {
					return NULL;
				}
				for (size_t j = 0; j < ptnef_proplist->count; ++j) {
					auto ptnef_propval = ptnef_proplist->ppropval + j;
					if (!rec_namedprop(phash, last_propid, ptnef_propval) ||
					    pproplist->set(PROP_TAG(ptnef_propval->proptype,
					    ptnef_propval->propid), ptnef_propval->pvalue) != 0)
						return NULL;
				}
				pproplist->erase(PR_ENTRYID);
				auto psmtp = pproplist->get<char>(PR_SMTP_ADDRESS);
				auto pdisplay_name = pproplist->get<char>(PR_DISPLAY_NAME);
				if (NULL != psmtp) {
					tmp_bin.cb = 0;
					tmp_bin.pb = tmp_buff;
					if (!username_to_entryid(psmtp, pdisplay_name, &tmp_bin, nullptr) ||
					    pproplist->set(PR_ENTRYID, &tmp_bin) != 0)
						return NULL;
				}
			}
			break;
		}
		case ATTRIBUTE_ID_PARENTID:
		case ATTRIBUTE_ID_CONVERSATIONID:
			/* have been deprecated in Exchange Server */
			break;
		default:
			mlog(LV_DEBUG, "tnef: illegal attribute ID %x", attribute.attr_id);
			return NULL;
		}
	} while (ext_pull.m_offset < length);
	
	if (NULL != powner && NULL != message_class) {
		if (is_meeting_request(message_class)) {
			if (!tnef_set_attribute_address(&pmsg->proplist,
			    PR_SENT_REPRESENTING_NAME_A,
			    PR_SENT_REPRESENTING_ADDRTYPE_A,
			    PR_SENT_REPRESENTING_EMAIL_ADDRESS_A, powner)) {
				return NULL;
			}
		} else if (is_meeting_response(message_class)) {
			if (!tnef_set_attribute_address(&pmsg->proplist,
			    PR_RCVD_REPRESENTING_NAME_A,
			    PR_RCVD_REPRESENTING_ADDRTYPE_A,
			    PR_RCVD_REPRESENTING_EMAIL_ADDRESS_A, powner)) {
				return NULL;
			}
		}
		
	}
	
	if (LVL_MESSAGE == cur_lvl) {
		goto FETCH_PROPNAME;
	}
	
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		return NULL;
	}
	message_content_set_attachments_internal(pmsg, pattachments);
	while (true) {
		if (b_props && attribute.attr_id != ATTRIBUTE_ID_ATTACHRENDDATA) {
			mlog(LV_DEBUG, "tnef: attAttachment should be "
				"the last attribute in attachment level");
			return NULL;
		}
		switch (attribute.attr_id) {
		case ATTRIBUTE_ID_ATTACHMENT: {
			auto tf = static_cast<TNEF_PROPLIST *>(attribute.pvalue);
			auto count = tf->count;
			for (size_t i = 0; i < count; ++i) {
				auto ptnef_propval = &tf->ppropval[i];
				if (!rec_namedprop(phash, last_propid, ptnef_propval)) {
					return nullptr;
				}
				auto r = rec_ptobj(alloc, get_propids, username_to_entryid,
				         pattachment, ptnef_propval);
				if (r == X_CONTINUE)
					continue;
				if (r == X_ERROR ||
				    pattachment->proplist.set(PROP_TAG(ptnef_propval->proptype,
				    ptnef_propval->propid), ptnef_propval->pvalue) != 0)
					return NULL;
			}
			b_props = TRUE;
			break;
		}
		case ATTRIBUTE_ID_ATTACHDATA:
			if (pattachment->proplist.set(PR_ATTACH_DATA_BIN,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ATTACHTITLE:
			if (pattachment->proplist.set(PR_ATTACH_LONG_FILENAME_A,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ATTACHMETAFILE:
			if (pattachment->proplist.set(PR_ATTACH_RENDERING,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ATTACHCREATEDATE:
			if (pattachment->proplist.set(PR_CREATION_TIME,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ATTACHMODIFYDATE:
			if (pattachment->proplist.set(PR_LAST_MODIFICATION_TIME,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME:
			if (pattachment->proplist.set(PR_ATTACH_TRANSPORT_NAME_A,
			    attribute.pvalue) != 0)
				return NULL;
			break;
		case ATTRIBUTE_ID_ATTACHRENDDATA:
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				return NULL;
			}
			if (!attachment_list_append_internal(pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return NULL;
			}
			if (ATTACH_TYPE_OLE == ((REND_DATA*)
				attribute.pvalue)->attach_type) {
				tmp_bin.cb = sizeof(OLE_TAG);
				tmp_bin.pb = deconst(OLE_TAG);
				if (pattachment->proplist.set(PR_ATTACH_TAG, &tmp_bin) != 0)
					return NULL;
			}
			if (FILE_DATA_MACBINARY == ((REND_DATA*)
				attribute.pvalue)->attach_type) {
				tmp_bin.cb = sizeof(MACBINARY_ENCODING);
				tmp_bin.pb = deconst(MACBINARY_ENCODING);
				if (pattachment->proplist.set(PR_ATTACH_ENCODING, &tmp_bin) != 0)
					return NULL;
			}
			if (pattachment->proplist.set(PR_RENDERING_POSITION,
			    &static_cast<REND_DATA *>(attribute.pvalue)->attach_position) != 0)
				return NULL;
			b_props = FALSE;
			break;
		}
		if (ext_pull.m_offset == length)
			break;
		if (ext_pull.g_attr(&attribute) != EXT_ERR_SUCCESS) {
			if (0 == pmsg->proplist.count) {
				return NULL;
			}
			break;
		}
	}
 FETCH_PROPNAME:
	propids.count = 0;
	propids.ppropid = static_cast<uint16_t *>(alloc(sizeof(uint16_t) * phash.size()));
	if (NULL == propids.ppropid) {
		return NULL;
	}
	propnames.count = 0;
	propnames.ppropname = static_cast<PROPERTY_NAME *>(alloc(sizeof(PROPERTY_NAME) * phash.size()));
	if (NULL == propnames.ppropname) {
		return NULL;
	}
	for (const auto &[name, propid] : phash) {
		propids.ppropid[propids.count] = propid;
		if (!tnef_convert_to_propname(name,
		    propnames.ppropname + propnames.count, alloc)) {
			return NULL;
		}
		propids.count ++;
		propnames.count ++;
	}
	phash.clear();
	
	if (!get_propids(&propnames, &propids1))
		return NULL;
	propididmap_t phash1;
	try { for (size_t i = 0; i < propids.count; ++i)
		phash1.emplace(propids.ppropid[i], propids1.ppropid[i]);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1987: ENOMEM");
	}
	tnef_replace_propid(&pmsg->proplist, phash1);
	if (NULL != pmsg->children.prcpts) {
		for (size_t i = 0; i < pmsg->children.prcpts->count; ++i)
			tnef_replace_propid(pmsg->children.prcpts->pparray[i], phash1);
	}
	if (NULL != pmsg->children.pattachments) {
		for (size_t i = 0; i < pmsg->children.pattachments->count; ++i)
			tnef_replace_propid(
				&pmsg->children.pattachments->pplist[i]->proplist, phash1);
	}
	
	if (!pmsg->proplist.has(PR_INTERNET_CPID)) {
		pmsg->proplist.set(PR_INTERNET_CPID, &cpid);
	}
	tnef_message_to_unicode(cpid, pmsg);
	pmsg->proplist.erase(PidTagMid);
	pmsg->proplist.erase(PR_ENTRYID);
	pmsg->proplist.erase(PR_SEARCH_KEY);
	auto pmsg_ret = pmsg;
	pmsg = nullptr; /* note cl_0 scope guard */
	return pmsg_ret;
}

MESSAGE_CONTENT* tnef_deserialize(const void *pbuff,
	uint32_t length, EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids,
	USERNAME_TO_ENTRYID username_to_entryid)
{
	return tnef_deserialize_internal(pbuff, length, FALSE,
			alloc, get_propids, username_to_entryid);
}

int tnef_push::p_propname(const PROPERTY_NAME &rr)
{
	auto pext = this;
	auto &ext = *pext;
	auto r = &rr;
	
	TRY(pext->p_guid(r->guid));
	if (r->kind != MNID_ID && r->kind != MNID_STRING)
		return EXT_ERR_FORMAT;
	uint32_t tmp_int = r->kind;
	TRY(pext->p_uint32(tmp_int));
	if (r->kind == MNID_ID) {
		return pext->p_uint32(r->lid);
	} else if (r->kind == MNID_STRING) {
		uint32_t offset = ext.m_offset;
		TRY(pext->advance(sizeof(uint32_t)));
		TRY(pext->p_wstr(r->pname));
		uint32_t offset1 = ext.m_offset;
		tmp_int = offset1 - (offset + sizeof(uint32_t));
		ext.m_offset = offset;
		TRY(pext->p_uint32(tmp_int));
		ext.m_offset = offset1;
		return pext->p_bytes(g_pad_bytes, tnef_align(tmp_int));
	}
	return EXT_ERR_SUCCESS;
}

int tnef_push::p_propval(const TNEF_PROPVAL &rr)
{
	auto pext = this;
	auto &ext = *pext;
	auto r = &rr;
	uint32_t tmp_int;
	
	TRY(pext->p_uint16(r->proptype));
	TRY(pext->p_uint16(r->propid));
	if (NULL != r->ppropname) {
		TRY(p_propname(*r->ppropname));
	}
	switch (r->proptype) {
	case PT_SHORT:
		TRY(pext->p_uint16(*static_cast<uint16_t *>(r->pvalue)));
		return pext->p_bytes(g_pad_bytes, 2);
	case PT_ERROR:
	case PT_LONG:
		return pext->p_uint32(*static_cast<uint32_t *>(r->pvalue));
	case PT_FLOAT:
		return pext->p_float(*static_cast<float *>(r->pvalue));
	case PT_DOUBLE:
	case PT_APPTIME:
		return pext->p_double(*static_cast<double *>(r->pvalue));
	case PT_BOOLEAN:
		TRY(pext->p_uint16(*static_cast<uint8_t *>(r->pvalue)));
		return pext->p_bytes(g_pad_bytes, 2);
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME:
		return pext->p_uint64(*static_cast<uint64_t *>(r->pvalue));
	case PT_STRING8: {
		TRY(pext->p_uint32(1));
		uint32_t offset = ext.m_offset;
		TRY(pext->advance(sizeof(uint32_t)));
		TRY(pext->p_str(static_cast<char *>(r->pvalue)));
		uint32_t offset1 = ext.m_offset;
		tmp_int = offset1 - (offset + sizeof(uint32_t));
		ext.m_offset = offset;
		TRY(pext->p_uint32(tmp_int));
		ext.m_offset = offset1;
		return pext->p_bytes(g_pad_bytes, tnef_align(tmp_int));
	}
	case PT_UNICODE: {
		TRY(pext->p_uint32(1));
		uint32_t offset = ext.m_offset;
		TRY(pext->advance(sizeof(uint32_t)));
		TRY(pext->p_wstr(static_cast<char *>(r->pvalue)));
		uint32_t offset1 = ext.m_offset;
		tmp_int = offset1 - (offset + sizeof(uint32_t));
		ext.m_offset = offset;
		TRY(pext->p_uint32(tmp_int));
		ext.m_offset = offset1;
		return pext->p_bytes(g_pad_bytes, tnef_align(tmp_int));
	}
	case PT_CLSID:
		return pext->p_guid(*static_cast<GUID *>(r->pvalue));
	case PT_SVREID:
		return pext->p_svreid(*static_cast<SVREID *>(r->pvalue));
	case PT_OBJECT: {
		TRY(pext->p_uint32(1));
		auto bv = static_cast<BINARY *>(r->pvalue);
		if (bv->cb != UINT32_MAX) {
			TRY(pext->p_uint32(bv->cb + 16));
			TRY(pext->p_guid(IID_IStorage));
			TRY(pext->p_bytes(bv->pb, bv->cb));
			return pext->p_bytes(g_pad_bytes,
			       tnef_align(bv->cb + 16));
		}
		uint32_t offset = ext.m_offset;
		TRY(pext->advance(sizeof(uint32_t)));
		TRY(pext->p_guid(IID_IMessage));
		if (!tnef_serialize_internal(*this, TRUE,
		    static_cast<MESSAGE_CONTENT *>(bv->pv)))
			return EXT_ERR_FORMAT;
		uint32_t offset1 = ext.m_offset;
		tmp_int = offset1 - (offset + sizeof(uint32_t));
		ext.m_offset = offset;
		TRY(pext->p_uint32(tmp_int));
		ext.m_offset = offset1;
		return pext->p_bytes(g_pad_bytes, tnef_align(tmp_int));
	}
	case PT_BINARY: {
		TRY(pext->p_uint32(1));
		auto bv = static_cast<BINARY *>(r->pvalue);
		TRY(pext->p_uint32(bv->cb));
		TRY(pext->p_bytes(bv->pb, bv->cb));
		return pext->p_bytes(g_pad_bytes, tnef_align(bv->cb));
	}
	case PT_MV_SHORT: {
		auto sa = static_cast<SHORT_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(sa->count));
		for (size_t i = 0; i < sa->count; ++i) {
			TRY(pext->p_uint16(sa->ps[i]));
			TRY(pext->p_bytes(g_pad_bytes, 2));
		}
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_LONG: {
		auto la = static_cast<LONG_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(la->count));
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->p_uint32(la->pl[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME: {
		auto la = static_cast<LONGLONG_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(la->count));
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->p_uint64(la->pll[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_FLOAT: {
		auto la = static_cast<FLOAT_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(la->count));
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->p_float(la->mval[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		auto la = static_cast<DOUBLE_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(la->count));
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->p_double(la->mval[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_STRING8: {
		auto sa = static_cast<STRING_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(sa->count));
		for (size_t i = 0; i < sa->count; ++i) {
			uint32_t offset = ext.m_offset;
			TRY(pext->advance(sizeof(uint32_t)));
			TRY(pext->p_str(sa->ppstr[i]));
			uint32_t offset1 = ext.m_offset;
			tmp_int = offset1 - (offset + sizeof(uint32_t));
			ext.m_offset = offset;
			TRY(pext->p_uint32(tmp_int));
			ext.m_offset = offset1;
			TRY(pext->p_bytes(g_pad_bytes, tnef_align(tmp_int)));
		}
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_UNICODE: {
		auto sa = static_cast<STRING_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(sa->count));
		for (size_t i = 0; i < sa->count; ++i) {
			uint32_t offset = ext.m_offset;
			TRY(pext->advance(sizeof(uint32_t)));
			TRY(pext->p_wstr(sa->ppstr[i]));
			uint32_t offset1 = ext.m_offset;
			tmp_int = offset1 - (offset + sizeof(uint32_t));
			ext.m_offset = offset;
			TRY(pext->p_uint32(tmp_int));
			ext.m_offset = offset1;
			TRY(pext->p_bytes(g_pad_bytes, tnef_align(tmp_int)));
		}
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_CLSID: {
		auto ga = static_cast<GUID_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(ga->count));
		for (size_t i = 0; i < ga->count; ++i)
			TRY(pext->p_guid(ga->pguid[i]));
		return EXT_ERR_SUCCESS;
	}
	case PT_MV_BINARY: {
		auto ba = static_cast<BINARY_ARRAY *>(r->pvalue);
		TRY(pext->p_uint32(ba->count));
		for (size_t i = 0; i < ba->count; ++i) {
			TRY(pext->p_uint32(ba->pbin[i].cb));
			TRY(pext->p_bytes(ba->pbin[i].pb, ba->pbin[i].cb));
			TRY(pext->p_bytes(g_pad_bytes,tnef_align(ba->pbin[i].cb)));
		}
		return EXT_ERR_SUCCESS;
	}
	}
	return EXT_ERR_BAD_SWITCH;
}

int tnef_push::p_attr(uint8_t level, uint32_t attr_id, const void *value)
{
	auto pext = this;
	auto &ext = *pext;
	DTR tmp_dtr;
	uint16_t tmp_len;
	time_t unix_time;
	struct tm tmp_tm;
	TRP_HEADER header;
	static constexpr uint8_t empty_bytes[8]{};

	TRY(pext->p_uint8(level));
	TRY(pext->p_uint32(attr_id));
	uint32_t offset = ext.m_offset;
	TRY(pext->advance(sizeof(uint32_t)));
	switch (attr_id) {
	case ATTRIBUTE_ID_FROM: {
		auto aa = static_cast<const ATTR_ADDR *>(value);
		TRY(pext->p_uint16(0x0004));
		header.displayname_len = strlen(aa->displayname) + 1;
		header.address_len = strlen(aa->address) + 1;
		header.total_len = header.displayname_len + header.address_len + 16;
		TRY(pext->p_uint16(header.total_len));
		TRY(pext->p_uint16(header.displayname_len));
		TRY(pext->p_uint16(header.address_len));
		TRY(pext->p_str(aa->displayname));
		TRY(pext->p_str(aa->address));
		TRY(pext->p_bytes(empty_bytes, 8));
		break;
	}
	case ATTRIBUTE_ID_SUBJECT:
	case ATTRIBUTE_ID_MESSAGEID:
	case ATTRIBUTE_ID_ATTACHTITLE:
	case ATTRIBUTE_ID_ORIGNINALMESSAGECLASS:
	case ATTRIBUTE_ID_MESSAGECLASS:
	case ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME:
		TRY(pext->p_str(static_cast<const char *>(value)));
		break;
	case ATTRIBUTE_ID_DATESTART:
	case ATTRIBUTE_ID_DATEEND:
	case ATTRIBUTE_ID_DATESENT:
	case ATTRIBUTE_ID_DATERECD:
	case ATTRIBUTE_ID_ATTACHCREATEDATE:
	case ATTRIBUTE_ID_ATTACHMODIFYDATE:
	case ATTRIBUTE_ID_DATEMODIFY:
		unix_time = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(value));
		localtime_r(&unix_time, &tmp_tm);
		tmp_dtr.sec = tmp_tm.tm_sec;
		tmp_dtr.min = tmp_tm.tm_min;
		tmp_dtr.hour = tmp_tm.tm_hour;
		tmp_dtr.day = tmp_tm.tm_mday;
		tmp_dtr.month = tmp_tm.tm_mon + 1;
		tmp_dtr.year = tmp_tm.tm_year + 1900;
		tmp_dtr.dow = tmp_tm.tm_wday + 1;
		TRY(pext->p_uint16(tmp_dtr.year));
		TRY(pext->p_uint16(tmp_dtr.month));
		TRY(pext->p_uint16(tmp_dtr.day));
		TRY(pext->p_uint16(tmp_dtr.hour));
		TRY(pext->p_uint16(tmp_dtr.min));
		TRY(pext->p_uint16(tmp_dtr.sec));
		TRY(pext->p_uint16(tmp_dtr.dow));
		break;
	case ATTRIBUTE_ID_REQUESTRES:
	case ATTRIBUTE_ID_PRIORITY:
		TRY(pext->p_uint16(*static_cast<const uint16_t *>(value)));
		break;
	case ATTRIBUTE_ID_AIDOWNER:
		TRY(pext->p_uint32(*static_cast<const uint32_t *>(value)));
		break;
	case ATTRIBUTE_ID_BODY: {
		auto b = static_cast<const char *>(value);
		TRY(pext->p_bytes(b, strlen(b)));
		break;
	}
	case ATTRIBUTE_ID_MSGPROPS:
	case ATTRIBUTE_ID_ATTACHMENT: {
		auto tf = static_cast<const TNEF_PROPLIST *>(value);
		TRY(pext->p_uint32(tf->count));
		for (size_t i = 0; i < tf->count; ++i)
			TRY(p_propval(tf->ppropval[i]));
		break;
	}
	case ATTRIBUTE_ID_RECIPTABLE: {
		auto tf = static_cast<const TNEF_PROPSET *>(value);
		TRY(pext->p_uint32(tf->count));
		for (size_t i = 0; i < tf->count; ++i) {
			TRY(pext->p_uint32(tf->pplist[i]->count));
			for (size_t j = 0; j < tf->pplist[i]->count; ++j)
				TRY(p_propval(tf->pplist[i]->ppropval[j]));
		}
		break;
	}
	case ATTRIBUTE_ID_OWNER:
	case ATTRIBUTE_ID_SENTFOR: {
		auto aa = static_cast<const ATTR_ADDR *>(value);
		tmp_len = strlen(aa->displayname) + 1;
		TRY(pext->p_uint16(tmp_len));
		TRY(pext->p_str(aa->displayname));
		tmp_len = strlen(aa->address) + 1;
		TRY(pext->p_uint16(tmp_len));
		TRY(pext->p_str(aa->address));
		break;
	}
	case ATTRIBUTE_ID_ATTACHRENDDATA: {
		auto rd = static_cast<const REND_DATA *>(value);
		TRY(pext->p_uint16(rd->attach_type));
		TRY(pext->p_uint32(rd->attach_position));
		TRY(pext->p_uint16(rd->render_width));
		TRY(pext->p_uint16(rd->render_height));
		TRY(pext->p_uint32(rd->data_flags));
		break;
	}
	case ATTRIBUTE_ID_DELEGATE:
	case ATTRIBUTE_ID_ATTACHDATA:
	case ATTRIBUTE_ID_ATTACHMETAFILE:
	case ATTRIBUTE_ID_MESSAGESTATUS: {
		auto bv = static_cast<const BINARY *>(value);
		TRY(pext->p_bytes(bv->pb, bv->cb));
		break;
	}
	case ATTRIBUTE_ID_TNEFVERSION:
	case ATTRIBUTE_ID_OEMCODEPAGE: {
		auto la = static_cast<const LONG_ARRAY *>(value);
		for (size_t i = 0; i < la->count; ++i)
			TRY(pext->p_uint32(la->pl[i]));
		break;
	}
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	uint32_t offset1 = ext.m_offset;
	tmp_len = offset1 - (offset + sizeof(uint32_t));
	ext.m_offset = offset;
	TRY(pext->p_uint32(tmp_len));
	ext.m_offset = offset1;
	offset += sizeof(uint32_t);
	uint16_t checksum = tnef_generate_checksum(&ext.m_udata[offset], tmp_len);
	return pext->p_uint16(checksum);
}

static const char* tnef_from_msgclass(const char *str_class)
{
	if (0 == strcasecmp("IPM.Note", str_class)) {
		return "IPM.Microsoft Mail.Note";
	} else if (0 == strcasecmp("Report.IPM.Note.IPNRN", str_class)) {
		return "IPM.Microsoft Mail.Read Receipt";
	} else if (0 == strcasecmp("Report.IPM.Note.NDR", str_class)) {
		return "IPM.Microsoft Mail.Non-Delivery";
	} else if (0 == strcasecmp("IPM.Schedule.Meeting.Resp.Pos",
		str_class)) {
		return "IPM.Microsoft Schedule.MtgRespP";
	} else if (0 == strcasecmp("IPM.Schedule.Meeting.Resp.Neg",
		str_class)) {
		return "IPM.Microsoft Schedule.MtgRespN";
	} else if (0 == strcasecmp("IPM.Schedule.Meeting.Resp.Tent",
		str_class)) {
		return "IPM.Microsoft Schedule.MtgRespA";
	} else if (0 == strcasecmp("IPM.Schedule.Meeting.Request",
		str_class)) {
		return "IPM.Microsoft Schedule.MtgReq";
	} else if (0 == strcasecmp("IPM.Schedule.Meeting.Canceled",
		str_class)) {
		return "IPM.Microsoft Schedule.MtgCncl";
	}
	return str_class;
}

static TNEF_PROPLIST* tnef_convert_recipient(TPROPVAL_ARRAY *pproplist,
	EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname)
{
	int i;
	BINARY tmp_bin;
	uint8_t tmp_buff[1280];
	
	auto ptnef_proplist = static_cast<TNEF_PROPLIST *>(alloc(sizeof(TNEF_PROPLIST)));
	if (NULL == ptnef_proplist) {
		return NULL;
	}
	ptnef_proplist->count = 0;
	const char *psmtp = nullptr, *pdisplay_name = nullptr;
	if (0 == pproplist->count) {
		ptnef_proplist->ppropval = NULL;
	} else {
		ptnef_proplist->ppropval = static_cast<TNEF_PROPVAL *>(alloc(sizeof(TNEF_PROPVAL) * (pproplist->count + 1)));
		if (NULL == ptnef_proplist->ppropval) {
			return NULL;
		}
		psmtp = pproplist->get<char>(PR_SMTP_ADDRESS);
		pdisplay_name = pproplist->get<char>(PR_DISPLAY_NAME);
	}
	for (i=0; i<pproplist->count; i++) {
		ptnef_proplist->ppropval[ptnef_proplist->count].propid =
			PROP_ID(pproplist->ppropval[i].proptag);
		ptnef_proplist->ppropval[ptnef_proplist->count].proptype =
			PROP_TYPE(pproplist->ppropval[i].proptag);
		if (psmtp != nullptr && pproplist->ppropval[i].proptag == PR_ENTRYID)
			continue;
		if (is_nameprop_id(ptnef_proplist->ppropval[ptnef_proplist->count].propid)) {
			if (!get_propname(
			    ptnef_proplist->ppropval[ptnef_proplist->count].propid,
			    &ptnef_proplist->ppropval[ptnef_proplist->count].ppropname))
				return NULL;
		} else {
			ptnef_proplist->ppropval[ptnef_proplist->count].ppropname = NULL;
		}
		ptnef_proplist->ppropval[ptnef_proplist->count++].pvalue =
									pproplist->ppropval[i].pvalue;
	}
	if (NULL != psmtp) {
		auto pbin = static_cast<BINARY *>(alloc(sizeof(BINARY)));
		if (NULL == pbin) {
			return NULL;
		}
		tmp_bin.cb = 0;
		tmp_bin.pb = tmp_buff;
		if (!tnef_username_to_oneoff(psmtp, pdisplay_name, &tmp_bin))
			return NULL;
		pbin->cb = tmp_bin.cb;
		pbin->pv = alloc(tmp_bin.cb);
		if (pbin->pv == nullptr)
			return NULL;
		memcpy(pbin->pb, tmp_bin.pv, tmp_bin.cb);
		ptnef_proplist->ppropval[ptnef_proplist->count].propid = PROP_ID(PR_ENTRYID);
		ptnef_proplist->ppropval[ptnef_proplist->count].proptype = PROP_TYPE(PR_ENTRYID);
		ptnef_proplist->ppropval[ptnef_proplist->count].ppropname = NULL;
		ptnef_proplist->ppropval[ptnef_proplist->count++].pvalue = pbin;
	}
	return ptnef_proplist;
}

static bool serialize_rcpt(tnef_push &ep, const MESSAGE_CONTENT &msg,
    EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname, uint32_t disptag,
    uint32_t addrtag, uint32_t mailtag, uint32_t tnefattr) try
{
	auto dispname = msg.proplist.get<const char>(disptag);
	auto addrtype = msg.proplist.get<const char>(addrtag);
	auto mailaddr = msg.proplist.get<const char>(mailtag);
	if (dispname == nullptr || addrtype == nullptr || mailaddr == nullptr)
		return true;
	auto joint = addrtype + ":"s + mailaddr;
	ATTR_ADDR addr = {deconst(dispname), deconst(joint.c_str())};
	return ep.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_FROM, &addr) == EXT_ERR_SUCCESS;
	/* keep these properties for attMsgProps */
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1648: ENOMEM");
	return false;
}

static BOOL tnef_serialize_internal(tnef_push &ext, BOOL b_embedded,
	const MESSAGE_CONTENT *pmsg)
{
	auto pext = &ext;
	auto alloc = ext.tnef_alloc;
	auto get_propname = ext.tnef_getpropname;
	BOOL b_key;
	uint8_t tmp_byte;
	REND_DATA tmp_rend;
	char tmp_buff[4096];
	ATTACHMENT_CONTENT *pattachment;
	
	if (pext->p_uint32(0x223e9f78) != EXT_ERR_SUCCESS ||
	    pext->p_uint16(TNEF_LEGACY) != EXT_ERR_SUCCESS)
		return FALSE;
	/* ATTRIBUTE_ID_TNEFVERSION */
	uint32_t tmp_int32 = TNEF_VERSION;
	LONG_ARRAY tmp_larray = {1, &tmp_int32};
	if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_TNEFVERSION,
	    &tmp_larray) != EXT_ERR_SUCCESS)
		return FALSE;
	/* ATTRIBUTE_ID_OEMCODEPAGE */
	auto num = pmsg->proplist.get<const uint32_t>(PR_INTERNET_CPID);
	if (num == nullptr) {
		mlog(LV_DEBUG, "tnef: cannot find PR_INTERNET_CPID");
	} else {
		uint32_t tmp_cpids[] = {*num, 0};
		tmp_larray = {2, tmp_cpids};
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_OEMCODEPAGE,
		    &tmp_larray) != EXT_ERR_SUCCESS)
			return FALSE;
	}
	/* ATTRIBUTE_ID_MESSAGESTATUS */
	if (b_embedded) {
		tmp_byte = 0;
		num = pmsg->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
		if (num != nullptr) {
			if (*num & MSGFLAG_UNSENT)
				tmp_byte |= FMS_LOCAL;
			if (*num & MSGFLAG_SUBMITTED)
				tmp_byte |= FMS_SUBMITTED;
		}
		auto flag = pmsg->proplist.get<const uint8_t>(PR_READ);
		if (flag != nullptr && *flag != 0)
			tmp_byte |= FMS_READ;
		auto stamp  = pmsg->proplist.get<const uint64_t>(PR_CREATION_TIME);
		auto stamp1 = pmsg->proplist.get<const uint64_t>(PR_LAST_MODIFICATION_TIME);
		if (stamp != nullptr && stamp1 != nullptr && *stamp1 > *stamp)
			tmp_byte |= FMS_MODIFIED;
		if (NULL != pmsg->children.pattachments) {
			tmp_byte |= FMS_HASATTACH;
		}
		BINARY tmp_bin = {1, &tmp_byte};
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_MESSAGESTATUS,
		    &tmp_bin) != EXT_ERR_SUCCESS)
			return FALSE;
	}
	uint32_t proptag_buff[32];
	PROPTAG_ARRAY tmp_proptags = {0, proptag_buff};
	tmp_proptags.pproptag[tmp_proptags.count++] = PR_MESSAGE_FLAGS;

	/* ATTRIBUTE_ID_FROM */
	if (b_embedded && !serialize_rcpt(*pext, *pmsg, alloc, get_propname,
	    PR_SENDER_NAME_A, PR_SENDER_ADDRTYPE_A, PR_SENDER_EMAIL_ADDRESS_A,
	    ATTRIBUTE_ID_FROM))
		return false;
	/* ATTRIBUTE_ID_MESSAGECLASS */
	auto message_class = pmsg->proplist.get<const char>(PR_MESSAGE_CLASS_A);
	if (message_class == nullptr)
		message_class = pmsg->proplist.get<char>(PR_MESSAGE_CLASS);
	if (message_class == nullptr) {
		mlog(LV_DEBUG, "tnef: cannot find PR_MESSAGE_CLASS");
	} else {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_MESSAGECLASS,
		    deconst(tnef_from_msgclass(message_class))) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_MESSAGE_CLASS_A;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_MESSAGE_CLASS;
	}
	/* ATTRIBUTE_ID_ORIGNINALMESSAGECLASS */
	auto str = pmsg->proplist.get<const char>(PR_ORIG_MESSAGE_CLASS_A);
	if (str != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_ORIGNINALMESSAGECLASS,
		    deconst(tnef_from_msgclass(str))) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_ORIG_MESSAGE_CLASS_A;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_ORIG_MESSAGE_CLASS;
	}
	/* ATTRIBUTE_ID_SUBJECT */
	if (!b_embedded) {
		str = pmsg->proplist.get<char>(PR_SUBJECT_A);
		if (str != nullptr && ext.p_attr(LVL_MESSAGE,
		    ATTRIBUTE_ID_SUBJECT, str) != EXT_ERR_SUCCESS)
			return FALSE;
		/* keep this property for attMsgProps */
	}
	/* ATTRIBUTE_ID_BODY */
	if (b_embedded) {
		str = pmsg->proplist.get<char>(PR_BODY_A);
		if (str != nullptr) {
			if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_BODY,
			    str) != EXT_ERR_SUCCESS)
				return FALSE;
			tmp_proptags.pproptag[tmp_proptags.count++] = PR_BODY_A;
		}
	}
	/* ATTRIBUTE_ID_MESSAGEID */
	auto bv = pmsg->proplist.get<const BINARY>(PR_SEARCH_KEY);
	if (bv != nullptr) {
		if (!encode_hex_binary(bv->pb, bv->cb, tmp_buff, arsizeof(tmp_buff)))
			return FALSE;
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_MESSAGEID,
		    tmp_buff) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_SEARCH_KEY;
	}
	/* ATTRIBUTE_ID_OWNER */
	if (is_meeting_request(message_class)) {
		if (!serialize_rcpt(*pext, *pmsg, alloc, get_propname,
		    PR_SENT_REPRESENTING_NAME_A, PR_SENT_REPRESENTING_ADDRTYPE_A,
		    PR_SENT_REPRESENTING_EMAIL_ADDRESS_A, ATTRIBUTE_ID_OWNER))
			return false;
	} else if (is_meeting_response(message_class)) {
		if (!serialize_rcpt(*pext, *pmsg, alloc, get_propname,
		    PR_RCVD_REPRESENTING_NAME_A, PR_RCVD_REPRESENTING_ADDRTYPE_A,
		    PR_RCVD_REPRESENTING_EMAIL_ADDRESS_A, ATTRIBUTE_ID_OWNER))
			return false;
	}
	/* ATTRIBUTE_ID_SENTFOR */
	if (!serialize_rcpt(*pext, *pmsg, alloc, get_propname,
	    PR_SENT_REPRESENTING_NAME_A, PR_SENT_REPRESENTING_ADDRTYPE_A,
	    PR_SENT_REPRESENTING_EMAIL_ADDRESS_A, ATTRIBUTE_ID_SENTFOR))
		return false;
	/* ATTRIBUTE_ID_DELEGATE */
	bv = pmsg->proplist.get<BINARY>(PR_RCVD_REPRESENTING_ENTRYID);
	if (bv != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_DELEGATE,
		    bv) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_RCVD_REPRESENTING_ENTRYID;
	}
	/* ATTRIBUTE_ID_DATESTART */
	auto stamp = pmsg->proplist.get<const uint64_t>(PR_START_DATE);
	if (stamp != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_DATESTART,
		    stamp) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_START_DATE;
	}
	/* ATTRIBUTE_ID_DATEEND */
	stamp = pmsg->proplist.get<uint64_t>(PR_END_DATE);
	if (stamp != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_DATEEND,
		    stamp) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_END_DATE;
	}
	/* ATTRIBUTE_ID_AIDOWNER */
	num = pmsg->proplist.get<uint32_t>(PR_OWNER_APPT_ID);
	if (num != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_AIDOWNER,
		    num) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_OWNER_APPT_ID;
	}
	/* ATTRIBUTE_ID_REQUESTRES */
	auto flag = pmsg->proplist.get<const uint8_t>(PR_RESPONSE_REQUESTED);
	if (flag != nullptr && *flag != 0) {
		uint16_t tmp_int16 = 1;
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_REQUESTRES,
		    &tmp_int16) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_RESPONSE_REQUESTED;
	}
	/* ATTRIBUTE_ID_DATESENT */
	stamp = pmsg->proplist.get<uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (stamp != nullptr && ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_DATESENT,
	    stamp) != EXT_ERR_SUCCESS)
		return FALSE;
	/* ^ keep this property for attMsgProps */
	/* ATTRIBUTE_ID_DATERECD */
	stamp = pmsg->proplist.get<uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	if (stamp != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_DATERECD,
		    stamp) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_MESSAGE_DELIVERY_TIME;
	}
	/* ATTRIBUTE_ID_PRIORITY */
	num = pmsg->proplist.get<uint32_t>(PR_IMPORTANCE);
	if (num != nullptr) {
		uint16_t tmp_int16;
		switch (*num) {
		case IMPORTANCE_LOW:
			tmp_int16 = 3;
			break;
		case IMPORTANCE_NORMAL:
			tmp_int16 = 2;
			break;
		case IMPORTANCE_HIGH:
			tmp_int16 = 1;
			break;
		default:
			mlog(LV_DEBUG, "tnef: PR_IMPORTANCE error");
			return FALSE;
		}
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_PRIORITY,
		    &tmp_int16) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_MESSAGE_DELIVERY_TIME;
	}
	/* ATTRIBUTE_ID_DATEMODIFY */
	stamp = pmsg->proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	if (stamp != nullptr) {
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_DATEMODIFY,
		    stamp) != EXT_ERR_SUCCESS)
			return FALSE;
		tmp_proptags.pproptag[tmp_proptags.count++] = PR_LAST_MODIFICATION_TIME;
	}
	/* ATTRIBUTE_ID_RECIPTABLE */
	/* do not generate this attribute for top-level message */
	if (b_embedded && pmsg->children.prcpts != nullptr) {
		TNEF_PROPSET tnef_propset;
		tnef_propset.count = 0;
		if (0 != pmsg->children.prcpts->count) {
			tnef_propset.pplist = static_cast<TNEF_PROPLIST **>(alloc(sizeof(TNEF_PROPLIST *) *
			                      pmsg->children.prcpts->count));
			if (NULL == tnef_propset.pplist) {
				return FALSE;
			}
		}
		for (size_t i = 0; i < pmsg->children.prcpts->count; ++i) {
			num = pmsg->children.prcpts->pparray[i]->get<uint32_t>(PR_RECIPIENT_TYPE);
			/* BCC recipients must be excluded */
			if (num != nullptr && *num == MAPI_BCC)
				continue;
			tnef_propset.pplist[tnef_propset.count] =
				tnef_convert_recipient(pmsg->children.prcpts->pparray[i],
					alloc, get_propname);
			if (NULL == tnef_propset.pplist[tnef_propset.count]) {
				return FALSE;
			}
			tnef_propset.count ++;
		}
		if (ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_RECIPTABLE,
		    &tnef_propset) != EXT_ERR_SUCCESS)
			return FALSE;
	}
	/* ATTRIBUTE_ID_MSGPROPS */
	b_key = FALSE;
	BINARY key_bin, tmp_bin;
	TNEF_PROPLIST tnef_proplist;
	tnef_proplist.count = 0;
	tnef_proplist.ppropval = static_cast<TNEF_PROPVAL *>(alloc(sizeof(TNEF_PROPVAL) *
	                         (pmsg->proplist.count + 1)));
	if (NULL == tnef_proplist.ppropval) {
		return FALSE;
	}
	for (size_t i = 0; i < pmsg->proplist.count; ++i) {
		if (tmp_proptags.has(pmsg->proplist.ppropval[i].proptag))
			continue;
		tnef_proplist.ppropval[tnef_proplist.count].propid =
			PROP_ID(pmsg->proplist.ppropval[i].proptag);
		if (pmsg->proplist.ppropval[i].proptag == PR_MESSAGE_CLASS) {
			tnef_proplist.ppropval[tnef_proplist.count].proptype = PT_STRING8;
		} else {
			if (pmsg->proplist.ppropval[i].proptag == PR_TNEF_CORRELATION_KEY)
				b_key = TRUE;
			tnef_proplist.ppropval[tnef_proplist.count].proptype = PROP_TYPE(pmsg->proplist.ppropval[i].proptag);
		}
		if (is_nameprop_id(tnef_proplist.ppropval[tnef_proplist.count].propid)) {
			if (!get_propname(
			    tnef_proplist.ppropval[tnef_proplist.count].propid,
			    &tnef_proplist.ppropval[tnef_proplist.count].ppropname))
				return FALSE;
		} else {
			tnef_proplist.ppropval[tnef_proplist.count].ppropname = NULL;
		}
		tnef_proplist.ppropval[tnef_proplist.count++].pvalue =
							pmsg->proplist.ppropval[i].pvalue;
	}
	if (!b_key) {
		str = pmsg->proplist.get<char>(PR_INTERNET_MESSAGE_ID);
		if (str != nullptr) {
			tnef_proplist.ppropval[tnef_proplist.count].propid =
				PROP_ID(PR_TNEF_CORRELATION_KEY);
			tnef_proplist.ppropval[tnef_proplist.count].proptype = PT_BINARY;
			tnef_proplist.ppropval[tnef_proplist.count].ppropname = NULL;
			tnef_proplist.ppropval[tnef_proplist.count++].pvalue = &key_bin;
			key_bin.cb = strlen(str) + 1;
			key_bin.pv = deconst(str);
		}
	}
	if (tnef_proplist.count > 0 &&
	    ext.p_attr(LVL_MESSAGE, ATTRIBUTE_ID_MSGPROPS,
	    &tnef_proplist) != EXT_ERR_SUCCESS)
			return FALSE;
	if (NULL == pmsg->children.pattachments) {
		return TRUE;
	}
	
	for (size_t i = 0; i < pmsg->children.pattachments->count; ++i) {
		pattachment = pmsg->children.pattachments->pplist[i];
		tmp_proptags.count = 0;
		/* ATTRIBUTE_ID_ATTACHRENDDATA */
		auto pmethod = pattachment->proplist.get<uint32_t>(PR_ATTACH_METHOD);
		if (NULL == pmethod) {
			tmp_rend.attach_type = ATTACH_TYPE_FILE;
			break;
		} else {
			switch (*pmethod) {
			case NO_ATTACHMENT:
			case ATTACH_BY_VALUE:
			case ATTACH_EMBEDDED_MSG:
				tmp_rend.attach_type = ATTACH_TYPE_FILE;
				break;
			case ATTACH_OLE:
				tmp_rend.attach_type = ATTACH_TYPE_OLE;
				break;
			default:
				mlog(LV_DEBUG, "tnef: unsupported type in PR_ATTACH_METHOD by attachment");
				return FALSE;
			}
		}
		num = pattachment->proplist.get<uint32_t>(PR_RENDERING_POSITION);
		tmp_rend.attach_position = num != nullptr ? *num : indet_rendering_pos;
		bv = pattachment->proplist.get<BINARY>(PR_ATTACH_ENCODING);
		tmp_rend.data_flags = bv != nullptr && bv->cb == sizeof(MACBINARY_ENCODING) &&
		                      memcmp(bv->pb, MACBINARY_ENCODING, sizeof(MACBINARY_ENCODING)) == 0 ?
		                      FILE_DATA_MACBINARY : FILE_DATA_DEFAULT;
		tmp_rend.render_width = 32;
		tmp_rend.render_height = 32;
		if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHRENDDATA,
		    &tmp_rend) != EXT_ERR_SUCCESS)
			return FALSE;
		/* ATTRIBUTE_ID_ATTACHDATA */
		if (pmethod != nullptr && *pmethod == ATTACH_BY_VALUE) {
			bv = pattachment->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
			if (bv != nullptr) {
				if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHDATA,
				    bv) != EXT_ERR_SUCCESS)
					return FALSE;
				tmp_proptags.pproptag[tmp_proptags.count++] = PR_ATTACH_DATA_BIN;
			}
		}
		/* ATTRIBUTE_ID_ATTACHTITLE */
		str = pattachment->proplist.get<char>(PR_ATTACH_LONG_FILENAME_A);
		if (str != nullptr) {
			if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHTITLE,
			    str) != EXT_ERR_SUCCESS)
				return FALSE;
			tmp_proptags.pproptag[tmp_proptags.count++] = PR_ATTACH_LONG_FILENAME_A;
		} else {
			str = pattachment->proplist.get<char>(PR_ATTACH_FILENAME_A);
			if (str != nullptr) {
				if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHTITLE,
				    str) != EXT_ERR_SUCCESS)
					return FALSE;
				tmp_proptags.pproptag[tmp_proptags.count++] = PR_ATTACH_FILENAME_A;
			}
		}
		/* ATTRIBUTE_ID_ATTACHMETAFILE */
		bv = pattachment->proplist.get<BINARY>(PR_ATTACH_RENDERING);
		if (bv != nullptr) {
			if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHMETAFILE,
			    bv) != EXT_ERR_SUCCESS)
				return FALSE;
			tmp_proptags.pproptag[tmp_proptags.count++] = PR_ATTACH_RENDERING;
		}
		/* ATTRIBUTE_ID_ATTACHCREATEDATE */
		stamp = pattachment->proplist.get<uint64_t>(PR_CREATION_TIME);
		if (stamp != nullptr) {
			if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHCREATEDATE,
			    stamp) != EXT_ERR_SUCCESS)
				return FALSE;
			tmp_proptags.pproptag[tmp_proptags.count++] = PR_CREATION_TIME;
		}
		/* ATTRIBUTE_ID_ATTACHMODIFYDATE */
		stamp = pattachment->proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
		if (stamp != nullptr) {
			if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHMODIFYDATE,
			    stamp) != EXT_ERR_SUCCESS)
				return FALSE;
			tmp_proptags.pproptag[tmp_proptags.count++] = PR_LAST_MODIFICATION_TIME;
		}
		/* ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME */
		str = pattachment->proplist.get<char>(PR_ATTACH_TRANSPORT_NAME_A);
		if (str != nullptr) {
			if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHTRANSPORTFILENAME,
			    str) != EXT_ERR_SUCCESS)
				return FALSE;
			tmp_proptags.pproptag[tmp_proptags.count++] = PR_ATTACH_TRANSPORT_NAME_A;
		}
		/* ATTRIBUTE_ID_ATTACHMENT */
		if (0 == pattachment->proplist.count) {
			continue;
		}
		tnef_proplist.count = 0;
		tnef_proplist.ppropval = static_cast<TNEF_PROPVAL *>(alloc(sizeof(TNEF_PROPVAL) *
		                         pattachment->proplist.count + 1));
		if (NULL == tnef_proplist.ppropval) {
			return FALSE;
		}
		for (size_t j = 0; j < pattachment->proplist.count; ++j) {
			if (tmp_proptags.has(pattachment->proplist.ppropval[j].proptag))
				continue;
			tnef_proplist.ppropval[tnef_proplist.count].propid =
				PROP_ID(pattachment->proplist.ppropval[j].proptag);
			tnef_proplist.ppropval[tnef_proplist.count].proptype = PROP_TYPE(pattachment->proplist.ppropval[j].proptag);
			if (is_nameprop_id(tnef_proplist.ppropval[tnef_proplist.count].propid)) {
				if (!get_propname(
				    tnef_proplist.ppropval[tnef_proplist.count].propid,
				    &tnef_proplist.ppropval[tnef_proplist.count].ppropname))
					return FALSE;
			} else {
				tnef_proplist.ppropval[tnef_proplist.count].ppropname = NULL;
			}
			tnef_proplist.ppropval[tnef_proplist.count++].pvalue =
						pattachment->proplist.ppropval[j].pvalue;
		}
		if (NULL != pattachment->pembedded) {
			tmp_bin.cb = UINT32_MAX;
			tmp_bin.pv = pattachment->pembedded;
			tnef_proplist.ppropval[tnef_proplist.count].propid = PROP_ID(PR_ATTACH_DATA_OBJ);
			tnef_proplist.ppropval[tnef_proplist.count].proptype = PT_OBJECT;
			tnef_proplist.ppropval[tnef_proplist.count].ppropname = NULL;
			tnef_proplist.ppropval[tnef_proplist.count++].pvalue = &tmp_bin;
		}
		if (ext.p_attr(LVL_ATTACHMENT, ATTRIBUTE_ID_ATTACHMENT,
		    &tnef_proplist) != EXT_ERR_SUCCESS)
			return FALSE;
	}
	return TRUE;
}

/* must convert some properties into ansi code before call this function */
BINARY* tnef_serialize(const MESSAGE_CONTENT *pmsg,
	EXT_BUFFER_ALLOC alloc, GET_PROPNAME get_propname)
{
	tnef_push ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16))
		return NULL;
	ext_push.tnef_alloc = alloc;
	ext_push.tnef_getpropname = get_propname;
	if (!tnef_serialize_internal(ext_push, false, pmsg))
		return NULL;
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}

