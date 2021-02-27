// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/applefile.hpp>
#include <gromox/endian_macro.hpp>
#include <cstring>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

/* Mac time of 00:00:00 GMT, Jan 1, 1970 */
#define TIMEDIFF 0x7c25b080

static int applefile_pull_int16(EXT_PULL *pext, int16_t *v)
{
	if (pext->data_size < sizeof(int16_t) ||
		pext->offset + sizeof(int16_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = (int16_t)RSVAL(pext->data, pext->offset);
	pext->offset += sizeof(int16_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_uint16(EXT_PULL *pext, uint16_t *v)
{
	if (pext->data_size < sizeof(uint16_t) ||
		pext->offset + sizeof(uint16_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = RSVAL(pext->data, pext->offset);
	pext->offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_int32(EXT_PULL *pext, int32_t *v)
{
	if (pext->data_size < sizeof(int32_t) ||
		pext->offset + sizeof(int32_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = RIVALS(pext->data, pext->offset);
	pext->offset += sizeof(int32_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_uint32(EXT_PULL *pext, uint32_t *v)
{
	if (pext->data_size < sizeof(uint32_t) ||
		pext->offset + sizeof(uint32_t) > pext->data_size) {
		return EXT_ERR_BUFSIZE;
	}
	*v = RIVAL(pext->data, pext->offset);
	pext->offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_asheader(EXT_PULL *pext, ASHEADER *r)
{
	TRY(applefile_pull_uint32(pext, &r->magic_num));
	if (APPLESINGLE_MAGIC != r->magic_num &&
		APPLEDOUBLE_MAGIC != r->magic_num) {
		return EXT_ERR_FORMAT;
	}
	TRY(applefile_pull_uint32(pext, &r->version_num));
	if (APPLEFILE_VERSION != r->version_num) {
		return EXT_ERR_FORMAT;
	}
	return ext_buffer_pull_bytes(pext, r->filler, 16);
}

static int applefile_pull_asiconbw(EXT_PULL *pext,
	uint32_t entry_length, ASICONBW *r)
{
	int i;
	uint32_t offset;
	
	memset(r, 0, sizeof(ASICONBW));
	offset = pext->offset;
	for (i=0; i<32; i++) {
		TRY(applefile_pull_uint32(pext, &r->bitrow[i]));
		if (pext->offset - offset == entry_length) {
			return EXT_ERR_SUCCESS;
		}
	}
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_asfiledates(EXT_PULL *pext,
	uint32_t entry_length, ASFILEDATES *r)
{
	uint32_t offset;
	int32_t tmp_time;
	
	memset(r, 0, sizeof(ASFILEDATES));
	offset = pext->offset;
	TRY(applefile_pull_int32(pext, &tmp_time));
	r->create = TIMEDIFF + tmp_time;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_int32(pext, &tmp_time));
	r->modify = TIMEDIFF + tmp_time;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_int32(pext, &tmp_time));
	r->backup = TIMEDIFF + tmp_time;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_int32(pext, &tmp_time));
	r->access = TIMEDIFF + tmp_time;
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_asfinderinfo(EXT_PULL *pext,
	uint32_t entry_length, ASFINDERINFO *r)
{
	int i;
	uint32_t offset;
	
	memset(r, 0, sizeof(ASFINDERINFO));
	offset = pext->offset;
	TRY(ext_buffer_pull_bytes(pext, &r->finfo.fd_type, 4));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_pull_bytes(pext, &r->finfo.fd_creator, 4));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_uint16(pext, &r->finfo.fd_flags));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_int16(pext, &r->finfo.fd_location.v));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_int16(pext, &r->finfo.fd_location.h));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_int16(pext, &r->finfo.fd_folder));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	
	TRY(applefile_pull_int16(pext, &r->fxinfo.fd_iconid));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	for (i=0; i<3; i++) {
		TRY(applefile_pull_int16(pext, &r->fxinfo.fd_unused[i]));
		if (pext->offset - offset == entry_length) {
			return EXT_ERR_SUCCESS;
		}
	}
	r->valid_count ++;
	TRY(ext_buffer_pull_int8(pext, &r->fxinfo.fd_script));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_pull_int8(pext, &r->fxinfo.fd_xflags));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_pull_int16(pext, &r->fxinfo.fd_comment));
	r->valid_count ++;
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_pull_int32(pext, &r->fxinfo.fd_putaway));
	r->valid_count ++;
	return EXT_ERR_SUCCESS;
}

static int applefile_pull_asmacinfo(EXT_PULL *pext,
	uint32_t entry_length, ASMACINFO *r)
{
	uint32_t offset;
	
	memset(r, 0, sizeof(ASMACINFO));
	offset = pext->offset;
	TRY(ext_buffer_pull_bytes(pext, r->filler, 3));
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_pull_uint8(pext, &r->attribute);
}

static int applefile_pull_asprodosinfo(EXT_PULL *pext,
	uint32_t entry_length, ASPRODOSINFO *r)
{
	uint32_t offset;
	
	memset(r, 0, sizeof(ASPRODOSINFO));
	offset = pext->offset;
	TRY(applefile_pull_uint16(pext, &r->access));
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_pull_uint16(pext, &r->filetype));
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	return applefile_pull_uint32(pext, &r->auxtype);
}

static int applefile_pull_asmsdosinfo(EXT_PULL *pext,
	uint32_t entry_length, ASMSDOSINFO *r)
{
	uint32_t offset;
	
	memset(r, 0, sizeof(ASMSDOSINFO));
	offset = pext->offset;
	TRY(ext_buffer_pull_uint8(pext, &r->filler));
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_pull_uint8(pext, &r->attr);
}

static int applefile_pull_asafpinfo(EXT_PULL *pext,
	uint32_t entry_length, ASAFPINFO *r)
{
	uint32_t offset;
	
	memset(r, 0, sizeof(ASAFPINFO));
	offset = pext->offset;
	TRY(ext_buffer_pull_bytes(pext, r->filler, 3));
	if (pext->offset - offset == entry_length) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_pull_uint8(pext, &r->attr);
}

static int applefile_pull_asafpdirid(EXT_PULL *pext, ASAFPDIRID *r)
{
	return applefile_pull_uint32(pext, &r->dirid);
}

static int applefile_pull_entry(EXT_PULL *pext,
	uint32_t entry_id, uint32_t entry_length, void **ppentry)
{	
	switch (entry_id) {
	case AS_ICONBW:
		*ppentry = pext->anew<ASICONBW>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASICONBW));
		return applefile_pull_asiconbw(pext, entry_length, static_cast<ASICONBW *>(*ppentry));
	case AS_FILEDATES:
		*ppentry = pext->anew<ASFILEDATES>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASFILEDATES));
		return applefile_pull_asfiledates(pext, entry_length, static_cast<ASFILEDATES *>(*ppentry));
	case AS_FINDERINFO:
		*ppentry = pext->anew<ASFINDERINFO>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASFINDERINFO));
		return applefile_pull_asfinderinfo(pext, entry_length, static_cast<ASFINDERINFO *>(*ppentry));
	case AS_MACINFO:
		*ppentry = pext->anew<ASMACINFO>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASMACINFO));
		return applefile_pull_asmacinfo(pext, entry_length, static_cast<ASMACINFO *>(*ppentry));
	case AS_PRODOSINFO:
		*ppentry = pext->anew<ASPRODOSINFO>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASPRODOSINFO));
		return applefile_pull_asprodosinfo(pext, entry_length, static_cast<ASPRODOSINFO *>(*ppentry));
	case AS_MSDOSINFO:
		*ppentry = pext->anew<ASMSDOSINFO>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASMSDOSINFO));
		return applefile_pull_asmsdosinfo(pext, entry_length, static_cast<ASMSDOSINFO *>(*ppentry));
	case AS_AFPINFO:
		*ppentry = pext->anew<ASAFPINFO>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASAFPINFO));
		return applefile_pull_asafpinfo(pext, entry_length, static_cast<ASAFPINFO *>(*ppentry));
	case AS_AFPDIRID:
		*ppentry = pext->anew<ASAFPDIRID>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		memset(*ppentry, 0, sizeof(ASAFPDIRID));
		return applefile_pull_asafpdirid(pext, static_cast<ASAFPDIRID *>(*ppentry));
	default:
		*ppentry = pext->anew<BINARY>();
		if (NULL == *ppentry) {
			return EXT_ERR_ALLOC;
		}
		((BINARY*)*ppentry)->cb = entry_length;
		static_cast<BINARY *>(*ppentry)->pb = const_cast<uint8_t *>(pext->data + pext->offset);
		return ext_buffer_pull_advance(pext, entry_length);
	}
	
}

static int applefile_push_int16(EXT_PUSH *pext, int16_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(int16_t))) {
		return EXT_ERR_BUFSIZE;
	}
	RSSVAL(pext->data, pext->offset, (uint16_t)v);
	pext->offset += sizeof(int16_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_push_uint16(EXT_PUSH *pext, uint16_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint16_t))) {
		return EXT_ERR_BUFSIZE;
	}
	RSSVAL(pext->data, pext->offset, v);
	pext->offset += sizeof(uint16_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_push_int32(EXT_PUSH *pext, int32_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(int32_t))) {
		return EXT_ERR_BUFSIZE;
	}
	RSIVALS(pext->data, pext->offset, v);
	pext->offset += sizeof(int32_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_push_uint32(EXT_PUSH *pext, uint32_t v)
{
	if (FALSE == ext_buffer_push_check_overflow(pext, sizeof(uint32_t))) {
		return EXT_ERR_BUFSIZE;
	}
	RSIVAL(pext->data, pext->offset, v);
	pext->offset += sizeof(uint32_t);
	return EXT_ERR_SUCCESS;
}

static int applefile_push_asheader(EXT_PUSH *pext, const ASHEADER *r)
{
	if (APPLESINGLE_MAGIC != r->magic_num &&
		APPLEDOUBLE_MAGIC != r->magic_num) {
		return EXT_ERR_FORMAT;
	}
	TRY(applefile_push_uint32(pext, r->magic_num));
	if (APPLEFILE_VERSION != r->version_num) {
		return EXT_ERR_FORMAT;
	}
	TRY(applefile_push_uint32(pext, r->version_num));
	return ext_buffer_push_bytes(pext, r->filler, 16);
}

static int applefile_push_asiconbw(EXT_PUSH *pext, const ASICONBW *r)
{
	int i;
	
	for (i=0; i<32; i++) {
		TRY(applefile_push_uint32(pext, r->bitrow[i]));
	}
	return EXT_ERR_SUCCESS;
}

static int applefile_push_asfiledates(EXT_PUSH *pext, const ASFILEDATES *r)
{
	int32_t tmp_time;
	
	tmp_time = r->create - TIMEDIFF;
	TRY(applefile_push_int32(pext, tmp_time));
	tmp_time = r->modify - TIMEDIFF;
	TRY(applefile_push_int32(pext, tmp_time));
	tmp_time = r->backup - TIMEDIFF;
	TRY(applefile_push_int32(pext, tmp_time));
	tmp_time = r->access - TIMEDIFF;
	return applefile_push_int32(pext, tmp_time);
}

static int applefile_push_asfinderinfo(EXT_PUSH *pext, const ASFINDERINFO *r)
{
	int i;
	uint8_t count;
	
	if (0 == r->valid_count) {
		count = 0xFF;
	} else {
		count = r->valid_count;
	}
	TRY(ext_buffer_push_bytes(pext, &r->finfo.fd_type, 4));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_push_bytes(pext, &r->finfo.fd_creator, 4));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_push_uint16(pext, r->finfo.fd_flags));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_push_int16(pext, r->finfo.fd_location.v));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_push_int16(pext, r->finfo.fd_location.h));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(applefile_push_int16(pext, r->finfo.fd_folder));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	
	TRY(applefile_push_int16(pext, r->fxinfo.fd_iconid));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	for (i=0; i<3; i++) {
		TRY(applefile_push_int16(pext, r->fxinfo.fd_unused[i]));
	}
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_push_int8(pext, r->fxinfo.fd_script));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_push_int8(pext, r->fxinfo.fd_xflags));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	TRY(ext_buffer_push_int16(pext, r->fxinfo.fd_comment));
	if (0 == --count) {
		return EXT_ERR_SUCCESS;
	}
	return ext_buffer_push_int32(pext, r->fxinfo.fd_putaway);
	
}

static int applefile_push_asmacinfo(EXT_PUSH *pext, const ASMACINFO *r)
{
	TRY(ext_buffer_push_bytes(pext, r->filler, 3));
	return ext_buffer_push_uint8(pext, r->attribute);
}

static int applefile_push_asprodosinfo(EXT_PUSH *pext, const ASPRODOSINFO *r)
{
	TRY(applefile_push_uint16(pext, r->access));
	TRY(applefile_push_uint16(pext, r->filetype));
	return applefile_push_uint32(pext, r->auxtype);
}

static int applefile_push_asmsdosinfo(EXT_PUSH *pext, const ASMSDOSINFO *r)
{
	TRY(ext_buffer_push_uint8(pext, r->filler));
	return ext_buffer_push_uint8(pext, r->attr);
}

static int applefile_push_asafpinfo(EXT_PUSH *pext, const ASAFPINFO *r)
{
	TRY(ext_buffer_push_bytes(pext, r->filler, 3));
	return ext_buffer_push_uint8(pext, r->attr);
}

static int applefile_push_asafpdirid(EXT_PUSH *pext, const ASAFPDIRID *r)
{
	return applefile_push_uint32(pext, r->dirid);
}

static int applefile_push_entry(EXT_PUSH *pext,
	uint32_t entry_id, const void *pentry)
{
	switch (entry_id) {
	case AS_ICONBW:
		return applefile_push_asiconbw(pext, static_cast<const ASICONBW *>(pentry));
	case AS_FILEDATES:
		return applefile_push_asfiledates(pext, static_cast<const ASFILEDATES *>(pentry));
	case AS_FINDERINFO:
		return applefile_push_asfinderinfo(pext, static_cast<const ASFINDERINFO *>(pentry));
	case AS_MACINFO:
		return applefile_push_asmacinfo(pext, static_cast<const ASMACINFO *>(pentry));
	case AS_PRODOSINFO:
		return applefile_push_asprodosinfo(pext, static_cast<const ASPRODOSINFO *>(pentry));
	case AS_MSDOSINFO:
		return applefile_push_asmsdosinfo(pext, static_cast<const ASMSDOSINFO *>(pentry));
	case AS_AFPINFO:
		return applefile_push_asafpinfo(pext, static_cast<const ASAFPINFO *>(pentry));
	case AS_AFPDIRID:
		return applefile_push_asafpdirid(pext, static_cast<const ASAFPDIRID *>(pentry));
	default:
		return ext_buffer_push_bytes(pext,
				((BINARY*)pentry)->pb,
				((BINARY*)pentry)->cb);
	}
	
}

int applefile_pull_file(EXT_PULL *pext, APPLEFILE *r)
{
	int i;
	uint32_t offset;
	uint32_t entry_offset;
	uint32_t entry_length;
	
	TRY(applefile_pull_asheader(pext, &r->header));
	TRY(applefile_pull_uint16(pext, &r->count));
	r->pentries = pext->anew<ENTRY_DATA>(r->count);
	if (NULL == r->pentries) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		TRY(applefile_pull_uint32(pext, &r->pentries[i].entry_id));
		TRY(applefile_pull_uint32(pext, &entry_offset));
		TRY(applefile_pull_uint32(pext, &entry_length));
		offset = pext->offset;
		pext->offset = entry_offset;
		TRY(applefile_pull_entry(pext, r->pentries[i].entry_id, entry_length, &r->pentries[i].pentry));
		if (pext->offset > entry_offset + entry_length) {
			return EXT_ERR_FORMAT;
		}
		pext->offset = offset;
	}
	return EXT_ERR_SUCCESS;
}

int applefile_push_file(EXT_PUSH *pext, const APPLEFILE *r)
{
	int i;
	uint32_t offset;
	uint32_t des_offset;
	uint32_t entry_offset;
	uint32_t entry_length;
	
	TRY(applefile_push_asheader(pext, &r->header));
	TRY(applefile_push_uint16(pext, r->count));
	des_offset = pext->offset;
	TRY(ext_buffer_push_advance(pext, r->count * 3 * sizeof(uint32_t)));
	entry_offset = pext->offset;
	for (i=0; i<r->count; i++) {
		TRY(applefile_push_entry(pext, r->pentries[i].entry_id, r->pentries[i].pentry));
		entry_length = pext->offset - entry_offset;
		offset = pext->offset;
		pext->offset = des_offset;
		TRY(applefile_push_uint32(pext, r->pentries[i].entry_id));
		TRY(applefile_push_uint32(pext, entry_offset));
		TRY(applefile_push_uint32(pext, entry_length));
		des_offset = pext->offset;
		pext->offset = offset;
		entry_offset = offset;
	}
	return EXT_ERR_SUCCESS;
}
