// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/apple_util.hpp>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>

using namespace gromox;

BINARY* apple_util_binhex_to_appledouble(const BINHEX *pbinhex)
{
	BINARY tmp_bin;
	BINARY tmp_bin1;
	EXT_PUSH ext_push;
	APPLEFILE applefile{};
	ASFINDERINFO fdr_entry;
	ENTRY_DATA entry_buff[3];
	
	applefile.header.magic_num = APPLEDOUBLE_MAGIC;
	applefile.header.version_num = APPLEFILE_VERSION;
	if (0 == pbinhex->res_len) {
		applefile.count = 2;
	} else {
		applefile.count = 3;
	}
	applefile.pentries = entry_buff;
	entry_buff[0].entry_id = AS_FINDERINFO;
	entry_buff[0].pentry = &fdr_entry;
	fdr_entry.valid_count = 3;
	fdr_entry.finfo.fd_type = pbinhex->type;
	fdr_entry.finfo.fd_creator = pbinhex->creator;
	fdr_entry.finfo.fd_flags = pbinhex->flags & 0xFFF8;
	entry_buff[1].entry_id = AS_REALNAME;
	entry_buff[1].pentry = &tmp_bin;
	tmp_bin.cb = strlen(pbinhex->file_name);
	tmp_bin.pv = deconst(pbinhex->file_name);
	if (0 != pbinhex->res_len) {
		entry_buff[2].entry_id = AS_RESOURCE;
		entry_buff[2].pentry = &tmp_bin1;
		tmp_bin1.cb = pbinhex->res_len;
		tmp_bin1.pb = pbinhex->presource;
	}
	if (!ext_push.init(nullptr, 0, 0))
		return nullptr;
	if (EXT_ERR_SUCCESS != applefile_push_file(&ext_push, &applefile)) {
		return nullptr;
	}
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}

BINARY* apple_util_macbinary_to_appledouble(const MACBINARY *pmacbin)
{
	BINARY tmp_bin;
	BINARY tmp_bin1;
	EXT_PUSH ext_push;
	APPLEFILE applefile;
	ASFILEDATES entry_date;
	ENTRY_DATA entry_buff[5];
	ASFINDERINFO finder_entry;
	
	applefile.header.magic_num = APPLEDOUBLE_MAGIC;
	applefile.header.version_num = APPLEFILE_VERSION;
	memset(applefile.header.filler, 0, std::size(applefile.header.filler));
	applefile.count = 0;
	applefile.pentries = entry_buff;
	entry_buff[applefile.count].entry_id = AS_REALNAME;
	entry_buff[applefile.count++].pentry = &tmp_bin;
	tmp_bin.cb = strlen(pmacbin->header.file_name);
	tmp_bin.pv = deconst(pmacbin->header.file_name);
	entry_buff[applefile.count].entry_id = AS_FILEDATES;
	entry_buff[applefile.count++].pentry = &entry_date;
	entry_date.create = pmacbin->header.creat_time;
	entry_date.modify = pmacbin->header.modify_time;
	entry_date.backup = 0;
	entry_date.access = 0;
	entry_buff[applefile.count].entry_id = AS_FINDERINFO;
	entry_buff[applefile.count++].pentry = &finder_entry;
	finder_entry.valid_count = 6;
	finder_entry.finfo.fd_type = pmacbin->header.type;
	finder_entry.finfo.fd_creator = pmacbin->header.creator;
	finder_entry.finfo.fd_flags = ((uint16_t)
		pmacbin->header.original_flags) << 8 |
		pmacbin->header.finder_flags;
	finder_entry.finfo.fd_folder = pmacbin->header.folder_id;
	finder_entry.finfo.fd_location.v = pmacbin->header.point_v;
	finder_entry.finfo.fd_location.h = pmacbin->header.point_h;
	entry_buff[applefile.count].entry_id = AS_MACINFO;
	ASMACINFO mac_info{};
	entry_buff[applefile.count++].pentry = &mac_info;
	mac_info.attribute = (pmacbin->header.protected_flag >> 1) & 0x01;
	if (0 != pmacbin->header.res_len) {
		entry_buff[applefile.count].entry_id = AS_RESOURCE;
		entry_buff[applefile.count++].pentry = &tmp_bin1;
		tmp_bin1.cb = pmacbin->header.res_len;
		tmp_bin1.pb = deconst(pmacbin->presource);
	}
	if (!ext_push.init(nullptr, 0, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != applefile_push_file(&ext_push, &applefile)) {
		return NULL;
	}
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}

BINARY* apple_util_appledouble_to_macbinary(const APPLEFILE *papplefile,
	const void *pdata, uint32_t data_len)
{
	int i;
	MACBINARY macbin{};
	EXT_PUSH ext_push;
	
	for (i=0; i<papplefile->count; i++) {
		if (AS_REALNAME == papplefile->pentries[i].entry_id) {
			auto bin = static_cast<BINARY *>(papplefile->pentries[i].pentry);
			if (bin->cb > 63)
				memcpy(macbin.header.file_name, bin->pb, 63);
			else
				memcpy(macbin.header.file_name, bin->pb, bin->cb);
			
		} else if (AS_FINDERINFO == papplefile->pentries[i].entry_id) {
			auto fi = static_cast<ASFINDERINFO *>(papplefile->pentries[i].pentry);
			macbin.header.type = fi->finfo.fd_type;
			macbin.header.creator = fi->finfo.fd_creator;
			macbin.header.original_flags = fi->finfo.fd_flags >> 8;
			macbin.header.finder_flags = fi->finfo.fd_flags & 0xFF;
			macbin.header.folder_id = fi->finfo.fd_folder;
			macbin.header.point_v = fi->finfo.fd_location.v;
			macbin.header.point_h = fi->finfo.fd_location.h;
		} else if (AS_RESOURCE == papplefile->pentries[i].entry_id) {
			auto bin = static_cast<BINARY *>(papplefile->pentries[i].pentry);
			macbin.header.res_len = bin->cb;
			macbin.presource = bin->pb;
		} else if (AS_MACINFO == papplefile->pentries[i].entry_id) {
			auto mi = static_cast<ASMACINFO *>(papplefile->pentries[i].pentry);
			macbin.header.protected_flag = (mi->attribute & 0x01) << 1;
		} else if (AS_FILEDATES == papplefile->pentries[i].entry_id) {
			auto fd = static_cast<ASFILEDATES *>(papplefile->pentries[i].pentry);
			macbin.header.creat_time  = fd->create;
			macbin.header.modify_time = fd->modify;
		}
	}
	macbin.header.version = 130;
	macbin.header.mini_version = 129; 
	memcpy(&macbin.header.signature, "mBIN", 4);
	macbin.header.data_len = data_len;
	macbin.pdata = static_cast<const uint8_t *>(pdata);
	if (!ext_push.init(nullptr, 0, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != macbinary_push_binary(&ext_push, &macbin)) {
		return NULL;
	}
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}

BINARY* apple_util_applesingle_to_macbinary(const APPLEFILE *papplefile)
{
	int i;
	MACBINARY macbin{};
	EXT_PUSH ext_push;
	
	for (i=0; i<papplefile->count; i++) {
		if (AS_REALNAME == papplefile->pentries[i].entry_id) {
			auto bin = static_cast<BINARY *>(papplefile->pentries[i].pentry);
			if (bin->cb > 63)
				memcpy(macbin.header.file_name, bin->pb, 63);
			else
				memcpy(macbin.header.file_name, bin->pb, bin->cb);
		} else if (AS_FINDERINFO == papplefile->pentries[i].entry_id) {
			auto fi = static_cast<ASFINDERINFO *>(papplefile->pentries[i].pentry);
			macbin.header.type = fi->finfo.fd_type;
			macbin.header.creator = fi->finfo.fd_creator;
			macbin.header.original_flags = fi->finfo.fd_flags >> 8;
			macbin.header.finder_flags = fi->finfo.fd_flags & 0xFF;
			macbin.header.folder_id = fi->finfo.fd_folder;
			macbin.header.point_v = fi->finfo.fd_location.v;
			macbin.header.point_h = fi->finfo.fd_location.h;
		} else if (AS_RESOURCE == papplefile->pentries[i].entry_id) {
			auto bin = static_cast<BINARY *>(papplefile->pentries[i].pentry);
			macbin.header.res_len = bin->cb;
			macbin.presource = bin->pb;
		} else if (AS_MACINFO == papplefile->pentries[i].entry_id) {
			auto mi = static_cast<ASMACINFO *>(papplefile->pentries[i].pentry);
			macbin.header.protected_flag = (mi->attribute & 0x01) << 1;
		} else if (AS_FILEDATES == papplefile->pentries[i].entry_id) {
			auto fd = static_cast<ASFILEDATES *>(papplefile->pentries[i].pentry);
			macbin.header.creat_time  = fd->create;
			macbin.header.modify_time = fd->modify;
		} else if (AS_DATA == papplefile->pentries[i].entry_id) {
			auto bin = static_cast<BINARY *>(papplefile->pentries[i].pentry);
			macbin.header.data_len = bin->cb;
			macbin.pdata = bin->pb;
		}
	}
	macbin.header.version = 130;
	macbin.header.mini_version = 129; 
	memcpy(&macbin.header.signature, "mBIN", 4);
	if (!ext_push.init(nullptr, 0, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != macbinary_push_binary(&ext_push, &macbin)) {
		return NULL;
	}
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}

BINARY* apple_util_binhex_to_macbinary(const BINHEX *pbinhex)
{
	MACBINARY macbin{};
	EXT_PUSH ext_push;
	
	strcpy(macbin.header.file_name, pbinhex->file_name);
	macbin.header.type = pbinhex->type;
	macbin.header.creator = pbinhex->creator;
	macbin.header.version = 130;
	macbin.header.mini_version = 129; 
	memcpy(&macbin.header.signature, "mBIN", 4);
	macbin.header.original_flags = pbinhex->flags >> 8;
	macbin.header.finder_flags = pbinhex->flags & 0xF8;
	if (0 != pbinhex->data_len) {
		macbin.header.data_len = pbinhex->data_len;
		macbin.pdata = pbinhex->pdata;
	}
	if (0 != pbinhex->res_len) {
		macbin.header.res_len = pbinhex->res_len;
		macbin.presource = pbinhex->presource;
	}
	if (!ext_push.init(nullptr, 0, 0))
		return NULL;
	if (EXT_ERR_SUCCESS != macbinary_push_binary(&ext_push, &macbin)) {
		return NULL;
	}
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}

BINARY* apple_util_applesingle_to_appledouble(const APPLEFILE *papplefile)
{
	int i;
	EXT_PUSH ext_push;
	APPLEFILE applefile;
	
	applefile.header = papplefile->header;
	applefile.header.magic_num = APPLEDOUBLE_MAGIC;
	applefile.count = 0;
	applefile.pentries = me_alloc<ENTRY_DATA>(papplefile->count);
	if (NULL == applefile.pentries) {
		return NULL;
	}
	for (i=0; i<papplefile->count; i++) {
		if (AS_DATA == papplefile->pentries[i].entry_id) {
			continue;
		}
		applefile.pentries[applefile.count++] = papplefile->pentries[i];
	}
	if (!ext_push.init(nullptr, 0, 0)) {
		free(applefile.pentries);
		return nullptr;
	}
	if (EXT_ERR_SUCCESS != applefile_push_file(&ext_push, &applefile)) {
		free(applefile.pentries);
		return nullptr;
	}
	free(applefile.pentries);
	auto pbin = me_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = ext_push.m_offset;
	pbin->pb = ext_push.release();
	return pbin;
}
