// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <fmt/core.h>
#include <openssl/evp.h>
#include <tinyxml2.h>
#include <gromox/ab_tree.hpp>
#include <gromox/config_file.hpp>
#include <gromox/cryptoutil.hpp>
#include <gromox/defs.h>
#include <gromox/hpm_common.h>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/plugin.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>

using namespace gromox;
using namespace gromox::ab_tree;

namespace {

/* OAB v4 binary format constants */
static constexpr uint32_t OAB_V4_VERSION = 0x20;

/* Header schema (4 properties) */
static constexpr proptag_t hdr_props[] = {
	PR_OAB_NAME, PR_OAB_DN, PR_OAB_SEQUENCE, PR_OAB_CONTAINER_GUID,
};
static constexpr uint32_t hdr_flags[] = {0, 0, 0, 0};
static constexpr size_t HDR_PROP_COUNT = std::size(hdr_props);

/* Object schema (14 properties) */
static constexpr proptag_t obj_props[] = {
	PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS, PR_DISPLAY_NAME, PR_OBJECT_TYPE,
	PR_DISPLAY_TYPE, PR_DISPLAY_TYPE_EX, PR_GIVEN_NAME, PR_SURNAME,
	PR_TITLE, PR_DEPARTMENT_NAME, PR_COMPANY_NAME, PR_OFFICE_LOCATION,
	PR_BUSINESS_TELEPHONE_NUMBER, PR_OAB_TRUNCATED_PROPS,
};
static constexpr uint32_t obj_flags[] = {
	2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
static constexpr size_t OBJ_PROP_COUNT = std::size(obj_props);

/* IEEE 802.3 CRC-32 (polynomial 0xEDB88320, seeded 0xFFFFFFFF) */
static uint32_t crc32_oab(const void *data, size_t len)
{
	auto p = static_cast<const uint8_t *>(data);
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; ++i) {
		crc ^= p[i];
		for (int j = 0; j < 8; ++j)
			crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
	}
	return crc ^ 0xFFFFFFFF;
}

/* OAB binary writer helper */
class oab_writer {
	public:
	void put_u8(uint8_t v) { buf.push_back(v); }

	void put_u32le(uint32_t v)
	{
		buf.push_back(v & 0xFF);
		buf.push_back((v >> 8) & 0xFF);
		buf.push_back((v >> 16) & 0xFF);
		buf.push_back((v >> 24) & 0xFF);
	}

	/* MS-OXOAB v16 §2.9.6.1 variable-length unsigned integer encoding */
	void put_varui(uint32_t v)
	{
		if (v <= 0x7F) {
			buf.push_back(static_cast<uint8_t>(v));
		} else if (v <= 0xFF) {
			buf.push_back(0x81);
			buf.push_back(static_cast<uint8_t>(v));
		} else if (v <= 0xFFFF) {
			buf.push_back(0x82);
			buf.push_back(v & 0xFF);
			buf.push_back((v >> 8) & 0xFF);
		} else if (v <= 0xFFFFFF) {
			buf.push_back(0x83);
			buf.push_back(v & 0xFF);
			buf.push_back((v >> 8) & 0xFF);
			buf.push_back((v >> 16) & 0xFF);
		} else {
			buf.push_back(0x84);
			put_u32le(v);
		}
	}

	/*
	 * Null-terminated string (PT_UNICODE or PT_STRING8). The caller must
	 * ensure the string is non-empty; empty strings are not encoded but
	 * marked absent in the presence bit array instead (v16 §2.9.6.3).
	 */
	void put_str(const std::string &s)
	{
		buf.append(s.data(), s.data() + s.size() + 1); /* includes \0 this way */
	}

	/* Write placeholder for record size, return offset for later patching */
	size_t begin_record()
	{
		auto off = buf.size();
		put_u32le(0); // placeholder
		return off;
	}

	/*
	 * Patch the record size (cbSize) at the given offset. cbSize includes
	 * itself per MS-OXOAB v16 §2.9.5.
	 */
	void end_record(size_t off)
	{
		patch_u32le(off, buf.size() - off);
	}

	/* Patch a uint32_t at a given offset */
	void patch_u32le(size_t off, uint32_t v)
	{
		buf[off]   = v & 0xFF;
		buf[off+1] = (v >> 8) & 0xFF;
		buf[off+2] = (v >> 16) & 0xFF;
		buf[off+3] = (v >> 24) & 0xFF;
	}

	std::string &data() { return buf; }
	const std::string &data() const { return buf; }
	size_t size() const { return buf.size(); }

	private:
	std::string buf;
};

/*
 * Wrap raw OAB binary data in the compressed file format. MS-OXOAB v16
 * §2.11.1: LZX_HDR (16 bytes) followed by LZX_BLK blocks. Uses stored
 * (uncompressed) blocks with ulFlags=0.
 */
static std::string oab_wrap_lzx(const std::string &raw)
{
	static constexpr size_t BLOCK_MAX = 0x40000;
	std::string out;
	/* LZX_HDR (16 bytes) + per-block 16 bytes header + data */
	size_t nblocks = raw.empty() ? 1 : (raw.size() + BLOCK_MAX - 1) / BLOCK_MAX;
	out.reserve(16 + nblocks * 16 + raw.size());

	auto put_u32 = [&out](uint32_t v) {
		out.push_back(v & 0xFF);
		out.push_back((v >> 8) & 0xFF);
		out.push_back((v >> 16) & 0xFF);
		out.push_back((v >> 24) & 0xFF);
	};

	/* LZX_HDR */
	put_u32(3); // ulVersionHi
	put_u32(1); // ulVersionLo
	put_u32(BLOCK_MAX); // ulBlockMax
	put_u32(raw.size()); // ulTargetSize

	size_t pos = 0;
	while (pos < raw.size()) {
		uint32_t chunk = std::min(raw.size() - pos, BLOCK_MAX);
		auto blk_crc = crc32_oab(raw.data() + pos, chunk);

		/* LZX_BLK header (16 bytes) */
		put_u32(0); // ulFlags: not compressed (stored)
		put_u32(chunk); // ulCompSize: same as uncompressed for stored
		put_u32(chunk); // ulUncompSize
		put_u32(blk_crc); // ulCRC: CRC32 of decompressed block
		out.append(raw, pos, chunk);
		pos += chunk;
	}

	/* Handle empty input: one empty stored block */
	if (raw.empty()) {
		put_u32(0); // ulFlags
		put_u32(0); // ulCompSize
		put_u32(0); // ulUncompSize
		put_u32(crc32_oab(nullptr, 0)); // ulCRC
	}
	return out;
}

/* Compute SHA-1 hex digest of data (MS-OXWOAB specifies SHA-1, 40 hex chars) */
static std::string sha1_hex(std::string_view input)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	std::unique_ptr<EVP_MD_CTX, sslfree> ctx(EVP_MD_CTX_new());
	if (ctx == nullptr)
		return {};
	if (EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) <= 0 ||
	    EVP_DigestUpdate(ctx.get(), input.data(), input.size()) <= 0 ||
	    EVP_DigestFinal_ex(ctx.get(), hash, &len) <= 0)
		return {};
	return bin2hex(hash, len);
}

/*
 * Generate a deterministic GUID string from base_id
 * so the URL remains stable across ab_tree cache reloads.
 */
static std::string deterministic_guid(int32_t base_id)
{
	uint32_t v = base_id;
	return fmt::format("{:08x}-baad-cafe-0ab0-{:012x}", v, v);
}

/* Map display_type (etyp) to MAPI PidTagObjectType value */
static uint32_t etyp_to_objtype(enum display_type dt)
{
	switch (dt) {
	case DT_DISTLIST:
	case DT_PRIVATE_DISTLIST:
		return static_cast<uint32_t>(MAPI_DISTLIST);
	case DT_FORUM:
		return static_cast<uint32_t>(MAPI_FOLDER);
	default:
		return static_cast<uint32_t>(MAPI_MAILUSER);
	}
}

class OabPlugin {
	public:
	OabPlugin();
	http_status proc(int, const void *, uint64_t);
	static BOOL preproc(int);
};

} /* anonymous namespace */

DECLARE_HPM_API(,);

static constexpr char
	response[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><OAB></OAB>",
	header[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"Content-Length: 49\r\n\r\n";

OabPlugin::OabPlugin(){}

BOOL OabPlugin::preproc(int ctx_id)
{
	auto req = get_request(ctx_id);
	return strncasecmp(req->f_request_uri.c_str(), "/OAB", 4) == 0 ? TRUE : false;
}

http_status OabPlugin::proc(int ctx_id, const void *content, uint64_t len) try
{
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if (auth_info.auth_status != http_status::ok)
		return http_status::unauthorized;
	auto wr = write_response(ctx_id, header, strlen(header));
	if (wr != http_status::ok)
		return wr;
	return write_response(ctx_id, response, strlen(response));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2092: ENOMEM");
	return http_status::none;
}

///////////////////////////////////////////////////////////////////////////////
// Plugin management

static std::unique_ptr<OabPlugin> g_oab_plugin;

static BOOL oab_init(const struct dlfuncs &apidata)
{
	LINK_HPM_API(apidata)
	HPM_INTERFACE ifc{};
	ifc.preproc = &OabPlugin::preproc;
	ifc.proc    = [](int ctx, const void *cont, uint64_t len) { return g_oab_plugin->proc(ctx, cont, len); };
	ifc.retr    = [](int ctx) { return HPM_RETRIEVE_DONE; };
	ifc.term    = [](int ctx) {};
	if (!register_interface(&ifc))
		return false;
	try {
		g_oab_plugin.reset(new OabPlugin());
	} catch (const std::exception &e) {
		mlog(LV_ERR, "oab: failed to initialize: %s", e.what());
		return false;
	}
	return TRUE;
}

BOOL HPM_oab(enum plugin_op reason, const struct dlfuncs &data)
{
	if (reason == PLUGIN_INIT)
		return oab_init(data);
	else if (reason == PLUGIN_FREE)
		g_oab_plugin.reset();
	return TRUE;
}
