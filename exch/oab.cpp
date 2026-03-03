// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
/*
 * MS-OXOAB Offline Address Book implementation.
 * Generates OAB Full Details files and XML manifest for Outlook clients.
 */
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
#include <gromox/clock.hpp>
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

namespace {

/* Cached OAB data for a single address book base */
struct oab_cache_entry {
	std::string manifest_xml, lzx_data;
	gromox::time_point gen_time;
	uint32_t sequence = 1;
};

/* OAB binary writer helper */
class oab_writer {
	public:
	void put_u8(uint8_t v) { buf.push_back(v); }
	void put_u32le(uint32_t);
	void put_varui(uint32_t);
	void put_str(const std::string &);
	size_t begin_record();

	/**
	 * Patch the record size (cbSize) at the given offset. cbSize includes
	 * itself per MS-OXOAB v16 §2.9.5.
	 */
	void end_record(size_t off) { patch_u32le(off, buf.size() - off); }

	void patch_u32le(size_t off, uint32_t v);
	std::string &data() { return buf; }
	const std::string &data() const { return buf; }
	size_t size() const { return buf.size(); }

	private:
	std::string buf;
};

} /* anon-ns */

void oab_writer::put_u32le(uint32_t v)
{
	buf.push_back(v & 0xFF);
	buf.push_back((v >> 8) & 0xFF);
	buf.push_back((v >> 16) & 0xFF);
	buf.push_back((v >> 24) & 0xFF);
}

/**
 * MS-OXOAB v16 §2.9.6.1 variable-length unsigned integer encoding.
 */
void oab_writer::put_varui(uint32_t v)
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

/**
 * Null-terminated string (PT_UNICODE or PT_STRING8). The caller must
 * ensure the string is non-empty; empty strings are not encoded but
 * marked absent in the presence bit array instead (v16 §2.9.6.3).
 */
void oab_writer::put_str(const std::string &s)
{
	buf.append(s.data(), s.data() + s.size() + 1); /* includes \0 this way */
}

/**
 * Write placeholder for record size, return offset for later patching.
 */
size_t oab_writer::begin_record()
{
	auto off = buf.size();
	put_u32le(0); // placeholder
	return off;
}

/**
 * Patch a uint32_t at a given offset
 */
void oab_writer::patch_u32le(size_t off, uint32_t v)
{
	buf[off]   = v & 0xFF;
	buf[off+1] = (v >> 8) & 0xFF;
	buf[off+2] = (v >> 16) & 0xFF;
	buf[off+3] = (v >> 24) & 0xFF;
}

/**
 * CRC-32 for OAB LZX_BLK headers (polynomial 0xEDB88320).
 *
 * libmspack's OAB decompressor compares the running CRC (seeded
 * 0xFFFFFFFF, no final XOR) directly against the stored value.
 * So we store the running CRC, not the standard finalized one.
 */
static uint32_t crc32_oab(const void *data, size_t len)
{
	auto p = static_cast<const uint8_t *>(data);
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; ++i) {
		crc ^= p[i];
		for (int j = 0; j < 8; ++j)
			crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
	}
	return crc; /* running CRC, no final XOR */
}

/**
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

/**
 * Compute SHA-1 hex digest of data (MS-OXWOAB specifies SHA-1, 40 hex chars)
 */
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

/**
 * Generate a deterministic GUID string from base_id
 * so the URL remains stable across ab_tree cache reloads.
 */
static std::string deterministic_guid(int32_t base_id)
{
	uint32_t v = base_id;
	return fmt::format("{:08x}-baad-cafe-0ab0-{:012x}", v, v);
}

/**
 * Map display_type (etyp) to MAPI PidTagObjectType value
 */
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

namespace {

class OabPlugin {
	public:
	OabPlugin();
	http_status proc(int, const void *, uint64_t);
	static BOOL preproc(int);
	void clear_cache();

	private:
	http_status send_response(int ctx_id, const char *ct_type, const std::string &body);
	http_status send_error(int ctx_id, http_status);
	http_status serve_manifest(int ctx_id, int32_t base_id);
	http_status serve_lzx(int ctx_id, int32_t base_id, uint32_t seq);
	const oab_cache_entry *get_or_generate(int32_t base_id);
	std::string generate_uc(int32_t base_id, uint32_t seq, const std::string &guid, const std::string &oab_dn);
	bool generate_oab(int32_t base_id, oab_cache_entry &entry);

	std::mutex m_cache_lock;
	std::unordered_map<int32_t, oab_cache_entry> m_cache;
	std::string m_org_name;
	std::chrono::seconds m_cache_interval{300};
};

} /* anonymous namespace */

DECLARE_HPM_API(,);

static constexpr cfg_directive oab_nsp_cfg_defaults[] = {
	{"cache_interval", "5min", CFG_TIME, "1s", "1d"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

OabPlugin::OabPlugin()
{
	auto cfg = config_file_initd("exchange_nsp.cfg", get_config_path(),
	           oab_nsp_cfg_defaults);
	if (cfg != nullptr) {
		auto v = cfg->get_value("X500_ORG_NAME");
		if (v != nullptr)
			m_org_name = v;
		auto ci = cfg->get_ll("cache_interval");
		if (ci > 0)
			m_cache_interval = std::chrono::seconds(ci);
	}
	if (m_org_name.empty())
		m_org_name = "Gromox default";
}

BOOL OabPlugin::preproc(int ctx_id)
{
	auto req = get_request(ctx_id);
	return strncasecmp(req->f_request_uri.c_str(), "/OAB/", 5) == 0 ? TRUE : false;
}

http_status OabPlugin::proc(int ctx_id, const void *content, uint64_t len) try
{
	HTTP_AUTH_INFO auth_info = get_auth_info(ctx_id);
	if (auth_info.auth_status != http_status::ok)
		return http_status::unauthorized;

	/* Resolve username -> domain -> base_id */
	auto pdomain = strchr(auth_info.username, '@');
	if (pdomain == nullptr)
		return send_error(ctx_id, http_status::bad_request);
	pdomain++;

	unsigned int domain_id = 0, org_id = 0;
	if (!mysql_adaptor_get_domain_ids(pdomain, &domain_id, &org_id)) {
		mlog(LV_WARN, "oab: domain %s not found", pdomain);
		return send_error(ctx_id, http_status::not_found);
	}
	int32_t base_id = org_id == 0 ? -domain_id : org_id;

	/* Parse URI */
	auto req = get_request(ctx_id);
	const auto &uri = req->f_request_uri;

	/* /OAB/oab.xml or /OAB/{seq}.lzx */
	if (strcasecmp(&uri[5], "oab.xml") == 0)
		return serve_manifest(ctx_id, base_id);

	/* Check for {N}.lzx */
	char *end = nullptr;
	auto seq = strtoul(&uri[5], &end, 10);
	if (end != nullptr && end != &uri[5] && strcmp(end, ".lzx") == 0)
		return serve_lzx(ctx_id, base_id, seq);

	return send_error(ctx_id, http_status::not_found);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2092: ENOMEM");
	return http_status::none;
}

http_status OabPlugin::send_response(int ctx_id,
	const char *content_type, const std::string &body)
{
	auto hdr = fmt::format(
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: {}\r\n"
		"Content-Length: {}\r\n\r\n",
		content_type, body.size());
	auto wr = write_response(ctx_id, hdr.data(), hdr.size());
	if (wr != http_status::ok)
		return wr;
	return write_response(ctx_id, body.data(), body.size());
}

http_status OabPlugin::send_error(int ctx_id, http_status code)
{
	const char *text = "Error";
	unsigned int icode = 500;
	switch (code) {
	case http_status::bad_request:
		text = "Bad Request"; icode = 400; break;
	case http_status::not_found:
		text = "Not Found"; icode = 404; break;
	default:
		break;
	}
	auto body = fmt::format("{} {}", icode, text);
	auto hdr = fmt::format(
		"HTTP/1.1 {} {}\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: {}\r\n\r\n",
		icode, text, body.size());
	auto wr = write_response(ctx_id, hdr.data(), hdr.size());
	if (wr != http_status::ok)
		return wr;
	return write_response(ctx_id, body.data(), body.size());
}

const oab_cache_entry *OabPlugin::get_or_generate(int32_t base_id)
{
	std::lock_guard lock(m_cache_lock);
	auto it = m_cache.find(base_id);
	auto now = std::chrono::steady_clock::now();
	if (it != m_cache.end() &&
	    now - it->second.gen_time < m_cache_interval)
		return &it->second;

	/* Generate fresh data */
	oab_cache_entry entry;
	if (it != m_cache.end())
		entry.sequence = it->second.sequence + 1;
	if (!generate_oab(base_id, entry))
		return nullptr;
	entry.gen_time = now;
	auto &ref = m_cache[base_id] = std::move(entry);
	return &ref;
}

http_status OabPlugin::serve_manifest(int ctx_id, int32_t base_id)
{
	auto entry = get_or_generate(base_id);
	if (entry == nullptr)
		return send_error(ctx_id, http_status::not_found);
	return send_response(ctx_id, "text/xml", entry->manifest_xml);
}

http_status OabPlugin::serve_lzx(int ctx_id, int32_t base_id, uint32_t seq)
{
	auto entry = get_or_generate(base_id);
	if (entry == nullptr || entry->sequence != seq)
		return send_error(ctx_id, http_status::not_found);
	return send_response(ctx_id, "application/octet-stream", entry->lzx_data);
}

/**
 * Procedure for MS-OXOAB v16 §2.9
 * "Uncompressed OAB Version 4 Full Details File"
 */
std::string OabPlugin::generate_uc(int32_t base_id, uint32_t sequence,
    const std::string &guid_str, const std::string &oab_dn)
{
	auto pbase = ab_tree::AB.get(base_id);
	if (pbase == nullptr) {
		mlog(LV_WARN, "oab: ab_tree base_id %d not available", base_id);
		return {};
	}
	const auto &base = *pbase;

	/* Count GAL-visible users */
	size_t user_count = base.filtered_user_count();

	oab_writer w;

	/* OAB_HDR (12 bytes, MS-OXOAB §2.9.1) */
	w.put_u32le(OAB_V4_VERSION);
	auto serial_off = w.size();
	w.put_u32le(0); // placeholder for ulSerial (CRC32 of rest of file)
	w.put_u32le(user_count);

	/* OAB_META_DATA (MS-OXOAB §2.9.2): cbSize includes itself */
	auto meta_off = w.begin_record();

	/* rgHdrAtts: OAB_PROP_TABLE for header record */
	w.put_u32le(HDR_PROP_COUNT);
	for (size_t i = 0; i < HDR_PROP_COUNT; ++i) {
		w.put_u32le(hdr_props[i]);
		w.put_u32le(hdr_flags[i]);
	}

	/* rgOabAtts: OAB_PROP_TABLE for object records */
	w.put_u32le(OBJ_PROP_COUNT);
	for (size_t i = 0; i < OBJ_PROP_COUNT; ++i) {
		w.put_u32le(obj_props[i]);
		w.put_u32le(obj_flags[i]);
	}

	w.end_record(meta_off);

	/* Header record (OAB_V4_REC, MS-OXOAB §2.9.4) */
	{
		auto rec_off = w.begin_record();
		// Presence bit array: 4 props -> ceil(4/8)=1 byte
		// MSB = prop 0; all 4 present -> 0xF0
		w.put_u8(0xF0);

		// Prop 0: PidTagOfflineAddressBookName (PT_UNICODE)
		w.put_str("\\Default Global Address List");
		// Prop 1: PidTagOfflineAddressBookDistinguishedName (PT_STRING8)
		w.put_str(oab_dn);
		// Prop 2: PidTagOfflineAddressBookSequence (PT_LONG)
		w.put_varui(sequence);
		// Prop 3: PidTagOfflineAddressBookContainerGuid (PT_STRING8)
		w.put_str(guid_str);

		w.end_record(rec_off);
	}

	/* Object records (one OAB_V4_REC per GAL-visible entry) */
	for (auto it = base.ufbegin(); it != base.ufend(); ++it) {
		auto mid = *it;
		auto rec_off = w.begin_record();

		/* Collect property values */
		std::string dn_val, smtp_val;

		bool has_dn   = base.dn(mid, dn_val);
		auto smtp_ptr = base.user_info(mid, userinfo::mail_address);
		if (smtp_ptr != nullptr)
			smtp_val = smtp_ptr;

		auto display_val      = base.displayname(mid);
		auto etyp_val         = base.etyp(mid);
		uint32_t obj_type_val = etyp_to_objtype(etyp_val);
		uint32_t dtyp_val     = base.dtyp(mid);
		auto dtypx_opt        = base.dtypx(mid);
		uint32_t dtypx_val    = dtypx_opt.value_or(0);
		bool has_dtypx        = dtypx_opt.has_value();

		std::string given_val, surname_val, title_val, dept_val;
		std::string company_val, office_val, phone_val;

		base.fetch_prop(mid, PR_GIVEN_NAME, given_val);
		base.fetch_prop(mid, PR_SURNAME, surname_val);
		base.fetch_prop(mid, PR_TITLE, title_val);
		base.fetch_prop(mid, PR_DEPARTMENT_NAME, dept_val);
		base.company_name(mid, company_val);
		base.office_location(mid, office_val);
		base.fetch_prop(mid, PR_BUSINESS_TELEPHONE_NUMBER, phone_val);

		/*
		 * Build presence bit array (14 props -> ceil(14/8) = 2 bytes)
		 * MSB of first byte = prop 0, bit 6 = prop 1, ...
		 * Per MS-OXOAB: empty strings MUST NOT be encoded;
		 * mark absent in presence bits instead.
		 */
		uint8_t presence[2] = {0, 0};
		if (has_dn && !dn_val.empty())      presence[0] |= 0x80; // prop 0
		if (!smtp_val.empty())              presence[0] |= 0x40; // prop 1
		if (!display_val.empty())           presence[0] |= 0x20; // prop 2
		presence[0] |= 0x10; // prop 3: object type (always present)
		presence[0] |= 0x08; // prop 4: display type (always present)
		if (has_dtypx)                      presence[0] |= 0x04; // prop 5
		if (!given_val.empty())             presence[0] |= 0x02; // prop 6
		if (!surname_val.empty())           presence[0] |= 0x01; // prop 7
		if (!title_val.empty())             presence[1] |= 0x80; // prop 8
		if (!dept_val.empty())              presence[1] |= 0x40; // prop 9
		if (!company_val.empty())           presence[1] |= 0x20; // prop 10
		if (!office_val.empty())            presence[1] |= 0x10; // prop 11
		if (!phone_val.empty())             presence[1] |= 0x08; // prop 12
		// prop 13: PidTagOfflineAddressBookTruncatedProperties - always absent

		w.put_u8(presence[0]);
		w.put_u8(presence[1]);

		/* Write present property values in schema order */
		if (presence[0] & 0x80) w.put_str(dn_val);
		if (presence[0] & 0x40) w.put_str(smtp_val);
		if (presence[0] & 0x20) w.put_str(display_val);
		w.put_varui(obj_type_val);  // always present
		w.put_varui(dtyp_val);      // always present
		if (presence[0] & 0x04) w.put_varui(dtypx_val);
		if (presence[0] & 0x02) w.put_str(given_val);
		if (presence[0] & 0x01) w.put_str(surname_val);
		if (presence[1] & 0x80) w.put_str(title_val);
		if (presence[1] & 0x40) w.put_str(dept_val);
		if (presence[1] & 0x20) w.put_str(company_val);
		if (presence[1] & 0x10) w.put_str(office_val);
		if (presence[1] & 0x08) w.put_str(phone_val);

		w.end_record(rec_off);
	}

	/* Patch ulSerial: CRC32 of everything after the 12-byte OAB_HDR */
	auto &raw   = w.data();
	auto serial = crc32_oab(&raw[12], raw.size() - 12);
	w.patch_u32le(serial_off, serial);
	mlog(LV_INFO, "oab: generated OABv4 for base_id %d: %zu users, %zu bytes",
		static_cast<int>(base_id), user_count, raw.size());
	return std::move(w.data());
}

/**
 * Procedure for MS-OXOAB v16 §2.11 "Compressed OAB Version 4 Details File"
 */
bool OabPlugin::generate_oab(int32_t base_id, oab_cache_entry &entry)
{
	auto guid_str = deterministic_guid(base_id);
	auto oab_dn   = fmt::format("/o={}/cn=addrlists/cn=oabs/cn=Default Offline Address Book",
	                m_org_name);
	auto raw = generate_uc(base_id, entry.sequence, guid_str, oab_dn);
	if (raw.empty())
		return false;

	entry.lzx_data = oab_wrap_lzx(raw);
	auto sha = sha1_hex(entry.lzx_data);
	/* Generate manifest XML (MS-OXWOAB) */
	tinyxml2::XMLDocument doc;
	doc.InsertEndChild(doc.NewDeclaration());
	auto root = doc.NewElement("OAB");
	doc.InsertEndChild(root);

	auto oal = doc.NewElement("OAL");
	oal->SetAttribute("id", guid_str.c_str());
	oal->SetAttribute("dn", oab_dn.c_str());
	oal->SetAttribute("name", "\\Default Global Address List");
	root->InsertEndChild(oal);

	auto full = doc.NewElement("Full");
	full->SetAttribute("seq", entry.sequence);
	full->SetAttribute("ver", OAB_V4_VERSION);
	full->SetAttribute("size", entry.lzx_data.size());
	full->SetAttribute("uncompressedsize", raw.size());
	full->SetAttribute("SHA", sha.c_str());
	full->SetText((std::to_string(entry.sequence) + ".lzx").c_str());
	oal->InsertEndChild(full);

	tinyxml2::XMLPrinter printer(nullptr, true);
	doc.Print(&printer);
	entry.manifest_xml.assign(printer.CStr(), printer.CStrSize() > 0 ?
	                          printer.CStrSize() - 1 : 0);
	return true;
}

void OabPlugin::clear_cache()
{
	std::lock_guard lock(m_cache_lock);
	m_cache.clear();
}

///////////////////////////////////////////////////////////////////////////////
// Plugin management

static std::unique_ptr<OabPlugin> g_oab_plugin;

static BOOL oab_init(const struct dlfuncs &apidata)
{
	LINK_HPM_API(apidata)
	if (service_run_library({"libgxs_mysql_adaptor.so",
	    SVC_mysql_adaptor}) != PLUGIN_LOAD_OK)
		return false;

	/* Initialize ab_tree (shared with NSP; init is idempotent per running count) */
	auto cfg = config_file_initd("exchange_nsp.cfg", get_config_path(),
	           oab_nsp_cfg_defaults);
	if (cfg != nullptr) {
		auto org = cfg->get_value("X500_ORG_NAME");
		auto ci = cfg->get_ll("cache_interval");
		if (ab_tree::AB.init(org != nullptr ? org : "Gromox default",
		    ci > 0 ? ci : 300) != 0)
			return false;
	} else {
		if (ab_tree::AB.init("Gromox default", 300) != 0)
			return false;
	}
	if (!ab_tree::AB.run()) {
		mlog(LV_ERR, "oab: failed to start ab_tree");
		return false;
	}

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
	if (reason == PLUGIN_INIT) {
		return oab_init(data);
	} else if (reason == PLUGIN_FREE) {
		g_oab_plugin.reset();
		ab_tree::AB.stop();
		return TRUE;
	} else if (reason == PLUGIN_RELOAD) {
		ab_tree::AB.invalidate_cache();
		if (g_oab_plugin)
			g_oab_plugin->clear_cache();
		return TRUE;
	}
	return TRUE;
}
