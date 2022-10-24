// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <libolecf.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <fmt/core.h>
#include <libHX/option.h>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"

using namespace gromox;

namespace {

struct olecf_error_del { void operator()(libolecf_error_t *x) { libolecf_error_free(&x); } };
struct olecf_file_del { void operator()(libolecf_file_t *x) { libolecf_file_free(&x, nullptr); } };
struct olecf_item_del { void operator()(libolecf_item_t *x) { libolecf_item_free(&x, nullptr); } };

using oxm_error_ptr = std::unique_ptr<libolecf_error_t, olecf_error_del>;
using oxm_file_ptr  = std::unique_ptr<libolecf_file_t, olecf_file_del>;
using oxm_item_ptr  = std::unique_ptr<libolecf_item_t, olecf_item_del>;
using ustring = std::basic_string<uint8_t>;

}

static constexpr HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static YError az_error(const char *prefix, const oxm_error_ptr &err)
{
	char buf[160];
	buf[0] = '\0';
	libolecf_error_sprint(err.get(), buf, std::size(buf));
	return YError(std::string(prefix) + ": " + buf);
}

static ustring slurp_stream(libolecf_item_t *stream)
{
	oxm_error_ptr err;
	uint32_t strm_size = 0;

	if (libolecf_item_get_size(stream, &strm_size, &unique_tie(err)) < 1)
		throw az_error("PO-1009", err);
	ustring buf;
	buf.resize(strm_size);
	for (size_t ofs = 0; ofs < strm_size; ) {
		auto ret = libolecf_stream_read_buffer(stream, &buf[ofs],
		           strm_size - ofs, &~unique_tie(err));
		if (ret < 0)
			throw az_error("PO-1010", err);
		else if (ret == 0)
			break;
		ofs += ret;
	}
	return buf;
}

static ustring slurp_stream(libolecf_item_t *dir, const char *file)
{
	oxm_error_ptr err;
	oxm_item_ptr propstrm;

	if (libolecf_item_get_sub_item_by_utf8_path(dir,
	    reinterpret_cast<const uint8_t *>(file), strlen(file),
	    &unique_tie(propstrm), &unique_tie(err)) < 1)
		throw az_error("PO-1007", err);
	return slurp_stream(propstrm.get());
}

static int parse_propstrmentry(EXT_PULL &ep, TPROPVAL_ARRAY &proplist)
{
	uint32_t proptag = 0, alloc_len = 0;
	ustring blob;

	if (ep.eof())
		return 0;
	if (ep.g_uint32(&proptag) != EXT_ERR_SUCCESS)
		return -EIO;
	if (ep.advance(4) != EXT_ERR_SUCCESS)
		return -EIO;

	switch (PROP_TYPE(proptag)) {

	/* Fixed-length props */
#define IMMED(T, func) \
	do { \
		T v; \
		static_assert(sizeof(T) <= 8); \
		if (ep.func(&v) != EXT_ERR_SUCCESS) \
			return -EIO; \
		if (ep.advance(8 - sizeof(T)) != EXT_ERR_SUCCESS) \
			return -EIO; \
		proplist.set(proptag, &v); \
	} while (false)

		case PT_SHORT: IMMED(uint16_t, g_uint16); return 1;
		case PT_ERROR: [[fallthrough]];
		case PT_LONG: IMMED(uint32_t, g_uint32); return 1;
		case PT_FLOAT: IMMED(float, g_float); return 1;
		case PT_DOUBLE: [[fallthrough]];
		case PT_APPTIME: IMMED(double, g_double); return 1;
		case PT_CURRENCY: [[fallthrough]];
		case PT_SYSTIME: [[fallthrough]];
		case PT_I8: IMMED(uint64_t, g_uint64); return 1;
#undef IMMED
	case PT_BOOLEAN: {
		// make BOOL a class, forbid op&
		uint32_t v;
		if (ep.g_uint32(&v) != EXT_ERR_SUCCESS)
			return EIO;
		if (ep.advance(4) != EXT_ERR_SUCCESS)
			return EIO;
		BOOL w = !!v;
		proplist.set(proptag, &w);
		return 1;
	}

	/* Variable-length types */
	case PT_BINARY:
	case PT_STRING8:
	case PT_UNICODE:
	case PT_CLSID:
		if (ep.g_uint32(&alloc_len) != EXT_ERR_SUCCESS)
			return EIO;
		if (ep.advance(4) != EXT_ERR_SUCCESS)
			return EIO;
		blob.resize(alloc_len);
		// look for __substg1.0_<proptag> in a moment
		break;

	case PT_OBJECT:
		// special case

	/* Multi-valued types */
	case PT_MV_SHORT:
	case PT_MV_LONG:
	case PT_MV_FLOAT:
	case PT_MV_APPTIME:
	case PT_MV_DOUBLE:
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
	case PT_MV_I8:
	case PT_MV_CLSID:
	case PT_MV_BINARY:
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		printf("recognized but unimpl %x\n", proptag);
		ep.advance(8);
		break;
	default:
		throw YError(fmt::format("PO-1015: Unsupported proptype {:x}", proptag));
	}
	return 0;
}

static errno_t parse_propstrm(EXT_PULL &ep, TPROPVAL_ARRAY &proplist)
{
	while (parse_propstrmentry(ep, proplist) > 0)
		;
}

static errno_t do_message(libolecf_item_t *dir, MESSAGE_CONTENT *mc)
{
	/* MS-OXMSG v §2.4 */
	auto propstrm = slurp_stream(dir, "__properties_version1.0");
	EXT_PULL ep;
	ep.init(propstrm.data(), propstrm.size(), malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	if (ep.advance(16) != EXT_ERR_SUCCESS)
		return EIO;
	uint32_t recip_count = 0, atx_count = 0;
	if (ep.g_uint32(&recip_count) != EXT_ERR_SUCCESS)
		return EIO;
	if (ep.g_uint32(&atx_count) != EXT_ERR_SUCCESS)
		return EIO;
	if (ep.advance(8) != EXT_ERR_SUCCESS)
		return EIO;
	return parse_propstrm(ep, mc->proplist);
}

static errno_t do_file(const char *filename) try
{
	oxm_error_ptr err;
	oxm_file_ptr file;
	if (libolecf_file_initialize(&unique_tie(file), &unique_tie(err)) < 1) {
		fprintf(stderr, "%s\n", az_error("PO-1004", err).what());
		return EIO;
	}
	fprintf(stderr, "oxm2mt: Reading %s...\n", filename);
	errno = 0;
	if (libolecf_file_open(file.get(), filename,
	    LIBOLECF_OPEN_READ, &unique_tie(err)) < 1) {
		if (errno != 0)
			fprintf(stderr, "cfb: Could not open \"%s\": %s\n",
			        filename, strerror(errno));
		else
			fprintf(stderr, "cfb: \"%s\" not recognized as CFBF (CDFV2)\n", filename);
		return ECANCELED;
	}
	oxm_item_ptr root;
	if (libolecf_file_get_root_item(file.get(), &unique_tie(root),
	    &~unique_tie(err)) < 1)
		throw az_error("PO-1001", err);
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> gx_msg(message_content_init());
	if (gx_msg == nullptr)
		throw std::bad_alloc();
	auto ret = do_message(root.get(), gx_msg.get());
	return ret;
} catch (const char *e) {
	fprintf(stderr, "pff: Exception: %s\n", e);
	return ECANCELED;
} catch (const std::string &e) {
	fprintf(stderr, "pff: Exception: %s\n", e.c_str());
	return ECANCELED;
} catch (const std::exception &e) {
	fprintf(stderr, "pff: Exception: %s\n", e.what());
	return ECANCELED;
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-oxm2mt input.msg | gromox-mt2.... \n");
	fprintf(stderr, "Option overview: gromox-oxm2mt -?\n");
	fprintf(stderr, "Documentation: man gromox-oxm2mt\n");
}

int main(int argc, const char **argv)
{
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argc < 2) {
		terse_help();
		return EXIT_FAILURE;
	}
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	auto ret = do_file(argv[1]);
	if (ret != 0) {
		fprintf(stderr, "oxm2mt: Import unsuccessful.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
