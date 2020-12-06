#include <cstdint>
#include <memory>
#include <gromox/mapidefs.h>
#include <gromox/scope.hpp>
#include <gromox/tie.hpp>
#include "common_util.h"
#include "exmdb_server.h"
#include "html.h"
#include "mail_func.h"
#include "rtf.h"
#include "rtfcp.h"
#include "tpropval_array.h"

using namespace gromox;

struct instbody_free {
	void operator()(void *x) { free(x); }
	void operator()(BINARY *x) {
		if (x == nullptr)
			return;
		free(x->pv);
		free(x);
	}
};

static constexpr size_t UTF8LEN_MARKER_SIZE = sizeof(uint32_t);

/* Get an arbitrary body, no fallbacks. */
static int instance_get_raw(MESSAGE_CONTENT *mc, BINARY *&bin, unsigned int tag)
{
	auto data = tpropval_array_get_propval(&mc->proplist, tag);
	if (data == nullptr)
		return 0;
	uint32_t length = 0;
	auto content = instance_read_cid_content(*static_cast<uint64_t *>(data), &length);
	if (content == nullptr)
		return -1;
	bin = static_cast<BINARY *>(common_util_alloc(sizeof(BINARY)));
	if (bin == nullptr)
		return -1;
	bin->cb = length;
	bin->pv = content;
	return 1;
}

/* Get uncompressed RTF body, no fallbacks. */
static int instance_get_rtf(MESSAGE_CONTENT *mc, BINARY *&bin)
{
	auto ret = instance_get_raw(mc, bin, ID_TAG_RTFCOMPRESSED);
	if (ret <= 0)
		return ret;
	BINARY rtf_comp = *bin;
	ssize_t unc_size = rtfcp_uncompressed_size(&rtf_comp);
	if (unc_size < 0)
		return -1;
	bin->pv = common_util_alloc(unc_size);
	if (bin->pv == nullptr)
		return -1;
	size_t unc_size2 = unc_size;
	if (!rtfcp_uncompress(&rtf_comp, bin->pc, &unc_size2))
		return -1;
	bin->cb = unc_size2;
	return 1;
}

static int instance_conv_htmlfromhigher(MESSAGE_CONTENT *mc, BINARY *&bin)
{
	auto ret = instance_get_rtf(mc, bin);
	if (ret <= 0)
		return ret;
	std::unique_ptr<char, instbody_free> outbuf;
	size_t outlen = 0;
	auto at = attachment_list_init();
	auto at_clean = make_scope_exit([&]() { attachment_list_free(at); });
	if (!rtf_to_html(bin->pc, bin->cb, "utf-8", &unique_tie(outbuf), &outlen, at))
		return -1;
	bin->cb = outlen;
	bin->pv = common_util_alloc(outlen);
	if (bin->pv == nullptr)
		return -1;
	memcpy(bin->pv, outbuf.get(), outlen);
	return 1;
}

static int instance_conv_textfromhigher(MESSAGE_CONTENT *mc, BINARY *&bin)
{
	auto ret = instance_get_raw(mc, bin, ID_TAG_HTML);
	if (ret == 0)
		ret = instance_conv_htmlfromhigher(mc, bin);
	if (ret <= 0)
		return ret;
	std::unique_ptr<char, instbody_free> outbuf;
	ret = html_to_plain(bin->pc, bin->cb, &unique_tie(outbuf));
	if (ret <= 0)
		return 0;
	bin->pv = common_util_alloc(strlen(outbuf.get()) + 1);
	if (bin->pv == nullptr)
		return -1;
	memcpy(bin->pv, outbuf.get(), strlen(outbuf.get()) + 1);
	return 1;
}

static int instance_conv_htmlfromlower(MESSAGE_CONTENT *mc,
    unsigned int cpid, BINARY *&bin)
{
	auto ret = instance_get_raw(mc, bin, ID_TAG_BODY);
	if (ret > 0)
		bin->pc += UTF8LEN_MARKER_SIZE;
	if (ret == 0) {
		ret = instance_get_raw(mc, bin, ID_TAG_BODY_STRING8);
		if (ret > 0) {
			bin->pc = common_util_convert_copy(true, cpid, bin->pc);
			if (bin->pc == nullptr)
				return -1;
		}
	}
	if (ret <= 0)
		return ret;
	std::unique_ptr<char, instbody_free> htmlout(plain_to_html(bin->pc));
	if (htmlout == nullptr)
		return -1;
	bin->cb = strlen(htmlout.get());
	bin->pv = common_util_alloc(bin->cb + 1);
	if (bin->pv == nullptr)
		return -1;
	memcpy(bin->pv, htmlout.get(), bin->cb + 1);
	return 1;
}

static int instance_conv_rtfcpfromlower(MESSAGE_CONTENT *mc, unsigned int cpid, BINARY *&bin)
{
	auto ret = instance_conv_htmlfromlower(mc, cpid, bin);
	if (ret <= 0)
		return ret;
	std::unique_ptr<char, instbody_free> rtfout;
	size_t rtflen = 0;
	if (!html_to_rtf(bin->pc, bin->cb, cpid, &unique_tie(rtfout), &rtflen))
		return -1;
	std::unique_ptr<BINARY, instbody_free> rtfcpbin(rtfcp_compress(rtfout.get(), rtflen));
	if (rtfcpbin == nullptr)
		return -1;
	bin->cb = rtfcpbin->cb;
	bin->pv = common_util_alloc(rtfcpbin->cb);
	if (bin->pv == nullptr)
		return -1;
	memcpy(bin->pv, rtfcpbin->pv, rtfcpbin->cb);
	return 1;
}

/* Get any plaintext body, fallback to autogeneration. */
static int instance_get_body_unspec(MESSAGE_CONTENT *mc, TPROPVAL_ARRAY *pval)
{
	BINARY *bin = nullptr;
	auto ret = instance_get_raw(mc, bin, ID_TAG_BODY);
	auto unicode_body = ret > 0;
	if (ret > 0)
		bin->pc += UTF8LEN_MARKER_SIZE;
	else if (ret == 0)
		ret = instance_get_raw(mc, bin, ID_TAG_BODY_STRING8);
	if (ret == 0) {
		ret = instance_conv_textfromhigher(mc, bin);
		if (ret > 0)
			unicode_body = true;
	}
	if (ret <= 0)
		return ret;

	/* Strictly required to respond with the same proptag as was requested */
	auto tpv = static_cast<TYPED_PROPVAL *>(common_util_alloc(sizeof(TYPED_PROPVAL)));
	if (tpv == nullptr)
		return -1;
	tpv->type   = unicode_body ? PT_UNICODE : PT_STRING8;
	tpv->pvalue = bin->pv;
	auto &pv    = pval->ppropval[pval->count];
	pv.proptag  = CHANGE_PROP_TYPE(PR_BODY, PT_UNSPECIFIED);
	pv.pvalue   = tpv;
	++pval->count;
	return 1;
}

/* Get UTF plaintext body, fallback to autogeneration. */
static int instance_get_body_utf8(MESSAGE_CONTENT *mc, unsigned int cpid,
    TPROPVAL_ARRAY *pval)
{
	BINARY *bin = nullptr;
	int ret = instance_get_raw(mc, bin, ID_TAG_BODY);
	if (ret > 0)
		bin->pc += UTF8LEN_MARKER_SIZE;
	if (ret == 0) {
		ret = instance_get_raw(mc, bin, ID_TAG_BODY_STRING8);
		if (ret > 0) {
			bin->pc = common_util_convert_copy(true, cpid, bin->pc);
			if (bin->pc == nullptr)
				return -1;
		}
	}
	if (ret == 0)
		ret = instance_conv_textfromhigher(mc, bin);
	if (ret <= 0)
		return ret;

	auto &pv   = pval->ppropval[pval->count];
	pv.proptag = PROP_TAG_BODY;
	pv.pvalue  = bin->pc;
	++pval->count;
	return 1;
}

/* Get 8-bit plaintext body, fallback to autogeneration. */
static int instance_get_body_8bit(MESSAGE_CONTENT *mc, unsigned int cpid,
    TPROPVAL_ARRAY *pval)
{
	BINARY *bin = nullptr;
	auto ret = instance_get_raw(mc, bin, ID_TAG_BODY_STRING8);
	if (ret == 0) {
		ret = instance_get_raw(mc, bin, ID_TAG_BODY);
		if (ret > 0) {
			bin->pc = common_util_convert_copy(false, cpid, bin->pc + UTF8LEN_MARKER_SIZE);
			if (bin->pc == nullptr)
				return -1;
		}
	}
	if (ret == 0) {
		ret = instance_conv_textfromhigher(mc, bin);
		if (ret > 0) {
			bin->pc = common_util_convert_copy(false, cpid, bin->pc);
			if (bin->pc == nullptr)
				return -1;
		}
	}
	if (ret <= 0)
		return ret;

	auto &pv   = pval->ppropval[pval->count];
	pv.proptag = PROP_TAG_BODY_STRING8;
	pv.pvalue  = bin->pc;
	++pval->count;
	return 1;
}

static int instance_get_html(MESSAGE_CONTENT *mc, unsigned int cpid,
    TPROPVAL_ARRAY *pval)
{
	BINARY *bin = nullptr;
	auto ret = instance_get_raw(mc, bin, ID_TAG_HTML);
	if (ret == 0)
		ret = instance_conv_htmlfromhigher(mc, bin);
	if (ret == 0)
		ret = instance_conv_htmlfromlower(mc, cpid, bin);
	if (ret <= 0)
		return ret;
	auto &pv   = pval->ppropval[pval->count];
	pv.proptag = PR_HTML;
	pv.pvalue  = bin;
	++pval->count;
	return 1;
}

static int instance_get_html_unspec(MESSAGE_CONTENT *mc, unsigned int cpid,
    TPROPVAL_ARRAY *pval)
{
	auto ret = instance_get_html(mc, cpid, pval);
	if (ret <= 0)
		return ret;
	auto tpv = static_cast<TYPED_PROPVAL *>(common_util_alloc(sizeof(TYPED_PROPVAL)));
	if (tpv == nullptr)
		return -1;
	auto &pv = pval->ppropval[pval->count];
	tpv->type   = PT_BINARY;
	tpv->pvalue = pv.pvalue;
	pv.proptag  = CHANGE_PROP_TYPE(PR_HTML, PT_UNSPECIFIED);
	pv.pvalue   = tpv;
	return 1;
}

/* Get RTFCP, fallback to autogeneration. */
static int instance_get_rtfcp(MESSAGE_CONTENT *mc, unsigned int cpid,
    TPROPVAL_ARRAY *pval)
{
	BINARY *bin = nullptr;
	auto ret = instance_get_raw(mc, bin, ID_TAG_RTFCOMPRESSED);
	if (ret == 0)
		ret = instance_conv_rtfcpfromlower(mc, cpid, bin);
	if (ret <= 0)
		return ret;
	auto &pv   = pval->ppropval[pval->count];
	pv.proptag = PR_RTF_COMPRESSED;
	pv.pvalue  = bin;
	++pval->count;
	return 1;
}

int instance_get_message_body(MESSAGE_CONTENT *mc, unsigned int tag, unsigned int cpid,
    TPROPVAL_ARRAY *pv)
{
	switch (tag) {
	case PR_BODY_A:
		return instance_get_body_8bit(mc, cpid, pv);
	case PR_BODY_W:
		return instance_get_body_utf8(mc, cpid, pv);
	case CHANGE_PROP_TYPE(PR_BODY, PT_UNSPECIFIED):
		return instance_get_body_unspec(mc, pv);
	case PR_HTML:
		return instance_get_html(mc, cpid, pv);
	case CHANGE_PROP_TYPE(PR_HTML, PT_UNSPECIFIED):
		return instance_get_html_unspec(mc, cpid, pv);
	case PR_RTF_COMPRESSED:
		return instance_get_rtfcp(mc, cpid, pv);
	}
	return -1;
}
