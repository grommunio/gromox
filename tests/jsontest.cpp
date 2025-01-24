// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstring>
#include <json/value.h>
#include <gromox/json.hpp>
#include <gromox/mjson.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static void enx(const MJSON_MIME *mi, void *q)
{
	printf("this=%p type=%u id=%s\n", mi,
	       static_cast<unsigned int>(mi->mime_type), mi->get_id());
}

static constexpr char tdata1[] =
	"{\"file\":\"\",\"uid\":0,\"recent\":1,\"read\":0,\"replied\":0,"
	"\"unsent\":0,\"forwarded\":0,\"flag\":0,\"priority\":3,"
	"\"msgid\":\"PDg0YzA3MWFiM2ViOWUyNDU4YTg0MDRhYjhjMzBlMDAxQGFrby1kZXYtMDEuZ3JhbW1tLmNvbT4=\","
	"\"from\":\"Ij0/dXRmLTg/Qj9VMmxuYldGeUlGTmphSExEdG1SbGNnPT0/PSIgPHRlc3QxQGdyYW1tbS5jb20+\","
	"\"to\":\"Ij0/dXRmLTg/Qj81cldjNWJTTzVhQ0E1YkMrSUVoaGJXRnpZV3RwSUVodmNtbHY/PSIgPHRlc3RAZ3JhbW1tLmNvbT4=\","
	"\"cc\":\"\",\"subject\":\"UQ==\","
	"\"received\":\"RnJpLCAxMCBTZXAgMjAyMSAxMjoxMzowMiArMDIwMA==\","
	"\"date\":\"RnJpLCAxMCBTZXAgMjAyMSAxMjoxMzowMiArMDIwMA==\","
	"\"charset\":\"utf-8\",\"structure\":[{\"id\":\"\",\"ctype\":\"multipart/alternative\",\"head\":0,\"begin\":783, \"length\":539}],"
	"\"mimes\":["
	"{\"id\":\"1\",\"ctype\":\"text/plain\",\"encoding\":\"base64\",\"head\":875,\"begin\":957,\"length\":6,\"charset\":\"utf-8\"},"
	"{\"id\":\"2\",\"ctype\":\"text/html\",\"encoding\":\"base64\",\"head\":1007,\"begin\":1088,\"length\":186,\"charset\":\"utf-8\"}],"
	"\"size\":1322}";

static constexpr char tdata2[] =
	"{\"charset\":\"UTF-8\",\"date\":\"\",\"file\":\"\",\"flag\":0,"
	"\"forwarded\":0,\"from\":\"\",\"inreply\":\"\",\"mimes\":["
	"{\"begin\":1564,\"charset\":\"UTF-8\",\"ctype\":\"text/plain\",\"encoding\":\"8bit\",\"head\":1473,\"id\":\"1\",\"length\":1647},"
	"{\"begin\":3452,\"charset\":\"UTF-8\",\"ctype\":\"text/html\",\"encoding\":\"8bit\",\"head\":3377,\"id\":\"2.1\",\"length\":5109},"
	"{\"begin\":8822,\"cid\":\"\",\"cntdspn\":\"inline\",\"ctype\":\"image/png\",\"encoding\":\"base64\",\"filename\":\"\",\"head\":8601,\"id\":\"2.2\",\"length\":112058},"
	"{\"begin\":121141,\"cid\":\"\",\"cntdspn\":\"inline\",\"ctype\":\"image/png\",\"encoding\":\"base64\",\"filename\":\"\",\"head\":120920,\"id\":\"2.3\",\"length\":99078},"
	"{\"begin\":220480,\"cid\":\"\",\"cntdspn\":\"inline\",\"ctype\":\"image/png\",\"encoding\":\"base64\",\"filename\":\"\",\"head\":220259,\"id\":\"2.4\",\"length\":130052},"
	"{\"begin\":350793,\"cid\":\"\",\"cntdspn\":\"inline\",\"ctype\":\"image/png\",\"encoding\":\"base64\",\"filename\":\"\",\"head\":350572,\"id\":\"2.5\",\"length\":136990}"
	"],\"msgid\":\"\",\"priority\":3,\"read\":0,\"received\":\"\","
	"\"recent\":1,\"ref\":\"\",\"replied\":0,\"size\":487869,\"structure\":["
	"{\"begin\":1387,\"ctype\":\"multipart/alternative\",\"head\":0,\"id\":\"\",\"length\":486482},"
	"{\"begin\":3337,\"ctype\":\"multipart/related\",\"head\":3251,\"id\":\"2\",\"length\":484490}"
	"],\"subject\":\"\","
	"\"to\":\"\",\"uid\":0,\"unsent\":0}";

static int t_digest()
{
	static char line[] = "{\"foo\": \"bar\", \"OH\": \"NO\", \"bar\": \"result\", \"xy\": 15}";
	char out[128];
	out[0] = '\0';
	if (!get_digest(line, "bar", out, std::size(out)))
		return EXIT_FAILURE;
	printf("digest test >%s<\n", out);
	if (strcmp(out, "result") != 0)
		printf("test failure\n");
	if (!get_digest(line, "xy", out, std::size(out)))
		return EXIT_FAILURE;
	printf("digest test >%s<\n", out);
	if (strcmp(out, "15") != 0)
		printf("test failure\n");

	if (!set_digest(line, std::size(line), "bar", "YA"))
		return EXIT_FAILURE;
	if (!get_digest(line, "bar", out, std::size(out)))
		return EXIT_FAILURE;
	printf("digest test >%s<\n", out);
	if (strcmp(out, "YA") != 0)
		printf("test failure\n");
	return EXIT_SUCCESS;
}

static int t_extparse(const char *s)
{
	Json::Value json;
	if (!json_from_str(s, json))
		return EXIT_FAILURE;
	MJSON m;
	if (!m.load_from_json(json)) {
		fprintf(stderr, "retrieve failed\n");
		return EXIT_FAILURE;
	}
	m.path = "/tmp";
	const_cast<const MJSON &>(m).enum_mime(enx, nullptr);
	return EXIT_SUCCESS;
}

int main()
{
	MJSON_MIME m1, m2;
	m1.mime_type = mime_type::single;
	m2 = std::move(m1);

	if (t_extparse(tdata1) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	if (t_extparse(tdata2) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	if (t_digest() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
