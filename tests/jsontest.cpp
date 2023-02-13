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

static void enx(MJSON_MIME *mi, void *q)
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

int main()
{
	alloc_limiter<MJSON_MIME> al(4096, "mjson");
	Json::Value json;
	if (!json_from_str(tdata1, json))
		return EXIT_FAILURE;
	MJSON m(&al);
	if (!m.load_from_json(json, "/tmp")) {
		fprintf(stderr, "retrieve failed\n");
		return EXIT_FAILURE;
	}
	m.enum_mime(enx, nullptr);
	if (t_digest() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
