// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
/*
 * Minimal GSS auth helper loosely working similar to
 * `/usr/libexec/squid/negotiate_kerberos_auth -s GSS_C_NO_NAME`.
 * Use for testing with http.cfg:gss_program only.
 */
#include <string>
#include <unistd.h>
#include <gssapi/gssapi.h>
#include <libHX/string.h>
#include <gromox/util.hpp>

using namespace gromox;

int main(int argc, char **argv)
{
	gss_cred_id_t srv_creds{};
	gss_ctx_id_t ctx{};
	OM_uint32 status{};
	hxmc_t *line = nullptr;
	setvbuf(stdout, NULL, _IOLBF, 0);

	while (HX_getl(&line, stdin)) {
		HX_chomp(line);
		bool yr = line[0] == 'Y' && line[1] == 'R' && line[2] == ' ';
		bool kk = line[0] == 'K' && line[1] == 'K' && line[2] == ' ';
		if (yr) {
			auto ret = gss_acquire_cred(&status, nullptr,
			           GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
			           GSS_C_ACCEPT, &srv_creds, nullptr, nullptr);
			if (ret != GSS_S_COMPLETE) {
				fprintf(stderr, "BH gss_acquire_cred failed\n");
				continue;
			}
		}
		if (yr || kk) {
			auto vss = base64_decode(&line[3]);
			gss_buffer_desc input_buf{}, user_buf{}, output_token{};
			gss_name_t username{};
			input_buf.value  = vss.data();
			input_buf.length = vss.size();
			auto ret = gss_accept_sec_context(&status, &ctx, srv_creds,
			      &input_buf, GSS_C_NO_CHANNEL_BINDINGS, &username,
			      nullptr, &output_token, nullptr, nullptr,
			      nullptr);
			if (ret == GSS_S_CONTINUE_NEEDED) {
				std::string_view sv(static_cast<char *>(output_token.value), output_token.length);
				printf("TT %s\n", base64_encode(sv).c_str());
				continue;
			} else if (ret != 0) {
				fprintf(stderr, "BH gss_accept_sec_context failed\n");
				return 1;
			}
			ret = gss_display_name(&status, username, &user_buf, nullptr);
			if (ret != 0) {
				fprintf(stderr, "BH no username determined\n");
				continue;
			}
			std::string sv(static_cast<char *>(user_buf.value), user_buf.length);
			printf("AF = %s\n", sv.c_str());
			continue;
		}
		printf("BH what?\n");
	}
	return 0;
}
