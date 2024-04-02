// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <gromox/usercvt.hpp>

using namespace gromox;

int main()
{
	const char org[] = "Gromox default";
	for (const auto &u : {"horio@a4.inai.de", "public.folder.root@a4.inai.de"}) {
		std::string essdn, serverdn, mdbdn, mbid;
		unsigned int uid = 0xaa17, did = 0xdd33;
		auto err = cvt_username_to_essdn(u, org, uid, did, essdn);
		if (err != ecSuccess)
			return EXIT_FAILURE;
		err = cvt_username_to_serverdn(u, org, uid, serverdn);
		if (err != ecSuccess)
			return EXIT_FAILURE;
		err = cvt_username_to_mdbdn(u, org, uid, mdbdn);
		if (err != ecSuccess)
			return EXIT_FAILURE;
		err = cvt_username_to_mailboxid(u, strncmp(u, "public.folder.root@", 19) == 0 ? 0 : uid, mbid);
		if (err != ecSuccess)
			return EXIT_FAILURE;
		printf("* SPN:       %s\n* MailboxId: %s\n* ESSDN:     %s\n* Server:    %s\n* MdbDN:     %s\n",
			u, mbid.c_str(), essdn.c_str(), serverdn.c_str(), mdbdn.c_str());
	}
}
