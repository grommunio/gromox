#pragma once
#include <string>

/**
 * %EXCH:	can login via emsmdb or zcore
 * %IMAP:	can login via IMAP
 * %SMTP:	can login via pam_gromox
 * %CHGPASSWD:	user is allowed to change their own password via zcore
 * %PUBADDR:	(unused)
 */
enum {
	USER_PRIVILEGE_EXCH = 0,
	USER_PRIVILEGE_IMAP = 1U << 0,
	USER_PRIVILEGE_POP3 = USER_PRIVILEGE_IMAP,
	USER_PRIVILEGE_SMTP = 1U << 1,
	USER_PRIVILEGE_CHGPASSWD = 1U << 2,
	USER_PRIVILEGE_PUBADDR = 1U << 3,
};

using authmgr_login_t = bool (*)(const char *username, const char *password, char *maildir, char *lang, char *reason, size_t rsnrsize, unsigned int privbits);
