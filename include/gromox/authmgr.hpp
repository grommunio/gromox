#pragma once
#include <string>

/**
 * %EXCH:	can login via emsmdb or zcore
 * %IMAP:	can login via IMAP & POP3
 * %CHGPASSWD:	user is allowed to change their own password via zcore
 * %PUBADDR:	(unused)
 * %SMTP, %CHAT, %VIDEO, %FILES, %ARCHIVE:
 * 		pam_gromox with service=...
 */
enum {
	USER_PRIVILEGE_EXCH = 0,
	USER_PRIVILEGE_IMAP = 1U << 0,
	USER_PRIVILEGE_POP3 = USER_PRIVILEGE_IMAP,
	USER_PRIVILEGE_SMTP = 1U << 1,
	USER_PRIVILEGE_CHGPASSWD = 1U << 2,
	USER_PRIVILEGE_PUBADDR = 1U << 3,
	USER_PRIVILEGE_CHAT = 1U << 4,
	USER_PRIVILEGE_VIDEO = 1U << 5,
	USER_PRIVILEGE_FILES = 1U << 6,
	USER_PRIVILEGE_ARCHIVE = 1U << 7,
};

using authmgr_login_t = bool (*)(const char *username, const char *password, char *maildir, size_t msize, char *lang, size_t lsize, char *reason, size_t rsnrsize, unsigned int privbits);
