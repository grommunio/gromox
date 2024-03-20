#pragma once
#include <cstdint>
#include <string>

/**
 * Services that a user is allowed to exercise:
 *
 * %IMAP:	  allow the use of IMAP & POP3
 * %CHGPASSWD:	  allow the user to change password on their own via zcore
 * %PUBADDR:	  (unused)
 * %SMTP, %CHAT, %VIDEO, %FILES, %ARCHIVE:
 *                allow user authentication via pam_gromox with service=...
 * %DETAIL1:      in the *absence* of this bit, privbits is treated as if
 *                (WEB|EAS|DAV) was set
 * %WEB:          allow the use of web MUA (not evaluated by gromox, but g-web)
 * %EAS:          allow the use of EAS (not evaluated by gromox, but g-sync)
 * %DAV:          allow the use of DAV (not evaluated by gromox, but g-dav)
 *
 * %WANTPRIV_BASIC:
 *                Mnemonic for source code when no particular privbit should be
 *                tested. (In essence allowing MAPI & EWS & PHP-MAPI implicitly
 *                at all times.)
 * %WANTPRIV_METAONLY:
 *                Extra flag for the mysql_adaptor_meta function (not present
 *                in the database); indicates that callers of meta() that only
 *                account metadata is desired, but no login checks on
 *                address_status or dtypx.
 */
enum {
	USER_PRIVILEGE_IMAP = 1U << 0,
	USER_PRIVILEGE_POP3 = USER_PRIVILEGE_IMAP,
	USER_PRIVILEGE_SMTP = 1U << 1,
	USER_PRIVILEGE_CHGPASSWD = 1U << 2,
	USER_PRIVILEGE_PUBADDR = 1U << 3,
	USER_PRIVILEGE_CHAT = 1U << 4,
	USER_PRIVILEGE_VIDEO = 1U << 5,
	USER_PRIVILEGE_FILES = 1U << 6,
	USER_PRIVILEGE_ARCHIVE = 1U << 7,
	USER_PRIVILEGE_DETAIL1 = 0x100U,
	USER_PRIVILEGE_WEB = 0x200U,
	USER_PRIVILEGE_EAS = 0x400U,
	USER_PRIVILEGE_DAV = 0x800U,

	WANTPRIV_BASIC = 0,
	WANTPRIV_METAONLY = 0x40000000U,
};

/**
 * Outputs from mysql_adaptor_meta
 * @username:	Primary, e-mail-address-based username
 * @maildir:	Mailbox location
 * @lang:	Preferred language for mailbox
 * @enc_passwd:	Encrypted password right from the SQL column,
 * 		used by authmgr to perform authentication.
 * @errstr:	Error message, if any. This is for the system log only,
 * 		it must not be sent to any peer.
 * @have_xid:	Whether an externid is set
 * 		(0=no / 1=yes / 0xFF=indeterminate)
 */
struct sql_meta_result {
	std::string username, maildir, lang, enc_passwd, errstr;
	std::string ldap_uri, ldap_binddn, ldap_bindpw, ldap_basedn;
	std::string ldap_mail_attr;
	bool ldap_start_tls = false;
	uint8_t have_xid = 0xFF;
	uint32_t privbits = 0;
};

using authmgr_login_t = bool (*)(const char *username, const char *password, unsigned int wantprivs, sql_meta_result &);
using authmgr_login_t2 = bool (*)(const char *token, unsigned int wantprivs, sql_meta_result &);
