#pragma once

#ifdef __cplusplus
extern "C" {
#endif

extern BOOL ldap_adaptor_login_exch(const char *username, const char *password, char *maildir, char *lang, char *reason, int length);
extern BOOL ldap_adaptor_login_pop3(const char *username, const char *password, char *maildir, char *lang, char *reason, int length);
extern BOOL ldap_adaptor_login_smtp(const char *username, const char *password, char *reason, int length);

#ifdef __cplusplus
} /* extern "C" */
#endif
