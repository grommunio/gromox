#ifndef _H_ACL_CONTROL_
#include "common_types.h"

#define ACL_PRIVILEGE_IGNORE		-1
#define ACL_PRIVILEGE_SETUP			0
#define ACL_PRIVILEGE_ANTI_SPAM		1
#define ACL_PRIVILEGE_MISC			2
#define ACL_PRIVILEGE_STATUS		3


#define ACL_SESSION_ERROR			-1
#define ACL_SESSION_OK				0
#define ACL_SESSION_TIMEOUT			1
#define ACL_SESSION_PRIVILEGE		2

void acl_control_init(const char *token_path, const char *acl_path, int timeout);

int acl_control_run();

BOOL acl_control_auth(const char *usernmae, const char *password);

BOOL acl_control_produce(const char *username, const char *ip, char *session);

int acl_control_check(const char *session, const char *ip, int m_id);

BOOL acl_control_naming(const char *session, char *usernmae);

void acl_control_remove(const char *session);

int acl_control_stop();

void acl_control_free();


#endif
