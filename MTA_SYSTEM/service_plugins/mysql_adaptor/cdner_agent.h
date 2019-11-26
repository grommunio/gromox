#ifndef _H_CDNER_AGENT_
#define _H_CDNER_AGENT_
#include "common_types.h"


enum {
	CDNER_TOTAL_CONNECTION,
	CDNER_ALIVE_CONNECTION
};

void cdner_agent_init(int conn_num, const char *host_ip, int host_port);
extern int cdner_agent_run(void);
extern int cdner_agent_stop(void);
extern void cdner_agent_free(void);
int cdner_agent_get_param(int param);

BOOL cdner_agent_check_user(const char *username);

BOOL cdner_agent_login(const char *username, const char *password);

void cdner_agent_create_user(const char *username);

#endif
