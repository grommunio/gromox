#pragma once
#include <gromox/hook_common.h>

#define RESPONSE_CONNECT_ACCEPT     1

#define RESPONSE_CONNECT_REJECT     2

#define RESPONSE_PING_OK            3

#define RESPONSE_RECV_READY         4

#define RESPONSE_RECV_ERROR         5

#define RESPONSE_RECV_OK            6

#define COMMAND_CONNECT_CLOSE       1

#define COMMAND_CONNECT_PING        2

#define COMMAND_SEND_BUFFER         3

#define SCAN_INTERVAL               30

#define PING_INTERVAL               180

#define SOCKET_TIMEOUT              180

#define MAX_INTERVAL                360

#define BUFFER_SIZE                 64*1024

#define RELAY_TAG                   "X-Relay-From"

#define DEF_MODE             S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


enum {
	RELAY_SWITCH,
	CHANNEL_NUM
};

void relay_agent_init(const char *list_path, const char *save_path,
	int channel_num, BOOL relay_switch);
extern int relay_agent_run(void);
extern int relay_agent_stop(void);
extern void relay_agent_free(void);
BOOL relay_agent_process(MESSAGE_CONTEXT *pcontext);
extern BOOL relay_agent_refresh_table(void);
int relay_agent_get_param(int param);

void relay_agent_set_param(int param, int value);
