#ifndef _H_MESSAGE_
#define _H_MESSAGE_

#define MESSAGE_BUFF_SIZE		64*1024

enum {
	MESSAGE_SMTP_BASE = -1, /* for SMTP alarm message type */
	MESSAGE_SMTP_CANNOT_CONNECT,
	MESSAGE_SMTP_CONNECT_ERROR,
	MESSAGE_SMTP_TIME_OUT,
	MESSAGE_SMTP_TEMP_ERROR,
	MESSAGE_SMTP_UNKOWN_RESPONSE,
	MESSAGE_SMTP_PERMANENT_ERROR,
	MESSAGE_SMTP_AUTH_FAIL,
	MESSAGE_ALARM_QUEUE,
	MESSAGE_POP3_BASE = MESSAGE_ALARM_QUEUE, /* for POP3 alarm message type */
	MESSAGE_POP3_CANNOT_CONNECT,
	MESSAGE_POP3_CONNECT_ERROR,
	MESSAGE_POP3_TIME_OUT,
	MESSAGE_POP3_RESPONSE_ERROR,
	MESSAGE_POP3_UPDATE_FAIL,
	MESSAGE_POP3_AUTH_FAIL,
	MESSAGE_POP3_RETRIEVE_NONE
};

enum {
	MESSAGE_SUPERVISING_SMTP,
	MESSAGE_SUPERVISING_POP3
};

void message_init();

int message_run();

int message_stop();

void message_free();

void message_supervising(char *buff, int message_type, int id);

void message_alarm_message(char *buff, int type, const char *command,
	const char *response, const char *ip, int port, const char *to);

#endif
