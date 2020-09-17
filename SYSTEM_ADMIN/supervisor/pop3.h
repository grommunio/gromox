#pragma once

enum {
	POP3_RETRIEVE_OK,
	POP3_CANNOT_CONNECT,
	POP3_CONNECT_ERROR,
	POP3_TIME_OUT,
	POP3_RESPONSE_ERROR,
	POP3_UPDATE_FAIL,
	POP3_AUTH_FAIL,
	POP3_RETRIEVE_NONE
};

int pop3_retrieve_message(const char *ip, int port, const char *username,
	const char *password, int message_type, int check_id, char *last_command, 
	char *last_response);
