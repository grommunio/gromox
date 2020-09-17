#pragma once

enum {
	SMTP_SEND_OK = 0,
	SMTP_CANNOT_CONNECT,
	SMTP_CONNECT_ERROR,
	SMTP_TIME_OUT,
	SMTP_TEMP_ERROR,
	SMTP_UNKOWN_RESPONSE,
	SMTP_PERMANENT_ERROR,
	SMTP_AUTH_FAIL
};

int smtp_send_inbound(const char *ip, int port, const char *rcpt,
	const char *message, char *last_command, char *last_response);

int smtp_send_outbound(const char *ip, int port, const char *username,
	const char *password, const char *rcpt, const char *message,
	char *last_command, char *last_response);

void smtp_send_message(const char *from, const char *rcpt, const char *message);
