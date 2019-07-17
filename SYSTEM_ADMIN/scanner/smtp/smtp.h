#ifndef _H_SMTP_
#define _H_SMTP_

void smtp_init();

int smtp_run();

int smtp_stop();

void smtp_free();

void smtp_send_message(const char *from, const char *rcpt, const char *message);

#endif
