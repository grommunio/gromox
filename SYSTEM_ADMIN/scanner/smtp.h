#ifndef _H_SMTP_
#define _H_SMTP_

extern void smtp_init(void);
extern int smtp_run(void);
extern int smtp_stop(void);
extern void smtp_free(void);
void smtp_send_message(const char *from, const char *rcpt, const char *message);

#endif
