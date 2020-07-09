#include "mail_func.h"
#include <gromox/hook_common.h>
#include "spam_complain.h"
#include <stdio.h>

void spam_complain_init()
{
	/* do nothing */
}

int spam_complain_run()
{
	return 0;
}

int spam_complain_stop()
{
	return 0;
}

void spam_complain_free()
{
	/* do nothing */
}

BOOL spam_complain_process(MESSAGE_CONTEXT *pcontext)
{
	char date_buf[128];
	char rcpt_to[256];
	time_t cur_time;
	struct tm time_buff;
	MIME *pmime;
	MESSAGE_CONTEXT *pbounce_context;
	

	mem_file_readline(&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256);
	if (0 != strncasecmp(rcpt_to, "spam-complain@", 14)) {
		return FALSE;
	}
	pbounce_context = get_context();
	if (NULL == pbounce_context) {
		return TRUE;
	}
	sprintf(pbounce_context->pcontrol->from, "spam-complain@%s",
		get_default_domain());
	mem_file_writeline(&pbounce_context->pcontrol->f_rcpt_to,
		(char*)get_admin_mailbox());
	pbounce_context->pcontrol->need_bounce = FALSE;
	pmime = mail_add_head(pbounce_context->pmail);
	if (NULL == pmime) {
		put_context(pbounce_context);
		return FALSE;
	}
	mime_set_content_type(pmime, "message/rfc822");
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
		"(unknown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", pbounce_context->pcontrol->from);
	mime_set_field(pmime, "To", get_admin_mailbox());
	mime_set_field(pmime, "Subject", "SPAM COMPLAIN MAIL");
	time(&cur_time);
	strftime(date_buf, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Date", date_buf);
	mime_write_mail(pmime, pcontext->pmail);
	throw_context(pbounce_context);
	return TRUE;
}


