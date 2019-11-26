#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <gromox/as_common.h>
#include "config_file.h"
#include "util.h"
#include <stdio.h>

#define SPAM_STATISTIC_PROPERTY_010		39

typedef void (*SPAM_STATISTIC)(int);
typedef BOOL (*CHECK_TAGGING)(const char*, MEM_FILE*);

static int boundary_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection, char *reason, int length);

DECLARE_API;

static SPAM_STATISTIC spam_statistic;
static CHECK_TAGGING check_tagging;

static char g_return_string[1024];

int AS_LibMain(int reason, void **ppdata)
{
	CONFIG_FILE *pconfig_file;
	char file_name[256], temp_path[256];
	char *str_value, *psearch;

    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		check_tagging = (CHECK_TAGGING)query_service("check_tagging");
		if (NULL == check_tagging) {
			printf("[property_010]: fail to get \"check_tagging\" service\n");
			return FALSE;
		}
		spam_statistic = (SPAM_STATISTIC)query_service("spam_statistic");
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig_file = config_file_init2(NULL, temp_path);
		if (NULL == pconfig_file) {
			printf("[property_010]: config_file_init %s: %s\n", temp_path, strerror(errno));
			return FALSE;
		}
		str_value = config_file_get_value(pconfig_file, "RETURN_STRING");
		if (NULL == str_value) {
			strcpy(g_return_string, "000039 you are now sending spam mail!");
		} else {
			strcpy(g_return_string, str_value);
		}
		printf("[property_010]: return string is \"%s\"\n", g_return_string);
		config_file_free(pconfig_file);

        /* invoke register_auditor for registering auditor of mime head */
        if (FALSE == register_auditor(boundary_filter)) {
			printf("[property_010]: fail to register auditor function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
        return TRUE;
    }
    return TRUE;
}

static int boundary_filter(int context_ID, MAIL_ENTITY *pmail,
	CONNECTION *pconnection,  char *reason, int length)
{
    char buf[1024], *ptr, *pbackup;
    int  out_len, i, offset;

	if (TRUE == pmail->penvelop->is_relay) {
		return MESSAGE_ACCEPT;
	}
    out_len = mem_file_read(&pmail->phead->f_content_type, buf, 1024);
    if (MEM_END_OF_FILE == out_len) {   /* no content type */
        return MESSAGE_ACCEPT;
    }
	buf[out_len] = '\0';
    if (NULL == (ptr = search_string(buf, "boundary", out_len))) {
        return MESSAGE_ACCEPT;
    }
    ptr += 8;
    if (NULL == (ptr = strchr(ptr, '"'))) {
        return MESSAGE_ACCEPT;
    }
    ptr++;
    pbackup = ptr;
    if (NULL == (ptr = strchr(ptr, '"'))) {
        return MESSAGE_ACCEPT;
    }
    out_len = (int)(ptr - pbackup);
	if (32 <= out_len && out_len <= 36) {
		/* ----=lqwb422_8956_352128715.061652 */
		if (0 != strncmp("----=", pbackup, 5)) {
			return MESSAGE_ACCEPT;
		}
		for (i=5; i<13; i++) {
			if (HX_isalpha(pbackup[i]))
				continue;
			else if (HX_isdigit(pbackup[i]))
				break;
			else
				return MESSAGE_ACCEPT;
		}
		if (i < 8 || i > 11) {
			return MESSAGE_ACCEPT;
		}
		offset = i;
		if ('_' != pbackup[offset + 3] || '_' != pbackup[offset + 8] ||
			('.' != pbackup[offset + 17] && '.' != pbackup[offset + 18])) {
			return MESSAGE_ACCEPT;
		}
		for (i=0; i<3; i++) {
			if (!HX_isdigit(pbackup[offset+i]))
				return MESSAGE_ACCEPT;
		}
		for (i=4; i<8; i++) {
			if (!HX_isdigit(pbackup[offset+i]))
				return MESSAGE_ACCEPT;
		}
		for (i=9; i<17; i++) {
			if (!HX_isdigit(pbackup[offset+i]))
				return MESSAGE_ACCEPT;
		}
		for (i=19; i<24; i++) {
			if (!HX_isdigit(pbackup[offset+i]))
				return MESSAGE_ACCEPT;
		}
		if (TRUE == check_tagging(pmail->penvelop->from,
			&pmail->penvelop->f_rcpt_to)) {
			mark_context_spam(context_ID);
			return MESSAGE_ACCEPT;
		} else {
			strncpy(reason, g_return_string, length);
			if (NULL != spam_statistic) {
				spam_statistic(SPAM_STATISTIC_PROPERTY_010);
			}
			return MESSAGE_REJECT;
		}
	}
	return MESSAGE_ACCEPT;
}

