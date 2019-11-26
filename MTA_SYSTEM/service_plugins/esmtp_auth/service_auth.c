#include "service_auth.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SERVICE_AUTH_ERROR      0   /* auth session fail  */
#define SERVICE_AUTH_CONTINUE   1   /* auth session processed OK, continue */
#define SERVICE_AUTH_FINISH     2   /* auth session processed OK, finished */

enum{
	T_AUTH_NONE = 0,
	T_LOGIN_USER,
	T_LOGIN_PASS,
	T_PLAIN_ONE,
	T_PLAIN_TWO
};

typedef struct _AUTH_INFO{
	int state;
	BOOL b_username;
	char username[256];
	char password[256];
} AUTH_INFO;

static BOOL service_auth_parse_plain(char* buf, int buf_len,
	char* user, char* pass);

static VERIFY_USER_PASS service_auth_verify_user_pass;

static AUTH_INFO *g_context_list;
static int g_context_num;

/*
 *  service auth's construction function
 *	@param
 *		context_num			context number of system
 *		verify_user_pass	callback function fot verifing username 
 *                      	and password
 */
void service_auth_init(int context_num, VERIFY_USER_PASS verify_user_pass)
{
	service_auth_verify_user_pass = verify_user_pass;
	g_context_num = context_num;
}

/*
 *	run the service auth module
 *	@return
 *		0			OK
 *		<>0			FAIL
 */
int service_auth_run()
{
	g_context_list = (AUTH_INFO*)malloc(sizeof(AUTH_INFO)*g_context_num);
	if (NULL == g_context_list) {
		return -1;
	}
	memset(g_context_list, 0, sizeof(AUTH_INFO)*g_context_num);
	return 0;
}

/*
 *	stop the service auth module
 *	@return
 *		0			OK
 *		<>0			FAIL
 */
int service_auth_stop()
{
	if (NULL != g_context_list) {
		free(g_context_list);
		g_context_list = NULL;
	}
	return 0;
}

/*
 *	service auth's destruction function
 */
void service_auth_free()
{
	/* do nothing */

}

/*
 *	implementation of "auth_ehlo"
 *	@return
 *		string of auth types
 */
const char* service_auth_ehlo()
{
	return "LOGIN PLAIN";

}

/*
 *	implementation of auth_process
 *	@param
 *		context_ID				context ID
 *		cmd_line [in]			string line passed from client
 *		line_len				length of cmd_line
 *		reply_string [out]		buffer for passing out result
 *		reply_len				length of reply_string 
 *	@return
 *		SERVICE_AUTH_ERROR		error
 *		SERVICE_AUTH_CONTINUE	continue the auth steps
 *		SERVICE_AUTH_FINISH		auth OK, finished
 */
int service_auth_process(int context_ID, const char *cmd_line, int line_len,
    char *reply_string, int reply_len)
{
	AUTH_INFO *pauth_info;
	size_t string_length;
	char reason[1024];
	char buff[1024];

	pauth_info = g_context_list + context_ID;
	if (0 == strncasecmp(cmd_line + 5, "LOGIN", 5)) {
		if (T_AUTH_NONE != pauth_info->state) {
			strncpy(reply_string, "503 Bad sequence of commands", reply_len);
			pauth_info->state      = T_AUTH_NONE;
			pauth_info->b_username = FALSE;
			return SERVICE_AUTH_ERROR;
		}

		/*
		 *	C: auth login XXX
		 *	S: 334 UGFzc3dvcmQ6
         *	S: 235 Authentication ok, go ahead
         */
		if (line_len > 11 && ' ' == cmd_line[10]) {
			if (0 != decode64_ex(cmd_line + 11, line_len - 11,
				pauth_info->username, 256, &string_length)) {
            	strncpy(reply_string, "554 Username is not base64 encoding",
                	reply_len);
            	pauth_info->state = T_AUTH_NONE;
				pauth_info->b_username = FALSE;
            	return SERVICE_AUTH_ERROR;
        	}
        	pauth_info->b_username = TRUE;
        	pauth_info->state      = T_LOGIN_PASS;
        	/* send base64 encoded "password" */
        	strncpy(reply_string, "334 UGFzc3dvcmQ6", reply_len);
        	return SERVICE_AUTH_CONTINUE;
		}

		/*
		 *	C: auth login
		 *	S: 334 VXNlcm5hbWU6
		 *	C: XXX
         *	S: 334 UGFzc3dvcmQ6
         *	C: XXX
         *	S: 235 Authentication ok, go ahead
         */
        /* send base64 encoded "username" */
		if (10 == line_len) {
			strncpy(reply_string, "334 VXNlcm5hbWU6", reply_len);
			pauth_info->state = T_LOGIN_USER;
			return SERVICE_AUTH_CONTINUE;
		}
		strncpy(reply_string, "501 Syntax error in parameters or arguments",
			reply_len);
		pauth_info->state = T_AUTH_NONE;
		pauth_info->b_username = FALSE;
        return SERVICE_AUTH_ERROR;
	}
	if (0 == strncasecmp(cmd_line + 5, "PLAIN", 5)) {
		if (T_AUTH_NONE != pauth_info->state) {
            strncpy(reply_string, "503 Bad sequence of commands", reply_len);
            pauth_info->state      = T_AUTH_NONE;
            pauth_info->b_username = FALSE;
            return SERVICE_AUTH_ERROR;
        }

        /*
         *  C: auth plain XXX
         *  S: 235 Authentication ok, go ahead
         */
        if (line_len > 11 && ' ' == cmd_line[10]) {
        	if (0 != decode64_ex(cmd_line + 11, line_len - 11, buff, 256,
				&string_length)) {
				strncpy(reply_string, "554 Auth plain string must be "
					"base64 encoding", reply_len);
            	pauth_info->state = T_AUTH_NONE;
            	pauth_info->b_username = FALSE;
            	return SERVICE_AUTH_ERROR;
			}
			if (FALSE == service_auth_parse_plain(buff, string_length,
            	pauth_info->username, pauth_info->password)) {
           		strncpy(reply_string, "554 Unrecognized auth plain string",
                    reply_len);
                pauth_info->state = T_AUTH_NONE;
                pauth_info->b_username = FALSE;
                return SERVICE_AUTH_ERROR;
        	}
			if (FALSE == service_auth_verify_user_pass(pauth_info->username,
            	pauth_info->password, reason, sizeof(reason) - 1)) {
            	reason[sizeof(reason) - 1] = '\0';
            	snprintf(reply_string, reply_len, "554 Temporary authentication "
                	"failure, because %s", reason);
            	return SERVICE_AUTH_ERROR;
        	}
			pauth_info->b_username = TRUE;
        	strncpy(reply_string, "235 Authentication ok, go ahead", reply_len);
        	return SERVICE_AUTH_FINISH;
        }
		/*
         *  C: auth plain
         *  S: 334 OK, go on
         *  S: 235 Authentication ok, go ahead
         */
		if (10 == line_len) {
            strncpy(reply_string, "334 OK, go on", reply_len);
            pauth_info->state = T_PLAIN_ONE;
            return SERVICE_AUTH_CONTINUE;
        }
        strncpy(reply_string, "501 Syntax error in parameters or arguments",
            reply_len);
        pauth_info->state = T_AUTH_NONE;
        pauth_info->b_username = FALSE;
        return SERVICE_AUTH_ERROR;
	}
	switch (pauth_info->state) {
	case T_LOGIN_USER:
		if (0 != decode64_ex(cmd_line, line_len, pauth_info->username, 256,
			&string_length)) {
			strncpy(reply_string, "554 Username is not base64 encoding",
				reply_len);
			pauth_info->state = T_AUTH_NONE;
			pauth_info->b_username = FALSE;
			return SERVICE_AUTH_ERROR;
		}
		pauth_info->b_username = TRUE;
		pauth_info->state      = T_LOGIN_PASS;
		/* send base64 encoded "password" */
        strncpy(reply_string, "334 UGFzc3dvcmQ6", reply_len);
		return SERVICE_AUTH_CONTINUE;
	case T_LOGIN_PASS:
		if (0 != decode64_ex(cmd_line, line_len, pauth_info->password, 256,
            &string_length)) {
            strncpy(reply_string, "554 Password is not base64 encoding",
				reply_len);
            pauth_info->state = T_AUTH_NONE;
            return SERVICE_AUTH_ERROR;
        }
		pauth_info->state = T_AUTH_NONE;
		if (FALSE == service_auth_verify_user_pass(pauth_info->username,
			pauth_info->password, reason, sizeof(reason) - 1)) {
			reason[sizeof(reason) - 1] = '\0';
			snprintf(reply_string, reply_len, "554 Temporary authentication "
				"failure, because %s", reason);
			return SERVICE_AUTH_ERROR;
		}
		strncpy(reply_string, "235 Authentication ok, go ahead", reply_len);
		return SERVICE_AUTH_FINISH;
	case T_PLAIN_ONE:
		if (0 != decode64_ex(cmd_line, line_len, buff, 256, &string_length)) {
			/* 
			 *	only for foxmail
			*	C: auth plain
		 	*	S: 334 OK, go on
		 	*	C: XXX
         	*	S: 334 OK, go on
         	*	C: XXX
         	*	S: 235 Authentication ok, go ahead
		 	* 
         	*/
			memcpy(pauth_info->username, cmd_line, line_len);
			pauth_info->username[line_len] = '\0';
			pauth_info->b_username = TRUE;
        	strncpy(reply_string, "334 OK, go on", reply_len);
            pauth_info->state = T_PLAIN_TWO;
            return SERVICE_AUTH_CONTINUE;
		}
		pauth_info->state = T_AUTH_NONE;
        if (FALSE == service_auth_parse_plain(buff, string_length,
        	pauth_info->username, pauth_info->password)) {
           	strncpy(reply_string, "554 Unrecognized auth plain string",
                reply_len);
            pauth_info->b_username = FALSE;
            return SERVICE_AUTH_ERROR;
        }
        if (FALSE == service_auth_verify_user_pass(pauth_info->username,
            pauth_info->password, reason, sizeof(reason) - 1)) {
            reason[sizeof(reason) - 1] = '\0';
            snprintf(reply_string, reply_len, "554 Temporary authentication "
                "failure, because %s", reason);
            return SERVICE_AUTH_ERROR;
        }
		pauth_info->b_username = TRUE;
        strncpy(reply_string, "235 Authentication ok, go ahead", reply_len);
        return SERVICE_AUTH_FINISH;
	case T_PLAIN_TWO:
        pauth_info->state = T_AUTH_NONE;
		memcpy(pauth_info->password, cmd_line, line_len);
		pauth_info->password[line_len] = '\0';
        if (FALSE == service_auth_verify_user_pass(pauth_info->username,
            pauth_info->password, reason, sizeof(reason) - 1)) {
            reason[sizeof(reason) - 1] = '\0';
            snprintf(reply_string, reply_len, "554 Temporary authentication "
                "failure, because %s", reason);
            return SERVICE_AUTH_ERROR;
        }
        strncpy(reply_string, "235 Authentication ok, go ahead", reply_len);
        return SERVICE_AUTH_FINISH;
	}
	
	strncpy(reply_string, "502 Command not implemented", reply_len);
	pauth_info->state      = T_AUTH_NONE;
	pauth_info->b_username = FALSE;
	return SERVICE_AUTH_ERROR;
}

/*
 *	implementation of auth_retrieve
 *	@param
 *		context_ID			context ID
 *		username [out]		buffer for retrieving username
 *		length				username buffer len
 *	@return
 *		TRUE				OK, has user name
 *		FALSE				NO, there's not user name
 */
BOOL service_auth_retrieve(int context_ID, char *username , int length)
{
	AUTH_INFO *pauth_info;
	
	pauth_info = g_context_list + context_ID;
	if (FALSE == pauth_info->b_username) {
		return FALSE;
	}
	strncpy(username, pauth_info->username, length);
	return TRUE;
}

void service_auth_clear(int context_ID)
{
	memset(g_context_list + context_ID, 0 , sizeof(AUTH_INFO));
}


static BOOL service_auth_parse_plain(char* buf, int buf_len,
	char* user, char* pass)
{
    char *ptr = NULL;
	char *pbackup = NULL;
    int len;

    ptr = strchr(buf, '\0');
	if (NULL == ptr) {
        return FALSE;
    }
    pbackup = ptr + 1;
    if (pbackup - buf >= buf_len) {
        return FALSE;
    }
    ptr = strchr(pbackup, '\0');
	if (NULL == ptr) {
        return FALSE;
    }
    len = ptr - pbackup;
    if (len >= 255) {
        return FALSE;
    }
    memcpy(user, pbackup, len);
    user[len] = '\0';
    ptr ++;
	len = (int)(ptr - buf);
    if (len >= buf_len) {
        return FALSE;
    }
    len = buf_len - len;
    if (len >= 255) {
        return FALSE;
    }
    memcpy(pass, ptr, len);
    pass[len] = '\0';
    return TRUE;
}
                   

