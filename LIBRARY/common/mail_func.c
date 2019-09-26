/*
 *	  Addr_kids, for parse the email addr
 */
#include "common_types.h"
#include "mail_func.h"
#include "timezone.h"
#include "util.h"
#include <string.h>
#include <ctype.h>


enum {
	SW_USUAL = 0,
	SW_SLASH,
	SW_DOT,
	SW_DOT_DOT,
	SW_QUOTED,
	SW_QUOTED_SECOND
};

static uint32_t  g_uri_usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};

/*
 *	extract ip address from buff
 *	@param
 *		buff_in [in]   buffer contains ip address
 *		buff_out [out] buffer for saving out result
 *	@return
 *		begin address of IP in original buffer
 */
char* extract_ip(char *buff_in, char *buff_out)
{
	long i, j, k;
	long len, end;
	char temp_buff[4];
	long pos[3] = {0, 0, 0};
	long begin_pos, end_pos;
	int found = 0;

	len = strlen(buff_in);
	for (i=0, j=0; i<len; i++) {
		if (buff_in[i] == '.') {
			pos[j] = i;
			j++;
			if (3 == j) {
				if (pos[0] == 0) {
					i = pos[0];
					j = 0;
					continue;
				}
				if (pos[1] - pos[0] > 4) {
					i = pos[0];
					j = 0;
					continue;
				}
				if (pos[2] - pos[1] > 4) {
					i = pos[1];
					j = 0;
					continue;
				}
				if (pos[0] < 3) {
					end = 0;
				} else {
					end = pos[0] - 3;
				}
				begin_pos = end;
				for (k=pos[0]-1; k>=end; k--) {
					if (buff_in[k] < '0' || buff_in[k] > '9') {
						begin_pos = k + 1;
						break;
					}
				}
				/* if not number is found */
				if (k == pos[0] - 1) {
					i = pos[0];
					j = 0;
					continue;
				}
				for (k=pos[0]+1; k<pos[1]; k++) {
					if (buff_in[k] > '9' || buff_in[k] < '0') {
						i = pos [0];
						j = 0;
						break;
					}
				}
				if (0 == j) {
					continue;
				}
				for (k=pos[1]+1; k<pos[2]; k++) {
					if (buff_in[k] >'9' || buff_in[k] < '0') {
						i = pos[1];
						j = 0;
						break;
					}
				}
				if (0 == j) {
					continue;
				}
				if (len - pos[2] < 3) {
					end = len;
				} else {
					end = pos[2] + 4;
				}
				end_pos = end - 1;
				for (k=pos[2]+1; k<end; k++) {
					if (buff_in[k] >'9' || buff_in[k] <'0') {
						end_pos = k - 1;
						break;
					}
				}
				if (k==pos[2]) {
					i = pos[2];
					j = 0;
					continue;
				}
				found = 1;
				break;
			}
		}

	}
	if (1 == found) {
		len = pos[0] - begin_pos;
		memcpy(temp_buff, buff_in + begin_pos, len);
		temp_buff[len] = '\0';
		if (atoi(temp_buff) > 255) {
			return 0;
		}

		len = pos[1] - (pos[0] + 1);
		memcpy(temp_buff, buff_in + pos[0] + 1, len);
		temp_buff[len] = '\0';
		if (atoi(temp_buff) > 255) {
			return 0;
		}

		len = pos[2] - (pos[1] + 1);
		memcpy(temp_buff, buff_in + pos[1] + 1, len);
		temp_buff[len] = '\0';
		if (atoi(temp_buff) > 255) {
			return 0;
		}

		len = end_pos - pos[2];
		memcpy(temp_buff, buff_in + pos[2] + 1, len);
		temp_buff[len] = '\0';
		if (atoi(temp_buff) > 255) {
			return 0;
		}

		strncpy(buff_out, buff_in + begin_pos, end_pos - begin_pos + 1);
		buff_out[end_pos - begin_pos + 1] = '\0';
		return buff_in + begin_pos;
	}
	return 0;
}

/*
 *	  parse email as "John Honey" <john@mail.com> into e_addr
 *	  @param
 *		  email	 [in]	  string contain the address
 *		  e_addr [out]	  for retrieving parsed address
 */
void parse_email_addr(EMAIL_ADDR *e_addr, const char *email)
{
	int i, j;
	int tokenloc;
	int bgettoken;
	int lasttokenloc;
	const char *tmp_ptr;
	const char *loc_ptr;
	const char *email_ptr;
	
	tokenloc = 0;
	bgettoken = 0;
	lasttokenloc = -1;
	email_ptr = email;
	tmp_ptr = email;
	loc_ptr = email;
	/* first get the display name, begin with token " */
	while (*tmp_ptr != '\0') {
		if ('"' == *tmp_ptr) {
			if (-1 == lasttokenloc){
				lasttokenloc = tmp_ptr - email;
				loc_ptr = tmp_ptr;
			} else {
				bgettoken = 1;
				tokenloc = tmp_ptr - email;
				break;
			}
		}
		if ('<' == *tmp_ptr && -1 == lasttokenloc) {
			bgettoken = 1;
			tokenloc = tmp_ptr - email;
			break;
		}
		tmp_ptr ++;
	}
	
	/* check if two quotation marks are found */
	if (0 == bgettoken || tokenloc - lasttokenloc >
		sizeof(e_addr->display_name)) {
		tmp_ptr = loc_ptr;
		e_addr->display_name[0] = '\0';
	} else {
		for (i=lasttokenloc+1, j=0; i<tokenloc; i++, j++) {
			e_addr->display_name[j] = email[i];
		}
		e_addr->display_name[j] = '\0';
		ltrim_string(e_addr->display_name);
		rtrim_string(e_addr->display_name);
	}
	/* get the first < token */
	loc_ptr = tmp_ptr;
	bgettoken = 0;
	tokenloc = 0;
	while (*tmp_ptr != '\0') {
		if ('<' == *tmp_ptr) {
			lasttokenloc = tokenloc;
			tokenloc = tmp_ptr - email;
			bgettoken = 1;
			break;
		}
		tmp_ptr ++;
	}
	
	if (0 == bgettoken) {
		tmp_ptr = loc_ptr;
	}
	/* get the local part in the string */
	bgettoken = 0;
	if (lasttokenloc != -1){
		lasttokenloc = tokenloc;
	}
	loc_ptr = tmp_ptr;
	tokenloc = 0;
	while (*tmp_ptr != '\0') {
		if ('@' == *tmp_ptr) { 
			bgettoken = 1;
			tokenloc = tmp_ptr - email;
			break;
		}
		tmp_ptr ++;
	}
	
	/* check if at token is found */
	if (0 == bgettoken || tokenloc - lasttokenloc >
		sizeof(e_addr->local_part)) {
		e_addr->local_part[0] = '\0';
		tmp_ptr = loc_ptr;
	} else {
		for (i=lasttokenloc+1, j=0; i<tokenloc; i++, j++) {
			e_addr->local_part[j] = email[i];
		}
		e_addr->local_part[j] = '\0';
		ltrim_string(e_addr->local_part);
		rtrim_string(e_addr->local_part);
	}

	/* get the domain */
	lasttokenloc = tokenloc;
	if (bgettoken != 0) {
		tmp_ptr ++;
	}
	for (i=lasttokenloc+1, j=0; *(tmp_ptr+j)!='\0' && *(tmp_ptr+j)!='>'; 
		 i++, j++) {
		if (j >= sizeof(e_addr->domain)) {
			j = 0;
			break;
		}
		e_addr->domain[j] = tmp_ptr[j];
	}
	e_addr->domain[j] = '\0';
	ltrim_string(e_addr->domain);
	rtrim_string(e_addr->domain);
}

BOOL parse_uri(const char *uri_buff, char *parsed_uri)
{
	int tmp_len;
	const char *p;
	const char *uri_end;
	const char *args_start;
	int state, quoted_state;
    char c, ch, decoded, *u;
    
	decoded = '\0';
	quoted_state = SW_USUAL;
	state = SW_USUAL;
	p = uri_buff;
	uri_end = uri_buff + strlen(uri_buff);
	u = parsed_uri;
	args_start = NULL;
	ch = *p ++;
	while (p <= uri_end) {
		switch (state) {
		case SW_USUAL:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				*u++ = ch;
				ch = *p++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_SLASH:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				/* merge slash */
				break;
			case '.':
				state = SW_DOT;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_DOT:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				u --;
				break;
			case '.':
				state = SW_DOT_DOT;
				*u ++ = ch;
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_DOT_DOT:
			if (g_uri_usual[ch >> 5] & (1U << (ch & 0x1f))) {
				state = SW_USUAL;
				*u ++ = ch;
				ch = *p ++;
				break;
			}
			switch (ch) {
			case '/':
				state = SW_SLASH;
				u -= 5;
				for ( ;; ) {
					if (u < parsed_uri) {
						return FALSE;
					}
					if ('/' == *u) {
						u ++;
						break;
					}
					u --;
				}
				break;
			case '%':
				quoted_state = state;
				state = SW_QUOTED;
				break;
			case '?':
				args_start = p;
				goto PARSE_ARGS;
			case '#':
				goto PARSE_DONE;
			default:
				state = SW_USUAL;
				*u ++ = ch;
				break;
			}
			ch = *p ++;
			break;
		case SW_QUOTED:
			if (ch >= '0' && ch <= '9') {
				decoded = (uint8_t)(ch - '0');
				state = SW_QUOTED_SECOND;
				ch = *p ++;
				break;
			}
			c = (uint8_t)(ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				decoded = (uint8_t)(c - 'a' + 10);
				state = SW_QUOTED_SECOND;
				ch = *p ++;
				break;
			}
			return FALSE;
		case SW_QUOTED_SECOND:
			if (ch >= '0' && ch <= '9') {
				ch = (uint8_t)((decoded << 4) + (ch - '0'));
				if ('%' == ch || '#' == ch) {
					state = SW_USUAL;
					*u ++ = ch;
					ch = *p ++;
					break;

				} else if ('\0' == ch) {
					return FALSE;
				}
				state = quoted_state;
				break;
			}

			c = (uint8_t)(ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				ch = (uint8_t) ((decoded << 4) + (c - 'a') + 10);
				if ('?' == ch) {
					state = SW_USUAL;
					*u ++ = ch;
					ch = *p ++;
					break;

				}
				state = quoted_state;
				break;
			}
			return FALSE;
		}
	}
PARSE_ARGS:
    while (p < uri_end) {
        if (*p ++ != '#') {
            continue;
        }
		tmp_len = p - args_start;
		memcpy(u, args_start, tmp_len);
		u += tmp_len;
        break;
    }
PARSE_DONE:
	*u = '\0';
    return TRUE;
}

/*
 *	  parse email address in mime field into e_addr
 *	  @param
 *		  email	 [in]	  string contain the address
 *		  e_addr [out]	  for retrieving parsed address
 */
void parse_mime_addr(EMAIL_ADDR *e_addr, const char *email)
{
	int i, j;
	int tmp_len;
	int bquoted;
	int tokenloc;
	int bgettoken;
	int lasttokenloc;
	const char *tmp_ptr;
	const char *loc_ptr;
	const char *email_ptr;
	
	tmp_ptr = email;
	loc_ptr = email;
	email_ptr = email;
	tokenloc = 0;
	bquoted = 0;
	bgettoken = 0;
	while (*tmp_ptr != '\0') {
		if ('"' == *tmp_ptr) {
			if (0 == bquoted) {
				bquoted = 1;
			} else {
				bquoted = 0;
			}
		} else if ('<' == *tmp_ptr && (0 == bquoted
			|| NULL == strchr(tmp_ptr + 1, '"'))) {
			bgettoken = 1;
			tokenloc = tmp_ptr - email;
			break;
		}
		tmp_ptr ++;
	}
	if (0 == bgettoken || 0 == tokenloc ||
		tokenloc >= sizeof(e_addr->display_name)) {
		tmp_ptr = email;
		e_addr->display_name[0] = '\0';
	} else {
		memcpy(e_addr->display_name, email, tokenloc);
		e_addr->display_name[tokenloc] = '\0';
		ltrim_string(e_addr->display_name);
		rtrim_string(e_addr->display_name);
		tmp_len = strlen(e_addr->display_name);
		if (tmp_len > 1 && '"' == e_addr->display_name[0]
			&& '"' == e_addr->display_name[tmp_len - 1]) {
			tmp_len --;
			e_addr->display_name[tmp_len] = '\0';
			memmove(e_addr->display_name,
				e_addr->display_name + 1, tmp_len);
			tmp_len --;
		}
		if (tmp_len > 1 && '\'' == e_addr->display_name[0]
			&& '\'' == e_addr->display_name[tmp_len - 1]) {
			tmp_len --;
			e_addr->display_name[tmp_len] = '\0';
			memmove(e_addr->display_name,
				e_addr->display_name + 1, tmp_len);
			tmp_len --;
		}
		for (i=0; i<tmp_len; i++) {
			if ('\\' == e_addr->display_name[i]) {
				memmove(e_addr->display_name + i,
					e_addr->display_name + i + 1,
					tmp_len - i);
				tmp_len --;
				i ++;
			}
			
		}
	}
	/* get the first < token */
	loc_ptr = tmp_ptr;
	bgettoken = 0;
	tokenloc = 0;
	lasttokenloc = -1;
	while (*tmp_ptr != '\0') {
		if ('<' == *tmp_ptr) {
			lasttokenloc = tokenloc;
			tokenloc = tmp_ptr - email;
			bgettoken = 1;
			break;
		}
		tmp_ptr ++;
	}
	
	if (0 == bgettoken) {
		tmp_ptr = loc_ptr;
	}
	/* get the local part in the string */
	bgettoken = 0;
	if (lasttokenloc != -1){
		lasttokenloc = tokenloc;
	}
	loc_ptr = tmp_ptr;
	tokenloc = 0;
	while (*tmp_ptr != '\0') {
		if ('@' == *tmp_ptr) { 
			bgettoken = 1;
			tokenloc = tmp_ptr - email;
			break;
		}
		tmp_ptr ++;
	}
	
	/* check if at token is found */
	if (0 == bgettoken || tokenloc - lasttokenloc >
		sizeof(e_addr->local_part)) {
		e_addr->local_part[0] = '\0';
		tmp_ptr = loc_ptr;
	} else {
		for (i=lasttokenloc+1, j=0; i<tokenloc; i++, j++) {
			e_addr->local_part[j] = email[i];
		}
		e_addr->local_part[j] = '\0';
		ltrim_string(e_addr->local_part);
		rtrim_string(e_addr->local_part);
	}

	/* get the domain */
	lasttokenloc = tokenloc;
	if (bgettoken != 0) {
		tmp_ptr ++;
	}
	for (i=lasttokenloc+1, j=0; *(tmp_ptr+j)!='\0' && *(tmp_ptr+j)!='>'; 
		 i++, j++) {
		if (j >= sizeof(e_addr->domain)) {
			j = 0;
			break;
		}
		e_addr->domain[j] = tmp_ptr[j];
	}
	e_addr->domain[j] = '\0';
	ltrim_string(e_addr->domain);
	rtrim_string(e_addr->domain);
}

/*
 *	  parse mime information from buffer into mime field
 *	  @param
 *		  in_buff [in]		buffer for passing the content of mime head
 *		  buff_len			length of buff_in
 *		  pmime_field [out] buffer for retrieving information of mime
 *	  @return
 *		  end of mime field information, including the last "\r\n", if the last
 *		  two byte in buff_in is "\r\n", it is also considered as a mime field 
 */
int parse_mime_field(char *in_buff, long buff_len, MIME_FIELD *pmime_field)
{
	int i;
	BOOL meet_slash;
	int value_length = 0;
	char *tmp_ptr = NULL;
	char *dest_ptr = NULL;
	
	
	if (buff_len > MIME_FIELD_LEN) {
		buff_len = MIME_FIELD_LEN;
	}
	/* parse the first line the get the field name and part of value*/
	tmp_ptr = in_buff;
	dest_ptr = (char*)&pmime_field->field_name;
	i = 0;
	while (*tmp_ptr != ':' && i < buff_len &&
		i <= MIME_NAME_LEN && *tmp_ptr != '\r'
		&& *tmp_ptr != '\n') {
		*dest_ptr = *tmp_ptr;
		tmp_ptr ++; 
		dest_ptr ++;
		i ++;
	}
	if (i == buff_len || MIME_NAME_LEN + 1 == i ||
		'\r' == *tmp_ptr || '\n' == *tmp_ptr) {
		return 0;
	}
	pmime_field->field_name_len = i;
	tmp_ptr ++;	   /* skip ':' */
	i ++;
	while (i < buff_len && (' ' == *tmp_ptr || '\t' == *tmp_ptr)) { 
		tmp_ptr ++;	/* skip WSP */
		i ++;
	}
	if (i == buff_len) {
		return 0;
	}
	dest_ptr = (char*)&pmime_field->field_value;
	while (TRUE) {
		meet_slash = FALSE;
		while (i < buff_len && *tmp_ptr != '\r' && *tmp_ptr != '\n') {
			if ('\\' == *tmp_ptr && ('\r' == *(tmp_ptr + 1) ||
				'\n' == *(tmp_ptr + 1))) {
				meet_slash = TRUE;
			} else {
				*dest_ptr = *tmp_ptr;
				value_length ++;
				dest_ptr ++;
			}
			tmp_ptr ++;
			i ++;
		}
		if (i == buff_len) {
			if ('\r' == *tmp_ptr || '\n' == *tmp_ptr) {
				pmime_field->field_value_len = value_length;
				return buff_len;
			} else {
				return 0;
			}
		}
		tmp_ptr ++;
		i ++;
		if (i == buff_len) {
			if ('\n' == *tmp_ptr) {
				pmime_field->field_value_len = value_length;
				return buff_len;
			} else if (' ' == *tmp_ptr || '\t' == *tmp_ptr ||
				TRUE == meet_slash) {
				return 0;
			} else {
				buff_len --;
			}
		} else {
			if ('\n' == *tmp_ptr) {
				tmp_ptr ++;
				i ++;
			}
		}
		if (*tmp_ptr != ' ' && *tmp_ptr != '\t' && FALSE == meet_slash) {
			pmime_field->field_value_len = value_length;
			return i;
		} else {
			while (i < buff_len && (' ' == *tmp_ptr || '\t' == *tmp_ptr)) {
				tmp_ptr ++; /* skip WSP */
				i ++;
			}
			if (i == buff_len) {
				return 0;
			} else {
				*dest_ptr = ' ';
				dest_ptr ++;
				value_length ++;
			}
		}
	}
	return 0;
}

void parse_mime_encode_string(char *in_buff, long buff_len,
	ENCODE_STRING *pencode_string)
{
	long i = 0, tmp_begin; 
	long charset_begin, charset_len, title_begin, title_len;
	
	memset(pencode_string, 0, sizeof(ENCODE_STRING));
	/* first ignore the ' ' in the buffer */
	for (i=0; i<buff_len; i++) {
		if (in_buff[i] != ' ') {
			break;
		}
	}
	if (i >= buff_len - 2) {
		strcpy(pencode_string->charset, "default");
		strcpy(pencode_string->encoding, "none");
		memcpy(pencode_string->title, in_buff + i, buff_len - i);
		pencode_string->title[buff_len - i] = '\0';
		return;
	}
	if (in_buff[i] != '=' || in_buff[i+1] != '?') {
		strcpy(pencode_string->charset, "default");
		strcpy(pencode_string->encoding, "none");
		title_len = (buff_len > sizeof(pencode_string->title) - 1) ? 
				sizeof(pencode_string->title) - 1 : buff_len;
		memcpy(pencode_string->title, in_buff, title_len);
		pencode_string->title[title_len] = '\0';
		return;
	}
	charset_begin = i + 2;
	tmp_begin = charset_begin;
	for (i=tmp_begin; i<buff_len; i++) {
		if (in_buff[i] == '?') {
			break;
		}
	}
	if (i >= buff_len - 1) {
		return;
	}
	/* copy charset to pasred structure */
	charset_len = i - charset_begin;
	if (charset_len > sizeof(pencode_string->charset) - 1) {
		return;
	}
	if (0 == charset_len) {
		strcpy(pencode_string->charset, "default");
	} else {	
		memcpy(pencode_string->charset, in_buff + charset_begin, charset_len);
		pencode_string->charset[charset_len] = '\0';
	}
	if ('b' == in_buff[i+1] || 'B' == in_buff[i+1]) {
		strcpy(pencode_string->encoding, "base64");
		tmp_begin = i + 2;
	} else if ('q' == in_buff[i+1] || 'Q' == in_buff[i+1]) {
		strcpy(pencode_string->encoding, "quoted-printable");
		tmp_begin = i + 2;
	} else {
		strcpy(pencode_string->encoding, "none");
		tmp_begin = i + 1;
	}
	if (tmp_begin >= buff_len) {
		return;
	}
	/* ignore the ? */
	if (in_buff[tmp_begin] == '?') {
		tmp_begin ++;
	}
	title_begin = tmp_begin;
	for (i=tmp_begin; i<buff_len; i++) {
		if (in_buff[i] == '?' && in_buff[i+1] == '=') {
			break;
		}
	}
	title_len = i - title_begin;
	if (title_len > sizeof(pencode_string->title) - 1) {
		title_len = sizeof(pencode_string->title) - 1;
	}
	memcpy(pencode_string->title, in_buff + title_begin, title_len);
	pencode_string->title[title_len] = '\0';
}

long decode_mime_string(char *in_buff, long buff_len, char *out_buff, long len)
{
	long i, begin_pos, end_pos;
	long offset, title_len;
	size_t	decode_len;
	BOOL b_decoded;
	ENCODE_STRING encode_string;

	b_decoded = FALSE;
	offset = 0;
	begin_pos = -1;
	end_pos = -1;
	for (i=0; i<buff_len-1&&offset<len-1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
		}
		if (-1 == end_pos && -1 != begin_pos && '?' == in_buff[i] &&
			'=' == in_buff[i + 1] && ('q' != in_buff[i - 1] &&
			'Q' != in_buff[i - 1] || '?' != in_buff[i - 2])) {
			end_pos = i + 1;
		}
		if (-1 != begin_pos && -1 != end_pos) {
			b_decoded = TRUE;
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			title_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, title_len, out_buff + offset,
					&decode_len);
				offset += decode_len;
			} else if (0 == strcmp(encode_string.encoding, "quoted-printable")){
				offset += qp_decode(out_buff + offset, encode_string.title, 
							title_len);
			} else if (0 == strcmp(encode_string.encoding, "none")) {
				strcpy(out_buff + offset, encode_string.title);
				offset += title_len;
			} else {
				memcpy(out_buff + offset, in_buff + begin_pos,
					end_pos - begin_pos + 1);
				offset += end_pos - begin_pos + 1;
			}
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
		if (-1 == end_pos && -1 == begin_pos) {
			if (' ' != in_buff[i] && '\t' != in_buff[i]) {
				out_buff[offset] = in_buff[i];
				offset ++;
			}
		}
	}
	if (FALSE == b_decoded) {
		title_len =	 buff_len>len - 1?len - 1:buff_len;
		memcpy(out_buff, in_buff, title_len);
		offset = title_len;
	} else if (-1 != begin_pos && -1 == end_pos) {
		title_len = 
			buff_len-begin_pos>len-offset-1?len-offset-1:buff_len-begin_pos;
		memcpy(out_buff + offset, in_buff + begin_pos, title_len);
		offset += title_len;
	} else if (-1 == begin_pos && -1 == end_pos && i == buff_len - 1) {
		if (' ' != in_buff[i] && '\t' != in_buff[i]) {
			out_buff[offset] = in_buff[i];
			offset ++;
		}
	}
	out_buff[offset] = '\0';
	return offset;
}

/*
 *	this function parse the buffer containing the parameters in mime 
 *	field value
 *	@param
 *		in_buff [in]	buffer passed in
 *		buff_len		buffer length, normally should be less tahn 64K
 *		value [out]		buffer for retriving the value
 *		val_len			length of value buffer
 *		pfile [in,out]	mem file to retrieving the parsing result of params
 */
void parse_field_value(char *in_buff, long buff_len, char *value, long val_len,
	MEM_FILE *pfile)
{
	char *ptr, *prev_section, *ptr_equal;
	int offset, distance;
	int paratag_len = 0;
	int paraval_len = 0;
	char param_tag[MIME_FIELD_LEN];
	char param_value[MIME_FIELD_LEN];

	offset = 0;
	ptr = in_buff;
	prev_section = NULL;
	while (ptr=memchr(ptr, ';', buff_len - (ptr - in_buff))) {
		if (NULL == prev_section) {
			distance = ptr - in_buff;
			paratag_len = (val_len - 1 > distance)?distance:(val_len - 1);
			memcpy(value, in_buff, paratag_len);
			value[paratag_len] = '\0';
			ltrim_string(value);
			rtrim_string(value);
		} else {
			ptr_equal = memchr(prev_section, '=', (ptr - prev_section));
			if (NULL == ptr_equal) {
				paratag_len = ptr - prev_section;
				memcpy(param_tag, prev_section, paratag_len);
				paraval_len = 0;
			} else {
				paratag_len = ptr_equal - prev_section;
				memcpy(param_tag, prev_section, paratag_len);
				ptr_equal ++;
				paraval_len = ptr - ptr_equal;
				memcpy(param_value, ptr_equal, paraval_len);
			}
			param_tag[paratag_len] = '\0';
			param_value[paraval_len] = '\0';
			ltrim_string(param_tag);
			rtrim_string(param_tag);
			ltrim_string(param_value);
			rtrim_string(param_value);
			paratag_len = strlen(param_tag);
			paraval_len = strlen(param_value);
			if (0 != paratag_len || 0 != paraval_len) {
				mem_file_write(pfile, (char*)&paratag_len, sizeof(int));
				mem_file_write(pfile, param_tag, paratag_len);
				mem_file_write(pfile, (char*)&paraval_len, sizeof(int));
				mem_file_write(pfile, param_value, paraval_len);
			}
		}
		ptr ++;
		prev_section = ptr;
	}
	ptr = in_buff + buff_len;
	if (NULL == prev_section) {
		distance = ptr - in_buff;
		paratag_len = (val_len - 1 > distance)?distance:(val_len - 1);
		memcpy(value, in_buff, paratag_len);
		value[paratag_len] = '\0';
		ltrim_string(value);
		rtrim_string(value);
	} else {
		ptr_equal = memchr(prev_section, '=', (ptr - prev_section));
		if (NULL == ptr_equal) {
			paratag_len = ptr - prev_section;
			memcpy(param_tag, prev_section, paratag_len);
			paraval_len = 0;
		} else {
			paratag_len = ptr_equal - prev_section;
			memcpy(param_tag, prev_section, paratag_len);
			ptr_equal ++;
			paraval_len = ptr - ptr_equal;
			memcpy(param_value, ptr_equal, paraval_len);
		}
		param_tag[paratag_len] = '\0';
		param_value[paraval_len] = '\0';
		ltrim_string(param_tag);
		rtrim_string(param_tag);
		ltrim_string(param_value);
		rtrim_string(param_value);
		paratag_len = strlen(param_tag);
		paraval_len = strlen(param_value);
		if (0 != paratag_len || 0 != paraval_len) {
			mem_file_write(pfile, (char*)&paratag_len, sizeof(int));
			mem_file_write(pfile, param_tag, paratag_len);
			mem_file_write(pfile, (char*)&paraval_len, sizeof(int));
			mem_file_write(pfile, param_value, paraval_len);
		}
	}
}

/*
 *	find URL of format scheme:hostname[:port]/dir in a buffer.	The
 *	buffer may contain pretty much anything; no errors are signaled.
 *	@param
 *		buf	[in]		buffer to be searched
 *		howmuch			buffer length
 *		count [out]		url length
 */
char* find_url(char *buf, size_t howmuch, int *count)
{
	
	long i;
	char *s1, *s2;
	register char tmp;

	for (s1=buf; howmuch>6; s1++) {
		switch (*s1) {
		case 'h':
		case 'H':
			if (0 != strncasecmp(s1 + 1, "ttp", 3)) {
				goto CONTINUE_LOOP;
			}
			if (':' != s1[4] && (('s' != s1[4] && 'S' != s1[4])
				|| ':' != s1[5])) {
				goto CONTINUE_LOOP;
			}
			break;
		case 'w':
		case 'W':
			if (0 != strncasecmp(s1 + 1, "ww.", 3)) {
				goto CONTINUE_LOOP;
			}
			break;
		default:
			goto CONTINUE_LOOP;
		}
		for (s2=s1, *count=0; howmuch>0; s2++, (*count)++, howmuch--) {
			tmp = *s2;
			if (tmp < 32 || tmp >= 127 || tmp == ' ' || 
				tmp == '!' || tmp == '"' || tmp == '\'' || tmp == '#'
				|| tmp == '(' || tmp == ')' || tmp == ',' ||
				tmp == '`' || tmp == '{' || tmp == '}' || tmp == '|'
				|| tmp == '<' || tmp == '>') {
				break;
			}
		}
		return s1;
CONTINUE_LOOP:
		howmuch --;
	}
	*count = 0;
	return NULL;
}

/*
 *	find email address in a buffer. The buffer may contain pretty 
 *	much anything; no errors are signaled.
 *	@param
 *		buf	[in]		buffer to be searched
 *		howmuch			buffer length
 *		count [out]		address length
 */
char* find_mail_address(char *buf, size_t howmuch, int *count)
{
	long i, j, stop;
	long at_pos, begin_pos, end_pos;
	register char tmp;

	for (i=0; i<howmuch; i++) {
		if ('@' == buf[i]) {
			if (i >= howmuch - 1 || 0 == i) {
				continue;
			}
			at_pos = i;
			stop = (at_pos - 255 > 0)?(at_pos - 255):0;
			for (j=at_pos-1; j>=stop; j--) {
				tmp = buf[j];
				if (('a' <= tmp && 'z' >= tmp) || ('A' <= tmp && 'Z' >= tmp) ||
					('0' <= tmp && '9' >= tmp) || '_' == tmp || '-' == tmp ||
					'.' == tmp || '=' == tmp || '/' == tmp || '\\' == tmp) {
					continue;
				} else {
					break;
				}
			}
			begin_pos = j + 1;
			stop = (at_pos + 255 > howmuch)?howmuch:(at_pos + 255);
			for (j=at_pos+1; j<stop; j++) {
				tmp = buf[j];
				if (('a' <= tmp && 'z' >= tmp) || ('A' <= tmp && 'Z' >= tmp) ||
					('0' <= tmp && '9' >= tmp) || '_' == tmp || '-' == tmp ||
					'.' == tmp || '=' == tmp || '/' == tmp || '\\' == tmp) {
					continue;
				} else {
					break;
				}
			}
			end_pos = j;
			if (end_pos - begin_pos > 255 || end_pos == at_pos + 1 ||
				begin_pos == at_pos) {
				continue;
			}
			*count = end_pos - begin_pos;
			return buf + begin_pos;
		}
	}
	*count = 0;
	return NULL;
}

static const int Index_64[128] = {
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, 63,-1,-1,-1,
	52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
	-1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
	15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
	-1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
	41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};

static const char B64Chars[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', ','
};

int utf7_to_utf8 (const char *u7, size_t u7len, char *u8, size_t u8len)
{
  char *u8end;
  char *buf, *p;
  int b, ch, k;

  p = buf = u8;

  u8end = u8 + u8len - 1;

  for (; u7len&&p<u8end; u7++, u7len--)
  {
	if (*u7 == '&')
	{
	  u7++, u7len--;

	  if (u7len && *u7 == '-')
	  {
		*p++ = '&';
		continue;
	  }

	  ch = 0;
	  k = 10;
	  for (; u7len&&p<u8end; u7++, u7len--)
	  {
		if ((*u7 & 0x80) || (b = Index_64[(int)*u7]) == -1)
		  break;
		if (k > 0)
		{
		  ch |= b << k;
		  k -= 6;
		}
		else
		{
		  ch |= b >> (-k);
		  if (ch < 0x80)
		  {
			if (0x20 <= ch && ch < 0x7f)
			  /* Printable US-ASCII */
			  return -1;
			*p++ = ch;
		  }
		  else if (ch < 0x800)
		  {
			*p++ = 0xc0 | (ch >> 6);
			*p++ = 0x80 | (ch & 0x3f);
		  }
		  else
		  {
			*p++ = 0xe0 | (ch >> 12);
			*p++ = 0x80 | ((ch >> 6) & 0x3f);
			*p++ = 0x80 | (ch & 0x3f);
		  }
		  ch = (b << (16 + k)) & 0xffff;
		  k += 10;
		}
	  }
	  if (ch || k < 6)
		/* Non-zero or too many extra bits */
		return -1;
	  if (!u7len || *u7 != '-')
		/* BASE64 not properly terminated */
		return -1;
	  if (u7len > 2 && u7[1] == '&' && u7[2] != '-')
		/* Adjacent BASE64 sections */
		return -1;
	}
	else if (*u7 < 0x20 || *u7 >= 0x7f)
	  /* Not printable US-ASCII */
	  return -1;
	else
	  *p++ = *u7;
  }
  if (p >= u8end) {
	 return -1;
  }
  *p = '\0';
  return p - u8;
}

int utf8_to_utf7 (const char *u8, size_t u8len, char *u7, size_t u7len)
{
  char *u7end;
  char *buf, *p;
  int ch;
  int n, i, b = 0, k = 0;
  int base64 = 0;

  /*
   * In the worst case we convert 2 chars to 7 chars. For example:
   * "\x10&\x10&..." -> "&ABA-&-&ABA-&-...".
   */
  p = buf = u7;

  u7end = u7 + u7len - 1;

  while (u8len&&p<u7end)
  {
	unsigned char c = *u8;

	if (c < 0x80)
	  ch = c, n = 0;
	else if (c < 0xc2)
	  return -1;
	else if (c < 0xe0)
	  ch = c & 0x1f, n = 1;
	else if (c < 0xf0)
	  ch = c & 0x0f, n = 2;
	else if (c < 0xf8)
	  ch = c & 0x07, n = 3;
	else if (c < 0xfc)
	  ch = c & 0x03, n = 4;
	else if (c < 0xfe)
	  ch = c & 0x01, n = 5;
	else
	  return -1;

	u8++, u8len--;
	if (n > u8len)
	  return -1;
	for (i = 0; i < n; i++)
	{
	  if ((u8[i] & 0xc0) != 0x80)
		return -1;
	  ch = (ch << 6) | (u8[i] & 0x3f);
	}
	if (n > 1 && !(ch >> (n * 5 + 1)))
	  return -1;
	u8 += n, u8len -= n;

	if (ch < 0x20 || ch >= 0x7f)
	{
	  if (!base64)
	  {
		*p++ = '&';
		base64 = 1;
		b = 0;
		k = 10;
	  }
	  if (ch & ~0xffff)
		ch = 0xfffe;
	  *p++ = B64Chars[b | ch >> k];
	  k -= 6;
	  for (; k >= 0; k -= 6)
		*p++ = B64Chars[(ch >> k) & 0x3f];
	  b = (ch << (-k)) & 0x3f;
	  k += 16;
	}
	else
	{
	  if (base64)
	  {
		if (k > 10)
		  *p++ = B64Chars[b];
		*p++ = '-';
		base64 = 0;
	  }
	  *p++ = ch;
	  if (ch == '&')
		*p++ = '-';
	}
  }

  if (u8len||p>=u7end)
  {
	return -1;
  }

  if (base64)
  {
	if (k > 10)
	  *p++ = B64Chars[b];
	*p++ = '-';
  }

  *p = '\0';
  return p - buf;
}

int parse_imap_args(char *cmdline, int cmdlen, char **argv, int argmax)
{
	int argc;
	char *ptr;
	int length;
	int b_count;
	int s_count;
	BOOL is_quoted;
	char *last_space;
	char *last_square;
	char *last_quota;
	char *last_brace;
	char *last_bracket;

	cmdline[cmdlen] = ' ';
	cmdlen ++;
	ptr = cmdline;
	/* Build the argv list */
	argc = 0;
	last_quota = NULL;
	last_bracket = NULL;
	last_square = NULL;
	last_space = cmdline;
	is_quoted = FALSE;
	while (ptr - cmdline < cmdlen && argc < argmax - 1) {
		if ('{' == *ptr && NULL == last_quota) {
			if (NULL != (last_brace = memchr(ptr + 1, '}', 16))) {
				*last_brace = '\0';
				length = atoi(ptr + 1);
				memmove(ptr, last_brace + 1, cmdline + cmdlen - 1 - last_brace);
				cmdlen -= last_brace + 1 - ptr;
				ptr += length;
			} else {
				argv[0] = NULL;
				return -1;
			}
		}
		if ('\"' == *ptr) {
			memmove(ptr, ptr + 1, cmdline + cmdlen - ptr - 1);
			cmdlen --;
			if (NULL == last_quota) {
				is_quoted = TRUE;
				last_quota = ptr;
				/* continue the lookp for the empty "" because of memmove */
				continue;
			} else {
				last_quota = NULL;
			}
		}
		if ('[' == *ptr && NULL == last_quota) {
			if (NULL == last_square) {
				last_square = ptr;
				s_count = 0;
			} else {
				s_count ++;
			}
		}
		if (']' == *ptr && NULL != last_square) {
			if (0 == s_count) {
				last_square = NULL;
			} else {
				s_count --;
			}
		}
		if ('(' == *ptr && NULL == last_quota) {
			if (NULL == last_bracket) {
				last_bracket = ptr;
				b_count = 0;
			} else {
				b_count ++;
			}
		}
		if (')' == *ptr && NULL != last_bracket) {
			if (0 == b_count) {
				last_bracket = NULL;
			} else {
				b_count --;
			}
		}
		if (' ' == *ptr && NULL == last_quota &&
			NULL == last_bracket && NULL == last_square) {
			/* ignore leading spaces */
			if (ptr == last_space && FALSE == is_quoted) {
				last_space ++;
			} else {
				argv[argc] = last_space;
				*ptr = '\0';
				if (FALSE == is_quoted && 0 == strcasecmp(argv[argc], "NIL")) {
					argv[argc] = "";
				}
				last_space = ptr + 1;
				argc ++;
				is_quoted = FALSE;
			}
		}
		ptr ++;
	}
	/* only one quota is found, error */
	if (NULL != last_quota || NULL != last_bracket || NULL != last_square) {
		argv[0] = NULL;
		return -1;
	}
	argv[argc] = NULL;
	return argc;
}

time_t make_gmtime(struct tm *ptm)
{
	static const struct state *sp = NULL;
	
	if (NULL == sp) {
		sp = tz_alloc("UTC");
		if (NULL == sp) {
			return 0;
		}
	}
	return tz_mktime(sp, ptm);
}

void make_gmtm(time_t gm_time, struct tm *ptm)
{
	static const struct state *sp = NULL;
	
	if (NULL == sp) {
		sp = tz_alloc("UTC");
		if (NULL == sp) {
			return;
		}
	}
	tz_localtime_r(sp, &gm_time, ptm);
}

BOOL parse_rfc822_timestamp(const char *str_time, time_t *ptime)
{
	int hour;
	int minute;
	int factor;
	int zone_len;
	time_t tmp_time;
	char tmp_buff[3];
	struct tm tmp_tm;
	const char *str_zone;
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	str_zone = strptime(str_time, "%a, %d %b %Y %H:%M:%S ", &tmp_tm);
	if (NULL == str_zone) {
		return FALSE;
	}
	
	zone_len = strlen(str_zone);
	if (zone_len >= 5) {
		if ('-' == str_zone[0]) {
			factor = 1;
		} else if ('+' == str_zone[0]) {
			factor = -1;
		} else {
			return FALSE;
		}
		if (!isdigit(str_zone[1]) || !isdigit(str_zone[2]) ||
			!isdigit(str_zone[3]) || !isdigit(str_zone[4])) {
			return FALSE;
		}

		tmp_buff[0] = str_zone[1];
		tmp_buff[1] = str_zone[2];
		tmp_buff[2] = '\0';
		hour = atoi(tmp_buff);
		if (hour < 0 || hour > 23) {
			return FALSE;
		}

		tmp_buff[0] = str_zone[3];
		tmp_buff[1] = str_zone[4];
		tmp_buff[2] = '\0';
		minute = atoi(tmp_buff);
		if (minute < 0 || minute > 59) {
			return FALSE;
		}
	} else if (1 == zone_len) {
		if ('A' <= str_zone[0] && 'J' > str_zone[0]) {
			factor = 1;
			hour = str_zone[0] - 'A' + 1;
			minute = 0;
		} else if ('J' < str_zone[0] && 'M' >= str_zone[0]) {
			factor = 1;
			hour = str_zone[0] - 'A';
			minute = 0;
		} else if ('N' <= str_zone[0] && 'Y' >= str_zone[0]) {
			factor = -1;
			hour = str_zone[0] - 'N' + 1;
			minute = 0;
		} else if ('Z' == str_zone[0]) {
			factor = 1;
			hour = 0;
			minute = 0;
		} else {
			return FALSE;
		}
	} else if (2 == zone_len || 3 == zone_len) {
		if (0 == strcmp("UT", str_zone) ||
			0 == strcmp("GMT", str_zone)) {
			factor = 1;
			hour = 0;
			minute = 0;
		} else if (0 == strcmp("EDT", str_zone)) {
			factor = 1;
			hour = 4;
			minute = 0;
		} else if (0 == strcmp("EST", str_zone) ||
			0 == strcmp("CDT", str_zone)) {
			factor = 1;
			hour = 5;
			minute = 0;
		} else if (0 == strcmp("CST", str_zone) ||
			0 == strcmp("MDT", str_zone)) {
			factor = 1;
			hour = 6;
			minute = 0;
		} else if (0 == strcmp("MST",  str_zone) ||
			0 == strcmp("PDT", str_zone)) {
			factor = 1;
			hour = 7;
			minute = 0;
		} else if (0 == strcmp("PST", str_zone)) {
			factor = 1;
			hour = 8;
			minute = 0;
		} else {
			return FALSE;
		}
	} else {
		return FALSE;
	}
	
	tmp_time = make_gmtime(&tmp_tm);
	tmp_time += factor*(60*60*hour + 60*minute);
	*ptime = tmp_time;
	return TRUE;
}

static BOOL encode_strings_to_utf8(
	const char *mime_string, char *out_string)
{
	char *in_buff;
	int i, buff_len;
	char last_charset[32];
	ENCODE_STRING encode_string;
	char temp_buff[MIME_FIELD_LEN];
	int last_pos, begin_pos, end_pos;
	size_t buff_offset, decode_len, tmp_len;
		
	buff_len = strlen(mime_string);
	in_buff = (char*)mime_string;
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	buff_offset = 0;
	last_charset[0] = '\0';
	for (i=0; i<buff_len-1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				if (1 != begin_pos - last_pos || ' ' != in_buff[last_pos]) {
					return FALSE;
				}
				last_pos = i;
			}
		}
		if (-1 == end_pos && -1 != begin_pos && '?' == in_buff[i] &&
			'=' == in_buff[i + 1] && ('q' != in_buff[i - 1] &&
			'Q' != in_buff[i - 1] || '?' != in_buff[i - 2])) {
			end_pos = i + 1;
		}
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			if ('\0' == last_charset[0]) {
				strcpy(last_charset, encode_string.charset);
			} else if (0 != strcasecmp(
				encode_string.charset, last_charset)) {
				return FALSE;
			}
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len,
					temp_buff + buff_offset, &decode_len);
				buff_offset += decode_len;
			} else if (0 == strcmp(encode_string.encoding,
				"quoted-printable")){
				buff_offset += qp_decode(temp_buff,
					encode_string.title, tmp_len);
			} else {
				return FALSE;
			}
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos) {
		return FALSE;
	} 
	temp_buff[buff_offset] = '\0';
	if (FALSE == string_to_utf8(last_charset,
		temp_buff, out_string)) {
		return FALSE;	
	}
	return utf8_check(out_string);
}

BOOL mime_string_to_utf8(const char *charset,
	const char *mime_string, char *out_string)
{
	int i, buff_len;
	char *in_buff, *out_buff;
	ENCODE_STRING encode_string;
	char temp_buff[MIME_FIELD_LEN];
	int last_pos, begin_pos, end_pos;
	size_t offset, decode_len, tmp_len;
	
	
	buff_len = strlen(mime_string);
	in_buff = (char*)mime_string;
	out_buff = out_string;
	offset = 0;
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	for (i=0; i<buff_len-1&&offset<2*buff_len+1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				memcpy(temp_buff, in_buff + last_pos, begin_pos - last_pos);
				temp_buff[begin_pos - last_pos] = '\0';
				ltrim_string(temp_buff);
				if (FALSE == string_to_utf8(charset, temp_buff,
					out_buff + offset)) {
					return FALSE;
				}
				offset += strlen(out_buff + offset);
				last_pos = i;
			}
		}
		if (-1 == end_pos && -1 != begin_pos && '?' == in_buff[i] &&
			'=' == in_buff[i + 1] && ('q' != in_buff[i - 1] &&
			'Q' != in_buff[i - 1] || '?' != in_buff[i - 2])) {
			end_pos = i + 1;
		}
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len, temp_buff, &decode_len);
				temp_buff[decode_len] = '\0';
				if (FALSE == string_to_utf8(encode_string.charset, temp_buff,
					out_buff + offset)) {
					return encode_strings_to_utf8(mime_string, out_string);
				}
			} else if (0 == strcmp(encode_string.encoding,
				"quoted-printable")){
				decode_len = qp_decode(temp_buff, encode_string.title,
								tmp_len);
				temp_buff[decode_len] = '\0';
				if (FALSE == string_to_utf8(encode_string.charset, temp_buff,
					out_buff + offset)) {
					return encode_strings_to_utf8(mime_string, out_string);
				}
			} else {
				if (FALSE == string_to_utf8(charset, encode_string.title,
					out_buff + offset)) {
					return FALSE;
				}
			}
			
			offset += strlen(out_buff + offset);
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos || 1 == buff_len) {
		if (FALSE == string_to_utf8(charset, in_buff + last_pos,
			out_buff + offset)) {
			return FALSE;
		}
		offset += strlen(out_buff + offset);
	} 
	out_buff[offset] = '\0';
	return utf8_check(out_buff);
}

void enriched_to_html(const char *enriched_txt,
	char *html, int max_len)
{
	char *p;
	int len;
	int len1;
	int offset;
	int nofill;
	int paramct;
	int c, i, j;
	char token[62];
	
	paramct = 0;
	nofill = 0;
	len = strlen(enriched_txt);
	for (i=0,offset=0; i<len&&offset<max_len-2; i++) {
		c = enriched_txt[i];
		if('<' == c) {
			i ++;
			if (i >= len) {
				break;
			}
			c = enriched_txt[i];
			if('<' == c) {
				if (offset + 4 >= max_len - 2) {
					break;
				}
				memcpy(html + offset, "&lt;", 4);
				offset += 4;
			} else {
				for (j=0, p=token; (c=enriched_txt[i+j])!='\0'&&c!='>'; j++) {
					if (j < sizeof(token)-1) {
						*p++ = isupper(c) ? tolower(c) : c;
					}
				}
				*p = '\0';
				if('\0' == c) {
					break;
				}
				if (0 == strcmp(token, "/param")) {
					paramct --;
					html[offset] = '>';
					offset ++;
					i += 6;
				} else if (paramct > 0) {
					len1 = strlen(token);
					if (offset + 8 + len1 >= max_len - 2) {
						break;
					}
					memcpy(html + offset, "&lt;", 4);
					offset += 4;
					memcpy(html + offset, token, len1);
					offset += len1;
					memcpy(html + offset, "&gt;", 4);
					offset += 4;
				} else {
					html[offset] = '<';
					offset ++;
					if (0 == strcmp(token, "nofill")) {
						nofill ++;
						if (offset + 3 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, "pre", 3);
						offset += 3;
						i += 6;
					} else if (strcmp(token, "/nofill") == 0) {
						nofill --;
						if (offset + 4 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, "/pre", 4);
						offset += 4;
						i += 7;
					} else if (strcmp(token, "bold") == 0) {
					   html[offset] = 'b';
					   offset ++;
					   i += 4;
					} else if (strcmp(token, "/bold") == 0) {
						memcpy(html + offset, "/b", 2);
						offset += 2;
						i += 5;
					} else if(strcmp(token, "italic") == 0) {
						html[offset] = 'i';
						offset ++;
						i += 6;
					} else if (strcmp(token, "/italic") == 0) {
						memcpy(html + offset, "/i", 2);
						offset += 2;
						i += 7;
					} else if (strcmp(token, "fixed") == 0) {
						memcpy(html + offset, "tt", 2);
						offset += 2;
						i += 5;
					} else if (strcmp(token, "/fixed") == 0) {
						if (offset + 3 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, "/tt", 3);
						offset += 3;
						i += 6;
					} else if (strcmp(token, "excerpt") == 0) {
						if (offset + 10 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, "blockquote", 10);
						offset += 10;
						i += 7;
					} else if (strcmp(token, "/excerpt") == 0) {
						if (offset + 11 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, "/blockquote", 11);
						offset += 11;
						i += 8;
					} else {
						len1 = strlen(token);
						if (offset + len1 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, token, len1);
						offset += len1;
						i += len1;
						if(0 == strcmp(token, "param")) {
							paramct ++;
							html[offset] = ' ';
							offset ++;
							continue;
						}
					}
					html[offset] = '>';
					offset ++;
				}
			}
		} else if('>' == c) {
			if (offset + 4 >= max_len - 2) {
				break;
			}
			memcpy(html + offset, "&gt;", 4);
			offset += 4;
		} else if ('&' == c) {
			if (offset + 5 >= max_len - 2) {
				break;
			}
			memcpy(html + offset, "&amp;", 5);
			offset += 5;
		} else {
			if('\n' == c && nofill <= 0 && paramct <= 0) {
				for (j=i+1; j<len; j++) {
					if ('\n' == enriched_txt[j]) {
						if (offset + 4 >= max_len - 2) {
							break;
						}
						memcpy(html + offset, "<br>", 4);
						offset += 4;
					} else {
						break;
					}
				}
				i = j - 1;
			}
			html[offset] = c;
			offset ++;
		}
	}
	html[offset] = '\n';
	offset ++;
	html[offset] = '\0';
}

int html_to_plain(char *rbuf, int len)
{
	int i = 0;
	char is_xml = 0;
	uint8_t state = 0;
	int br, depth = 0, in_q = 0;
	char *tbuf, *buf, *p, *tp, *rp, c, lc;
	
	buf = malloc(len + 1);
	if (NULL == buf) {
		return 0;
	}
	memcpy(buf, rbuf, len);
	buf[len] = '\0';
	c = *buf;
	p = buf;
	rp = rbuf;
	br = 0;
	tbuf = tp = NULL;
	while (i < len) {
		switch (c) {
		case '\0':
			break;
		case '<':
			if (in_q) {
				break;
			}
			if (isspace(*(p + 1))) {
				goto REG_CHAR;
			}
			if (0 == state) {
				if (0 == strncasecmp(p, "<br>", 4) ||
					0 == strncasecmp(p, "</p>", 4)) {
					*(rp ++) = '\r';
					*(rp ++) = '\n';
					i += 3;
					p += 3;
				} else if (0 == strncasecmp(p, "<style", 6)) {
					lc = 1;
					state = 2;
					i += 6;
					p += 6;
				} else if (0 == strncasecmp(p, "<script", 7)) {
					lc = 2;
					state = 2;
					i += 7;
					p += 7;
				} else {
					state = 1;
				}
			} else if (1 == state) {
				depth ++;
			} else if (2 == state) {
				if (1 == lc && 0 == strncasecmp(p, "</style>", 8)) {
					state = 0;
					i += 7;
					p += 7;
				} else if (2 == lc && 0 == strncasecmp(p, "</script>", 9)) {
					state = 0;
					i += 8;
					p += 8;
				}
			}
			break;
		case '&':
			if (0 == state) {
				if (0 == strncasecmp(p, "&quot;", 6)) {
					*(rp ++) = '"';
					i += 5;
					p += 5;
				} else if (0 == strncasecmp(p, "&amp;", 5)) {
					*(rp ++) = '&';
					i += 4;
					p += 4;
				} else if (0 == strncasecmp(p, "&lt;", 4)) {
					*(rp ++) = '<';
					i += 3;
					p += 3;
				} else if (0 == strncasecmp(p, "&gt;", 4)) {
					*(rp ++) = '>';
					i += 3;
					p += 3;
				} else if (0 == strncasecmp(p, "&nbsp;", 6)) {
					*(rp ++) = ' ';
					i += 5;
					p += 5;
				}
			}
			break;
		case '(':
		case ')':
			if (0 == state) {
				*(rp ++) = c;
			}
			break;
		case '>':
			if (depth) {
				depth --;
				break;
			}
			if (in_q) {
				break;
			}
			switch (state) {
			case 1: /* HTML/XML */
				if (is_xml && '-' == *(p - 1)) {
					break;
				}
				in_q = state = is_xml = 0;
				break;
			case 2: /* <style>/<script> */
				break;
			case 3:
				in_q = state = 0;
				tp = tbuf;
				break;
			case 4: /* JavaScript/CSS/etc... */
				if (p >= buf + 2 && '-' == *(p - 1) && '-' == *(p - 2)) {
					in_q = state = 0;
					tp = tbuf;
				}
				break;
			default:
				*(rp ++) = c;
				break;
			}
			break;
		case '"':
		case '\'':
			if (4 == state) {
				/* Inside <!-- comment --> */
				break;
			} else if (0 == state) {
				*(rp ++) = c;
			}
			if (state && p != buf && (1 == state || *(p - 1) != '\\') && (!in_q || *p == in_q)) {
				if (in_q) {
					in_q = 0;
				} else {
					in_q = *p;
				}
			}
			break;
		case '!':
			/* JavaScript & Other HTML scripting languages */
			if (1 == state && '<' == *(p - 1)) {
				state = 3;
			} else {
				if (0 == state) {
					*(rp ++) = c;
				}
			}
			break;
		case '-':
			if (3 == state && p >= buf + 2 && '-' == *(p - 1) && '!' == *(p - 2)) {
				state = 4;
			} else {
				goto REG_CHAR;
			}
			break;
		case 'E':
		case 'e':
			/* !DOCTYPE exception */
			if (3 == state && p > buf + 6
				&& tolower(*(p - 1)) == 'p'
				&& tolower(*(p - 2)) == 'y'
				&& tolower(*(p - 3)) == 't'
				&& tolower(*(p - 4)) == 'c'
				&& tolower(*(p - 5)) == 'o'
				&& tolower(*(p - 6)) == 'd') {
				state = 1;
				break;
			}
			/* fall-through */
		default:
REG_CHAR:
			if (0 == state) {
				*(rp ++) = c;
			}
			break;
		}
		c = *(++ p);
		i ++;
	}
	if (rp < rbuf + len) {
		*rp = '\0';
	}
	free(buf);
	return (int)(rp - rbuf);
}

int plain_to_html(char *rbuf, int len)
{
	int tag_len;
	int rbuf_len;
	char tag_buff[1024];
	
	strcpy(tag_buff,
		"<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;"
		" charset=utf-8\">\r\n<meta name=\"Generator\" content=\"GRID text "
		"converter\">\r\n</head>\r\n<body>\r\n<pre>");
	tag_len = strlen(tag_buff);
	rbuf_len = strlen(rbuf);
	if (len < rbuf_len + tag_len + 25) {
		return rbuf_len;
	}
	memmove(rbuf + tag_len, rbuf, rbuf_len);
	memcpy(rbuf, tag_buff, tag_len);
	memcpy(rbuf + tag_len + rbuf_len, "</pre>\r\n</body>\r\n</html>", 25);
	return tag_len + rbuf_len + 25;
}
