#include <libHX/defs.h>
#include "uid_db.h"
#include "double_list.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct pdbitem {
	char uid[256];
};

static void uid_db_encode_line(const char *in, char *out);

void uid_db_init(UID_DB *pdb, const char *path, const char *username)
{
	strcpy(pdb->mailbox_path, path);
	strcpy(pdb->username, username);
	pdb->pfile = NULL;
}

BOOL uid_db_open(UID_DB *pdb)
{
	int fd;
	char temp_path[256];
	struct stat node_stat;
	
	if (NULL != pdb->pfile) {
		list_file_free(pdb->pfile);
		pdb->pfile = NULL;
	}

	sprintf(temp_path, "%s/tmp/%s", pdb->mailbox_path, pdb->username);
	if (0 != stat(temp_path, &node_stat)) {
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 == fd) {
			return FALSE;
		}
		close(fd);
	}

	pdb->pfile = list_file_init(temp_path, "%s:256");
	if (NULL == pdb->pfile) {
		return FALSE;
	}
	return TRUE;
}

void uid_db_free(UID_DB *pdb)
{
	pdb->mailbox_path[0] = '\0';
	pdb->username[0] = '\0';
}

BOOL uid_db_close(UID_DB *pdb)
{
	if (NULL != pdb->pfile) {
		list_file_free(pdb->pfile);
		pdb->pfile = NULL;
	}
	return TRUE;
}

BOOL uid_db_update(UID_DB *pdb, POP3_SESSION *psession)
{
	int fd;
	int offset;
	char temp_path[256];
	char temp_string[512];
	DOUBLE_LIST_NODE *pnode;
	char temp_buff[1024*1024];
	UID_ITEM *puid;

	if (FALSE == psession->b_touch) {
		return TRUE;
	}

	if (NULL != pdb->pfile) {
		list_file_free(pdb->pfile);
		pdb->pfile = NULL;
	}
	
	offset = 0;
	for (pnode=double_list_get_head(&psession->uid_list); NULL!=pnode;
		pnode=double_list_get_after(&psession->uid_list, pnode)) {
		puid = (UID_ITEM*)pnode->pdata;
		if (FALSE == puid->b_done) {
			continue;
		}
		uid_db_encode_line(puid->uid, temp_string);
		offset += snprintf(temp_buff + offset, 1024*1024 - offset, "%s\r\n",
					temp_string);
	}

	sprintf(temp_path, "%s/tmp/%s", pdb->mailbox_path, pdb->username);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	write(fd, temp_buff, offset);
	close(fd);
	return TRUE;
}

BOOL uid_db_check(UID_DB *pdb, POP3_SESSION *psession)
{
	int i, num;
	UID_ITEM *puid;
	DOUBLE_LIST_NODE *pnode;

	if (NULL == pdb->pfile) {
		return FALSE;
	}

	num = list_file_get_item_num(pdb->pfile);
	const struct pdbitem *pitem = reinterpret_cast(struct pdbitem *, list_file_get_list(pdb->pfile));
	for (i=0; i<num; i++) {
		for (pnode=double_list_get_head(&psession->uid_list); NULL!=pnode;
			pnode=double_list_get_after(&psession->uid_list, pnode)) {
			puid = (UID_ITEM*)pnode->pdata;
			if (strcmp(puid->uid, pitem[i].uid) == 0)
				puid->b_done = TRUE;
		}
	}
	return TRUE;
}


static void uid_db_encode_line(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if (' ' == in[i] || '\\' == in[i] || '\t' == in[i] || '#' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

