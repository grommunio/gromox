#include "rules_object.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

RULES_OBJECT* rules_object_create(
	STORE_OBJECT *pstore, uint64_t folder_id)
{
	RULES_OBJECT *prules;
	
	prules = malloc(sizeof(RULES_OBJECT));
	if (NULL == prules) {
		return NULL;
	}
	prules->pstore = pstore;
	prules->folder_id = folder_id;
	return prules;
}

STORE_OBJECT* rules_object_get_store(RULES_OBJECT *prules)
{
	return prules->pstore;
}

uint64_t rules_object_get_folder_id(RULES_OBJECT *prules)
{
	return prules->folder_id;
}

void rules_object_free(RULES_OBJECT *prules)
{
	free(prules);
}

static BOOL rules_object_flush_delegats(int fd,
	FORWARDDELEGATE_ACTION *paction)
{
	int i, j;
	int tmp_len;
	char *ptype;
	char *paddress;
	BINARY *pentryid;
	char address_buff[256];

	for (i=0; i<paction->count; i++) {
		ptype = NULL;
		paddress = NULL;
		pentryid = NULL;
		for (j=0; j<paction->pblock[i].count; j++) {
			switch (paction->pblock[i].ppropval[j].proptag) {
			case PROP_TAG_ADDRESSTYPE:
				ptype = paction->pblock[i].ppropval[j].pvalue;
				break;
			case PROP_TAG_ENTRYID:
				pentryid = paction->pblock[i].ppropval[j].pvalue;
				break;
			case PROP_TAG_EMAILADDRESS:
				paddress = paction->pblock[i].ppropval[j].pvalue;
				break;
			}
		}
		address_buff[0] = '\0';
		if (NULL != ptype && NULL != paddress) {
			if (0 == strcasecmp(ptype, "SMTP")) {
				strncpy(address_buff, paddress, sizeof(address_buff));
			} else if (0 == strcasecmp(ptype, "EX")) {
				common_util_essdn_to_username(paddress, address_buff);
			}
		}
		if ('\0' == address_buff[0] && NULL != pentryid) {
			if (FALSE == common_util_entryid_to_username(
				pentryid, address_buff)) {
				return FALSE;	
			}
		}
		if ('\0' != address_buff[0]) {
			tmp_len = strlen(address_buff);
			address_buff[tmp_len] = '\n';
			tmp_len ++;
			write(fd, address_buff, tmp_len);
		}
	}
	return TRUE;
}


BOOL rules_object_update(RULES_OBJECT *prules,
	uint32_t flags, const RULE_LIST *plist)
{
	int i, fd;
	BOOL b_exceed;
	BOOL b_delegate;
	char *pprovider;
	char temp_path[256];
	RULE_ACTIONS *pactions;
	
	if (flags & MODIFY_RULES_FLAG_REPLACE) {
		if (FALSE == exmdb_client_empty_folder_rule(
			store_object_get_dir(prules->pstore),
			prules->folder_id)) {
			return FALSE;	
		}
	}
	b_delegate = FALSE;
	for (i=0; i<plist->count; i++) {
		if (FALSE == common_util_convert_from_zrule(
			&plist->prule[i].propvals)) {
			return FALSE;	
		}
		pprovider = common_util_get_propvals(
				&plist->prule[i].propvals,
				PROP_TAG_RULEPROVIDER);
		if (NULL == pprovider || 0 != strcasecmp(
			pprovider, "Schedule+ EMS Interface")) {
			continue;	
		}
		pactions = common_util_get_propvals(
					&plist->prule[i].propvals,
					PROP_TAG_RULEACTIONS);
		if (NULL != pactions) {
			b_delegate = TRUE;
		}
	}
	if (((flags & MODIFY_RULES_FLAG_REPLACE) || TRUE == b_delegate)
		&& TRUE == store_object_check_private(prules->pstore)) {
		sprintf(temp_path, "%s/config/delegates.txt",
				store_object_get_dir(prules->pstore));
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			if (TRUE == b_delegate) {
				for (i=0; i<pactions->count; i++) {
					if (ACTION_TYPE_OP_DELEGATE ==
						pactions->pblock[i].type) {
						if (FALSE == rules_object_flush_delegats(
							fd, pactions->pblock[i].pdata)) {
							close(fd);
							return FALSE;
						}
					}
				}
			}
			close(fd);
		}
	}
	return exmdb_client_update_folder_rule(
		store_object_get_dir(prules->pstore),
		prules->folder_id, plist->count,
		plist->prule, &b_exceed);
}
