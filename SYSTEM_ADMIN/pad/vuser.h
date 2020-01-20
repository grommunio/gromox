#pragma once

enum {
	VUSER_OK,
	VUSER_NONE,
	VUSER_FAIL
};

typedef struct _VUSER {
	char username[128];
} VUSER;


void vuser_init(VUSER *puser, const char *username);

int vuser_work(VUSER *puser);

void vuser_free(VUSER *puser);
